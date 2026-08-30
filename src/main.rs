//! zyris-docker — a Zyris node for containers.
//!
//! Runs inside a container (targeting Docker hosts and Kubernetes clusters) and connects to
//! Attacca over the Zyris protocol. It offers:
//!
//! - `monitor`: system snapshot, process listing, Docker and Kubernetes state — the tools an
//!   agent uses to see what is happening on this node.
//! - `file_io`: read/write/edit inside the configured roots.
//! - `terminal`: PTY and `exec`, gated to the configured roots and capped by timeout.
//!
//! And it is the trigger half of a self-healing loop: on a timer it checks the watched processes,
//! containers and cluster; when one is down it opens an Attacca session so an agent diagnoses and
//! fixes it with this node's own tools, then reports back.
//!
//! Configuration is environment-driven. **The program layer that reads those variables is this
//! node's own now** (`src/runtime/`, `src/enroll.rs`): upstream deleted `zyris::runtime` when
//! `zyris` became a library, on the grounds that backoff, exit codes and where on a machine a
//! secret may be written are properties of a program rather than of a protocol. What it reads is
//! unchanged — `ZYRIS_SERVER_URL`, `ZYRIS_NODE_NAME`, `ZYRIS_PROFILE`, `ZYRIS_SCOPES`,
//! `ZYRIS_CONFIG_DIR`, and credentials from `ZYRIS_NODE_TOKEN` / `ZYRIS_NODE_TOKEN_FILE`. This
//! node's own knobs are `ZYRISD_*` (see `config.rs` and the README).
//!
//! **A mounted `znt_` is the deployment path and always was.** Enrollment — an eight-character
//! code printed into the container log for somebody to approve in a browser — is the fallback for
//! a first run with no token yet, and it is real for the first time in this build: before the port
//! this node was compiled without zyris's `enroll` feature, so `request_scopes` fed a device grant
//! that was never constructed and the only working credential sources were the two token forms.

mod config;
mod docker;
mod enroll;
mod file_io;
mod gate;
mod heal;
mod k8s;
mod monitor;
mod runtime;
mod system;
mod terminal;

use std::path::PathBuf;
use std::sync::Arc;

use zyris::{Connection, NodeKind};
use zyris_caps::{FileIoServer, TerminalServer};

use crate::config::Config;
use crate::file_io::GatedFileIo;
use crate::gate::PathGate;
use crate::heal::{ConnSlot, SelfHealer};
use crate::monitor::{MonitorNode, MonitorServer};
use crate::runtime::{RunConfig, RunError, Runner};
use crate::terminal::GatedTerminal;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The scopes this node asks to be granted at enrollment, so the self-healing watcher can open a
/// session and drive it. An approving user may grant fewer; an operator who sets `$ZYRIS_SCOPES`
/// decides the final answer and this list is then unused.
///
/// **Adding one is not free and not local.** A scope the deployment does not know refuses the
/// *whole* authorize request with a 422 — attacca's `Json` extractor cannot read an enum variant it
/// has never heard of — so nobody ever reaches the approval page and no code is ever shown. Measure
/// a new scope against the deployment before adding it here; `enroll::enrollment_trouble` names the
/// offending scope when it happens, which is the difference between "enrollment is broken" and one
/// line to delete.
const SCOPES: [&str; 5] =
    ["agents:read", "sessions:write", "sessions:read", "projects:read", "jobs:write"];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("zyris-docker {VERSION}");
        return;
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "zyris-docker {VERSION} — a Zyris node for containers.\n\n\
             Connects this container to Attacca and exposes monitor, file_io and terminal \n\
             capabilities, plus a self-healing watcher. Configure with the ZYRIS_* / ZYRISD_* \n\
             environment variables (see README.md).\n\n\
             USAGE:\n  zyris-docker [--version] [--help]\n"
        );
        return;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // **`zyris_core`, not `zyris`.** The runtime moved: `zyris` is a facade of
                // re-exports with no code of its own now, so every `tracing` call the protocol
                // stack makes is emitted under the `zyris_core` target and a `zyris=info` directive
                // matches nothing at all. The program layer this node owns logs under
                // `zyris_docker`, so it is already covered by the first directive.
                .unwrap_or_else(|_| "zyris_docker=info,zyris_core=info".into()),
        )
        .init();

    // **Settled before `RunConfig::from_env()` reads it, and there is no setter any more.**
    // `Runner::request_scopes` existed because that runner resolved its credential source lazily; a
    // device grant copies `config.scopes` when it is built, and it is built by `enroll::source`
    // from the config read just below — so a scope named after that point never rides on the
    // authorization request and the approval page asks for nothing.
    //
    // Only set when unset, so an operator's `$ZYRIS_SCOPES` wins. That is what the README and
    // `.env.example` promise, and `RunConfig::scopes_pinned` is the record of which one decided.
    if std::env::var_os("ZYRIS_SCOPES").is_none() {
        std::env::set_var("ZYRIS_SCOPES", SCOPES.join(","));
    }

    let cfg = Config::from_env();
    let (roots, deny) = resolve_roots(&cfg);

    let slot = ConnSlot::new();
    let heal_slot = slot.clone();
    let heal_cfg = cfg.clone();

    let config = RunConfig::from_env();
    let creds: Arc<dyn runtime::Credentials> = match enroll::source(&config) {
        Ok(creds) => creds,
        // Through `RunError` so it lands on the same exit-code table as every later failure: an
        // `atk_` key pasted into `$ZYRIS_NODE_TOKEN` is 1 — nothing to wait for, and no amount of
        // restarting rewrites it — where a credential nobody has approved yet is 2.
        Err(e) => {
            let error = RunError::from(e);
            tracing::error!(%error, "could not decide what credential to present");
            std::process::exit(error.exit_code());
        }
    };

    // **The node is assembled here and handed over already built.** The collector the old runner
    // used (`CapabilitySet`) is not public any more and its public replacement,
    // `zyris::Capabilities::add`, is `async` — so there is nowhere synchronous left on that side.
    // `zyris::NodeBuilder` is synchronous and is exactly that collector, so `capability` and `kind`
    // are its methods now.
    //
    // **The name has to be said here.** A builder that is never told falls back to the literal
    // `"zyris-node"`, not this machine's hostname — so omitting it would make every container in a
    // fleet announce under one name.
    let node = match zyris::Node::builder()
        .name(config.node_name.clone())
        .kind(NodeKind::Service)
        .capability(MonitorServer(MonitorNode::new()))
        .capability(FileIoServer(GatedFileIo::new(PathGate::new(roots.clone(), deny.clone()))))
        .capability(TerminalServer(GatedTerminal::new(
            PathGate::new(roots, deny),
            cfg.max_output_bytes(),
            cfg.exec_timeout,
        )))
        .build()
    {
        Ok(node) => node,
        // Only a capability declared wrongly fails here — a duplicate name, a descriptor that will
        // not serialise. Reported through `RunError` so it uses the same exit-code table as
        // everything else: 2, which tells a supervisor that restarting changes nothing.
        Err(e) => {
            let error = RunError::Build(e);
            tracing::error!(%error, "could not build the node");
            std::process::exit(error.exit_code());
        }
    };

    // **On the runner, not on the builder.** `zyris::NodeBuilder::on_connect` fires from
    // `Node::connect`, through `Link`; this loop calls `Node::dial`, which does not run it. Hanging
    // the healer's slot there would leave it empty for the life of the process and self-healing
    // would silently never fire, with nothing in the log to say so.
    let runner = Runner::new(config, node, creds).on_connect(move |conn: Connection| {
        let slot = heal_slot.clone();
        async move {
            slot.put(conn);
        }
    });

    // The self-healing watcher runs for the life of the process. It samples on its own timer and
    // uses whichever connection is current; on a reconnect the slot is re-filled by on_connect.
    // It is spawned *inside* the runtime below (not before), or `tokio::spawn` panics with
    // "no reactor running".
    let code = run_runtime(runner, heal_cfg, slot);
    std::process::exit(code);
}

/// Create the tokio runtime, spawn the self-healing watcher on it, and run the node.
///
/// The status comes straight from `Runner::run`, which is where the exit-code table lives: 2 when a
/// person has to act (approve this node, give it a writable credential directory), 1 for anything
/// else. **The distinction is the whole reason a supervisor is not made to loop** on a condition no
/// restart can fix.
fn run_runtime(runner: Runner, heal_cfg: Config, slot: ConnSlot) -> i32 {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");
    rt.block_on(async {
        let mut healer = SelfHealer::new(heal_cfg, slot);
        let watcher = tokio::spawn(async move { healer.run().await });
        let code = runner.run().await;
        watcher.abort();
        code
    })
}

/// Resolve the `file_io` roots. Default is the whole container filesystem; the deny list is
/// always applied so the credential directory and host mounts stay out of reach.
fn resolve_roots(cfg: &Config) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let roots: Vec<PathBuf> = if cfg.file_roots.is_empty() {
        vec![PathBuf::from("/")]
    } else {
        cfg.file_roots.iter().map(PathBuf::from).collect()
    };
    // The node's own credential dir must never be editable through file_io.
    //
    // **It comes from the same function the store writes through** (`runtime::credential_dir`).
    // Before the port these were two answers that disagreed: this list guarded `$HOME/.zyris` while
    // the runtime it was guarding against wrote to `$XDG_CONFIG_HOME/zyris`, so the gate denied a
    // directory that held nothing and left the one that would hold the refresh token open. One
    // function, or they drift apart again.
    let deny: Vec<PathBuf> = vec![
        PathBuf::from("/run/secrets"),
        PathBuf::from("/var/run/secrets"),
        runtime::credential_dir(),
    ];
    (roots, deny)
}
