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
//! Configuration is environment-driven. The zyris runtime reads `ZYRIS_SERVER_URL`,
//! `ZYRIS_NODE_NAME`, `ZYRIS_PROFILE`, `ZYRIS_SCOPES`, and resolves credentials from
//! `ZYRIS_NODE_TOKEN` / `ZYRIS_NODE_TOKEN_FILE`; this node's own knobs are `ZYRISD_*` (see
//! `config.rs` and the README).

mod config;
mod docker;
mod file_io;
mod gate;
mod heal;
mod k8s;
mod monitor;
mod system;
mod terminal;

use std::path::PathBuf;

use zyris::runtime::Runner;
use zyris::{Connection, NodeKind};
use zyris_caps::{FileIoServer, TerminalServer};

use crate::config::Config;
use crate::file_io::GatedFileIo;
use crate::gate::PathGate;
use crate::heal::{ConnSlot, SelfHealer};
use crate::monitor::{MonitorNode, MonitorServer};
use crate::terminal::GatedTerminal;

const VERSION: &str = env!("CARGO_PKG_VERSION");

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
                .unwrap_or_else(|_| "zyris_docker=info,zyris=info".into()),
        )
        .init();

    // The runtime asks for a bounded set of scopes needed to drive self-healing sessions back
    // into Attacca. An approving user may grant fewer; an operator who sets `$ZYRIS_SCOPES`
    // decides the final answer and this is a no-op.
    let scopes = [
        "agents:read",
        "sessions:write",
        "sessions:read",
        "projects:read",
        "jobs:write",
    ];

    let cfg = Config::from_env();
    let (roots, deny) = resolve_roots(&cfg);

    let slot = ConnSlot::new();
    let heal_slot = slot.clone();
    let heal_cfg = cfg.clone();

    let runner = Runner::from_env()
        .kind(NodeKind::Service)
        .request_scopes(scopes)
        .capability(MonitorServer(MonitorNode::new()))
        .capability(FileIoServer(GatedFileIo::new(PathGate::new(roots.clone(), deny.clone()))))
        .capability(TerminalServer(GatedTerminal::new(
            PathGate::new(roots, deny),
            cfg.max_output_bytes(),
            cfg.exec_timeout,
        )))
        .on_connect(move |conn: Connection| {
            let slot = heal_slot.clone();
            async move {
                slot.put(conn);
            }
        });

    // The self-healing watcher runs for the life of the process. It samples on its own timer and
    // uses whichever connection is current; on a reconnect the slot is re-filled by on_connect.
    let watcher = {
        let mut healer = SelfHealer::new(heal_cfg, slot.clone());
        tokio::spawn(async move { healer.run().await })
    };

    // `run` returns only on shutdown; the watcher is aborted as the process exits.
    let code = pollster_tokio(runner);
    watcher.abort();
    std::process::exit(code);
}

/// Block on the runner's tokio future. `#[tokio::main]` is awkward here because the watcher must
/// be spawned inside the same runtime; running the runtime manually keeps both on one executor.
fn pollster_tokio(runner: Runner) -> i32 {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");
    rt.block_on(async {
        let code = runner.run().await;
        if code == std::process::ExitCode::SUCCESS { 0 } else { 1 }
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
    let deny: Vec<PathBuf> = vec![
        PathBuf::from("/run/secrets"),
        PathBuf::from("/var/run/secrets"),
        dirs_zyris_config_dir(),
    ];
    (roots, deny)
}

/// Where the zyris runtime keeps credentials (`~/.zyris`), so file_io cannot edit them.
fn dirs_zyris_config_dir() -> PathBuf {
    std::env::var("ZYRIS_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".zyris"))
                .unwrap_or_else(|_| PathBuf::from("/root/.zyris"))
        })
}
