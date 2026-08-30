//! The dial/reconnect loop this node runs, so nothing above it has to write one.
//!
//! Nothing here is clever, and that is the point: backoff with jitter, a healthy connection resets
//! it, one forced credential rotation on a refusal — which a credential source may answer by
//! discarding itself and enrolling again — graceful shutdown, and exit codes a supervisor can act
//! on. Each of those is a small decision that is easy to get subtly wrong once and then carry
//! forever — a node pinned at the backoff ceiling after a nightly server restart, a restart loop
//! printing enrollment codes into a log nobody reads.
//!
//! **Why this loop exists at all when the library has `Node::connect`.** `connect` takes one fixed
//! token string and redials with it forever behind a `Link`. That is exactly right for a `znt_`
//! node token, which never expires, and exactly wrong for the other credential this node can hold:
//! an account access token good for about an hour. A `Link` built on one would redial with a spent
//! token from the second hour on. So the loop stays ours and asks [`Credentials::bearer`]
//! immediately before *every* dial, which is what makes expiry a non-event rather than a reconnect
//! storm — and it costs a node on a mounted `znt_` nothing.
//!
//! `zyris::Account::register_node` would mint a `znt_` that never expires and let `Link` take this
//! job over, which would delete the whole rotation story. Deliberately not taken: it needs the
//! `nodes:write` scope, this node does not ask for it, and **a scope a deployment does not know
//! refuses the entire authorize request with a 422 before a code is ever shown** — so adding one
//! is a change that has to be measured against the deployment first, not a refactor.

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use zyris::{ConnectError, Connection, Node};

use crate::runtime::credentials::{token_prefix, Credentials, CredentialsError};

/// A connection that stayed up this long counts as healthy, so its eventual drop restarts the
/// backoff from the bottom. Without this a nightly server restart would leave every node pinned at
/// the ceiling forever.
const DEFAULT_STABLE_AFTER: Duration = Duration::from_secs(30);
const DEFAULT_BACKOFF_MIN: Duration = Duration::from_secs(1);
const DEFAULT_BACKOFF_MAX: Duration = Duration::from_secs(30);
/// Long enough for a closing frame to reach the server, so it retires the node promptly instead of
/// waiting for the heartbeat to lapse. Well inside the ten seconds `docker stop` allows.
const CLOSE_GRACE: Duration = Duration::from_millis(200);

/// Everything a node needs to know before it dials.
///
/// Upstream also carried the [`zyris::NodeKind`] here. **Dropped**: the node is assembled by the
/// caller through `zyris::NodeBuilder` now (see [`Runner::new`]), so the kind is said there, and a
/// second copy of it in this struct would be a field nothing reads and everything could disagree
/// with.
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// The websocket URL. The enrollment endpoints are derived from it, so this is the only address
    /// a node is configured with.
    pub url: String,
    pub node_name: String,
    /// Names the credential file, so one machine can hold separate identities against the same
    /// deployment without them clobbering each other.
    pub profile: String,
    /// What this node *asks* for at enrollment. The user narrows it at approval time and may grant
    /// none of it.
    ///
    /// **This is settled before anything reads it and there is no setter to change it later.**
    /// Upstream had `Runner::request_scopes`, which existed because the old `Runner` resolved its
    /// credential source lazily; a device grant copies the scopes it will ask for when it is built,
    /// so the setter had to run before that. Here the credential source is built by
    /// `enroll::source` from this very config, which is why `main.rs` writes `$ZYRIS_SCOPES`
    /// before it calls [`RunConfig::from_env`]. Reverse that order and the approval screen appears
    /// asking for nothing.
    pub scopes: Vec<String>,
    /// Set when `$ZYRIS_SCOPES` was present. Read through [`Self::scopes_pinned()`].
    scopes_pinned: bool,
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    pub stable_after: Duration,
}

impl Default for RunConfig {
    fn default() -> RunConfig {
        RunConfig {
            url: zyris::DEFAULT_SERVER_URL.to_string(),
            // In a container this is a random hex string, which is why `main.rs` supplies a real
            // default through `$ZYRIS_NODE_NAME`. This is the floor under that, not the answer.
            node_name: zyris::machine_name().unwrap_or_else(|| "zyris-node".to_string()),
            profile: "default".to_string(),
            // Empty on purpose. A node that only announces tools needs no access to its owner's
            // account, and a default that asks for some would have every node asking by accident.
            scopes: Vec::new(),
            scopes_pinned: false,
            backoff_min: DEFAULT_BACKOFF_MIN,
            backoff_max: DEFAULT_BACKOFF_MAX,
            stable_after: DEFAULT_STABLE_AFTER,
        }
    }
}

impl RunConfig {
    /// Read the `ZYRIS_*` variables, falling back to [`RunConfig::default`] for each.
    ///
    /// | Variable | Falls back to |
    /// |---|---|
    /// | `ZYRIS_SERVER_URL` | `zyris::DEFAULT_SERVER_URL` |
    /// | `ZYRIS_NODE_NAME` | this machine's hostname |
    /// | `ZYRIS_PROFILE` | `default` |
    /// | `ZYRIS_SCOPES` | nothing |
    pub fn from_env() -> RunConfig {
        let default = RunConfig::default();
        let scopes = std::env::var("ZYRIS_SCOPES").ok().map(|raw| {
            raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
        });
        RunConfig {
            url: env_or("ZYRIS_SERVER_URL", default.url),
            node_name: env_or("ZYRIS_NODE_NAME", default.node_name),
            profile: env_or("ZYRIS_PROFILE", default.profile),
            scopes_pinned: scopes.is_some(),
            scopes: scopes.unwrap_or(default.scopes),
            ..default
        }
    }

    /// Whether `$ZYRIS_SCOPES` is where [`scopes`](Self::scopes) came from.
    ///
    /// It is the only record of *who decided*: an operator who set the variable outranks the list
    /// compiled into `main.rs`, and code that overrode it without checking here would make the
    /// variable a lie. It is logged at startup because in a headless node the log is the only place
    /// an operator can find out whether the variable they set actually took.
    pub fn scopes_pinned(&self) -> bool {
        self.scopes_pinned
    }

    /// What this machine reports itself as at enrollment. A hint the server never verifies.
    pub fn platform(&self) -> &'static str {
        match std::env::consts::OS {
            "linux" => "linux",
            "macos" => "macos",
            "windows" => "windows",
            _ => "other",
        }
    }
}

fn env_or(key: &str, fallback: String) -> String {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty()).unwrap_or(fallback)
}

/// A node could not be started, or could not keep running.
#[derive(Debug)]
pub enum RunError {
    Credentials(CredentialsError),
    /// The node itself could not be assembled — two capabilities claiming one name, a descriptor
    /// the wire rejects. **Nothing in this file produces it**: the node is built by the caller
    /// through `zyris::NodeBuilder` now (see [`Runner::new`]). It stays so that caller can report a
    /// build failure through the same exit-code table as everything else here, instead of inventing
    /// a second one.
    Build(zyris::Error),
    /// The server refused this node in a way retrying will not fix — a revoked credential, an
    /// unsupported protocol version, a build with no TLS provider compiled in.
    Refused(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Credentials(error) => write!(f, "{error}"),
            RunError::Build(error) => write!(f, "could not build the node: {error}"),
            RunError::Refused(reason) => write!(f, "the server refused this node: {reason}"),
        }
    }
}

impl std::error::Error for RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RunError::Credentials(error) => Some(error),
            RunError::Build(error) => Some(error),
            RunError::Refused(_) => None,
        }
    }
}

impl From<CredentialsError> for RunError {
    fn from(error: CredentialsError) -> RunError {
        RunError::Credentials(error)
    }
}

impl RunError {
    /// Exit 2 when a human has to do something, 1 otherwise.
    ///
    /// The distinction is what stops a supervisor from restart-looping on a condition no restart
    /// can fix — `restart: unless-stopped` in the compose file, CrashLoopBackOff in a cluster —
    /// printing a fresh enrollment code into a log nobody reads each time around.
    ///
    /// **An `i32` rather than upstream's `ExitCode`.** This program leaves through
    /// `std::process::exit`, and an `ExitCode` cannot be turned back into a number, so keeping that
    /// type would have meant a second table beside this one to translate it. The numbers are the
    /// point; the wrapper was not.
    pub fn exit_code(&self) -> i32 {
        match self {
            RunError::Credentials(CredentialsError::NeedsOperator(_)) | RunError::Build(_) => 2,
            _ => 1,
        }
    }
}

/// What a refused dial means to this loop.
///
/// [`Refusal::of`] is **exhaustive on [`ConnectError`] on purpose**: a variant upstream adds later
/// must stop the build here rather than be quietly folded into "unreachable, back off" — that is
/// the folding that turns a revocation into a node reconnecting forever and never coming back.
enum Refusal {
    /// Worth one forced credential rotation before giving up.
    Rotate,
    /// Retrying gets the same answer. A different build or a different person fixes it.
    Fatal,
    /// The network or the server, briefly. Back off and dial again.
    Backoff,
}

impl Refusal {
    fn of(error: &ConnectError) -> Refusal {
        match error {
            // A 401 can be a container clock that drifted, and `Revoked` is recoverable too for the
            // device-grant source: `AccountGrant::refresh` throws the dead credential away, so the
            // next `bearer` enrolls and the following dial is a fresh identity.
            ConnectError::Unauthorized | ConnectError::Revoked => Refusal::Rotate,
            // A build speaking the wrong major will speak it just as wrong in a second; a build
            // with no TLS provider compiled in cannot grow one at runtime.
            ConnectError::VersionMismatch { .. } | ConnectError::NoTlsProvider => Refusal::Fatal,
            ConnectError::Unreachable(_) => Refusal::Backoff,
        }
    }
}

type ConnectHook = Arc<dyn Fn(Connection) -> BoxFuture<'static, ()> + Send + Sync>;

/// A node, its credentials, and the loop that keeps them connected.
pub struct Runner {
    config: RunConfig,
    node: Node,
    credentials: Arc<dyn Credentials>,
    on_connect: Option<ConnectHook>,
}

impl Runner {
    /// Take an already-built node and keep it dialled.
    ///
    /// **The node arrives assembled, which is the one shape change from upstream.** The old
    /// `Runner` collected capabilities itself into a private `CapabilitySet` and built the node at
    /// `try_run`. That type is not public any more, and the public replacement,
    /// `zyris::Capabilities::add`, is `async` — so there is no way to collect capabilities behind a
    /// synchronous builder method on this type. `zyris::NodeBuilder` is synchronous and does
    /// exactly that job, so `capability` and `kind` are its methods now, not this one's.
    ///
    /// Building outside the loop is still load-bearing for the same reason it was upstream: a
    /// `Node` is reusable across connections and owns the capability implementations, so rebuilding
    /// one per attempt would hand every reconnect a freshly initialised capability that had
    /// forgotten whatever the last one knew — every open PTY session, in this node's case.
    pub fn new(config: RunConfig, node: Node, credentials: Arc<dyn Credentials>) -> Runner {
        Runner { config, node, credentials, on_connect: None }
    }

    /// Run once per established connection, concurrently with the connection itself.
    ///
    /// This is the *consume* half of a node: the server announces its own capabilities on the same
    /// websocket, which is how the self-healing watcher reaches `attacca_api`. The hook is spawned
    /// and its outcome is ignored — a node whose token lacks a scope should still serve the tools
    /// it announced.
    ///
    /// **`zyris::NodeBuilder::on_connect` is not the same hook and will not do.** That one fires
    /// from `Node::connect`, through `Link`; this loop calls `Node::dial`, which does not run it.
    /// Hanging the healer's slot there would leave it empty for the life of the process and
    /// self-healing would silently never fire, with nothing in the log to say so.
    pub fn on_connect<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(Connection) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        self.on_connect = Some(Arc::new(move |conn| Box::pin(hook(conn))));
        self
    }

    /// Connect, stay connected, and translate whatever happens into an exit status.
    ///
    /// Returns only when the node is shut down deliberately (`SIGTERM`, `Ctrl-C`) or hits something
    /// no retry can fix. Every failure along the way is logged as it happens, so the caller has
    /// nothing left to report.
    pub async fn run(self) -> i32 {
        match self.try_run().await {
            Ok(()) => 0,
            Err(error) => {
                tracing::error!(%error, "zyris node stopped");
                error.exit_code()
            }
        }
    }

    /// Race the dial loop against a stop signal.
    ///
    /// **The select is out here rather than around the connection, and that is a departure from
    /// upstream's shape with a reason.** Upstream waited for `Ctrl-C` only while a connection was
    /// live, which is fine when the signal is otherwise fatal by default — anywhere else it simply
    /// killed the process. It is not fine once this node listens for the signal at all: registering
    /// a handler replaces the default action **for the life of the process** — tokio says so itself:
    /// "Once a signal handler is registered with the process the underlying libc signal handler is
    /// never unregistered" (`tokio/src/signal/unix.rs`). A `SIGTERM` arriving while the loop was
    /// backing off, or while an enrollment
    /// was polling for up to ten minutes, would then be delivered to nobody and *ignored* — so
    /// `docker stop` would hang for its full grace period and end in `SIGKILL`, which is worse than
    /// never having listened.
    ///
    /// One select around the whole loop covers every state it can wait in. The live connection is
    /// parked in `live` so the graceful close still happens: it is the frame that retires this node
    /// server-side, without which the deployment keeps routing tool calls at it until the heartbeat
    /// lapses.
    async fn try_run(self) -> Result<(), RunError> {
        let live: Arc<std::sync::Mutex<Option<Connection>>> = Arc::default();
        let parked = live.clone();
        tokio::select! {
            outcome = self.dial_loop(parked) => outcome,
            signal = stop_requested() => {
                tracing::info!(signal, "shutting down");
                let held = live.lock().expect("connection mutex poisoned").take();
                if let Some(conn) = held {
                    conn.close("node shutting down");
                    tokio::time::sleep(CLOSE_GRACE).await;
                }
                Ok(())
            }
        }
    }

    /// Dial, serve, redial. Only returns when something no retry can fix says so — stopping is the
    /// caller's business, above.
    async fn dial_loop(
        &self,
        live: Arc<std::sync::Mutex<Option<Connection>>>,
    ) -> Result<(), RunError> {
        let credentials = self.credentials.clone();

        // `capabilities` is counted through `descriptors()` because `Capabilities::len` is
        // upstream-private. One descriptor is one capability, so the number is the one an operator
        // expects to see; the vector it builds to get there is paid for once, at startup.
        tracing::info!(
            node = %self.config.node_name,
            url = %self.config.url,
            credentials = %credentials.describe(),
            scopes = ?self.config.scopes,
            // Whether `$ZYRIS_SCOPES` won. In a headless node the log is the only place an operator
            // can find out that the variable they set was the one that decided.
            scopes_from_env = self.config.scopes_pinned(),
            capabilities = self.node.capabilities().descriptors().len(),
            "starting zyris node"
        );

        let mut backoff = self.config.backoff_min;
        // Tracks whether a refusal has already been answered with a forced rotation, so a genuinely
        // dead credential still terminates instead of refreshing forever.
        let mut rotated_after_refusal = false;

        loop {
            // Freshness is decided immediately before each dial rather than by a timer task: a
            // token that is valid now is valid for the handshake, and a connection that outlives
            // its token is handled server-side by the heartbeat.
            let bearer = match credentials.bearer().await {
                Ok(bearer) => bearer,
                // The credential *source* is unreachable — a Secret not mounted yet, an enrollment
                // server that timed out. That is a startup race, not a dead node, so it backs off
                // like any other transient failure instead of killing the process.
                Err(e @ CredentialsError::Unavailable(_)) => {
                    tracing::warn!(error = %e, "credential source unavailable");
                    backoff = self.wait_then_widen(backoff).await;
                    continue;
                }
                Err(e) => return Err(e.into()),
            };

            tracing::info!(token = %token_prefix(&bearer), "connecting");
            // `dial`, not `connect`: one attempt, and the loop around it is ours. See the module
            // comment for why a `Link` cannot hold an account access token.
            let error = match self.node.dial(&self.config.url, &bearer).await {
                Ok(conn) => {
                    rotated_after_refusal = false;
                    let up = Instant::now();
                    tracing::info!(
                        node_id = %conn.info().node_id,
                        conn_id = %conn.info().conn_id,
                        "connected"
                    );
                    if let Some(hook) = &self.on_connect {
                        tokio::spawn(hook(conn.clone()));
                    }
                    // Parked where the shutdown branch can reach it, and taken back when it drops
                    // on its own — so a stop signal always finds either this connection or nothing,
                    // never one that closed a moment ago.
                    *live.lock().expect("connection mutex poisoned") = Some(conn.clone());
                    let reason = conn.closed().await;
                    live.lock().expect("connection mutex poisoned").take();
                    tracing::warn!(%reason, "disconnected");
                    if up.elapsed() >= self.config.stable_after {
                        backoff = self.config.backoff_min;
                    }
                    // The same wait the refusal paths below take. Spelled out here rather than
                    // shared at the bottom of the loop so the classification match stays flat.
                    backoff = self.wait_then_widen(backoff).await;
                    continue;
                }
                Err(error) => error,
            };

            match Refusal::of(&error) {
                Refusal::Rotate if !rotated_after_refusal => {
                    tracing::warn!(%error, "credential refused; rotating once before giving up");
                    rotated_after_refusal = true;
                    match credentials.refresh().await {
                        // A different credential is ready right now, so no backoff: this is the
                        // one path in the loop that dials again immediately.
                        Ok(true) => continue,
                        Ok(false) => return Err(RunError::Refused(error.to_string())),
                        // The rotation endpoint could not be reached, so no rotation actually
                        // happened. Charging it against the one attempt would mean a server that
                        // blipped during a deploy kills every node that dialled through it.
                        Err(refresh_error @ CredentialsError::Unavailable(_)) => {
                            tracing::warn!(error = %refresh_error, "could not rotate the credential");
                            rotated_after_refusal = false;
                        }
                        Err(refresh_error) => return Err(refresh_error.into()),
                    }
                }
                // The one rotation is spent, so this credential really is dead. Saying so is what
                // stops a supervisor restart-looping on it.
                Refusal::Rotate | Refusal::Fatal => {
                    return Err(RunError::Refused(error.to_string()))
                }
                Refusal::Backoff => tracing::warn!(%error, "connect failed"),
            }

            backoff = self.wait_then_widen(backoff).await;
        }
    }

    async fn wait_then_widen(&self, backoff: Duration) -> Duration {
        let wait = jitter(backoff);
        tracing::info!(seconds = wait.as_secs_f64(), "reconnecting");
        tokio::time::sleep(wait).await;
        (backoff * 2).min(self.config.backoff_max)
    }
}

/// Wait for whichever signal means *stop*, and name it.
///
/// **`SIGTERM` is the one that matters here and upstream did not listen for it.** Upstream's loop
/// selected on `Ctrl-C` alone, which is the right answer for a program somebody started in a
/// terminal. A container is not one: `docker stop`, `docker compose down` and a Kubernetes pod
/// eviction all send `SIGTERM` and then `SIGKILL` ten seconds later. Ignoring it means every stop
/// is a ten-second hang followed by a kill, and the close frame that retires this node server-side
/// is never sent — so the deployment keeps routing tool calls at a node that is already gone until
/// the heartbeat lapses.
///
/// `Ctrl-C` stays, because `docker run -it` is how this image gets tried out.
async fn stop_requested() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => "SIGINT",
                    _ = terminate.recv() => "SIGTERM",
                }
            }
            // Registering a handler can only fail for reasons a retry will not fix. Losing the
            // graceful stop is bad; refusing to serve because of it would be worse.
            Err(error) => {
                tracing::warn!(%error, "cannot listen for SIGTERM; only Ctrl-C will stop this node");
                let _ = tokio::signal::ctrl_c().await;
                "SIGINT"
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        "Ctrl-C"
    }
}

/// ±20%, so a server restart does not bring every node back in the same instant.
///
/// `RandomState` rather than an `rand` dependency: a fresh one hashes differently on every call,
/// which is the entire requirement here. Backoff jitter does not need a real RNG, and this node has
/// no other use for one.
fn jitter(base: Duration) -> Duration {
    use std::hash::{BuildHasher, Hasher, RandomState};
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u8(0);
    let factor = 0.8 + (hasher.finish() % 400) as f64 / 1000.0;
    base.mul_f64(factor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_stays_within_twenty_percent_and_actually_varies() {
        let base = Duration::from_secs(10);
        let samples: Vec<Duration> = (0..64).map(|_| jitter(base)).collect();
        for sample in &samples {
            assert!(*sample >= base.mul_f64(0.8) && *sample <= base.mul_f64(1.2), "{sample:?}");
        }
        assert!(
            samples.iter().any(|s| *s != samples[0]),
            "every node backing off by the same amount is the thundering herd this exists to avoid"
        );
    }

    #[test]
    fn defaults_point_at_the_default_deployment() {
        let config = RunConfig::default();
        assert_eq!(config.url, zyris::DEFAULT_SERVER_URL);
        assert!(config.scopes.is_empty(), "a bare default must not ask for account access");
        assert!(!config.scopes_pinned(), "nobody has said anything about scopes yet");
        assert!(!config.node_name.is_empty());
    }

    /// The two mistakes are not symmetric: reading an outage as a revocation drags a person back to
    /// a browser, and reading a revocation as an outage is a node that reconnects forever and never
    /// comes back. This is the table that keeps them apart.
    #[test]
    fn a_refusal_is_classified_by_what_another_dial_could_possibly_change() {
        let rotate = [ConnectError::Unauthorized, ConnectError::Revoked];
        for error in rotate {
            assert!(matches!(Refusal::of(&error), Refusal::Rotate), "{error}");
        }

        let mismatch =
            ConnectError::VersionMismatch { ours: "1".to_string(), theirs: Some("2".to_string()) };
        let fatal = [mismatch, ConnectError::NoTlsProvider];
        for error in fatal {
            assert!(matches!(Refusal::of(&error), Refusal::Fatal), "{error}");
        }

        let blip = ConnectError::Unreachable(zyris::TransportError::Closed);
        assert!(matches!(Refusal::of(&blip), Refusal::Backoff), "{blip}");
    }

    /// **Exit 2 is what stops a restart loop.** A supervisor reads the number, and the only thing
    /// that distinguishes "try again in a second" from "a person has to approve this node" is which
    /// one comes back.
    #[test]
    fn only_the_failures_a_person_must_fix_exit_two() {
        let operator = RunError::Credentials(CredentialsError::NeedsOperator("approve".into()));
        assert_eq!(operator.exit_code(), 2);

        let fatal = RunError::Credentials(CredentialsError::Fatal("bad token".into()));
        assert_eq!(fatal.exit_code(), 1);
        assert_eq!(RunError::Refused("revoked".into()).exit_code(), 1);
    }
}
