//! Where this node's credential comes from, and **the enrollment code printed into the log.**
//!
//! Upstream used to drive the whole device grant: an `Enroller` held the store, ran the polling
//! loop, and printed the code itself. **That layer is gone** — the library-only `zyris` hands back
//! the code as a value and refuses to write the loop, on the grounds that a loop the caller cannot
//! end is a program rather than a library. So the loop is here.
//!
//! **This is `zyris-code`'s port with the screen taken out.** That app draws the code in a ratatui
//! window; here it goes to stdout, which in a container *is* `docker logs` / `kubectl logs`.
//! [`LogEnroll`] keeps the same four methods so the polling loop reads the same in both programs.
//! What was deliberately left behind: `Reauth`/`/account logout` (there is no keystroke to log out
//! with), the `enrolling` mutex (the dial loop is the one caller and it is serial), and the
//! unbounded renewal loop (see [`MAX_RENEWALS`]).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::runtime::{
    CredentialStore, CredentialStoreError, Credentials, CredentialsError, FileCredentialStore,
    RunConfig,
};

/// The program this node enrolls as. Attacca files its credential under the chosen system, so a
/// container's address reads `srv-a/zyris-docker/<ZYRIS_NODE_NAME>`.
const PROGRAM: &str = "zyris-docker";

/// The credentials this node will use.
///
/// **The order is the deployment story.** What an operator explicitly gives always wins —
/// `$ZYRIS_CREDENTIAL`, then `$ZYRIS_CREDENTIAL_FILE` — and the path that has to ask a person comes
/// last. A `zc_` obtained by approving a device code never expires, so a node given one directly
/// writes nothing and needs no volume.
///
/// **Scopes must be settled before getting here.** `main.rs` writes `$ZYRIS_SCOPES` before
/// `RunConfig::from_env` reads it: settle them later and the approval page asks for nothing.
///
/// **The error keeps its shade rather than becoming a string**, because the caller is
/// `std::process::exit` and the difference between 1 and 2 is the whole exit-code table.
pub fn source(config: &RunConfig) -> Result<Arc<dyn Credentials>, CredentialsError> {
    use crate::runtime::{StaticToken, TokenFile};

    // Where an operator gave a credential directly, there is nothing to enroll and nobody to ask.
    if let Some(token) = StaticToken::from_env()? {
        return Ok(Arc::new(token));
    }
    if let Some(file) = TokenFile::from_env() {
        return Ok(Arc::new(file));
    }

    // An operator who upgraded the image and kept the old variable would otherwise get an
    // enrollment code in a log nobody reads, and a node that never comes up.
    if let Some(name) = leftover(|name| std::env::var_os(name).is_some_and(|v| !v.is_empty())) {
        return Err(CredentialsError::NeedsOperator(format!(
            "{name} is no longer read: node tokens are gone. Remove it and either let this node \
             enroll itself (approve the printed code at /settings/zyris → Enter a code in Attacca) \
             or pass an existing credential as ZYRIS_CREDENTIAL_FILE or ZYRIS_CREDENTIAL"
        )));
    }

    // The credential file lands wherever `credential_dir()` says, which is `$ZYRIS_CONFIG_DIR`
    // when a person set one. The `file_io` deny list is built from the same function, which is what
    // keeps the store and the gate in agreement about where the secret is.
    let store = Arc::new(FileCredentialStore::for_server(&config.url, &config.profile))
        as Arc<dyn CredentialStore>;

    Ok(Arc::new(DeviceGrant::new(
        store,
        config.url.clone(),
        zyris::EnrollRequest {
            program: PROGRAM.to_string(),
            // In a container this is the container's hostname — a random id unless the operator
            // set one — so the person approving usually picks or creates the system by hand.
            system_hint: zyris::machine_name().unwrap_or_default(),
            platform: config.platform().to_string(),
            scopes: config.scopes.clone(),
        },
    )))
}

/// The variable an earlier image read, if one is still set.
fn leftover(is_set: impl Fn(&str) -> bool) -> Option<&'static str> {
    ["ZYRIS_NODE_TOKEN", "ZYRIS_NODE_TOKEN_FILE"].into_iter().find(|name| is_set(name))
}

/// How many times a lapsed code is renewed before this node gives up and exits.
///
/// **The one deliberate departure from `zyris-code`'s port.** That app renews without bound because
/// its window is on screen and `Ctrl-C` is always live. Neither holds in a container: renewing
/// forever there is a process idling against a code nobody will type, and attacca answers repeated
/// grants from one address with `too many pending enrollments from this address`.
///
/// Giving up is `NeedsOperator`, so the process exits 2 and `restart: on-failure` /
/// CrashLoopBackOff surfaces it instead of hiding it behind a container that looks alive.
const MAX_RENEWALS: u32 = 3;

/// The credential this node presents: the one held, the one on disk, or a fresh enrollment with the
/// code printed into the log. A `zc_` never expires and never rotates, so once one is held it is
/// simply presented before every dial.
struct DeviceGrant {
    store: Arc<dyn CredentialStore>,
    /// The websocket URL. `zyris::enroll` derives the HTTP base from it, so this node cannot end up
    /// enrolling against one deployment while connecting to another.
    url: String,
    /// What to ask to be enrolled as. Settled before this value is built — see [`source`].
    request: zyris::EnrollRequest,
    ui: LogEnroll,
    held: tokio::sync::Mutex<Option<zyris::Credential>>,
}

impl DeviceGrant {
    fn new(
        store: Arc<dyn CredentialStore>,
        url: String,
        request: zyris::EnrollRequest,
    ) -> DeviceGrant {
        DeviceGrant { store, url, request, ui: LogEnroll, held: tokio::sync::Mutex::new(None) }
    }

    /// The credential to present: the one held, the one on disk, or a fresh enrollment.
    async fn credential(&self) -> Result<zyris::Credential, CredentialsError> {
        if let Some(credential) = self.held.lock().await.clone() {
            return Ok(credential);
        }
        let credential = match self.stored().await? {
            Some(credential) => credential,
            None => self.enroll().await?,
        };
        *self.held.lock().await = Some(credential.clone());
        Ok(credential)
    }

    /// A corrupt or unreadable credential — including an account credential an earlier image
    /// wrote — is a reason to enroll again, not to die. A *refused* one is different — a
    /// world-readable key file — and refusing loudly is the whole point of that distinction, so it
    /// propagates rather than answering an exposed secret with a quiet re-enrollment.
    async fn stored(&self) -> Result<Option<zyris::Credential>, CredentialsError> {
        match self.store.load().await {
            Ok(credential) => Ok(credential),
            Err(e) if !e.is_discardable() => Err(store_trouble(e)),
            Err(e) => {
                tracing::warn!(error = %e, "discarding unusable stored credential");
                self.store.clear().await.map_err(store_trouble)?;
                Ok(None)
            }
        }
    }

    /// Ask for a code, put it in front of a person, and wait. Bounded — see [`MAX_RENEWALS`].
    async fn enroll(&self) -> Result<zyris::Credential, CredentialsError> {
        let mut enrollment =
            zyris::enroll(&self.url, self.request.clone()).await.map_err(enrollment_trouble)?;
        self.ui.show(enrollment.code());
        let mut renewals = 0u32;
        loop {
            // Hoisted out of the `match` so nothing borrows `enrollment` while the arm that has
            // to renew it runs.
            let progress = enrollment.poll().await.map_err(enrollment_trouble)?;
            match progress {
                // `poll` sleeps to the server's own cadence, `slow_down` included.
                zyris::Progress::Waiting { .. } => {}
                zyris::Progress::Granted(credential) => {
                    // Stored **before** it is used, and before anything is told the approval took.
                    // A credential this process began dialling on but never wrote down would enroll
                    // again on the next start — and in a container, "the next start" is every crash
                    // and every rollout, each leaving an unused credential in the account.
                    self.store.save(&credential).await.map_err(store_trouble)?;
                    self.ui.authorized();
                    return Ok(credential);
                }
                zyris::Progress::Lapsed => {
                    renewals += 1;
                    if renewals > MAX_RENEWALS {
                        return Err(CredentialsError::NeedsOperator(format!(
                            "no one approved this node after {MAX_RENEWALS} codes; \
                             start it again when somebody is ready to authorize it"
                        )));
                    }
                    self.ui.lapsed();
                    enrollment.renew().await.map_err(enrollment_trouble)?;
                    self.ui.show(enrollment.code());
                }
                zyris::Progress::Denied => {
                    self.ui.denied();
                    return Err(CredentialsError::NeedsOperator(
                        "the request was declined in the browser".to_string(),
                    ));
                }
            }
        }
    }

    #[cfg(test)]
    async fn is_holding(&self) -> bool {
        self.held.lock().await.is_some()
    }

    #[cfg(test)]
    async fn hold(&self, credential: zyris::Credential) {
        *self.held.lock().await = Some(credential);
    }

    /// A grant over whatever store the test hands it. Nothing in these tests reaches the network.
    #[cfg(test)]
    fn for_test(store: Arc<dyn CredentialStore>) -> DeviceGrant {
        DeviceGrant::new(
            store,
            "wss://example.invalid/zyris/v1/ws".to_string(),
            zyris::EnrollRequest {
                program: PROGRAM.to_string(),
                system_hint: "srv-a".to_string(),
                platform: "linux".to_string(),
                scopes: Vec::new(),
            },
        )
    }
}

#[async_trait::async_trait]
impl Credentials for DeviceGrant {
    async fn bearer(&self) -> Result<String, CredentialsError> {
        Ok(self.credential().await?.secret().to_string())
    }

    /// Attacca refused the credential — revoked in the web UI, or one from before credentials
    /// existed. Forget it, on disk and in memory, so the next `bearer` enrolls and prints a code.
    ///
    /// **Unless a sibling already replaced it.** A rolling update runs two pods over one volume;
    /// the first to be refused enrolls and writes a new credential, and the second, refused a
    /// moment later, must adopt that one rather than delete it.
    async fn forget_refused(&self) -> Result<bool, CredentialsError> {
        let refused = self.held.lock().await.take();
        if let Some(stored) = self.stored().await? {
            if refused.as_ref().is_none_or(|held| held.secret != stored.secret) {
                *self.held.lock().await = Some(stored);
                return Ok(true);
            }
        }
        tracing::warn!("Attacca refused this credential; forgetting it and enrolling again");
        self.store.clear().await.map_err(store_trouble)?;
        Ok(true)
    }

    fn describe(&self) -> String {
        format!("device enrollment ({})", self.store.describe())
    }
}

/// How the run loop should read a failure that came from the enrollment layer.
///
/// Matched exhaustively on purpose: a shade added upstream must stop the build here rather than be
/// folded into "back off and try again", which is the answer that never surfaces anything.
fn enrollment_trouble(error: zyris::EnrollError) -> CredentialsError {
    match error {
        // **One scope the deployment does not know refuses the *whole* authorize request** with a
        // 422, so nobody ever reaches the approval page. Naming the scope is the difference between
        // "enrollment is broken" and one line to delete from `main.rs`'s `SCOPES`.
        zyris::EnrollError::ScopeUnknown { scope } => CredentialsError::NeedsOperator(format!(
            "this server does not know the scope {scope}; it must be removed from the list this \
             build asks for before enrollment can even show a code"
        )),
        // Somebody said no in the browser. Asking again is pestering them.
        e @ zyris::EnrollError::Denied => CredentialsError::NeedsOperator(e.to_string()),
        // Both are worth another dial rather than an exit: a lapsed code is renewed by the next
        // attempt, and a server that is merely unreachable is usually a startup race.
        e @ (zyris::EnrollError::Lapsed | zyris::EnrollError::Unreachable(_)) => {
            CredentialsError::Unavailable(e.to_string())
        }
    }
}

/// A store failure that reached the caller needs a person.
///
/// [`DeviceGrant::stored`] already swallows the discardable ones on the read path, so what is left
/// is either a refusal — an exposed secret — or a *write* that could not be kept (a read-only
/// rootfs, no volume, a uid that cannot write). Retrying the second would mean a fresh code on
/// every restart, so neither is a reason to loop.
fn store_trouble(error: CredentialStoreError) -> CredentialsError {
    CredentialsError::NeedsOperator(error.to_string())
}

/// What moves the enrollment code to where an operator will see it. The polling loop calls these.
///
/// **The whole UI of this feature, and it is four lines of output.** `zyris-code` has a
/// `ScreenEnroll` here that draws into a ratatui window and only falls back to printing when there
/// is no screen; a container is that fallback, permanently. The four methods are kept even though
/// three of them are one line each, so the loop above reads the same in both programs.
struct LogEnroll;

impl LogEnroll {
    /// A fresh code is ready. Called for the first one and again after every renewal.
    ///
    /// **`println!` rather than `tracing`.** Somebody running with `RUST_LOG=error` must still see
    /// the code — it is the only actionable thing this process will ever say, and a filter set for
    /// quiet operation is exactly the state a first enrollment happens in. Rust's stdout is line
    /// buffered even when it is a pipe, so it reaches `docker logs` without a flush.
    fn show(&self, code: &zyris::Code) {
        println!("{}", notice(code));
    }

    /// The code lapsed. A new one is on its way; the run loop is not disturbed.
    fn lapsed(&self) {
        tracing::warn!("the enrollment code expired; asking for another");
    }

    fn denied(&self) {
        tracing::warn!("the enrollment request was declined in the browser");
    }

    fn authorized(&self) {
        tracing::info!("this node was authorized");
    }
}

/// How much of a code's life is left, on the wall clock it was issued against.
///
/// `unwrap_or_default` because renewal and this conversion race: a code that already lapsed must
/// convert to no time left rather than panicking, and the worst possible moment for a panic is the
/// one where the process is telling somebody how to authorize it.
fn time_left(code: &zyris::Code) -> Duration {
    code.expires_at.duration_since(SystemTime::now()).unwrap_or_default()
}

/// The block printed for a person to act on.
///
/// Built here rather than fetched from the library: upstream's `authorization_notice` went with the
/// program layer, and it was three facts and a border.
fn notice(code: &zyris::Code) -> String {
    let minutes = time_left(code).as_secs().div_ceil(60);
    format!(
        "\n\
         --------------------------------------------------------------\n  \
         Authorize this node\n\n  \
         1. Open        {uri}\n  \
         2. Enter code  {user_code}\n\n  \
         Waiting for approval. This code expires in {minutes} minutes.\n\
         --------------------------------------------------------------\n",
        uri = code.verification_uri,
        user_code = code.user_code,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::store::MemoryCredentialStore;

    fn a_credential(secret: &str) -> zyris::Credential {
        zyris::Credential {
            version: 2,
            secret: secret.to_string(),
            system: zyris::Named { id: "s".into(), name: "srv-a".into(), slug: "srv-a".into() },
            program: zyris::Named {
                id: "c".into(),
                name: "zyris-docker".into(),
                slug: "zyris-docker".into(),
            },
            scopes: Vec::new(),
            owner_email: "e@example.com".into(),
        }
    }

    fn code() -> zyris::Code {
        zyris::Code {
            user_code: "WXQR-7KBD".into(),
            verification_uri: "https://attacca.example/settings/zyris/device".into(),
            expires_at: SystemTime::now() + Duration::from_secs(600),
        }
    }

    /// What goes on the wire is the credential's secret, and nothing needs the network to say so.
    #[tokio::test]
    async fn the_bearer_is_the_stored_credentials_secret() {
        let store = Arc::new(MemoryCredentialStore::default());
        store.save(&a_credential("zc_stored")).await.unwrap();
        let grant = DeviceGrant::for_test(store);

        assert_eq!(grant.bearer().await.unwrap(), "zc_stored");
        assert!(grant.is_holding().await);
    }

    /// Attacca refused it: gone from the volume and from memory, so the next `bearer` enrolls.
    #[tokio::test]
    async fn a_refused_credential_is_forgotten_so_the_next_dial_enrolls() {
        let store = Arc::new(MemoryCredentialStore::default());
        store.save(&a_credential("zc_revoked")).await.unwrap();
        let grant = DeviceGrant::for_test(store.clone());
        grant.hold(a_credential("zc_revoked")).await;

        assert!(grant.forget_refused().await.unwrap());
        assert!(store.load().await.unwrap().is_none(), "the refused credential is still stored");
        assert!(!grant.is_holding().await, "the refused credential would be dialled again");
    }

    /// Review focus 3: a sibling pod already enrolled and wrote a new credential. Adopt it —
    /// deleting it would throw that pod's approval away.
    #[tokio::test]
    async fn a_credential_a_sibling_pod_just_enrolled_is_adopted_not_deleted() {
        let store = Arc::new(MemoryCredentialStore::default());
        store.save(&a_credential("zc_new")).await.unwrap();
        let grant = DeviceGrant::for_test(store.clone());
        grant.hold(a_credential("zc_old")).await;

        assert!(grant.forget_refused().await.unwrap());
        assert_eq!(store.load().await.unwrap().unwrap().secret, "zc_new");
        assert_eq!(grant.bearer().await.unwrap(), "zc_new");
    }

    /// Review focus 1: a compose file from before credentials still sets the old variable.
    #[test]
    fn an_old_token_variable_is_named_rather_than_ignored() {
        assert_eq!(leftover(|name| name == "ZYRIS_NODE_TOKEN_FILE"), Some("ZYRIS_NODE_TOKEN_FILE"));
        assert_eq!(leftover(|name| name == "ZYRIS_NODE_TOKEN"), Some("ZYRIS_NODE_TOKEN"));
        assert_eq!(leftover(|_| false), None);
    }

    /// **The block has to carry both halves.** A code with nowhere to type it is not actionable,
    /// and this string is the entire user interface of enrolling a headless node.
    #[test]
    fn the_printed_block_names_the_code_and_where_to_type_it() {
        let block = notice(&code());
        assert!(block.contains("WXQR-7KBD"), "the code is missing: {block}");
        assert!(block.contains("https://attacca.example/settings/zyris/device"));
        assert!(block.contains("expires in 10 minutes"), "no idea how long it lasts");
    }

    /// **A code that already lapsed still prints.**
    #[test]
    fn a_code_that_already_expired_still_prints_rather_than_panicking() {
        let lapsed =
            zyris::Code { expires_at: SystemTime::now() - Duration::from_secs(60), ..code() };
        assert!(notice(&lapsed).contains("WXQR-7KBD"));
        assert_eq!(time_left(&lapsed), Duration::ZERO);
    }
}
