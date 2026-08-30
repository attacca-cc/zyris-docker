//! Where this node's credential comes from, and **the enrollment code printed into the log.**
//!
//! Upstream used to drive the whole device grant: an `Enroller` held the store, ran the polling
//! loop, and printed the code itself. **That layer is gone** — the library-only `zyris` hands back
//! the code as a value and refuses to write the loop, on the grounds that a loop the caller cannot
//! end is a program rather than a library. So the loop is here.
//!
//! **This is `zyris-code`'s port with the screen taken out.** That app draws the code in a ratatui
//! window, and everything in its `enroll.rs` that exists to reach a window has no counterpart in a
//! container. What was deliberately left behind, and why:
//!
//! - `ScreenEnroll`, `Bridge`, `Frame::Enroll`, `EnrollPhase`, `EnrollView`, `Frame::EnrollDone`.
//!   There is no frame. The code goes to stdout, which in a container *is* `docker logs` /
//!   `kubectl logs`. [`LogEnroll`] keeps the same four methods so the polling loop below reads the
//!   same as that one and a future fix can be moved across without translating it.
//! - `Reauth`, `discard`, `discard_once`, `spent`. Those exist for `/account logout` — a keystroke
//!   — and for discarding a credential when the granted scopes come up short. The second is
//!   actively *wrong* here: a container that throws away a working credential and prints a fresh
//!   code into a log nobody is reading is worse off than one that keeps working and logs the
//!   shortfall.
//! - `AccountGrant`'s `enrolling` mutex. Its stated reason was that logging out must not park
//!   behind a ten-minute grant, and there is no logout. [`AccountGrant::bearer`] has exactly one
//!   caller, the dial loop, which is serial.
//! - The unbounded renewal loop. See [`MAX_RENEWALS`].
//! - `lang.rs`. There is no bilingual UI; the notice is English and goes through no string table.
//!
//! Everything else is carried across as it stands, including the four decisions that are not
//! decorative: the on-disk format, `store.save` before anything is told the approval took, dropping
//! a due account so the file is read again, and refusing to dial after a rotation the disk would
//! not keep. Each is commented where it lives.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::runtime::{
    CredentialStore, CredentialStoreError, Credentials, CredentialsError, FileCredentialStore,
    RunConfig,
};

/// The credentials this node will use.
///
/// **The order is upstream's old `credentials::from_env` and must stay it.** What a person
/// explicitly gives always wins, and the path that has to ask a person comes last. In a container
/// that ordering is not a nicety, it is the deployment story: a mounted `znt_` never expires, so a
/// node given one writes nothing, rotates nothing and needs no volume — none of the machinery below
/// this line ever runs. The device grant is the fallback for somebody running the image on a laptop
/// with no token yet.
///
/// **Scopes must be settled before getting here.** The `EnrollRequest` built below is what the
/// authorize call carries, and the grant is approved once against exactly that list. `main.rs`
/// writes `$ZYRIS_SCOPES` before `RunConfig::from_env` reads it for that reason: settle them later
/// and the approval page asks for nothing, which is a browser round trip that grants nothing.
/// **The error keeps its shade rather than becoming a string.** `zyris-code`'s version flattens it
/// to `String` because its caller has a screen to print on; here the caller is `std::process::exit`,
/// and the difference between "an `atk_` key was pasted into `$ZYRIS_NODE_TOKEN`" (1, nothing to
/// wait for) and "a person must approve this node" (2) is the entire reason the exit-code table
/// exists. Flattening it would have made every credential problem look the same to a supervisor.
pub fn source(config: &RunConfig) -> Result<Arc<dyn Credentials>, CredentialsError> {
    use crate::runtime::{StaticToken, TokenFile};

    // Where a person gave a token directly, there is nothing to enroll and nobody to ask.
    if let Some(token) = StaticToken::from_env()? {
        return Ok(Arc::new(token));
    }
    if let Some(file) = TokenFile::from_env() {
        return Ok(Arc::new(file));
    }

    // The credential file lands wherever `credential_dir()` says, which is `$ZYRIS_CONFIG_DIR`
    // when a person set one. **Nothing writes that variable on their behalf** — the store calls
    // `credential_dir()` itself, and so does the `file_io` deny list, which is what keeps the two
    // in agreement. An earlier version of this comment said `main.rs` filled it, and a later reader
    // trusting that could "simplify" the store to read the variable directly and reintroduce the
    // divergence the single function exists to prevent. Was filled from
    // `runtime::credential_dir()` — the same function that put the directory on the `file_io` deny
    // list, so the store and the gate cannot disagree about where the secret is.
    let store = Arc::new(FileCredentialStore::for_server(&config.url, &config.profile))
        as Arc<dyn CredentialStore>;

    Ok(Arc::new(AccountGrant::new(
        store,
        config.url.clone(),
        zyris::EnrollRequest {
            name: config.node_name.clone(),
            platform: config.platform().to_string(),
            scopes: config.scopes.clone(),
        },
    )))
}

/// How many times a lapsed code is renewed before this node gives up and exits.
///
/// **The one deliberate departure from `zyris-code`'s port**, and it is a departure back to what
/// upstream did. That app renews without bound and says why: the window is on screen and `Ctrl-C`
/// is always live, so giving up on the node's behalf would take away the one thing it can still do.
/// Neither clause holds in a container — there is no window and nobody is watching a `Ctrl-C`.
/// Renewing forever there is exactly the failure `runtime`'s module comment names, a process idling
/// against a code nobody will type; and attacca answers repeated grants from one address with
/// `too many pending enrollments from this address`, so it eventually just spins on a refusal.
///
/// Giving up is `NeedsOperator`, so the process exits 2 and `restart: on-failure` /
/// CrashLoopBackOff surfaces it instead of hiding it behind a container that looks alive.
const MAX_RENEWALS: u32 = 3;

/// The credential this node presents.
///
/// It is the device grant end to end: load what is stored, or enroll and print a code; wrap the
/// result in a [`zyris::Account`], which rotates the refresh token and hands each rotation back for
/// storing; and answer `bearer` from it before every dial.
struct AccountGrant {
    store: Arc<dyn CredentialStore>,
    /// The websocket URL. `Account` and `zyris::enroll` both derive the HTTP base from it, so this
    /// node cannot end up enrolling against one deployment while connecting to another.
    url: String,
    /// What to ask to be enrolled as. Settled before this value is built — see [`source`].
    request: zyris::EnrollRequest,
    ui: LogEnroll,
    held: tokio::sync::Mutex<Option<Arc<zyris::Account>>>,
    /// Why a rotation could not be stored, once one could not be.
    ///
    /// **This is the difference between stopping and being revoked, and in a container it is the
    /// most likely failure of the lot** — a read-only root filesystem, no volume mounted, a uid
    /// that cannot write the directory, a full disk.
    ///
    /// `zyris::Account` does not adopt a rotation its hook refused, and it reports the refusal as
    /// `Unreachable` — the same shade a server that blipped produces, which the run loop answers by
    /// backing off and dialling again. Here that answer is wrong and dangerous: the server has
    /// *already* spent the old refresh token, so every later attempt re-presents a spent one, and
    /// attacca reads a replay past its 30-second grace as a leaked chain — `revoke_all_for_node`,
    /// which kills every node under this credential rather than only this one.
    ///
    /// Worse, without this the failure is invisible. `Account::bearer` still holds an access token
    /// good for the remaining 20% of its life, so the dial *succeeds* and nothing looks wrong until
    /// the credential is already dead.
    ///
    /// Upstream could not reach that state: its `Enroller` persisted with `?`, so a store failure
    /// was `NeedsOperator` and the process exited 2 on the first one. Recording it here is how that
    /// answer survives the move — the hook is our code, so it is the one place that can still tell
    /// a full disk from a slow server.
    store_broke: Arc<tokio::sync::Mutex<Option<String>>>,
}

/// Persist a rotated credential, and remember a refusal as well as returning it.
///
/// **Extracted from the hook so a test can drive it, which is the half that was missing.** The two
/// tests below used to set `store_broke` by hand and assert the node then stopped — which proves
/// *"if the flag is set, we stop"* and says nothing about *"a store that refuses sets the flag"*.
/// The second half is the one that fires in the real incident: a read-only rootfs, no volume, a uid
/// that cannot write.
///
/// **Remembering is not the same as refusing, and both are needed.** The refusal alone reaches the
/// run loop as a transient error, which it answers by dialling again — and by then the server has
/// spent the refresh token that produced `rotated`, so every retry is a replay. attacca answers a
/// replay past its 30-second grace with `revoke_all_for_node`: every node under the credential, not
/// only this one.
async fn persist_rotation(
    store: &Arc<dyn CredentialStore>,
    broke: &Arc<tokio::sync::Mutex<Option<String>>>,
    rotated: &zyris::AccountCredential,
) -> Result<(), zyris::RotateError> {
    match store.save(rotated).await {
        Ok(()) => Ok(()),
        Err(e) => {
            *broke.lock().await = Some(e.to_string());
            Err(zyris::RotateError(e.to_string()))
        }
    }
}

impl AccountGrant {
    fn new(
        store: Arc<dyn CredentialStore>,
        url: String,
        request: zyris::EnrollRequest,
    ) -> AccountGrant {
        AccountGrant {
            store,
            url,
            request,
            ui: LogEnroll,
            held: tokio::sync::Mutex::new(None),
            store_broke: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// The account to ask for a bearer: the one being held, the one on disk, or a fresh enrollment.
    ///
    /// **An account whose credential is due for rotation is dropped and the file read again**, and
    /// that re-read is the whole reason two processes on one credential are survivable. Upstream's
    /// held credential went back through `Enroller::obtain()` whenever the access token was spent,
    /// and `obtain` opened by reading the file — so the second process found the pair the first had
    /// just written and simply used it. Holding an `Account` for the life of the process instead
    /// means both carry the same credential, reach 80% of the *same* `access_expires_at` at the
    /// same instant, and rotate from the same single-use refresh token. That is not a race to lose
    /// occasionally, it is an appointment — and attacca answers a replay past its 30-second grace
    /// with `revoke_all_for_node`.
    ///
    /// **This is not rare in a container, it is a rollout.** A rolling update runs the new pod
    /// before the old one terminates; `replicas: 2` over one `ReadWriteMany` volume does it
    /// permanently; `docker compose up --scale` does it by hand. Nothing here is a lock — there is
    /// none to be had — and re-reading only keeps the odds where they were.
    async fn account(&self) -> Result<Arc<zyris::Account>, CredentialsError> {
        if let Some(account) = self.usable().await {
            return Ok(account);
        }

        let credential = match self.stored().await? {
            Some(credential) => credential,
            None => self.enroll().await?,
        };
        let account = Arc::new(self.restore(credential));
        *self.held.lock().await = Some(account.clone());
        Ok(account)
    }

    /// The held account, if there is one and it is not already due to rotate.
    async fn usable(&self) -> Option<Arc<zyris::Account>> {
        let mut held = self.held.lock().await;
        let account = held.as_ref()?.clone();
        if account.credential().await.should_refresh(now_unix(), ACCESS_LIFETIME_SECS) {
            *held = None;
            return None;
        }
        Some(account)
    }

    /// A corrupt or unreadable credential is a reason to enroll again, not to die. A *refused* one
    /// is different — a world-readable key file — and refusing loudly is the whole point of that
    /// distinction, so it propagates rather than answering an exposed secret with a quiet
    /// re-enrollment.
    async fn stored(&self) -> Result<Option<zyris::AccountCredential>, CredentialsError> {
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

    /// Wrap a credential in an account that writes every rotation back to the store.
    ///
    /// **The hook runs before the rotation is adopted, and that ordering is the load-bearing part.**
    /// A refresh token is single-use: a process that started presenting a pair which never reached
    /// disk would present the spent one on its next start, and attacca reads a replay past its
    /// 30-second grace as a leaked chain. `zyris::Account` enforces the order; all we owe it is a
    /// hook that fails when the write failed.
    fn restore(&self, credential: zyris::AccountCredential) -> zyris::Account {
        let store = self.store.clone();
        let broke = self.store_broke.clone();
        zyris::Account::restore(&self.url, credential)
            .on_rotate(move |rotated| {
                let store = store.clone();
                let broke = broke.clone();
                async move { persist_rotation(&store, &broke, &rotated).await }
            })
            .build()
    }

    /// The reason this node must stop, if a rotation could not be stored.
    ///
    /// **Asked whether or not the dial would have worked.** A hook that failed means the server
    /// rotated and the pair on disk is spent, which is true no matter what the call it happened
    /// inside went on to return. `NeedsOperator` is the shade that ends the process (exit 2)
    /// instead of backing off into a replay — the same answer upstream gave, from the same fact.
    async fn cannot_go_on(&self) -> Option<CredentialsError> {
        let why = self.store_broke.lock().await.clone()?;
        Some(CredentialsError::NeedsOperator(format!(
            "a rotated credential could not be stored ({why}), so the one on disk is spent and \
             dialling again would replay it. Give this node a writable credential directory \
             (ZYRIS_CONFIG_DIR, or mount a volume) and start it again."
        )))
    }

    /// Ask for a code, put it in front of a person, and wait.
    ///
    /// **The renewal loop is ours because the library refuses to write it.** `Enrollment::renew`
    /// exists and nothing calls it on its own; without this the node would die at the ten-minute
    /// mark of the first code. It is bounded — see [`MAX_RENEWALS`].
    async fn enroll(&self) -> Result<zyris::AccountCredential, CredentialsError> {
        let mut enrollment =
            zyris::enroll(&self.url, self.request.clone()).await.map_err(enrollment_trouble)?;
        self.ui.show(enrollment.code());
        let mut renewals = 0u32;
        loop {
            // Hoisted out of the `match` so nothing borrows `enrollment` while the arm that has
            // to renew it runs.
            let progress = enrollment.poll().await.map_err(enrollment_trouble)?;
            match progress {
                // `poll` sleeps to the server's own cadence, `slow_down` included. A sleep here
                // would be a second clock, disagreeing with the one the server asked for.
                zyris::Progress::Waiting { .. } => {}
                zyris::Progress::Granted(credential) => {
                    // Stored **before** it is used, and before anything is told the approval took.
                    // A credential this process began dialling on but never wrote down would enroll
                    // again on the next start and leave a dead node row in the account behind each
                    // time — and in a container, "the next start" is every crash and every rollout.
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

    /// Lets go of the account held in memory. The next `bearer` goes back through
    /// [`account`](Self::account), which finds whatever the store now holds — nothing, once a
    /// revoked credential has been cleared — and enrolls.
    ///
    /// Private here. `zyris-code` publishes it because logging out has to reach it; this node has
    /// one caller, the `Revoked` branch of [`bearer`](Credentials::bearer).
    async fn forget(&self) {
        *self.held.lock().await = None;
    }

    /// Whether an account is being held right now. For the test that a due credential is dropped —
    /// there is no other way to see it.
    #[cfg(test)]
    async fn is_holding(&self) -> bool {
        self.held.lock().await.is_some()
    }

    #[cfg(test)]
    async fn hold(&self, credential: zyris::AccountCredential) {
        *self.held.lock().await = Some(Arc::new(self.restore(credential)));
    }

    /// A grant over whatever store the test hands it. Nothing in these tests reaches the network —
    /// the URL never resolves — but the grant has to exist to be asked anything.
    #[cfg(test)]
    fn for_test(store: Arc<dyn CredentialStore>) -> AccountGrant {
        AccountGrant::new(
            store,
            "wss://example.invalid/zyris/v1/ws".to_string(),
            zyris::EnrollRequest {
                name: "zyris-docker-node".to_string(),
                platform: "linux".to_string(),
                scopes: Vec::new(),
            },
        )
    }
}

#[async_trait::async_trait]
impl Credentials for AccountGrant {
    async fn bearer(&self) -> Result<String, CredentialsError> {
        let account = self.account().await?;
        let asked = account.bearer().await;
        // Before the answer is read, because a rotation that could not be stored is fatal whatever
        // this call returned — it may well have returned a perfectly good token, held over from
        // before the rotation the disk refused.
        if let Some(stop) = self.cannot_go_on().await {
            return Err(stop);
        }
        match asked {
            Ok(bearer) => Ok(bearer),
            // The server disowned this credential while we were holding it. Clearing the store and
            // letting go of the account sends the next dial back through `account`, which finds
            // nothing stored and enrolls — so a node whose grant chain was revoked prints a fresh
            // code instead of presenting a dead token until somebody deletes the file by hand.
            // `Unavailable` rather than `Fatal` is what buys that next dial: the run loop backs off
            // and comes round again, where `Fatal` would end the process.
            Err(zyris::EnrollError::Revoked) => {
                tracing::warn!("this credential was revoked; enrolling again");
                if let Err(e) = self.store.clear().await {
                    tracing::warn!(error = %e, "could not discard the revoked credential");
                }
                self.forget().await;
                Err(CredentialsError::Unavailable(
                    "this credential was revoked; asking for a new one".to_string(),
                ))
            }
            Err(e) => Err(enrollment_trouble(e)),
        }
    }

    async fn refresh(&self) -> Result<bool, CredentialsError> {
        let mut held = self.held.lock().await;
        // Nothing held means nothing was presented, so the refusal was not about a token of ours.
        let Some(account) = held.take() else { return Ok(false) };

        let forced = self.restore(due_now(account.credential().await));
        let asked = forced.bearer().await;
        if let Some(stop) = self.cannot_go_on().await {
            return Err(stop);
        }
        match asked {
            Ok(_) => {
                *held = Some(Arc::new(forced));
                Ok(true)
            }
            // The same conclusion the startup path reaches, and for the same reason: a node whose
            // grant chain was revoked while it was connected must not be left presenting the dead
            // token until a human deletes the file. The store is cleared here and nothing is put
            // back in `held`, so the next `bearer` enrolls and a fresh code appears.
            Err(zyris::EnrollError::Revoked) => {
                tracing::warn!("this credential was rejected on rotation; enrolling again");
                if let Err(e) = self.store.clear().await {
                    tracing::warn!(error = %e, "could not discard the revoked credential");
                }
                Ok(true)
            }
            Err(e) => Err(enrollment_trouble(e)),
        }
    }

    fn describe(&self) -> String {
        format!("device enrollment ({})", self.store.describe())
    }
}

/// The access-token lifetime attacca issues, used only to ask when a rotation is due.
///
/// **A copy of a constant `zyris::Account` keeps private** (`ACCESS_LIFETIME_SECS` in
/// `zyris-core/src/account.rs`). It has to be the same number: this is what decides when to drop a
/// held account and read the file again, and `Account` uses it to decide when to rotate. Read it
/// too large and the re-read never happens before the rotation it exists to get ahead of; read it
/// too small and every dial re-reads the file for nothing. If upstream changes it, change this.
const ACCESS_LIFETIME_SECS: i64 = 3600;

/// The same credential, stamped as already due for rotation.
///
/// **[`zyris::Account`] has no "rotate now"**: it decides from the credential's own expiry, at 80%
/// of a one-hour life. Upstream's `Enroller::force_refresh` could call the refresh endpoint
/// outright, and that is what answered the 401 a drifted container clock produces — without it a
/// node exits permanently on a condition it could have fixed itself, because the transport marks
/// 401 non-retriable and the run loop would spend its one rotation on a no-op.
///
/// So the copy handed to a throwaway account is aged instead. **Nothing false reaches disk**: the
/// stored credential is untouched and the only thing `on_rotate` ever writes is what came back
/// rotated. An expiry of *now* also means a rotation that fails leaves nothing presentable, so the
/// failure is reported rather than papered over with the token that was just refused.
fn due_now(credential: zyris::AccountCredential) -> zyris::AccountCredential {
    zyris::AccountCredential::new(
        credential.access_token,
        credential.refresh_token,
        credential.node_id,
        credential.node_name,
        credential.owner_email,
        now_unix(),
    )
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// How the run loop should read a failure that came from the enrollment or account layer.
///
/// Matched exhaustively on purpose: a shade added upstream must stop the build here rather than be
/// folded into "back off and try again", which is the answer that never surfaces anything.
fn enrollment_trouble(error: zyris::EnrollError) -> CredentialsError {
    match error {
        // **One scope the deployment does not know refuses the *whole* authorize request**:
        // attacca's axum `Json` extractor cannot read an enum variant it has never heard of and
        // answers 422, so nobody ever reaches the approval page and no code is ever shown. Naming
        // the scope is the difference between "enrollment is broken" and one line to delete from
        // `main.rs`'s `SCOPES`.
        zyris::EnrollError::ScopeUnknown { scope } => CredentialsError::NeedsOperator(format!(
            "this server does not know the scope {scope}; it must be removed from the list this \
             build asks for before enrollment can even show a code"
        )),
        // Somebody said no in the browser. Asking again is pestering them.
        e @ zyris::EnrollError::Denied => CredentialsError::NeedsOperator(e.to_string()),
        // All three are worth another dial rather than an exit. `Lapsed` and `Revoked` reaching
        // here mean the caller has already cleared what it had, so the next attempt enrolls; and a
        // server that is merely unreachable is usually a startup race, not a dead node.
        e @ (zyris::EnrollError::Lapsed
        | zyris::EnrollError::Revoked
        | zyris::EnrollError::Unreachable(_)) => CredentialsError::Unavailable(e.to_string()),
    }
}

/// A store failure that reached the caller needs a person.
///
/// [`AccountGrant::stored`] already swallows the discardable ones on the read path, so what is left
/// is either a refusal — an exposed secret — or a *write* that could not be kept. Retrying the
/// second would mean a fresh code on every restart and a dead node row in the account behind each
/// one, so neither is a reason to loop.
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

    fn stored() -> zyris::AccountCredential {
        zyris::AccountCredential::new(
            "a".into(),
            "r".into(),
            "n".into(),
            "zyris-docker-node".into(),
            "e@example.com".into(),
            i64::MAX,
        )
    }

    /// A credential due to rotate at a chosen moment. `access_expires_at` is what `should_refresh`
    /// reads, so this is the only knob a test needs to say "due" or "not yet".
    fn expiring_at(at: i64) -> zyris::AccountCredential {
        zyris::AccountCredential::new(
            "a".into(),
            "r".into(),
            "n".into(),
            "zyris-docker-node".into(),
            "e@example.com".into(),
            at,
        )
    }

    fn code() -> zyris::Code {
        zyris::Code {
            user_code: "WXQR-7KBD".into(),
            verification_uri: "https://attacca.example/settings/zyris/device".into(),
            expires_at: SystemTime::now() + Duration::from_secs(600),
        }
    }

    /// **A rotation that could not be stored stops this node instead of dialling again.**
    ///
    /// `zyris::Account` reports a hook refusal as `Unreachable`, which the run loop answers with
    /// backoff and another dial — but the server has already spent the refresh token by then, so
    /// every retry is a replay, and attacca answers a replay past its 30-second grace with
    /// `revoke_all_for_node`: every node under the credential, not just this one. `NeedsOperator`
    /// is what ends the process instead, which is the answer upstream's `Enroller` gave by
    /// persisting with `?`.
    ///
    /// This is the container's most likely failure — a read-only rootfs, no volume, a uid that
    /// cannot write — and the one whose symptom is that nothing at all looks wrong.
    #[tokio::test]
    async fn a_rotation_that_could_not_be_stored_stops_the_node() {
        let store = Arc::new(MemoryCredentialStore::default());
        store.save(&stored()).await.unwrap();
        let grant = AccountGrant::for_test(store.clone());
        *grant.store_broke.lock().await = Some("read-only file system".to_string());
        grant.hold(stored()).await;

        // The credential is nowhere near expiry, so this asks nothing of the network: the token it
        // would have handed back is perfectly good, and that is exactly the case being locked.
        match grant.bearer().await {
            Err(CredentialsError::NeedsOperator(why)) => {
                assert!(why.contains("read-only file system"), "the reason is lost: {why}");
            }
            other => panic!("a spent credential must not be dialled with again: {other:?}"),
        }
    }

    /// A store that refuses a rotation is **remembered**, not only refused.
    ///
    /// The other test starts from `store_broke` already set, so between them they lock the two
    /// halves: this one that a refusal fills the flag, that one that a filled flag stops the node.
    /// On its own either is comfortable and wrong — a hook that returned `Err` without recording it
    /// passes the second test and loses the deployment, because the run loop reads a bare `Err` as
    /// an outage and dials again with a credential the server has already spent.
    #[tokio::test]
    async fn a_store_that_refuses_a_rotation_is_remembered_not_just_refused() {
        /// Every write fails, the way a read-only rootfs does.
        #[derive(Debug, Default)]
        struct RefusingStore;

        #[async_trait::async_trait]
        impl CredentialStore for RefusingStore {
            async fn load(&self) -> Result<Option<zyris::AccountCredential>, CredentialStoreError> {
                Ok(None)
            }
            async fn save(
                &self,
                _credential: &zyris::AccountCredential,
            ) -> Result<(), CredentialStoreError> {
                Err(CredentialStoreError::Refused("read-only file system".to_string()))
            }
            async fn clear(&self) -> Result<(), CredentialStoreError> {
                Ok(())
            }
            fn describe(&self) -> String {
                "a store that refuses".to_string()
            }
        }

        let store: Arc<dyn CredentialStore> = Arc::new(RefusingStore);
        let broke = Arc::new(tokio::sync::Mutex::new(None));

        let refused = persist_rotation(&store, &broke, &stored()).await;

        assert!(refused.is_err(), "a rotation that was not written must not be reported as adopted");
        let remembered = broke.lock().await.clone();
        let why = remembered.expect(
            "the refusal was returned but not remembered, so the run loop will read it as an \
             outage and dial again with a spent credential",
        );
        assert!(why.contains("read-only file system"), "the reason is lost: {why}");
    }

    /// **A credential due to rotate is dropped and the file is read again.**
    ///
    /// Two processes on one credential file share one credential. Upstream went back to disk
    /// whenever its token was spent, so the second found the pair the first had just written and
    /// used it. Holding an account for the life of the process instead puts both on the same
    /// `access_expires_at`, so both rotate from the same single-use refresh token at the same
    /// instant — an appointment rather than a race, and the answer to it is `revoke_all_for_node`.
    /// A rolling update is exactly that arrangement.
    #[tokio::test]
    async fn a_credential_due_to_rotate_is_not_handed_back_from_memory() {
        let store = Arc::new(MemoryCredentialStore::default());
        let grant = AccountGrant::for_test(store);

        // Well inside its life: nothing to re-read, so what is held is what is used.
        grant.hold(expiring_at(now_unix() + ACCESS_LIFETIME_SECS)).await;
        assert!(grant.usable().await.is_some(), "a fresh credential is still good");

        // Past the 80% mark, which is where `Account` would rotate. The held one goes, and with it
        // the guarantee that this process rotates from a pair another one has already spent.
        grant.hold(expiring_at(now_unix() + 60)).await;
        assert!(grant.usable().await.is_none(), "a due credential was handed back");
        assert!(!grant.is_holding().await, "the due account is still held");
    }

    /// **The block has to carry both halves.** A code with nowhere to type it is not actionable,
    /// and this string is the entire user interface of enrolling a headless node. The device
    /// code — the secret half of the grant — is not in `zyris::Code` at all, so it cannot be
    /// printed by accident.
    #[test]
    fn the_printed_block_names_the_code_and_where_to_type_it() {
        let block = notice(&code());
        assert!(block.contains("WXQR-7KBD"), "the code is missing: {block}");
        assert!(block.contains("https://attacca.example/settings/zyris/device"));
        assert!(block.contains("expires in 10 minutes"), "no idea how long it lasts");
    }

    /// **A code that already lapsed still prints.** Renewal and the wall-clock conversion race, and
    /// `SystemTime::duration_since` answers a past instant with an error — panicking at the moment
    /// this process is telling somebody how to authorize it would be the worst place for one.
    #[test]
    fn a_code_that_already_expired_still_prints_rather_than_panicking() {
        let lapsed =
            zyris::Code { expires_at: SystemTime::now() - Duration::from_secs(60), ..code() };
        assert!(notice(&lapsed).contains("WXQR-7KBD"));
        assert_eq!(time_left(&lapsed), Duration::ZERO);
    }
}
