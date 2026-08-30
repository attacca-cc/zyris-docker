//! Where this node keeps its account credential between runs.
//!
//! **This layer used to be upstream's** — `zyris::enroll::store` and `zyris::enroll::file_store` —
//! and moved here when zyris became a library with no program layer of its own. The seam is
//! unchanged, because the reason for it is: what holds a credential varies far more than the
//! enrollment flow does. A laptop wants a file under `$HOME`, a pod wants a Secret, a test wants
//! nothing at all. That is a trait, not a path, which is why [`CredentialStore`] is the seam and
//! [`FileCredentialStore`] is merely the default behind it.
//!
//! What gets stored is [`zyris::AccountCredential`], and **it is field-for-field the old
//! `StoredCredential` with the same `version = 1`**. Do not change the JSON and do not change the
//! file name: any node that has already enrolled reads its credential back by exactly these rules,
//! and a change to either answers a perfectly good credential with an enrollment code.
//!
//! Be honest about the threat model of the file backend: a file on disk cannot be protected from
//! anyone who can become the user that owns it, and in this image that user also drives `exec`.
//! For anything shared the right answer is a static `znt_` out of a secret manager, which is
//! exactly why [`TokenFile`](crate::runtime::credentials::TokenFile) is the *first* source tried.
//! What this backend can do is stop a credential leaking through a permissive umask or a restored
//! tarball, and it does.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use zyris::AccountCredential;

/// Bumped only on an incompatible change. A file from the future is refused rather than guessed
/// at, because guessing wrong here means a node that authenticates as something unintended.
///
/// **This must stay equal to the version `zyris::AccountCredential::new` stamps.** Upstream keeps
/// its own copy of the number private, so there is nothing to import; the two agree at 1 today and
/// that agreement is the only reason an already-enrolled node still loads its credential. If
/// upstream ever bumps its version, this has to move with it.
const CREDENTIAL_VERSION: u32 = 1;

/// Where the credential goes when nobody said otherwise.
///
/// **Not under `$HOME`, and not under a file root.** Two reasons, both specific to this image:
///
/// - The Dockerfile creates the `zyris` user with no home directory (`useradd -r`, no `-m`), so an
///   XDG-style fallback resolves to a path that does not exist and cannot be created. Run the same
///   image as root and it resolves instead to `/root/.config/...`, which lives in the *writable
///   container layer* — discarded on `docker rm` and on every rollout, so the node would silently
///   re-enroll on each restart and leave a dead node row in the account behind each one.
/// - `/data` is the default `ZYRISD_FILE_ROOTS`, which is exactly what `file_io.read` and
///   `terminal.exec` are allowed to touch. A refresh token there is a refresh token the agent can
///   read. The path gate denies the credential directory as well, but a gate is a net and a
///   directory outside the roots is a wall.
///
/// It is declared a `VOLUME` in the Dockerfile so a credential survives the container it was
/// written in; name that volume and it survives the container being recreated too.
const DEFAULT_CREDENTIAL_DIR: &str = "/var/lib/zyris-docker";

/// The one answer to *where does this node keep its credential*.
///
/// **One function, because the gate has to deny exactly what the store writes.** `main.rs` uses
/// this both as the store's own answer (via [`FileCredentialStore::for_server`], which calls it)
/// and to build the `file_io` deny list. The version of this node before the port had two answers
/// that disagreed — the deny list guarded `$HOME/.zyris` while the runtime it was guarding against
/// wrote to `$XDG_CONFIG_HOME/zyris` — so the gate denied a directory that held nothing.
///
/// **A `$ZYRIS_CONFIG_DIR` a person gave is used exactly**, with no app name appended: they meant
/// that location. Unlike upstream's version this cannot fail — this node's directory is either
/// given or a fixed path, so there is no "could not determine a config directory" case to report.
pub fn credential_dir() -> PathBuf {
    std::env::var_os("ZYRIS_CONFIG_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CREDENTIAL_DIR))
}

/// What went wrong reaching a credential, in the only two shades the caller can act on.
///
/// The distinction is load-bearing: on startup a node *discards* a credential it cannot use and
/// enrolls again, but a credential it must not use is an operator's problem and has to be said out
/// loud. Collapsing the two would turn a leaked secret into a silent re-enrollment.
///
/// Upstream carried a third, `Other`, so a third-party backend could report something this crate
/// cannot classify. **Dropped here**: this node has exactly two backends, both in this file, and a
/// variant nothing constructs is a variant nothing tests.
#[derive(Debug)]
pub enum CredentialStoreError {
    /// The credential may exist, but using it would be wrong and someone needs to know — a
    /// world-readable key file. Never discarded silently.
    Refused(String),
    /// Unreadable, corrupt, or written by a version this build does not understand. Safe to throw
    /// away and enroll again.
    Unusable(String),
}

impl std::fmt::Display for CredentialStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialStoreError::Refused(message) | CredentialStoreError::Unusable(message) => {
                f.write_str(message)
            }
        }
    }
}

impl std::error::Error for CredentialStoreError {}

impl CredentialStoreError {
    /// Whether the caller may respond by clearing the credential and starting over.
    pub fn is_discardable(&self) -> bool {
        matches!(self, CredentialStoreError::Unusable(_))
    }
}

/// Where this node's credentials live between runs.
///
/// Async because the interesting backends are: a keychain prompts, a secret manager is a network
/// call. The default file backend does blocking IO inside these methods, which is bounded by one
/// small read or write per rotation.
#[async_trait]
pub trait CredentialStore: Send + Sync + 'static {
    /// The stored credential, or `None` when this node has never enrolled.
    async fn load(&self) -> Result<Option<AccountCredential>, CredentialStoreError>;
    /// Write, replacing whatever was there. Callers persist *before* using a credential, so a
    /// backend that can be atomic should be.
    async fn save(&self, credential: &AccountCredential) -> Result<(), CredentialStoreError>;
    /// Forget a credential the server will never honour again, so the next start enrolls cleanly
    /// instead of looping on it. Clearing nothing is success, not an error.
    async fn clear(&self) -> Result<(), CredentialStoreError>;
    /// Where this backend keeps things, for the one line a node logs at startup. Must never
    /// contain a secret — this is a path, not a token.
    fn describe(&self) -> String;
}

/// Keeps a credential for exactly as long as the process lives.
///
/// It exists so the enrollment flow can be exercised end to end without touching a filesystem —
/// `enroll.rs`'s tests build every `AccountGrant` on top of this. **`#[cfg(test)]` because nothing
/// outside the tests builds one**: a container using it in earnest would re-enroll on every
/// restart, which is the failure this whole module exists to avoid.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct MemoryCredentialStore {
    held: std::sync::Mutex<Option<AccountCredential>>,
}

#[cfg(test)]
#[async_trait]
impl CredentialStore for MemoryCredentialStore {
    async fn load(&self) -> Result<Option<AccountCredential>, CredentialStoreError> {
        Ok(self.held.lock().expect("credential mutex poisoned").clone())
    }

    async fn save(&self, credential: &AccountCredential) -> Result<(), CredentialStoreError> {
        *self.held.lock().expect("credential mutex poisoned") = Some(credential.clone());
        Ok(())
    }

    async fn clear(&self) -> Result<(), CredentialStoreError> {
        *self.held.lock().expect("credential mutex poisoned") = None;
        Ok(())
    }

    fn describe(&self) -> String {
        "memory (this credential is lost on restart)".to_string()
    }
}

/// What the file backend can fail with, before it is classified into a [`CredentialStoreError`].
///
/// Upstream also had a `NoConfigDir`. **Dropped**, because [`credential_dir`] cannot fail here.
#[derive(Debug)]
pub enum StoreError {
    Permissive { path: String, mode: u32 },
    UnknownVersion { found: u32 },
    Corrupt(serde_json::Error),
    Io(io::Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Says the fix, not just the fault: the person reading this is at a shell.
            StoreError::Permissive { path, mode } => write!(
                f,
                "credential file {path} is readable by other users (mode {mode:04o}); \
                 run: chmod 600 {path}"
            ),
            StoreError::UnknownVersion { found } => write!(
                f,
                "credential file was written by a newer version \
                 ({found}, expected {CREDENTIAL_VERSION})"
            ),
            StoreError::Corrupt(error) => write!(f, "credential file is corrupt: {error}"),
            StoreError::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::Corrupt(error) => Some(error),
            StoreError::Io(error) => Some(error),
            StoreError::Permissive { .. } | StoreError::UnknownVersion { .. } => None,
        }
    }
}

impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> StoreError {
        StoreError::Io(error)
    }
}

impl From<StoreError> for CredentialStoreError {
    fn from(error: StoreError) -> CredentialStoreError {
        match error {
            // An exposed secret is not a reason to quietly enroll again.
            StoreError::Permissive { .. } => CredentialStoreError::Refused(error.to_string()),
            // A file this build cannot read is a reason to enroll again, not to die. `Io` is here
            // deliberately: `NotFound` is already reported as "no credential", so what remains is a
            // file that exists and cannot be read, and looping on it forever helps nobody.
            //
            // **A read-only or unwritable directory does not arrive here.** That is a *write*
            // failure, and it reaches the caller through `on_rotate` — see `AccountGrant`'s
            // `store_broke`, which is what stops the node rather than letting it dial on a spent
            // refresh token. Which is the common case in a container with no volume mounted.
            StoreError::UnknownVersion { .. } | StoreError::Corrupt(_) | StoreError::Io(_) => {
                CredentialStoreError::Unusable(error.to_string())
            }
        }
    }
}

/// A credential kept in one file, private to the user running the node.
pub struct FileCredentialStore {
    path: PathBuf,
}

impl FileCredentialStore {
    /// The conventional location for a given deployment URL and profile.
    ///
    /// One file per `(deployment, profile)` so two nodes started against different servers cannot
    /// clobber each other, and no locking is needed to make that true.
    ///
    /// **The name is not ours to change.** `<server>-<profile>.json` by this exact rule is what
    /// every node that has already enrolled has on disk; change it and a node with a perfectly good
    /// credential asks to be enrolled again.
    pub fn for_server(server_url: &str, profile: &str) -> FileCredentialStore {
        FileCredentialStore::at(credential_dir().join(file_name(server_url, profile)))
    }

    /// An exact path, for a node whose location is decided by something other than this module.
    pub fn at(path: impl Into<PathBuf>) -> FileCredentialStore {
        FileCredentialStore { path: path.into() }
    }
}

#[async_trait]
impl CredentialStore for FileCredentialStore {
    async fn load(&self) -> Result<Option<AccountCredential>, CredentialStoreError> {
        Ok(load(&self.path)?)
    }

    async fn save(&self, credential: &AccountCredential) -> Result<(), CredentialStoreError> {
        Ok(save(&self.path, credential)?)
    }

    async fn clear(&self) -> Result<(), CredentialStoreError> {
        Ok(clear(&self.path)?)
    }

    fn describe(&self) -> String {
        self.path.display().to_string()
    }
}

/// The file name for a deployment and profile, split out of [`FileCredentialStore::for_server`] so
/// the naming rule can be pinned by a test without setting `$ZYRIS_CONFIG_DIR` — that variable is
/// process-global, and a test that sets it changes the answer every other test gets.
fn file_name(server_url: &str, profile: &str) -> String {
    format!("{}-{}.json", slugify(server_url), slugify(profile))
}

/// Read a stored credential, or `None` when there is none yet.
///
/// A file with group or other bits set is **refused**, the way `ssh` refuses a world-readable
/// private key. This is the cheapest possible mitigation for a credential restored from a tarball
/// or created under a permissive umask, and refusing is safer than silently repairing: the
/// operator should know it was exposed.
fn load(path: &Path) -> Result<Option<AccountCredential>, StoreError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(StoreError::Permissive { path: path.display().to_string(), mode });
        }
    }

    let credential: AccountCredential =
        serde_json::from_slice(&bytes).map_err(StoreError::Corrupt)?;
    if credential.version != CREDENTIAL_VERSION {
        return Err(StoreError::UnknownVersion { found: credential.version });
    }
    Ok(Some(credential))
}

/// Write atomically: temp file, `sync_all`, rename. A node killed mid-write must not come back to
/// a half-written credential, because that is indistinguishable from a corrupt one and would force
/// a re-enrollment that needed a human — and in a container `SIGKILL` mid-write is not exotic, it
/// is what happens ten seconds after every `docker stop`.
fn save(path: &Path, credential: &AccountCredential) -> Result<(), StoreError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }

    let temp = path.with_extension("tmp");
    let bytes = serde_json::to_vec_pretty(credential).map_err(StoreError::Corrupt)?;
    {
        use std::io::Write;
        let mut file = fs::File::create(&temp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Set before writing, so the secret is never briefly on disk under the umask's mode.
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(&temp, path)?;
    Ok(())
}

/// Forget a credential the server no longer honours, so the next start enrolls cleanly instead of
/// looping on a token that will never work again.
fn clear(path: &Path) -> Result<(), StoreError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Reduce a URL or profile name to something safe as a filename component.
fn slugify(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_dash = false;
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            out.extend(ch.to_lowercase());
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
        if out.len() >= 48 {
            break;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "default".to_string()
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential() -> AccountCredential {
        AccountCredential::new(
            "zna_access".into(),
            "znr_refresh".into(),
            "node-id".into(),
            "zyris-docker-node".into(),
            "allen@example.com".into(),
            1_000_000,
        )
    }

    #[tokio::test]
    async fn memory_store_round_trips() {
        let store = MemoryCredentialStore::default();
        assert_eq!(store.load().await.unwrap(), None);
        store.save(&credential()).await.unwrap();
        assert_eq!(store.load().await.unwrap().unwrap(), credential());
        store.clear().await.unwrap();
        assert_eq!(store.load().await.unwrap(), None);
        // Clearing nothing is success, so a node that never enrolled can still take the
        // credential-was-rejected branch without dying on the cleanup.
        store.clear().await.unwrap();
    }

    /// The one classification the startup path branches on.
    #[test]
    fn only_unusable_may_be_thrown_away() {
        assert!(CredentialStoreError::Unusable("corrupt".into()).is_discardable());
        assert!(!CredentialStoreError::Refused("mode 0644".into()).is_discardable());
    }

    /// **The credential must not live where the agent can read it.** `/data` is the image's default
    /// `ZYRISD_FILE_ROOTS`, which is precisely the set `file_io` and `exec` may touch; a refresh
    /// token inside it re-issues this node's identity without this machine. The path gate denies
    /// the credential directory too, but that is a net over a directory that should not have been
    /// reachable in the first place.
    #[test]
    fn the_credential_directory_is_not_inside_the_default_file_root() {
        let dir = Path::new(DEFAULT_CREDENTIAL_DIR);
        assert!(dir.is_absolute(), "a relative directory follows the working directory around");
        assert!(!dir.starts_with("/data"), "the agent may read everything under the file roots");
    }

    /// `bearer` immediately before each dial is the whole mid-connection-expiry story, so the skew
    /// boundary is the thing worth pinning. The method is upstream's — this stays as a
    /// characterization test, because our dial loop is built on the answer it gives.
    #[test]
    fn bearer_expires_early_by_the_skew_allowance() {
        let credential = credential();
        assert_eq!(credential.bearer(0, 30), Some("zna_access"));
        assert_eq!(credential.bearer(999_969, 30), Some("zna_access"));
        // 30 seconds out with a 30-second allowance: refuse, rather than race the handshake.
        assert_eq!(credential.bearer(999_970, 30), None);
        assert_eq!(credential.bearer(2_000_000, 30), None);
    }

    #[test]
    fn refresh_fires_at_eighty_percent_of_the_lifetime() {
        let credential = credential();
        // A one-hour token expiring at 1_000_000 was issued at 996_400; 80% of the way is 999_280.
        assert!(!credential.should_refresh(999_279, 3600));
        assert!(credential.should_refresh(999_280, 3600));
    }

    /// A credential file written by any build that shares the `version = 1` JSON must still load.
    /// Spelled out as bytes rather than round-tripped, so a change to the struct that breaks an
    /// enrolled node has to fail here first.
    #[test]
    fn a_credential_file_in_the_stored_format_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wss-attacca-cc-api-zyris-v1-ws-default.json");
        fs::write(
            &path,
            br#"{"version":1,"access_token":"zna_access","refresh_token":"znr_refresh",
                "node_id":"node-id","node_name":"zyris-docker-node",
                "owner_email":"allen@example.com","access_expires_at":1000000}"#,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(load(&path).unwrap().unwrap(), credential());
    }

    #[tokio::test]
    async fn save_then_load_round_trips_through_the_trait() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileCredentialStore::at(dir.path().join("nested").join("creds.json"));
        assert_eq!(store.load().await.unwrap(), None, "a missing file is not an error");

        store.save(&credential()).await.unwrap();
        assert_eq!(store.load().await.unwrap().unwrap(), credential());

        store.clear().await.unwrap();
        assert_eq!(store.load().await.unwrap(), None);
        store.clear().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_file_is_private_and_a_permissive_one_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds.json");
        let store = FileCredentialStore::at(&path);
        store.save(&credential()).await.unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777, 0o700);

        // A credential restored from a tarball, or written under a lax umask, must be refused
        // rather than silently used — and refused in the shade that never gets thrown away, or the
        // node would answer an exposed secret by quietly enrolling again.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = store.load().await.unwrap_err();
        assert!(matches!(error, CredentialStoreError::Refused(_)));
        assert!(!error.is_discardable());
    }

    #[tokio::test]
    async fn a_file_from_the_future_is_refused_rather_than_guessed_at() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds.json");
        let mut future = credential();
        future.version = CREDENTIAL_VERSION + 1;
        save(&path, &future).unwrap();

        let error = FileCredentialStore::at(&path).load().await.unwrap_err();
        assert!(error.is_discardable(), "a file this build cannot read is re-enrollable");
    }

    #[tokio::test]
    async fn corrupt_json_is_discardable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds.json");
        fs::write(&path, b"{not json").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(FileCredentialStore::at(&path).load().await.unwrap_err().is_discardable());
    }

    /// One file per (deployment, profile), so concurrent starts against different servers cannot
    /// clobber each other and no locking is needed.
    #[test]
    fn paths_are_per_deployment_and_per_profile() {
        let prod = file_name("wss://attacca.example/zyris/v1/ws", "default");
        let staging = file_name("wss://staging.attacca.example/zyris/v1/ws", "default");
        let other = file_name("wss://attacca.example/zyris/v1/ws", "builder");
        assert_ne!(prod, staging);
        assert_ne!(prod, other);

        let store = FileCredentialStore::at(Path::new("/cfg").join(&prod));
        assert!(store.describe().starts_with("/cfg"));
        assert!(store.describe().ends_with(".json"));
    }

    /// The file name an enrolled node already has on disk. Spelled out rather than derived, so that
    /// a change to `slugify` has to change this line too and cannot pass unnoticed.
    #[test]
    fn the_name_on_disk_is_the_one_an_enrolled_node_already_has() {
        assert_eq!(
            file_name("wss://attacca.cc/api/zyris/v1/ws", "default"),
            "wss-attacca-cc-api-zyris-v1-ws-default.json"
        );
    }

    #[test]
    fn slugify_is_filename_safe() {
        assert_eq!(slugify("wss://attacca.example/zyris/v1/ws"), "wss-attacca-example-zyris-v1-ws");
        assert_eq!(slugify("///"), "default");
        assert_eq!(slugify(""), "default");
        assert!(!slugify("a/../../etc/passwd").contains('/'));
    }
}
