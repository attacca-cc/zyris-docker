//! How this node proves who it is, as a hook with the simple answers already in the box.
//!
//! Something has to answer one question before every dial — *what bearer do I present?* — and there
//! are only a few real answers: a token from the environment, a token from a mounted file, or a
//! credential the node enrolled for itself. The first two ship here.
//!
//! **The third one lives in `crate::enroll`.** Upstream carried a `DeviceGrant` next to these two
//! and a `from_env` that picked between the three; the library-only zyris no longer ships a program
//! layer, so both moved. The order the sources are tried in is [`crate::enroll::source`], and for a
//! container the order is the whole design: a mounted `znt_` never expires, so a node given one
//! writes nothing, rotates nothing, and needs no volume. The device grant is the fallback for
//! somebody running this image on a laptop with no token yet.

use async_trait::async_trait;

/// Why a bearer could not be produced, in the three shades the run loop reacts to differently.
///
/// Written out rather than derived: every arm's message is just the string it carries, so a
/// `thiserror` derive would buy nothing that `Display` does not already say.
#[derive(Debug)]
pub enum CredentialsError {
    /// A person has to do something — approve the node, set a variable, fix a permission. The
    /// process exits 2 rather than restart-looping, so a supervisor (`restart: on-failure`,
    /// CrashLoopBackOff) does not spin forever on a condition no amount of retrying will change.
    NeedsOperator(String),
    /// Wrong in a way retrying will not fix: a revoked credential, a malformed token. Exits 1.
    Fatal(String),
    /// The credential *source* could not be reached — a server that timed out, a Secret on a mount
    /// that is not up yet. Retried with backoff, because this is usually a pod-start race.
    Unavailable(String),
}

impl std::fmt::Display for CredentialsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialsError::NeedsOperator(message)
            | CredentialsError::Fatal(message)
            | CredentialsError::Unavailable(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for CredentialsError {}

/// The bearer a node presents at the websocket upgrade.
///
/// [`bearer`](Self::bearer) is called immediately before *every* dial rather than once at startup.
/// That is the entire answer to mid-connection expiry: a token valid now is valid for the
/// handshake, and a connection that outlives its token is handled server-side by the heartbeat. It
/// also means an implementation may return a different token each time without telling anyone.
///
/// It is also why the run loop is ours rather than `zyris::Node::connect`: that one takes a fixed
/// token string and redials with it forever, which an account access token that expires in an hour
/// cannot survive.
#[async_trait]
pub trait Credentials: Send + Sync + 'static {
    /// The bearer to present right now.
    async fn bearer(&self) -> Result<String, CredentialsError>;

    /// Called once when a dial is refused as unauthorized, before giving up.
    ///
    /// Return `true` if the next dial is worth attempting — because a different credential is now
    /// available, or because this source has thrown away the dead one and the following
    /// [`bearer`](Self::bearer) will go and get a fresh one. The default is `false`: a source that
    /// hands back the same token every time has nothing to contribute here, and answering `true`
    /// would loop on a credential that will never work.
    async fn refresh(&self) -> Result<bool, CredentialsError> {
        Ok(false)
    }

    /// Where this credential comes from, for the one line a node logs at startup. Never a secret —
    /// a path, a variable name, or a token prefix at most.
    fn describe(&self) -> String;
}

/// What a static node token starts with. Attacca mints these; the prefix is what makes a mispasted
/// credential of some other kind diagnosable instead of a bare 401.
pub const NODE_TOKEN_PREFIX: &str = "znt_";

/// How much of a token is safe to log. The same prefix length the server stores and shows on the
/// node card, so a log line can be matched to a node in the UI without leaking the secret.
const TOKEN_DISPLAY_PREFIX: usize = 12;

/// The leading, non-secret part of a token.
pub fn token_prefix(token: &str) -> &str {
    &token[..token.len().min(TOKEN_DISPLAY_PREFIX)]
}

/// Reject anything that is not a node token, by prefix.
///
/// This exists to catch one specific mistake: pasting an `atk_` API key where a `znt_` node token
/// goes. Both are long opaque strings from the same dashboard, and without this check the only
/// symptom is a 401 at the upgrade with nothing to suggest what is actually wrong — which in a
/// container means a crash loop and a log full of `unauthorized`.
fn validate_node_token(token: &str, source: &str) -> Result<String, CredentialsError> {
    let token = token.trim();
    if token.is_empty() {
        return Err(CredentialsError::NeedsOperator(format!("{source} is empty")));
    }
    if !token.starts_with(NODE_TOKEN_PREFIX) {
        return Err(CredentialsError::Fatal(format!(
            "{source} does not look like a node token (expected a `znt_` prefix). API keys \
             (`atk_`) will not work here."
        )));
    }
    Ok(token.to_string())
}

/// A token held in memory for the life of the process.
pub struct StaticToken {
    token: String,
    source: String,
}

impl StaticToken {
    /// Trusts the caller: no prefix check, for a node that mints its own credentials or talks to
    /// something other than Attacca.
    ///
    /// **`#[cfg(test)]` because nothing in this node builds one.** Every production path goes
    /// through [`StaticToken::from_env`], which wants the `atk_` diagnostic; an unused constructor
    /// in a binary crate is dead code, and hiding it behind an `allow` would only hide the next one
    /// too.
    #[cfg(test)]
    pub fn new(token: impl Into<String>) -> StaticToken {
        StaticToken { token: token.into(), source: "a static token".to_string() }
    }

    /// Read `$ZYRIS_NODE_TOKEN`, checking that it is actually a node token.
    pub fn from_env() -> Result<Option<StaticToken>, CredentialsError> {
        let Some(raw) = std::env::var("ZYRIS_NODE_TOKEN").ok().filter(|v| !v.trim().is_empty())
        else {
            return Ok(None);
        };
        Ok(Some(StaticToken {
            token: validate_node_token(&raw, "ZYRIS_NODE_TOKEN")?,
            source: "$ZYRIS_NODE_TOKEN".to_string(),
        }))
    }
}

#[async_trait]
impl Credentials for StaticToken {
    async fn bearer(&self) -> Result<String, CredentialsError> {
        Ok(self.token.clone())
    }

    fn describe(&self) -> String {
        format!("{} ({}…)", self.source, token_prefix(&self.token))
    }
}

/// A token read from a file, fresh on every dial.
///
/// This is the shape Kubernetes Secrets and systemd's `LoadCredential=` mount, and **the reason to
/// prefer it over an environment variable is sharper in a container than anywhere**: an env var is
/// visible in `/proc`, inherited by every child process this node's `exec` capability spawns, and
/// printed by any crash reporter that dumps the environment.
///
/// Re-reading per dial rather than caching means a rotated Secret is picked up on the next
/// reconnect with no restart — which is the whole point of mounting one.
pub struct TokenFile {
    path: std::path::PathBuf,
}

impl TokenFile {
    pub fn at(path: impl Into<std::path::PathBuf>) -> TokenFile {
        TokenFile { path: path.into() }
    }

    /// Read `$ZYRIS_NODE_TOKEN_FILE`.
    pub fn from_env() -> Option<TokenFile> {
        std::env::var_os("ZYRIS_NODE_TOKEN_FILE").filter(|v| !v.is_empty()).map(TokenFile::at)
    }
}

#[async_trait]
impl Credentials for TokenFile {
    async fn bearer(&self) -> Result<String, CredentialsError> {
        let path = self.path.clone();
        let read = tokio::task::spawn_blocking(move || std::fs::read_to_string(&path))
            .await
            .map_err(|e| CredentialsError::Unavailable(e.to_string()))?;

        match read {
            Ok(contents) => {
                validate_node_token(&contents, &format!("the token in {}", self.path.display()))
            }
            // A mount that is not up yet is the common case at pod start, and it resolves itself.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(CredentialsError::Unavailable(format!(
                    "{} does not exist yet",
                    self.path.display()
                )))
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                Err(CredentialsError::NeedsOperator(format!(
                    "cannot read {}: {e}",
                    self.path.display()
                )))
            }
            Err(e) => Err(CredentialsError::Unavailable(format!(
                "cannot read {}: {e}",
                self.path.display()
            ))),
        }
    }

    fn describe(&self) -> String {
        self.path.display().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_static_token_is_returned_verbatim_and_never_logged_whole() {
        let creds = StaticToken::new("znt_abcdefghijklmnop");
        assert_eq!(creds.bearer().await.unwrap(), "znt_abcdefghijklmnop");
        assert!(!creds.describe().contains("ijklmnop"), "{}", creds.describe());
        assert!(!creds.refresh().await.unwrap(), "a fixed token has nothing to refresh to");
    }

    /// The one mistake worth a bespoke message: an `atk_` API key pasted where a node token goes.
    #[test]
    fn an_api_key_is_named_rather_than_left_to_401() {
        let error = validate_node_token("atk_looks_about_right", "ZYRIS_NODE_TOKEN").unwrap_err();
        assert!(matches!(error, CredentialsError::Fatal(_)));
        assert!(error.to_string().contains("atk_"), "{error}");
        assert!(validate_node_token("znt_fine", "x").is_ok());
    }

    #[tokio::test]
    async fn a_token_file_is_read_fresh_every_time_so_rotation_needs_no_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        let creds = TokenFile::at(&path);

        // A mount that is not up yet is retriable, not fatal: it is the normal pod-start race.
        assert!(matches!(creds.bearer().await, Err(CredentialsError::Unavailable(_))));

        std::fs::write(&path, "znt_first\n").unwrap();
        assert_eq!(creds.bearer().await.unwrap(), "znt_first", "trailing newline is trimmed");

        std::fs::write(&path, "znt_rotated").unwrap();
        assert_eq!(creds.bearer().await.unwrap(), "znt_rotated");
    }

    #[tokio::test]
    async fn a_token_file_holding_an_api_key_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "atk_wrong_kind").unwrap();
        let error = TokenFile::at(&path).bearer().await.unwrap_err();
        assert!(matches!(error, CredentialsError::Fatal(_)), "{error}");
    }
}
