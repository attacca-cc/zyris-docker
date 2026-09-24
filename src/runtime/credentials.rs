//! How this node proves who it is, as a hook with the simple answers already in the box.
//!
//! Something has to answer one question before every dial — *what bearer do I present?* — and there
//! are only a few real answers: a `zc_` credential from the environment, one from a mounted file,
//! or one the node enrolled for itself. The first two ship here.
//!
//! **The third one lives in `crate::enroll`.** The order the sources are tried in is
//! [`crate::enroll::source`], and for a container the order is the whole design: a mounted `zc_`
//! is issued once in Attacca, never expires, and needs no volume. The device grant is the fallback
//! for somebody running this image on a laptop with nothing issued yet.

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
    /// Wrong in a way retrying will not fix: a malformed credential. Exits 1.
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
/// [`bearer`](Self::bearer) is called immediately before *every* dial rather than once at startup,
/// so an implementation may hand back a different credential each time without telling anyone — a
/// replaced Secret, or a fresh enrollment after a refusal.
#[async_trait]
pub trait Credentials: Send + Sync + 'static {
    /// The bearer to present right now.
    async fn bearer(&self) -> Result<String, CredentialsError>;

    /// Called once when Attacca refuses the credential (HTTP 401), before giving up.
    ///
    /// Return `true` if the next dial is worth attempting — because this source has thrown the
    /// refused credential away and the following [`bearer`](Self::bearer) will enroll, or because a
    /// different one is already available. The default is `false`: a credential an operator
    /// mounted is theirs to replace, and answering `true` would loop on one that will never work.
    async fn forget_refused(&self) -> Result<bool, CredentialsError> {
        Ok(false)
    }

    /// Where this credential comes from, for the one line a node logs at startup. Never a secret —
    /// a path, a variable name, or a prefix at most.
    fn describe(&self) -> String;
}

/// What a credential starts with. Attacca issues these; the prefix is what makes a mispasted
/// secret of some other kind diagnosable instead of a bare 401.
pub const CREDENTIAL_PREFIX: &str = "zc_";

/// How much of a credential is safe to log. The same prefix length the server stores and shows,
/// so a log line can be matched to a credential in the UI without leaking the secret.
const TOKEN_DISPLAY_PREFIX: usize = 12;

/// The leading, non-secret part of a credential.
pub fn token_prefix(token: &str) -> &str {
    &token[..token.len().min(TOKEN_DISPLAY_PREFIX)]
}

/// Reject anything that is not a credential, by prefix.
///
/// It catches the two mistakes most likely to be made: an `atk_` API key from the same dashboard,
/// and a `znt_` node token kept from before credentials existed. Without it the only symptom of
/// either is a 401 at the upgrade — which in a container means a crash loop and a log full of
/// `unauthorized`.
fn validate_credential(secret: &str, source: &str) -> Result<String, CredentialsError> {
    let secret = secret.trim();
    if secret.is_empty() {
        return Err(CredentialsError::NeedsOperator(format!("{source} is empty")));
    }
    if !secret.starts_with(CREDENTIAL_PREFIX) {
        return Err(CredentialsError::Fatal(format!(
            "{source} does not look like a credential (expected a `zc_` prefix). API keys \
             (`atk_`) and node tokens (`znt_`) will not work here; issue a credential under \
             Settings → Zyris in Attacca."
        )));
    }
    Ok(secret.to_string())
}

/// A credential held in memory for the life of the process.
pub struct StaticToken {
    token: String,
    source: String,
}

impl StaticToken {
    /// Trusts the caller: no prefix check.
    ///
    /// **`#[cfg(test)]` because nothing in this node builds one.** Every production path goes
    /// through [`StaticToken::from_env`], which wants the prefix diagnostic.
    #[cfg(test)]
    pub fn new(token: impl Into<String>) -> StaticToken {
        StaticToken { token: token.into(), source: "a static credential".to_string() }
    }

    /// Read `$ZYRIS_CREDENTIAL`, checking that it is actually a credential.
    pub fn from_env() -> Result<Option<StaticToken>, CredentialsError> {
        let Some(raw) = std::env::var("ZYRIS_CREDENTIAL").ok().filter(|v| !v.trim().is_empty())
        else {
            return Ok(None);
        };
        Ok(Some(StaticToken {
            token: validate_credential(&raw, "ZYRIS_CREDENTIAL")?,
            source: "$ZYRIS_CREDENTIAL".to_string(),
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

/// A credential read from a file, fresh on every dial.
///
/// This is the shape Kubernetes Secrets and systemd's `LoadCredential=` mount, and **the reason to
/// prefer it over an environment variable is sharper in a container than anywhere**: an env var is
/// visible in `/proc`, inherited by every child process this node's `exec` capability spawns, and
/// printed by any crash reporter that dumps the environment.
///
/// Re-reading per dial rather than caching means a replaced Secret is picked up on the next
/// reconnect with no restart.
pub struct TokenFile {
    path: std::path::PathBuf,
}

impl TokenFile {
    pub fn at(path: impl Into<std::path::PathBuf>) -> TokenFile {
        TokenFile { path: path.into() }
    }

    /// Read `$ZYRIS_CREDENTIAL_FILE`.
    pub fn from_env() -> Option<TokenFile> {
        std::env::var_os("ZYRIS_CREDENTIAL_FILE").filter(|v| !v.is_empty()).map(TokenFile::at)
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
            Ok(contents) => validate_credential(
                &contents,
                &format!("the credential in {}", self.path.display()),
            ),
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
    async fn a_static_credential_is_returned_verbatim_and_never_logged_whole() {
        let creds = StaticToken::new("zc_abcdefghijklmnop");
        assert_eq!(creds.bearer().await.unwrap(), "zc_abcdefghijklmnop");
        assert!(!creds.describe().contains("ijklmnop"), "{}", creds.describe());
        assert!(
            !creds.forget_refused().await.unwrap(),
            "a mounted credential is the operator's to replace, not this node's to forget"
        );
    }

    /// The two mistakes worth a bespoke message: an API key, and a node token kept from before
    /// credentials existed.
    #[test]
    fn a_key_or_an_old_node_token_is_named_rather_than_left_to_401() {
        for wrong in ["atk_looks_about_right", "znt_from_before_credentials"] {
            let error = validate_credential(wrong, "ZYRIS_CREDENTIAL").unwrap_err();
            assert!(matches!(error, CredentialsError::Fatal(_)), "{wrong}");
            assert!(error.to_string().contains("zc_"), "{error}");
        }
        assert!(validate_credential("zc_fine", "x").is_ok());
    }

    #[tokio::test]
    async fn a_credential_file_is_read_fresh_every_time_so_replacing_it_needs_no_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credential");
        let creds = TokenFile::at(&path);

        // A mount that is not up yet is retriable, not fatal: it is the normal pod-start race.
        assert!(matches!(creds.bearer().await, Err(CredentialsError::Unavailable(_))));

        std::fs::write(&path, "zc_first\n").unwrap();
        assert_eq!(creds.bearer().await.unwrap(), "zc_first", "trailing newline is trimmed");

        std::fs::write(&path, "zc_replaced").unwrap();
        assert_eq!(creds.bearer().await.unwrap(), "zc_replaced");
    }

    #[tokio::test]
    async fn a_credential_file_holding_an_api_key_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credential");
        std::fs::write(&path, "atk_wrong_kind").unwrap();
        let error = TokenFile::at(&path).bearer().await.unwrap_err();
        assert!(matches!(error, CredentialsError::Fatal(_)), "{error}");
    }
}
