//! The program layer: credentials, where they are kept, and the loop that keeps this node dialled.
//!
//! **Upstream deleted all of this when `zyris` became a library.** `zyris::runtime::{Runner,
//! RunConfig, RunError}`, `zyris::runtime::credentials::*` and `zyris::enroll::{CredentialStore,
//! FileCredentialStore, …}` are gone from the dependency, and that is the right call rather than a
//! regression: a library cannot decide a program's supervision story. How long to back off, when a
//! refusal is worth one more rotation, whether a dead credential exits 1 or 2 for a supervisor to
//! read, where in a container a secret may be written — every one of those is a property of the
//! program, and a library that answers them makes every node that disagrees fight it.
//!
//! So this node owns them now. The code here is a port of `zyris-code`'s port, kept close to it on
//! purpose: each of these is a small decision that is easy to get subtly wrong once and then carry
//! forever, and the comments naming the incident behind each one are the most valuable part of what
//! moved. Where the shape had to change for a headless container node, the comment says why.
//!
//! **What a container changed, and nothing else did.** Three things:
//!
//! - `NodeKind` moved out of [`RunConfig`] onto `zyris::NodeBuilder`, because the node is assembled
//!   by the caller now (see [`Runner::new`]) and a field nothing reads is a field that drifts.
//! - `RunError::exit_code` answers with an `i32`, because this program leaves through
//!   `std::process::exit` rather than by returning `ExitCode` from `main`, and an `ExitCode` cannot
//!   be turned back into a number. The table it encodes — 2 when a person must act, 1 otherwise —
//!   is the whole point and is unchanged.
//! - The run loop stops on `SIGTERM` as well as `Ctrl-C`. `docker stop` and a Kubernetes pod
//!   eviction both send `SIGTERM`; a node that only listens for `Ctrl-C` answers them by being
//!   `SIGKILL`ed ten seconds later, having never sent the close frame that retires it server-side.
//!
//! What did **not** move is anything the library still does: the handshake, the reconnect
//! primitives, the device-grant flow, and the account layer that rotates a refresh token. `Node`,
//! `Account` and `zyris::enroll` are still upstream's, and this layer is only the loop around them.

pub mod credentials;
mod runner;
pub mod store;

pub use credentials::{Credentials, CredentialsError, StaticToken, TokenFile};
pub use runner::{RunConfig, RunError, Runner};
pub use store::{credential_dir, CredentialStore, CredentialStoreError, FileCredentialStore};
