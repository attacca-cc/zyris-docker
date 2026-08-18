//! zyris-docker configuration.
//!
//! The zyris runtime already reads the standard `ZYRIS_*` variables (`ZYRIS_SERVER_URL`,
//! `ZYRIS_NODE_NAME`, `ZYRIS_PROFILE`, `ZYRIS_SCOPES`) and resolves credentials from
//! `ZYRIS_NODE_TOKEN` / `ZYRIS_NODE_TOKEN_FILE`. Everything else this node needs lives here, under a
//! `ZYRISD_` prefix so it can never collide with the runtime's own variables.

use std::time::Duration;

/// Every option zyris-docker reads beyond what the zyris runtime handles.
#[derive(Debug, Clone)]
pub struct Config {
    /// How often the self-healing watcher samples system, container and Kubernetes state.
    pub monitor_interval: Duration,
    /// Process names (from `/proc/<pid>/comm`) that must be running. An absent one is an incident.
    pub watch_processes: Vec<String>,
    /// Docker container names that must be running. A stopped one is an incident.
    pub watch_containers: Vec<String>,
    /// Whether to watch Kubernetes pods and nodes (requires `kubectl` and a kubeconfig).
    pub watch_k8s: bool,
    /// The agent id self-healing sessions are opened against. When unset, the first agent the node
    /// can read is used.
    pub heal_agent_id: Option<String>,
    /// Project id to file self-healing sessions under. Defaults to the account's default project.
    pub heal_project_id: Option<String>,
    /// System instructions attached to every self-healing session.
    pub heal_preamble: String,
    /// Paths inside the container that Attacca is allowed to touch through `file_io`. Relative to
    /// the container root; default is the whole container filesystem.
    pub file_roots: Vec<String>,
    /// Hard cap on how long any `exec` may run. Callers may ask for less, never more.
    pub exec_timeout: Duration,
}

fn env_str(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

fn env_bool(key: &str) -> bool {
    env_str(key).map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on")).unwrap_or(false)
}

fn env_csv(key: &str) -> Vec<String> {
    env_str(key)
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn env_duration_secs(key: &str, default: u64) -> Duration {
    env_str(key)
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(default))
}

impl Config {
    pub fn from_env() -> Config {
        Config {
            monitor_interval: env_duration_secs("ZYRISD_MONITOR_INTERVAL_SECS", 30),
            watch_processes: env_csv("ZYRISD_WATCH_PROCESSES"),
            watch_containers: env_csv("ZYRISD_WATCH_CONTAINERS"),
            watch_k8s: env_bool("ZYRISD_WATCH_K8S"),
            heal_agent_id: env_str("ZYRISD_HEAL_AGENT_ID"),
            heal_project_id: env_str("ZYRISD_HEAL_PROJECT_ID"),
            heal_preamble: env_str("ZYRISD_HEAL_PREAMBLE").unwrap_or_else(|| {
                "You are the self-healing incident responder for this container node. An incident \
                 was detected on the node's system, Docker or Kubernetes state. Diagnose the root \
                 cause with the node's `monitor` and `exec` capabilities, resolve it if you can \
                 (restart a stopped service or container, recover a pod), and then report back \
                 concisely: what broke, what you found, what you did, and what remains."
                    .to_string()
            }),
            file_roots: env_csv("ZYRISD_FILE_ROOTS"),
            exec_timeout: env_duration_secs("ZYRISD_EXEC_TIMEOUT_SECS", 120),
        }
    }
}

/// Max bytes each `exec` stream (stdout, stderr) may carry back before surplus is discarded.
const DEFAULT_MAX_OUTPUT_BYTES: usize = 256 * 1024;

impl Config {
    /// Cap for a single `exec` output stream.
    pub fn max_output_bytes(&self) -> usize {
        env_str("ZYRISD_MAX_OUTPUT_BYTES")
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_MAX_OUTPUT_BYTES)
    }
}
