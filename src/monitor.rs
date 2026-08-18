//! The `monitor` capability — the reason this node exists.
//!
//! `zyris-caps` already declares the standard `file_io` and `terminal` tools. `monitor` is this
//! node's own capability, announced to Attacca so an agent can read system / Docker / Kubernetes
//! state and act on it. It wraps the pure readers in `system`, `docker` and `k8s`, and maps their
//! `Result<_, String>` errors onto the wire's `WireError`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zyris::{ErrorCode, WireError};

use crate::docker::{container_info, container_running, list_containers, ContainerInfo};
use crate::k8s::{available as k8s_available, nodes, pods, NodeInfo, PodInfo};
use crate::system::{process_list, process_running, system_snapshot, ProcessInfo, SystemSnapshot};

/// A single failing watch target, as the self-healing watcher reports it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Incident {
    /// Which kind of target broke: `process`, `container`, `k8s_pod`, `k8s_node`.
    pub kind: String,
    /// The target's name (a comm name, container name, pod name or node name).
    pub name: String,
    /// What the watcher observed, human-readable.
    pub detail: String,
}

fn map_err(e: String) -> WireError {
    WireError::new(ErrorCode::Other("monitor".into()), e)
}

/// What a `docker` action returned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ActionResult {
    pub ok: bool,
    /// `stdout` when the action succeeded, `stderr` otherwise.
    pub output: String,
}

fn run_action(args: &[&str]) -> ActionResult {
    match std::process::Command::new("docker").args(args).output() {
        Ok(out) => {
            if out.status.success() {
                ActionResult { ok: true, output: String::from_utf8_lossy(&out.stdout).trim().to_string() }
            } else {
                ActionResult { ok: false, output: String::from_utf8_lossy(&out.stderr).trim().to_string() }
            }
        }
        Err(e) => ActionResult { ok: false, output: e.to_string() },
    }
}

/// The capability this node announces to Attacca.
///
/// The doc comments on each method are what the model reads as the tool description — keep them
/// concrete about what the tool returns and what an agent can do with it.
#[zyris::capability(name = "monitor", version = 1)]
pub trait Monitor {
    /// Snapshot the node's system state: hostname, uptime, CPU%, load average, memory, swap,
    /// process count, and root-filesystem disk usage. Good first call when diagnosing an incident.
    async fn system_snapshot(&self) -> zyris::Result<SystemSnapshot>;

    /// List every process visible in this container's PID namespace, with pid, name, state, RSS,
    /// CPU seconds and command line.
    async fn process_list(&self) -> zyris::Result<Vec<ProcessInfo>>;

    /// Whether a process whose comm name equals `name` is currently running in this PID namespace.
    async fn process_running(&self, name: String) -> zyris::Result<bool>;

    /// List all Docker containers (including stopped), with id, name, image, state, running flag
    /// and status line. Requires the `docker` CLI and a mounted docker socket or context.
    async fn docker_list(&self) -> zyris::Result<Vec<ContainerInfo>>;

    /// Fetch one Docker container by name or id.
    async fn docker_container(&self, selector: String) -> zyris::Result<ContainerInfo>;

    /// Whether the named Docker container is currently running.
    async fn docker_running(&self, selector: String) -> zyris::Result<bool>;

    /// Start a stopped Docker container by name or id.
    async fn docker_start(&self, selector: String) -> zyris::Result<ActionResult>;

    /// Restart a Docker container by name or id (stops then starts it).
    async fn docker_restart(&self, selector: String) -> zyris::Result<ActionResult>;

    /// List all Kubernetes pods across every namespace, with phase, readiness, restarts, node and
    /// failure reason. Requires `kubectl` and a reachable cluster (or in-cluster config).
    async fn k8s_pods(&self) -> zyris::Result<Vec<PodInfo>>;

    /// List all Kubernetes nodes, with ready flag, roles and version.
    async fn k8s_nodes(&self) -> zyris::Result<Vec<NodeInfo>>;

    /// Whether Kubernetes is reachable at all. False when kubectl is absent or has no cluster.
    async fn k8s_available(&self) -> zyris::Result<bool>;
}

pub struct MonitorNode;

impl MonitorNode {
    pub fn new() -> MonitorNode {
        MonitorNode
    }
}

#[zyris::async_trait]
impl Monitor for MonitorNode {
    async fn system_snapshot(&self) -> zyris::Result<SystemSnapshot> {
        Ok(system_snapshot())
    }

    async fn process_list(&self) -> zyris::Result<Vec<ProcessInfo>> {
        Ok(process_list())
    }

    async fn process_running(&self, name: String) -> zyris::Result<bool> {
        Ok(process_running(&name))
    }

    async fn docker_list(&self) -> zyris::Result<Vec<ContainerInfo>> {
        list_containers().map_err(map_err)
    }

    async fn docker_container(&self, selector: String) -> zyris::Result<ContainerInfo> {
        container_info(&selector).map_err(map_err)
    }

    async fn docker_running(&self, selector: String) -> zyris::Result<bool> {
        Ok(container_running(&selector))
    }

    async fn docker_start(&self, selector: String) -> zyris::Result<ActionResult> {
        Ok(run_action(&["start", &selector]))
    }

    async fn docker_restart(&self, selector: String) -> zyris::Result<ActionResult> {
        Ok(run_action(&["restart", &selector]))
    }

    async fn k8s_pods(&self) -> zyris::Result<Vec<PodInfo>> {
        pods().map_err(map_err)
    }

    async fn k8s_nodes(&self) -> zyris::Result<Vec<NodeInfo>> {
        nodes().map_err(map_err)
    }

    async fn k8s_available(&self) -> zyris::Result<bool> {
        Ok(k8s_available())
    }
}
