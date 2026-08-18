//! Kubernetes pod and node state, queried through the `kubectl` CLI.
//!
//! Reading the API directly would pull the whole `kube` stack; this node instead shells out to
//! `kubectl` with `-o json` and walks the JSON. `kubectl` must be in the image and a kubeconfig
//! mounted (in-cluster service accounts work too, since kubectl auto-discovers
//! `/var/run/secrets/kubernetes.io/serviceaccount`).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One pod across all namespaces.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PodInfo {
    pub namespace: String,
    pub name: String,
    /// Pod phase: `Running`, `Pending`, `Succeeded`, `Failed`, `Unknown`.
    pub phase: String,
    /// Ready containers / total containers.
    pub ready: String,
    /// Cumulative container restarts.
    pub restarts: u32,
    /// Node the pod is scheduled on (empty while unscheduled).
    pub node: String,
    /// Reason for a non-running pod, if the pod has one set.
    pub reason: String,
}

/// One Kubernetes node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct NodeInfo {
    pub name: String,
    /// Whether the node reports `Ready=True`.
    pub ready: bool,
    /// Roles, e.g. `control-plane`, `worker`.
    pub roles: Vec<String>,
    /// Kubelet/kube-proxy version string.
    pub version: String,
}

fn run_kubectl(args: &[&str]) -> Result<serde_json::Value, String> {
    let out = std::process::Command::new("kubectl")
        .args(args)
        .output()
        .map_err(|e| format!("kubectl unavailable: {e}"))?;
    if out.status.success() {
        serde_json::from_slice(&out.stdout).map_err(|e| format!("bad kubectl output: {e}"))
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// All pods, newest name order as kubectl returns them.
pub fn pods() -> Result<Vec<PodInfo>, String> {
    let v = run_kubectl(&["get", "pods", "-A", "-o", "json"])?;
    let mut out = Vec::new();
    let Some(items) = v.get("items").and_then(|i| i.as_array()) else {
        return Ok(out);
    };
    for pod in items {
        let meta = pod.get("metadata");
        let namespace = meta.and_then(|m| m.get("namespace")).and_then(|s| s.as_str()).unwrap_or("");
        let name = meta.and_then(|m| m.get("name")).and_then(|s| s.as_str()).unwrap_or("");
        let spec = pod.get("spec");
        let node = spec.and_then(|s| s.get("nodeName")).and_then(|s| s.as_str()).unwrap_or("");
        let status = pod.get("status");
        let phase = status.and_then(|s| s.get("phase")).and_then(|s| s.as_str()).unwrap_or("");
        // Reason may live at status.reason or in the last container status' state.
        let reason = status
            .and_then(|s| s.get("reason"))
            .and_then(|s| s.as_str())
            .map(str::to_string)
            .or_else(|| {
                status
                    .and_then(|s| s.get("containerStatuses"))
                    .and_then(|c| c.as_array())
                    .and_then(|arr| arr.last())
                    .and_then(|c| c.get("state"))
                    .and_then(|st| st.get("waiting"))
                    .and_then(|w| w.get("reason"))
                    .and_then(|s| s.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_default();
        // Ready = containerStatuses with ready==true, over total.
        let (ready_count, total, restarts) = container_counts(status);
        out.push(PodInfo {
            namespace: namespace.to_string(),
            name: name.to_string(),
            phase: phase.to_string(),
            ready: format!("{ready_count}/{total}"),
            restarts,
            node: node.to_string(),
            reason,
        });
    }
    Ok(out)
}

fn container_counts(status: Option<&serde_json::Value>) -> (u32, u32, u32) {
    let Some(cs) = status.and_then(|s| s.get("containerStatuses")).and_then(|c| c.as_array()) else {
        return (0, 0, 0);
    };
    let total = cs.len() as u32;
    let ready = cs
        .iter()
        .filter(|c| c.get("ready").and_then(|r| r.as_bool()).unwrap_or(false))
        .count() as u32;
    let restarts = cs.iter().filter_map(|c| c.get("restartCount").and_then(|r| r.as_u64())).sum::<u64>() as u32;
    (ready, total, restarts)
}

/// All nodes.
pub fn nodes() -> Result<Vec<NodeInfo>, String> {
    let v = run_kubectl(&["get", "nodes", "-o", "json"])?;
    let mut out = Vec::new();
    let Some(items) = v.get("items").and_then(|i| i.as_array()) else {
        return Ok(out);
    };
    for node in items {
        let name = node
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let ready = node
            .get("status")
            .and_then(|s| s.get("conditions"))
            .and_then(|c| c.as_array())
            .and_then(|arr| {
                arr.iter().find(|c| c.get("type").and_then(|t| t.as_str()) == Some("Ready"))
            })
            .and_then(|c| c.get("status"))
            .and_then(|s| s.as_str())
            == Some("True");
        let roles = node
            .get("metadata")
            .and_then(|m| m.get("labels"))
            .and_then(|l| l.as_object())
            .map(|labels| {
                labels
                    .keys()
                    .filter(|k| k.starts_with("node-role.kubernetes.io/"))
                    .filter_map(|k| k.rsplit('/').next())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let version = node
            .get("status")
            .and_then(|s| s.get("nodeInfo"))
            .and_then(|i| i.get("kubeletVersion"))
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        out.push(NodeInfo { name, ready, roles, version });
    }
    Ok(out)
}

/// Whether Kubernetes is reachable at all (used to skip k8s watching when no cluster is present).
pub fn available() -> bool {
    run_kubectl(&["version", "--client=false"]).is_ok()
}
