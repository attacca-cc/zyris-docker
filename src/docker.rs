//! Docker container state, queried through the `docker` CLI.
//!
//! The container mounts the host's `/var/run/docker.sock` (or a remote docker context) and this node
//! shells out to `docker`. That keeps the binary free of the whole docker API client stack; the CLI
//! is present in the runtime image. Each `docker ps` row is JSON, so output is parsed line-by-line.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One container as reported by `docker ps -a`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ContainerInfo {
    /// Full container id.
    pub id: String,
    /// The container's primary name (first of `Names`).
    pub name: String,
    /// Image the container runs.
    pub image: String,
    /// Docker's state word: `running`, `exited`, `created`, `paused`, `restarting`, `dead`.
    pub state: String,
    /// True when the container is currently running.
    pub running: bool,
    /// Human-readable status line, e.g. `Up 3 hours (healthy)`.
    pub status: String,
}

fn run_docker(args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new("docker").args(args).output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn parse_container_line(line: &str) -> Option<ContainerInfo> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let names = v.get("Names")?.as_str()?.to_string();
    let name = names.split(',').next().map(str::to_string).unwrap_or_default();
    let state = v.get("State").and_then(|s| s.as_str()).unwrap_or("").to_string();
    Some(ContainerInfo {
        id: v.get("ID").and_then(|s| s.as_str()).unwrap_or("").to_string(),
        name,
        image: v.get("Image").and_then(|s| s.as_str()).unwrap_or("").to_string(),
        state: state.clone(),
        running: state == "running",
        status: v.get("Status").and_then(|s| s.as_str()).unwrap_or("").to_string(),
    })
}

/// List all containers (including stopped ones), most recently created first.
pub fn list_containers() -> Result<Vec<ContainerInfo>, String> {
    let raw = run_docker(&["ps", "-a", "--no-trunc", "--format", "{{json .}}"])?;
    Ok(raw.lines().filter_map(parse_container_line).collect())
}

/// Fetch one container by name or id.
pub fn container_info(selector: &str) -> Result<ContainerInfo, String> {
    let raw = run_docker(&[
        "ps",
        "-a",
        "--no-trunc",
        "--filter",
        &format!("name={selector}"),
        "--format",
        "{{json .}}",
    ])?;
    raw.lines().find_map(parse_container_line).ok_or_else(|| format!("no container {selector}"))
}

/// Whether the named container is currently running.
pub fn container_running(selector: &str) -> bool {
    container_info(selector).map(|c| c.running).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_docker_ps_row() {
        let row = r#"{"Command":"nginx -g daemon off;","CreatedAt":"2026-08-18 10:00:00","ID":"abc123","Image":"nginx:alpine","Labels":"","LocalVolumes":"0","Mounts":"","Names":"web","Networks":"bridge","Ports":"0.0.0.0:80->80/tcp","RunningFor":"3 hours ago","Size":"0B","State":"running","Status":"Up 3 hours"}"#;
        let c = parse_container_line(row).unwrap();
        assert_eq!(c.id, "abc123");
        assert_eq!(c.name, "web");
        assert_eq!(c.state, "running");
        assert!(c.running);
        assert_eq!(c.image, "nginx:alpine");
    }
}
