//! The self-healing watcher.
//!
//! The node is not only a passive tool surface: it is the *trigger* half of the healing loop.
//! On a timer it samples the state the operator asked it to watch (`ZYRISD_WATCH_PROCESSES`,
//! `ZYRISD_WATCH_CONTAINERS`, `ZYRISD_WATCH_K8S`). When something it must be running is not, it
//! reports an incident by opening a session against an Attacca agent, whose preamble tells it to
//! diagnose the root cause using this same node's `monitor` and `exec` tools, fix what it can, and
//! report back. That keeps Attacca — and the agent's judgement — in the loop, instead of the node
//! blindly restarting things.
//!
//! Deliberately fire-and-forget per incident: the watcher keeps sampling; it never blocks on a
//! session. A re-discovered incident while one is still open opens another — which is the point,
//! an incident that comes back needs a second look.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zyris::Connection;
use zyris_attacca::{AttaccaApi, AttaccaApiClient, ZNewSession};

use crate::config::Config;
use crate::docker::container_running;
use crate::monitor::Incident;
use crate::system::process_running;

/// How long to wait for the server to announce `attacca_api` after a reconnect.
const CONSUME_WAIT: Duration = Duration::from_secs(5);

/// Where the live connection is handed in by `on_connect`.
#[derive(Clone, Default)]
pub struct ConnSlot(Arc<Mutex<Option<Connection>>>);

impl ConnSlot {
    pub fn new() -> ConnSlot {
        ConnSlot::default()
    }

    pub fn put(&self, conn: Connection) {
        *self.0.lock().unwrap() = Some(conn);
    }

    pub fn get(&self) -> Option<Connection> {
        self.0.lock().unwrap().as_ref().cloned()
    }
}

/// Names already reported, so a process/container that keeps failing does not spam a session every
/// tick. Cleared when the thing comes back (the watcher re-arms), and bounded so a watched list
/// that keeps failing does not grow forever.
pub struct SelfHealer {
    cfg: Config,
    conn: ConnSlot,
    reported: HashMap<String, bool>,
}

impl SelfHealer {
    pub fn new(cfg: Config, conn: ConnSlot) -> SelfHealer {
        SelfHealer { cfg, conn, reported: HashMap::new() }
    }

    /// One full sample: every watched target that is currently down, as an `Incident`.
    fn sample(&self) -> Vec<Incident> {
        let mut incidents = Vec::new();

        for name in &self.cfg.watch_processes {
            if !process_running(name) {
                incidents.push(Incident {
                    kind: "process".into(),
                    name: name.clone(),
                    detail: format!("required process `{name}` is not running in this container"),
                });
            }
        }

        for name in &self.cfg.watch_containers {
            if !container_running(name) {
                incidents.push(Incident {
                    kind: "container".into(),
                    name: name.clone(),
                    detail: format!("required docker container `{name}` is not running"),
                });
            }
        }

        if self.cfg.watch_k8s {
            match crate::k8s::pods() {
                Ok(pods) => {
                    for pod in pods {
                        // A pod that is meant to be Running but is Pending/Failed/Unknown is an
                        // incident; Succeeded is a job that finished and is not.
                        if pod.phase != "Running" && pod.phase != "Succeeded" && !pod.name.is_empty() {
                            incidents.push(Incident {
                                kind: "k8s_pod".into(),
                                name: format!("{}/{}", pod.namespace, pod.name),
                                detail: format!("pod in phase {} ({})", pod.phase, pod.reason),
                            });
                        }
                    }
                }
                Err(e) => {
                    incidents.push(Incident {
                        kind: "k8s".into(),
                        name: "cluster".into(),
                        detail: format!("could not read pods: {e}"),
                    });
                }
            }
            if let Ok(nodes) = crate::k8s::nodes() {
                for node in nodes {
                    if !node.ready {
                        incidents.push(Incident {
                            kind: "k8s_node".into(),
                            name: node.name.clone(),
                            detail: "node is not Ready".into(),
                        });
                    }
                }
            }
        }

        incidents
    }

    /// The main loop: sample, report anything newly down, re-arm anything back up.
    pub async fn run(&mut self) {
        let mut tick = tokio::time::interval(self.cfg.monitor_interval);
        tick.tick().await; // skip the immediate first tick, let it settle
        loop {
            tick.tick().await;
            let incidents = self.sample();
            let down: std::collections::HashSet<String> =
                incidents.iter().map(|i| format!("{}:{}", i.kind, i.name)).collect();

            // Re-arm anything that is healthy again.
            let keys: Vec<String> = self.reported.keys().cloned().collect();
            for key in keys {
                if !down.contains(&key) {
                    self.reported.remove(&key);
                }
            }

            for incident in incidents {
                let key = format!("{}:{}", incident.kind, incident.name);
                if self.reported.contains_key(&key) {
                    continue; // already reported, still down
                }
                self.reported.insert(key, true);
                if let Some(conn) = self.conn.get() {
                    tokio::spawn(report_incident(self.cfg.clone(), conn, incident));
                }
            }
        }
    }
}

/// Open (or reuse the agent's first) a session against the heal agent, send the incident, and let
/// the agent act. Runs detached; failures are logged, never fatal.
async fn report_incident(cfg: Config, conn: Connection, incident: Incident) {
    let api = match conn.wait_capability::<AttaccaApiClient>(CONSUME_WAIT).await {
        Ok(api) => api,
        Err(e) => {
            tracing::warn!(error = %e, "server did not announce attacca_api; skipping incident report");
            return;
        }
    };

    // Resolve the agent id: configured, else the first readable agent.
    let agent_id = match cfg.heal_agent_id.clone() {
        Some(id) => id,
        None => match api.list_agents().await {
            Ok(mut agents) if !agents.is_empty() => agents.remove(0).id,
            Ok(_) => {
                tracing::warn!("no heal agent configured and no agents readable; skipping report");
                return;
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not list agents; skipping incident report");
                return;
            }
        },
    };

    let title = format!("zyris-docker incident: {} {}", incident.kind, incident.name);
    let body = format!(
        "Self-healing incident on container node.\n\n{}\n\n\
         Diagnose with this node's `monitor` and `exec` capabilities, fix what you can, and report \
         back what broke, what you found, what you did, and what remains.",
        incident.detail,
    );

    let session = match api
        .create_session_with(ZNewSession {
            agent_id: agent_id.clone(),
            title: Some(title),
            project_id: cfg.heal_project_id.clone(),
            preamble: Some(cfg.heal_preamble.clone()),
        })
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, agent = %agent_id, "could not open heal session");
            return;
        }
    };

    if let Err(e) = api.send_message(session.id.clone(), body, Vec::new()).await {
        tracing::warn!(error = %e, "could not send incident to heal session");
    } else {
        tracing::info!(kind = %incident.kind, name = %incident.name, session = %session.id, "incident reported to Attacca");
    }
}
