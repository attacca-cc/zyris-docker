# zyris-docker

A [Zyris](https://github.com/attacca-cc/zyris) node that runs **inside a container** and connects
that container — and the Docker / Kubernetes infrastructure around it — to
[Attacca](https://attacca.cc). It is the server-management sibling of
[`zyris-code`](https://github.com/attacca-cc/zyris-code) (a desktop coding client) and
[`zyris-daemon`](https://github.com/attacca-cc/zyris-daemon) (a desktop daemon): where those are
optimised for a machine with a display, this one is optimised for a containerised host.

| capability | what it does |
|---|---|
| `monitor` | System snapshot, process list, Docker container state/logs, Kubernetes pod/node state |
| `file_io` | Read, write, edit, list, remove inside the configured roots |
| `terminal` | PTY shell and `exec` (with timeout + output cap), gated to the configured roots |

It is also the **trigger half of a self-healing loop**: it watches the processes, containers and
cluster you tell it to, and when something it must be running is not, it opens a session against
an Attacca agent whose job is to diagnose the incident with this node's own `monitor`/`exec` tools,
fix it, and report back. Recovery stays in the hands of an agent with judgement — the node does
not blindly restart things.

## How it connects

The node presents a bearer token to an Attacca deployment over the Zyris protocol. It looks for
one in this order, and the first answer wins:

1. `ZYRIS_NODE_TOKEN` — a `znt_` node token in the environment.
2. `ZYRIS_NODE_TOKEN_FILE` — the same token in a file. **This is the container path.** It is what a
   Kubernetes Secret and `docker secret` mount, it is re-read on every reconnect so rotating the
   Secret needs no restart, and unlike an environment variable it is not visible in `/proc` or
   inherited by everything this node's `exec` capability spawns.
3. Neither — the node enrolls itself, printing an eight-character code into the container log
   (`docker logs` / `kubectl logs`) for you to approve in a browser. It then keeps the credential in
   `ZYRIS_CONFIG_DIR` (default `/var/lib/zyris-docker`, a declared volume) and rotates it as it
   expires. **Give that path a named volume** or every restart enrolls again and leaves a dead node
   row in your account behind each time.

A `znt_` never expires, so a node given one writes nothing and needs no volume at all. Enrollment
is the convenience path for trying the image out; a token is the one to deploy.

## Quick start (Docker)

```bash
# Enroll first to get a node token, then mount it into the container.
docker run --rm \
  -e ZYRIS_NODE_TOKEN_FILE=/run/secrets/zyris_token \
  -e ZYRISD_WATCH_CONTAINERS=web,db \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/secrets/zyris_token:/run/secrets/zyris_token:ro" \
  ghcr.io/attacca-cc/zyris-docker:latest
```

To expose **Docker** state, mount the host's `/var/run/docker.sock` (as above) or point `DOCKER_HOST`
at a remote context. To expose **Kubernetes** state, set `ZYRISD_WATCH_K8S=1` and mount a
kubeconfig (or rely on an in-cluster service account, which `kubectl` discovers automatically):

```bash
docker run --rm \
  -e ZYRIS_NODE_TOKEN_FILE=/run/secrets/zyris_token \
  -e ZYRISD_WATCH_K8S=1 \
  -v "$HOME/.kube/config:/home/zyris/.kube/config:ro" \
  ghcr.io/attacca-cc/zyris-docker:latest
```

> **Root vs. non-root.** The image runs as the unprivileged `zyris` user. Reading the docker
> socket works when the `zyris` uid is in the host's `docker` group; otherwise the `monitor`
> docker tools return an error the agent can see. Kubernetes reads only need the mounted
> kubeconfig.

## docker-compose

```yaml
services:
  zyris-docker:
    image: ghcr.io/attacca-cc/zyris-docker:latest
    # Not `unless-stopped`: exit 2 means a person has to do something, and restarting through it
    # loops forever. See "Stopping, and what the exit code means".
    restart: on-failure:3
    environment:
      - ZYRIS_NODE_TOKEN_FILE=/run/secrets/zyris_token
      - ZYRISD_WATCH_CONTAINERS=web,db
      - ZYRISD_WATCH_PROCESSES=nginx
      - ZYRISD_MONITOR_INTERVAL_SECS=30
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./secrets/zyris_token:/run/secrets/zyris_token:ro
      - ./data:/data
```

## Configuration

The standard `ZYRIS_*` variables are read by this node's own program layer (`src/runtime/`); the
node-specific knobs all carry a `ZYRISD_` prefix so they can never collide with them.

### Runtime (zyris)

| Variable | Default | Meaning |
|---|---|---|
| `ZYRIS_SERVER_URL` | `wss://attacca.cc/api/zyris/v1/ws` | Server to connect to |
| `ZYRIS_NODE_NAME` | hostname | Node name shown in Attacca. In a container the hostname is a random id that changes when the container is recreated — set this to something stable |
| `ZYRIS_PROFILE` | `default` | Credential profile name |
| `ZYRIS_SCOPES` | the five below | Comma-separated scopes to ask for at enrollment. Setting it wins over the built-in list |
| `ZYRIS_CONFIG_DIR` | `/var/lib/zyris-docker` | Where a self-enrolled credential is kept. Used verbatim; also the directory `file_io` is denied |
| `ZYRIS_NODE_TOKEN` / `ZYRIS_NODE_TOKEN_FILE` | — | The bearer token (or a file holding it) |

The scopes asked for by default are `agents:read`, `sessions:write`, `sessions:read`,
`projects:read` and `jobs:write` — what the self-healing watcher needs to open a session and drive
it. Asking for a scope the deployment does not know refuses the whole authorization request, so
narrow this list rather than widening it.

### Node (zyris-docker)

| Variable | Default | Meaning |
|---|---|---|
| `ZYRISD_MONITOR_INTERVAL_SECS` | `30` | How often the self-healing watcher samples state |
| `ZYRISD_WATCH_PROCESSES` | empty | Comma-separated `/proc/<pid>/comm` names that must be running |
| `ZYRISD_WATCH_CONTAINERS` | empty | Comma-separated Docker container names that must be running |
| `ZYRISD_WATCH_K8S` | `false` | `1`/`true` to also watch Kubernetes pods and nodes |
| `ZYRISD_HEAL_AGENT_ID` | first readable agent | Agent id self-healing sessions are opened against |
| `ZYRISD_HEAL_PROJECT_ID` | default project | Project id to file healing sessions under |
| `ZYRISD_HEAL_PREAMBLE` | built-in | System instructions for each healing session |
| `ZYRISD_FILE_ROOTS` | `/data` | Comma-separated roots `file_io`/`exec` may touch |
| `ZYRISD_EXEC_TIMEOUT_SECS` | `120` | Hard cap on any single `exec` |
| `ZYRISD_MAX_OUTPUT_BYTES` | `262144` | Per-stream cap on `exec` output |

## Self-healing

Set at least one of `ZYRISD_WATCH_PROCESSES`, `ZYRISD_WATCH_CONTAINERS`, or `ZYRISD_WATCH_K8S=1`.
On each `ZYRISD_MONITOR_INTERVAL_SECS` tick the watcher checks:

- every watched process is running in the container's PID namespace,
- every watched container is in the `running` state,
- when Kubernetes watching is on, every pod is `Running`/`Succeeded` and every node is `Ready`.

When a target is down, the node opens a session against `ZYRISD_HEAL_AGENT_ID` (or the account's
first agent), attaches the `ZYRISD_HEAL_PREAMBLE`, and sends the incident. The agent then uses this
node's `monitor` and `exec` tools to diagnose and fix — e.g. `docker_restart` a stopped container,
or `exec` a recovery command — and reports back. The watcher keeps sampling; an incident that comes
back re-opens a session, so nothing is silently ignored.

## Stopping, and what the exit code means

`SIGTERM` (`docker stop`, `docker compose down`, a pod eviction) and `Ctrl-C` both stop the node
promptly and send a closing frame first, so the deployment retires it instead of routing tool calls
at a node that has gone away.

When it stops on its own, the status says whether restarting can help:

| Status | Meaning |
|---|---|
| `0` | Stopped on request |
| `1` | Refused in a way another dial will not change — a revoked credential, a malformed token |
| `2` | **A person has to do something.** Nobody approved the enrollment code, the credential directory is not writable, a scope this build asks for does not exist on that deployment |

`2` is worth wiring into your supervisor: with `restart: unless-stopped` a node that needs a human
would otherwise loop forever, printing a fresh enrollment code into a log nobody is reading.

## Build from source

```bash
cargo build --release      # produces target/release/zyris-docker
docker build -t ghcr.io/attacca-cc/zyris-docker:0.1.0 .   # or build the image
```

## License

MIT OR Apache-2.0.
