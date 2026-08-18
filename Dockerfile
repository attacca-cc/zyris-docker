# syntax=docker/dockerfile:1
# Multi-stage build: compile the node in a Rust builder, then copy the binary into a slim
# runtime image that also carries the `docker` and `kubectl` CLIs this node shells out to.
#
# The docker CLI is a static binary from the official download.docker.com static tarball; the
# kubectl CLI comes from the official dl.k8s.io release channel.

ARG RUST_VERSION=1.97
ARG DEBIAN_VERSION=bookworm-slim

########## builder ##########
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS builder
WORKDIR /build
# Fetch and compile dependencies first (best layer caching). The dummy main is replaced below.
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src && echo "fn main(){}" > src/main.rs \
 && cargo build --release -j2 2>/dev/null || true
COPY src ./src
RUN touch src/main.rs && cargo build --release -j2

########## runtime ##########
FROM debian:${DEBIAN_VERSION} AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    # Official static docker CLI.
    && curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-27.5.1.tgz -o /tmp/docker.tgz \
    && tar -xzf /tmp/docker.tgz -C /tmp \
    && install -m 0755 /tmp/docker/docker /usr/local/bin/docker \
    && rm -rf /tmp/docker /tmp/docker.tgz \
    # Official kubectl.
    && curl -fsSL -o /usr/local/bin/kubectl \
        "https://dl.k8s.io/release/$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
    && chmod +x /usr/local/bin/kubectl

COPY --from=builder /build/target/release/zyris-docker /usr/local/bin/zyris-docker

# Run as a non-root user. Mount the docker socket and/or a kubeconfig at runtime when you want
# Docker / Kubernetes visibility — see the README.
RUN useradd -r -u 10001 zyris && mkdir -p /data && chown zyris:zyris /data
USER zyris

ENV ZYRISD_FILE_ROOTS=/data
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/zyris-docker"]
