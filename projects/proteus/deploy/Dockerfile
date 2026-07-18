# syntax=docker/dockerfile:1.7
# ---- builder ----
# The official Rust image pins the compiler family.  Install the native
# C/CMake inputs explicitly because aws-lc-sys cannot build without them.
FROM rust:1.85-slim-bookworm@sha256:9f841bbe9e7d8e37ceb96ed907265a3a0df7f44e3737d0b100e7907a679acb36 AS builder
ARG DEBIAN_MIRROR=http://deb.debian.org/debian
ARG DEBIAN_SECURITY_MIRROR=http://deb.debian.org/debian-security
RUN sed -i \
        -e "s|http://deb.debian.org/debian-security|${DEBIAN_SECURITY_MIRROR}|g" \
        -e "s|http://deb.debian.org/debian|${DEBIAN_MIRROR}|g" \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
        build-essential ca-certificates clang cmake git libclang-dev perl pkg-config \
    && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_TOOLCHAIN=1.85.1
WORKDIR /src

# The lockfile is part of the build input. Omitting it silently resolves a
# different dependency graph and can raise the effective Rust MSRV.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --bin proteus-server --bin proteus-client --bin proteus-bench && \
    cp /src/target/release/proteus-server /usr/local/bin/proteus-server && \
    cp /src/target/release/proteus-client /usr/local/bin/proteus-client && \
    cp /src/target/release/proteus-bench /usr/local/bin/proteus-bench

# ---- uTLS bridge builder ----
# Kept separate from the Rust builder so the browser-profile adapter
# can be rebuilt and audited without copying Go or uTLS sources into
# the Rust image. The multi-arch digest resolves to Go 1.26.5.
FROM golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS utls-builder
WORKDIR /src/bridges/utls
COPY bridges/utls/go.mod bridges/utls/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY bridges/utls ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go test ./... && \
    go vet ./... && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
      -o /usr/local/bin/proteus-utls-bridge .

# ---- runtime: server ----
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS server
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates dumb-init libssl3 curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r -g 911 proteus \
    && useradd -r -u 911 -g proteus -s /usr/sbin/nologin proteus \
    && mkdir -p /etc/proteus /var/log/proteus \
    && chown -R proteus:proteus /etc/proteus /var/log/proteus

COPY --from=builder /usr/local/bin/proteus-server /usr/local/bin/proteus-server

# Healthcheck shim: probes /readyz on the metrics port. Defaults to
# 127.0.0.1:9090 (matches the bundled server.example.yaml). Override
# with -e PROTEUS_HEALTH_URL=http://host:port/readyz if you re-bind.
RUN printf '#!/bin/sh\nset -e\nexec curl --fail --silent --max-time 2 "${PROTEUS_HEALTH_URL:-http://127.0.0.1:9090/readyz}" > /dev/null\n' \
        > /usr/local/bin/proteus-server-healthcheck \
    && chmod +x /usr/local/bin/proteus-server-healthcheck

USER proteus:proteus
ENV RUST_LOG=proteus_server=info,proteus_transport_alpha=info
EXPOSE 8443/tcp
HEALTHCHECK --interval=10s --timeout=3s --retries=3 --start-period=15s \
    CMD ["/usr/local/bin/proteus-server-healthcheck"]
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/usr/local/bin/proteus-server", "run", "--config", "/etc/proteus/server.yaml"]

# ---- runtime: client (alternative target) ----
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS client
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates dumb-init libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r -g 911 proteus \
    && useradd -r -u 911 -g proteus -s /usr/sbin/nologin proteus \
    && mkdir -p /etc/proteus \
    && chown -R proteus:proteus /etc/proteus

COPY --from=builder /usr/local/bin/proteus-client /usr/local/bin/proteus-client

USER proteus:proteus
ENV RUST_LOG=proteus_client=info,proteus_transport_alpha=info
EXPOSE 1080/tcp
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/usr/local/bin/proteus-client", "run", "--config", "/etc/proteus/client.yaml"]

# ---- runtime: uTLS browser-profile bridge ----
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS utls-bridge
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates dumb-init \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r -g 911 proteus \
    && useradd -r -u 911 -g proteus -s /usr/sbin/nologin proteus \
    && mkdir -p /run/proteus /etc/proteus \
    && chown -R proteus:proteus /run/proteus /etc/proteus

COPY --from=utls-builder /usr/local/bin/proteus-utls-bridge /usr/local/bin/proteus-utls-bridge

USER proteus:proteus
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/usr/local/bin/proteus-utls-bridge", \
     "--listen", "/run/proteus/utls.sock", \
     "--knock-psk", "/etc/proteus/keys/server.knock_psk"]

# ---- benchmark participant ----
# Same Rust builder as production, with only the cross-host benchmark
# binary plus the route/bootstrap helpers required by the isolated
# two-network netem topology.
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS bench
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates dumb-init iproute2 procps \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r -g 911 proteus \
    && useradd -r -u 911 -g proteus -s /usr/sbin/nologin proteus \
    && mkdir -p /run/proteus-bench \
    && chown -R proteus:proteus /run/proteus-bench

COPY --from=builder /usr/local/bin/proteus-bench /usr/local/bin/proteus-bench
COPY bench/container/proteus-server-entrypoint.sh /usr/local/bin/
COPY bench/container/proteus-client-entrypoint.sh /usr/local/bin/
COPY bench/container/resource-monitor.sh /usr/local/bin/

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/usr/local/bin/proteus-bench", "--help"]

# ---- production-shaped proxy benchmark participant ----
# Contains the real server/client binaries plus the protocol-neutral
# workload driver.  The netem matrix uses this target to exercise the
# same SOCKS5 -> Proteus β -> CONNECT relay path operators deploy,
# instead of comparing Proteus' bespoke echo command with competitors'
# proxy surfaces.
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS proxy-bench
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates dumb-init iproute2 procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/proteus-server /usr/local/bin/proteus-server
COPY --from=builder /usr/local/bin/proteus-client /usr/local/bin/proteus-client
COPY --from=builder /usr/local/bin/proteus-bench /usr/local/bin/proteus-bench
COPY bench/container/proteus-proxy-setup.sh /usr/local/bin/
COPY bench/container/proteus-proxy-server-entrypoint.sh /usr/local/bin/
COPY bench/container/proteus-proxy-client-entrypoint.sh /usr/local/bin/

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/usr/local/bin/proteus-bench", "--help"]

# ---- in-path Linux netem router ----
# This target never contains protocol code. It has one interface on
# each isolated bridge, forwards between them, and owns the qdiscs
# that every competitor must cross.
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS netem
ARG DEBIAN_MIRROR=http://deb.debian.org/debian
ARG DEBIAN_SECURITY_MIRROR=http://deb.debian.org/debian-security
RUN sed -i \
        -e "s|http://deb.debian.org/debian-security|${DEBIAN_SECURITY_MIRROR}|g" \
        -e "s|http://deb.debian.org/debian|${DEBIAN_MIRROR}|g" \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
        dumb-init ethtool iproute2 iptables jq procps \
    && rm -rf /var/lib/apt/lists/*

COPY bench/container/netem-router.sh /usr/local/bin/
COPY bench/container/netem-control.sh /usr/local/bin/

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/usr/local/bin/netem-router.sh"]
