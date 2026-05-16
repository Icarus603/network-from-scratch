# syntax=docker/dockerfile:1.7
# ---- builder ----
FROM rust:1.85-slim-bookworm AS builder
WORKDIR /src

# Cache cargo registry by copying manifests first.
COPY Cargo.toml rust-toolchain.toml ./
COPY crates ./crates

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --bin proteus-server --bin proteus-client && \
    cp /src/target/release/proteus-server /usr/local/bin/proteus-server && \
    cp /src/target/release/proteus-client /usr/local/bin/proteus-client

# ---- runtime: server ----
FROM debian:bookworm-slim AS server
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates dumb-init libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r -g 911 proteus \
    && useradd -r -u 911 -g proteus -s /usr/sbin/nologin proteus \
    && mkdir -p /etc/proteus /var/log/proteus \
    && chown -R proteus:proteus /etc/proteus /var/log/proteus

COPY --from=builder /usr/local/bin/proteus-server /usr/local/bin/proteus-server

USER proteus:proteus
ENV RUST_LOG=proteus_server=info,proteus_transport_alpha=info
EXPOSE 8443/tcp
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/usr/local/bin/proteus-server", "run", "--config", "/etc/proteus/server.yaml"]

# ---- runtime: client (alternative target) ----
FROM debian:bookworm-slim AS client
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
