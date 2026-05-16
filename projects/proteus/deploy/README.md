# Proteus deployment guide

This directory ships the production deployment artifacts for the Proteus
α-profile reference implementation. The goal is **zero-surprise production
launch**: copy a config, run a binary, get a SOCKS5 endpoint that tunnels
through a quantum-safe, cover-protected, AEAD-protected, mutually-authenticated
channel.

## What you get

- **`proteus-server`** binary — accepts Proteus α-profile handshakes,
  forwards inner streams to user-requested upstreams.
- **`proteus-client`** binary — local SOCKS5 listener that tunnels every
  CONNECT through a Proteus session.
- **Cover forwarding** (`cover_endpoint:` in `server.yaml`) — on auth
  failure, the server byte-verbatim splices the connection to a real
  HTTPS endpoint, making it indistinguishable from a generic HTTPS
  reverse proxy. (REALITY-style protection without TLS-in-TLS overhead.)
- **systemd unit** with full hardening profile.
- **Multi-stage Dockerfile** with a 911:911 unprivileged service user.

## Quick start (bare-metal Linux VPS)

```bash
# 1. Build (on the build host).
cd projects/proteus
cargo build --release --bin proteus-server --bin proteus-client
sudo install -m 0755 target/release/proteus-server /usr/local/bin/
sudo install -m 0755 target/release/proteus-client /usr/local/bin/

# 2. Generate server keys.
sudo useradd --system --shell /usr/sbin/nologin proteus
sudo mkdir -p /etc/proteus/keys /etc/proteus/keys/tls /var/log/proteus
sudo chown -R proteus:proteus /etc/proteus /var/log/proteus
sudo -u proteus proteus-server keygen --out /etc/proteus/keys

# 2b. Get a TLS certificate. Production: use Let's Encrypt:
#       certbot certonly --standalone -d vps.example.com
#       cp /etc/letsencrypt/live/vps.example.com/fullchain.pem /etc/proteus/keys/tls/
#       cp /etc/letsencrypt/live/vps.example.com/privkey.pem   /etc/proteus/keys/tls/
#       chown proteus:proteus /etc/proteus/keys/tls/*
#       chmod 0600 /etc/proteus/keys/tls/privkey.pem
# Testing-only: generate a self-signed cert (clients must trust it as CA):
sudo -u proteus proteus-server gencert \
    --dns-name vps.example.com \
    --out /etc/proteus/keys/tls

# 3. Distribute these to your users (out-of-band, encrypted):
#    /etc/proteus/keys/server_lt.mlkem768.pk
#    /etc/proteus/keys/server_lt.x25519.pk
#    /etc/proteus/keys/server_lt.pq.fingerprint
# Keep secret on server:
#    /etc/proteus/keys/server_lt.mlkem768.sk
#    /etc/proteus/keys/server_lt.x25519.sk
sudo chmod 0600 /etc/proteus/keys/*.sk

# 4. Receive each user's Ed25519 public key, add to allowlist.
sudo install -m 0644 alice.ed25519.pk /etc/proteus/keys/clients/

# 5. Copy + edit config.
sudo install -m 0644 deploy/server.example.yaml /etc/proteus/server.yaml
sudoedit /etc/proteus/server.yaml

# 6. Install + start the service.
sudo install -m 0644 deploy/systemd/proteus-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now proteus-server
sudo journalctl -u proteus-server -f
```

## Client (on user's laptop)

```bash
# 1. Generate identity.
proteus-client keygen --out ./keys/client

# 2. Send keys/client/client.ed25519.pk to the server admin.

# 3. Receive server's public bundle, put under ./keys/.

# 4. Configure.
cp deploy/client.example.yaml ~/.proteus.yaml
vim ~/.proteus.yaml

# 5. Run.
proteus-client run --config ~/.proteus.yaml

# 6. Use via SOCKS5.
curl --socks5 127.0.0.1:1080 https://example.com/
```

## Docker

```bash
# Build the image (multi-stage; the dependency layer is cached).
docker compose -f deploy/docker-compose.yml build

# Place server.yaml + keys/ next to docker-compose.yml.
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml logs -f
```

## Logging

`proteus-server` uses `tracing` with an `EnvFilter` driven by `RUST_LOG`.
The systemd unit ships with a sensible default
(`RUST_LOG=proteus_server=info,proteus_transport_alpha=info`).
Useful filters for triage:

| Filter | What you see |
|---|---|
| `proteus_transport_alpha=debug` | Per-connection rate-limit / cover-forward decisions, peer addrs |
| `proteus_transport_alpha=trace` | Every state-machine transition |
| `info` | Default; only startup + cover/rate-limit warnings + session errors |
| `warn` | Just operational anomalies (e.g. handshake_deadline elapsed) |

Override per invocation:
```bash
RUST_LOG=proteus_transport_alpha=debug proteus-server run --config /etc/proteus/server.yaml
```

Filter by peer in journald:
```bash
journalctl -u proteus-server -f | grep 'peer=203.0.113'
```

## Observability

Set `metrics_listen: "127.0.0.1:9090"` in `server.yaml` to expose three
co-hosted HTTP endpoints:

- `GET /metrics` — Prometheus 0.0.4 text exposition.
- `GET /healthz` — liveness probe. `200 alive` once the listener is
  bound, `503 dead` during shutdown after the drain window.
- `GET /readyz`  — readiness probe. `200 ready` while accepting new
  traffic, `503 draining` the instant SIGTERM/SIGINT arrives so an
  upstream load balancer drains us before the process exits.

Sample `/metrics` scrape:

```
proteus_sessions_accepted_total 42
proteus_handshakes_succeeded_total 41
proteus_handshakes_failed_total 1
proteus_cover_forwards_total 1
proteus_tx_bytes_total 5048321
proteus_rx_bytes_total 4119883
proteus_aead_drops_total 0
proteus_ratchets_total 14
proteus_in_flight_sessions 3
proteus_up 1
proteus_ready 1
```

Kubernetes example:

```yaml
livenessProbe:
  httpGet: { path: /healthz, port: 9090 }
  initialDelaySeconds: 5
  periodSeconds: 10
  failureThreshold: 3
readinessProbe:
  httpGet: { path: /readyz, port: 9090 }
  periodSeconds: 5
  failureThreshold: 2
```

### Authentication

`/healthz` and `/readyz` are **never** authenticated — orchestrator
probes (kubelet, ECS, GCP HCs) don't carry tokens, and the bodies
only leak `alive` / `dead` / `ready` / `draining`.

`/metrics` is authenticated when `metrics_token_file` is configured:

```yaml
metrics_listen: "0.0.0.0:9090"           # exposed beyond loopback
metrics_token_file: /etc/proteus/metrics.token
```

```bash
# Generate a 32-byte token:
sudo openssl rand -hex 32 | sudo tee /etc/proteus/metrics.token
sudo chmod 0600 /etc/proteus/metrics.token
sudo chown proteus:proteus /etc/proteus/metrics.token
```

Prometheus scrape:

```yaml
- job_name: proteus
  bearer_token_file: /etc/prometheus/proteus-metrics.token
  static_configs:
    - targets: ['proteus.internal:9090']
```

Bind only to a private interface (loopback or VPN). When
`metrics_listen` is non-loopback **and** `metrics_token_file` is unset,
the binary warns at startup that `/metrics` is world-readable. When
`metrics_token_file` is set, comparisons are constant-time
(`subtle::ConstantTimeEq`) and the in-memory token is wiped on
process exit via `zeroize`.

## Graceful shutdown

`proteus-server` installs SIGTERM/SIGINT handlers. The signal flow is:

1. Signal received → `/readyz` flips to `503 draining` immediately so
   the load balancer steers new traffic elsewhere.
2. The accept loop is dropped (no new sessions are admitted).
3. In-flight sessions are given up to `drain_secs` (default 30 s) to
   flush. Override in `server.yaml` and match systemd's
   `TimeoutStopSec` accordingly (`drain_secs + 5 s` of margin).
4. After the drain window, `/healthz` flips to `503 dead` and the
   process exits cleanly.

For longer drain windows, raise both `drain_secs` in `server.yaml` and
`TimeoutStopSec` in the systemd unit override.

## Access log rotation (SIGUSR1)

`proteus-server` opens the access log (`access_log: /var/log/...` in
server.yaml) once at startup and keeps the FD for the lifetime of the
process. For correct **rename-then-rotate** rotation (the standard
logrotate flow), send SIGUSR1 after the rotation:

```text
/var/log/proteus/access.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        systemctl kill --signal=USR1 proteus-server
    endscript
}
```

On SIGUSR1 the writer task flushes the current buffer, closes the old
FD, and reopens the original path — which now points to a fresh
file. If the new path is unwritable (permissions, missing parent
dir), the writer logs an error and **keeps using the old FD** — the
binary keeps running, the operator gets a chance to fix the issue
and signal again. No scenario will brick the running process.

`copytruncate` also works (the old FD remains valid; the file just
gets truncated under us, so further appends start at the beginning
of the file). SIGUSR1 + rename gives sharper rotation boundaries.

## Pre-deploy validation (`proteus-server validate`)

Every YAML edit should be dry-run-checked before SIGHUP or
`systemctl restart` so a typo doesn't brick the service:

```bash
sudoedit /etc/proteus/server.yaml
sudo -u proteus proteus-server validate --config /etc/proteus/server.yaml
echo $?  # 0 = green, 1 = at least one failure
```

The preflight parses the YAML, opens every referenced file (server
keys, TLS cert + key, client allowlist Ed25519 pubs, metrics token,
firewall CIDRs), runs the same TLS-acceptor build as the production
path (catches cert/key-type mismatch), and prints a coloured per-check
report:

```
preflight check: "/etc/proteus/server.yaml"
  [ok]   YAML parses
  [ok]   listen_alpha parses (0.0.0.0:8443)
  [ok]   keys.mlkem_pk exists and readable ("/etc/proteus/keys/server_lt.mlkem768.pk")
  ...
  [ok]   tls.cert_chain parses (3 certs)
  [ok]   tls.private_key parses
  [ok]   tls.acceptor builds (cert/key match)
  [ok]   cover_endpoint parses (www.cloudflare.com:443)
  [ok]   firewall: 2 allow, 1 deny rules parse
  [ok]   metrics_token_file readable ("/etc/proteus/metrics.token")
  ----
  14 passed, 0 warnings, 0 failed
```

Suitable for CI / Ansible / Terraform pre-deploy gating. The
preflight does NOT bind sockets or talk to the cover endpoint — it
only verifies what can be verified locally.

## TLS certificate hot-reload (SIGHUP)

`proteus-server` installs a SIGHUP handler that re-reads the
`tls.cert_chain` and `tls.private_key` files from disk and atomically
swaps in the new cert. **In-flight sessions keep their existing TLS
keys**; only connections accepted after the reload use the new cert.

This means Let's Encrypt renewal becomes a zero-downtime operation:

```bash
# Run inside the certbot deploy-hook directory.
# /etc/letsencrypt/renewal-hooks/deploy/proteus-reload.sh
#!/bin/sh
set -e
RENEWED=/etc/letsencrypt/live/vps.example.com
cp -f "$RENEWED/fullchain.pem" /etc/proteus/keys/tls/fullchain.pem
cp -f "$RENEWED/privkey.pem"   /etc/proteus/keys/tls/privkey.pem
chown proteus:proteus /etc/proteus/keys/tls/*.pem
chmod 0600 /etc/proteus/keys/tls/privkey.pem
systemctl kill --signal=HUP proteus-server
```

If the reload fails (bad PEM, missing file, key/cert mismatch) the
server logs an error at `ERROR` level and **continues serving with the
old cert** — production keeps running, the operator gets a chance to
fix the file and try again. There is no scenario in which a failed
reload bricks the running server.

Verify success in journald:

```bash
sudo journalctl -u proteus-server -n 5 | grep 'TLS cert'
# May 16 12:34:56 vps proteus-server[1234]: INFO ... TLS cert reloaded successfully
```

## Firewall hot-reload (SIGHUP)

The **same** SIGHUP that hot-reloads the TLS cert also re-reads the
full `server.yaml` and atomically swaps in the new `firewall:` block.
Add or remove allow/deny rules without restarting the binary:

```bash
sudoedit /etc/proteus/server.yaml         # edit firewall.allow / firewall.deny
sudo systemctl kill --signal=HUP proteus-server
sudo journalctl -u proteus-server -n 5 | grep 'firewall'
# INFO ... firewall rules reloaded rules=4
```

Reload semantics:

- The cert reload and the firewall reload are **independent**: a YAML
  parse error on one does not abort the other. Both leave the
  in-memory state intact if their respective reload fails.
- **In-flight sessions are not affected.** The firewall is evaluated
  at `accept()`, not per-record, so an existing session admitted under
  the old rules keeps running even if its source IP is now in the new
  denylist. (If you need to terminate an existing session, restart
  the binary or kill the specific connection via `ss --kill`.)
- Removing the `firewall:` block entirely (or commenting it out)
  followed by SIGHUP clears the rules — the next accept admits
  everything subject only to rate-limit / max-connections.

## Security checklist before going live

- [ ] `proteus-server keygen` ran on the **server itself** (never copy
      `*.sk` files between hosts).
- [ ] `/etc/proteus/keys/*.sk` are mode `0600`, owned by `proteus`.
- [ ] `client_allowlist` is **non-empty**. An empty allowlist accepts any
      client — only acceptable for testing.
- [ ] `cover_endpoint` is configured to a real, popular HTTPS site you
      do **not** operate. Cloudflare, Microsoft, Apple are good choices.
      Crucially, the cover server MUST NOT be your own — that would be a
      first-party fingerprint.
- [ ] Firewall: only the listen port (`8443` or `443`) is exposed; key
      files are not on a shared filesystem.
- [ ] NTP is running. Spec §8.2 rejects timestamps skewed > 90 s.
- [ ] Logs at `/var/log/proteus/*` are rotated (use `logrotate` or
      `journald` retention policy).

## Threat surface (what this build actually defends)

- **Network adversary**: cannot read the inner stream
  (ChaCha20-Poly1305 with per-direction keys derived from a
  TLS 1.3-style schedule; FS via ephemeral X25519+ML-KEM-768).
- **Compromised long-running AEAD key**: per-direction symmetric
  ratchet auto-rotates the AEAD key every 4 MiB / 16 384 records. A
  leaked key at epoch N exposes only the bytes within that 4 MiB
  window, never past or future epochs (HKDF is forward-only).
  Strictly stronger than VLESS+REALITY/Hy2/TUIC which never rotate.
- **Quantum store-now-decrypt-later (SNDL)**: ML-KEM-768 hybrid path
  protects today's traffic.
- **Active probing**: handshake failures forward to `cover_endpoint`
  byte-verbatim; an external prober sees an honest HTTPS response from
  the cover.
- **Replay**: 90-second sliding window over `(client_nonce, timestamp)`
  pairs rejects retransmitted ClientHellos.
- **Wire-format fuzzing**: invalid-length / non-zero-reserved /
  bad-profile-hint ClientHellos route to the cover-forward path.

Not yet defended in this M1 release:
- Multipath / blanket-port-block fallback (M4).
- Active shape-shifting / cover-IAT online learning (M3).
- Real TLS 1.3 outer record layer (M2 — current build uses a typed
  framing shim directly over TCP).
