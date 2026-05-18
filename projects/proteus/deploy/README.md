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

### Prometheus alerts

This repo ships ready-to-load Prometheus alert rules:

- `deploy/prometheus/proteus-alerts.yaml` — 40+ server-side alerts
- `deploy/prometheus/proteus-client-alerts.yaml` — 10 client-side alerts

Load with `rule_files:` in `prometheus.yml`, or mount into a
Prometheus Operator `PrometheusRule` resource. Severity grammar:

- **critical** — operator must act now (paging-grade); examples:
  `ProteusServerDown`, `ProteusPanic`, `ProteusTlsCertExpired`,
  `ProteusAeadDropsCatastrophic` (>1 AEAD-drop/sec for 2 min =
  active MITM), `ProteusSsrfAttemptsCatastrophic` (credential
  compromise + internal-network probing), `ProteusHandshakeLatencyP99Catastrophic`
  (CPU-exhaustion attack / PoW-bypass).
- **warning** — investigate within the hour; examples:
  `ProteusCoverForwardStorm`, `ProteusUserQuotaAdmissionRejecting`,
  `ProteusProbeAnomalyFired`, `ProteusFirewallReloadFailing`,
  `ProteusServerDrainStuck` (sustained SIGTERM drain).
- **info** — trending signal; dashboard-panel-grade, not paging.

Every alert message includes a recovery action in the
description. Example: `ProteusUserQuotaAdmissionRejecting`
points the operator to "audit access_log + adjust per-user
override OR raise default_period_bytes"; `ProteusAeadDropsCatastrophic`
points to "identify source IP from access_log + firewall-deny
immediately. If multiple sources, treat as coordinated attack."

### Grafana dashboard

A pre-built Grafana dashboard ships at
`deploy/grafana/dashboards/proteus-overview.json` covering 30+
panels across the server + client surface. Import via Grafana
UI ("Import dashboard" → upload JSON) OR provision via
`provisioning/dashboards/`:

```yaml
# /etc/grafana/provisioning/dashboards/proteus.yaml
apiVersion: 1
providers:
  - name: proteus
    type: file
    options:
      path: /var/lib/grafana/dashboards/proteus
```

The dashboard's panel families:

- **Liveness** (server/client up, TLS cert days remaining, panic
  count, previous-run-unclean, restart count)
- **Throughput** (handshakes/sec, in-flight sessions, bytes/sec,
  handshake latency p50/p95/p99)
- **DNS + bootstrap** (DoH-leak signal: bootstrap_via_system_resolver)
- **Log throttling** (rate-of-suppressed log lines, access-log
  writer alive)
- **Cover-forward** (rate + REJECTIONs)
- **Client dial outcomes** (per-endpoint success/fail rate,
  carrier-suppressed, all-endpoints-suppressed)
- **SIGHUP reload backlog** (per surface: firewall, rate_limit,
  user_rate_limit, handshake_budget, client_pool_reload)
- **Per-user observability** (top-5 bandwidth via `topk()`,
  abuse-fires across the 3 detectors)
- **Attack signals** (AEAD integrity drops + ratchets context,
  SSRF rejections, probe-anomaly per-/24 attribution, handshake
  failure vs success rate, per-user quota rejections,
  session-lifecycle reaps)

Every panel description references the alert rule that fires on
the same signal, so an operator clicking a panel can immediately
trace back to "what would page me about this graph going red".

### In-process `alerts-check` (no Prometheus needed)

Single-user / personal-VPN deploys often don't run Prometheus.
Both binaries ship a one-shot evaluator that scrapes `/metrics`
in-process and prints per-rule verdicts:

```
proteus-server admin alerts-check --token-file /etc/proteus/keys/metrics.token
proteus-client alerts-check --url http://127.0.0.1:9091
```

Exits 0 on PASS+WARN-only, 1 on any CRIT. Wire into
Ansible/Terraform deploy gates + cron for fresh-deploy smoke
checks. Every rule in the bundled `*-alerts.yaml` files has a
matching in-process check (except a small number that
genuinely need a TSDB for `rate(...[5m])` semantics).

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

## Live snapshot (`proteus-server admin status`)

SSH'd into a live server, no need to remember the `/metrics` path or
the bearer token format:

```bash
# Loopback bind, no auth (matches bundled server.example.yaml):
proteus-server admin status

# With bearer auth:
proteus-server admin status \
    --url http://127.0.0.1:9090/metrics \
    --token-file /etc/proteus/metrics.token

# Or via env var (handy in shell aliases):
export PROTEUS_METRICS_TOKEN=$(cat /etc/proteus/metrics.token)
proteus-server admin status
```

Sample output:

```
============================================================
 proteus-server status — LIVE / READY
============================================================
 Sessions
  in_flight_sessions               7
  sessions_accepted_total          1042
  handshakes_succeeded_total       1019
  handshakes_failed_total          23
  handshake_timeouts_total         2

 Defense pipeline (rejections)
  firewall_denied                  17
  handshake_budget_rejected        0
  rate_limited                     5
  conn_limit_rejected              0
  user_rate_rejected               2
  cover_forwards                   24
  total_rejected                   24

 Session teardown causes
  session_idle_reaped              3
  session_byte_budget_exhausted    0

 Throughput
  tx_bytes_total                   5048321 (4.81 MiB)
  rx_bytes_total                   4119883 (3.93 MiB)
  ratchets_total                   14
  aead_drops_total                 0
============================================================
```

Exit-code-honest: 0 on success, non-zero on any HTTP failure (wrong
URL, wrong/missing token, server down). Suitable for `watch -n 5
proteus-server admin status` over an SSH session or as a probe in
Ansible / Nomad health checks.

### Counter deltas (`admin diff` / `admin watch`)

`status` shows totals. When triaging a fresh DoS the real question
is "how many rejections happened in the last 30 seconds?". Two
modes:

**One-shot delta between two saved scrapes:**

```bash
curl http://127.0.0.1:9090/metrics > /tmp/before
sleep 30
curl http://127.0.0.1:9090/metrics > /tmp/after
proteus-server admin diff --before /tmp/before --after /tmp/after \
                          --interval-secs 30
```

**Live-watch loop (Ctrl-C to exit):**

```bash
proteus-server admin watch --interval-secs 5
```

Either prints per-counter deltas plus per-second rates, e.g.:

```
============================================================
 proteus-server delta over 30.0s — LIVE / READY
============================================================
 Defense pipeline (rejections delta)
  firewall_denied                          5 (  0.17/s)
  handshake_budget_rejected                0 (  0.00/s)
  rate_limited                            10 (  0.33/s)
  ...
  total_rejected                          15 (  0.50/s)
```

If a counter drops between scrapes (process restart, manual reset),
the output displays a `⚠ counter reset detected` banner — operators
know to discard the rate numbers for that interval. The display
saturates clamped to 0, never wraps.

### JSON output for scripts

All three admin subcommands accept `--format json`, which emits a
single canonical JSON document (no banners, no human formatting).
Field names are stable snake_case `u64`/`bool`. Pipe straight into
`jq` for scripted alerting:

```bash
# Alert when rejection rate goes above 1/s over the last 30s.
proteus-server admin diff --before /tmp/before --after /tmp/after \
                          --interval-secs 30 --format json |
    jq 'if .total_rejected / .interval_secs > 1
        then "ALERT: \(.total_rejected) rejections in \(.interval_secs)s"
        else empty
        end'

# Live-watch loop emitting one JSON line per refresh:
proteus-server admin watch --interval-secs 5 --format json |
    jq -c 'select(.firewall_denied > 0) | {ts: now, firewall_denied}'
```

JSON shape:

- `MetricsSnapshot` (status): every counter as snake_case `u64`,
  plus `alive`/`ready` bools, plus `other: {…}` for unknown
  counters (forward-compat).
- `MetricsDelta` (diff/watch): same counters as deltas, plus
  `interval_secs` (`f64`), `counter_reset` (`bool`), and end-of-
  interval `alive`/`ready`/`in_flight_sessions`.

Zero-interval calls render `interval_secs: 0.000` (never `Inf` or
`NaN` — those are not valid JSON).

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

### Host-posture preflight (`preflight check-host` / `check-host`)

`validate` checks the YAML + referenced files; the host-posture
preflight checks the HOST's posture (key file modes, DNS
resolvability of hostname endpoints, urandom seeding, clock skew,
trusted_ca readability). Run alongside `validate` for full
coverage. **Note the asymmetric subcommand naming**: the server
binary exposes it under the `preflight` umbrella (one of three
sub-checks; `preflight all` runs everything in one shot — see
the next section), the client binary exposes it as a top-level
`check-host` command (no umbrella — the client only has the one
preflight surface):

```bash
# Server — full preflight suite (IP reputation + host posture + JA4 fingerprint):
sudo -u proteus proteus-server preflight all \
    --config /etc/proteus/server.yaml \
    --public-ip "$(curl -s https://api.ipify.org)"

# Server — host posture only:
sudo -u proteus proteus-server preflight check-host --config /etc/proteus/server.yaml

# Client (operator's laptop) — host posture, top-level subcommand:
proteus-client check-host --config ~/.proteus/client.yaml
```

What the host-posture preflight catches that `validate` doesn't:

- **Key file mode (0600 on Unix)** — a `rsync` without `-p` leaves
  PQ secret keys world-readable on the destination. `validate`
  only checks the file exists; `preflight check-host` FAILs on
  group-or-world readable.
- **Hostname endpoint DNS resolvability** — `vps.example.com:8443`
  in `server_endpoint` typoed to `vps.exmple.com:8443` won't be
  caught by `validate` (it's a valid host:port string); the
  client `check-host` does an actual DNS lookup.
- **CA bundle PEM block presence** — `tls.trusted_ca` is a file
  but `validate` doesn't parse the bytes; `preflight check-host`
  confirms there's at least one PEM block.

### Live handshake smoke (`connect-test`)

For end-to-end verification (the operator wants to know "does my
new client.yaml actually CONNECT, not just parse?"), the client
ships a one-shot handshake test:

```bash
# Test the configured server_endpoint
proteus-client connect-test --config ~/.proteus/client.yaml

# Test EVERY entry in server_endpoints: pool independently
proteus-client connect-test --all-endpoints --config ~/.proteus/client.yaml
```

Runs the full Proteus α-profile handshake (TLS + ML-KEM + X25519
+ Finished MAC), drops the session, prints per-stage timing +
exit 0 / 1. The `--all-endpoints` form runs the test once per
pool entry — without it operators only verify the primary,
leaving HA backup entries unverified until first failover (the
worst possible moment for a surprise).

Five-command pre-deploy smoke checklist (gate every operator
edit through this):

```bash
proteus-server validate --config /etc/proteus/server.yaml || exit 1
proteus-server preflight check-host --config /etc/proteus/server.yaml || exit 1
# (on client laptop after the server is up:)
proteus-client validate --config ~/.proteus/client.yaml || exit 1
proteus-client check-host --config ~/.proteus/client.yaml || exit 1
proteus-client connect-test --all-endpoints --config ~/.proteus/client.yaml || exit 1
```

All five green = production ready. Any FAIL = fix before deploy.

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

## Key rotation (anti-clobber by default; `--force` to opt in)

All four key-emitting subcommands (`proteus-server keygen` /
`gencert` / `knock-keygen` / `proteus-client keygen`) **refuse to
overwrite existing files by default**. This protects you from
re-running the bootstrap script on a deployed server and silently
clobbering the production keys (which would break every active
session AND every future connect — see the rotation runbooks
below for what actually has to happen).

A refused run prints exactly what would break and exits 1 without
touching any file:

```text
Error: refusing to overwrite existing key file /etc/proteus/keys/server_lt.mlkem768.pk.
The current server identity bundle is in active use — every client's
`server.pq.fingerprint` pin would mismatch the new mlkem768.pk and reject
the handshake with 'fingerprint mismatch' on the very next connect.
If you ARE deliberately rotating: 1) pre-distribute the new fingerprint
to every client (out-of-band), 2) re-run with `--force` to overwrite,
3) restart the server.
```

### Rotation runbook: TLS cert (`gencert --force` or just Let's Encrypt)

```bash
# Option A: regenerate the self-signed cert in place. The SIGHUP
# handler (see TLS hot-reload section above) hot-swaps without
# dropping in-flight sessions.
sudo -u proteus proteus-server gencert \
    --dns-name vps.example.com \
    --out /etc/proteus/keys/tls \
    --force
sudo systemctl kill --signal=HUP proteus-server

# Option B: just use Let's Encrypt + the certbot deploy hook above.
# The hook already does in-place file replacement + SIGHUP — no
# `--force` needed because certbot writes to a different path
# and the operator's hook is the one that copies into /etc/proteus.
```

### Rotation runbook: knock PSK (`knock-keygen --force`)

```bash
# 1. Mint the new PSK to a STAGING path (does not affect the live
#    server yet — the live server is still using the old PSK).
sudo -u proteus proteus-server knock-keygen \
    --out /etc/proteus/keys/server.knock_psk.NEW

# 2. Distribute the new PSK to EVERY client out-of-band BEFORE you
#    cut the server over. Any client not pre-staged with the new
#    PSK will fail the knock and see only the cover-site response.

# 3. Cut over the server to the new PSK by replacing in place.
sudo mv /etc/proteus/keys/server.knock_psk.NEW \
        /etc/proteus/keys/server.knock_psk
# (mv overwrites the old file; the binary will pick up the new
# PSK on its NEXT load — restart or SIGHUP.)
sudo systemctl restart proteus-server

# OR if you'd rather use --force in one step (no staging):
sudo -u proteus proteus-server knock-keygen \
    --out /etc/proteus/keys/server.knock_psk \
    --force
# But the staging variant lets you abort cleanly mid-rotation.
```

### Rotation runbook: long-term server identity (`keygen --force`)

The full ML-KEM-768 + X25519 + fingerprint bundle. **This is the
most disruptive rotation** because every client's
`server.pq.fingerprint` pin must be re-distributed before they
can reconnect. Only do this if you have reason to believe the
long-term secret was compromised, or as a planned annual rotation.

```bash
# 1. Mint a fresh bundle to a side dir.
sudo -u proteus proteus-server keygen --out /etc/proteus/keys-NEW

# 2. Pre-distribute the new server_lt.*.pk + server_lt.pq.fingerprint
#    files to EVERY client out-of-band.

# 3. Swap atomically. Old keys go to keys-OLD/ as recovery insurance.
sudo mv /etc/proteus/keys /etc/proteus/keys-OLD
sudo mv /etc/proteus/keys-NEW /etc/proteus/keys
sudo systemctl restart proteus-server

# 4. After ~24h with no client breakage, remove the recovery dir.
sudo rm -rf /etc/proteus/keys-OLD
```

The `keygen --force` form (in place, no staging dir) is supported
but NOT recommended for this bundle — there's no way back to the
old keys once `--force` writes over them, so the staging-dir +
atomic-mv recipe above gives you a recovery escape hatch.

### Rotation runbook: client identity (`client keygen --force`)

Same idea but coordinated with the server admin:

```bash
# 1. Mint a new bundle to a side dir.
proteus-client keygen --out ./new-client-keys

# 2. Send new-client-keys/client.ed25519.pk to server admin.

# 3. WAIT for confirmation it's been added to the server allowlist.

# 4. Swap. The old identity stops working the moment ~/.proteus.yaml
#    points at the new SK.
mv ./keys/client ./keys/client-OLD
mv ./new-client-keys ./keys/client
# Edit ~/.proteus.yaml if the path changed; restart proteus-client.
```

`client keygen --force` (overwrite in place) is supported for the
"I haven't deployed yet, I'm just iterating on local config"
workflow — but ONCE you've shared your `client.ed25519.pk` with
the server admin, always use the staging recipe instead.

## Deployment topology — direct-dial vs. relay (2026 GFW reality check)

The single biggest deployment decision that affects Proteus's
survival under 2026 GFW pressure is **not** any in-protocol knob.
It's the **physical topology** of where your server lives and how
the client reaches it.

### TL;DR

- ✅ **Direct-dial from client to a single offshore VPS you control.**
  This is the only topology that survived the 2026-04 mass-takedown
  wave intact. Use it.
- ❌ **Domestic-relay / "中转机场" topology** (client → IDC inside
  the censoring country → exit IP offshore). Wiped at the IDC layer
  during the 2026-04 takedown — physical disconnection, not protocol
  detection. Even a perfect protocol won't save you if your relay
  server's network cable is pulled out of the rack. **Do not deploy
  Proteus in this topology.**
- ⚠ **Shared-IP commercial proxy farm** (one VPS, many users from
  many subscriptions). Subject to the Geedge / Tiangou cross-deployment
  shared-blocklist attack (`qa/2026-05-17-gfw-2026-q1q2-threat-intel.md`
  main line 1). Acceptable for short-lived testing; not acceptable
  for a node you want to keep running.

### Why this matters more than the protocol

The 2026 GFW threat surface has moved beyond "can the adversary
identify the protocol's wire signature?" Two of the seven active
2026 attack lines hit the *deployment*, not the protocol:

| Attack line | What it targets | Defense at the protocol layer? |
|---|---|---|
| **Tiangou shared IP blocklist** (main line 1) | The IP address itself, regardless of what protocol it runs | None. Your job is to pick an unburned IP. |
| **2026-04 IDC physical disconnection** (main line 2) | The hosting provider's coercion exposure, not the wire signal | None. Your job is to not depend on an IDC inside the censoring country's jurisdiction. |

Full analysis lives in the threat-intel doc; the operational
takeaway is below.

### Recommended topology (direct-dial)

```mermaid
flowchart LR
    Client["Client device<br/>(laptop, phone)"]
    VPS["Offshore VPS<br/>(your own, single-tenant)"]
    Upstream["Upstream target<br/>(Google, GitHub, ...)"]

    Client == "β QUIC / α TLS<br/>(Proteus inner handshake)" ==> VPS
    VPS -- "plain TCP" --> Upstream

    classDef ours fill:#fde,stroke:#c39,stroke-width:2px
    class Client,VPS ours
```

Properties:

- **Single-hop, no intermediary.** Client opens a TCP/UDP socket
  directly to the VPS's offshore IP. No domestic forwarder, no
  jurisdiction layering.
- **You alone control the server.** Not a shared subscription with
  unknown other users — your IP is yours to keep clean. Shared IPs
  inherit other users' policy violations and end up on shared
  blocklists.
- **Personal-scale workload.** A handful of users you know, not
  hundreds of paying strangers. Reduces both the IP-reputation
  decay rate and the legal blast radius if your provider asks
  questions.
- **Operator picks the IP.** Run `proteus-server preflight
  check-ip-reputation --public-ip <ip>` before deploying (see
  `## Pre-deploy IP reputation check` further down) — catches the
  "I rented a Vultr droplet last month, didn't realize it was
  previously hosting a SS service" failure mode.
- **Bootstrap-DNS pinned.** Client config pins the VPS IP literal
  (`server_endpoint: "<vps-ip>:8443"`) OR pairs the hostname with
  `bootstrap_dns: { direct_ip: <vps-ip> }`. Either way, the client
  never issues an A/AAAA lookup for the VPS hostname — defeats the
  2026 GFW DoH/DoT identification attack at the bootstrap layer.

### Anti-pattern: domestic relay (do not deploy)

```mermaid
flowchart LR
    Client["Client device"]
    DomesticRelay["Domestic IDC relay<br/>(WIPED 2026-04)"]
    Exit["Offshore exit VPS"]
    Upstream["Upstream target"]

    Client --> DomesticRelay
    DomesticRelay --> Exit
    Exit --> Upstream

    classDef dead fill:#fcc,stroke:#900,stroke-width:2px,stroke-dasharray: 5 5
    class DomesticRelay dead
```

Why this died:

- **2026-04-01 onward**: executive coordination between authorities
  and major IDCs in Guangdong, Shanghai, Beijing led to **physical**
  network cable removal + power-down of identified relay servers
  ([RelyVPN April 2026 crackdown
  report](https://relyvpn.com/blog/china-vpn-crackdown-2026.html)).
  Not selective; entire racks went dark within hours.
- **The relay's wire protocol is irrelevant.** SS, V2Ray (VMess),
  Trojan, VLESS, and even VLESS+Reality nodes hosted on the wiped
  IDCs all died the same way. No amount of in-protocol obfuscation
  helps when the cable is unplugged.
- **The economic upstream had its own attack**: provincial authorities
  ordered ISPs to terminate the cross-border dedicated leased lines
  (跨境专线 / IEPL) that fed many relay services. Even relays that
  physically survived found their upstream capacity vanish.
- **It hits "中转机场" services hardest** because their cost model
  requires a domestic IDC for latency reasons. Pure-offshore services
  (which is what direct-dial is) were untouched by the IDC wave.

If you read this and your config looks like the second diagram, the
right action is **redeploy on a single offshore VPS** before adding
any more features. The protocol on top doesn't matter if the topology
is wrong.

### Anti-pattern: commercial proxy farm (avoid for long-lived nodes)

If you set up Proteus to resell access — say, a small subscription
shop with shared exit IPs — every user's misuse becomes your
problem. The Tiangou shared-blocklist model means one user
hammering a sensitive service from your shared IP poisons the IP
for every other user concurrently and for an unknown future
window. The 9 commercial VPN brands flagged "resolved" in the
Geedge leak tickets all share this exposure shape.

The user scenario this project targets — **a single person with
one clean offshore VPS, running Proteus for themselves and a small
trusted circle** — explicitly avoids this failure mode. If your
plan deviates from that, factor in the IP-rotation overhead
explicitly and budget for `proteus-server preflight
check-ip-reputation --watchlist` to drive automated IP refresh.

### Pre-deploy IP reputation check

Before binding the listener:

```bash
# Discover your VPS's actual outbound IP (cloud providers expose this
# in the console, or use a one-off lookup):
MY_VPS_IP="$(curl -s https://api.ipify.org)"

# Classify it against the offline reputation table (special-use IPs,
# known commercial-cloud CIDRs, optional operator watchlist):
proteus-server preflight check-ip-reputation \
    --public-ip "$MY_VPS_IP" \
    --config /etc/proteus/server.yaml
```

Exit codes:

- `0` — PASS or WARN (proceed if WARN is acceptable, e.g. "yes I know
  this is a Vultr IP, I just rented it fresh and accept the rotation
  budget"). The WARN line names the provider so you can decide.
- `1` — FAIL. Either the IP is special-use (config error: the listener
  is bound to `127.0.0.1` / RFC 1918 / CGNAT etc.) or it matches an
  operator-supplied `--watchlist` rule for an IP you previously
  burned. Fix before proceeding.

Run this in your provisioning pipeline (Ansible / Terraform / hand-
rolled deploy script) **before** `systemctl start proteus-server`.
Documented in detail at
`crates/proteus-server/src/ip_reputation.rs` — the table is
intentionally non-exhaustive, so a CLEAN result is "no obvious
red flag", not "verified safe by us".

### Operator-supplied watchlist (your own burned-IP record)

```bash
# /etc/proteus/burned-ips.txt — track IPs that have failed in the past
# so a future operator (or future-you) doesn't accidentally re-rent one.
cat > /etc/proteus/burned-ips.txt <<'EOF'
# Format: CIDR  human-readable reason
198.51.100.42/32   2026-03-15: blocked within 2 days of deploy, suspect carry-over
203.0.113.0/24     2026-02-04: entire /24 from provider X went dark mid-quarter
EOF

proteus-server preflight check-ip-reputation \
    --public-ip "$MY_VPS_IP" \
    --watchlist /etc/proteus/burned-ips.txt
```

Treat this file as part of your deployment state — version-control
it alongside your `server.yaml`. Each entry encodes one fact you've
paid for; losing the record means re-paying.

---

## Security checklist before going live

### Mandatory preflight gate (5 commands, all must exit 0)

The single canonical gate that subsumes most of the items
below. Run on every deploy + every config edit:

```bash
proteus-server validate --config /etc/proteus/server.yaml
proteus-server preflight check-host --config /etc/proteus/server.yaml
# (on the client laptop, AFTER the server is up:)
proteus-client validate --config ~/.proteus/client.yaml
proteus-client check-host --config ~/.proteus/client.yaml
proteus-client connect-test --all-endpoints --config ~/.proteus/client.yaml
```

The preflight gates catch ~130 documented operator-trap classes
including: cert expiry, all-zero placeholder keys,
SOCKS5 open-proxy binds, admin-endpoint wildcard exposure,
catastrophic open-relay coherence (empty allowlist + wildcard
+ no firewall), SSRF defense disabled, cloud-metadata IP
exposure, DoH-leak via system resolver, key file mode 0644,
HA pool entries with hostname-divergent SNI, etc.

### Items not covered by the preflight gates

Operator-judgment items the binary can't verify automatically:

- [ ] `proteus-server keygen` ran on the **server itself** (never copy
      `*.sk` files between hosts).
- [ ] `cover_endpoint` is a real, popular HTTPS site you do **not**
      operate. Cloudflare, Microsoft, Apple are good choices. The
      cover server MUST NOT be your own — that would be a first-party
      fingerprint. (`validate` catches private-IP / loopback / self-
      reference but can't verify "the operator doesn't own this domain".)
- [ ] **Topology is direct-dial offshore VPS** (see `## Deployment
      topology` above). NOT a domestic relay (wiped 2026-04), NOT a
      shared-IP commercial proxy farm (Tiangou shared-blocklist
      exposure). Required for the design's threat model to hold.
- [ ] **`proteus-server preflight check-ip-reputation` ran clean OR
      WARN** for the VPS's actual outbound IP. A WARN with an
      acknowledged provider name is acceptable for a freshly-rented
      VPS; a FAIL is not.
- [ ] Logs at `/var/log/proteus/*` are rotated (use `logrotate` or
      `journald` retention policy).
- [ ] Prometheus alerts are loaded (or `alerts-check` is wired into
      cron / supervisor) — see `### Prometheus alerts` /
      `### In-process alerts-check` above.

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
- **SSRF / internal-network probing via the proxy**: the
  `OutboundFilter` blocks RFC 1918 / RFC 4193 ULA / link-local /
  loopback / cloud-metadata (`169.254.169.254`) by default; an
  attacker holding a stolen credential can't use the proxy as a
  gateway to map / probe the operator's LAN OR steal cloud IAM
  credentials. `validate` gates the three foot-guns at preflight:
  `disabled: true`, `replace_default_blocklist: true`, and bad
  CIDR entries. Runtime rate of rejections is alerted via
  `ProteusSsrfAttempts{Observed,Catastrophic}` + dashboarded.
- **Active MITM tampering** (bit-flipping records): AEAD-decryption
  rejection is counted on `proteus_aead_drops_total` and alerted
  via `ProteusAeadDropsCatastrophic` (>1/sec for 2 min = page-
  grade). Cross-references `proteus_ratchets_total` to distinguish
  key-rotation race from genuine tampering.
- **Operator-config-induced public open-relay**: empty
  `client_allowlist` + wildcard `listen_alpha` + no firewall =
  the whole internet relays through the operator's egress IP.
  `validate`'s catastrophic-open-relay coherence check (iter-97)
  FAILs the combination at preflight with three documented
  recovery paths.
- **Catastrophic config foot-guns (zero-value safety disable)**:
  every numeric knob with a `=0` "disable" path is gated at
  preflight (`max_inflight_sessions: 0` → local OOM,
  `socks_request_timeout_secs: 0` → slow-loris, `period_secs: 0`
  → quota collapse, `handshake_deadline_secs: 0` → every dial
  fails). 130+ checks across both binaries.
- **TLS cert expiry / rotation**: cert lifetime is checked at
  preflight (iter-46/iter-47) AND continuously via the
  `proteus_tls_cert_not_after_unix_seconds` gauge +
  `ProteusTlsCert{Expired,ExpiringSoon}` alerts + the file-mtime
  watcher (`tls_cert_watcher_interval_secs`) auto-reloads without
  SIGHUP.
- **Catastrophic admin endpoint exposure**: wildcard bind on the
  unauthenticated `admin_listen` (client) / `metrics_listen`
  (server, without token) is FAILed at preflight (iter-71/iter-73)
  — operators can't accidentally ship an internet-reachable
  HA-topology inventory.

Not yet defended in this M1 release:
- Multipath / blanket-port-block fallback (M4).
- Active shape-shifting / cover-IAT online learning (M3).
- Real TLS 1.3 outer record layer (M2 — current build uses a typed
  framing shim directly over TCP).
- 0-RTT QUIC resumption (M3 — α profile is 1.5-RTT, β is 1-RTT
  after handshake).
