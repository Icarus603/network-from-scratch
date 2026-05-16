---
name: gfw-report-20250820-port443
description: GFW.report 2025-08-20 analysis of unconditional TCP/443 RST event — distinct fingerprint suggests new or misconfigured GFW device
metadata:
  type: paper-precis
---

# Analysis of the GFW's Unconditional Port 443 Block on August 20, 2025
**Venue / Year**: GFW.report blog post, 2025-08-22 (analysis of 2025-08-20 incident)
**Authors**: GFW.report collective
**Read on**: 2026-05-16 (in lesson 9.15)
**Status**: full blog post; raw packets archived in GFW.report repository
**One-line**: For ~74 minutes on 2025-08-20 the GFW indiscriminately RST-injected every TCP-443 SYN/SYN+ACK observed crossing the China border, with an unusual *incrementing* RST fingerprint (TTL 96/97/98, WIN 2072/2073/2074) — likely a new device or misconfiguration.

## Problem
The GFW historically RST-injects only after matching content (TLS SNI / HTTP Host). An unconditional, port-based block of TCP/443 had never been observed at this scale. The incident broke even non-censorship TLS traffic for ~74 minutes.

## Findings (verbatim from packet captures)
- **Window**: 00:34 → 01:48 Beijing Time (UTC+8), 2025-08-20. Duration ≈ 74 min.
- **Scope**: TCP/443 only. Adjacent ports 1-72, 22, 80, 444, 8443 unaffected.
- **Fingerprint** (per injected RST+ACK burst, 3 RSTs per trigger):
  - IP TTL: 96, 97, 98 (sequential — *not* identical, which is anomalous for known GFW devices).
  - TCP window: 2072, 2073, 2074 (also sequential).
  - DF flag set.
  - Relative seqnum 1.
  - IP IDs: 40305 / 39808 / 38891 (mixed, no clear pattern).
- **Asymmetry**: outbound SYN and inbound SYN+ACK both triggered 3 RSTs. Direction matters less than 5-tuple including port 443.

## How it differs from known GFW devices
- Known GFW devices (MB-1, GFW II) inject *identical* RST values per burst. The incrementing TTL/WIN is novel.
- Suggests either (a) a newly deployed device not previously catalogued, (b) a known device operating in a misconfigured state (e.g., a forwarding-loop counter mistakenly emitted as TTL/WIN), or (c) a deliberate test by GFW operators.
- The brief 74-minute window prevented full identification before the event ended.

## Implications for G6 design
- **The GFW reserves the right to do port-blanket blocks**, even if rare. Any cover-protocol design that pins TCP/443 *only* is fragile against this class of event. G6's three-tier transport (γ=MASQUE/UDP/443, β=raw QUIC, α=TLS/TCP/443) ALREADY anticipates this — if α is RST-flooded, β/γ can serve as live fallback.
- **Fingerprint diversity** as a defensive observable: if client telemetry sees the 3-RST-with-incrementing-fields pattern, it should NOT switch to TCP fallback (which is what's broken) but stay on UDP path. G6 reference impl SHOULD log RST fingerprints when handshake fails on TCP path.
- **Operator implication**: G6 server-side telemetry should record "RST window" anomalies so that operators can correlate user-side breakage with GFW incident timelines.

## Open questions
- Was the new fingerprint a permanent device upgrade (re-deployed later in a stealthy mode) or a one-time misconfiguration?
- Have similar port-blanket events occurred since (poll GFW.report weekly)?

## References worth following
- GFW.report main page for ongoing incident reports.
- net4people/bbs issue tracker — community real-time observations.
- Zohaib USENIX 2025 — same observation methodology (RST fingerprinting for device attribution).
