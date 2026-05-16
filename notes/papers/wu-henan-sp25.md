---
name: wu-henan-sp25
description: Wu et al. S&P 2025 first measurement of provincial-level censorship in Henan, distinct from the national GFW
metadata:
  type: paper-precis
---

# A Wall Behind A Wall: Emerging Regional Censorship in China
**Venue / Year**: IEEE S&P 2025
**Authors**: Mingshi Wu, Ali Zohaib, Zakir Durumeric, Amir Houmansadr, Eric Wustrow (UMass Amherst + Stanford + CU Boulder + GFW Report)
**Read on**: 2026-05-16 (in lesson 9.15)
**Status**: full PDF (gfw.report/publications/sp25/en/)
**One-line**: First empirical measurement of provincial-level censorship inside China — Henan operates a separate firewall at hop 5 with a 4.2 M-domain blocklist, distinct RST fingerprint, no stateful tracking, and 20-byte-TCP-header parsing flaw.

## Problem
Prior censorship literature treats the GFW as monolithic. Anecdotal reports from Henan (esp. on `mlb.com` blocking 2022-2023) suggested a separate provincial layer. No prior at-scale measurement existed.

## Contribution
1. Identify and characterize the Henan Firewall (HenanFW) as a distinct censorship infrastructure operating *only* on egress from Henan.
2. Cumulative blocklist of 4.2 M domains over Nov-2023 → Mar-2025, ~10× the GFW's blocklist at peaks (~741K domains for GFW).
3. Identify three structural differences vs GFW: no TCP reassembly, no stateful connection tracking, no residual censorship after match.
4. Identify a critical parsing flaw: HenanFW only blocks TCP packets with exactly a 20-byte TCP header (no TCP options). 78% of real-world TLS traffic carries options → silently bypassed.
5. Distinctive RST+ACK injection: single packet with 10-byte TCP payload `01 02 03 04 05 06 07 08 09 00` — different from GFW's three-RST burst.

## Method
- Tranco top-1M daily measurement + 227M CZDS weekly sweeps.
- Measurement points across 7 Chinese cities via dedicated VPS.
- Differentiate provincial vs national censorship via packet-level fingerprint (RST count, RST payload pattern, TTL).
- Cross-validate with traceroute hop distance (HenanFW at hop 5, GFW at hop 7).
- Track blocklist churn (mean 35.7-day blocking duration with median 21 — vs GFW 173.8/256).

## Results
- HenanFW blocks generic SLDs aggressively: `*.com.au`, `*.co.za`, government second-level domains.
- HTTP-Host and TLS-SNI blocklists are *identical* in HenanFW (in contrast to GFW which keeps protocol-distinct blocklists per Zohaib 2025).
- 22% of all TCP packets and 19% of TLS packets in real traffic have the bare 20-byte TCP header that HenanFW requires for matching → 78%+ of real TLS traffic bypasses HenanFW without any active circumvention.

## Limitations / what they don't solve
- Does not characterize whether other provinces (Xinjiang, Tibet, Beijing) have similar infrastructure — the paper hints they do but does not measure.
- Mechanism for blocklist generation in Henan unknown.
- Does not address whether HenanFW is run by the province or by a delegated ISP (China Mobile / China Telecom Henan branch).

## How it informs our protocol design (Proteus)
- **Threat model must include "regional censor"**, not just national. Proteus spec §1.3 capability taxonomy should add C-regional (provincial, with own blocklist, different rules).
- **Parsing-flaw exploitation is real**: TCP options inclusion is a free defense against parser-fragile censors. Proteus over TCP-cover SHOULD include TCP options (timestamps, SACK-permitted) as default — many proxy stacks already do, but document this.
- **Henan's 10× blocklist size + 35-day churn** suggests "fail-open + aggressive" model. Implication: Proteus cover domain selection must avoid SLDs that any provincial censor might temporarily blacklist; rotate or use multi-cover.
- **Single-packet RST fingerprint** (10-byte specific payload) is the easiest signature to identify a HenanFW drop in client logs — good telemetry hook for Proteus reference impl.

## Open questions
- Are there more provincial firewalls (Xinjiang has historically had stricter controls)?
- Will Henan eventually fix the 20-byte-header parsing flaw? If so, what version of TCP option presence will it require?
- How does HenanFW interact with GFW when both fire simultaneously?

## References worth following
- Zohaib et al. USENIX Sec 2025 (QUIC SNI) — same author overlap, complementary national measurement.
- Ensafi et al. *Examining How the GFW Discovers Hidden Circumvention Servers.* IMC 2015 — methodology baseline.
- Ramesh et al. *Decentralized Control: A Case Study of Russia.* USENIX Sec 2020 — analogous provincial-vs-national model in another country.
