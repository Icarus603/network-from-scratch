---
name: 2025-09-11-geedge-mesa-leak
description: 600 GB Geedge Networks + MESA Lab document leak (2025-09-11) — first public catalogue of named GFW commercial products (Tiangou, TSG, Cyber Narrator) + cross-deployment shared blocklist evidence. Synthesizes GFW.report, InterSecLab 76 p, Amnesty 102 p secondary analyses.
metadata:
  type: gfw-incident-note
  source_kind: industry-leak-secondary-analyses
  raw_archive_size: ~600 GB
  primary_publication_date: 2025-09-11
---

# Geedge & MESA Leak: Analyzing the Great Firewall's Largest Document Leak
**Venue / Year**: GFW.report blog, 2025-09-15 (analysis of 2025-09-11 leak event)
**Authors**: GFW.report collective + InterSecLab (76 p technical report) + Amnesty International (102 p Pakistan report)
**Read on**: 2026-05-17 (qa/2026-05-17-gfw-2026-q1q2-threat-intel.md)
**Status**: secondary analyses public; **source code itself NOT yet exhaustively reverse-engineered** as of 2026-05
**One-line**: 600 GB of Geedge Networks + MESA Lab internal artifacts (Jira / Confluence / GitLab) leaked 2025-09-11, exposing the commercial GFW product line (Tiangou Secure Gateway, Cyber Narrator dashboard, TSG Galaxy data warehouse, Network Zodiac, AppSketch Works) and cross-customer shared VPN/proxy/Tor blocklists — first public confirmation that the GFW is now an industrialized exportable product, not a one-off government project.

## Problem

Until 2025-09 every GFW analysis was external: black-box probing (GFW.report, NDSS Wallbleed, USENIX Wu/Bock/Zohaib), inferred from RST patterns, timing, and ML classifier outputs. We had to guess at the internal architecture. The leak gave the first **named-component view** of how the GFW is built, sold, and operated.

## Contribution

The leak's contribution is **organizational and architectural**, not algorithmic. Even with source code not fully RE'd, the leak proves:

1. **A commercial product line exists**: Geedge Networks (Beijing, founded by Fang Binxing — "father of the GFW") sells GFW-equivalent appliances under names operators can deploy and configure. This is not a research curiosity.
2. **The product is sold abroad**: Belt-and-Road customers include Myanmar (26 data centers, 81 M concurrent TCP sessions), Pakistan, Ethiopia, Kazakhstan. The "GFW model" is now multi-jurisdiction.
3. **The product evolves under iteration pressure from paying customers**: not a static deployment. Customer-driven feature requests (e.g., "block X commercial VPN") flow through Jira → engineering → shipped detection rule.
4. **Cross-deployment blocklists are shared**: a VPN/proxy IP detected in Myanmar gets added to a Geedge-maintained global blocklist, instantly degrading that IP for every Geedge customer including domestic Chinese provinces.
5. **9 commercial VPNs are tagged as "resolved"** in internal tickets — i.e., Geedge claims complete identification + blocking capability. Specific names not in public summaries.

## Method (just enough to reproduce mentally)

The leak was published by an anonymous source on 2025-09-11 (Hetz / DDoSecrets mirror). Total ~500-600 GB, mix of:
- Jira tickets (engineering workflow, customer requests, bug reports)
- Confluence wikis (product documentation, architecture diagrams)
- GitLab repositories (source code — *the* substrate, but not yet exhaustively analyzed by Western researchers as of 2026-05)
- Build artifacts, deployment configs

**Named products surfaced from secondary analyses**:

| Product | Role |
|---|---|
| **Tiangou Secure Gateway (TSG, TSG8)** | DPI flagship — HTTPS/TLS inspection, SSL/TLS MITM, ML behavioral classification, VPN/proxy detection |
| **Cyber Narrator** | Operator dashboard (white-label for customer countries) |
| **TSG Galaxy** | Traffic data warehouse + offline analytics back-end |
| **Network Zodiac** | System monitoring + alert plane |
| **AppSketch Works** | "Application identification rule" maintenance UI — customer-local rules for what to block |

**Documented capabilities** (compiled from InterSecLab, Amnesty, GFW.report secondary analyses — none from full source RE):
- Deep packet inspection of HTTP/HTTPS/TLS
- SSL/TLS interception (mid-path decrypt where CA infrastructure cooperates)
- AI / behavioral analysis on encrypted-flow features (not signature-only)
- "Application identification" — proxy/VPN/Tor protocol classification
- Active probing of suspicious IPs (TCP / TLS / QUIC application-layer probes)
- IP reputation scoring + cross-deployment shared blocklist database
- HTTP session content injection (advertising / malware insertion — used by certain hostile-state operators)
- DDoS launch capability (the dual-use side)
- "Anonymous user identification via online footprint" — tracking individuals across services

## Results

- **9 commercial VPNs tagged "resolved"** in internal tickets (specific names not in public summaries; the tickets exist but require deeper RE).
- **Belt-and-Road deployments**: 26 Myanmar DCs running TSG; 81 M concurrent TCP sessions per deployment.
- **Domestic provincial deployments**: Xinjiang, Jiangsu, Fujian use TSG as supplementary to the primary GFW backbone — i.e., the GFW + Geedge appliances together form a layered defense within China itself.
- **No specific JA3/JA4 hashes, ML model weights, or numerical thresholds disclosed in public summaries** as of 2026-05. The source code presumably contains these but has not been exhaustively analyzed.

## Limitations / what they don't solve

The leak's **technical detail floor** is the binding constraint. We have:
- Architecture (named modules, dataflow, customer list)
- Capability statements (DPI / SSL inspection / ML / active probing)
- Geographic deployment evidence

We do NOT yet have:
- Concrete JA3/JA4 fingerprint database contents
- ML model architectures or feature vectors
- Active-probing payload templates (exact bytes Geedge sends)
- Cross-deployment blocklist data structures
- Customer-specific policy configurations beyond high-level descriptions

Until Western researchers complete a thorough source-code RE pass (a months-to-years project given 600 GB scope + Chinese-language comments + obfuscated internal terminology), the operational threat model for protocol designers is:

> "Assume Tiangou has at least the public-research-grade detection capability (USENIX 23 five heuristics, Wallbleed 2025, USENIX 25 QUIC SNI), AND additional capabilities NOT yet disclosed externally, AND a feedback loop from paying customers that drives faster iteration than the public-research community can keep up with."

## How it informs our protocol design

This leak is the single most important update to Proteus's threat model since the project started. Key shifts:

1. **The adversary is now an iterating commercial product, not a static research target.** Designs that beat "GFW as documented in USENIX 23-25" are insufficient — we must beat "GFW as it WILL be in 2027 after Geedge ships its next 4 customer-requested classifier updates."
2. **Cross-deployment shared blocklist is a new operational risk.** An IP burned in Myanmar burns the same IP for Chinese users. Operators MUST preflight VPS IPs against known Geedge-shared blocklists. → Proteus needs `proteus-server preflight --check-ip-reputation`.
3. **9 commercial VPNs are "resolved"** — implying Reality, VLESS, Hy2, TUIC, V2Ray, Trojan all have at least partial detection paths even if not flagged by name. Our design must assume "every existing widely-deployed proxy is already classifiable to some extent" and engineer around it.
4. **SSL/TLS interception capability** means cover-server splice on auth fail is *more* important, not less — but also means the cover server itself must be a legitimate high-traffic destination the adversary won't want to flag wholesale.
5. **AI behavioral analysis** confirms that signature-only defenses (clean JA4, byte-pattern obfuscation) are insufficient. Statistical-distribution defenses (cell-split padding, cover heartbeats, timing camouflage) are the load-bearing layer.

Concrete Proteus changes traced to this leak:
- **P0**: ECH (spec §7.4) — escalate from M3 to launch-blocker. SSL/TLS interception capability means SNI in cleartext is a stronger signal than under traditional GFW.
- **P0**: IP reputation preflight tool — `proteus-server preflight --check-ip-reputation`.
- **P0**: `bootstrap_dns: direct_ip` mode + recommendation — bypass DoH/DoT entirely.
- **P1**: uTLS bit-perfect ClientHello — close the JA4 ext_count gap, eliminate the last static-signature distinguisher.
- **P1**: Cover-endpoint pool rotation — defeat time-series active probing against a single cover URL.

## Open questions

1. **What exactly does Tiangou's "VPN classifier" inspect?** Until source RE is complete, we operate on inference: presumably (a) JA3/JA4 against a curated database, (b) packet-size + inter-arrival statistical features against trained models, (c) handshake-pattern signatures (e.g., V2Ray VMess timing), (d) active-probing response classification.
2. **How fresh is the cross-deployment blocklist?** Is it real-time pushed or batch? Critical for understanding our IP-rotation cadence.
3. **What's the false-positive tolerance Geedge sells?** A classifier with 95% precision and 50% recall has very different operational implications from 99.99/99.99. Their customer-facing SLAs would tell us.
4. **Has any 9-of-9 "resolved" commercial VPN published a post-mortem?** None public as of 2026-05 — operators don't want to confirm they're broken. We need OSINT here.
5. **When will full source RE land?** GFW.report has Geedge as a multi-year analysis target. Until then, plan for worst-case capabilities not best-case.

## References worth following

- [GFW.report Geedge & MESA Leak analysis (2025-09-15)](https://gfw.report/blog/geedge_and_mesa_leak/en/) — primary tracking index
- [InterSecLab "The Internet Coup" 76 p technical report](https://interseclab.org/research/the-internet-coup/) — most detailed public technical analysis
- [Amnesty International ASA 33/0206/2025 (Pakistan)](https://www.amnesty.org/en/wp-content/uploads/2025/09/ASA3302062025ENGLISH.pdf) — 102 p Belt-and-Road deployment evidence
- [net4people/bbs #519](https://github.com/net4people/bbs/issues/519) — community continuous-tracking thread
- [Tom's Hardware initial coverage (2025-09-13)](https://www.tomshardware.com/tech-industry/chinas-great-firewall-springs-huge-leak) — non-technical summary
- [Cybersecurefox "DPI stack" analysis](https://cybersecurefox.com/en/great-firewall-600gb-leak-dpi-tiangou/) — Tiangou architecture summary
- [China Digital Times 2025-09 dual-leak coverage](https://chinadigitaltimes.net/2025/09/two-major-leaks-illuminate-censorship-and-surveillance-sales-into-and-from-china/) — contextualizes against parallel Yunlu leak

## Citation hygiene note

When a future Proteus lesson cites "Tiangou can detect X" — the citation MUST be either (a) a public secondary analysis that itself cites the leak with a specific Jira ticket / Confluence page reference, OR (b) a source-RE result from a named analyst's published work. **Do not cite "the leak reveals X" from memory** — public summaries cherry-pick, and we cannot verify against the raw archive without the analyst chain.
