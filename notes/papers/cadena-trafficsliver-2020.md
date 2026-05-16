# TrafficSliver: Fighting Website Fingerprinting Attacks with Traffic Splitting
**Venue / Year**: ACM CCS 2020
**Authors**: Wladimir De La Cadena, Asya Mitseva, Jens Hiller, Jan Pennekamp, Marcin Reuter, Julian Filter, Thomas Engel, Klaus Wehrle, Andriy Panchenko
**Read on**: 2026-05-16 (in lesson 10.5)
**Status**: full PDF (publicly available)
**One-line**: Defense via traffic splitting across multiple Tor circuits — attacker observing one relay sees only fragmentary trace.

## Problem
All previous defenses operate on a single circuit. If attacker observes only one vantage, can splitting traffic across multiple circuits reduce attacker's effective trace fraction below useful threshold?

## Contribution
1. Client splits each connection's cells across K independent Tor circuits.
2. Three split strategies: round-robin, random, batched.
3. Attacker observing one circuit sees only 1/K fraction → accuracy collapses.

## Method
- K Tor circuits with different guard/middle/exit triples.
- Client outgoing cells dispatched to one circuit at a time per algorithm:
  - Round-robin: rotate every cell
  - Random: uniform random
  - Batched: send N cells then switch
- Reassembly at SOCKS-server peer endpoint (TrafficSliver-Server, hosted by user or trusted party).

## Results
| Attacker observation | DF acc |
|---|---|
| All circuits | 90%+ |
| 1 of K=3 circuits | random (1/N) |
| 2 of K=3 circuits | 60–70% |
| Multi-guard adversary (K=3, observes all) | back to baseline |

Bandwidth overhead: minimal (no padding). Latency: slight (multi-circuit jitter).

## Limitations
- Requires reassembly server — additional infrastructure.
- Multi-vantage adversary (ISP-level, controls multiple guards) defeats: GFW could observe all client circuits.
- Adds Tor circuit construction overhead.

## How it informs our protocol design
- **Splitting is orthogonal to shaping** — G6 should optionally split via Multipath QUIC (MASQUE).
- Single-vantage attacker (corporate, single ISP) is well-defended.
- For state-level multi-vantage adversary, splitting helps but is not sufficient — must combine with shaping.

## Open questions
- Optimal K vs latency/bandwidth/circuit-construction cost?
- Adaptive split when adversary detected on subset of circuits?
- Multi-path QUIC application of TrafficSliver concept?

## References worth following
- Panchenko 16 (CUMUL) — same group's older attack paper
- Multipath QUIC drafts (IETF) — modern transport substrate for splitting
- DeepCorr (Nasr 18 CCS) — multi-circuit correlation if adversary multi-vantage
