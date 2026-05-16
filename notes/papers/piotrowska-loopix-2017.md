# The Loopix Anonymity System
**Venue / Year**: USENIX Security 2017
**Authors**: Ania M. Piotrowska, Jamie Hayes, Tariq Elahi, Sebastian Meiser, George Danezis
**Read on**: 2026-05-16 (in lesson 10.9)
**Status**: full PDF
**One-line**: Continuous-time mixnet with Poisson-distributed cover loops (client-to-self packets), giving formal anonymity bound at moderate latency; deployed as Nym.

## Problem
Mixminion-style high-latency mixnets had hour-level delay. Tor low-latency had no formal anonymity vs GPA. Could a system reach formal anonymity with seconds-level latency?

## Contribution
1. **Cover loops**: each user sends a Poisson stream of self-addressed packets in addition to real messages.
2. Mixes apply exponential delay per packet.
3. Both real and loop packets indistinguishable on wire.
4. Formal anonymity entropy bound: $\log_2(N \lambda_L \mu / \lambda_P)$ where $N$ = active users, $\lambda_L$ = loop rate, $\mu$ = mix delay, $\lambda_P$ = payload rate.

## Method
- Sphinx packet format (fixed size).
- Each user generates Poisson stream: $\lambda_L$ loops + $\lambda_P$ payloads.
- Each mix in chain applies exponential delay per packet.
- Loops travel client → mix1 → mix2 → mix3 → client (self-addressed).

## Results
- 1-second median latency with 3-hop chain.
- Anonymity entropy ≥ 20 bits with $N = 100k$ users.
- Deployed as Nym (nymtech.net).

## Limitations
- Cover loop overhead ~ $\lambda_L / \lambda_P$; nontrivial bandwidth cost.
- Per-packet exponential delay incompatible with TCP-like streams.
- Web browsing impossible (latency too high for interactive web).

## How it informs our protocol design
- **Loopix is the formal-anonymity gold standard** for messaging; Proteus cannot match its bound without comparable cover-traffic overhead.
- Proteus "high-assurance mode" could approximate Loopix on a per-session basis: constant-rate cover loops with random mix delay.
- For web, Proteus should explicitly accept lower formal anonymity in exchange for usability.

## Open questions
- Loopix-style cover-loop overhead vs achieved anonymity at lower N (smaller user base)?
- Low-latency Loopix variant (sub-100ms latency, weaker but still formal anonymity)?
- Loopix + WF defense combined model?

## References worth following
- Chaum 81 CACM — mixnet origin
- Mixminion (S&P 03)
- Sphinx (S&P 09) — packet format
- Karaoke (OSDI 17) — DP-style anonymity
