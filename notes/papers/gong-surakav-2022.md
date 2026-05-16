# Surakav: Generating Realistic Traces for a Strong Website Fingerprinting Defense
**Venue / Year**: IEEE S&P 2022
**Authors**: Jiajun Gong, Wuqi Zhang, Charles Zhang, Tao Wang
**Read on**: 2026-05-16 (in lessons 10.4, 10.5)
**Status**: full PDF
**One-line**: GAN-based defense — train a generator to produce decoy traces that, when overlaid with real traces, are statistically indistinguishable from real traffic at the wire level.

## Problem
Adversarial-perturbation defenses (Mockingbird, BLANKET) fail to adaptive attackers because they rely on transfer attacks against fixed surrogate models. Need a fundamentally different defense paradigm.

## Contribution
1. Train a GAN: generator $G$ outputs synthetic decoy traces; discriminator $D$ distinguishes synthetic from real. After training, $G$ produces traces statistically indistinguishable from real.
2. Client and server share a synchronized $G$ via seed exchange in handshake.
3. Each real visit: $G$ generates a decoy of a paired site; both client and server send mixed real/decoy cells, attacker sees "real for site A or B".
4. Strong empirical defense even against adaptive attackers.

## Method
- LSTM-based sequence generator $G$.
- Discriminator $D$: 1D CNN over trace sequences.
- Training: min-max game on real-Tor trace dataset.
- Deployment: client/server agree on seed; $G(seed)$ deterministically produces decoy trace.
- Per-visit: defender selects target candidate trace, mixes generator output with real trace.

## Results
| Adversary | acc undef. | acc + Surakav | overhead |
|---|---|---|---|
| DF | 95% | 24% | 70% BW, 50% latency |
| Tik-Tok | 99% | 36% | – |
| k-FP | 95% | 19% | – |
| Adaptive DF (retrained on Surakav) | – | 40% | – |

## Limitations
- Bandwidth overhead 70% is heavy for general web use.
- Requires synchronized seed exchange — protocol-level support needed.
- LSTM generator can produce subtle artifacts (compute-aware adversary may exploit; Sheffey 24).
- Per-class generator may be needed for different traffic types.

## How it informs our protocol design
- **Surakav-style synchronized generator is the modern SOTA shape defense.** Proteus should adopt the concept with key-derived synchronization.
- 70% overhead is the price of GAN-based defense — Proteus should aim to reduce via combination with cheaper layers (FRONT, RegulaTor envelope).
- Demonstrates value of "indistinguishable from realistic trace" target rather than "minimize attacker accuracy".

## Open questions
- Per-class generators / multi-modal generators?
- Theoretical bound on generator-discriminator equilibrium?
- Bandwidth optimization while preserving Surakav-grade resistance?
- Cross-protocol (non-Tor) generator transfer?

## References worth following
- Sirinam 18 (DF) — adversary Surakav defeats
- Rahman 20 (Tik-Tok) — adversary Surakav addresses
- Goodfellow 14 NIPS — GAN foundation
- Sheffey 24 — adaptive evaluation
- Pulls 23 (Maybenot) — alternative framework
