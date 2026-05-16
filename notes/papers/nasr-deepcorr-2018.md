# DeepCorr: Strong Flow Correlation Attacks on Tor Using Deep Learning
**Venue / Year**: ACM CCS 2018
**Authors**: Milad Nasr, Alireza Bahramali, Amir Houmansadr
**Read on**: 2026-05-16 (in lessons 10.7, 10.11)
**Status**: full PDF
**One-line**: Deep-learning flow correlation against Tor; 90%+ accuracy linking entry-flow to exit-flow even with strong encryption.

## Problem
Tor designed against unobservable-relay traffic correlation. But if attacker observes both entry and exit, can they link? Earlier attacks (Murdoch 05) hand-crafted features achieved ~70%. Could DL push beyond?

## Contribution
1. CNN over (entry-flow, exit-flow) packet timing/size features → "same circuit" yes/no classifier.
2. Train on synthetic correlated pairs from real Tor traces.
3. 90%+ accuracy on previously unseen flows.

## Method
- Pairs of flows from same circuit (positive) and different circuits (negative).
- Features: per-packet size + IAT.
- CNN: 1D Conv processing two flow inputs in parallel, then merge for binary classification.

## Results
- 90% correlation accuracy with TPR 0.95 / FPR 0.005.
- Outperforms hand-crafted feature linking by 20%.

## Limitations
- Adversary must control both entry and exit (or observe).
- Defense via timing jitter shown to degrade but not eliminate.
- Closed-world circuit-pair assumption; real-world circuit churn not addressed.

## How it informs our protocol design
- **Flow correlation is real and DL-strong** — G6 timing module must include ±jitter to disrupt DeepCorr.
- Multipath (TrafficSliver / MASQUE multipath) spreads correlation surface.
- Defense effective if jitter ≥ 25ms — but at latency cost.

## Open questions
- Bound on minimal jitter for X% correlation reduction?
- Stream-level correlation (vs flow-level)?
- Cross-protocol correlation (Tor entry, VLESS exit)?

## References worth following
- Murdoch 05 IEEE S&P — predecessor correlation
- Mittal et al. 11 — flow correlation in Tor
- Iacovazzi 17 IEEE CST — watermarking survey
- TrafficSliver (Cadena 20) — splitting defense
