# RegulaTor: A Straightforward Website Fingerprinting Defense
**Venue / Year**: PoPETs 2022 issue 2
**Authors**: James K. Holland, Nicholas Hopper
**Read on**: 2026-05-16 (in lesson 10.5)
**Status**: full PDF (publicly available)
**One-line**: Cap outgoing rate to fixed envelope $R$, padding to envelope when under-rate; simple but very effective against DL adversaries.

## Problem
Tamaraw heavy; WTF-PAD weak vs DF. Need straightforward, configurable defense effective against DL with moderate cost.

## Contribution
1. RegulaTor: split trace into fixed-duration windows $w$, cap actual rate per window to threshold $R$; pad to $R$ if under.
2. Single tunable rate parameter — straightforward to deploy.
3. Strong empirical results against DF, Tik-Tok, k-FP.

## Method
- Window size $w$ (e.g., 0.5s), threshold $R$ (e.g., 60 cells/window).
- For each window: if real cells ≥ R, drop excess (queue); else pad to $R$ with dummies.
- Real-time deployable on Tor client.

## Results
| Attacker | acc undef. | acc + RegulaTor | BW% | Lat% |
|---|---|---|---|---|
| DF | 95% | 22% | 110% | 50% |
| Tik-Tok | 99% | 31% | – | – |
| k-FP | 95% | 19% | – | – |

Compared to Tamaraw (100% BW, 125% latency): RegulaTor slightly higher BW but lower latency.

## Limitations
- Single rate parameter → user activity unevenly affected (some sites pay more).
- Front of trace (first windows) shows distinctive envelope start — could be fingerprint.
- Real-time but not "zero delay" (queues real cells when over-rate).

## How it informs our protocol design
- **Window-rate envelope is the simplest strong WF defense** — G6 should include as a layer.
- Combine with FRONT (front-loaded random tokens) for opening-burst variation.
- Pareto-front position is excellent — G6 might match RegulaTor at lower BW% by adding Surakav-style decoys.

## Open questions
- Optimal window size $w$ given user activity distribution? Empirical only.
- Multi-rate envelope (different R per traffic class)?
- Adaptive R based on connection traffic class?

## References worth following
- Cai 14 CCS (Tamaraw) — older constant-rate baseline
- Gong-Wang 20 (FRONT) — complementary front-loading
- Pulls 23 (Maybenot) — framework for RegulaTor-like machines
- Gong 22 (Surakav) — modern hybrid
