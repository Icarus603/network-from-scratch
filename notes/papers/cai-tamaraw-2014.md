# A Systematic Approach to Developing and Evaluating Website Fingerprinting Defenses
**Venue / Year**: ACM CCS 2014
**Authors**: Xiang Cai, Rishab Nithyanand, Tao Wang, Rob Johnson, Ian Goldberg
**Read on**: 2026-05-16 (in lesson 11.3 of Part 11)
**Status**: abstract + key findings from CCS 2014 proceedings
**One-line**: Introduces Tamaraw — a website-fingerprinting defense with fixed packet schedule + early termination — and a systematic methodology for evaluating WF defenses; sets the bandwidth-overhead vs detection-accuracy frontier for years to come.

## Problem
Earlier WF defenses (BuFLO) had high bandwidth overhead (~140%). Cai et al. propose Tamaraw with same security at ~90% overhead, and propose evaluation methodology.

## Contribution
- Tamaraw defense:
  - Fixed-rate packet schedule (BuFLO-style).
  - Early termination when session "naturally" ends (saves bandwidth vs BuFLO).
  - Packet count quantization.
- Evaluation methodology:
  - Closed-world + open-world.
  - Bandwidth overhead curve vs detection accuracy.
- Frontier: at 90% overhead, attacker accuracy ~30%.

## Method
- Probabilistic analysis of attacker classifiers.
- Empirical evaluation on Tor traffic.

## Results
- Tamaraw at 90% overhead: ~30% closed-world classifier accuracy.
- BuFLO at 140%: ~20%.
- Trade-off curve standardized.

## Limitations / what they don't solve
- Doesn't anticipate DL classifiers (Sirinam 2018 later shows Tamaraw less effective vs DL).
- Single-flow assumption.

## How it informs our protocol design
- G6 padding strategy (1280B cell + cover IAT + idle off, ≤30% budget) is a much-less-aggressive scheme than Tamaraw — trade-off chosen for PERF.
- G6 explicitly accepts ε > Tamaraw's ε in exchange for goodput parity (PERF-1).
- Methodology adopted for G6 Part 12.10 evaluation (closed-world + open-world, overhead-vs-accuracy curve).

## References worth following
- Sirinam CCS 2018 (DF — challenge to Tamaraw)
- Wang-Hopper PoPETs 2019 (multi-flow extension)
- BuFLO papers (Tamaraw's predecessor)
- Rahman et al. 2019 (Mockingbird — adversarial defense)
