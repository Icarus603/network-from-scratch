# Multi-flow Attack-Resistant Website Fingerprinting Defenses
**Venue / Year**: PoPETs 2019 (issue 4)
**Authors**: Wang, Hopper
**Read on**: 2026-05-16 (in lessons 11.2, 11.3 of Part 11)
**Status**: abstract + key results from PoPETs proceedings (not yet fetched)
**One-line**: Establishes that multi-flow correlation classifiers raise ε significantly above single-flow estimates; even strong padding defenses fall to ε > 0.3 under multi-flow.

## Problem
Earlier WF defense evaluations (Cai 2014, Sirinam 2018) used single-flow per session. Real censors observe multiple flows from the same user across time. Does padding still work?

## Contribution
- Multi-flow attacker model: classifier sees N flows from same user, makes joint decision.
- Padding defenses calibrated against single-flow attacker: ε drops to 0.2.
- Same defenses against multi-flow attacker: ε rises to 0.3+.
- Proposes new multi-flow-aware padding.

## Method
- Train classifier with sequence-of-flow input.
- Compare ε vs single-flow baseline.

## Results
- BuFLO/Tamaraw single-flow ε ≈ 0.2; multi-flow ε ≈ 0.35.
- Cover-distribution shaping reduces multi-flow ε but at higher overhead.

## Limitations / what they don't solve
- Doesn't fully characterize the lower bound on multi-flow ε.
- Doesn't address per-flow vs per-cell padding allocation problem.

## How it informs our protocol design
- G6 CAR-1 target τ_short ≤ 0.20 assumes single-flow attacker; long-term ε_stretch ≤ 0.30 accommodates multi-flow.
- G6 spec §11.16 explicitly acknowledges long-term aggregation residual.

## Open questions
- Lower bound on multi-flow ε for any deterministic padding?
- Cover-conditioned shaping limits with multi-flow attacker?

## References worth following
- Cai CCS 2014 (Tamaraw)
- Sirinam CCS 2018 (DF)
- Tor pluggable transports list
