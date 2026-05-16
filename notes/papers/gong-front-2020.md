# Zero-delay Lightweight Defenses against Website Fingerprinting
**Venue / Year**: USENIX Security 2020
**Authors**: Jiajun Gong, Tao Wang
**Read on**: 2026-05-16 (in lesson 10.5)
**Status**: full PDF (publicly available)
**One-line**: FRONT (Front-loaded Random Token) defense — heavy random padding at trace start; GLUE — merging multiple page visits to obscure parsing.

## Problem
WTF-PAD broken by DF (Sirinam 18). Need zero-delay defense surviving against DL. Observation: WF features tend to weight early-trace patterns heavily — what if defenders attack precisely those features?

## Contribution
1. **FRONT**: at trace start, inject a Rayleigh-sampled number of random-direction dummy cells over the first T seconds. After that, no padding.
2. **GLUE**: at session level, "glue" multiple consecutive page visits with continuous traffic, hiding page boundaries (the parsing fallacy from Juarez 14).
3. Zero latency by design.

## Method
- FRONT params: $W$ (window seconds), $N$ (max dummies from Rayleigh sampling).
- Front padding cells sent at exponentially-distributed times within $W$.
- GLUE: when one page completes, immediately request another decoy page before disconnecting.

## Results
| Defense | DF acc | Tik-Tok acc | BW% | Latency |
|---|---|---|---|---|
| FRONT | 65% | 85% | 25% | 0 |
| GLUE | 70% | 80% | – | 0 |
| FRONT + WTF-PAD | 58% | 79% | 65% | 0 |

DF drops 33 pts at 25% overhead — best 2020 zero-delay defense.

## Limitations
- Tik-Tok exploits timing → FRONT less effective.
- Front-loaded padding visible as anomalous burst-at-start; could become its own fingerprint.
- GLUE requires application support (initiate decoy pages).

## How it informs our protocol design
- **Front-loaded padding is a cheap, effective primitive** — G6 should include it in opening burst.
- GLUE is conceptually important: G6 should consider session-level "no idle disconnect" with cover decoy fetches.
- Combining FRONT with shape envelope (RegulaTor) and decoy (Surakav) is unexplored — G6's hybrid opportunity.

## Open questions
- Front + back loading: does adding trace-end padding further help? (Unstudied.)
- GLUE-induced inter-page correlation: does combining 2 pages reveal more than concealing each?

## References worth following
- Sirinam 18 (DF) — adversary FRONT designed against
- Rahman 20 (Tik-Tok) — adversary FRONT fails to fully defeat
- Holland-Hopper 22 (RegulaTor) — alternative envelope approach
- Juarez 14 (Critical) — parsing fallacy GLUE addresses
