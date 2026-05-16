# Peek-a-Boo, I Still See You: Why Efficient Traffic Analysis Countermeasures Fail
**Venue / Year**: IEEE S&P 2012
**Authors**: Kevin P. Dyer, Scott E. Coull, Thomas Ristenpart, Thomas Shrimpton
**Read on**: 2026-05-16 (in lessons 10.2, 10.5)
**Status**: full PDF (publicly available)
**One-line**: Systematically broke all then-existing low-overhead WF defenses with simple classifiers; introduced BuFLO as the only formally-effective (but expensive) defense.

## Problem
By 2012 several padding defenses claimed to defeat WF: pad-to-MTU, pad-to-uniform, padding-to-power-of-2, packet morphing (Wright 09). No systematic comparison existed.

## Contribution
1. Reproduced every then-published WF defense.
2. Showed Naïve Bayes / SVM attacks defeat all of them (accuracy still 80%+).
3. Introduced **BuFLO** (Buffered Fixed-Length Obfuscation) — constant-rate fixed-size channel — as the only defense with formal indistinguishability.
4. Made the claim: "low-overhead efficient WF defense may be fundamentally impossible".

## Method
- Implement: pad-to-MTU, pad-to-uniform-distribution, pad-to-power-of-2, traffic morphing (Wright 09), packet-pair morphing.
- Test against NB and SVM classifiers on Tor/HTTPS traces.
- Introduce and evaluate BuFLO: constant rate $\rho$, fixed size $s$, minimum duration $T$.

## Results
| Defense | NB acc | SVM acc | overhead |
|---|---|---|---|
| no defense | 95% | 96% | – |
| pad-to-MTU | 80% | 82% | 30% |
| traffic morphing | 70% | 80% | 25% |
| BuFLO | 12% | 15% | 200%+ |

## Limitations
- Predates DL — BuFLO's empirical strength under DL still strong (Sirinam 18 reports 60%+, much worse than NB era).
- The pessimistic claim ("efficient defense impossible") is partly refuted by later work (Walkie-Talkie, RegulaTor) which find acceptable trade-offs.
- BuFLO's latency overhead makes it unusable for interactive web.

## How it informs our protocol design
- **Proteus should publish a "Peek-a-Boo style" sanity test**: run NB / SVM on Proteus traces and verify the simple attacks fail. If they don't, the defense isn't even at 2012 bar.
- Demonstrates the importance of **defense-in-depth across feature channels** — no single-channel padding suffices.
- BuFLO's 200% overhead provides the upper bound; Proteus should be much cheaper.

## Open questions
- Was the pessimism justified? Modern Surakav (Gong 22) achieves Tamaraw-level defense at ~70% overhead. Not "low" but much better.
- Is there a deeper theoretical lower bound on overhead vs accuracy?

## References worth following
- Wright 09 NDSS — defense Dyer 12 broke
- Cai 14 CCS — Tamaraw, improved BuFLO
- Sirinam 18 CCS — DL re-shock to defenses
- Cherubin 17 — Bayes lower bound on attacker accuracy
