# Mockingbird: Defending Against Deep-Learning-Based Website Fingerprinting Attacks with Adversarial Traces
**Venue / Year**: IEEE TIFS 2019 (arXiv 1902.06626)
**Authors**: Mohammad Saidur Rahman, Mohsen Imani, Nate Mathews, Matthew Wright (NOTE: paper is sometimes cited as "Hou 19" or "Imani 19"; primary author varies by version)
**Read on**: 2026-05-16 (in lessons 10.4, 10.5)
**Status**: full PDF (arXiv)
**One-line**: First adversarial-example based WF defense — perturb source trace to look like target site in DF's embedding space.

## Problem
DF (Sirinam 18) defeated all then-existing low-overhead defenses. Need a defense leveraging DL adversary's own properties — adversarial-example perturbations.

## Contribution
1. Algorithm: iteratively perturb source trace (insert dummies, delay timing) to minimize embedding distance to a chosen target trace in surrogate DF model.
2. Demonstrate transfer: perturbation crafted on DF surrogate works on other DF variants.
3. Bandwidth overhead 50–60%, attacker accuracy drops to ~30%.

## Method
- Surrogate model: pre-trained DF on (W-T attacker dataset).
- For each source trace, select target trace from different site.
- Greedy iterative: at each step, enumerate candidate perturbations (insert dummy at random index, delay timing by step), pick one minimizing distance to target embedding.
- Stop when distance below threshold or budget exhausted.

## Results
| Defense | DF acc | k-FP acc | overhead |
|---|---|---|---|
| Mockingbird | 30% | 15% | 50–60% |

## Limitations
- Per-trace iterative optimization too slow for real-time client deployment.
- Transfer attack from white-box DF surrogate — adaptive attacker training on Mockingbird-perturbed traces recovers ~70% accuracy (Sheffey 24).
- Bandwidth still substantial.

## How it informs our protocol design
- **Adversarial perturbation is a useful auxiliary technique but not a primary defense.** Adaptive attackers recover from transfer-perturbations.
- Suggests value of randomizing perturbation parameters frequently (key rotation analogue).
- Important baseline: Proteus must beat Mockingbird in BOTH offline and adaptive-attacker settings.

## Open questions
- Universal (not per-trace) adversarial perturbation (Nasr 21 BLANKET pursued).
- GAN-based realistic perturbations (Surakav 22 successor).
- Adversarial training of defender's generator against attacker's classifier.

## References worth following
- Goodfellow 15 ICLR — adversarial example basics
- Madry 18 ICLR — PGD adversarial training (defender side analog)
- Nasr 21 USENIX Sec (BLANKET) — universal perturbation successor
- Gong 22 IEEE S&P (Surakav) — GAN-based descendant
- Sheffey 24 PoPETs — adaptive-attacker evaluation
