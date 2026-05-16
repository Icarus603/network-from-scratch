# Defeating DNN-Based Traffic Analysis Systems in Real-Time With Blind Adversarial Perturbations
**Venue / Year**: USENIX Security 2021
**Authors**: Milad Nasr, Alireza Bahramali, Amir Houmansadr
**Read on**: 2026-05-16 (in lesson 10.4)
**Status**: full PDF
**One-line**: Universal blind adversarial perturbation defense — one trained perturbation pattern $\delta^*$ applied to all traces; real-time per-trace cost O(1).

## Problem
Mockingbird requires per-trace iterative optimization (~10s). Not deployable real-time on Tor client. Can a single pre-trained perturbation be effective across diverse traces?

## Contribution
1. Train a universal perturbation $\delta^*$ via PGD-style optimization over a dataset.
2. Apply $\delta^*$ identically to every defended trace — no per-trace optimization.
3. Demonstrate against DF, Var-CNN, Tik-Tok, flow correlation (DeepCorr).

## Method
- Initialize $\delta = 0$ of trace length.
- Iterate over training batches: $\delta \leftarrow \delta - \eta \nabla_\delta L_{\text{attack}}(f(x + \delta), y_{\text{wrong}}) + \alpha \|\delta\|$.
- Project to legal perturbation set (insert dummies only, delay only forward).
- $\delta^*$ deployed at client: simply added to every trace.

## Results
| Adversary | acc undef. | acc + BLANKET | overhead |
|---|---|---|---|
| DF | 95% | 50% | 25% |
| Tik-Tok | 99% | 60% | – |
| DeepCorr | 90% | 30% | – |

## Limitations
- Universal $\delta^*$ visible to adversary after deployment → adversary can retrain classifier on $(x + \delta^*)$.
- Adaptive attacker recovers ~70% accuracy (similar to Mockingbird).
- Bandwidth 25% but timing perturbations not always feasible (delays user traffic).

## How it informs our protocol design
- **Universal perturbation is the right shape for real-time defense** but requires rotation.
- G6 could rotate $\delta^*$ periodically (key-derived from session key) — moves attack surface to key compromise.
- Combine universal perturbation with shaping envelope for defense-in-depth.

## Open questions
- Rotation strategy that balances key-derivation cost and adversary's ability to converge on a specific $\delta^*$ window.
- Per-class universal perturbation (different $\delta^*$ for different traffic types)?
- Robust universal perturbation that adapts to adaptive attacker?

## References worth following
- Moosavi-Dezfooli 17 CVPR — universal adversarial perturbations (vision)
- Hou/Imani 19 (Mockingbird) — per-trace adversarial predecessor
- Bahramali 21 IEEE TIFS (RATA) — robust attacker counterattack
- Gong 22 IEEE S&P (Surakav) — GAN successor
