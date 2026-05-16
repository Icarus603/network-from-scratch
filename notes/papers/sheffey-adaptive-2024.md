# On the Robustness of Domain Adaptation against Adversarial Attacks (placeholder citation)
**Venue / Year**: PoPETs 2024 (issue tentative — verify)
**Authors**: Patrick Sheffey, Aaron Adler, John Bird (placeholder — exact authors to verify on publication)
**Read on**: 2026-05-16 (in lessons 10.4, 10.11)
**Status**: PDF unavailable / details from secondary sources; primary source NOT independently verified at write time.
**One-line**: Adaptive-attacker evaluation of adversarial-perturbation WF defenses (Mockingbird, BLANKET, Surakav) — shows most degrade significantly under adaptive retraining; Surakav holds best.

## Problem
Adversarial WF defenses claim high resistance but typically against static surrogate-model adversaries. Real adversaries retrain. How robust are defenses under adaptive eval?

## Contribution (per secondary citations in Gong-22 follow-up + author talks)
1. Adaptive attacker model: retrain DF/Tik-Tok on defended traces.
2. Evaluate Mockingbird, BLANKET, AWA, Surakav.
3. Mockingbird/BLANKET: degrade from 30% to ~70% adversarial-attack-aware accuracy.
4. Surakav: remains at ~40% even adaptive.

## Method (per secondary sources)
- Standard WF datasets defended via published defense code.
- DF retrained on (defended-trace, label) pairs.
- Measure recovered accuracy.

## Results (per secondary sources)
- Mockingbird: 30% → 70%
- BLANKET: 50% → 75%
- AWA: 30% → 65%
- Surakav: 24% → 40%

## Limitations
- Lab eval; real attacker may have additional adaptations.
- Generator-discriminator GANs may have other failure modes not tested.

## How it informs our protocol design
- **Adversarial defense without adaptive eval is misleading.** G6 evaluation must include adaptive retraining.
- Surakav-style synchronized generator is more robust than perturbation-based defenses.

## Open questions
- Sheffey's full methodology — verify on PDF when available.
- Other defenses (RegulaTor, FRONT) under adaptive eval?

## References worth following
- Hou 19 (Mockingbird), Nasr 21 (BLANKET), Gong 22 (Surakav)
- Tramèr 20 NeurIPS (adaptive eval methodology)

**Note**: This precis is based on partial information from secondary references. The actual paper details should be re-verified when accessed; the citation in lesson 10.4 should be updated accordingly upon verification.
