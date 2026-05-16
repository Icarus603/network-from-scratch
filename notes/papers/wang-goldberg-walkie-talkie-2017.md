# Walkie-Talkie: An Efficient Defense Against Passive Website Fingerprinting Attacks
**Venue / Year**: USENIX Security 2017
**Authors**: Tao Wang, Ian Goldberg
**Read on**: 2026-05-16 (in lessons 10.2, 10.3, 10.5)
**Status**: full PDF (publicly available)
**One-line**: Half-duplex Tor mode + supersequence padding to make a chosen site pair produce identical traces.

## Problem
Padding/morphing-based defenses (BuFLO, Tamaraw) have heavy overhead (100%+). Lighter defenses (WTF-PAD) fail against feature-rich classifiers. Goal: lightweight defense that gives provable indistinguishability for at least one site pair.

## Contribution
1. Half-duplex browser mode: each TCP burst is one-directional only (browser explicitly batches requests).
2. Supersequence construction: for site pair (A, B), compute the unique supersequence of bursts that contains both; pad each visit's burst to the supersequence.
3. With perfectly matched supersequence, attacker cannot distinguish A from B → 50% accuracy upper bound.

## Method
- Modify browser to send requests in half-duplex batches.
- Each batch becomes one Tor burst.
- Compute longest-common-burst-sequence for pair (A, B); pad both to the union supersequence.
- Send dummies in burst positions where A has burst but B doesn't (and vice versa).

## Results
| Defense | k-NN acc | k-FP acc | bandwidth overhead |
|---|---|---|---|
| Walkie-Talkie | 50% (random for pair) | 20% | 31% |
| Tamaraw | 11% | 12% | 100% |
| WTF-PAD | 60% | 65% | 50% |

DF (Sirinam 18) later achieved 49.7% on Walkie-Talkie — close to the 50% theoretical floor for 2-site indistinguishability.

## Limitations
- Only covers direction sequence. Timing not shaped → Tik-Tok (Rahman 20) reaches 81% by exploiting timing.
- Requires browser modification (half-duplex mode) — deployment friction.
- Site pair must be chosen carefully — random pairs don't share supersequence well, leading to large dummy overhead.
- Multi-tab user invalidates supersequence.

## How it informs our protocol design
- **Supersequence idea is sound but must extend to all leakage channels**, not just direction. Proteus supersequence-like pairing must include timing + size envelopes.
- 50% indistinguishability floor is achievable; Proteus should aim for similar 1/N floors with cover loops + decoy generation (Surakav).
- Half-duplex burst structure is exploitable at the protocol level — Proteus can mandate per-burst direction commitment without browser modification (by buffering at Proteus client).

## Open questions
- Can multi-site supersequence (3+ candidates) be made efficient? — open problem; bandwidth overhead becomes superlinear.
- Application-level support: half-duplex requires browser changes — can Proteus enforce it at QUIC layer transparently?
- Adversarial site-pair selection: if attacker chooses test pairs that maximize distinguishability across un-shaped channels, can defender adapt?

## References worth following
- Wang 14 USENIX Sec (Effective Attacks) — same authors' attack-side companion
- Sirinam 18 CCS (DF) — first DL break against W-T
- Rahman 20 PoPETs (Tik-Tok) — timing-channel exploitation
- Gong 22 IEEE S&P (Surakav) — extends supersequence-pair idea via GAN
