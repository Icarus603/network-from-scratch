# Toward an Efficient Website Fingerprinting Defense
**Venue / Year**: ESORICS 2016
**Authors**: Marc Juarez, Mohsen Imani, Mike Perry, Claudia Diaz, Matthew Wright
**Read on**: 2026-05-16 (in lesson 10.5)
**Status**: full PDF (publicly available)
**One-line**: Zero-delay adaptive padding (WTF-PAD) achieving useful defense against hand-crafted-feature attacks; Tor padding-spec 254's reference.

## Problem
Tor wanted zero-latency defense — no padding-induced delay to user data. Tamaraw and BuFLO violate this. WTF-PAD aimed to fill idle gaps with dummy cells without delaying real ones.

## Contribution
1. Adaptive Padding (AP) state machine with two states: burst (active sending) and gap (idle between bursts).
2. Per-state IAT histograms sampled from real Tor data; dummies injected to match the histogram distribution.
3. Zero latency by design — only dummies fill idle, real packets pass unmodified.

## Method
- Train empirical IAT histograms on undefended Tor traces.
- During defense: track time since last packet, sample target IAT from histogram, schedule dummy if real packet hasn't been sent by sampled time.
- Two separate histograms for "burst gap" vs "between-burst gap".

## Results
| Defense | k-NN | k-FP | overhead | latency |
|---|---|---|---|---|
| WTF-PAD | 60% (vs 91%) | 65% (vs 95%) | 50% bw | 0 |

DF (Sirinam 18) later reached 90.7% on WTF-PAD — showed it's broken against DL.

## Limitations
- Only marginal-IAT shaping; doesn't address direction sequence or burst-level structure (which DF exploits).
- Empirical histograms vulnerable to drift.
- Zero-delay constraint hard-caps achievable indistinguishability.

## How it informs our protocol design
- Demonstrates that **marginal-statistic shaping is insufficient against sequence-level DL adversaries**.
- The state-machine paradigm (used here) is the precursor to Maybenot (Pulls 23) — G6 should adopt Maybenot.
- Zero-latency is a useful design target but not sufficient on its own — G6 should combine zero-delay padding with occasional latency-tolerating modes.

## Open questions
- Could the IAT histograms be made adversarially robust via randomization / adaptive?
- Joint sequence-level shaping while preserving zero-latency: theoretical floor?

## References worth following
- Sirinam 18 (DF) — empirically broke WTF-PAD
- Pulls 23 (Maybenot) — modern framework subsumes WTF-PAD as a special case
- Holland-Hopper 22 (RegulaTor) — alternative zero/low-latency design
- Gong-Wang 20 (FRONT) — front-loaded variant
