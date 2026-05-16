# AppScanner: Automatic Fingerprinting of Smartphone Apps from Encrypted Network Traffic
**Venue / Year**: IEEE European Symposium on Security and Privacy (EuroS&P) 2016
**Authors**: Vincent F. Taylor, Riccardo Spolaor, Mauro Conti, Ivan Martinovic
**Read on**: 2026-05-16 (in lesson 10.8)
**Status**: full PDF
**One-line**: Per-app supervised fingerprinting from encrypted mobile traffic: random forest on size/IAT features achieves 70–90% on 110 apps.

## Problem
Mobile apps generate encrypted traffic; can the specific app be identified from its traffic pattern?

## Contribution
1. Per-flow feature extraction: packet sizes, IATs, flow durations.
2. Random forest classifier across 110 popular Android apps.
3. 70–90% accuracy.

## Method
- Capture TLS flows from each app while in use.
- Per-flow feature: histogram of sizes, IAT statistics, total bytes, etc.
- RF with ~50 features.

## Results
- 110 apps: 70%+ overall accuracy.
- Top-app: 90%+.

## Limitations
- Per-app supervised; FlowPrint (20) made it semi-supervised.
- Requires per-app training data.

## How it informs our protocol design
- Inner-app fingerprinting threat acknowledged; Proteus tunneling structurally helps but does not eliminate (if attacker has access at endpoint).
- Proteus should scope-out inner-app fingerprint protection (out of scope for transport).

## References worth following
- FlowPrint (NDSS 20) — semi-supervised successor
- FS-Net (INFOCOM 19) — deep-learning extension
