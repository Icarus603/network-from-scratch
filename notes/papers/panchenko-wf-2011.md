# Website Fingerprinting in Onion Routing Based Anonymization Networks
**Venue / Year**: WPES 2011
**Authors**: Andriy Panchenko, Lukas Niessen, Andreas Zinnen, Thomas Engel
**Read on**: 2026-05-16 (in lesson 10.2)
**Status**: full PDF
**One-line**: Restored Tor WF accuracy to ~55% via hand-crafted features capturing direction sequence + burst patterns; disproved Herrmann's pessimism.

## Problem
Herrmann 09 reported Tor WF only ~3%. Was this Tor's defense or Liberatore-Levine's feature inadequacy?

## Contribution
1. New feature set capturing structure beyond packet sizes: direction sequence, packet ordering, size markers, HTML markers, in/out packet counts in windows.
2. SVM with RBF kernel.
3. Tor closed-world ~55% — far above Herrmann's 3%.

## Method
- ~30 hand-crafted features per trace.
- SVM-RBF.

## Results
- ~55% on 800 Tor sites closed-world.
- Refuted "Tor defeats WF" claim.

## Limitations
- Still hand-crafted; subsequent k-NN / CUMUL / DF improved further.

## How it informs our protocol design
- Direction sequence and burst structure are first-class leakage channels.
- Tor's cell padding is not sufficient defense.

## References worth following
- Cai 12 (Touching from a Distance)
- Wang 14 USENIX Sec
- Panchenko 16 (CUMUL)
