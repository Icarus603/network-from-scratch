# Website Fingerprinting: Attacking Popular Privacy Enhancing Technologies with the Multinomial Naïve-Bayes Classifier
**Venue / Year**: CCSW 2009 (CCS Workshop on Cloud Computing Security)
**Authors**: Dominik Herrmann, Rolf Wendolsky, Hannes Federrath
**Read on**: 2026-05-16 (in lesson 10.2)
**Status**: full PDF
**One-line**: Applied Liberatore-Levine to Tor, found accuracy collapses to ~3% — temporarily concluded Tor's cell padding defeats WF.

## Problem
Tor uses fixed-size cells (512 bytes); does WF still work?

## Contribution
1. Application of Liberatore-Levine multinomial NB to Tor traces.
2. Accuracy drops from 75% (HTTPS) to ~3% (Tor).
3. Interpretation: cell padding defeats packet-size attacks.

## Method
- Same feature extraction as Liberatore-Levine.
- Tor traces over 200+ sites.

## Results
- ~3% accuracy.
- Concluded Tor's WF resistance is strong.

## Limitations
- Wrong conclusion in hindsight: Panchenko 11 showed direction-sequence / burst features still work; 2014 Wang reaches 91%.
- Only marginal-size features tested.

## How it informs our protocol design
- Historical lesson: "Tor's cell padding solves WF" was a costly wrong conclusion.
- Proteus must shape sequence, not just sizes.

## References worth following
- Panchenko 11 WPES — disproves Herrmann
- Wang 14 USENIX Sec — definitive Tor WF
