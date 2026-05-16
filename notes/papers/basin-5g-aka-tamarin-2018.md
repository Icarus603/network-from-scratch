# A Formal Analysis of 5G Authentication
**Venue / Year**: ACM CCS 2018
**Authors**: David Basin, Jannik Dreier, Lucca Hirschi, Saša Radomirović, Ralf Sasse, Vincent Stettler
**Read on**: 2026-05-16 (in lesson 11.11 of Part 11)
**Status**: abstract + key results from CCS 2018 proceedings; PDF widely available
**One-line**: Large-scale Tamarin verification of 5G AKA protocol, identifying authentication weaknesses and demonstrating Tamarin's capability for industrial-scale stateful crypto verification.

## Problem
3GPP's 5G AKA (Authentication and Key Agreement) protocol is core to mobile security. Earlier 4G AKA had known weaknesses. Did 5G fix them?

## Contribution
- Comprehensive Tamarin model of 5G AKA.
- Found authentication property weakness: certain configurations allow impersonation under specific compromise scenarios.
- Demonstrates Tamarin's strength on stateful protocols with explicit time/sequence dependencies.
- Worked with 3GPP to inform standard revisions.

## Method
- Hand-translated 5G AKA spec into Tamarin theory.
- Used Tamarin's interactive prover plus auto.
- Helper lemmas for stateful counters.

## Results
- Several authentication properties verified.
- One known weakness re-confirmed (privacy of subscription permanent identifier).
- Helped shape 5G AKA Privacy enhancements.

## Limitations / what they don't solve
- Doesn't address physical-layer attacks.
- Doesn't address implementation bugs.

## How it informs our protocol design
- G6Ratchet.spthy uses similar stateful pattern (KEYUPDATE epoch tracking via persistent facts).
- Confirms Tamarin handles stateful crypto + ratchet well (lesson 11.11 §1 comparison vs ProVerif).
- Engineering style of helper lemmas adopted.

## Open questions
- Scale-up: can Tamarin handle 5G + 6G + IoT multi-protocol composition? Partial.
- Auto-generation of Tamarin theory from spec? Active research.

## References worth following
- Meier CAV 2013 (Tamarin foundation)
- Cremers CCS 2017 (TLS 1.3 Tamarin — sister project)
- 3GPP TS 33.501 (5G security spec)
