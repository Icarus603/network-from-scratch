# Marionette: A Programmable Network Traffic Obfuscation System
**Venue / Year**: USENIX Security 2015
**Authors**: Kevin P. Dyer, Scott E. Coull, Thomas Shrimpton
**Read on**: 2026-05-16 (in lesson 10.6)
**Status**: full PDF
**One-line**: Programmable state-machine obfuscation: define protocol templates (HTTP session, SSH, FTP) and generate wire traffic conforming to them.

## Problem
FTE (Dyer 13) covers single regex but not full protocol sessions. Real protocols have multi-state behavior (handshake, request-response, control plane). Need a framework to express full-session mimicry.

## Contribution
1. Marionette language: declarative spec of state machine + FTE-encoded actions per state.
2. Reference implementation supporting HTTP/SMB/SSH templates.
3. Demonstrate evasion against DPI implementing those protocols' parsers.

## Method
- Template: list of states with transitions.
- Each state: defines what data to send/recv, what regex (FTE template) the wire should match.
- Client and bridge maintain synced state.

## Results
- Successfully mimics HTTP/SMB/SSH against contemporary DPI.
- Wire-level fingerprint passes for those protocols.

## Limitations
- Implementation complexity high; never widely deployed in Tor.
- Adaptive DPI checking timing / control behavior catches incomplete mimicry.
- "Parrot is dead" applies — real-world protocol bugs and edge cases hard to replicate.

## How it informs our protocol design
- **State-machine paradigm for obfuscation is sound** — Maybenot (Pulls 23) is the modern, narrower-scope successor.
- Marionette tried to be too ambitious (full protocol mimicry); G6 keeps shaping at lower level (size/timing) and relies on real-protocol tunneling for higher-level conformance.
- Programmable defenses are reusable infrastructure — G6 should build defenses as Maybenot machines, not hard-coded logic.

## Open questions
- Marionette + REALITY-style real-server fallback hybrid?
- Auto-generation of Marionette templates from real protocol traces?

## References worth following
- Dyer 13 (FTE) — predecessor
- Pulls 23 (Maybenot) — modern programmable shaping
- Houmansadr 13 (Parrot is Dead) — critique
