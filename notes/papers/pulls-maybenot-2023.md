# Maybenot: A Framework for Traffic Analysis Defenses
**Venue / Year**: PoPETs 2023 (issue tentative — verify on publication)
**Authors**: Tobias Pulls, Ethan Witwer
**Read on**: 2026-05-16 (in lessons 10.5, 10.6, 10.11, 10.12)
**Status**: full PDF (publicly available; supplementary code at maybenot-io/maybenot)
**One-line**: State-machine framework for specifying programmable traffic-analysis defenses; the Tor padding-v2 successor framework.

## Problem
Each WF defense (WTF-PAD, FRONT, RegulaTor, Tamaraw) has its own ad hoc implementation. Tor needs a unified, configurable mechanism for padding negotiation. Existing padding-spec (proposal 254) is limited to WTF-PAD-style.

## Contribution
1. Defines defense as a state machine: states, transitions, events (packet sent/received, timer fired), actions (send dummy, delay, modify size).
2. Reference Rust implementation: maybenot-io/maybenot.
3. Cargo crate for embedding in Tor / other relay software.
4. Companion: a simulator allowing offline evaluation of defenses against attacks before deployment.

## Method
- State: arbitrary integer ID.
- Transition: (event, conditions) → next-state + action list.
- Actions: send N dummies, delay packet by X μs, drop packet, set timer.
- Spec serialized to TOML / Rust-derived format.

## Results
- Reference machines: WTF-PAD, RegulaTor, FRONT all expressible.
- Performance: per-event dispatch < 1μs in Rust impl.
- Tor integration: WIP in arti (Rust Tor).

## Limitations
- State-machine is Turing-incomplete by design — some adversarial defenses (Mockingbird per-trace optimization) don't fit cleanly.
- Doesn't itself provide formal security proofs — Stuart 24 (forthcoming) provides Bayes-bound analysis tool.
- Padding-spec adoption requires Tor-network-wide negotiation.

## How it informs our protocol design
- **G6 traffic-shaping layer should be specified as a Maybenot machine.** Reuse the spec language and tooling.
- Provides natural artifact for security analysis (Cherubin 17 Bayes bound automation).
- Promotes interoperability — if multiple proxy protocols adopt Maybenot, defense innovations transfer.

## Open questions
- Turing-completeness extensions for adversarial GAN-style defenses?
- Spec auto-derivation from real-app traces?
- Formal verification of Maybenot specs against threat model (Part 11 forward reference).

## References worth following
- Pulls 20 PoPETs — Maybenot's precursor research
- Stuart 24 (forthcoming PoPETs) — Maybenot Bayes-bound analyzer
- Tor padding-spec proposal 254 — predecessor
- arti (Rust Tor) — adoption integration target
