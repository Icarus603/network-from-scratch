# Karaoke: Distributed Private Messaging Immune to Passive Traffic Analysis
**Venue / Year**: USENIX OSDI 2017
**Authors**: David Lazar, Yossi Gilad, Nickolai Zeldovich
**Read on**: 2026-05-16 (in lesson 10.9)
**Status**: full PDF
**One-line**: Vuvuzela successor scaling to millions of users with similar DP-style anonymity, lower latency, and tolerance for N-1 server compromise.

## Problem
Vuvuzela bottlenecks on single-server shuffle; latency grows with user count. Karaoke aims for scalable DP-anonymity.

## Contribution
1. Distributed mix chain (multiple shuffle servers).
2. Anytrust model: as long as one server honest, anonymity holds.
3. Reduced per-round latency: ~10s at 1M users.

## Method
- Round-based protocol like Vuvuzela.
- Mix chain: each server shuffles + adds DP noise.
- Verifiable shuffle proofs ensure no server cheats.

## Results
- 1M users at ~10s per round.
- $(\varepsilon, \delta)$-DP linkability protection.

## Limitations
- Per-round delay still incompatible with web.
- DP noise overhead in cover messages.

## How it informs our protocol design
- DP anonymity baseline for messaging-mode Proteus if pursued.
- Anytrust model concept: Proteus multi-bridge could use similar threshold trust.

## References worth following
- Vuvuzela (SOSP 15) — predecessor
- Atom (OSDI 18) — successor
