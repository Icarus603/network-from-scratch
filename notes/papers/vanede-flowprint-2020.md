# FlowPrint: Semi-Supervised Mobile-App Fingerprinting on Encrypted Network Traffic
**Venue / Year**: NDSS 2020
**Authors**: Thijs van Ede, Riccardo Bortolameotti, Andrea Continella, Jingjing Ren, Daniel J. Dubois, Martina Lindorfer, David Choffnes, Maarten van Steen, Andreas Peter
**Read on**: 2026-05-16 (in lesson 10.8)
**Status**: full PDF
**One-line**: Semi-supervised mobile-app fingerprinting from encrypted traffic — clusters destination IP / port / TLS fingerprint patterns to identify apps without per-app labels.

## Problem
AppScanner (Taylor 16) required per-app training data; unfeasible for thousands of apps. FlowPrint uses semi-supervised clustering to discover apps without exhaustive labels.

## Contribution
1. **Destination feature**: each flow characterized by (IP, port, TLS SNI/cert) cluster ID.
2. Time-series clustering of destinations during a session.
3. Cross-reference clusters to known apps via partial labels.

## Method
- Per flow: extract destination cluster (TLS-fingerprint based).
- Per session: temporal pattern of destinations → "fingerprint".
- Semi-supervised: label some sessions, generalize via clustering.

## Results
- 200+ apps fingerprinted with 88%+ accuracy.
- Few labeled samples per app required.
- Even with VPN tunnelling, destination cluster preserved (since CDN endpoints multiplex).

## Limitations
- Tunnelling all destinations through single CDN (G6-style) breaks FlowPrint's destination clustering.
- Per-app destination patterns may evolve over time.

## How it informs our protocol design
- **G6 + DoH-over-tunnel + single-endpoint tunneling fundamentally breaks FlowPrint** — all flows appear to go to G6 bridge.
- Confirms that G6's "everything-through-single-tunnel" model has anti-FlowPrint side benefit.
- FlowPrint motivates G6 to NOT split-tunnel certain apps directly without G6 protection.

## Open questions
- Multi-bridge G6 deployment — does that re-introduce FlowPrint vulnerability?
- Inner-tunnel app discovery from inside G6 protocol (G6 client logs)?

## References worth following
- AppScanner (Taylor 16 EuroS&P) — per-app supervised predecessor
- FS-Net (Liu 19 INFOCOM) — RNN-based extension
- Bahramali 20 NDSS — messaging app fingerprinting
