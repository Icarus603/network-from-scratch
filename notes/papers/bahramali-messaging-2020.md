# Practical Traffic Analysis Attacks on Secure Messaging Applications
**Venue / Year**: NDSS 2020
**Authors**: Alireza Bahramali, Amir Houmansadr, Ramin Soltani, Dennis Goeckel, Don Towsley
**Read on**: 2026-05-16 (in lessons 10.7, 10.11)
**Status**: full PDF
**One-line**: Encrypted messaging apps (Signal, WhatsApp, Telegram) leak message type/content category via packet sequences; DL classifier 80–95%.

## Problem
End-to-end-encrypted messaging is widely deployed. Does it leak user-level activity?

## Contribution
1. Demonstrate text/voice/image/video message classification from encrypted Signal/WhatsApp/Telegram traffic.
2. CNN over packet size/IAT sequences.
3. ~80–95% accuracy depending on app.

## Method
- Per-message traces (segmented by manual annotation in lab).
- 1D CNN on packet size + IAT.

## Results
- Signal: 85% media-type accuracy.
- WhatsApp: 92%.
- Telegram: 88%.

## Limitations
- Lab segmentation; real continuous chat session would be harder.
- Doesn't recover message content.

## How it informs our protocol design
- Proteus packet-level shaping insufficient if inner app traffic is distinct.
- Proteus user might mix in cover traffic at app level if extra privacy needed.

## References worth following
- AppScanner (Taylor 16) — predecessor
- FlowPrint (van Ede 20) — destination-based
