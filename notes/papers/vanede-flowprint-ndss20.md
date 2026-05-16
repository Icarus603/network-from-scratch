# FlowPrint: Semi-Supervised Mobile-App Fingerprinting on Encrypted Network Traffic
**Venue / Year**: NDSS 2020
**Authors**: Thijs van Ede, Riccardo Bortolameotti, Andrea Continella, Jingjing Ren, Daniel J. Dubois, Martina Lindorfer, David Choffnes, Maarten van Steen, Andreas Peter
**Read on**: 2026-05-16 (in lessons 9.8, 9.13, 10.2, 10.3)
**Status**: full PDF (`https://www.ndss-symposium.org/wp-content/uploads/2020/02/24412.pdf`); code (`https://github.com/Thijsvanede/FlowPrint`)
**One-line**: Semi-supervised mobile-app fingerprinter (89.2 % closed-world, 93.5 % precision on previously-unseen apps) built from temporal correlation of destination-related features without needing per-app prior knowledge.

## Problem
App-level traffic classification matters both for defenders (BYOD policies, malware family triage) and for circumvention research (knowing whether an app is identifiable from encrypted traffic alone). Prior supervised methods (AppScanner, *USENIX Security 2016*) need labelled training per app and can't generalise to unseen apps — but mobile ecosystems churn weekly.

## Contribution
1. **Browser-tab / app classification without per-app labels**, by clustering flows in time and using destination-related features (`(dst_IP, dst_port, TLS-SNI, certificate hash)`).
2. **Open-world evaluation**: detects 72.3 % of previously-unseen apps within the first 5 minutes of communication.
3. Reusable feature taxonomy (categorical + binned continuous) suitable for transfer to other classification problems (proxy detection, malware family detection).

## Method
- Per flow, extract:
  - **Destination features**: `dst_IP`, `dst_port`, **TLS SNI**, certificate fingerprint.
  - **Volume features**: bytes-out, bytes-in, packet count.
  - **Temporal features**: inter-flow time, packet inter-arrival time (in/out).
- **Clustering**: agglomerative on destination features → "destination groups" (apps tend to use a stable set of CDNs/back-ends).
- **Cross-correlation**: flows in the same time window (and same device) that hit the same destination group are merged into an app session.
- **Fingerprint**: the set of destinations + volume distribution per session.
- Classification: nearest-fingerprint lookup with confidence threshold; unknown if max similarity < τ.

## Results
- Datasets: ReCon-Cross-Platform (Android+iOS, 81 apps), Andrubis (~110 k samples, malware), and 5 in-house lab datasets.
- Closed-world accuracy 89.2 %, vs AppScanner ~75 %.
- Open-world: 93.5 % precision on isolating an unseen app as "new".

## Limitations / what they don't solve
- Heavy dependence on SNI/certificate: if the entire transport hides behind a single CDN with a single cover SNI, the destination features collapse and FlowPrint degrades.
- Temporal grouping assumes one device runs one foreground app at a time — false in multi-tasking.
- Cannot fingerprint proxied traffic where all destinations look like the proxy endpoint.

## How it informs our protocol design
- **Adversary capability lift**: even without per-app labels, an attacker can build app-level fingerprints. Our protocol must ensure that all our traffic looks like a single destination cluster (the cover SNI + its real backend population).
- **Volume/timing leakage** is the residual risk. Padding+pacing matter even when destinations are perfectly masked.
- **For our testbed**: FlowPrint provides a strong baseline classifier for "is this traffic from our protocol or from Chrome browsing the cover domain?" — Lesson 9.13 uses it.

## Open questions
- Performance on **single-destination** traffic (proxy → one host). Authors briefly note degradation; precise numbers not in paper.
- How well does FlowPrint distinguish two proxy users behind the same egress (multi-user co-residence)?

## References worth following
- Taylor et al. *AppScanner.* USENIX Security 2016 (supervised baseline).
- Conti et al. *Robust Smartphone App Identification via Encrypted Network Traffic Analysis.* TIFS 2016.
- Sirinam et al. *Deep Fingerprinting.* CCS 2018 → [[sirinam-deep-fingerprinting-ccs18]].
