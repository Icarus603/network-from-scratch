# Detecting Probe-resistant Proxies
**Venue / Year**: NDSS 2020
**Authors**: Sergey Frolov, Eric Wustrow
**Read on**: 2026-05-16 (in lesson 10.7, 10.8)
**Status**: full PDF
**One-line**: Active-probing detection of "silent" proxies (obfs4, ScrambleSuit) — these don't respond to invalid probes, which itself is anomalous in the broader Internet.

## Problem
Probe-resistant proxies (obfs4 with HMAC silence) defeat naive active probing. But "completely silent host" is rare on the Internet — could detection be done by exploiting normality?

## Contribution
1. Catalogue several novel probing strategies: half-open TCP probes, ACK-only probes, malformed-TLS probes, etc.
2. Detect "non-responsive host" pattern: a host that drops/ignores certain probes that normal HTTPS servers would handle.
3. Demonstrate detection of obfs4 bridges via these patterns.

## Method
- Internet-wide scan with various probe types.
- Behavioral fingerprint: normal HTTPS servers respond with RST, FIN, or TLS alert to specific malformed probes; obfs4 stays silent.
- Compare bridge IP behavior to normal-host baseline.

## Results
- ~98% obfs4 bridge identification at 0.1% false-positive rate.
- ScrambleSuit similarly detectable.
- Snowflake/meek not affected (run via CDN/WebRTC respectively).

## Limitations
- High-volume scanning required.
- REALITY-style proxies (fallback to real TLS) immune.
- Detection vs blocking gap — blocking still has collateral risk.

## How it informs our protocol design
- **Silent fallback is insufficient.** Proteus must fall back to a real TLS server response (REALITY-style), not silence.
- The obfs4 design philosophy is officially deprecated by this paper.
- Proteus fallback should be carefully tested against Frolov-style probing.

## Open questions
- Larger-scale fallback consistency (how to maintain consistent fallback under load)?
- Anti-probing measures that don't require running a real TLS server?
- Asymmetric probing — does symmetric REALITY hold up against asymmetric probes?

## References worth following
- Houmansadr 13 (Parrot is Dead) — predecessor on mimicry weaknesses
- Frolov 19 NDSS uTLS
- Xray REALITY spec — successor design
- Wails 24 PoPETs — deployment data
