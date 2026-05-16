# The Use of TLS in Censorship Circumvention
**Venue / Year**: NDSS 2019
**Authors**: Sergey Frolov, Eric Wustrow (University of Colorado Boulder)
**Read on**: 2026-05-16 (in lessons 9.4, 9.9)
**Status**: full PDF (`https://censorbib.nymity.ch/pdf/Frolov2019a.pdf`)
**One-line**: First measurement at scale of TLS ClientHello fingerprint diversity in real backbone traffic; introduces `uTLS`, the de-facto library for ClientHello mimicry used by Tor, Psiphon, Lantern, TapDance, and almost every modern proxy that wants to look like a browser.

## Problem
Censorship-resistant tools that ride TLS assume "many tools also use TLS, so we hide among them." But each TLS implementation (BoringSSL, NSS, GnuTLS, Go `crypto/tls`, Java `JSSE`, Python `ssl`, …) emits a distinguishable ClientHello: cipher list, extension order, supported groups, signature algorithms, ALPN, GREASE values, padding. A censor can therefore enumerate the unique TLS fingerprint of a circumvention tool and block exactly those connections with very little collateral damage.

## Contribution
1. 9-month tap (~11 B TLS handshakes) at a 10 Gbps university border feeding the first large-scale ClientHello fingerprint census; resulting database `tlsfingerprint.io`.
2. Demonstrated that Tor (Snowflake/meek), Lantern, Psiphon, Signal, TapDance, and Outline each had a TLS fingerprint that appeared in **<0.0003 %** of background traffic — making them trivially distinguishable.
3. Released `uTLS`, a fork of Go's `crypto/tls` that lets the caller assemble an arbitrary ClientHello (preset Chrome/Firefox/Safari profiles or fully custom) while still completing a real TLS handshake.

## Method
- Define a **TLS fingerprint** as the SHA1 of `(TLS version, cipher list, compression list, extension list ordered, named-groups, EC-point-formats, sig-algs, ALPN, key-share-curves)` with GREASE values removed.
- Mirror packets, parse with a custom Bro/Zeek script, deduplicate, then join with destination SNI + Server fingerprint (JA3S-like) to characterise per-domain populations.
- For each circumvention tool, run a controlled instance through the tap, identify its fingerprint hash, query the census for prevalence and collateral.
- `uTLS` is implemented by exposing `ClientHelloSpec` plus helper builders for `HelloChrome_70`, `HelloFirefox_63`, etc.

## Results
- **18 %** of all observed TLS came from a single Chrome 70/71 fingerprint, so mimicking that fingerprint hides a tool inside a very large crowd.
- Tools that "parrot" Chrome via copy-paste of cipher lists still fail because they don't replicate **extension order, GREASE placement, padding length, and key-share split** — all of which the censor can hash.
- After integration of `uTLS`, the fingerprints of Psiphon/meek/TapDance collapsed into the Chrome population.

## Limitations / what they don't solve
- ClientHello fingerprint is not the only TLS-level discriminator. Subsequent papers extend to **(ALPN, ECH, key share group, post-handshake)** features. Cf. JA4 (Althouse 2023+).
- Cannot disguise *behaviour after handshake*: HTTP/1.1 vs HTTP/2 frame patterns, response times, certificate validation paths.
- `uTLS` is a Go-only library; analogous libraries in Rust (`rustls-utls`, used in `sing-box`) and C++ (`utls-cpp`) appeared later. Other-language tools may still leak fingerprints.

## How it informs our protocol design
- **Required**: our protocol's outermost TLS layer must use `uTLS` (or equivalent) with a current-Chrome profile, refreshed at every Chrome stable release (≈6 weeks).
- **Required**: the SNI/ALPN/ECH/key-share/ClientHello padding values must match the cover host's own population, not Chrome's global average — otherwise we fingerprint by mismatch with the destination's typical client population.
- **Failure mode to avoid**: pinning to one fingerprint forever. As Chrome rolls extensions (PQ key share, Encrypted ClientHello), our fingerprint slot shrinks → must auto-rotate.

## Open questions
- Beyond ClientHello, how distinguishable are tools by combined `(ClientHello, ClientHelloRetry-on-HRR, ServerName-derived behaviour)`? Census data exists but per-tool studies don't.
- How does ECH (RFC 9460 / draft-ietf-tls-esni) change the prevalence game when only the outer SNI is observable?
- ML classifiers trained on Frolov's census labels: can they identify previously-unseen tool fingerprints?

## References worth following
- Marlinspike's `forbiddenctype` posts on ClientHello uniqueness (engineering pre-history).
- Althouse, J. *JA3/JA3S TLS fingerprinting* (2017 Salesforce blog) → [[althouse-ja3]].
- Althouse, J. et al. *JA4+ specifications* (FoxIO 2023+) → [[althouse-ja4]] (next-gen, supersedes JA3).
- Houmansadr et al. *The Parrot is Dead.* IEEE S&P 2013 → [[houmansadr-parrot-is-dead]] (mimicry is fundamentally hard).
- Bhargavan, Bhupatiraju, Wood. *Privacy of TLS 1.3 client hello with ECH.* 2020 → [[bhargavan-ech-privacy]].
