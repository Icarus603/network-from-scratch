# The use of TLS in Censorship Circumvention
**Venue / Year**: NDSS 2019
**Authors**: Sergey Frolov, Eric Wustrow
**Read on**: 2026-05-16 (in lessons 10.6, 10.7, 10.8)
**Status**: full PDF
**One-line**: Documents TLS ClientHello fingerprinting (JA3-style) in circumvention; introduces uTLS — a Go library to "parrot" browser fingerprints byte-for-byte.

## Problem
Tor pluggable transports, Shadowsocks, Lantern etc. use Go/Python TLS libraries whose ClientHello differs visibly from Chrome/Firefox. GFW etc. fingerprint and block them.

## Contribution
1. Catalogue of TLS ClientHello differences across Chrome, Firefox, Safari, and various proxy implementations (Go, Python, Java).
2. uTLS library — a fork of Go's crypto/tls allowing arbitrary ClientHello synthesis.
3. Measurement of fingerprintability in real censored networks.

## Method
- Capture ClientHellos from real browsers (Chrome, Firefox, Safari, Edge across versions).
- Define a "TLS parrot" — generate ClientHello matching a specific browser.
- Implement in Go: uTLS package with HelloChrome_xx, HelloFirefox_xx presets.
- Measure detection rates against fingerprint-based DPI.

## Results
- Default Go crypto/tls ClientHello: uniquely identifiable.
- uTLS Chrome 70 mode: indistinguishable from real Chrome 70 ClientHello at byte level.
- Adoption: V2Ray, Xray, Lantern, sing-box, all use uTLS.

## Limitations
- Maintenance burden: uTLS lags real browser updates by weeks-to-months.
- Wire-byte parity only — doesn't cover TLS extensions sent post-handshake (e.g., 0-RTT).
- TLS-in-TLS detection (subsequent work) bypasses uTLS-perfect ClientHello.
- Server-side fingerprinting (ServerHello) also possible; uTLS doesn't help defenders running TLS server.

## How it informs our protocol design
- **uTLS is mandatory for G6 client.** No exceptions. Direct Go/Rust crypto/tls usage betrays G6 identity.
- G6 must subscribe to a "uTLS profile sync" workflow — when Chrome updates, G6 client updates too.
- Server-side TLS still uniquely identifiable; G6 server should leverage REALITY-style passing of real TLS server's responses.

## Open questions
- Automated uTLS profile derivation from live traffic dumps?
- Combining uTLS with TLS-in-TLS evasion (when proxy nest TLS is unavoidable)?
- Mobile-browser fingerprints (Chrome iOS, Safari iOS) — currently underrepresented.

## References worth following
- Salesforce JA3 spec
- FoxIO JA4 spec
- Sosnowski 24 / TLS-in-TLS detection literature
- Houmansadr 13 (Parrot is Dead) — mimicry limits
