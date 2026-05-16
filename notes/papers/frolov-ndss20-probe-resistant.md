# Detecting Probe-Resistant Proxies
**Venue / Year**: NDSS 2020 (DOI 10.14722/ndss.2020.23087)
**Authors**: Sergey Frolov, Jack Wampler, Eric Wustrow (University of Colorado Boulder)
**Read on**: 2026-05-16 (in lessons 11.3, 11.4, 11.7, 11.10, 11.12)
**Status**: abstract + key findings from official NDSS page + slides (PDF available at https://www.ndss-symposium.org/wp-content/uploads/2020/02/23087.pdf)
**One-line**: Identifies fingerprintable "outside behaviors" that betray probe-resistant proxies (obfs4, Shadowsocks, Lampshade) even when they refuse to respond — a censor with minimal probing can confirm proxies with negligible false positives.

## Problem
"Probe-resistant" proxies (obfs4, SS, Lampshade) attempt to stay silent against unauthorized probes from censors. Claim: indistinguishable from generic non-responsive server. Frolov et al. show this claim breaks under more careful probing — silence itself, plus timeout behaviors and disconnect timing, fingerprint the proxy implementations.

## Contribution
- Identifies common code-pattern flaw: probe-resistant proxies first **read N bytes** then **check authentication**. This creates a distinctive "buffer-then-close" behavior unique to the family.
- Enumerates concrete outside-behavior leaks:
  1. **Popular-protocol response**: ~94% of internet servers respond meaningfully to at least one common protocol (HTTP, TLS, SSH); proxies typically don't.
  2. **Close-byte threshold**: how many bytes does the server accept before deciding to close? Each proxy has a specific N.
  3. **Close-timeout**: how long does the server wait before closing on partial/incorrect data?
  4. **Read pattern under malformed input**: differs between e.g. obfs4 vs SS vs raw TCP.
- Scans hundreds of thousands of internet-facing servers at a 10 Gbps university vantage; uses ZMap.
- Confirms attack works with low false-positive rate.

## Method
- Vantage point passively identifies candidate proxy IPs from flow patterns.
- Active prober sends sequence of probes (popular protocols + custom byte counts + timing measurements).
- Classifier on response behavior → high-confidence proxy detection.

## Results
- Each of obfs4, SS, Lampshade has a unique fingerprintable signature.
- Even when proxies are "silent", silence-style and close-style features identify them.
- Negligible false positives against legitimate non-responsive servers.

## Limitations / what they don't solve
- Doesn't propose a comprehensive new design that resists all four leaks simultaneously (Lampshade is somewhat better but still has minor leaks).
- Recommends mitigations: forward to real-server fallback, mimic popular-protocol response — direct intellectual ancestor of REALITY.

## How it informs our protocol design
- G6's REALITY-style fallback (cover forward on auth fail) directly addresses Leak #1.
- G6 spec §11.10 enumerates all 4 leaks and corresponding mitigations.
- Forward must complete with < 1ms p99 RTT inflation (spec §7) to defeat timing-based leak (#3, #4).
- Server OS tuning must match cover server's OS (Linux + standard tuning) to defeat (#2).

## Open questions
- Are there OS-level fingerprints beyond the 4 identified (e.g., TCP timestamp granularity, TCP option order)?
- Can fallback latency be reduced to genuinely zero via kernel module / eBPF?
- What's the lower bound on "outside behavior leakage" for any proxy that does any authentication?

## References worth following
- Houmansadr-Brubaker-Shmatikov S&P 2013 "Parrot is dead" — intellectual predecessor
- Frolov-Wustrow FOCI 2020 "HTTPT: A Probe-Resistant Proxy" — proposed design response
- REALITY README (xtls/reality) — production-grade implementation of fallback-style mitigation
