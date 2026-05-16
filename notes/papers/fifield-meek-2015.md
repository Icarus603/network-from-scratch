# Blocking-resistant communication through domain fronting
**Venue / Year**: PoPETs (PETS) 2015
**Authors**: David Fifield, Chang Lan, Rod Hynes, Percy Wegmann, Vern Paxson
**Read on**: 2026-05-16 (in lesson 10.6)
**Status**: full PDF
**One-line**: Domain fronting technique — SNI shows a permitted CDN host, while HTTP Host header routes to the actual destination; deployed as Tor's meek Pluggable Transport.

## Problem
By 2014 censors (GFW, Iran) routinely block Tor bridges via active probing and DPI on obfuscation protocols. Need a transport that censors cannot block without massive collateral damage.

## Contribution
1. Formalize **domain fronting** technique: TLS SNI = permitted-domain.com (e.g., Google App Engine), HTTP/1.1 Host header = blocked-bridge.com. CDN reads Host header to route.
2. Implementation: meek Pluggable Transport with Google, Amazon, Azure CDN backends.
3. Demonstrate effectiveness against GFW and Iran censors at PETS 2015.

## Method
- Client makes HTTPS connection to CDN-hosted "front domain" (visible to censor).
- Within TLS, send HTTP request to "back domain" (the actual bridge).
- CDN routes by Host header (back domain).
- Censor sees only TLS to front domain — blocking front would block all the CDN's traffic.

## Results
- 2015–2018: meek-google, meek-amazon, meek-azure widely deployed.
- Bandwidth penalty: minimal (~5–10%).
- Latency penalty: 100–500ms (CDN hop).
- Bypass effective in China, Iran, Turkey, others.

## Limitations
- 2018: Google and Amazon ended support — domain fronting policy decision.
- Cloudflare partially still supports.
- Per-connection latency to CDN.
- Censor can correlate fronting traffic via long-lived connections, sub-flow analysis (Wails 24).

## How it informs our protocol design
- **Domain fronting is fragile to CDN policy** — never depend on a single CDN provider.
- The principle (route via permitted host) generalizes — REALITY (Xray) is an evolution that doesn't depend on CDN cooperation.
- G6 may include domain fronting as optional fallback transport (in environments where Cloudflare/Azure still cooperate).

## Open questions
- Multi-CDN sharding to reduce single-provider risk (Wails et al. proposed).
- Cooperatively-trustless fronting without CDN explicit cooperation (Conjure path).
- Bandwidth-efficient fronting alternatives.

## References worth following
- Bocovich-Goldberg 16 (Slitheen) — decoy-routing alternative
- Frolov 19 NDSS uTLS — fingerprint-mimicry building block
- Conjure (Frolov 19 CCS) — refraction-networking successor
- Wails 24 PoPETs — fronting deployment data
