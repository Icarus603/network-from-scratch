# Conjure: Summoning Proxies from Unused Address Space
**Venue / Year**: ACM CCS 2019
**Authors**: Sergey Frolov, Jack Wampler, Sze Chuen Tan, J. Alex Halderman, Nikita Borisov, Eric Wustrow
**Read on**: 2026-05-16 (in lesson 10.6)
**Status**: full PDF
**One-line**: Refraction-networking variant where bridges occupy unused (dark) IP space; ISP-deployed TAP redirects client connections there; censor sees only "client connecting to dark IP".

## Problem
TapDance (Wustrow 14) required two-side cooperation: TAP in ISP and decoy site that lets through TapDance traffic. Hard to deploy widely. Conjure simplifies to one-side cooperation.

## Contribution
1. **Phantom proxies**: connect to dark IP space; TAP at ISP intercepts and routes to actual proxy.
2. ZeroTrust handshake: client uses TLS extension to signal Conjure participation; TAP recognizes and provisions phantom proxy.
3. Deployed pilot on Merit Network, University of Colorado.

## Method
- Client requests Conjure from registration service (over Tor or other circumvention).
- Registration assigns client a phantom IP in dark space.
- TAP at participating ISP recognizes client traffic to phantom IP, redirects to actual proxy.
- Client browses normally; censor sees connection to seemingly empty IP.

## Results
- Deployment: ISP-Scale TapDance (Frolov 20 FOCI) showed 1M+ users.
- Censor cost: blocking dark IPs is high-collateral (real services occasionally occupy them).
- Latency: ~30ms additional TAP processing.

## Limitations
- Requires ISP cooperation — limits deployment.
- Registration service is a censorship pressure point.
- Censor adaptive: classify "dark IP traffic" pattern.
- US-mostly deployment due to regulatory concerns elsewhere.

## How it informs our protocol design
- **Proteus is not pursuing Conjure-style ISP cooperation** — too narrow deployability.
- Conjure's "phantom IP" concept does inform Proteus bridge design: bridges should appear as low-profile services rather than obviously-proxy hosts.
- Registration-service vulnerability is a lesson: Proteus should avoid centralized registration where possible.

## Open questions
- Reduced-cooperation Conjure (no TAP)?
- Multi-ISP Conjure with cross-ISP redirection?
- Quantum-resistant Conjure handshake?

## References worth following
- Wustrow 14 (TapDance) — predecessor
- Bocovich 16 (Slitheen) — decoy routing variant
- Karlin 11 (Decoy Routing) — original refraction networking
- Frolov 20 FOCI — deployment data
