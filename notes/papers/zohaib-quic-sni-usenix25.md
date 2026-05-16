# Exposing and Circumventing SNI-based QUIC Censorship of the Great Firewall of China
**Venue / Year**: USENIX Security 2025
**Authors**: Ali Zohaib, Qiang Zao, Jackson Sippe, Abdulrahman Alaraj, Amir Houmansadr (UMass Amherst), Zakir Durumeric (Stanford), Eric Wustrow (CU Boulder); collaboration with GFW Report
**Read on**: 2026-05-16 (in lesson 9.5)
**Status**: full PDF (`https://www.usenix.org/system/files/usenixsecurity25-zohaib.pdf`); artifact (`https://github.com/gfw-report/usenixsecurity25-quic-sni`)
**One-line**: GFW began at-scale QUIC SNI censorship on 2024-04-07 by decrypting QUIC Initial packets using the publicly-derivable initial key, but does *not* reassemble multi-datagram Initials — yielding both a trivial circumvention (SNI-slicing) and an availability-attack primitive.

## Problem
QUIC encrypts the ClientHello inside the Initial packet, but the encryption key is derived from public material `(DCID, version-salt)`. Whether GFW would deploy at-scale Initial decryption was an open question through 2023. April 2024 anecdotal reports said yes; this paper quantifies what happened.

## Contribution
1. 3-month measurement (10 Beijing vantage points × full Tranco 7 M FQDN list) confirming a QUIC-specific SNI blocklist of ~58 207 FQDNs disjoint from but overlapping with DNS/HTTP/HTTPS blocklists.
2. Characterisation of the GFW's QUIC parser: (a) decrypts Initial using initial keys (RFC 9001 §5.2); (b) **does not reassemble** Initial across multiple UDP datagrams; (c) blocks only QUIC version 1 (`0x00000001`).
3. Multiple working circumventions (SNI-slicing across two UDP datagrams, version-2 forced negotiation, unknown-version probing) integrated upstream into `quic-go` 0.52 (May 2025) and Chrome.
4. Demonstrates the censor as an **availability-attack reflector**: an attacker can spoof QUIC Initials from arbitrary Chinese IPs to forbidden SNIs, forcing GFW to block real bystanders' QUIC.

## Method
- **Inside-out** measurement: Beijing client → US server (after bidirectional → unidirectional regression on 2024-09-30, inside-out is more reliable).
- For each FQDN: send a vanilla QUIC Initial containing that SNI, observe whether the server's Initial response is dropped on the return path.
- Reassemble experiments: send Initial that legally spans two UDP datagrams (per RFC 9000); observe whether GFW blocks (it doesn't if SNI splits across datagrams).
- Version-negotiation experiments: send `version = 0xfafafafa` to elicit a Version-Negotiation packet, then resume with a hidden version.

## Results
- Blocklist size stable at ~43.8 k FQDNs/week, cumulative 58 207.
- ~24 % overlap with DNS/HTTP/TLS blocklists; ~11 000 unique to QUIC (preemptive blocking of FQDNs that don't yet support HTTP/3).
- A brief delay between detection and packet drop allowed in-path-mode evidence: GFW operates on-path (mirror) + in-path (drop), not purely in-band.
- After disclosure (2025-01), GFW patched partial reassembly in 2025-03 but circumvention still works.

## Limitations / what they don't solve
- Does not characterise UDP rate-limiting (orthogonal control plane).
- Initial fragmentation defence is reactive — GFW could add multi-packet stateful reassembly any time, and Chrome's PQ-key-share ClientHello will soon force everyone to fragment.

## How it informs our protocol design
- **QUIC-over-cover is viable** at 2026 because of the no-reassembly bug. Long-term, plan for the day GFW reassembles.
- **SNI placement is mandatory.** Whatever cover protocol we use over QUIC, the SNI byte must (a) be a *real* unblocked SNI in plaintext, (b) survive a stateful reassembler.
- **Initial key derivation is public**, period. We cannot hide our cover SNI by trusting Initial encryption. Our threat model: GFW *can* read every QUIC Initial.
- **Version negotiation** as an evasion is a temporary trick. Don't bake protocol identity into version field; rotate.

## Open questions
- When (not if) GFW gains reassembly, what's the next QUIC-specific bypass? Padding inside Initial? Multi-CID handshake fan-out?
- Does the availability-attack vector persist after the 2025-03 patch?

## References worth following
- RFC 9000 *QUIC: A UDP-Based Multiplexed and Secure Transport.*
- RFC 9001 *Using TLS to Secure QUIC.*
- RFC 9412 *Establishing a QUIC connection (h3 specifics).*
- Bauer, Beck, Hofheinz. *Encrypting traffic, not metadata: lessons from QUIC Initial.* (CCS 2024 — adjacent threat model).
