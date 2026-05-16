# XTLS-Vision — wire-format spec
**Source**: https://github.com/XTLS/Xray-core/discussions/1295 · XTLS/Xray-core (proxy/proxy.go, proxy/vless/encoding/encoding.go)
**Fetched**: 2026-05-16 (for lessons 7.5, 7.7, 7.8, 7.9)
**Status**: partial spec from discussion + inferred from source code (no formal RFC-style document exists)

## Wire format

Vision is a **flow** (`xtls-rprx-vision`) selected via the VLESS addon. It does not change the VLESS request header; it changes how the body is framed for the first few packets and then *removes itself* — switching to a raw TCP splice between the inner socket and the outer TLS socket.

Each Vision-framed inner record on the wire:

```
| UUID    | Cmd | PadLen | ContentLen | Padding   | Content   |
| 16 B    | 1 B | 2 B BE | 2 B BE     | PadLen B  | ContentLen B |
```

`Cmd` is one of:

- `0x00 CommandPaddingContinue` — more Vision frames will follow
- `0x01 CommandPaddingEnd` — last Vision-padded frame; subsequent inner records use plain VLESS framing
- `0x02 CommandPaddingDirect` — last Vision frame; switch to **splice** (raw `io.Copy` between sockets, no further parsing)

## Auth model

Inherited from VLESS — 16-byte UUID. The Vision layer additionally embeds the same UUID at the start of every padded frame so the peer can re-synchronise / validate and so an off-path observer cannot trivially inject spoof frames into the inner stream.

## Anti-replay

None beyond outer TLS/REALITY. Vision is purely a length/timing-obfuscation and copy-mode layer; it adds no nonces or counters of its own.

## Encryption / AEAD

None added by Vision. The whole point is to *avoid* a second AEAD pass over the inner TLS stream so that real TLS records traverse the proxy unmolested (no double-encryption length signature, near-line-rate forwarding via splice).

## Key design quirks worth flagging

- **TLS record sniffing.** Vision recognises three byte patterns at the start of inner records:
  - `[0x16, 0x03]` — `TlsClientHandShakeStart` (any TLS 1.x ClientHello)
  - `[0x16, 0x03, 0x03]` — `TlsServerHandShakeStart` (TLS 1.2/1.3 ServerHello)
  - `[0x17, 0x03, 0x03]` — `TlsApplicationDataStart` (encrypted application data)
- **Five-packet handshake fingerprint.** The author identifies the canonical inner-TLS sequence: (1) VLESS request + UUID, (2) server ack, (3) inner ClientHello, (4) inner ServerHello, (5) inner Finished. Vision pads packets 1–5 to a randomised 900–1400 B range (seeds `900, 500, 900, 256` in `XtlsPadding`) so the lengths cease to scream "TLS-in-TLS".
- **Splice trigger.** Once Vision sees an inner record beginning with `0x17 0x03 0x03` (real application data) AND the trafficState says `EnableXtls`, it emits one final frame with `CommandPaddingDirect` and from then on uses `CopyRawConnIfExist` — the kernel just splices bytes between the two TCP sockets. Result: ~99% of the bytes on the wire are the original inner-TLS application-data records, untouched.
- **What it defends against.** The Frolov/Wustrow "TLS-in-TLS detector" (NDSS '19 family) and the GFW.report length-distribution probes that nailed VLESS-without-Vision. Vision flattens the handshake-length signature and removes the double-encryption length expansion.
- **What it does NOT defend against.** The author explicitly flags surviving "CSCSC" timing patterns (Client/Server alternation cadence) as an unfixed vulnerability; multiplexing different connections is suggested as the next mitigation.
- **Why "Vision" not "Direct/Splice".** Earlier XTLS variants (Origin, Direct, Splice) were the prototypes; Vision merges their best ideas with explicit padding into what RPRX calls the "ideal form."

## Source of truth (code citation)

- `XTLS/Xray-core/proxy/proxy.go` — `XtlsPadding`, `XtlsUnpadding`, `CopyRawConnIfExist`; constants `CommandPaddingContinue/End/Direct` and the three TLS-record-start byte arrays.
- `XTLS/Xray-core/proxy/vless/encoding/encoding.go` — `XtlsRead` / `XtlsWrite` orchestrating the switch from Vision framing to splice.
- Design rationale: `XTLS/Xray-core/discussions/1295` (RPRX, 2022) and follow-up `discussions/2466`.
