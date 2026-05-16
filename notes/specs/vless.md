# VLESS — wire-format spec
**Source**: https://xtls.github.io/development/protocols/vless.html · github.com/XTLS/Xray-core (proxy/vless/encoding/encoding.go)
**Fetched**: 2026-05-16 (for lessons 7.5, 7.7, 7.8, 7.9)
**Status**: full (v1 frozen format; addons evolve)

## Wire format

VLESS runs **inside** an outer transport (TLS, REALITY, WebSocket, gRPC, mKCP, …); the bytes below are the very first bytes of the inner stream.

### Request header (client → server)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 B | Protocol version (`0x00` = beta, `0x01` = release) |
| 1 | 16 B | UUID |
| 17 | 1 B | Addon length `M` |
| 18 | M B | Addons (ProtoBuf) — carries the `flow` string for XTLS-Vision etc. |
| 18+M | 1 B | Command (`0x01` TCP, `0x02` UDP, `0x03` Mux) |
| 19+M | 2 B | Destination port (BE) |
| 21+M | 1 B | Address type (`0x01` IPv4, `0x02` domain w/ 1-B length, `0x03` IPv6) |
| 22+M | var | Destination address |
| … | var | Payload (immediately follows; 0-RTT) |

### Response header (server → client)

| Size | Field |
|---|---|
| 1 B | Protocol version (echo) |
| 1 B | Addon length `N` |
| N B | Addons |
| var | Payload |

## Auth model

A single 16-byte UUID. The server keeps a `sync.Map[uuid] → user` and looks the value up in O(1). No timestamp, no HMAC, no random salt — the UUID is sent essentially in the clear at the start of the inner stream and relies entirely on the outer transport (TLS/REALITY) for confidentiality.

## Anti-replay

**None at the VLESS layer.** Replay protection is delegated to the outer transport (TLS 1.3 / REALITY rejects replayed handshakes via random nonces). Once an attacker has the UUID *and* can defeat the outer cert-pinning (e.g. with REALITY's stolen-target trick), nothing in VLESS prevents replay.

## Encryption / AEAD

**No inner encryption.** The body after the request header is whatever the outer transport produces — VLESS is a pure framing/auth layer. The spec reserves an `encryption` slot ("currently only `none` accepted; future may add aes-128-gcm, chacha20-poly1305") but as of 2026 production Xray still ships `none` only. This is the deliberate, headline difference from VMess.

## Key design quirks worth flagging

- **0-RTT payload.** Client appends user data immediately after the address; the server can dispatch as soon as it has the address bytes. No round-trip cost beyond the outer handshake.
- **Stateless server.** No per-user counters, no clock dependency — fixes VMess's NTP drift class of bugs.
- **Addons carry "flow".** XTLS-Vision is signalled via the `flow` field inside the ProtoBuf addon (e.g. `xtls-rprx-vision`). Without a flow string, VLESS is plain pass-through.
- **Header is plaintext inside outer TLS.** The 16-byte UUID is the first thing after `0x00`/`0x01` version byte. If outer TLS is broken (e.g. probe + key exfil), the UUID is trivially recovered — there is no challenge-response.
- **Forward-compatible response.** The server echoes the version, allowing clients to detect protocol upgrades without breaking older peers.

## Source of truth (code citation)

`XTLS/Xray-core/proxy/vless/encoding/encoding.go` — `EncodeRequestHeader`, `DecodeRequestHeader`, `EncodeResponseHeader`. UUID validation in `proxy/vless/validator.go`. Addons defined in `proxy/vless/account.proto`.
