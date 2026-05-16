# Trojan — wire-format spec
**Source**: https://trojan-gfw.github.io/trojan/protocol  · github.com/trojan-gfw/trojan/blob/master/docs/protocol.md
**Fetched**: 2026-05-16 (for lessons 7.5, 7.7, 7.8, 7.9)
**Status**: full

## Wire format

After a vanilla TLS handshake (server presents a real certificate; can be CDN-fronted or domain-bound), the client immediately sends:

```
| hex(SHA224(password)) | CRLF | Trojan Request | CRLF | Payload |
| 56 bytes              | 2 B  | variable       | 2 B  | …       |
```

Where `Trojan Request` mirrors SOCKS5:

```
| CMD | ATYP | DST.ADDR | DST.PORT |
| 1 B | 1 B  | variable | 2 B (BE) |
```

- `CMD`: `0x01` = CONNECT, `0x03` = UDP ASSOCIATE
- `ATYP`: `0x01` IPv4, `0x03` domain (1-byte length prefix), `0x04` IPv6

For UDP ASSOCIATE, each datagram framed inside the TLS stream as:

```
| ATYP | DST.ADDR | DST.PORT | Length | CRLF | Payload |
| 1 B  | variable | 2 B      | 2 B    | 2 B  | …       |
```

## Auth model

Single shared password. Client sends the lower-case ASCII hex of `SHA224(password)` (28-byte digest → 56 hex chars). Server keeps a hash table of authorised hex strings; lookup is O(1). No UUID, no per-connection nonce, no key exchange — TLS provides the only confidentiality.

## Anti-replay

**None at the application layer.** TLS rules out passive replay because the inner record key is per-session, but if the password hash leaks (e.g. via active-probe of a stolen cert), an attacker can authenticate forever — there is no timestamp window or counter.

## Encryption / AEAD

Outer TLS only (typically TLS 1.2 or 1.3 with whatever ciphersuite the operator's cert/server config picks). The application payload is plaintext inside the TLS record, byte-identical to a real HTTP/HTTPS proxy stream.

## Key design quirks worth flagging

- **Fail-open redirect.** If the first 56 bytes do not match a known hash, the server MUST splice the connection to a "fallback" target (default `127.0.0.1:80`), making active probes look like contact with the cover website. This is the central anti-censorship trick.
- **No length obfuscation.** TLS-in-TLS happens for any HTTPS destination, producing the now-famous record-size signature exploited by Frolov/Wustrow's TLS-in-TLS detector and later refined by GFW.report — Trojan has no defence here (Vision later does).
- **CRLF separators are weird.** Two `\r\n` terminators (after auth and after request) make the wire look vaguely HTTP-shaped, but offer no real cover.
- **Password hash is the long-term secret.** Rotation requires reconfiguring every client.

## Source of truth (code citation)

`trojan-gfw/trojan/src/proto/trojanrequest.cpp` (parser) and `src/session/clientsession.cpp` (writer); SOCKS5-shaped enums in `src/proto/socks5.h`. The Go fork sing-box mirrors the same layout in `protocol/trojan/protocol.go`.
