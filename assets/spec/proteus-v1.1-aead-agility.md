# Proteus v1.1 amendment — authenticated inner-AEAD agility

**Status:** implementation candidate, security and cross-host validation pending
**Updates:** Proteus v1.0 §§4.1, 5.1, 5.3, 6
**Wire version:** `0x11`

## 1. Motivation and invariant

Proteus encrypts every inner record even when the carrier already provides
TLS 1.3 or QUIC protection. The inner layer supplies carrier-independent
identity binding, per-direction traffic secrets, epoch separation, forward
secrecy and the post-compromise heal ratchet. Removing it would erase
security properties that VLESS+REALITY does not provide.

The v1.0 mandatory cipher, ChaCha20-Poly1305, is a material CPU bottleneck on
hosts with accelerated AES-GCM. Version 1.1 adds cipher agility under this
non-negotiable invariant:

> An on-path adversary cannot remove an offered suite, substitute the server's
> selection, or force v1.0 fallback without causing authentication failure.

## 2. Codepoints

| Meaning | Codepoint / bit |
|---|---:|
| `ChaCha20-Poly1305` suite | `0x01` |
| `AES-256-GCM` suite | `0x02` |
| Client offer: ChaCha20-Poly1305 | `aead_suite_mask & 0x0001` |
| Client offer: AES-256-GCM | `aead_suite_mask & 0x0002` |

Both suites use a 32-byte key, 12-byte nonce and 16-byte tag. Nonce formation,
AAD, epoch and sequence-number rules remain those of v1.0 §4.5.2.

Unknown suite-mask bits are a fatal parse error. An empty v1.1 offer is a fatal
parse error.

## 3. ClientHello encoding

The `ProteusAuthExtension` remains exactly 1,378 bytes. Version 1.1 assigns
the former v1.0 two-byte reserved field:

| Offset | Width | v1.0 | v1.1 |
|---:|---:|---|---|
| 0 | 1 | `version = 0x10` | `version = 0x11` |
| 1 | 1 | `profile_hint` | `profile_hint` |
| 2 | 2 | zero / reserved | `aead_suite_mask`, big-endian |
| 4… | unchanged | v1.0 fields | v1.0 fields |

For v1.1, `client_kex_sig` signs this exact byte string:

```text
version
|| profile_hint
|| aead_suite_mask_be
|| client_nonce
|| client_x25519_pub
|| client_mlkem768_ct
```

The existing `auth_tag` continues to cover every AuthExtension byte preceding
the tag, including the offer. The full encoded ClientHello body also remains
an input to the Finished transcript.

Version 1.0 signature input and reserved-zero validation remain unchanged.

## 4. Server selection

After authenticating and validating the ClientHello, the server selects one
offered suite according to local policy. The current mandatory policy is:

1. select AES-256-GCM when offered;
2. otherwise select ChaCha20-Poly1305 when offered;
3. otherwise fail closed and route through the carrier's normal rejection or
   cover behavior.

The v1.1 ServerHello body is:

```text
server_x25519_ephemeral_public_key[32]
|| selected_aead_suite[1]
```

The complete 33-byte body enters the Finished transcript. The client MUST
reject an unknown suite or any suite it did not offer before accepting
application keys.

The v1.0 ServerHello remains the original 32-byte ephemeral X25519 public key,
and v1.0 always means ChaCha20-Poly1305.

## 5. Downgrade analysis

Changing the client's offer invalidates its Ed25519 identity signature.
It also invalidates the AuthExtension HMAC and the Finished transcript.
Changing the server's selected suite changes the ServerHello transcript and
therefore invalidates both Finished computations. Replacing `0x11` with
`0x10` changes the signed version and cannot yield a valid legacy handshake.

A v1.1 client MUST NOT retry v1.0 merely because a connection, handshake or
Finished check failed. Legacy operation requires an explicitly selected v1.0
client implementation or configuration. Network-driven fallback would turn
packet dropping into a downgrade oracle and is forbidden.

## 6. Key lifecycle

Suite selection applies to every encrypted inner record in the session,
including DATA, padded DATA, CLOSE and RATCHET records. Every ratchet-derived
epoch key rebuilds the same authenticated suite. Switching suites inside a
session is forbidden.

AES-256-GCM is implemented through the same AWS-LC provider already linked by
the rustls/quinn carrier stack. This avoids a second production native crypto
provider. ChaCha20-Poly1305 remains available for v1.0 and future explicit
platform policy.

## 7. Required validation before promotion

Promotion from candidate to normative requires all of the following:

1. byte-exact v1.0 and v1.1 wire round trips;
2. negative tests for empty, unknown, removed and unoffered suites;
3. identity-signature failure after offer mutation;
4. Finished failure after ServerHello selection mutation;
5. DATA, CLOSE and ratchet interoperability under each suite;
6. Rust 1.85 container build and full workspace tests;
7. matched beta-proxy throughput, CPU and RSS measurements against Hysteria2
   and TUIC-v5;
8. two-host repetition under IID loss, burst loss, reordering and outage;
9. a public-repository redaction audit before commit and push.

Until these gates are met, v1.1 is an implementation candidate and no
“security or performance cap” claim is valid.

## 8. Primary references

- RFC 8439, *ChaCha20 and Poly1305 for IETF Protocols*.
- NIST SP 800-38D, *Recommendation for Block Cipher Modes of Operation:
  Galois/Counter Mode (GCM) and GMAC*.
- RFC 8446 §§4.4 and 7.1, transcript authentication and key schedule.
