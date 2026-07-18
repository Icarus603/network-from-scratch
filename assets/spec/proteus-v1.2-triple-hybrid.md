# Proteus v1.2 amendment — hedge-authenticated triple hybrid

**Status:** implementation candidate

**Version byte:** `0x12`

**Supersedes:** the v1.0/v1.1 two-component Handshake-Secret input and
legacy-version acceptance rules

**Wire layout:** unchanged from v1.1 except for the authenticated version byte

## 1. Motivation

Proteus v1.1 combined a per-session ephemeral X25519 contribution with an
ML-KEM-768 contribution. The pinned static X25519 public key remained in client
configuration but did not enter the key schedule. Consequently, a hypothetical
ML-KEM break would let an active attacker choose the ServerHello ephemeral
X25519 share and forge Server Finished. The construction therefore did not
provide the intended hedge property that one surviving server-authentication
component remains sufficient.

Version 1.2 restores the pinned static X25519 key as an independent KDF
component while retaining the per-session ephemeral X25519 share for classical
forward secrecy.

## 2. Key-exchange inputs

The client generates one fresh X25519 keypair and one fresh ML-KEM encapsulation
per handshake. The server generates one fresh ephemeral X25519 keypair per
handshake and retains its separately provisioned static X25519 and ML-KEM key
pairs.

```text
K_ephemeral = X25519(c_eph_sk, s_eph_pk)
K_static    = X25519(c_eph_sk, s_static_pk)
K_pq        = ML-KEM-768.Decaps(s_pq_sk, c_mlkem_ct)

hybrid_shared = K_ephemeral || K_static || K_pq
```

Each component is 32 bytes; `hybrid_shared` is exactly 96 bytes. Client and
server MUST reject an all-zero result from either X25519 operation. ML-KEM
decapsulation follows FIPS 203 implicit rejection.

The 96-byte `hybrid_shared` value is the IKM supplied to the existing
TLS-1.3-style Handshake-Secret `HKDF-Extract` stage. Component order is
normative.

## 3. Authentication and transcript binding

The client identity signature covers:

```text
version ||
profile_hint ||
aead_suite_mask ||
client_nonce ||
client_x25519_ephemeral_public ||
client_mlkem768_ciphertext
```

The outer TLS exporter remains in the ClientHello/ServerHello-equivalent
transcript hash. The ServerHello body remains:

```text
server_x25519_ephemeral_public[32] || selected_aead_suite[1]
```

Server Finished authenticates the transcript under keys derived from all three
components. An attacker that learns or cryptanalytically defeats only one
component still lacks the other two KDF inputs. The static-X25519 and ML-KEM
components are independent server-authentication hedges; the ephemeral-X25519
component supplies per-session classical forward secrecy.

## 4. Version negotiation and downgrade behavior

A v1.2 implementation MUST emit `version = 0x12`. The production v1.2 server
MUST fail closed on v1.0 and v1.1 authentication extensions. It MUST NOT retry,
fall back to, or silently derive the old 64-byte Handshake-Secret input.

The AuthExtension remains byte-for-byte the v1.1 length. Parsers may decode
v1.0 and v1.1 for diagnostics, fixtures, or explicit migration tooling, but
the production suite selector MUST reject them before key derivation. This rule
supersedes the v1.0 §12.4 compatibility language.

## 5. Required conformance gates

An implementation candidate is incomplete unless all of the following pass:

1. Client and server derive identical 96-byte ordered KDF input.
2. Substituting only the pinned static server public key changes only
   `K_static` and changes the final KDF input.
3. Corrupting the ML-KEM ciphertext produces a divergent `K_pq` through
   implicit rejection.
4. Two handshakes against one server emit distinct ephemeral ServerHello
   X25519 shares, and neither equals the static public key.
5. A client configured with a mismatched static server public key fails the
   handshake.
6. v1.0 and v1.1 inputs fail closed at the production suite selector.
7. The pinned ProVerif model proves bidirectional payload secrecy and
   injective agreement when any one shared component is disclosed before
   Server Finished authentication.

## 6. Proof boundary

The checked ProVerif model is a symbolic Dolev–Yao argument for secrecy and
agreement under its declared equations. It is not a computational reduction or
an implementation audit. Side channels, RNG failure, endpoint compromise,
traffic analysis, the post-handshake ratchet, state exhaustion, and
cross-protocol interactions remain separate obligations.
