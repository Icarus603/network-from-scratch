# The Noise Protocol Framework
**Venue / Year**: revision 34, July 2018 (running document)
**Authors**: Trevor Perrin
**Read on**: 2026-05-14 (in lesson 3.8)
**Status**: full PDF (`assets/papers/perrin-noise-2018.pdf`)
**One-line**: 定義一個 protocol-design DSL，用 token-based pattern 描述 handshake；12 個 fundamental patterns 涵蓋大部分 AKE 場景；WireGuard、Lightning Network、Signal、Wire 全採用；Proteus 直接 build on Noise IK。

## Problem
2014-2016 年 Signal 設計 X3DH + Double Ratchet 時 Perrin 觀察：每個新 protocol 都重新發明 KE + record layer + key schedule。需要一個 framework 能 systematically 設計 protocols with composable security properties。

## Contribution
1. **Pattern DSL**: 用 `e`, `s`, `ee`, `es`, `se`, `ss`, `psk` 等 tokens 描述 handshake。可機械 parse + analyze。
2. **State machine 抽象**: HandshakeState / SymmetricState / CipherState 三層抽象，所有 patterns 都 share 這套 state machine。
3. **12 fundamental patterns** (NN, NK, NX, KN, KK, KX, XN, XK, XX, IN, IK, IX) + PSK variants → 60+ specific protocols。
4. **每 pattern 內建 security analysis**: 每 message 標 (auth_level, conf_level) tuple。
5. **Composable**: KEM (X25519 / X448)、cipher (AES-GCM / ChaCha20-Poly1305)、hash (SHA-256 / SHA-512 / BLAKE2s/b) 三元組可任意組合。
6. **Reference implementations + production deploys** synchronized。

## Method (high-level structure)
**HandshakeState**:
```
ck: ChainingKey (32 byte)
h:  HandshakeHash (32 byte for BLAKE2s, 64 for SHA-512)
re: RemoteEphemeral pk (or empty)
rs: RemoteStatic pk (or empty)
e:  Our ephemeral pair (private, public)
s:  Our static pair (private, public)
cipher_state: CipherState (k, n)
```

**Operations**:
- `MixHash(data)`: h = H(h ‖ data)
- `MixKey(input_key_material)`: (ck, k) = HKDF(ck, input, 2); n = 0
- `EncryptAndHash(plaintext)`: c = AEAD-Enc(k, n, AD=h, plaintext); MixHash(c); return c
- `DecryptAndHash(ciphertext)`: p = AEAD-Dec(k, n, AD=h, ciphertext); MixHash(ciphertext); return p
- `Split()`: derive (k_send, k_recv) = HKDF(ck, empty, 2); return CipherStates

**Pattern execution**:
```
For each token in current message pattern:
    case e: write/read ephemeral_pub; MixHash(e_pub)
    case s: write/read static_pub (encrypted if cipher_state ready); MixHash
    case ee: MixKey(DH(my_eph_priv, remote_eph_pub))
    case es: MixKey(DH(my_eph_priv, remote_static_pub))  // initiator side
    case se: MixKey(DH(my_static_priv, remote_eph_pub))
    case ss: MixKey(DH(my_static_priv, remote_static_pub))
    case psk: MixKeyAndHash(psk)
After all message tokens, write/read payload (encrypted if cipher_state ready)
```

## Results
- **WireGuard (Donenfeld 2017)** 用 Noise IK + MAC1/MAC2 加固。
- **Lightning Network (BOLT-08)** 用 Noise XK。
- **Wire messenger** 用 Noise IK variants。
- **Whisper / Matrix Olm** 受 Noise 設計影響。
- **Noise Explorer (Kobeissi-Bhargavan 2019)** 自動 generate ProVerif models for all 16 patterns + verify 18 security properties → 為 Noise design 提供 formal backing。

## Limitations / what they don't solve
- **沒原生 PQ-KEM support**: spec 假設 DH 是 group element exchange。PQ KEM (Kyber) 結構不同（KEM encapsulate/decapsulate 而非 DH share exchange）；需要 protocol extension (PQNoise, Schwabe 等 2020 提案)。
- **沒原生 PCS / Ratchet 機制**: Noise IK 是 one-shot KE; PCS 需上層 (Double Ratchet) 或 rekey extension。
- **Hard-coded crypto primitives in protocol_name**: 缺 negotiation flexibility（但這是設計選擇，避免 Logjam-style downgrade）。
- **0-RTT replay 處理 minimal**: spec 提到但 implementation 負責。

## How it informs our protocol design
- **Proteus 直接 base on Noise IK**：享受 spec、formally verified、production-grade reference impl。
- **Proteus extends Noise**:
  - Add Kyber768 KEM token (or use ratification-pending PQNoise spec when available)。
  - Add MAC1 / Cookie reply (WireGuard-style)。
  - Add per-N-record DH ratchet (in transport phase, after handshake)。
  - Add Elligator2-disguised ephemeral pk (for cover-traffic plausibility)。

## Open questions
- **PQ KEM 整合 Noise**：PQNoise draft (Schwabe 等 2020) 處於 standardization；具體 token semantics (`ek`, `dk`) 仍 evolving。
- **Group Noise (multi-party)**：spec 限 two-party；group AKE 需另設計（MLS / TreeKEM）。
- **Hybrid signature in Noise**：current spec auth via DH ee/es；signature-based auth 在 spec 邊緣。

## References worth following
- Donenfeld *WireGuard* (NDSS 2017) — Noise IK 最完整 productionization。
- Kobeissi-Nicolas-Bhargavan *Noise Explorer* (EuroS&P 2019) — automated analysis。
- Lipp-Blanchet-Bhargavan *Mechanised WireGuard Proof* (EuroS&P 2019)。
- Schwabe 等 *PQNoise draft* (2020+) — post-quantum extension。
- noiseprotocol.org reference implementations。
