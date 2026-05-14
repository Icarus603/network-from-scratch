# Cryptographic Extraction and Key Derivation: The HKDF Scheme
**Venue / Year**: CRYPTO 2010
**Authors**: Hugo Krawczyk
**Read on**: 2026-05-14 (in lesson 3.3)
**Status**: abstract-only（IACR ePrint 2010/264 Cloudflare 阻擋；引用內容綜合自 Springer abstract、RFC 5869 spec、訓練資料）。
**One-line**: HKDF 的學術源頭——把 KDF 形式化為「Extract（從 high-entropy 但 biased source 推 PRK）+ Expand（從 PRK 推 arbitrary-length keystream）」兩段；證明若 underlying HMAC 是 dual-PRF，HKDF 是 secure KDF；TLS 1.3 / Noise / Signal / WireGuard 的 KDF 共同祖先。

## Problem
2010 年之前 KDF 設計都 *ad hoc*：TLS 1.0 的 PRF（基於 HMAC-MD5 + HMAC-SHA1）、TLS 1.2 的 PRF（HMAC-SHA256）、IKE 的 prf 函數，每個 protocol 各自設計。沒有 unified theory 說明：
1. 從 raw shared secret（DH output、ECDH point）推 working keys 的正確方法是什麼？
2. 為什麼必須兩段（Extract + Expand）而非一段直接 hash？
3. 在 PRF 假設下能證明什麼安全性？

## Contribution
1. **Two-step KDF 形式化**：
   - **Extract**: PRK = HMAC(salt, IKM)。把 IKM (input keying material) 的 min-entropy 集中到 fixed-size PRK，statistical close to uniform。
   - **Expand**: OKM = HKDF-Expand(PRK, info, L)。從 PRK 透過 HMAC chain 產生長 L bytes output。
2. **安全性證明**（兩個獨立性質）：
   - PRK 對對手 statistical close to uniform，前提是 IKM 有 sufficient min-entropy 且 salt is known but possibly known to attacker。
   - OKM 是 PRF function of (info)，前提是 HMAC PRF。
3. **Salt 的精細處理**：salt 可以是 zero（無 salt）、可以是 known to adversary、可以 vary across instances；論文證明 salt 即使 known 仍 secure（只要 IKM 有 entropy）。
4. **Info 的 domain separation**：不同 (info) 推不同 keys without correlation；TLS 1.3 用 "tls13 c hs traffic" / "tls13 s ap traffic" 等 distinct labels 達 KDF context separation。

## Method
HKDF spec（簡化版）：
```text
HKDF-Extract(salt, IKM):
    PRK = HMAC(key=salt, msg=IKM)    // 如果 salt empty 用 0^hash_len
    return PRK    // length = hash output length

HKDF-Expand(PRK, info, L):
    N = ⌈L / hash_len⌉
    T(0) = empty
    For i = 1..N:
        T(i) = HMAC(key=PRK, msg = T(i-1) ‖ info ‖ i_byte)
    OKM = T(1) ‖ T(2) ‖ ... ‖ T(N)
    return first L bytes of OKM
```

**為什麼必須兩段**：
- 一段（直接 H(IKM ‖ info)）的問題：IKM biased ⇒ H(IKM ‖ info) 不 uniform。
- Extract 步驟是 randomness extractor（per Leftover Hash Lemma）；Expand 步驟是 PRG。
- 分離兩責任 → easier proof + flexible design。

## Results
- **RFC 5869 (2010)** 標準化 HKDF。
- **TLS 1.3 (RFC 8446)** §7.1 全用 HKDF-Extract / HKDF-Expand-Label derive 所有 working keys。
- **Noise Protocol Framework** 用 HKDF 在 MixKey / MixHash 內部。
- **Signal Double Ratchet**：KDF_RK / KDF_CK 都是 HKDF 變體。
- **WireGuard**：noise-helpers.go 的 hkdf() 函數實作。
- **HPKE (RFC 9180)** Hybrid Public Key Encryption 內部用 HKDF。

## Limitations / what they don't solve
- 假設 underlying HMAC 是 PRF；若 H 出了問題（e.g. SHA-1 collision after 2017）整個 HKDF 受影響。
- 不處理 password-based KDF（low-entropy input）；那是 PBKDF2 / Argon2 領域。
- Multi-context derivation 的 tight bound 仍 active。

## How it informs our protocol design
- **G6 用 HKDF-SHA-256 全 derive**：所有 record-layer key、handshake-layer key、ratchet seed 都從 master secret 透過 HKDF-Expand-Label 推。
- **G6 的 info string**：強制含 protocol version + role + purpose（"g6 v1 client record key"），給 future 升級保留空間且避免 cross-context confusion。
- **G6 的 salt 用法**：handshake transcript hash 作為 salt 餵 Extract，把握手歷史綁進所有後續 keys（防 transcript collision attack, Bhargavan-Leurent NDSS 2016）。

## Open questions
- 在 quantum random oracle model 下 HKDF 仍 secure？需要 Q-PRF 假設。
- 多 context (>10^6 distinct info) 的 tight bound？
- HKDF over post-quantum hash（如 SHA-3）的 concrete bound 仍 active。

## References worth following
- RFC 5869 — HKDF spec。
- Bellare *New Proofs for NMAC and HMAC: Security without Collision-Resistance* (CRYPTO 2006) — HMAC PRF 證明。
- Dodis, Gennaro, Håstad, Krawczyk, Rabin *Randomness Extraction and Key Derivation Using the CBC, Cascade and HMAC Modes* (CRYPTO 2004) — KDF extractor 理論。
- RFC 9180 — HPKE 用 HKDF 的 productionized example。
