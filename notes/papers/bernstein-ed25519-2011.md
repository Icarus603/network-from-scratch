# High-speed high-security signatures (Ed25519)
**Venue / Year**: CHES 2011（journal 版 Journal of Cryptographic Engineering 2012）
**Authors**: Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter Schwabe, Bo-Yin Yang
**Read on**: 2026-05-14 (in lesson 3.5)
**Status**: full PDF (`assets/papers/bernstein-ed25519-2012.pdf`)
**One-line**: 把 Curve25519 改寫成 Edwards form 加 SHA-512 hash 構造 deterministic Schnorr-style signature——sUF-CMA secure、無 RNG 依賴、64-byte signature、~50k cycle sign + ~140k cycle verify；徹底取代 ECDSA 在 modern protocol 的地位。

## Problem
2010 年代主流數位簽章是 ECDSA (FIPS 186)。問題：
1. **Nonce-dependent**: 每簽一次需要 fresh random k。一旦 k 重用或 biased → 全 private key 洩 (PS3 2010 災難; Sony BMG; multiple Android Bitcoin wallets 2013)。
2. **Not sUF-CMA**: (r, s) 與 (r, -s mod n) 都 valid → signature malleability → Bitcoin BIP-66 修補。
3. **Implementation tricky**: scalar inversion、point validation、constant-time scalar mul 都易出錯。
4. **NIST P-curves issues**: 見 Bernstein-Lange SafeCurves critique。

需要一個 signature scheme: deterministic、sUF-CMA、簡單實作、與 Curve25519 同 base curve。

## Contribution
1. **Edwards-form Curve25519 (edwards25519)**: -x² + y² = 1 + (-121665/121666) x² y² mod 2^255-19。同 prime, 同 group, 不同 representation。Edwards form 用 unified addition formula → 簡化 implementation 且 constant-time。
2. **Schnorr-style signature with deterministic nonce**:
   ```text
   r = SHA-512(prefix ‖ M) mod ℓ   // deterministic!
   ```
   其中 prefix 是從 sk 派生的 secret bytes。**不需 RNG**。
3. **sUF-CMA secure**: canonical encoding + deterministic 確保 unique (M, σ) 對。
4. **效能**:
   - Sign ~50k-80k cycles (Skylake)
   - Verify ~140k-210k cycles
   - Batch verify ~2-3× per signature speedup
5. **64-byte signature, 32-byte public key**: vs RSA-2048 (256 byte each) 8× saving。

## Method
**KGen**:
```text
sk ← 32 random bytes
h = SHA-512(sk)              // 64 bytes
s = clamp(h[0:32])            // scalar, low 3 bits cleared, high bit set
prefix = h[32:64]
A = s · B                     // B = base point
pk = encode(A)                // 32 byte compressed
```

**Sign(sk, M)**:
```text
h = SHA-512(sk); s = clamp(h[0:32]); prefix = h[32:64]; A = encode(s·B)
r = SHA-512(prefix ‖ M) mod ℓ          // ℓ = curve order ~ 2^252
R = r · B
k = SHA-512(encode(R) ‖ A ‖ M) mod ℓ
S = (r + k · s) mod ℓ
σ = encode(R) ‖ encode(S)              // 64 bytes
```

**Verify(pk, M, σ)**:
```text
parse σ → R, S; A = decode(pk)
k = SHA-512(encode(R) ‖ encode(A) ‖ M) mod ℓ
check S · B == R + k · A
```

**為什麼 deterministic nonce 不洩 sk**：
- r 從 (prefix, M) 確定性派生；prefix 是 SHA-512(sk) 的後 32 byte，**對 sk 而言不可 invert**（hash one-way）。
- 同 (sk, M) 永遠給同 σ → 沒有 "nonce reuse with different M" 風險（因為對同 sk 不同 M 給不同 r）。
- 對手即使能讓 signer 簽相同 M 多次，也不能 leak 任何 sk info。

**對比 ECDSA**:
- ECDSA: s = k^-1 (H(M) + r·sk) mod n; r = (k·G).x。對手知 (M, σ) 與 k → 解 sk = (s·k - H(M))/r。
- 若兩次簽 M_1, M_2 用同 k: 兩方程 → 解 (k, sk)。
- EdDSA: 無 k；s = r + k·sk where r 是 hash output。對手知 σ 不能反推 (r, k·s) 分量。

**形式化證明**: 在 ROM 下 EUF-CMA-secure under ECDLP assumption (proof via forking lemma)。Bellare-Neven 2006 後續 patch + tightness 改進。

## Results
- **RFC 8032 (2017)** 標準化 EdDSA (Ed25519 + Ed448 + variants Ed25519ph/ctx)。
- **OpenSSH 6.5+ (2014)** 採用。
- **TLS 1.3 (RFC 8446)** 列為標準 signature algorithm `ed25519`。
- **WireGuard, Signal, Tor, Solana, Cardano, Tezos** 採用。
- **NIST FIPS 186-5 (2023)** 終於 include EdDSA (10 年後！)。

## Limitations / what they don't solve
- Quantum-vulnerable (Shor)。需 PQ hybrid。
- **Cofactor 8 issue**: 嚴格上 (M, σ) 對唯一 modulo cofactor，cofactor multiplier 不同 byte 表示同 abstract sig。Ed25519 spec 用 canonical encoding 防 trivially malleable bytes，但 protocol designer 仍須注意（CCTV-style protocol 用 Ristretto 更乾淨）。
- **No identity protection**: pk 在 sig 中可被 derive；G6 在 handshake 用 SIGMA-I 結構 encrypt pk。

## How it informs our protocol design
- **G6 簽章 = Ed25519**：deterministic、sUF-CMA、small、fast。
- **G6 hybrid with ML-DSA-65 (Dilithium)**: PQ 過渡。
- **G6 transcript signing**: sign hash of (sk side handshake transcript)，按 SIGMA-I 結構。
- **G6 不依賴 RNG for signing**：EdDSA deterministic → reduce one RNG dependency。

## Open questions
- Multi-user EdDSA tight bound (Bellare-Davis-Günther 2020 framework) 仍 evolving。
- Lattice-based Schnorr-like signatures (CRYSTALS-Dilithium) 在 hash design 上是否能借鑑 EdDSA 經驗？

## References worth following
- Bernstein 2007 prelim — early Ed25519 design notes。
- Bernstein-Josefsson-Lange-Schwabe-Yang *EdDSA for more curves* (eprint 2015/677)。
- RFC 8032 — IETF EdDSA spec。
- Brendel-Cremers-Jackson-Zhao *The Provable Security of Ed25519: Theory and Practice* (IEEE S&P 2021) — modern formal analysis。
