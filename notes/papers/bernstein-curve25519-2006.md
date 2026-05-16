# Curve25519: new Diffie-Hellman speed records
**Venue / Year**: Public Key Cryptography (PKC) 2006
**Authors**: Daniel J. Bernstein
**Read on**: 2026-05-14 (in lesson 3.5)
**Status**: full PDF (`assets/papers/bernstein-curve25519-2006.pdf`)
**One-line**: Bernstein 提出 Curve25519——基於 prime 2^255-19 + Montgomery form 的橢圓曲線，設計為「fast + safe + simple」三贏；2010 年代起取代 NIST P-curves 成為主流 ECC；WireGuard、Signal、TLS 1.3、SSH ed25519、Proteus 全部採用。

## Problem
2006 年的 ECDH 主流是 NIST P-curves (P-256, P-384, P-521)，但有多項設計問題：
- 不是 rigid (constants 來源不透明)。
- 完整 addition 公式 unsafe (special cases ⇒ side-channel)。
- Twist security 弱 (~80-bit)。
- Implementation 容易 timing-leak。

Bernstein 想設計一條 curve 同時：(a) 軟體最快、(b) implementation 不易出錯、(c) twist 與 main curve 都安全、(d) 不依賴隨機 magic constants。

## Contribution
1. **Prime selection 2^255 - 19**:
   - Mersenne-like ⇒ fast reduction via shift + add。
   - 接近 2^255 ⇒ 128-bit security with 32-byte representation。
   - p ≡ 5 (mod 8) ⇒ sqrt computation simpler。
   - Not 2^255 - 1 (factorable; weak)。

2. **Curve equation** (Montgomery form):
   ```
   y² = x³ + 486662 x² + x   (mod 2^255 - 19)
   ```
   - 486662 是 smallest A 使得 (curve order, twist order) 都 8 · prime。
   - A 值是 publicly derivable (smallest satisfying SafeCurves criteria)，**no magic numbers**。

3. **Montgomery ladder for X25519**: x-coordinate-only scalar multiplication; 每 iteration 一個 add + 一個 double; **operation count fixed**, 不依賴 scalar bits。

4. **Clamping**：32-byte scalar `k` 透過清三 bit + 設一 bit 確保 (a) k 是 8 倍數 (avoid cofactor) (b) k ≥ 2^254 (fixed ladder length) (c) k < 2^255 (in scalar field)。

5. **效能 records**: 2006 年 Pentium M ~640k cycles/scalar mul vs NIST P-256 ~10M cycles。10× 改進。

## Method
**Field arithmetic**: 64-bit limbs in radix 2^25.5 (5 + 5 split alternating)；最多 5 limb × 5 limb = 25 multiplications; reduction by mul-by-19。

**Montgomery ladder** (X25519 RFC 7748 變體):
```text
function X25519(k, u):
    k = clamp(k)
    x_1 = u; x_2 = 1; z_2 = 0; x_3 = u; z_3 = 1; swap = 0
    For t = 254 downto 0:
        k_t = bit t of k
        swap = swap XOR k_t
        (x_2, x_3) = cswap(swap, x_2, x_3)
        (z_2, z_3) = cswap(swap, z_2, z_3)
        swap = k_t
        // ladderstep:
        A = x_2 + z_2;  AA = A²
        B = x_2 - z_2;  BB = B²
        E = AA - BB
        C = x_3 + z_3
        D = x_3 - z_3
        DA = D · A
        CB = C · B
        x_3 = (DA + CB)²
        z_3 = x_1 · (DA - CB)²
        x_2 = AA · BB
        z_2 = E · (AA + a24·E)    // a24 = (486662 - 2)/4 = 121665
    cswap(swap, x_2, x_3); cswap(swap, z_2, z_3)
    return x_2 / z_2 mod p
```

`cswap` 是 constant-time conditional swap (用 mask trick)。

## Results
- **RFC 7748 (2016)** 標準化 X25519 + X448。
- **TLS 1.3 (RFC 8446)** Mandatory curve。
- **WireGuard, Signal, SSH, libsodium, BoringSSL, ring** 採用。
- **Web Crypto API** include。
- **Bitcoin Cash, Solana, Cardano** 等 blockchain 用 Curve25519/Ed25519。

## Limitations / what they don't solve
- Quantum-vulnerable (Shor)：必須 PQ hybrid。
- Cofactor 8：某些 protocol（PAKE, ZK）需要 prime-order group → 用 Ristretto255 quotient。
- 不直接給 signature scheme：需另 Ed25519 (Bernstein 等 2011)。

## How it informs our protocol design
- **Proteus key exchange = X25519**：直接採用 RFC 7748 spec。
- **Proteus 不需要 point validation**：Curve25519 設計上每 32-byte 都 valid public key (after twist security analysis)。
- **Proteus 加 PQ hybrid**：X25519 + Kyber768 → post-quantum 過渡。
- **Proteus implementation library**：curve25519-dalek (Rust) 或 libsodium。

## Open questions
- Multi-key X25519 in TLS 1.3 multi-user setting 的 tight bound 仍 active。
- Quantum cost of breaking Curve25519 via Shor 精確 estimate 在 fault-tolerant qubit count 仍 disputed。

## References worth following
- Bernstein-Lange *SafeCurves* — curve evaluation criteria。
- Bernstein 等 *Ed25519 paper* (CHES 2011) — signature scheme on same curve。
- RFC 7748 — IETF spec。
- Hamburg *Decaf* / *Ristretto255 draft* — cofactor elimination。
