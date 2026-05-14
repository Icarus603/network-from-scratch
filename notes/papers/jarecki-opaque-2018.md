# OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation Attacks
**Venue / Year**: EUROCRYPT 2018
**Authors**: Stanislaw Jarecki, Hugo Krawczyk, Jiayu Xu
**Read on**: 2026-05-14 (in lesson 3.9)
**Status**: abstract-only（IACR ePrint 2018/163 Cloudflare 阻擋；引用內容綜合自 EUROCRYPT 2018 proceedings + Krawczyk Cloudflare blog series + 訓練資料 + RFC 9807 draft history）
**One-line**: 第一個同時提供「offline dictionary attack resistance」+「pre-computation attack resistance」的 augmented PAKE；server compromise 後 attacker 仍須對每個 candidate password 跟 (compromised) server 互動一次 → 顯著拉高 break cost；2025 RFC 9807 標準化，WhatsApp、1Password 部署。

## Problem
2018 年 augmented PAKE (SRP, AugPAKE) 都 vulnerable to pre-computation attack：
- Server stores password verifier (hash + salt)。
- Attacker compromise server → 取出 verifier。
- 在自己 hardware 用 verifier offline brute-force candidate password。
- 即使 verifier 用 Argon2 memory-hard 加固，sufficient resources (e.g., $10M ASIC farm) 仍可破。

需要：augmented PAKE 使得「即使 server compromise」brute-force 仍要 expensive online interaction per candidate。

## Contribution
1. **OPRF-based password processing**:
   - Server holds OPRF key k_s。
   - Client 對 password 做 blinded query: client 不洩露 password to server，得 F_{k_s}(password) (= PRF output)。
   - F_{k_s}(password) 作為 key 解密 client-side stored "envelope"。
   - Envelope 內含 client static private key + server static public key。
2. **AKE 階段**: 從 envelope 取出的 keys 跑 HMQV (or other AKE)。
3. **安全分析**:
   - **Offline dictionary attack resistance** (基本 PAKE 保證): passive observer 看不到 password 任何 hint。
   - **Pre-computation resistance**: 攻陷 server 後 attacker 取得 (k_s, envelope)。要試 password candidate p_i:
     - 計算 F_{k_s}(p_i)（attacker 自己當 OPRF server，可離線做但每 candidate 一次 expensive OPRF eval）。
     - 用此解密 envelope；驗證 plaintext 結構是否 well-formed。
     - 仍 brute force 但 cost per candidate ≫ 普通 hash brute force。
4. **形式化證明**: in Universal Composability (UC) model + standard ROM assumptions。
5. **變體**: OPAQUE-3DH (default AKE), OPAQUE-HMQV (alternate), OPAQUE-Sigma (sign-based)。

## Method (simplified)
**Registration**:
```text
Client (knows password pw):
    seed ← random
    client_static_priv, client_static_pub = KeyGen(seed)
    blinded = OPRF.Blind(pw)            // random blind r; b = H(pw)^r
    send blinded to server

Server (has OPRF key k_s):
    response = OPRF.Eval(k_s, blinded)   // = b^k_s
    send response back

Client:
    F = OPRF.Unblind(response, r)         // = H(pw)^k_s
    envelope = Enc(F, client_static_priv ‖ server_static_pub)
    send (client_id, envelope) to server

Server stores (client_id, envelope, ...) along with own k_s.
```

**Login**:
```text
Client:
    blinded = OPRF.Blind(pw)
    send (client_id, blinded) to server

Server:
    response = OPRF.Eval(k_s, blinded)
    send (response, envelope, server_eph_pub) to client

Client:
    F = OPRF.Unblind(response, r)
    decrypt envelope using F: get (client_static_priv, server_static_pub)
    Run AKE (HMQV or similar) using (client_static_priv, server_static_pub, ephemeral) ↔ server's (static, eph)
    Derive session key K
    Confirm K via MAC.
```

## Results
- **RFC 9807 (2025) 標準化**.
- **WhatsApp account recovery** (2020+): users recover device using only passphrase, no PKI。
- **1Password Watchtower** (2023+): zero-knowledge proof of password ownership for password breach detection。
- **Cloudflare's Privacy Pass** components (2022+) use OPAQUE-derived primitives。
- **Apple iCloud Keychain Escrow** (2024+) 部分用。
- **IETF CFRG 推 OPAQUE 為 next-gen RADIUS / EAP authentication base**。

## Limitations / what they don't solve
- **Complex spec** (~50 pages of draft); implementation pitfalls 多。
- **OPRF implementation critical**: 必須 constant-time + side-channel-resistant。
- **PQ migration 仍在進行**: 當前用 X25519 + classical OPRF。Kyber-based OPRF + AKE 仍 evolving。
- **Two round trips for login**: vs SPAKE2 的 1.5 RTT。
- **Client-side envelope storage**: 對 stateless client 是負擔（但 server-side 存 envelope 也可，仍 secure）。

## How it informs our protocol design
- **G6 PSK-from-passphrase mode 用 OPAQUE**：替代 simple Argon2(passphrase, salt) PSK derivation。
- **G6 server-side storage protection**: 即使 G6 server 被 hack，passphrase-mode users 仍 safe (modulo online OPRF query cost)。
- **G6 spec 預留 PQ-OPAQUE migration path**: RFC 9807 變動兼容版 (Kyber + OPRF) 將在 v2 採用。
- **G6 不直接用 OPAQUE for primary handshake**: primary mode 是 cert/static-pk (Noise IK)，OPAQUE 是 passphrase mode 的 sub-protocol。

## Open questions
- **PQ-OPAQUE**: 當前 IETF draft 階段；Kyber-based OPRF + Kyber AKE 整合 spec 仍 evolving。
- **Threshold OPAQUE**: t-of-n server setup, 仍 active research。
- **OPAQUE + post-compromise security**: 當前 OPAQUE 給 FS 不給 PCS；如何加 ratchet on top？
- **OPAQUE in lossy networks**: 對 GFW-style network 對手能 selectively drop OPAQUE messages 引發 client retry，是否會 leak info？open。

## References worth following
- Krawczyk *OPAQUE blog series* (Cloudflare 2018-2020) — accessible introduction。
- RFC 9807 — 標準化 spec。
- Beguinet 等 *PQ-PAKE adaptation* (2023) — post-quantum direction。
- opaque-ke Rust crate (Facebook open source) — reference impl。
- WhatsApp account recovery whitepaper (2020+)。
