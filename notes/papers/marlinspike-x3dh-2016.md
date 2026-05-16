# The X3DH Key Agreement Protocol
**Venue / Year**: Signal whitepaper, 2016（rev 1.0）
**Authors**: Moxie Marlinspike, Trevor Perrin
**Read on**: 2026-05-14 (in lesson 3.6)
**Status**: full PDF (`assets/papers/marlinspike-x3dh-2016.pdf`)
**One-line**: Signal Messenger 的 asynchronous AKE 設計——透過 4 個 DH 結合長期 + 預發布 prekey + ephemeral 達到 Alice 對線下 Bob 仍能加密發訊；後接 Double Ratchet 提供 PCS；現代 secure messaging 標準。

## Problem
TLS-style synchronous AKE 假設雙方同時在線：Alice send g^a → Bob send g^b → shared secret。但 messaging app (Signal, WhatsApp, Messenger) 要求 asynchronous：Alice 想送訊息給 currently offline 的 Bob。需要 Bob **預先**部署足夠 key material 讓 Alice 能單方面 derive shared secret。

## Contribution
1. **Pre-key 模型**：Bob 預先發布到 Signal server：
   - **Identity Key IK_B**：long-term Ed25519 (signed pre-key 上的 signing key)。
   - **Signed Pre-Key SPK_B**：X25519, rotated weekly, signed by IK_B。
   - **One-Time Pre-Keys [OPK_B_1, ...]**：X25519, consumed once each, batch ~100。
2. **Four-DH combine**：Alice 對 4 個 DH 結果 KDF combine：
   ```text
   DH1 = DH(IK_A, SPK_B)       // long-long auth
   DH2 = DH(EK_A, IK_B)        // eph-long, mutual
   DH3 = DH(EK_A, SPK_B)       // eph-signed-prekey
   DH4 = DH(EK_A, OPK_B)       // eph-one-time → PCS seed
   SK = KDF(DH1 ‖ DH2 ‖ DH3 ‖ DH4)
   ```
3. **Security goals**:
   - **Mutual authentication**: DH1 binds identities。
   - **Forward Secrecy**: ephemeral EK_A + ephemeral-side prekeys deleted after use。
   - **Asynchronicity**: Bob does not need to be online。
   - **Deniability**: signature only on SPK (not on individual messages) → Alice can claim "didn't send" with plausible deniability。
4. **Selfie attack mitigation** (added later, Cremers 2019)：identifier binding into KDF info string。

## Method
**Bob 預發**:
```text
upload to server:
    (IK_B_pub, SPK_B_pub, Sig_IK_B(SPK_B), [OPK_B_1_pub, OPK_B_2_pub, ...])
```

**Alice send**:
```text
1. Fetch Bob's bundle (IK_B, SPK_B, sig, OPK_B_j) from server.
2. Verify sig.
3. Generate ephemeral EK_A (X25519).
4. Compute DH1..DH4, SK.
5. AD = encode(IK_A_pub) ‖ encode(IK_B_pub)    // associated data
6. ciphertext = AEAD(SK, message, AD)
7. Send (IK_A_pub, EK_A_pub, OPK_index, ciphertext) to Bob (via server).
8. Initialize Double Ratchet with SK as root key.
```

**Bob receive** (whenever online):
```text
1. Lookup OPK_B private by index.
2. Compute same DH1..DH4 from his side.
3. Derive SK; decrypt message; init Double Ratchet。
4. Delete used OPK_B private (consumed)。
```

## Results
- **Signal Protocol** core protocol; deployed in Signal, WhatsApp (1B+ users), Facebook Messenger secret conversations, Skype Private, Wire。
- **MLS (RFC 9420)** for groups 借鑑 X3DH 概念。
- **Formal proof** (Cohn-Gordon-Cremers-Dowling-Garratt-Stebila EuroS&P 2017)。

## Limitations / what they don't solve
- **OPK exhaustion**: one-time prekey 用完後，protocol falls back to 3-DH (no DH4) → weaker PCS。需要 client 持續上傳新 OPK。
- **Trust server for prekey integrity**: 雖然 SPK 有 sig，server 仍可選擇性給 prekey (e.g., consistently 給 attacker prekey)。Signal 用 "Safety Numbers" (fingerprint comparison) 給 out-of-band 驗證。
- **Selfie attack (Cremers 2019)**：multi-device 同 user 場景下，attacker 可讓 device 跟自己對話。Spec 1.1 修補。
- **No quantum resistance**：DH 全 X25519, Shor 可破。Signal PQ-XDH (2023+) 加 Kyber768 hybrid。

## How it informs our protocol design
- **Proteus 不是 messaging 但 borrowing 兩個 idea**:
  1. **Multiple-DH combine** for robustness：Proteus hybrid X25519 + Kyber768 + (optional PSK) 結合 multiple DH→ KDF。
  2. **Identifier binding in KDF info**: Proteus transcript hash + KDF info 必含 client_id + server_id + protocol_version。
- **Proteus 不用 prekey 模型**：Proteus 是 synchronous proxy（client 連 server 時 server 在線）。
- **PCS 機制**：Proteus 借鑑 Double Ratchet 思想（後續 lesson 詳述），per-N-record DH ratchet 達粗粒度 PCS。

## Open questions
- PCS in stateless protocols (0-RTT) 仍 open。
- PQ X3DH 設計 (Signal PQXDH 2023) 的 formal verification 仍 active。
- Group X3DH (multi-recipient) 的 efficient async 設計仍 evolving。

## References worth following
- Marlinspike, Perrin *Double Ratchet Algorithm* (Signal whitepaper) — 與 X3DH 配套。
- Cohn-Gordon 等 *Formal Security Analysis of Signal* (EuroS&P 2017)。
- Kret 等 *Signal PQXDH spec* (2023) — quantum-resistant X3DH。
- Cremers 等 *Selfie attack on Signal X3DH* (2019)。
