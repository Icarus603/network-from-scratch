# HMQV: A High-Performance Secure Diffie-Hellman Protocol
**Venue / Year**: CRYPTO 2005
**Authors**: Hugo Krawczyk
**Read on**: 2026-05-14 (in lesson 3.6)
**Status**: abstract-only（IACR ePrint 2005/176 Cloudflare 阻擋；引用內容綜合自 CRYPTO 2005 proceedings + Springer abstract + 訓練資料）
**One-line**: 把 MQV (Menezes-Qu-Vanstone 1995) implicit-authentication DH 加 hash 形成 HMQV，給出第一個 formal proof in CK model；安全屬性含 FS, KCI-resistance, UKS-resistance；但因 SIGMA 結構更模組化 + Krawczyk 自己後續推 SIGMA，HMQV 未成主流。

## Problem
MQV 1995 是 implicit-authentication AKE：兩端用 long-term key + ephemeral key 結合 compute shared secret，不需 signature 也達認證。優勢：short message (no signature)、fast。缺點：原 MQV (a) UKS-vulnerable in specific scenarios (Kaliski 2001); (b) 缺 formal proof in modern AKE security model。

## Contribution
1. **HMQV 設計**：對 X = xG, Y = yG, identity keys A = aG, B = bG，定義：
   ```text
   sigma_A = (Y · B^e)^(x + d·a)   where e = H(Y, B_id), d = H(X, A_id)
   sigma_B = (X · A^d)^(y + e·b)
   shared K = sigma_A = sigma_B = (x + da)(y + eb) · G
   ```
   d, e 是 「short hash」(half-length of curve order)，hash 把 ephemeral 與 long-term 綁起來，防 UKS。
2. **Formal proof in CK model**: 證明 HMQV 在 CDH assumption 下達到 mutual authentication + FS + KCI + UKS resistance。
3. **效能**：~1.5 scalar multiplications per side（multi-scalar mul），比 SIGMA 的 sign+verify+DH 快。
4. **影響後續 AKE**：HMQV 證明結構是 modern AKE proof 的範本。

## Method (high-level)
**Setup**: prime-order group, base G, identity keys A = aG, B = bG。

**Protocol**:
```text
A: ephemeral x; X = xG; send X
B: ephemeral y; Y = yG; send Y

both compute:
    d = H(X, B_id)
    e = H(Y, A_id)
    A's view: σ = (Y + e·B)·(x + d·a)
    B's view: σ = (X + d·A)·(y + e·b)
    K = KDF(σ)
```

注意：每方需要 own long-term + ephemeral secrets + 對方 long-term + ephemeral publics。

**安全性 (草稿)**:
- FS: 若 a 之後洩，過去 session 用 x + da scalar 算 σ；x 在 honest party 已刪除，對手不能 recompute σ。
- KCI: 對手知 a 不能假冒 B 對 A，因 σ 需要 b。
- UKS: identity 進 hash d, e 中，對手不能讓兩端對同 session 認不同 ID。

## Results
- **NSA Suite B (2005-2018)** 將 MQV-family 列為 candidate (但實際選 ECDH + ECDSA)。
- **IEEE P1363 標準化** MQV / HMQV variants。
- **TLS 沒採用**：因 SIGMA 結構與 X.509 signature-based PKI 更天然合。
- **TPM / 部分企業 secure messaging** 用 HMQV。

## Limitations / what they don't solve
- **缺 identity protection**: identity 進 hash 但 wire 上 ID 仍可能 visible（取決於實作）。SIGMA-I 透過 encrypted ID 達 identity protection。
- **No PCS**: 單純 HMQV 不提供 PCS；要 PCS 需加 ratchet。
- **Patent 顧慮**: MQV 早期 Certicom patents 拖部署。HMQV 1990s 早期 patents 已到期但 ecosystem 已選 SIGMA。
- **Single-DH 結構**: implicit auth 來自 ephemeral × long-term cross product；若 long-term key 弱（small a）或 ephemeral RNG 不好，整體崩。

## How it informs our protocol design
- **Proteus 不選 HMQV**：選 SIGMA-I 結構（與 TLS 1.3 / Noise IK / WireGuard 對齊）。理由：
  - SIGMA 與 PKI / X.509 cert 自然合。
  - SIGMA 透明易理解，formal verification 工具支援度高（Tamarin model 多）。
  - HMQV implicit auth 對 protocol developer 較 counterintuitive。
- **Proteus 借鑑 HMQV 的 e/d hash binding 思想**：transcript hash 必綁 ephemeral + identity，避免 UKS / cross-protocol。

## Open questions
- Multi-message HMQV variants 在 post-quantum setting 的 generalization 仍 open。
- HMQV-style implicit auth 是否能與 PQ KEM (Kyber) clean 整合？

## References worth following
- Menezes-Qu-Vanstone *MQV: Some New Key Agreement Protocols* (SAC 1995) — original MQV。
- Kaliski 2001 *MQV revisited* — UKS critique。
- Krawczyk *SIGMA paper* (CRYPTO 2003) — author 自己的 SIGMA 設計。
- Boyd-Mathuria-Stebila *AKE textbook* — HMQV 章節 modern treatment。
