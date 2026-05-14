# Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice
**Venue / Year**: ACM CCS 2015（Best Paper Award）
**Authors**: David Adrian, Karthikeyan Bhargavan, Zakir Durumeric, Pierrick Gaudry, Matthew Green, J. Alex Halderman, Nadia Heninger, Drew Springall, Emmanuel Thomé, Luke Valenta, Benjamin VanderSloot, Eric Wustrow, Santiago Zanella-Béguelin, Paul Zimmermann
**Read on**: 2026-05-14 (in lesson 4.1)
**Status**: HTML 與 weakdh.org overview 完整；PDF 已下載到 `assets/papers/` 但 WebFetch 不易解析 PDF binary，內容以 site overview 為主
**One-line**: 1024-bit 共享 DH prime 對 state-level adversary 是可預算的 NFS target；export-grade DH 對 academic team 已即時可破——FS 不是免費的，DH 參數選擇是設計決策。

## Problem
- TLS 1.2 仍允許 export-grade（512-bit）DH ciphersuites 被 negotiate
- 即使 client/server 都不主動選 export，**active MITM 可以 downgrade** 把 ServerKeyExchange 改成 512-bit
- 真實 Internet 上絕大多數 server 共用同一個 DH prime（OpenSSL default、Apache default 等），導致一次 number field sieve (NFS) 預算可以重用攻擊整個 share

## Contribution
1. **Logjam attack**：MITM 對 TLS 進行版本 + ciphersuite downgrade，把 client 的 DHE 換成 DHE_EXPORT，server 回 512-bit prime，attacker 用預算好的 NFS table 即時破解 session key
2. **Internet-scale measurement**：直接掃 IPv4 + Top 1M Alexa，量化 vulnerable share（8.4% Top 1M 對直接 downgrade 易受）
3. **Cost analysis**：512-bit DH NFS 在學界硬體下 → 數天；1024-bit DH NFS 估算 state-level（NSA-budget）→ 一年一個 prime；最常見 1024-bit prime 一旦 broken，passive decrypt **18% Top 1M HTTPS** + 大量 VPN / SSH
4. **Snowden 連結**：論文推測 NSA 已對最常見 1024-bit DH 完成 NFS 預算，配合被動截獲解密大量歷史 traffic

## Method (just enough to reproduce mentally)
- TLS 1.2 ClientHello 列出 DHE_RSA_*；MITM 改 ServerHello 選 DHE_EXPORT_RSA + 改 ServerKeyExchange 為 512-bit prime
- TLS 1.2 把 ServerKeyExchange 簽進 server cert，但**沒簽 ciphersuite**（FREAK / Logjam 兩條路）→ 簽章不爆但 client 接受 512-bit prime
- Client/Server 完成 handshake，attacker 用預計算 NFS solve 512-bit discrete log（離線數分鐘）取 master secret → 解密 record

## Results
- 80% 支援 export ciphers 的 server 都用同一個 512-bit prime（=> 一次預算打全網）
- 8.4% Top 1M vulnerable to direct downgrade（2015 disclosure 時）
- 估算 NSA 級 adversary 對最常見 1024-bit prime 完成 NFS 後可被動解 ~18% Top 1M HTTPS
- 同時導致 OpenSSH、IKE/IPsec VPN（VPN 老 1024-bit DH group 1, 2, 5）大量 server 暴露

## Limitations / what they don't solve
- 攻擊不適用於 ECDHE（小參數空間，每個 group 對應特定 prime 與點，無「共用 prime」概念）→ TLS 1.3 強制 named groups + ECDHE 為主
- 對 forward-secret 但用「正常 size 一次性」DH 的 implementation 無效
- NFS 預算估算用的是 2015 硬體，量子計算不在範圍

## How it informs our protocol design
- 我們的協議只用 ECDHE（X25519/P-256），並把 group 列入 transcript bound 範圍（Part 4.3）
- 「export-grade backwards compatibility」這種 fallback **不存在**——任何「downgrade for compat」設計直接斃掉
- 我們的協議要對 state-level adversary 假設 1024-bit DH 已破，且部分 NIST curve 被預算過 trapdoor（Bernstein-Lange 2014）

## Open questions
- Logjam 之後仍有的開放問題：如何形式化「共享 prime 的攻擊複雜度攤提」？目前 economic-security model 散見於 systems paper
- Post-quantum 時代是否會重演？X25519MLKEM768 hybrid 是否同樣脆弱於「common implementation 預算」？

## References worth following
- Bhargavan, Leurent. *Transcript Collision Attacks: Breaking Authentication in TLS, IKE and SSH (SLOTH)*. NDSS 2016
- Bhargavan et al. *Downgrade Resilience in Key-Exchange Protocols*. S&P 2016 — Logjam 之後的形式化 framework
- Heninger 後續 work：mass DH 量測

---

**用於課程**：Part 4.1（TLS 死亡史）、Part 9（GFW 對 DH-based VPN 的觀察）、Part 11.5（為何我們不允許 fallback）
