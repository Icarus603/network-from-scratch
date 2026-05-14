# On Post-Compromise Security
**Venue / Year**: IEEE Computer Security Foundations Symposium (CSF) 2016（extended version IACR ePrint 2016/221）
**Authors**: Katriel Cohn-Gordon, Cas Cremers, Luke Garratt
**Read on**: 2026-05-14 (in lesson 3.1)
**Status**: full PDF (`assets/papers/cohn-gordon-pcs-2016.pdf`)
**One-line**: 第一篇給「對手已經拿到你的長期金鑰，但你之後仍能恢復安全」這件事下 formal definition 的論文——把 Signal 雙重 ratchet 的直覺安全性 productize 成可證明的 game model；定義 weak vs total compromise 與 PCS 的精確邊界。

## Problem
2014-2015 年 Signal 的 Double Ratchet（Marlinspike & Perrin 2014）開始被廣泛部署（Signal、WhatsApp、Facebook Messenger），其核心宣稱是「即使長期金鑰外洩，未來訊息仍安全」。但這個宣稱在學術上**沒有 formal definition**——folklore 認為「LTK 一旦外洩，對手能永遠假冒」，與 Signal 的實務宣稱矛盾。需要一個 formal framework 解決矛盾。

## Contribution
1. **Post-Compromise Security (PCS) 的 informal + formal 定義**：
   - **Informal**：Alice 對「跟 Bob 通訊的安全」有保證，**即使** Bob 的 secrets 已被 compromise。
   - **Formal**：在 AKE security model 中加入 corruption oracle 與 healing 機制；證明若 corruption 後存在 honest interaction，subsequent session 安全。
2. **區分 Weak vs Total Compromise**：
   - **Weak**：對手暫時控制 LTK 操作（HSM 暫時被劫持），但**沒**取走 LTK 本身。Recovery 後仍 PCS。
   - **Total**：對手實際取得 LTK material。Recovery 需要 fresh secret（DH ratchet）。
3. **兩個 AKE security model**：
   - 一個處理 weak compromise + HSM。
   - 一個處理 total compromise + key update protocols。
4. **兩個具體 protocol construction** + 安全性證明。
5. **TLS 1.3 早期 draft 的 PCS critique**：指出某 TLS 1.3 提案不滿足 weak PCS。

## Method (just enough to reproduce mentally)
**核心觀察**：Folklore 的「LTK 外洩 ⇒ 對手永遠假冒」假設對手是 **持續 active**——對手實時跟 Bob 講話，假冒 Bob 對 Alice。但若對手只是**錄下 LTK 然後離開**，且 Alice 跟 Bob 之間有後續 honest interaction（例如 ratchet step），則：

- Bob 用 fresh ephemeral DH 跟 Alice 換新 key K'。
- 對手不在通道上，看不到這個 exchange。
- K' 跟 LTK 無關（pure DH，依賴 fresh ephemeral）。
- 之後 K' 加密的訊息，對手解不開——**healed**。

**形式化的關鍵**：定義一個 freshness predicate，限定哪些 session 對 corrupted party 仍 secure。具體地：

```text
Session π is post-compromise secure iff:
    (1) Π is initiated AFTER corruption time t_c, AND
    (2) Between t_c and π start, parties performed at least one
        honest key-update interaction, AND
    (3) The honest key-update was NOT observable / influenceable
        by adversary (active adversary may break PCS).
```

PCS 故意排除「對手持續 active 在通道」的 case——那叫 Active Persistent Adversary，無解。PCS 處理「snatch-and-run」對手（一次性 compromise + 之後離開）。

## Results
- Signal Double Ratchet 的學術背書——Cohn-Gordon-Cremers-Dowling-Garratt-Stebila *Formal Security Analysis of Signal* (EuroS&P 2017) 直接用本框架。
- 影響 TLS 1.3 final spec：post-handshake key update 機制的設計考量。
- WireGuard 的 rekey-after-time / rekey-after-messages 是 PCS 的粗粒度版本。
- 影響 MLS (Messaging Layer Security, RFC 9420) 的 group key agreement 設計。

## Limitations / what they don't solve
- 假設 corruption 是 distinct event，沒處理 continuous low-level compromise（malware）。
- 對 stateless protocols（QUIC 0-RTT）PCS 難以達成——0-RTT data 缺 ratchet 機會。
- 量子對手下 PCS 仍 open。

## How it informs our protocol design
- **G6 必須有 ratchet 機制**：每 N 個 record 或每 T 秒，ephemeral DH 換一次 session key。
- **G6 spec 寫 PCS 假設**：明確聲明「對手 snatch-and-run、後續無 active presence」是 PCS 達成的前提。
- **G6 0-RTT data 不享 PCS**：spec 內明確標示 0-RTT segment 為 reduced-security，且只允許 idempotent payload。

## Open questions
- 「持續部分 corruption」（malware on device）下的 PCS 仍 open。
- Quantum-PCS：對手量子算力 + LTK 取得，PCS 是否仍可達？Bos 等 2024 工作仍 active。
- Group setting：MLS 的 group PCS 在 100k+ group 下的效能/安全 tradeoff。

## References worth following
- Cohn-Gordon, Cremers, Dowling, Garratt, Stebila *A Formal Security Analysis of the Signal Messaging Protocol* (EuroS&P 2017) — Signal Double Ratchet 完整證明。
- Marlinspike, Perrin *The Double Ratchet Algorithm* (Signal whitepaper 2016) — DR 演算法 spec。
- Alwen, Coretti, Dodis *The Double Ratchet: Security Notions, Proofs, and Modularization for the Signal Protocol* (EUROCRYPT 2019) — 更精細的 PCS 變體。
- Barnes et al. *RFC 9420: The Messaging Layer Security (MLS) Protocol* (IETF 2023) — group PCS 的 productionized spec。
