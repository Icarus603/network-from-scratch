# QUICstep: Evaluating connection migration based QUIC censorship circumvention
**Venue / Year**: PETS 2026(1) (Proceedings on Privacy Enhancing Technologies)
**Authors**: Pouyan Fotouhi Tehrani, Cecylia Bocovich, Aniket Kate, Tariq Elahi, et al.（具體 author list 從 arxiv 抽取, 細節未完全 verified）
**Read on**: 2026-05-16 (in lesson 8.6, 8.10)
**Status**: arxiv abstract + ResearchGate summary fetched OK. Full PDF 未抓 (待 Part 10 / Part 11 設計時若需要再 deep-read)。
**One-line**: 把 QUIC connection migration 用作 anti-censorship 工具——在加密的 alternate path 上做 handshake (隱藏 SNI), 然後 migrate 到 normal path 跑 data。

## Problem
GFW 2024+ 解 Initial 看 SNI 過濾 (Zohaib 2025)。但 GFW 只看「first few packets of a connection」。若我們把 SNI-sensitive handshake 走別處（例如 encrypted proxy channel），之後 migrate 回 normal path，能否 bypass？

## Contribution
1. **QUICstep technique**: 用 QUIC connection migration 機制（RFC 9000 §9）
   - Phase 1: client 用 encrypted side channel（已有 proxy）做 QUIC handshake
   - Phase 2: 完成 handshake 後 migrate connection 到 normal path
   - Censor 只看到 normal path 上的 1-RTT data, 已加密 + 不再有 Initial → 看不到 SNI
2. **效能評估**: 比起「全程走 encrypted channel」, QUICstep 只在 handshake 階段佔用 encrypted channel 頻寬, 之後走 direct path
3. **量測 connection migration support**: 全球 QUIC server 對 connection migration 支援程度增加中, 但仍有限
4. **威脅模型**: 假設 censor 只看 first few packet, 不做 long-term flow tracking

## Method
- 設計 QUICstep client/server proof-of-concept
- 從 SOCKS5 proxy 走 encrypted channel 做 Initial handshake
- 1-RTT key established 後切換到 direct path
- 量測 throughput, latency, connection migration acceptance rate

## Results
- 在支援 connection migration 的 server（Cloudflare, Google, 部分自架）: QUICstep 成功
- Throughput 顯著高於「全程 encrypted channel」（因為只 handshake 用）
- Encrypted channel provider 流量負擔降低
- 普及度有限：仍多數 server 不支援 connection migration

## Limitations / what they don't solve
- 仍需要 encrypted side channel（即另一個 proxy）→ 不是 standalone
- 假設 censor 不做 long-term flow tracking — 若 GFW 升 Tier 5 ML-based, QUICstep wire image 仍可被識別
- Migration 過程的 packet pattern 可能是 fingerprint
- 沒 formal security analysis 對 「migration 期間 attacker 能做什麼」

## How it informs our protocol design
**Part 8.6 sec 5 referenced + Part 11 設計 candidate**:

- 我們協議**設計必須支援 connection migration**（無論是否用 QUICstep technique）
- 連線移轉本身是 anti-censorship 加分項
- 但**單獨用 QUICstep** 不夠 robust — 它假設 censor stateless, 不適合長期方案
- 跟 MASQUE wire image mimicry 結合可能更強

## Open questions
- Connection migration 在 2026+ 普及度多少？trend up but slow
- Censor 升級到「flow-level tracking」後 QUICstep 失效——時間表？
- Migration 過程本身能否做得 indistinguishable from 「IP 改變」(NAT rebinding)？
- 跨多個 path 的 migration sequence 是否能形成 anti-fingerprint pattern？

## References worth following
- **RFC 9000 §9** Connection Migration normative source
- **Zohaib USENIX Sec 2025** → [precis](./zohaib-quic-sni-2025.md)
- **MASQUE drafts** (RFC 9298/9484) — complementary approach
- **Wails et al. NDSS 2014** "Domain fronting" — 概念上前身
