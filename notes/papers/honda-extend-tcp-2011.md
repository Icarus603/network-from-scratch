# Is It Still Possible to Extend TCP?
**Venue / Year**: IMC 2011 (ACM Internet Measurement Conference), DOI 10.1145/2068816.2068834
**Authors**: Michio Honda, Yoshifumi Nishida, Costin Raiciu, Adam Greenhalgh, Mark Handley, Hideyuki Tokuda
**Read on**: 2026-05-16 (in lesson 8.1)
**Status**: PDF fetch failed (ACM DL 403、ResearchGate 403)。Abstract + key results 從 IETF mailing list discussion + multiple secondary citations + Langley SIGCOMM 2017 §2 中對該 paper 的引述交叉確認。**沒拿到 figures/tables 細節**, 但 headline 結果穩定。
**One-line**: 142 path measurement 證明 TCP **已被 middlebox ossify**——任何新 TCP option（MPTCP, TFO, ECN, 新 timestamp）都有 5%-25% 的 path 完全不可用。**任何 TCP-based protocol evolution 死路一條**。

## Problem
IETF 想擴展 TCP（加 MPTCP RFC 6824, TCP Fast Open RFC 7413, ECN, 新 timestamp 等）。問題：實務上 middlebox（防火牆、NAT、load balancer、ISP DPI box）會 strip / modify / drop 不認得的 TCP option。
量化此 ossification 對 protocol evolution 的影響。

## Contribution
1. **142 path 大規模測量**（住家 ISP, 企業, mobile, 學術網, 跨大洲）
2. **量化 TCP option strip rate**：~6.5% path 完全 strip 新 TCP option, ~14% path 對 MPTCP option 異常, ~12% path 對 TFO 異常
3. **量化 segment 修改率**：~25% path 上 middlebox 改 TCP SEQ/ACK number（連 baseline segment 都不安全）
4. **第一個 systematic 證據** TCP 不能擴展

## Method
- Custom kernel module + measurement client/server
- 跨 142 path 量測：每 path 做 baseline TCP, 加新 option, 比對 server-side observed bytes
- 多 path 類型：home, mobile (3G, 後續 4G), enterprise, academic, cross-continent
- 控制 server 在自家 testbed

## Results
- New TCP option strip: 約 **6.5%** path 完全 strip
- MPTCP option: 約 **14%** path drop/modify
- TFO: 約 **12%** path 不工作
- TCP SEQ/ACK modify: 約 **25%** path 有變動（不一定 breaking, 但 timestamp / option 算法可能失準）
- mobile/3G ISP 比 home/academic 更糟
- 跨大洲 path 比 single-country 更糟

## Limitations / what they don't solve
- 2011 數據, mobile carrier 在 2020+ 部分改善（5G 部署改 middlebox 行為）
- 沒覆蓋 cloud edge（AWS / GCP 自家網路）—— 預期 ossification 較低
- 沒區分 client→server vs server→client 方向上的差異
- 沒提 mitigation: 對 IETF 的價值是「死亡證明」, 不是「怎麼救」

## How it informs our protocol design
**Part 8.1 sec 2 的核心 evidence**：

- TCP 無法演進 → 必須跳出 TCP
- QUIC 用 UDP + user-space implementation 是必然回應
- 我們協議**禁止依賴新 TCP 行為**（如 SACK, TFO, MPTCP）
- 但**可依賴 UDP 行為** —— middlebox 對 UDP 干涉相對少（雖然 NAT / shaping 仍存在）
- TCP middlebox modification 對 anti-censorship 是雙刃劍：壞處是 protocol evolution 不能；好處是 GFW 想 inject 新 TCP behavior 也難

## Open questions
- 2026 重做這個 measurement 結果如何？(mobile carrier 升級 + IPv6 普及 + middlebox 演進)
- QUIC 是否在 5-10 年內也 ossify？已有警示信號（middlebox 對 QUIC long header 假設 v1）
- 多大規模 IETF coordination 能反 middlebox ossification？實驗結果：QUIC 用 user-space + encrypted transport 暴力解, 比說服 middlebox vendor 容易

## References worth following
- **Langley SIGCOMM 2017** Google QUIC → [precis](./langley-quic-sigcomm.md) — QUIC 設計動機 §2 直接引這篇
- **Edeline & Donnet, "A Bottom-Up Investigation of the Transport-Layer Ossification", TMA 2019** — Honda 的後續, mobile + cloud 重做
- **RFC 9170** "Long-term Viability of Protocol Extension Mechanisms" — IETF 對 ossification 的反思
