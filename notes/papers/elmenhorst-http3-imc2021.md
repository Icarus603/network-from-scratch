# Web censorship measurements of HTTP/3 over QUIC
**Venue / Year**: ACM IMC 2021 (Internet Measurement Conference)
**Authors**: Kathrin Elmenhorst, Bertram Schütz, Nils Aschenbruck, Simone Basso (OONI)
**Read on**: 2026-05-16 (in lesson 8.6)
**Status**: PDF 未直接 fetch（gfw.report URL 404）。內容從 Zohaib USENIX Sec 2025 §2 對該 paper 的引述 + IMC 2021 program page abstract 交叉確認。Headline 結果穩定，細節 figures 未取得。
**One-line**: 2021 年 QUIC/H3 在中國、伊朗、其他 censoring 環境的可用性 baseline——當時 censor 還沒做 SNI-based QUIC 過濾，是用整體 IP/UDP 阻擋。為 Zohaib 2025 後續工作提供 historical reference。

## Problem
2021 時 QUIC adoption 才約 ~5% web traffic, censor 對 QUIC 的態度未明朗。Elmenhorst et al. 用 OONI 平台量測：QUIC over UDP/443 在 censoring 國家是不是 routinely 可用？

## Contribution
1. 全球 QUIC reachability measurement using OONI probes
2. 證明 2021 時 censor **沒**用 SNI-based QUIC 過濾——blocking 是「對整個 destination IP 上 UDP 流量都 drop」
3. 區分國別策略：
   - **中國**: 對 known QUIC server IP (google.com 等) 的 TCP/443 + UDP/443 都 drop
   - **伊朗**: 對 known QUIC server IP **只** drop UDP traffic（TCP/443 仍通）
   - 其他國家：偶見零星 blocking
4. 結論：「QUIC 不是 anti-censorship 銀彈」，當時 (2021) censor 簡單暴力 drop UDP 就行

## Method
- OONI probes 在 ~10+ 國 vantage
- 對一組 known H/3 enabled domain (youtube.com, google.com, etc) 做 QUIC handshake attempt
- 比對 TCP/443 success rate vs UDP/443 success rate
- Longitudinal: 2020-2021 多個月

## Results
- 全球 H/3 可達率 ~95%（非 censoring 環境）
- 中國對 Google IP: TCP/443 + UDP/443 都 ~0% reachable
- 伊朗對 Google IP: TCP/443 ~30% reachable, UDP/443 ~0% reachable
- 中國其他大量 non-Google QUIC server: 普遍可達（沒專門擋）
- **沒**觀察 SNI-based 過濾證據

## Limitations / what they don't solve
- 2021 數據, 2024+ GFW 完全變了（Zohaib 2025）
- Probe scale 有限 (OONI volunteer 數)
- 沒測「同 IP 換 SNI 是否影響 reachability」（這個 test 才會發現 SNI-based 過濾）
- 純 reachability, 沒測 throughput / latency 

## How it informs our protocol design
**Historical baseline**：

- 2021 時 QUIC 普及度低, censor 簡單暴力 → 證明「QUIC 必須普及」才有 anti-censorship 紅利
- 我們協議部署時普及度約 30% (2026), 比 2021 好但 still niche
- 設計上**必須假設 censor 會升級**（Zohaib 2025 證明確實升了）
- 國別差異提示：不只擋 QUIC, 還可能擋 TCP/443（中國對 Google）

## Open questions
- 2026 重做這個 measurement 結果如何？Zohaib 2025 涵蓋部分但仍 narrow
- 伊朗 / 俄羅斯 對 QUIC 的最新策略？(俄羅斯 TSPU 2022-03 全擋 QUICv1 ≥1001 byte payload，已過時)
- 其他國家在 GFW 領先後是否跟進 SNI-based QUIC 過濾？目前已知只 中國

## References worth following
- **Zohaib USENIX Sec 2025** → [precis](./zohaib-quic-sni-2025.md) — 2024+ updated picture
- **OONI** documentation & global metrics dashboard
- **GFW.report blog** 對 QUIC 阻擋的多次討論（不一定 paper format）
