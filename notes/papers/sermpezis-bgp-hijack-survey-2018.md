# A Survey among Network Operators on BGP Prefix Hijacking

**Venue / Year**: ACM SIGCOMM CCR (Computer Communication Review), Vol. 48 No. 1, January 2018
**Authors**: Pavlos Sermpezis (FORTH-ICS), Vasileios Kotronis (FORTH-ICS), Alberto Dainotti (CAIDA, UCSD), Xenofontas Dimitropoulos (FORTH-ICS / U. of Crete)
**Read on**: 2026-05-16（in lesson [[1.15-bgp-internet-routing]] 引用）
**Status**: 從 arXiv 1801.02918 + CAIDA / CCR online 摘要合成；PDF 已 fetch 但 parser 部分失敗——關鍵統計來自摘要與已公開 review 內容
**One-line**: 對 75 個 network operator 問卷 + 量測：40% 自承曾被 hijack，76% 認為 hijack 影響「持續數小時以上」，RPKI 部署率仍低、operator 反應仰賴第三方服務——這證明 BGP-layer 對手對 Proteus 部署是 production-grade threat。

## Problem
- BGP 從 1989 部署起就無認證——任何 AS 可宣告任何 prefix。
- 多個 hijack-prevention 機制提案（BGPsec、RPKI、prefix monitoring）—— **但實際部署率低**。
- 沒有實證資料說「operator 為何不部署、實際遇到 hijack 怎麼處理」。
- 設計新 defense 缺乏 operator-validated requirement set。

## Threat Model
- BGP-layer adversary：能控制（或共謀）一個 AS，宣告比 victim 更 specific 或 same-length 的 prefix。
- 影響面：可全球或區域性（基於 AS 拓樸 + 鄰居 prefer rules）。
- 受害者：擁有該 prefix 的 organization；其客戶；任何依賴對 victim 服務做 DNS / TLS 信任的 user。

## Contribution
1. 第一份系統性 BGP hijack defense **operator survey**（n=75）。
2. 量化 operator 對 hijack 的**主觀** 風險認知 vs 客觀部署行為的 gap。
3. 把 operator-reported needs 轉化為 defense 設計需求（指向後續 ARTEMIS 系統）。

## Method
- 問卷分發給：NANOG、RIPE、APNIC、AfriNOG 等社群 mailing list。
- 75 份完整回覆，跨多大洲（具體分佈詳全文）。
- 問題涵蓋：
  - 是否經歷過 hijack？頻率？
  - 偵測機制：自建 / 第三方 / 訂閱服務（BGPmon, BGPStream 等）
  - 反應時間
  - 採用的 mitigation 機制
  - RPKI 部署狀態與障礙
  - 對新 defense 系統的 wishlist

## Results（關鍵統計）
- **40%** 的 operator 自承組織曾被 hijack。
- **76%** 認為 hijack 影響「持續數小時以上」。
- 多數 operator **不部署 BGPsec**，主要原因：CPU 開銷、鄰居未配合、缺乏明確 ROI。
- RPKI 部署仍受限——2018 時點 ROA-covered prefix 比例約 10-15%（2024 已升至 ~40-50%，但部分大型 AS 仍未實施）。
- 多數 operator 仰賴**第三方監測服務**（BGPmon, BGPStream, Cloudflare Radar 等）做被動偵測，並用 prefix de-aggregation、人工聯絡上游、緊急 community tagging 做 reactive mitigation。
- 反應時間：通常**數小時**——對 financial / DNS / Cert authority 服務是致命延遲。

## Limitations
1. **Self-selection bias**：填問卷的 operator 通常已關心 hijack，被 hijack 未察覺者不在樣本內 → 真實 hijack 比例可能更高。
2. **Sample size**：75 比起全球 ~80K AS 是小樣本；地理分布可能偏 OECD。
3. **時間切片**：2018 數據；RPKI 部署率與 detection tooling 已大幅演化（2024 RPKI ~50%、MANRS 倡議普及）——引用本 paper 時需配合更新數據。

## How it informs our protocol design
**Proteus 設計層次的 BGP threat 影響**：

1. **Proteus server prefix 應 RPKI sign**——保護 own announcement 不被 hijack（partial defense）。
2. **Proteus client bootstrap 必須容錯 BGP hijack**：
   - 若 client 透過 DNS 解析到 IP，IP 因 BGP hijack 連到攻擊者 server → TLS / Noise authentication 必須阻止 silent MITM。
   - 解：**pin server public key**（類似 SSH HPKP、TOFU），不只信 CA。Part 11.x 設計時對應 [[1.14-dns-anatomy]] DNS 威脅模型。
3. **BGP-level adversary 雖無法直接讀加密 payload，但可**：
   - DoS：黑洞化 Proteus server prefix → 區域 user 連不上。
   - Active MITM 平台：hijack + valid DV cert（Sun 2018 *Bamboozling CA* 證明 BGP hijack + Let's Encrypt DV 可拿到 valid cert）。
4. **Multi-region deployment**：Proteus 不該綁定單一 AS / 單一 anycast IP——分散 IP space + 多家 hosting provider 是 BGP-level resilience 基本盤。
5. **Forward ref**：Part 11.1 威脅模型必須明確列「BGP-layer attacker」為 known capability；Part 12.x 部署文件須含 RPKI ROA setup checklist。

## Open questions
- **RPKI 邊際**：2026 RPKI 覆蓋率拐點到 70% 後，剩下 30% prefix 的 hijack 防護如何？(經典「missing tail」問題)
- **ARTEMIS** 等 real-time hijack neutralization 系統能否做到分鐘級 mitigation？對 censor-controlled hijack 是否仍有效？
- **BGPsec** 為何遲未部署？是否徹底沒戲？replacement 提案？
- 對抗式 hijack：審查者用 BGP 配合 DNS / TLS attack chain 對 Proteus 設計的累積影響。

## References worth following
- Demchak & Shavitt — **China's Maxim** (Military Cyber Affairs 2018) — 對 China Telecom hijack 系統研究
- Cowie et al. — **China's 18-Minute Mystery** (Renesys 2010)
- Sun et al. — **Bamboozling Certificate Authorities with BGP** (USENIX Security 2018)
- Pilosov & Kapela — **Stealing The Internet** (DEFCON 2008)
- Hu & Mao — **Accurate Real-time Identification of IP Prefix Hijacking** (S&P 2007)
- Sermpezis et al. — **ARTEMIS** (IEEE/ACM ToN 2018) — 後續 defense 系統
- RFC 6480-6483 / 6810-6811 / 8210 — RPKI 規格族
- RFC 8205 — BGPsec
- RFC 7908 — Route Leak definitions
