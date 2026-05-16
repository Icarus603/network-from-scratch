# Exposing and Circumventing SNI-based QUIC Censorship of the Great Firewall of China
**Venue / Year**: USENIX Security 2025, Aug 2025. https://www.usenix.org/conference/usenixsecurity25/presentation/zohaib
**Authors**: Ali Zohaib, Qiang Zao, Jackson Sippe, Abdulrahman Alaraj, Amir Houmansadr, Zakir Durumeric, Eric Wustrow (UMass Amherst, Stanford, CU Boulder, GFW.report)
**Read on**: 2026-05-16 (in lessons 8.6, 8.7, 8.9, 8.10)
**Status**: PDF direct fetch failed (USENIX server 403、gfw.report 一個 mirror 也 403)。Paper full content 透過 (1) gfw.report 對應 publication page HTML summary, (2) WebSearch 多個 secondary 引述（The Register 2025-08, net4people/bbs #505, citation.thinkst.com talk page）, (3) USENIX 議程頁 abstract 交叉確認。Methodology / results / countermeasures 都有可靠 confirmation。
**One-line**: GFW 自 2024-04-07 起對 QUIC client Initial packet **解密看 SNI** 並執行 blocklist——中國成第一個 (also 唯一已知) 部署 SNI-based QUIC censorship 的國家。Paper 用 inside-out testbed 重建演算法、發現多個 bypass、實作 availability attack。

## Problem
QUIC 把 transport metadata 都加密。連 TLS ClientHello 也在加密的 Initial packet 內。SNI extension 因此不像 TCP+TLS 那樣明文可讀。但 Initial 加密 key 從 DCID 推導（RFC 9001 §5.2），任何 passive observer 都能解。
GFW 2024-04-07 起對特定 SNI 阻擋 QUIC connection。Paper 問：GFW 怎麼做的？有什麼弱點？

## Contribution
1. **重建 GFW QUIC censorship 演算法**：
   - 只看 source_port > destination_port packet（覆蓋 ~92% 真實 client, 漏 ~7.6%）
   - 解 Initial packet using standard QUICv1 salt
   - 從解出來的 ClientHello 取 SNI extension
   - 若 SNI ∈ blocklist → 對該 3-tuple (src_IP, dst_IP, dst_port) drop 後續 180 秒
2. **發現 GFW 有三個獨立 blocklist**（完全擋 / 僅 QUIC 擋 / rolling weekly）
3. **量化規模**：3 個月觀察到 58,207 unique FQDN 被擋 (38,451 真的支援 H/3)
4. **發現 jumbo Initial bypass**：GFW 不重組跨 UDP datagram 的 Initial → Chrome 2024-09 加 Kyber768 後 Initial 變 >1500 byte, 意外 bypass
5. **設計 SNI slicing**: 拆 ClientHello SNI extension 跨多個 CRYPTO frame, 上不同 UDP packet
6. **發現 availability attack**: spoof packet 含禁 SNI → 觸發任意 (src, dst, port) 180s drop → 可武器化擋 root DNS 等
7. **upstream defense**: SNI slicing 進 Firefox 137, quic-go v0.52.0, Hysteria, V2Ray, Cloudflare quiche

## Method
- **Inside-out measurement**: 10 vantage points in Beijing (AS45090) + server in US university (AS32). Bidirectional blocking 從 2024-09-30 後不穩 → 改 inside-out
- **Probing protocol**: client 送 QUIC client Initial → 1s 後送 5 × 10-byte UDP packet → 若任一 follow-up 沒回, mark SNI as blocked
- **Test SNI list**: Tranco list 2024-10-02 snapshot, ~7M FQDN
- **3 個月 longitudinal**: 觀察 blocklist 演進、diurnal pattern、特殊事件 (2024-09-13 Chrome PQ commit, 2024-09-30 bidirectional change)
- **Disclosure**: 2025-01-22 → CNCERT, 2025-03 觀察 partial mitigation

## Results
- 58,207 unique FQDN blocked
- 38,451 (66%) 真的支援 H/3 (因 blocklist 廣撒網)
- 平均週 43.8K FQDN active block
- **Diurnal pattern**: 早上 4-6 AM 阻擋率 ~80%, 下午 6-9 PM ~30% — 顯示 GFW 解 Initial 計算瓶頸
- **180s residual block**: stable observation, 不依 source port
- **source_port > destination_port heuristic**: ignore ~7.6% real client traffic, ~70% UDP traffic overall (GFW 用此 heuristic 省 ~50% 計算)
- **3 categories of blocklists**: 用不同 evidence 區分 (timing, 不同 IP 觸發, weekly rotation)
- **Bypass success rate**: SNI slicing / jumbo / dummy prepend / QUICv2 / src_port < dst_port 都 ~100%
- **Availability attack**: 證明可 spoof Mallory → block (Alice, Bob, 53) 180s

## Limitations / what they don't solve
- 只 1 個 ASN in Beijing (AS45090) + 1 US server (AS32) — 不能保證全網普適
- 沒覆蓋 IPv6 QUIC（雖預期類似）
- 沒區分 GFW box 的多個 hardware instance 行為（某些 vantage 觀察到不一致）
- Disclosure 後 GFW 部分 mitigation 細節未完全揭露
- 沒提 ML-based GFW 升級的 plan B

## How it informs our protocol design
**整 Part 8 後半的核心 evidence**:

- 我們協議**禁止 plaintext SNI in single Initial UDP packet**
- 必須**jumbo Initial 或 SNI slicing 或 ECH** 至少一個
- 預設用 **QUICv2** (規避 GFW v1 hardcoded salt)
- 避免 source_port > destination_port 在某些 client OS 上做得到
- 我們的 client 必須對 180s residual block 有 detection + retry logic（換 source port 或換 server IP）
- **availability attack** 是我們協議必須 explicit handle 的 threat
- Diurnal pattern 啟發：故意拉高 Initial 解 cost（jumbo + grease parameter）對 GFW 是真實負擔

## Open questions
- GFW 何時部署 jumbo Initial 重組？需要 stateful flow tracking, 計算貴 — 預測 2026-27
- 是否 GFW 對 QUICv2 在 USENIX Security 2025 publish 後 1-2 年內加支援？
- ML-based QUIC fingerprint 何時出現？Tier 5 capability 預測
- Availability attack 對全球 root DNS / Cloudflare DoT 的真實影響量化 — 沒做
- 自製 QUIC variant 在 2 年內仍能繞 GFW 嗎？這影響 Part 11 設計選擇

## References worth following
- **Elmenhorst et al. IMC 2021** "Web censorship measurements of HTTP/3 over QUIC" → [precis](./elmenhorst-http3-imc2021.md) — 2021 baseline
- **QUICstep PETS 2026** → [precis](./quicstep-pets2026.md) — Connection migration as bypass
- **RFC 9369** QUICv2 — bypass tool
- **Wu et al. USENIX Sec 2023** Fully-Encrypted Detection → [precis](./wu-fep-detection.md) — entropy-based detection（GFW 的另一條腿）
- **GFW.report blog & publications** — 持續追蹤
