# Blocking-resistant Communication through Domain Fronting

**Venue / Year**: PoPETs 2015 (Proceedings on Privacy Enhancing Technologies)
**Authors**: David Fifield, Chang Lan, Rod Hynes, Percy Wegmann, Vern Paxson
**Read on**: 2026-05-16（in lessons [[1.16-cdn-anycast]] / [[1.14-dns-anatomy]] 引用）
**Status**: 主要從官方頁面摘要 + WebFetch 全文擷取；技術細節已交叉驗證
**One-line**: 利用 HTTPS 分層讓 DNS / SNI 顯示「允許域名」而 HTTP Host header 才是真實目的地，把翻牆流量躲在大型 CDN 共享前端後面——meek pluggable transport 的奠基論文。

## Problem
審查者透過 DNS filtering / IP block / DPI 攔截禁區流量。既有翻牆工具被持續升級的審查壓制。挑戰：怎麼讓 client 連到禁區內容、同時讓網路看起來在跟「允許服務」對話。

## Threat Model
四個角色：
- **Censor**：控制國家網路、能 inspect/drop 封包；**不能** MITM 有效憑證（會觸發 cert validation 失敗）；**不能**控制 CA。
- **Censored client**：在 censor 網內。
- **Intermediate web service (front)**：在牆外、未合作（uncooperative）但也未與 censor 共謀。
- **Covert proxy**：在牆外、藏在 CDN 後面。

## Contribution
利用 HTTPS 的多層結構：
- **明文層（censor 可見）**：DNS query + TLS SNI = **front domain**（如 `allowed.example`）
- **加密層**：HTTP Host header = **真實目的地**（如 `forbidden.example`）
- **CDN 邊緣**：解 TLS 後讀 Host header → forward 到對應 origin

Censor 唯一封鎖辦法是封整個 front domain → 巨大 collateral damage（封 Google、Cloudflare 等熱門服務）。這是 domain fronting 的核心政治經濟學。

## Method
- **meek pluggable transport (Tor)**：meek-client 把 Tor cells 包成 HTTPS POST，X-Session-Id header 對應 Tor circuit；strictly serialized（≤64KB / request，等 response 才送下一塊）。
- **Lantern flashlight**：enproxy 把 TCP stream 編成 HTTP request；fronted lib 處理 fronting；sticky routing via custom header。
- **Psiphon**：SSH-over-meek + encrypted session ID；10 個 proxy 並發選最快；streaming HTTP（1MB chunks 取代 64KB → 4-5× 影片加速）。
- **TLS fingerprint mitigation**：meek-client 透過 headless Firefox / Chrome 發 request，避免被 censor 用 TLS fingerprint 偵測。

## Results
- **可 front 的服務（2015 時點）**：Google App Engine、AWS CloudFront、Azure、Fastly、CloudFlare、Akamai、Level 3。
- **下載速度**：~2-3× 慢於直連 Tor。
- **2015 May 部署**：4,000 concurrent meek users；22.5GB on App Engine + 14.8GB on CloudFront；總成本約 $7,085。
- **traffic analysis 結果**：對比 LBNL 真實 Google HTTPS 10 分鐘 / 313MB trace，packet length 分布相近（meek 略缺短 payload）；connection lifetime 較長（60% ≥5min vs 13%）—— censor 能用此做 weak fingerprint，但會誤判大量合法 long-transfer 流量。
- 「我們不知道有任何明顯特徵能可靠區分 fronting 與一般 HTTPS」。

## Limitations
1. **Collateral damage calculus** 依賴 censor 願不願封 front—— 不對稱情境下無效（如 Iran 願封 Google）。
2. **Latency penalty** 2-3× 慢、HTTP serialization。
3. **Financial DoS**：2015 GreatFire / GitHub 被 Great Cannon 攻擊，反向耗盡 CDN 預算（數萬美元）。
4. **CDN 自主關閉**：Google App Engine 主動禁 fronting（2018-04 後 Tor meek-google 失效）；CloudFront 2018-04 跟進；Azure 2018-09 同樣關閉；Cloudflare 2015-03 開始 enforce SNI = Host matching。
5. **Same-entity correlation**：若 front 與 destination 同公司（如 fronting `www.google.com` to YouTube），CDN 自己能 timing-correlate。
6. **SNI 強制檢查**：2015 後 Fastly、CloudFlare 已 enforce SNI=Host，需「domainless」模式繞過。

## How it informs our protocol design
**G6 對 fronting 的態度**：
- **不能當 baseline**——2018 後主要 CDN 大規模封禁，long-tail CDN 仍可用但邊際遞減。
- **可作 fallback transport**：當 G6 正規 transport 被 SNI fingerprint / active probe 識別後啟用。
- **ECH (Encrypted Client Hello) 是 fronting 的後繼者**：明文 SNI 改 encrypted → 不再需要 CDN 配合，但仍受 GFW selective drop 影響（見 [[hoang-gfwatch]]）。
- **設計取捨**：fronting / ECH 都依賴「不能封 front」這個外部假設——G6 不可把抗審查根基放在外部假設上。
- **影響 Part 11.3 設計空間**：fronting 列為 optional transport，**不是**主協議組件。

## Open questions
- ECH 部署率拐點到了沒？2025 後 Cloudflare 預設 ECH，GFW 反制如何演化？（見 Hoang 等 2024 後續工作）
- Refraction networking（Slitheen / Conjure）是否能替代 fronting？需要 ISP 配合 → 部署門檻高。
- 「Domain hosting」（直接租 CDN 帳號 + WAF 規則）是否仍可在 long-tail CDN 上做 fronting？

## References worth following
- Bocovich & Goldberg, **Slitheen** (CCS 2016) — refraction networking 1.0
- Frolov, Wustrow, **Conjure** (CCS 2019) — refraction 2.0
- Frolov, Wampler, Wustrow — **Use of TLS in Censored Regions** (FOCI 2020)
- Markwood et al. — **Domain Fronting in the Wild**
- IETF draft-ietf-tls-esni → RFC 9180 (HPKE) → ECH RFC 9460 / draft（ECH 正式 RFC 仍 in flight 2026）
