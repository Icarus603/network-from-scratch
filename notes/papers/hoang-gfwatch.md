# How Great is the Great Firewall? Measuring China's DNS Censorship

**Venue / Year**: 30th USENIX Security Symposium (USENIX Security 2021). DOI [10.5555/3489212.3489413](https://www.usenix.org/conference/usenixsecurity21/presentation/hoang). Full PDF <https://www.usenix.org/system/files/sec21-hoang.pdf>.
**Authors**: Nguyen Phong Hoang (Stony Brook University & Citizen Lab/U of Toronto), Arian Akhavan Niaki (UMass Amherst), Jakub Dalek, Jeffrey Knockel, Pellaeon Lin, Bill Marczak, Masashi Crete-Nishihata (Citizen Lab), Phillipa Gill (UMass Amherst), Michalis Polychronakis (Stony Brook)
**Read on**: 2026-05-14（in lesson [1.14 DNS 完整解剖](../../lessons/part-1-networking/1.14-dns-anatomy.md)；Part 9 GFW 章節亦會深入精讀）
**Status**: Full PDF freely available via USENIX open access. Methodology, dataset (411M domain/day × 9 months) and main findings cross-confirmed via arXiv preprint 2106.02167 + GFWatch project page. Subsequent FOCI 2025 follow-up "I'll Shake Your Hand" referenced.
**One-line**: 構建 **GFWatch** —— 至本論文發表時最大規模的中國 DNS 審查量測平台 —— 每天測 411M 域名 × 9 月，發現 **311K 受審查域名**、**3 個 injector**（用 packet header 指紋區分，Injector 2 負責 99%）、**11 組 forged IP**（含被冒充的美國公司 IP）、**41K innocuous overblocking**；逆向 GFW DNS filter 正則 + 量化對全球公共 resolver cache 污染——是 GFW DNS 對抗研究 2021+ 必引用 baseline。

## Problem

過去 GFW DNS 審查研究（2014 FOCI Anonymous, 2016 ASIACCS Verkamp, 2017 SIGCOMM Anonymous *Triplet Censors*）多數**受限規模**：
- 樣本通常 Alexa Top 1M 或更少
- 量測短期（數天到數週）
- 對 injector 識別不深
- 對 forged IP behavior 後續無 follow-up

具體未解問題：
- **多少 domain 真正被 censored**？真實數量級從未量化
- **GFW DNS 用幾個 injector**？各自負責什麼？
- **forged IP 來源**？是否有 pattern？
- **overblocking 多大**？innocuous domain 被誤殺多少？
- **對全球 public resolver 的 spillover** 多大？

## Contribution

#### 1. GFWatch 量測平台

- 主機在美國學術網路（不受審查）
- 對 411M 域名/天 發 A + AAAA query 到位於中國的受控 host
- 觀察 forged response 來自 GFW（透過 packet fingerprint）
- 持續 9 個月（2020-2021）

#### 2. 規模化發現

- **311K 受審查域名**（previous studies < 10K）
- **每天 277K-301K** 之間波動
- 增量：average **~700 new censored domains/day**（GFW 持續加 entries）

#### 3. Injector 指紋分類

根據 packet header 特徵識別 **3 個 GFW DNS injector**：

| Injector | AA bit | DF bit | 負責 % |
|---|---|---|---|
| **Injector 1** | 1 | * | < 1% (2K domains) |
| **Injector 2** | 0 | 1 | **99%** |
| **Injector 3** | 0 | 0 | 64% (overlapping) |

⇒ GFW 不是 single device——是分散 infrastructure；不同 device 對不同 domain set。

#### 4. Forged IP 分組

11 個明顯 cluster（先前研究只發現 6 個）：
- Group 0-4：包含真實 US 公司 IP（Facebook、Dropbox、Twitter 等）——victim 連 forged IP 反而連到合法服務（confusion）
- Group 5-10：其他 forged set
- 每組對應特定 censored domain 子集——pattern 是非隨機

#### 5. Regex reverse-engineer

對 311K 受審查 domain 比對 string pattern → 推斷 GFW 用的 **regex filter**。發現：
- 部分 keyword-based（如 `freedom`, `tibet` substrings）
- 大量 wildcard / suffix match
- **41K innocuous overblocking**——例如 `linuxfoundation.org` 含 "tibet" 之類字串 → 誤殺

#### 6. Spillover 到全球 public resolver

某些 censored domain 的 forged response 在路徑上被 cache 進 **Google DNS / Cloudflare DNS** → 全球非中國 user 也拿到 poisoned response。
量化：**77K censored domain 在公共 resolver 出現 poisoned record**。

#### 7. 對抗策略

論文末段 propose：
- **Sanitization**：public resolver 偵測 + 從 cache 移除 forged IP（已有部分 deployment）
- **Client-side detection**：用 forged IP set + packet fingerprint 自助偵測

## Method (just enough to reproduce mentally)

#### 大規模 query 生成

- 從多 source（Alexa, Tranco, OpenINTEL, .com zone, 子域名生成）構建 domain set ≈ 411M
- query rate 限制以避不過載受控 host

#### Injector fingerprint extraction

對每 forged response 提取 IP header fields（IPID、TTL、DF）+ UDP header + DNS payload (AA bit、TC bit、Z bits)。聚類為 injector profile。

#### Forged IP cluster

對所有 forged IP 觀察 → set 化 → 對應 censored domain 子集——同 domain 多次 query 拿到 set 內 random IP（rotation pattern）。

#### Validation

部分 censored domain 從中國境內 manual probe 驗證——確認 GFW DNS injection 是 root cause。

## Results

- **Censored domains**: 311K（>30× previous estimate）
- **Injector count**: 3
- **Forged IP groups**: 11
- **Overblocked innocuous**: 41K（13% of all blocked）
- **Public resolver spillover**: 77K domains poisoned in major public DNS
- **9-month data publicly released** at GFWatch project

## Limitations / what they don't solve

作者承認：

1. **量測點限制**：domain set 仍是 subset of internet——可能漏掉某些 censored domain（如非 popular site）
2. **Active probing 互動未深探**：論文 focus DNS injection，**對應的 active probing**（Ensafi 2015）未充分整合分析
3. **Resolver 從 user end-host 視角 limited**：論文用 academic vantage point；user 從中國 broadband / mobile carrier 可能看到不同 injection pattern
4. **Temporal evolution**：9 個月觀察期，**長期 trend** （e.g. 5 年）仍未明確
5. **無 mitigation deployment evaluation**：論文 propose sanitization 但 deployment effectiveness 未量測

## How it informs our protocol design

對 G6 設計直接 implication：

#### 1. G6 server domain 命名

- 必須避開 GFW regex filter（41K overblocking 含很多無辜 substring）
- **不**用「vpn」、「proxy」、「circumvent」等 keyword
- 也避開「tibet」「freedom」「democracy」等 GFW heavy filter substring
- 建議：**普通商業 sounding 域名**（如 `analytics-cdn.example.com`）

#### 2. G6 client bootstrap 不能靠 plain DNS

311K 受審查域名 + GFW 持續加新——G6 server domain 隨時可能被 added。**Plain DNS 不可信**——必須 DoH / DoQ + IP pre-config fallback。

#### 3. Forged IP detection

GFWatch 公開的 11 組 forged IP——G6 client SDK 內 bundle 這個 list。client 看 DNS response 含 known forged IP → 立即標記 + 切到 fallback bootstrap。

#### 4. 對 GFW injector 指紋的攻擊性反向利用

了解 GFW response 用 DF=1, AA=0 (Injector 2)、特定 IPID pattern——G6 client 可**主動發 probe 觸發 GFW injection**作測量但不依賴此測量做生產決策（風險）。

#### 5. 對 public resolver poisoning 的應對

77K domain 在 public resolver 也 poisoned——**即便用 8.8.8.8 / 1.1.1.1**，部分受審查 domain 仍可能拿 forged response。**G6 client 必須做 cross-resolver consistency check + forged IP detection**。

## Open questions

- **GFW DNS 2024-2026 演化**：自 2021 後 GFW 在 ECH / DoH / DoQ 對抗上是否新策略？最近 FOCI 2025 報告暗示 GFW 變主動 honeypot——open
- **Injector 物理位置**：3 個 injector 在 ISP layer 哪邊？學術 reverse engineering 仍 limited
- **Injection 對 IPv6 query**：論文主要 IPv4——IPv6 injection rate 與 IPv4 相同嗎？open
- **Forged IP set 動態變化**：GFW 每多久 rotate forged IP？模式如何？
- **與 active probing 的聯動**：DNS injection trigger 主動 probing 嗎？vice versa？
- **AI / ML 對 GFW DNS detection 的 feasibility**：基於 response 特徵動態識別 forged——是否可以 deploy 在 client-side without false positive？
- **GFW 對 G6 server domain 命名 ML detection**：如果 GFW 用 ML 識別「**可能是翻牆 server**」的命名——這是否已發生？open
- **跨國家 DNS censorship 比較**：Iran / Russia / Turkmenistan 同類 measurement——comparative study 缺

## References worth following

- **Hoang et al. 2024 USENIX Sec *GFWeb*** — web censorship 後續
- **FOCI 2025 *I'll Shake Your Hand: What Happens After DNS Poisoning*** — forged IP 主動 honeypot 行為
- **Ensafi 2015 IMC active probing**（[precis](ensafi-gfw-probing.md)） — 配套了解
- **Wu 2023 FEP detection**（[precis](wu-fep-detection.md)） — entropy detection era
- **GFWatch website + dataset** <https://gfwatch.org/>
- **Verkamp & Gupta 2016 *Inferring Mechanics of Web Censorship Around the World*** (FOCI)
- **Pearce 2017 IEEE S&P Augur** — connectivity disruption via DNS + IPID
- **Anonymous et al. 2014 FOCI *Towards a Comprehensive Picture of the GFW's DNS Censorship***
- **OONI Project** <https://ooni.org/> — censorship measurement
- **Censored Planet** <https://censoredplanet.org/>
- **Nguyen Phong Hoang's page** — 持續 censorship measurement
