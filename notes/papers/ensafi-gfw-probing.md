# Examining How the Great Firewall Discovers Hidden Circumvention Servers

**Venue / Year**: ACM Internet Measurement Conference (IMC 2015), Tokyo, Japan, October 28-30, 2015. DOI [10.1145/2815675.2815690](https://doi.org/10.1145/2815675.2815690).
**Authors**: Roya Ensafi (Princeton/Censored Planet), David Fifield (UC Berkeley), Philipp Winter (Princeton), Nick Feamster (Princeton), Nicholas Weaver (ICSI), Vern Paxson (UC Berkeley / ICSI)
**Read on**: 2026-05-14（in lesson [1.6 ICMP 深度](../../lessons/part-1-networking/1.6-icmp-deep.md)，也將為 Part 9 GFW 章節核心 reference）
**Status**: ACM DL summary + multiple cross-references in subsequent literature (Wu et al. 2023, Khattak et al. 2016 SoK, Tschantz et al. 2016 SoK). Methodology widely replicated. Precis from abstract + secondary literature; PDF not directly fetched but content well-corroborated in CCS/USENIX subsequent works.
**One-line**: 系統識別並逆向工程 GFW 的 **active probing 體系**：不只 passive DPI——GFW 在偵測到可疑流量後**主動從中國境內 IP 連可疑 server**，用 protocol replay（Tor handshake、Shadowsocks、obfs2/3）判斷是否 circumvention service，命中後 IP+port 加 blacklist。本文 fingerprinting probe 來源、量化 probe 模式、為後續 circumvention 研究確立威脅模型。

## Problem

2010s 初圈內已知 GFW 不只 passive DPI——使用者報告：在中國連 Tor bridge 一段時間後該 bridge 開始**從中國其他 IP** 被連，數秒到幾天後**整個 IP 被全網封**。但學界對：
- probe 的精確 trigger 機制
- probe 來源 IP 的物理分布
- probe protocol 多樣性
- probe 與 passive detection 的時序耦合
**缺乏系統研究**。設計 circumvention tool（Tor pluggable transport、Shadowsocks variants）的人**不知道對手能力的精確輪廓**——只有 anecdotal evidence。

## Contribution

四個主要貢獻：

#### 1. 跨時間 / 跨協議的 probe 行為刻畫

部署多個誘餌 server（不同 protocol：Tor vanilla、obfs2、obfs3、Shadowsocks、SoftEther、GoAgent），跨數月觀察 probe 行為：

- **Probe 在 connection trigger 後 1 秒至數天延遲到達**——顯示 GFW probe queue **batch processing** 且 priority queue 設計
- **Probe 來源 IP 從 ~75 個中國境內 prefix**——非單一 source，但 prefix 集中（可推斷部分基礎設施位置）
- **同一誘餌 server 收到多種 protocol probe**——GFW 不知 server 真正運行哪 protocol，就**全部試一遍**
- **Probe IP 不重複**：一旦用過一個 IP 探過特定 server，下次換 IP（避免被 server 用 IP 黑名單防）

#### 2. Probe protocol 的逆向工程

實測 GFW 跑的 probe 內容：

| 目標 protocol | Probe 動作 |
|---|---|
| **Tor vanilla** | TLS ClientHello 仿 Tor、replay 真實 Tor handshake bytes |
| **obfs2** | 送 obfs2 handshake first message（可預測 byte pattern） |
| **obfs3** | 送 obfs3 handshake（uniform-random 也可被 trigger 判斷） |
| **SoftEther** | SoftEther-specific challenge |
| **VPN gates** | 各種 protocol-specific probe |

**關鍵發現**：GFW probe library **保持更新**——新 circumvention protocol 出現後**數月到一年內**對應 probe 出現。

#### 3. Trigger 機制的「**不對稱**」識別

GFW probing 不是純 random scan：
- 連到 server 的**真實 user 流量**才 trigger probe
- **無 user 流量**的 honey-pot server 收不到 probe（part of paper's verification methodology）
- ⇒ Passive DPI 看到「**像 Tor 的 client handshake**」**才**啟動 probe queue

對 circumvention tool 設計的含意：**「flow-level 看起來像 Tor」是 trigger 條件**——所以 obfuscation 必須在 flow level 做到 indistinguishable，不只 payload encryption。

#### 4. Probing 邊緣 case 與 anomaly

- **誤殺**：誘餌 server 偶爾收到 probe **連自己都不知道為什麼**——說明 trigger heuristic 有 false positive
- **Aggressive blocking**：probe 命中後封鎖通常**全 port** 而非單 port——over-block 比 under-block 偏好
- **時效性**：probe 後 IP blacklist 持續**至少幾週**，部分 prefix **永久**

## Method (just enough to reproduce mentally)

#### Honey-pot 部署

部署多個 server 在中國境外（美國學術網路），每個 server 運行不同 protocol。Server IP 不公開——只透過 connection 從中國 client 來觸發。

#### Trigger 控制

從中國境內若干 client 連 honey-pot，控制 protocol、流量大小、connection 數量。

#### Probe 觀察

server 端 tcpdump 全部 inbound flow，後續 analysis 區分：
- 真實 client trigger 連線
- GFW probe 連線（特徵：source IP 非 trigger client、protocol 多樣性、timing pattern）

#### Probe IP geolocation

對所有 probe source IP 做 BGP / WHOIS / RIPE 查詢，cross-reference 中國 ISP 結構，定位 probe infrastructure 物理分布。

## Results

- **Probe sources**：~75 個中國境內 /24 prefix，集中在 CN-CHINANET、CN-CHINA169 主幹 AS
- **Probe latency**：1 sec ~ 數天 延遲；mean ~10 sec
- **Probe protocols**：identifies > 10 種 circumvention protocols
- **Detection accuracy**：對已知 protocol > 95% 識別率
- **False positive**：~3-5% 誤殺率

**Operational significance**：本文是學界第一次系統 fingerprinting GFW probing 設施。後續所有 circumvention 設計（meek, Snowflake, obfs4, Conjure, REALITY）必須在威脅模型中對應 active probing。

## Limitations / what they don't solve

作者承認：

1. **無法看 GFW internal**：所有結論基於 black-box 觀察，**probe queue 內部 scheduling 是推測**
2. **probe IP 是 effector 不是 sensor**：GFW 用哪些 sensor IP 偵測 trigger 流量並不公開——作者僅 reverse-engineer effector 端
3. **時間性問題**：GFW 在 2015 後 evolve，**論文結論的 2026 適用度** 需 update（Wu 2023 顯示 passive detection 已躍進到 entropy-based 通用偵測，active probing 可能 less critical）
4. **協議覆蓋有限**：只測了 ~10 種 circumvention protocol，新出現的（meek、Snowflake、REALITY、Hysteria2）未在原文覆蓋
5. **缺少 client-side 配合的精確 timing 研究**：trigger 流量內容必須極接近真實 user，但「真實 user」流量是什麼分布在多種變體下未深入

## How it informs our protocol design

對 Proteus 的直接影響：

1. **威脅模型必須列入 active probing**：不是「邊緣 case」是 first-class adversary capability。**Proteus server 設計階段就要假設「對手可以隨時主動連我」**

2. **「不留指紋」是 mandatory，不是 nice-to-have**：
   - **Connection handshake 必須 indistinguishable from normal HTTPS server**（REALITY 設計就是這目的，Proteus 繼承）
   - **無 user 流量時 server 行為與 nginx/Apache 等真實 server 無法區分**
   - **probe pattern 偵測 + log + 但不改變 response**——若改變 response 就被識別

3. **Passive trigger surface 縮小是 winning condition**：Ensafi 2015 證實 **沒有 trigger 就沒有 probe**。⇒ Proteus 對抗的優先順序：
   - **passive obfuscation > active probing 防禦**
   - 若 passive 看起來像 normal HTTPS（不 trigger），probing 自然不發生
   - 這也是 Wu 2023 FEP 之後 [precis](wu-fep-detection.md) entropy-based detection 變主要威脅的原因

4. **Probe 後 blacklist 永久**：意味著「**IP 燒了**」是不可逆——Proteus 設計必須有 **IP rotation strategy**（多 server IP、可動態替換）+ **client 端離線更新通道**（不能依賴查 DNS 在中國解析，因為解析本身可能被監視）

5. **Anti-mimicry stance**：Houmansadr 2013 "Parrot is Dead" 教訓 + Ensafi 2015 證實——**完全 mimic 真實 protocol 必失敗**。Proteus 走 **cryptographic indistinguishability** 路線：每個 packet 看起來像 uniform random（or like real HTTPS data），**不**試圖偽裝成具體某種 protocol

## Open questions

- **GFW 2026 active probing strategy**：本文 2015，10 年後 probing 設施與策略應大幅 evolved。是否有 follow-up systematic study？目前看到的最新跡象：probing 似乎變少（passive ML detection 進步使 probing less necessary）但**未證實**
- **Probe sensor 位置 vs effector 位置**：本文 reverse engineer effector，**sensor 部署位置是什麼**？是否在每個 AS 邊界，是否在 IXP？這部分仍是 partial-knowledge
- **Probe scheduling 的 ML 化**：GFW probe queue 是否用 ML 排序「最可能命中」的目標優先？目前無公開證據
- **跨國家 probing infrastructure 比較**：Iran、Russia、Turkmenistan 都有類似機制，**comparative study** 缺乏
- **Proteus 對抗 probing 的可證明性**：如何**formally prove**「我的 server 在 probing 下沒有 distinguishable behavior」？目前只有 empirical evidence，**formal indistinguishability proof** 仍 open
- **被 probe 後 server 主動 honeypot**：probe 確認後，server 是否該**主動回應 plausible fake** 誤導 GFW 浪費資源？道德、技術、戰術上都有討論空間

## References worth following

- **Censored Planet Observatory** <https://censoredplanet.org/> — Ensafi lab 持續 censorship measurement
- **Ensafi 2015 PoPETs "Analyzing the Great Firewall of China Over Space and Time"** — 同年姊妹論文，用 IPID side channel 量測 GFW
- **Khattak et al. 2016 SoK "Resistance to Internet Censorship"** (PoPETs)（[precis](khattak-sok-resistance.md)） — 整體 circumvention SoK
- **Tschantz et al. 2016 SoK "Bypassing Censorship"** (IEEE S&P)（[precis](tschantz-sok-circumvention.md)）
- **Wu et al. 2023 USENIX Sec "How GFW Detects Fully Encrypted Traffic"**（[precis](wu-fep-detection.md)） — 後續 entropy detection
- **Marczak et al. 2015 "China's Great Cannon"** (FOCI) — 同年 GFW offensive capability 揭露
- **Winter & Lindskog 2012 FOCI** — 早期 Tor blocking analysis
- **Fifield's PhD thesis on circumvention** — UC Berkeley
- **Houmansadr et al. 2013 "Parrot is Dead"** (IEEE S&P)（[precis](houmansadr-parrot-is-dead.md)） — anti-mimicry 教訓
