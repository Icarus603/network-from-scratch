# SoK: Making Sense of Censorship Resistance Systems

**Venue / Year**: Proceedings on Privacy Enhancing Technologies (PoPETs) 2016, Issue 4, pp. 37–61
**Authors**: Sheharbano Khattak, Tariq Elahi, Laurent Simon, Colleen M. Swanson, Steven J. Murdoch, Ian Goldberg
**Read on**: 2026-05-14 (in lesson 0.1)
**Status**: full PDF (25 pages) at `assets/papers/popets-2016-khattak-sok-resistance.pdf` (read pp. 1–15; remaining is per-system tables and appendix)
**One-line**: 把 73 個 censorship resistance systems (CRS) 拆成 **threat model → scheme → property** 三層，建立統一的 security/privacy/performance/deployability 四維評估框架。

## Problem

CRS 數量爆炸（73 個 deployed + academic），但**評估標準各說各話**——每篇論文用自己的威脅模型、自己的 metric。結果：
- **無法跨系統比較**
- **無法判斷某 CRS 是否能對付某 censor**
- **無法看出 sub-field 的 trends 與 gaps**

## Contribution

1. **統一 censor 攻擊模型**（§2.4）：把所有觀察到的 censor 行為歸納成 fingerprinting + direct censorship 兩階段；fingerprinting 細分 **destinations / content / properties / semantics**（Fig. 3）。
2. **CRS 抽象架構**（§3）：把 CRS 拆成 **CRS client / CRS server / dissemination server**，與兩個 phase（Communication Establishment / Conversation）。
3. **四維評估框架**（§4）：
   - **Security**：unobservability、unblockability、availability、communication integrity
   - **Privacy**：user/server anonymity、user/server/participant deniability
   - **Performance**：latency、goodput、stability、scalability、computational/storage overhead
   - **Deployability**：synchronicity、network agnosticism、coverage、participation patterns
4. **Schemes**（§5–6）：把 73 系統歸類成 11 個 representative schemes
   - Communication Establishment 5 schemes：High Churn Access、Rate-Limited（Proof of Work / Time / Keyspace partition）、Active Probing Resistance（Obfuscating Aliveness / Service）、Trust-based
   - Conversation 6 schemes：Mimicry（content/flow）、Tunnelling、Covert Channel、Traffic Manipulation、Destination Obfuscation（Proxy / Decoy Routing）、Content Redundancy、Distributed Storage
5. 每個 scheme 用代表系統做評估表（Table 1, Table 2），給出研究空白點。

## Method

- 從 academic 論文（well-known venues）+ 部署工具的 reference + Google Scholar 搜尋 →  73 系統
- 6 名作者拆成 domain expert + cross-validator
- 4 步驟：survey → categorization → develop framework → evaluate（評估再讓另兩位獨立驗證）
- 每個 property 用 binary 或 partial 三級評分（has / partially has / does not have）

## Results

- **62 系統**做 Conversation phase，只 **11 系統**做 Communication Establishment（與 Tschantz 的 D1 disconnect 完全一致）
- Mimicry 類**完全失敗**抗主動探測（與 Houmansadr "Parrot is dead" 一致）
- Decoy Routing（Telex、TapDance、Cirripede）是少數**對 censor 而言難以阻擋**的 scheme，但部署成本極高（要 ISP 配合）
- 大部分 scheme **不抗 DoS**、不提供 **server anonymity**
- **Coverage** vs **unblockability** 是內建 trade-off：要支援廣泛 publisher 就難隱藏 server

## Limitations / what they don't solve

- 沒涵蓋 **usability** 維度（作者明說留給 future work）
- 框架定義 high-level，個別 system 的 property 會被 abstraction 抹掉細節
- cutoff 在 2016 年初——SS-AEAD、Trojan、VLESS、REALITY、Hysteria/TUIC 全沒包含（與 Tschantz 同樣有時代局限）
- Active Probing 僅模型化「server 該不該回 unauthorized request」，**沒模型化 GFW 2023 那種純被動 fully-encrypted detection**（Wu et al.）

## How it informs our protocol design

**直接結構**了 Part 11 我們協議的 spec 與 evaluation：

1. **Spec 結構** — 我們的 spec 文件 (Part 11.5–11.8) 應按本篇的 Communication Establishment / Conversation phase 拆。
2. **Threat Model section** — 直接套用本篇 §2.4 的 censor attack model，加上 Wu 2023 的 fully encrypted detection 作為 update。
3. **Security Properties section** — 用本篇定義的 5 個 security + 5 個 privacy property 作為 baseline，逐項 declare：has / partially has / does not have，並給出形式化定義（指向 Part 5.4–5.6 的 ProVerif/Tamarin spec）。
4. **Performance Properties section** — 5 個 performance metric 直接套用，加我們特別強調的 high-loss-link goodput（Hysteria2 戰場）。
5. **Evaluation table** — Phase III 12.11–12.18 評測直接產出本篇 Table 1/Table 2 風格的對比表，與 Hysteria2、TUIC v5、VLESS+REALITY 並排。

**設計座標 G6 vs Table 1/2**：
- 我們相對 Active Probing Resistance（SilentKnock, ScrambleSuit）：要 inherit 全部該欄屬性
- 我們相對 Tunnelling（Freewave）/ Covert Channel（Collage）/ Traffic Manipulation（Khattak et al.）：要在 unobservability 三個 sub-property（Content / Flow / Destination Obfuscation）全勝
- 我們的劣勢：可能需要在 deniability 部分讓步（換取效能）

## Open questions

- **CRS 互通性沒被研究**：兩個 CRS 是否能 layer（例如 SS over Tor）？如果可以 layer，evaluation 是否要 compositionally 算？
- 形式化方法（ProVerif、Tamarin）能否驗證本篇的 property 定義？目前定義多半是英文 prose，沒形式化。
- 「**partial has**」的判定標準完全靠 expert judgment——是否能有更客觀指標？
- 本篇強調對抗 censor，但 **CRS 內部攻擊**（malicious participants、Sybil）只在 deniability 部分提及——這個威脅維度值得獨立 SoK
- **Decoy Routing 為什麼至今沒大規模部署**？技術上理論最強，但 ISP 合作問題顯然不是學術 SoK 能回答的

## References worth following

- **Tschantz et al. SoK** (S&P 2016) — 姊妹篇，本門課 Part 9.1 主軸，已建檔
- **Houmansadr et al.** *The Parrot is Dead* (S&P 2013) — Mimicry 失敗的證明
- **Pfitzmann & Hansen** terminology paper — unobservability/unlinkability/undetectability 的標準定義來源
- **Karlin et al.** *Decoy Routing: Toward Unblockable Internet Communication* (FOCI 2011) — Decoy Routing 概念起源
- **Brubaker et al.** *CloudTransport* (PoPETs 2014) — 用 cloud storage 當 covert channel
- 本篇 Appendix A — 完整 73 系統清單與 citation，當作我們 Phase II 文獻 survey 的 seed

## 跨札記比較：本篇 vs Tschantz SoK

兩篇是同年（2016）兩個學界圈子的姊妹 SoK，互補度極高：

| | **Tschantz S&P 2016** | **Khattak PoPETs 2016** |
|---|---|---|
| 主視角 | empirical alignment（學界 vs 真實 censor） | structural taxonomy（系統 vs scheme vs property） |
| 對象數 | 33 學術 + 22 部署 = 55 | 73 包括 academic + deployed |
| 核心圖 | 三個 disconnect + 六個 research gap | 11 representative schemes 的 4-dimension 評估表 |
| 我們協議用法 | 校正威脅模型 + evaluation 哲學 | 結構化 spec + property declaration |

兩篇配合讀，恰好涵蓋「我們**該怎麼想**這個問題」+「我們**該怎麼結構化呈現**設計」。
