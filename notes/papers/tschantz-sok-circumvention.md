# SoK: Towards Grounding Censorship Circumvention in Empiricism

**Venue / Year**: IEEE Symposium on Security and Privacy (S&P) 2016
**Authors**: Michael Carl Tschantz (ICSI), Sadia Afroz (ICSI), Anonymous, Vern Paxson (UC Berkeley + ICSI)
**Read on**: 2026-05-14 (in lesson 0.1)
**Status**: full PDF (20 pages) at `assets/papers/ieee-sp-2016-tschantz-sok-circumvention.pdf` (read pp. 1–12 in detail; pp. 13–20 are appendix tables and references)
**One-line**: 把學界的審查規避（censorship circumvention）研究跟真實對手的實際行為對齊——指出三個 disconnect、六個 research gap，要研究員別再閉門造設計。

## Problem

學界 circumvention 研究**評估方法各說各話**，缺乏共同基準；而設計者**對真實審查者的能力做了不切實際的假設**——傾向假設複雜攻擊（流量分析、ML 分類），但真實 censor（GFW 為主例）偏好**便宜、被動、低偽陽性**的攻擊。結果：學界產出大量在實驗室漂亮、但在現實對手面前長相不對的協議。

## Contribution

1. 系統性收集 **31 篇審查測量論文** + **55 個 circumvention 設計（33 學術 + 22 部署）**，整理成統一比較表（Table I~VII）。
2. 用 Tor vs GFW 的 cat-and-mouse 史當主線，把抽象的 censor 模型具體化（in-path/on-path、stateful/stateless、whitelist/blacklist、blocking timeline、collateral damage 容忍度）。
3. 點名三個 **disconnect**：
   - **D1**：真實 censor 攻擊的是「使用者怎麼**發現**和**設置**通道」（IDM、setup），學界卻多研究「通道**使用**中」的攻擊。
   - **D2**：真實 censor 偏好**便宜被動監測 + active probing**，學界研究的是**複雜被動分析 + 流量操控**。
   - **D3**：真實 censor **怕誤封合法流量**（不願承擔 collateral damage），學界假設的攻擊常會誤封大量正常流量。
4. 列出 **6 個 research gap**（值得當未來工作清單）。
5. 用 30+ 真實阻斷事件（Table II）為論文裡的設計選擇校準現實。

## Method

- **mining**：抓 Tor blog（747 篇）+ bug-tracker（13,337 reports，2007/12–2015/3）;用 keyword + supervised classifier 找出 censorship-related events
- **classification**：對每篇學術設計，逐行對照表（Table IV，23 goals × 74 metrics）標出他們**宣稱滿足**的指標
- **comparison**：把學術評估指標跟真實事件對齊，找出不匹配
- **inference**：當無法直接觀測 GFW 內部，採取 **conservative inference from observed effects**

## Results

- 大量 attack 集中在 **setup phase**（Table V/VI），但學術論文的 evaluation 多半 evaluate **channel usage**
- 實際 censor 用的 attack 多半是 passive（看 TLS Client Hello、看 IP 黑名單），少數 active probing；真正用 ML/統計分析的證據罕見
- 33 學術論文中只有 9 篇真正 evaluate **usability**，6 篇講 **cost to advocate**（維運成本）
- VPN Gate 案例：3 天內被 GFW 封——說明流行度本身就是 distinguisher

## Limitations / what they don't solve

- **限定範圍**：只看 channel-based circumvention 對抗 country-level censor。internal censorship、application-layer 審查、商業利益審查不在內。
- **學術文獻 cutoff 在 2015**——之後的 SS-AEAD、Trojan、VLESS、REALITY、Hysteria 全部沒涵蓋（這是十年前的 SoK，但分析框架仍適用）。
- **真實 censor 行為的觀測有偏差**：作者只看到 Tor 跟少數工具被封的事件；對 GFW 內部分類器無直接 evidence，只能 inference。
- **沒有給出「正確」的 evaluation methodology**——只指出問題、提建議。

## How it informs our protocol design

對我們研究目標**特別關鍵**——這篇定義了 Phase III 設計階段必須處理的對手模型與評估標準：

1. **Recommendation 1**: 評估必須由**目標使用者群與審查 context** 主導，不是由協議能力主導 → Part 11.1 威脅模型撰寫的核心原則
2. **Recommendation 2**: 報告其他 approach 的弱點時要給**具體 exploit**，不只是 vulnerability → 我們做 evaluation 時要寫得 GFW 級的具體
3. **Recommendation 3**: 設計者該擔心的是**通道 setup 的弱點**，不是通道 usage 的弱點 → 我們協議設計時 IDM、setup phase 的安全屬性權重要拉高
4. **D2 啟示**：設計可以**犧牲一些抗複雜分析的強度**，去換對 active probing + 便宜統計檢測的強保障——這跟 REALITY 的設計哲學完全一致
5. **D3 啟示**：協議的「**讓 censor 誤封合法流量**」屬性是真正的競爭優勢——我們協議要設計成 censor 一旦封我們就會大量誤封 HTTPS

對 **Part 9.1 GFW 研究綜述**將會以本篇為主軸論文之一。

## Open questions

- 本篇 cutoff 在 2015，**Wu et al. USENIX Security 2023** 顯示 GFW 已具備 **large-scale 實時被動全加密流量檢測**——這是否反駁了 D2「censor 偏好便宜被動」的論點？或者說「便宜」的標準在 ML 加速硬體普及後已經變了？
- 作者**完全沒提中國以外**的 active probing 證據（伊朗、俄羅斯、土耳其的 censor 是否做 active probing 仍開放）。
- D3「censor 怕 collateral damage」對中國 PSC（政治敏感期）是否成立？實際觀測顯示某些政治事件期間 censor 會大幅放寬 false positive 容忍度——這個動態學術界沒充分模型化。
- 「**長期** vs 短期 evaluation」——一個協議可能初期通過所有 known censor checks，但部署後一年才被 censor 學會檢測。我們協議的 evaluation 時間維度該怎麼設計？

## References worth following

- **Houmansadr et al.** *The Parrot is Dead: Observing Unobservable Network Communications* (S&P 2013) — 證明 mimicry-based 翻牆的根本缺陷，是 Trojan/VLESS 哲學轉向「真 TLS」的學理依據。
- **Ensafi et al.** *Examining How the Great Firewall Discovers Hidden Circumvention Servers* (IMC 2015) — GFW active probing 對 obfs2/obfs3 的研究，本門課 Part 9.6 主要參考。
- **Geddes et al.** *Cover Your ACKs: Pitfalls of Covert Channel Censorship Circumvention* (CCS 2013) — 加 ACK channel 的 covert channel 漏洞分析。
- **Khattak et al.** *SoK: Making Sense of Censorship Resistance Systems* (PoPETs 2016) — 姊妹 SoK，涵蓋 73 系統，互補本篇——本門課 Part 10.10 主要參考，已建檔。
- **Pfitzmann & Hansen** 對 unobservability/unblockability/undetectability 的形式化定義 — 我們 spec 的 security property 命名要對齊這個 vocabulary。
- 本篇 §V Table III 的 polymorphism vs steganography 二分法 — Part 11 設計時的關鍵設計空間維度。
