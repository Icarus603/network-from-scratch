# The Parrot is Dead: Observing Unobservable Network Communications

**Venue / Year**: IEEE Symposium on Security and Privacy (S&P) 2013, pp. 65–79. DOI: 10.1109/SP.2013.14
**Authors**: Amir Houmansadr, Chad Brubaker, Vitaly Shmatikov (The University of Texas at Austin)
**Read on**: 2026-05-14 (in lesson 0.4)
**Status**: full PDF (15 pages) at `assets/papers/ieee-sp-2013-houmansadr-parrot-is-dead.pdf`
**One-line**: 用 SkypeMorph、StegoTorus、CensorSpoofer 三個當時最新的 "parrot" 翻牆系統當靶，**證明 unobservability-by-imitation 是根本錯誤的設計哲學**——一個「parrot」要 mimic 一個複雜協議是 daunting requirement，而 censor 只要找**一個**discrepancy 就贏。直接奠定了之後 Trojan / VLESS 「不要模仿，要真的 run」 的設計轉向。

## Problem

2010 年代初的翻牆系統紛紛走 **mimicry** 路線：SkypeMorph 把 Tor 流量包裝成 Skype 視訊；StegoTorus 偽裝成 HTTP/Skype/Ventrilo；CensorSpoofer 模擬 SIP-based VoIP。所有人都假設「**只要看起來像 X 協議，censor 就會放過**」。

問題：
- 這個假設**從沒被嚴格驗證**過
- 沒有人系統定義 "look like X" 究竟需要 mimic 哪些 observable
- 三個系統的 threat model 各說各話、語焉不詳

## Contribution

1. **Adversary taxonomy**：
   - **Capability**: passive / active / proactive
   - **Knowledge**: local (LO) / state-level oblivious (OB) / state-level omniscient (OM)
2. **Mimicry requirement enumeration**——一個 parrot 要成功必須 mimic 的觀察維度（這是論文的核心 contribution）：
   - **Protocol entirety**: Correct（協議行為合規）
   - **Side-protocols**: 必須 mimic 所有並行的控制通道（VoIP 的 RTCP、Skype 的 TCP control channel、HTTP 的 cookies）
   - **IntraDepend**: 主流量與控制通道間的**動態 inter-dependency** 必須 faithful
   - **InterDepend**: 一個 protocol 觸發其他 protocol 的行為（HTTP 觸發 DNS 等）
   - **Err**: 對所有錯誤狀況的反應必須一致
   - **Network**: 對網路條件變化的反應（congestion → codec rate change 等）
   - **Content**: header / payload metadata 必須完全一致
   - **Patterns**: packet size / IPI / flow rate 統計分佈
   - **Users**: typical user behavior 需 mimic
   - **Geo**: 地理特徵（中國境內 Skype 用 TOM-Skype 不同實作）
   - **Soft**: 特定軟體實作的 quirks
   - **OS**: TCP ISN 算法等 OS-level fingerprint
3. **實證攻擊三個系統**：
   - SkypeMorph 失敗 6/9 passive Skype detection tests（Table I）
   - StegoTorus-Embed 失敗 6/9 同上
   - StegoTorus-HTTP 對 9 種 httprecon 測試**全部失敗**（Table III）
   - CensorSpoofer SIP probing 全失敗（Table IV）
4. **Active attacks**：對 hypothetical 改進版 SkypeMorph+/StegoTorus+ 也設計 6 種 active attack 全部 break unobservability（Table II）——證明**即使 fix 已知 passive attack**，active probing 仍然能識破
5. **核心 thesis**：「**Three Researchers, Five Conjectures**」精神——partial imitation 比沒有 imitation 還糟，因為 partial imitation 創造可被觀測的 discrepancy
6. **Lessons & Recommendations**：明確建議**轉向「run actual protocol，把 hidden content 藏在更高層」**——例如 FreeWave（藏在真實 Skype voice payload 裡）。這個建議**直接導致了** Trojan（藏在真實 TLS 裡）的設計哲學

## Method

### Adversary 模型化
- 三層 capability × 三層 knowledge = 9 種對手
- GFW 被 classify 為 **state-level OM with active + proactive 能力**

### Skype 詳盡逆向工程（Appendix A）
- Skype client startup, supernode discovery, NSN selection
- TCP/UDP probe sequences, packet sizes, timing patterns
- T1–T9 detection tests（HTTP update, login, SoM fields, etc.）
- 為了證明 "mimic Skype 完整" 有多難，作者必須先 reverse-engineer Skype 的所有 quirks——光這部分就佔論文 1/4 篇幅

### Experimental setup
- 真實 SkypeMorph / StegoTorus / CensorSpoofer code
- VirtualBox + VDE virtual switches with custom plugins for packet drop
- 9 種 httprecon HTTP request 測試
- SIP probing 測試 against Ekiga / PhonerLite / Blink / Twinkle

## Results

關鍵數據點（重要性對我們設計）：

1. **SkypeMorph 對 SkypeID T1**（HTTP update）：失敗——因為它沒在 startup 時連 ui.skype.com
2. **StegoTorus 對 T2**（login）：失敗——沒對 Skype login server 認證
3. **TCP control channel T9**：兩個系統**都失敗**——只 mimic UDP 通道
4. **httprecon GET non-existing**：StegoTorus 回 "200 OK"，真實 HTTP server 回 404——這是任何 fingerprinting tool 一秒就能識破
5. **StegoTorus PDF embedding**：缺 xref table——pdftotext 一跑就破
6. **Active attack: drop UDP packets** → Skype 真的 client 會 trigger TCP control channel activity（Fig 1），SkypeMorph 不會
7. **CensorSpoofer SIP probing**：對任何 IP 發 SIP INVITE，真 SIP client 會回 100 Trying / 180 Ringing / 404 Not Found，CensorSpoofer **什麼都不回**——明顯破綻

## Limitations / what they don't solve

- **2013 cutoff**：SS-AEAD、VMess、Trojan、VLESS、REALITY、Hysteria 都還沒出現
- **沒給 quantitative cost model**：「a low-cost adversary」是直覺判斷，沒精確 CPU/memory 模型
- **沒處理 collateral damage tolerance**：作者 implicitly 假設 censor 不在意誤封——後來 Tschantz 2016 / Wu 2023 發現 censor 對 collateral damage 非常敏感
- **建議的「run actual protocol」**對 latency 敏感應用（Tor browsing）沒給可行方案——FreeWave 對 web browsing 太慢
- **Decoy routing 被 dismiss 太快**——僅一段帶過，但其實是 unobservability 的另一條路（後來 Telex / Conjure 證實值得做）
- **沒區分 "mimicking deployed system" 與 "tunnelling through actual deployed system"**——這個 distinction 後來成為 Trojan / NaiveProxy 哲學分野

## How it informs our protocol design

**對 Proteus 設計的根本影響**——本篇是「為什麼我們不能走 mimicry 路線」的學理判決：

### 1. **Proteus 不能走 mimicry**

確認本門課協議目標的設計約束：
- ❌ 不模擬 Skype / WhatsApp / Zoom 等具體應用（會撞 parrot 死路）
- ❌ 不模擬 HTTP 格式但不真的處理 HTTP（StegoTorus 失敗模式）
- ✅ 必須**真的跑 TLS handshake + 真的能當 fallback HTTPS 服務**（Trojan / REALITY 路線）
- ✅ 第一個 packet 必須通過 TLS fingerprint check（Wu 2023 evidence + Parrot's IndDepend requirement）

### 2. **設計必須 enumerate 所有 observable 維度**

把本篇 §V 的 mimicry requirements 改寫成 **Proteus 的「不暴露 observable」清單**：

| 本篇 mimicry requirement | Proteus 對應 design requirement |
|---|---|
| Correct | 真實 TLS 1.3 handshake，行為完全合規 |
| SideProtocols | 處理 SNI extension lookup, OCSP stapling 等 TLS side info |
| IntraDepend | TLS handshake → record layer → ALPN 之間的依賴必須 natural |
| InterDepend | 對應 HTTP/2 的 SETTINGS、HTTP/3 的 QPACK 等需 natural |
| Err | invalid input 反應要像目標 fallback server |
| Network | RTT / loss 變化下行為要像 web server |
| Content | 訊息格式、cookie、header order、JA4 fingerprint 對齊 |
| Patterns | packet size / timing 統計分佈 |
| Users | typical user activity pattern（不是同時 1000 connections） |
| Geo | 服務器地理位置與 fallback 域名 plausible |
| Soft | 特定 web server 實作（nginx vs apache）的指紋 |
| OS | TCP/IP stack fingerprint |

每一項都需要在 Phase III 11.1 威脅模型中明確 declare 我們**如何**滿足。

### 3. **Active probing 是 first-class threat**

本篇 Table II 證明即使 hypothetically fix 所有 passive attack，**active probing 仍能 break**。所以：
- Proteus spec 必須包含 **active probing resistance**（對應 Khattak 2016 framework 的 Active Probing Resistance scheme）
- REALITY 的「**借用真實大網站握手 + fallback 給 real server**」就是對 active probing 的標準回應——本門課要繼承並強化

### 4. **「Three Researchers, Five Conjectures」**警告

本篇引用 Knockel et al. 2011 的這篇副標——研究員容易**承認某 attack 困難就忽略**。我們的威脅模型不能假設 "censor 不會做 X 因為 expensive"——必須假設 censor 會做（Wu 2023 的 GFW 已實時 ML detection 證實）。

### 5. **Threat model precision**

本篇的 capability × knowledge 二維 taxonomy 是 0.1 補遺對手分類學的擴展版。我們 Part 11.1 寫威脅模型時要直接套用：

> Our adversary is **state-level OM with active + proactive capabilities**（即 GFW 同等級）。

不能弱於這個 baseline。

## Open questions

- **2026 censor 比 2013 強多少**？本篇假設 OM censor 已是 worst case；但 Wu 2023 顯示 GFW 還在演化（增加 ML、增加 active probing system）——本篇的 baseline 是否還夠保守？
- **AI-augmented censor**：LLM 能 augment GFW 的識別能力嗎？例如自動找出 protocol implementation 的不一致？這是後 2023 的 open question
- **Mimicry 的 "death" 是否完整**？某些後來的研究（如 Geneva 用 GA 找 evasion strategies）暗示 partial mimicry 在特定狀況仍可行——但對 GFW 級對手是否成立沒共識
- **Steganography in real protocols** vs **tunnel through real protocols**：本篇 §XI 推薦後者；但前者（FreeWave、SWEET 用 voice / email payload steganography）的 capacity-vs-stealth trade-off 仍開放
- **本篇推薦的「run actual protocol」是 Trojan/REALITY 的學理基礎**——但 REALITY 走得更遠，連證書都借——這個 escalation 是否還有上限？

## References worth following

從 §X Related Work + Bibliography 摘出對我們最 relevant：

- **Pfitzmann & Hansen 2000** *A Consolidated Proposal for Terminology* — unobservability/anonymity/pseudonymity 的學界定義來源（已在 0.1 提到）
- **Houmansadr, Riedl, Borisov, Singer NDSS 2013** *I Want My Voice to Be Heard: IP over Voice-over-IP for Unobservable Censorship Circumvention* — FreeWave，本篇推薦的 alternative approach
- **Houmansadr, Nguyen, Caesar, Borisov CCS 2011** *Cirripede: Circumvention Infrastructure Using Router Redirection* — decoy routing 學理 grounded
- **Murdoch & Danezis 2005** *Low-Cost Traffic Analysis of Tor* — passive attack on Tor 的經典證明
- **Schuchard, Geddes, Thompson, Hopper CCS 2012** *Routing Around Decoys* — 對 decoy routing 的反擊（part 10 會用）
- **Winter & Lindskog FOCI 2012** *How the Great Firewall of China Is Blocking Tor* — 早期 GFW × Tor 觀測（Part 9 列為必讀）
- **Wright et al. NDSS 2009** *Traffic Morphing: An Efficient Defense Against Statistical Traffic Analysis* — packet size morphing 的早期嘗試
- **Dyer et al. 2012** *Format-Transforming Encryption (FTE)* — 模擬任意 packet format 的另一條路
- **Knockel, Crandall, Saia FOCI 2011** *Three Researchers, Five Conjectures* — 副標出處
- **TOM-Skype** 中國境內 Skype 變體（內建 surveillance）— Geo requirement 的存在性證明

## 跨札記連結

- **與 Tschantz SoK 2016**：Tschantz 把 mimicry-based research 的 evaluation 不對齊問題系統化；Houmansadr 是更早、更具體的「mimicry 為什麼根本錯」 evidence。**兩者一起讀**才完整理解 G2/G3 世代為什麼必須出現
- **與 Khattak SoK 2016**：Khattak framework 的「Mimicry (content / flow)」scheme 列出 partial / failed 評分——直接基於本篇證據
- **與 Wu et al. 2023**：本篇 2013 預言「partial mimicry 比沒 mimicry 更糟」；Wu 2023 在 GFW 真實部署上證實——SS / VMess 這些 fully encrypted protocols（partial mimicry of "random data"）反而比明文更可疑
- **與 REALITY / VLESS spec**：REALITY 的設計直接繼承本篇 §XI 「run actual protocol」recommendation——TLS handshake 不是 mimic，是借用真實 server
- **直接 inform** 本門課 Part 7.7 (Trojan)、Part 7.8–7.12 (VLESS+REALITY) 的設計理由講解
- **直接 inform** Part 11.1 威脅模型撰寫——用本篇的 capability × knowledge taxonomy 作為 baseline
- **直接 inform** Part 11.5 spec 撰寫——本篇 §V 的 mimicry requirements 變成我們 spec 的「unobservability properties」清單
