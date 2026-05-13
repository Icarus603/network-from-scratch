# Distributed Practice in Verbal Recall Tasks: A Review and Quantitative Synthesis

**Venue / Year**: Psychological Bulletin 132(3), 354–380, 2006. DOI: 10.1037/0033-2909.132.3.354
**Authors**: Nicholas J. Cepeda (UCSD + UC Boulder), Harold Pashler (UCSD), Edward Vul (UCSD), John T. Wixted (UCSD), Doug Rohrer (USF)
**Read on**: 2026-05-14 (in lesson 0.2)
**Status**: full PDF (27 pages) at `assets/papers/psychbull-2006-cepeda-distributed-practice.pdf` (read pp. 1–15 in detail; remaining is appendix tables of individual studies + references)
**One-line**: Meta-analysis of **839 distributed-practice assessments** across 184 papers — establishes that **optimal Inter-Study Interval (ISI) increases with retention interval (RI)**, and any spacing > massing for retention > 1 min.

## Problem

「Spacing effect」（分散練習贏 massed 練習）是教育心理學最 robust 的發現之一，1885 年 Ebbinghaus 就觀察到。但**一個世紀後仍無實用 prescriptive guidance**：
- 給定要記到 1 個月後，最佳 ISI 是多少？1 天？1 週？1 個月？
- ISI 跟 RI 的 joint effect 從沒被嚴格量化
- 既有 4 篇 meta-analysis 結論互相矛盾

實務上**不知道該間隔多久**，就無法把 spacing effect 用在課程設計、語言學習、技能訓練。

## Contribution

1. **839 accuracy assessments** + **317 experiments** + **184 papers**——是 distributed practice 領域**史上最大** meta-analysis
2. 確認 **spacing effect 全面成立**：271 比較中只 12 個無效或反向，所有 RI bin 都顯著（Table 1）；總體 spaced 47.3% vs massed 36.7%（t(540) = 6.6, p < 0.001）
3. **發現 nonmonotonic ISI effect** — 對於固定 RI，ISI 從 0 增加 retention 也增加，**但過了 optimal 後反而下降**（inverse-U）；先前 meta-analysis 都漏了這個
4. **發現 optimal ISI 隨 RI 增加而拉長** — 經驗 rule of thumb 約 **optimal ISI ≈ 10–20% of RI**（Table 7）：
   - RI = 6 days → optimal ISI ≈ 1 day
   - RI = 30 days → optimal ISI ≈ 7 days
   - RI = 360 days → optimal ISI ≈ 14–28 days
   - RI = 2900 days (~8 years) → optimal ISI ≈ 30 days
5. **Expanding ISI 沒比 fixed ISI 顯著好**（Table 8: 62.0% vs 58.6%, p = 0.61）—— 推翻流行的 expanding spaced repetition 假設
6. **明確識別了 distributed practice theory 的 gap**：deficient processing theory 跟 encoding variability theory 都無法完全解釋 ISI × RI 交互效應

## Method

- **Inclusion criteria**：verbal recall task only（list/paired-associate/cued-recall/sentence/text/spelling/picture/category recall），≥ 2 learning episodes，可從 published data 計算 accuracy difference
- **Coding**：把 ISI、RI、accuracy 從每篇 paper 抽出（時間單位統一成 days，1 min = 0.000694 days）
- **三種 lag analysis**：
  - **Difference lag**：configurations differing in ISI 直接 pairwise 比較
  - **Absolute lag**：bin by absolute ISI 看 retention 模式
  - **Within-study lag**：同一篇 study 內部 across ISI 的 maximal-retention ISI
- **Effect size**：Cohen's d，corrected for SD computation issues + within-subject correlation

## Results

關鍵 finding 整理（與 Phase III 學習 schedule 直接相關）：

1. **總體 spacing**：spaced 47.3% > massed 36.7%（+10.6 percentage points across all RI）
2. **長 RI 下差距更大**（Table 1）：
   - RI 1–59s: spaced 50.1% vs massed 41.2%（+9 pp）
   - RI 31+ days: spaced 39% vs massed 17%（+22 pp）
3. **最強 finding**：**ISI difference of 1 day** 對 RI 1 day 有最大 retention 差異（Fig 4: effect size ~1.2 at RI=1 day）
4. **Long-term studies (Table 7)**：RI > 1 month 時 optimal ISI 是 weeks~months
5. **Bahrick & Phelps 1987 經典案例**：RI = 2900 days 時，ISI=30 days 的 final test 表現是 ISI=1 day 的 ~2x（15% vs 8%）

## Limitations / what they don't solve

- **Verbal recall only** — 結論不一定移植到 procedural skill / conceptual knowledge / problem solving（Rohrer & Taylor 2007 補上 procedural mathematical 部分）
- **Lab settings** — 真實課程環境的 noise（學生動機、社會互動）沒模型化
- **Theory still contested** — 兩個競爭理論（deficient processing vs encoding variability）都被質疑，**作者明說**新理論需要
- **Expanding ISI 結論基於 22 比較** — sample 不夠 robust，作者承認 needs further research
- **No interaction with task difficulty** — 容易 vs 困難 task 的 spacing 最佳劑量是否不同？沒分析

## How it informs our protocol design

**對 0.2 策略 C（混合動力版）給出量化基礎**——學習 schedule 設計可以從 hand-wave 升級成 evidence-based:

### 1. **學習 schedule 量化 prescription**

對本門課（目標：1.5–3 年完成 + 長期 retention 5+ 年）：

| 我們的目標 RI | 從 Cepeda 表得出的 optimal ISI |
|---|---|
| 1 週（self-check 隔週重做） | ~1 天 |
| 1 個月（每月期末 review） | ~7 天 |
| 1 年（畢業後仍記得） | ~14–28 天 |
| 5+ 年（永久研究 capital） | ~30+ 天 |

具體建議：
- **Self-check 問題**：寫完一堂後 1 天再做一次（強化 ISI=1day, RI=1week）
- **跨 Part review**：每 2 週回頭做之前所有 Part 的 self-check 抽樣
- **每月「總複習」**：對前一個月所有 lesson 的核心 claim 各寫一句話
- **evergreen notes 重訪**：每 1–3 個月 grep 自己之前的 evergreen notes，刻意重讀，正是 ISI ~30 days

### 2. **避免 "expanding spaced repetition" 工具盲信**

Anki / SuperMemo 的 expanding interval 流派沒比 fixed interval 強——對我們這種**自學者**反而 fixed weekly review 可能更可靠（lower scheduling overhead）。

### 3. **長 RI 下差距更大** = 投資複利

從 +10pp 到 +22pp 的差距：你越想長期記得，spacing 投資的 ROI 越高。Phase III 設計階段如果發現「Phase I 的某個基礎概念忘了」，那就是當初 spacing 投資不夠的具體後果。

### 4. **不是只 inform 個人學習，也 inform 我們協議的「測試 protocol」**

Phase III 12.13 對抗評測時：
- 一次性 benchmark（lab benchmark）vs spaced 多週 deployment 的差距會放大
- 我們協議的 anti-fingerprinting 在 1 hour 內看不出問題，1 個月後 GFW ML detector 可能已經 retrain 識別出來
- **建議 test protocol 包含 30+ 天 spaced re-evaluation**，不只是 t=0 的 baseline

## Open questions

- **AI advisor + spaced repetition** 的最佳整合？Claude 永遠在，是降低 spacing 的必要性（隨時可問）還是加強（隨時可被 quizz）？
- **Procedural skill** (e.g. 寫 Go code) 跟 verbal recall 的 spacing optimal 不同——本論文沒覆蓋。Phase III 程式 implementation 階段該怎麼間隔練習？
- **Massed initial learning + spaced review** vs **always spaced**：哪個更省時？實務上初學階段往往 mass, 然後再 space——這個混合策略的 evidence?
- **Cross-domain spacing**（學 cryptography 跟學 networking 交錯）vs **within-domain spacing**（cryptography 內部不同子題交錯）——effect size 差別？

## References worth following

論文最有用的 forward reference 有：

- **Ebbinghaus 1885/1964** — 整個 spacing effect 領域的源頭
- **Bahrick, H. P. (1979)** + **Bahrick et al. (1993)** — long-term retention 經典 longitudinal studies (RI = years)
- **Bjork, R. A. (1994, 1988)** — desirable difficulties theoretical framework
- **Pashler, H. (2007)** *Enhancing learning and retarding forgetting* — Cepeda 同 lab 的同年延伸論文
- **Rohrer & Taylor (2007)** — 已建檔，本門課直接借用
- **Glenberg & Lehmann (1980)** — earliest joint ISI × RI study, Table 7 列在 long-RI 中

## 跨札記連結

- **與 Rohrer & Taylor 2007**：Cepeda 提供 spacing 的 quantitative synthesis（百倍規模），Rohrer-Taylor 提供 mathematical procedural 的具體案例 + interleaving 補充。**兩者合讀** = 我們學習 schedule 的完整 evidence base
- **與 Schwartz 2008**：spacing 的 desirable difficulty 是 Schwartz productive stupidity 的學習機制版本——感覺 forget 了是 spacing 在 work
- **與 Hamming 1986**：Hamming 的「knowledge compounds」機制 = spacing 重訪 evergreen notes 的累積效應
- **與 Keshav 2007**：Keshav 三遍法的 second pass 完成寫精讀札記後，**1 週 + 1 月 + 6 月** 各 grep 一次 = 對論文知識本身做 spacing
- **直接 inform** lesson 0.2 §1 「研究級補遺」第一節 — 補正 Rohrer-Taylor 引用時應同步引 Cepeda 給 quantitative 量化
- **直接 inform** lesson 0.2 §2 策略 C：四線並行的 inter-study interval 不該太短（< 1 day），也不該太長（> 1 week），sweet spot 大概 2–3 天一次跨線切換
