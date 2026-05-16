# Effective Attacks and Provable Defenses for Website Fingerprinting
**Venue / Year**: USENIX Security 2014（23rd USENIX Security Symposium，San Diego，pp. 143–157）。CACR 2014-05 為延伸 tech report。
**Authors**: Tao Wang（U. Waterloo）、Xiang Cai（Stony Brook）、Rishab Nithyanand（Stony Brook）、Rob Johnson（Stony Brook）、Ian Goldberg（U. Waterloo）
**Read on**: 2026-05-16（in lessons 12.X cited，protoxx shaping 的理論下界）
**Status**: full abstract + technical content via USENIX page + CACR tech report
**One-line**: 提出 k-NN 攻擊（用 weighted feature distance + hill-climbing 學權重）大幅提升 Tor WF 準確率；同時提出 **Tamaraw** 與 **Supersequence** 兩個 **provable** 防禦——首次把 WF 防禦從 ad hoc 推到「在固定 anonymity set 內可證明信息論意義上不可區分」。

## Problem
2014 年之前的 WF 攻擊（Cai 2011、Wang–Goldberg 2013）已能對 Tor 達 ~80% 準確；防禦端（Dyer 2012 BuFLO、Cai-StoryTeller）開銷大或無形式保證。需要 (a) 更強的攻擊 baseline、(b) 真的有 provable security 的防禦——後者長期是 WF 領域的空白。

## Contribution
- **k-NN 攻擊**：以 packet sequence 上的多種 feature（unique packet count、burst 長度、time-based bin counts）做加權距離度量，權重靠 hill-climbing 在 training set 上學出。比先前 SVM/edit-distance 更快、accuracy 更高、FPR 更低。
- 在大型 open-world 場景測試（client 可能訪問 attacker 不知道的網站），k-NN 仍有實用 precision。
- **Provable defense framework**：把 WF 防禦形式化為「output packet sequence 對 anonymity set 內所有 input page 一樣」——若 defense 是 deterministic 且 simulatable，則任何 attacker 在該 set 內 advantage = 0。
- **Tamaraw**：proof-of-concept 防禦，固定間隔送 fixed-size packet，session 結束後 padding 到下一個整數倍 burst。Provable WF-secure 對固定 anonymity set；overhead 比 BuFLO 小但仍重。
- **Supersequence**：cluster 所有 page 進 anonymity set，把 packet sequence 補齊到該 set 的 elementwise supersequence；overhead 隨 cluster 大小可調。

## Method (just enough to reproduce mentally)
**Attack (k-NN)**:
1. 從每條 trace 抽 ~3000 個 feature（packet count、burst stats、time bins）。
2. 用 weighted L1 距離 d(P, P') = Σ w_i |f_i(P) − f_i(P')|，權重 w_i 待學。
3. Hill-climbing: 在 training set 上，對每個 w_i 上下調整，若 leave-one-out accuracy 上升就保留。R=6000 rounds。
4. Test phase: 對 P_test 找 k 個 nearest training trace，多數決決定類別。

**Defense (Tamaraw)**:
1. Client 與 Tor 之間插一個 shaper。
2. 固定 packet 間隔 ρ_in、ρ_out。每個間隔 tick，若有真實 packet 就送、沒有就送 dummy。
3. Session 結束時 padding 到 L 的整數倍（L 為 fixed-burst 長度）。
4. 對所有 page，輸出 sequence 長度與 timing 完全由 L 與 burst count 決定 ⇒ 同 anonymity set 內不可區分。

## Results
- k-NN 攻擊：在 100-page closed-world 上 ~91% accuracy（無防禦）；在 open-world 5000 page 干擾下仍維持高 precision。
- Tamaraw：對 k-NN 攻擊 accuracy 降至接近隨機；overhead ≈ 100% bandwidth + 50% delay（對 100-page set）。
- Supersequence：trade-off 可調，cluster size 越大越安全 overhead 越大。

## Limitations / what they don't solve
- Tamaraw 的「provable」要求 anonymity set 內 page 的 sequence 真的能被一個 supersequence 覆蓋——對 dynamic content（Twitter、新聞網）覆蓋率有限。
- Overhead 對實際部署仍偏高（~100% bandwidth）。
- 不抗 DF 級 deep learning attack？這篇早於 DF；後續 Sirinam 2018 證明 Tamaraw 仍然有效（DF 對 Tamaraw 也接近隨機）。

## How it informs our protocol design
這篇給 protoxx **defense 設計的形式化模板**：
1. 任何 shaping 設計都應該定義「anonymity set」——具體是哪些行為 pattern 視為等效。
2. 「provable」要走 simulatable + deterministic 路線；adaptive padding（如 WTF-PAD）就算 indistinguishable to ML attack 也不是 provable，會被 DF 級攻擊破。
3. protoxx 的 traffic shaping module 應分兩檔：**provable 檔**（類 Tamaraw，high overhead，user 在高威脅環境 opt-in）與 **adaptive 檔**（低 overhead，default）。前者作為 fallback。
4. Overhead 量化：bandwidth × 1.5–2.0 對代理用戶可接受？這是需要 user study 的設計問題，不是純技術問題。

## Open questions
- 在 multi-tab / streaming 場景下，Tamaraw 的「session 結束」definition 不清，如何延伸？
- Provable defense 能否與 QUIC 的多 stream 結合？stream 之間獨立 shape vs 整 connection shape 是不同的 anonymity set。

## References worth following
- Dyer, Coull, Ristenpart, Shrimpton. *Peek-a-Boo, I Still See You: Why Efficient Traffic Analysis Countermeasures Fail.* IEEE S&P 2012 — BuFLO 與 WF 防禦的前作。
- Cai, Nithyanand, Wang, Johnson, Goldberg. *A systematic approach to developing and evaluating website fingerprinting defenses.* CCS 2014 — 同一團隊的形式化評估方法論。
- Sirinam, Imani, Juarez, Wright. *Deep Fingerprinting.* CCS 2018 — 證明 Tamaraw 仍然 hold，WTF-PAD 不 hold。

Source: [USENIX Security 14](https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/wang_tao), [CACR tech report PDF](https://cacr.uwaterloo.ca/techreports/2014/cacr2014-05.pdf)
