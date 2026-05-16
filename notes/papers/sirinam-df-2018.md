# Deep Fingerprinting: Undermining Website Fingerprinting Defenses with Deep Learning
**Venue / Year**: ACM CCS 2018（25th ACM Conference on Computer and Communications Security）
**Authors**: Payap Sirinam（RIT）、Mohsen Imani（U. Texas Arlington）、Marc Juarez（KU Leuven / imec）、Matthew Wright（RIT）
**Read on**: 2026-05-16（in lessons 12.X cited，protoxx shaping 設計的對手模型）
**Status**: abstract + key results via arXiv 1801.02265 + CCS proceedings；full PDF accessible
**One-line**: 用一個約 8 層 1D-CNN（受 VGG 啟發）直接吃 Tor cell direction 序列，把 website fingerprinting 攻擊從「靠手工特徵 + 機器學習」推到「end-to-end deep learning」，並首次破解 WTF-PAD 防禦。

## Problem
Website fingerprinting (WF) 是 local passive eavesdropper（ISP、Wi-Fi AP、GFW）對 Tor / VPN 用戶看 packet 長度 / 方向序列，反推訪問了哪個網站的攻擊。在 DF 之前，state-of-the-art 是 Wang 2014 的 k-NN、Hayes 2016 的 k-FP、Panchenko 2016 的 CUMUL——這些都依賴手工特徵 + SVM / Random Forest。同時防禦端推出了 WTF-PAD（Juarez 2016，自適應 padding）、Walkie-Talkie（half-duplex + padding），號稱能破壞特徵。問題：deep learning 能不能 (a) 不靠手工特徵，(b) 突破這些「最強」的低開銷防禦？

## Contribution
- 提出 **Deep Fingerprinting (DF)**：一個專為 WF 設計的 1D-CNN，輸入是 Tor cell direction 序列（每 cell 標 +1 / −1），輸出是 monitored 網站類別。
- 證明 **WTF-PAD 不安全**：DF 在 WTF-PAD 防禦下達 ~90% closed-world accuracy（先前攻擊最多 ~60%）。這是第一個有效擊穿 WTF-PAD 的攻擊。
- 確認 **Walkie-Talkie 仍可抵禦**：DF 對 WT 只能達 ~49.7%（≈ 隨機）。對 protoxx 是強訊號：half-duplex + decoy 才是真正有效的 shape。
- 開源 dataset + 模型，後續成為 WF research 的 baseline。

## Method (just enough to reproduce mentally)
- **Input representation**: 每條 trace 是長度 5000 的 ±1 序列（不足 padding 0，超過截斷）。**只用 direction，不用 timing 與 size**——這也是 Tor 的最低資訊量假設。
- **Architecture**: 8 個 conv block（每 block 兩個 1D-conv + batchnorm + ReLU + max-pool + dropout），filters 從 32 增至 256，kernel size 8。最後接 2 個 fully-connected layer + softmax。約 7M 參數。
- **Loss & training**: cross-entropy，Adam optimizer，dropout 0.1–0.5，batch normalization。每類 ~800 trace（closed-world），訓練 30 epochs。
- **Defended traces 訓練**: 對 WTF-PAD / Walkie-Talkie 各重新訓練（不是 zero-shot transfer），代表「攻擊者已知防禦演算法」這個強對手假設。

## Results
- **Closed-world, 無防禦**: 98.3% accuracy（95 個 monitored sites × 1000 trace）。
- **WTF-PAD**: 90.7%——首次有效擊穿，論文這個 number 直接讓 Tor 社群放棄 WTF-PAD 部署。
- **Walkie-Talkie**: 49.7%——defense 仍然有效。
- **Open-world**（5000 個非 monitored sites 為干擾）: 無防禦時 precision 0.99 / recall 0.94；WTF-PAD 下 precision 0.96 / recall 0.68。

## Limitations / what they don't solve
- 強假設：攻擊者擁有大量已標記訓練資料、用戶 browsing 是單一 page、無 multi-tab。
- 對「concept drift」（網站改版、CDN 變動）幾天就會明顯衰減，需要持續重訓。
- 不涵蓋 Walkie-Talkie 那類強防禦——意味著「夠好的 shape 仍然能擋」。

## How it informs our protocol design
DF 是 protoxx **shape model 的 baseline 對手**：任何 shaping 設計（adaptive padding、constant rate、burst-mimicry）都必須在 DF 級的攻擊下評估。具體：
1. 我們的 traffic shaping module（adaptive shaping）要在 Part 12 的 evaluation harness 裡跑 DF attack，accuracy 若 > 60% 就必須回設計桌。
2. Walkie-Talkie 的 half-duplex 思路（client 與 server 不同時送）值得借鑑，但延遲懲罰大，可能需要 selective application（只在 sensitive frame 上用）。
3. DF 用 direction-only 還能達 98% ⇒ 任何只動 packet size、不動 direction pattern 的 shape 等於沒做。

## Open questions
- 對「multi-tab / multi-page」場景，DF 衰減多少？實際用戶 traffic 是否仍可被分類？
- Transformer-based WF attack（Bahramali 2023 等）是否進一步降低對防禦的容忍度？

## References worth following
- Juarez, Imani, Perry, Diaz, Wright. *Toward an efficient website fingerprinting defense.* ESORICS 2016（WTF-PAD 原論文，被 DF 擊穿）。
- Wang, Goldberg. *Walkie-Talkie: An efficient defense against passive website fingerprinting attacks.* USENIX Security 2017。
- Rahman, Sirinam, Mathews, Gangadhara, Wright. *Tik-Tok: The utility of packet timing in website fingerprinting attacks.* PoPETS 2020 — DF 後續，加入 timing。

Source: [arXiv:1801.02265](https://arxiv.org/abs/1801.02265), [ACM CCS 2018 DL](https://dl.acm.org/doi/10.1145/3243734.3243768)
