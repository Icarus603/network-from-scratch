# On the Security of Public Key Protocols
**Venue / Year**: IEEE Transactions on Information Theory, Vol. 29, No. 2, March 1983（preliminary FOCS / SFCS 1981）
**Authors**: Danny Dolev, Andrew Chi-Chih Yao
**Read on**: 2026-05-14 (in lesson 3.1)
**Status**: abstract-only（HuJI 站當前 down／503；IEEE Xplore paywall；CMU 的 mirror URL 未通；引用內容綜合自訓練資料、Semantic Scholar abstract、ACM DL 摘要）
**One-line**: 1983 年定義了「對手控制整個網路（讀、寫、刪、重排、注入），但不能破密碼學原語」這個 protocol-level 對手抽象——後世稱 Dolev-Yao Model；ProVerif、Tamarin、所有 symbolic verification 工具的根基。

## Problem
1980 年代早期，公鑰加密剛被發明（Diffie-Hellman 1976、RSA 1977），但「protocol-level 安全」沒人知道怎麼定義。Needham-Schroeder 1978 給了第一個著名公鑰認證 protocol，但後來 Lowe 1995（17 年後！）才發現缺陷。當時根本沒有對手模型可以讓你**證明**或**反駁**一個 protocol 的安全性。

## Contribution
1. **網路對手模型 (Dolev-Yao adversary)**：
   - 對手 = 整個網路
   - 對手能：截聽任何訊息、修改、刪除、重排、注入新訊息
   - 對手能：模擬任何身份（除了被攻擊的 honest party）
   - 對手**不能**：解開未知 key 加密的 ciphertext、偽造 signature 沒有對應 sk、預測 fresh nonce
2. **Symbolic / Term-rewriting 抽象**：把密碼學原語當「黑盒 perfect」——加密 = 一個 function symbol；要解密必須有對應 key 的 function symbol。對手在 term rewriting 系統內推 derivation。
3. **可決定性結果**：對 cascade protocol、ping-pong protocol，作者證明 secrecy 是 polynomial-time decidable。對更一般 protocol class，secrecy 是 undecidable（後續工作如 Even-Goldreich 1985 補上）。
4. **影響整個 formal verification 領域**：ProVerif、Tamarin、Maude-NPA、Scyther 全部以 Dolev-Yao model 為基礎。

## Method
**Dolev-Yao 對手能力的形式化**（直觀版）：

```text
對手 A 的知識集 K_A 從 initial knowledge 開始（A 自己的 keys + 公鑰目錄）。
對任何訊息 m 在通道上：
    K_A := K_A ∪ {m}

A 能做的 derivation 規則：
    1. pair: x, y ∈ K_A ⇒ <x, y> ∈ K_A
    2. unpair: <x, y> ∈ K_A ⇒ x ∈ K_A, y ∈ K_A
    3. encrypt: x ∈ K_A, k ∈ K_A ⇒ {x}_k ∈ K_A
    4. decrypt: {x}_k ∈ K_A, k^-1 ∈ K_A ⇒ x ∈ K_A
    5. sign: x ∈ K_A, sk ∈ K_A ⇒ Sign_sk(x) ∈ K_A

問題：給定 protocol 與 honest party 互動，A 最終能否 derive 出某個 secret s？
```

**Symbolic vs Computational gap**：Dolev-Yao 把 crypto 當黑盒；現實的 crypto 是 computational（可機率破，但 negligible）。後續 Abadi-Rogaway 2002 *Reconciling Two Views of Cryptography* 試圖橋接兩個 view。CryptoVerif (Blanchet 2008) 提供 computational sound 的 symbolic tool。

## Results
- 為整個 protocol verification 領域提供基礎模型。
- Lowe 1995 用 FDR 在 Dolev-Yao 模型下找到 Needham-Schroeder 缺陷（17 年後！）。
- ProVerif (Blanchet 2001+) 把 Dolev-Yao 自動化，現在仍是 IETF spec 採用的 verification 工具（TLS 1.3、Noise、MLS 都有 ProVerif 模型）。
- Tamarin (Meier-Schmidt-Cremers-Basin 2013) 用 Dolev-Yao + multiset rewriting 證明更複雜協議（Signal、5G AKA 等）。

## Limitations / what they don't solve
- **Symbolic abstraction 太強**：把所有 crypto 當 perfect black box。實務攻擊（padding oracle、fault injection、side-channel）在 Dolev-Yao 模型下看不到。
- **No probabilistic reasoning**：computational 攻擊（如 birthday）在 symbolic model 不可表示。
- **No timing**：許多 attack 依賴 timing，Dolev-Yao 抽象掉時間。

## How it informs our protocol design
- **Proteus 形式化驗證用 ProVerif（symbolic）+ CryptoVerif（computational）雙軌**：
  - ProVerif：證明 secrecy / authenticity / forward secrecy 在 symbolic model（Part 11.10）。
  - CryptoVerif：證明 IND-CCA2 + EUF-CMA 的 computational reduction（Part 11.11）。
- **Proteus 的 implementation 需另外處理 Dolev-Yao 抓不到的攻擊**：
  - Constant-time impl（Part 3.13 / Part 12.2）。
  - Side-channel resistance test（Part 12.16）。
  - Fuzzing（Part 12.8）。

## Open questions
- Symbolic-computational gap 的全自動橋接？目前要 manual lifting。
- 量子 Dolev-Yao：對手有量子算力，符號模型如何擴充？
- Dolev-Yao + IND-CCA decryption oracle 的整合 framework，仍 active。

## References worth following
- Lowe *An Attack on the Needham-Schroeder Public-Key Authentication Protocol* (Information Processing Letters 1995) — Dolev-Yao 模型下找出 Needham-Schroeder 缺陷的經典工作。
- Blanchet *An Efficient Cryptographic Protocol Verifier Based on Prolog Rules* (CSFW 2001) — ProVerif 的開山。
- Abadi, Rogaway *Reconciling Two Views of Cryptography (The Computational Soundness of Formal Encryption)* (Journal of Cryptology 2002) — symbolic-computational 橋接。
- Meier, Schmidt, Cremers, Basin *The TAMARIN Prover for the Symbolic Analysis of Security Protocols* (CAV 2013) — Tamarin。
