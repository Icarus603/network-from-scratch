# A Digital Signature Scheme Secure Against Adaptive Chosen-Message Attacks
**Venue / Year**: SIAM Journal on Computing, Vol. 17, No. 2, April 1988（preliminary version FOCS 1984）
**Authors**: Shafi Goldwasser, Silvio Micali, Ronald L. Rivest
**Read on**: 2026-05-14 (in lesson 3.1)
**Status**: full PDF (`assets/papers/gmr-signature-1988.pdf`)
**One-line**: 提出 EUF-CMA（Existential Unforgeability under Chosen-Message Attack）的金科玉律定義，並給出第一個僅基於 standard cryptographic assumption（claw-free trapdoor permutation）就 EUF-CMA-secure 的數位簽章方案——讓「簽章」從工藝走進可證明安全。

## Problem
1980 年代之前，數位簽章都是基於某個 *ad hoc* 構造（Rabin、Lamport one-time signature 等）。沒有人精確定義過「對手能贏的最強條件 vs 最弱目標是什麼」。實務上 RSA-textbook 簽章已存在但其「安全性」是含糊的——對手能不能挑訊息？能挑多少？要偽造**新訊息**還是**舊訊息的新簽章**？這些都沒講清楚。

## Contribution
1. **Adaptive Chosen-Message Attack (CMA) 定義**：對手 A 拿到 pk 後，可以**任意挑** m_1, m_2, ... 並向 signing oracle 詢問 σ_i = Sign(sk, m_i)。每次詢問後都能根據前面的結果決定下一個 m_{i+1}（adaptive）。
2. **Existential Unforgeability (EUF) 定義**：A 贏的目標是**任意**有效對 (m\*, σ\*)，只要 m\* 沒被詢問過。「Existential」強於「universal」（對手只需找到**一個**新訊息能簽，不需要對所有訊息都能簽）。
3. **EUF-CMA = 兩者結合**：現代簽章標準的最低門檻。
4. **第一個達成 EUF-CMA 的方案**：基於 claw-free trapdoor permutation。Tree-based 構造，每簽一次更新簽章鏈。後續 RSA-PSS、ECDSA、EdDSA、Schnorr-ROM、BLS 都以 EUF-CMA 為標準。
5. **嚴格 strong unforgeability 區分**：sUF-CMA 要求對手不能偽造**任何**新對 (m\*, σ\*)，即使 m\* 已被詢問過但 σ\* 是新的。

## Method (just enough to reproduce mentally)
EUF-CMA game：
```text
Game EUF-CMA(A):
    1.  (sk, pk) ← KGen(1^n)
    2.  Q ← {}                            // queried set
    3.  oracle Sign(m): Q ← Q ∪ {m}; return σ ← Sign(sk, m)
    4.  (m*, σ*) ← A^{Sign}(pk)
    5.  return [Vrfy(pk, m*, σ*) = 1 AND m* ∉ Q]
Adv^EUF-CMA(A) := Pr[Game returns 1]
```

**GMR 88 構造（簡化版）**：
- KGen 產生 trapdoor permutation pair (f, f^-1) 與 hash chain root r。
- Sign(m) 走一條 binary-tree path，每節點用 f^-1 produce signature sub-component；新訊息逐步 extend tree。
- Verify(m, σ) 用 f 沿 tree 重算到 root，比對。

**為什麼 textbook RSA 不是 EUF-CMA**：對手可以用 multiplicativity (s_1 · s_2 mod N) 偽造新簽章——若 σ_1 = m_1^d, σ_2 = m_2^d，則 σ_1·σ_2 = (m_1·m_2)^d 是 m_1·m_2 的有效簽章。修補方式：先 hash 再簽（Full Domain Hash, Bellare-Rogaway 1996）或加 padding（PSS, Bellare-Rogaway 1996）。

## Results
- EUF-CMA 至今仍是 NIST FIPS 186 簽章標準的 nominal 安全目標。
- 2012 年 Goldwasser, Micali 共獲 Turing Award，這篇論文是引文之一。

## Limitations / what they don't solve
- GMR 88 構造效率低（tree-based、stateful），實務不採用。後續 Cramer-Damgård 1996、ROM-based RSA-PSS 等是 deployment 主流。
- 沒涵蓋 multi-key / multi-user。Bellare-Boldyreva 2002 補。
- 沒涵蓋 fault attack / side-channel（簽章演算法的 ECDSA 在 RNG bias 下會洩 key——Bleichenbacher 2000、PS3 hack 2010）。

## How it informs our protocol design
- **Proteus 簽章必須 EUF-CMA + sUF-CMA**：選 Ed25519，因 EdDSA 設計上自帶 sUF（deterministic + canonical encoding）。
- **若選 ECDSA 必須加 anti-malleability**：例如 enforce low-s（BIP-66 比特幣方式）或加 transcript hash binding。
- **絕不 textbook RSA**：必用 RSA-PSS（若要選 RSA），但 Proteus 預設不用 RSA。

## Open questions
- Strong adaptive existential unforgeability 在量子 oracle (Q-EUF-CMA, Boneh-Zhandry 2013) 是否所有現有 PQ 簽章都達成？ML-DSA (Dilithium) 在 Q-EUF-CMA 的證明仍 active。

## References worth following
- Bellare, Rogaway, *The Exact Security of Digital Signatures: How to Sign with RSA and Rabin* (EUROCRYPT 1996) — RSA-FDH / PSS。
- Bernstein, Duif, Lange, Schwabe, Yang, *High-speed high-security signatures* (CHES 2011 / JCEN 2012) — Ed25519。
- Boneh, Lynn, Shacham, *Short Signatures from the Weil Pairing* (ASIACRYPT 2001) — BLS。
- Cramer, Damgård, *New Generation of Secure and Practical RSA-Based Signatures* (CRYPTO 1996) — practical EUF-CMA without ROM。
