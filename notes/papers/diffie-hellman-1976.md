# New Directions in Cryptography
**Venue / Year**: IEEE Transactions on Information Theory, Vol. IT-22, No. 6, November 1976
**Authors**: Whitfield Diffie, Martin E. Hellman
**Read on**: 2026-05-14 (in lesson 3.1)
**Status**: full PDF (`assets/papers/diffie-hellman-1976.pdf`)
**One-line**: 公鑰密碼學的 manifesto——首次提出無預共享金鑰的金鑰交換、公鑰加密與數位簽章的概念框架，定義了密碼學從工藝到科學的轉折點。

## Problem
1976 年的密碼學依賴**預先用安全通道分發的對稱金鑰**。在新興的 teleprocessing networks（早期 ARPANET）這意味著：
- N 個使用者要兩兩通訊需要 O(N²) 個 pre-shared key。
- 互不認識的雙方無法臨時建立加密通道。
- 沒有「數位簽章」對應實體世界的「親筆簽名 + 不可否認性」。

## Contribution
論文做了三件事，每一件都開創一個子領域：

1. **公鑰加密 (Public-Key Cryptosystem) 概念**：定義一對 (E, D) 使得從 E 反推 D「computationally infeasible」（原文用 10^100 instructions 比喻）。E 可以公開發布；只有持有 D 的人能解密。提出但**沒有給出**具體建構（一年後 RSA 完成）。
2. **公鑰金鑰交換 (Diffie-Hellman Key Agreement)**：給出第一個具體建構。Alice、Bob 公開選 prime p、generator α；A 送 α^a mod p、B 送 α^b mod p；雙方都能算出 K = α^(ab) mod p；對手只看到 α^a 和 α^b，從中解出 K 的問題（**Computational Diffie-Hellman, CDH problem**）被推測為難。**安全性歸約**到 Discrete Logarithm Problem (DLP)。
3. **數位簽章 (Digital Signature) 概念**：定義「只有 sk 持有者能產生、所有 pk 持有者能驗證」的訊息標記。提出 trapdoor one-way function 是數位簽章的數學基礎。

## Method (just enough to reproduce mentally)
DH 金鑰交換的完整 protocol：

```text
公開參數：(prime p, generator α of Z*_p)

Alice                          Bob
─────                          ───
a ← random in [1, p-1]
A := α^a mod p
                ─── A ───>
                                b ← random in [1, p-1]
                                B := α^b mod p
                <─── B ───
K := B^a mod p                 K := A^b mod p
        // K = α^(ab) mod p
```

**安全性論證骨架**（直觀，非 formal proof）：對手在通道上看到 (p, α, A, B)。要推 K = α^(ab) 等價於解 CDH。CDH 至少跟 DLP 一樣難（解 DLP 從 A 反推 a 後就能算 K = B^a）。1976 年沒有 sub-exponential DLP 演算法（後來 Number Field Sieve 把 DLP 從 exp 拉到 sub-exp，但仍 sufficiently hard for large p）。

**這個 protocol 沒有認證**——對手做 Man-in-the-Middle 把 (A → A', B → B') 替換掉雙方就分別跟對手建立 session，這是後續 SIGMA / TLS / Noise / WireGuard 都要解決的問題。Diffie-Hellman 自己在 paper 末尾承認此漏洞。

## Results
- 開創公鑰密碼學整個領域；1977 年 RSA、1985 年 ElGamal、後續整個 CRYPTO/EUROCRYPT 學界都建立在這篇論文上。
- DH 金鑰交換**至今仍是 TLS 1.3、IPsec IKEv2、Signal、SSH、WireGuard 的核心**——只是把 multiplicative group 換成 elliptic curve group（X25519, X448）。
- **2015 年 ACM Turing Award** 頒給 Diffie & Hellman，正是因為這篇論文的長期影響。

## Limitations / what they don't solve
- **沒有具體公鑰加密建構**：trapdoor function 概念給了，但沒建。1977 RSA 才補上。
- **沒有認證**：MitM 漏洞自己提了但沒解。STS (1992) → SIGMA (2003) → SIGMA-I → TLS 1.3 才完整解決。
- **沒有 forward secrecy 概念名稱**：但 ephemeral DH 的雛形已經在這裡（每個 session 用新的 a, b）；正式 PFS 概念由 Diffie-Oorschot-Wiener 1992 給出。
- **DLP 假設**：1976 論文假設 DLP 對 1000-bit prime 安全。實際上 Number Field Sieve（Joux 2014 等）讓 1024-bit DLP 在國家級資源下可破；現代 IKE 必須 ≥ 2048-bit MODP 或改用 ECDH。
- **量子脆弱**：Shor 1994 演算法讓 DLP 在量子電腦上 polynomial-time 可解；後 PQ 時代 DH 必須跟 Kyber 等做 hybrid（NIST FIPS 203）。

## How it informs our protocol design
- **Proteus 必須用 ephemeral DH 達成 PFS**：直接繼承 DH 1976 的 ephemeral key 概念。
- **Proteus 用 X25519**：橢圓曲線版本的 DH，安全性對應 ECDLP。Bernstein 2006 設計，prime 2^255-19。
- **Proteus 必須做 hybrid PQ**：X25519 + ML-KEM-768。原因：DH 1976 的 DLP 假設在量子時代失效，但 Kyber 的 LWE 假設（目前認為）量子安全。
- **Proteus 必須認證 DH**：SIGMA-I 結構（簽章綁定 transcript），避免 DH 1976 自己承認的 MitM 漏洞。

## Open questions
- 「post-quantum DH」是否存在 group-theoretic 的優雅構造？目前 NIST PQ KEM 都是 lattice/code-based，不是 group-based。
- DH 在多方場景的 generalization（GDH, Group Key Exchange）效能與安全的最佳權衡仍是 active research（Cohn-Gordon-Cremers-Dowling-Garratt-Stebila *A Formal Security Analysis of the Signal Messaging Protocol*, EuroS&P 2017 等）。

## References worth following
- 1977 RSA paper — 第一個具體公鑰加密。
- 1985 ElGamal — 把 DH 反向用作加密。
- 2015 RFC 7748 (X25519/X448) — 現代橢圓曲線 DH 標準。
- 2003 Krawczyk SIGMA — 認證版 DH 的權威 design。
- 2024 NIST FIPS 203 (ML-KEM) — DH 的後量子替代。
