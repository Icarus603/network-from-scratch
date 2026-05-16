# Encrypted Key Exchange: Password-Based Protocols Secure Against Dictionary Attacks
**Venue / Year**: IEEE Symposium on Security and Privacy (S&P / Oakland) 1992
**Authors**: Steven M. Bellovin, Michael Merritt
**Read on**: 2026-05-14 (in lesson 3.9)
**Status**: full PDF (`assets/papers/bellovin-eke-1992.pdf`)
**One-line**: PAKE 的 origin paper——首次提出「用 password 做金鑰交換，passive observer 不能 offline dictionary attack」的 EKE 構造；雖然原始 EKE 後續發現 subtle bug，但設計思想奠定 PAKE 整個領域，影響 SPAKE2 / SRP / OPAQUE。

## Problem
1992 年 password authentication 主流是：client 送 H(password) 或 H(password ‖ salt) 給 server。問題：
- 對 passive observer 錄下 hash → offline dictionary attack。
- 對 active MitM → easily impersonate。
- 即使加 challenge-response (CHAP), passive observer 仍 dictionary-attack。

Bellovin-Merritt 問：能不能用 password 派生 session key 但 password 本身不 leak (即使 entropy 低)?

## Contribution
1. **EKE 基本構造**:
   ```text
   Setup: shared password p (low entropy)
   Choose: large prime q, generator g.
   A: x ← random; X = g^x mod q; C_A = Enc_p(X); send C_A
   B: y ← random; Y = g^y mod q; C_B = Enc_p(Y); send C_B
   A: X' = Dec_p(C_B)^x = g^{xy};   K = KDF(X')
   B: Y' = Dec_p(C_A)^y = g^{xy};   K = KDF(Y')
   Confirm via challenge-response:
   A: C_1 ← random nonce; send Enc_K(C_1)
   B: receive, decrypt; send Enc_K(C_1, C_2); etc.
   ```
2. **「Encryption hides DH share」核心 insight**: passive observer 看 C_A, C_B 都是 ciphertext。要 dictionary-attack: 對 candidate p_i 解密得 X_i = Dec_{p_i}(C_A)。但 **X_i 對任何 p_i 都是 valid-looking group element**（隨機分布的 group element） → 對手無法 distinguish 對的 p_i。
3. **Multiple variants**:
   - EKE with DH (above)。
   - EKE with RSA。
   - Augmented EKE (A-EKE) — predecessor of SRP / OPAQUE 概念。

## Method (full security argument 直觀)
**Passive observer adversary**:
```text
View: (C_A, C_B)
For each candidate p_i:
    X_i = Dec_{p_i}(C_A)
    Y_i = Dec_{p_i}(C_B)
    If X_i, Y_i are valid group elements (in subgroup, correct order),
        p_i is a candidate match.
```

**問題**: Encryption Enc_p must be such that Dec_p(random ciphertext) gives random plaintext **regardless of p**. Otherwise dictionary-attack 可看 「Dec 後是否 well-formed」。

**初始 EKE 缺陷**:
- 早期版本用 normal block cipher (DES) for Enc_p。對 DH share = element in Z_q^*, DES output 是 64-bit string，但 not all 64-bit strings 對應 valid Z_q^* element。對手 dictionary-attack 可看 「Dec output 是否 ≤ q」 → narrow down p.
- Patcoh: select encoding such that all 64-bit strings 對應 group elements (e.g., use group order specifically chosen)。

**後續 PAKE 改進**:
- SPAKE2 (Abdalla-Pointcheval 2005): 用 masking constants M, N 而非 encryption → 避免 EKE encoding 問題。
- SRP (Wu 1998): augmented variant, server 不存 plain password。
- OPAQUE (2018): pre-computation resistant augmented PAKE。

## Results
- **EKE patent (Bellcore)** 1990s-2010s 拖延部署。
- **概念性奠基**: 後續所有 PAKE 都引用此 paper。
- **EKE 變體部署有限** (主要因 patent)。後續 SPAKE2 / SRP / OPAQUE 取代。
- **IEEE S&P 1992 paper 引用 1000+** — high-impact foundational work。

## Limitations / what they don't solve
- **Encoding issues**: original EKE 用 DES 編碼 DH share 有 issue, 後續多年才完全解決。
- **Lack of formal model**: 1992 沒 BPR-style PAKE model；後續 (BPR 2000) 才補。
- **No augmented version in original paper**：augmented PAKE 概念在 1990s 後續延伸。
- **Patent encumbrance**：Bellcore patent 阻 deployment。

## How it informs our protocol design
- **Proteus 不直接用 EKE** (過時)；用 OPAQUE。
- **Proteus 教訓 #1**：「passive observer 不能 dictionary attack」是 PAKE 的本質保證——任何 Proteus PSK-from-passphrase mode 必達此 baseline。
- **Proteus 教訓 #2**：encoding details 是 cryptographic implementation 中的 silent killer——必須 group element vs byte string 對應關係嚴格 well-defined（這影響 Proteus Elligator2-disguised ephemeral pk 設計）。

## Open questions
- **EKE 在 post-quantum setting 是否仍 viable**? Encryption-based encoding 對 PQ KEM 結構不直接適用。
- **EKE variants for emerging architectures** (TEE, secure enclaves) 仍 evolving。

## References worth following
- Bellovin-Merritt *Augmented Encrypted Key Exchange* (CCS 1993) — 後續加 augmented variant。
- Bellare-Pointcheval-Rogaway *AKE Against Dictionary Attacks* (EUROCRYPT 2000) — 第一個 formal PAKE model。
- Abdalla-Pointcheval *Simple Password-Based EKE Protocols* (CT-RSA 2005) — SPAKE2 origin。
- Wu *SRP* (NDSS 1998) — augmented PAKE deployment。
