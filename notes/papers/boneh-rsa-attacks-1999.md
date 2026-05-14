# Twenty Years of Attacks on the RSA Cryptosystem
**Venue / Year**: Notices of the American Mathematical Society, Vol. 46, No. 2, February 1999
**Authors**: Dan Boneh
**Read on**: 2026-05-14 (in lesson 3.4)
**Status**: full PDF (`assets/papers/boneh-rsa-1999.pdf`)
**One-line**: RSA 1978-1998 二十年攻擊的權威綜述——分四類（factoring, small e/d, padding, implementation），對每類給歷史 + 代表性 attack；現代 protocol designer 必讀，了解「RSA 不是黑盒」。

## Problem
1998 年 RSA 已部署 20 年，期間累積大量攻擊：Wiener (small d), Coppersmith (small message), Hastad (broadcast), Bleichenbacher (padding oracle), Boneh-DeMillo-Lipton (fault on CRT), Kocher (timing)。學界與工業界都需要一份 unified survey 知道「RSA 在現代正確用法是什麼」。

## Contribution
1. **四類攻擊框架**：
   - **Elementary attacks**：basic blunders (common modulus, blinding without verify, low private exponent)。
   - **Low private exponent attacks**：Wiener 1990 (d < n^(1/4))；Boneh-Durfee 1999 (d < n^0.292)。
   - **Low public exponent attacks**：Hastad broadcast、Coppersmith partial-known-plaintext、Franklin-Reiter related-message。
   - **Implementation attacks**：Timing (Kocher 1996)、Fault (Boneh 1997)、Bleichenbacher padding oracle (1998)。
2. **每類給「攻擊條件 + 修補方式」對應**。
3. **強烈警告 textbook RSA**：給數個未加 padding 的 RSA 應用設計反例。
4. **影響 PKCS#1 v2 設計**：Boneh 是 OAEP / PSS 的支持者，本論文間接推動 PKCS#1 從 v1.5 升級到 v2.0+。

## Method (representative attacks)
**Wiener 1990 (small d)**：給 (n, e), continued fraction expansion of e/n 給出 candidates for d/k. 若 d < n^(1/4), 其中一個 candidate 就是 (d, k)。

**Coppersmith 1996 (small root)**：給 polynomial f(x) mod n of degree d，可在 polynomial time 找所有 x_0 with |x_0| < n^(1/d) and f(x_0) ≡ 0 mod n。應用：RSA with e=3 加密 stereotyped message 可恢復。

**Hastad broadcast**：sender 用 e=3 把同 m 送 3 個不同 RSA pub key (n_1, n_2, n_3)。對手用 CRT 在 mod n_1 n_2 n_3 重組 m^3，cube root 恢復 m。

**Bleichenbacher 1998 padding oracle**：見 3.4 lesson 詳述。

**Boneh-DeMillo-Lipton 1997 fault**：若 CRT decryption 中產生 fault，從 (σ, σ') 用 GCD(σ - σ', n) 恢復 p。**RSA-CRT 必須有 fault detection**。

**Kocher 1996 timing**：modular exponentiation 時間依賴 d 的 bits；測 decrypt 時間能 leak d。修補：RSA blinding (multiply by random r^e 再 multiply 結果 by r^-1)。

## Results
- **PKCS#1 v2.0 (1998)** 加 OAEP。
- **PKCS#1 v2.1 (2002)** 加 PSS。
- **TLS 1.2 (2008)** 仍允許 PKCS#1 v1.5 → ROBOT 2018 證明歷史 bug 仍 viable。
- **TLS 1.3 (2018)** 廢 RSA KEX，強制 RSA-PSS for signature。
- 影響所有後續 public-key protocol 設計：**永遠不在 attacker-observable 處洩 decryption error**。

## Limitations / what they don't solve
- 只到 1998。後續 BB attacks 變體（DROWN 2016、ROBOT 2018）需另外讀。
- 不深入 quantum (Shor 已知但 1999 quantum hardware 不存在)。
- 不涵蓋 RSA blind signature (Chaum) 等 advanced variants。

## How it informs our protocol design
- **G6 設計時用此論文作為「不要重複歷史錯誤」checklist**：
  - ✗ Never use textbook RSA。
  - ✗ Never use PKCS#1 v1.5。
  - ✗ Never trust server padding error indication leak。
  - ✗ Never use small e=3 with stereotyped messages。
  - ✗ Never share RSA primes across devices（Heninger 2012 IoT）。
  - ✗ Never CRT without fault detection。
  - ✓ Always use OAEP for encryption / PSS for signature。
  - ✓ Always blind modular exponentiation。
  - ✓ Always constant-time impl with regular memory access。
- **G6 cert 處理**：必能 reject 任何 RSA cert with d < n^0.292 (Boneh-Durfee bound)。
- **G6 RNG 要求**：強 OS RNG 避免 Heninger-class shared-prime attack。

## Open questions
- 是否存在 sub-exponential factoring algorithm beyond GNFS? 仍 open。
- Lattice-based factoring (Schnorr 2021 撤回工作) 是否能改進到 polynomial？
- Quantum cost of factoring 2048-bit RSA 精確 estimate 仍在收斂。

## References worth following
- 後續更新：Boneh, Joux, Nguyen *Why Textbook ElGamal and RSA Encryption Are Insecure* (ASIACRYPT 2000)。
- Bellare 等 *PKCS #1 RSA Encryption Standard* 演化系列。
- Heninger 等 *Mining your Ps and Qs* (USENIX Security 2012)。
- Aviram 等 *DROWN* (USENIX Security 2016)。
- Böck 等 *ROBOT* (USENIX Security 2018)。
