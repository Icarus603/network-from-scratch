# Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1
**Venue / Year**: CRYPTO 1998
**Authors**: Daniel Bleichenbacher
**Read on**: 2026-05-14 (in lesson 3.4)
**Status**: full PDF (`assets/papers/bleichenbacher-1998.pdf`)
**One-line**: 第一個「padding oracle」攻擊——用 server 對 PKCS#1 v1.5 padding 錯誤的差異化回應作 oracle，~10^6 queries 恢復 plaintext；定義整個 padding oracle attack 家族，至 2018 ROBOT 仍在 wild 存在。

## Problem
PKCS#1 v1.5 (1991) RSA encryption padding：
```
EM = 0x00 0x02 PS 0x00 M       where PS = random non-zero bytes
```

server 用此 padding 接收 client 加密的 (premaster secret in SSL/TLS 1.0-1.2)。問題：server 解密後若 padding 不合法（不是 0x00 0x02 ...），回 error。**這個 error 是 oracle**。

Bleichenbacher 證明此 oracle 足以 recover any chosen ciphertext 的 plaintext，**without ever breaking RSA**。

## Contribution
1. **Padding oracle 攻擊形式化**：對手有 ciphertext c，能向 server submit c' 並觀察「padding valid / invalid」單 bit response。目標：recover m = c^d mod n。
2. **Iterative narrowing 演算法**：
   - 對手選 s，submit c' = c · s^e mod n。
   - Server 解 m' = m · s mod n。
   - 若 m' starts with 0x00 0x02 → m · s mod n ∈ [2B, 3B) where B = 2^(8(k-2))。
   - 這給出 m 落在 narrow interval 的 information。
   - Successively choose s_1, s_2, ... narrow intervals 直到收斂單一 m。
3. **效能分析**：~10^6 queries for 1024-bit RSA。實作可行（雖 1998 看似 academic，2003 Klima 等 improve 到 ~10^4 queries）。
4. **修補建議**：
   - 改用 RSA-OAEP (IND-CCA2 secure)。
   - 或 server 強制 constant-time response（無論 padding 是否合法）。後續證明 constant-time 極難實作對。

## Method
**演算法簡述**（簡化版）：
```text
B = 2^(8(k-2))   where k = byte length of n
M_0 = {[2B, 3B - 1]}      // initial interval for m

Step 1 (blinding): 
    若 c 不一定 padding-valid, blind: 找 s_0 such that c · s_0^e gives valid padding.
    Set c' = c · s_0^e mod n, M = {m · s_0 mod n}.

Step 2 (search):
    Iterative narrowing:
    if |M_i| has many intervals:
        s_(i+1) = smallest > prev s s.t. c' · s^e is valid
        M_(i+1) = filter M_i by constraint (m · s_(i+1)) starts 0x00 0x02
    else:  // single interval [a, b]
        Use smart step (Bleichenbacher's optimization) to find next s.
    
Step 3 (converge):
    When |M| = 1 and interval narrows to single value, output m.
```

**Optimization (Klima-Pokorny-Rosa 2003)**：對 TLS context，server 對 multiple padding-related errors 可能洩 finer-grained info；reduces queries to ~10^4。

## Results
- **SSL 3.0 / TLS 1.0 RSA premaster secret 被解**：2016 DROWN attack (Aviram 等 USENIX Security 2016) 用 SSLv2 server 作 oracle 解 TLS 1.2 RSA premaster。
- **POODLE 2014** 是 padding oracle 在 CBC mode 的變體。
- **ROBOT 2018** (Böck-Somorovsky-Young, USENIX Security 2018)：Bleichenbacher 在 modern TLS server 仍 work，影響 Cisco ACE、Citrix、F5、IBM Datapower、Erlang OTP（20 年後同攻擊還在）。
- **TLS 1.3 完全廢 RSA KEX**：強制 (EC)DHE，避免任何 RSA padding oracle 風險。
- **PKCS#1 v2 (2002) 加 OAEP**：IND-CCA2 secure，不靠 server 端 padding check。

## Limitations / what they don't solve
- 假設 server 區分「padding valid」vs「padding invalid」回應。對 constant-time + 統一 error message 的 server 攻擊不成立（但實作做對極難）。
- 不直接 break RSA primitive；只是 protocol-level 攻擊。
- 需要 server 端 active oracle；purely passive 對手攻不到。

## How it informs our protocol design
- **G6 設計從根本避免任何 server-side oracle**：
  - Record layer 用 AEAD（INT-CTXT，constant-time tag verify）。
  - 解密失敗 → drop packet，**沒有任何錯誤回應給對方**。
  - 握手錯誤 → close connection with generic close_notify，不洩具體錯誤原因。
- **G6 從不用 RSA encryption**：避免任何 PKCS#1 v1.5 / OAEP misuse 風險。簽章用 Ed25519，KEX 用 X25519。
- **G6 教訓**：「padding oracle」是任何 protocol 都可能存在的攻擊面，不只 RSA。設計時必須對所有 decryption / validation step 確保「無差異化 error response」。

## Open questions
- 是否存在「constant-time padding check」的 formally verified 實作？libsodium 用 constant-time 比較，但 hardware-level timing 仍 active research。
- ROBOT-class attacks 在 modern HSM with hardware timing leakage 仍 viable？

## References worth following
- Klima, Pokorny, Rosa *Attacking RSA-Based Sessions in SSL/TLS* (CHES 2003) — Bleichenbacher 對 TLS 改進。
- Aviram 等 *DROWN: Breaking TLS using SSLv2* (USENIX Security 2016) — cross-protocol 利用 v2 oracle 打 v1.2。
- Böck 等 *ROBOT: Return Of Bleichenbacher's Oracle Threat* (USENIX Security 2018)。
- Bardou 等 *Efficient Padding Oracle Attacks on Cryptographic Hardware* (CRYPTO 2012) — HSM 環境。
