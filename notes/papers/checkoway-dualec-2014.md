# On the Practical Exploitability of Dual EC in TLS Implementations
**Venue / Year**: USENIX Security 2014
**Authors**: Stephen Checkoway, Matthew Fredrikson, Ruben Niederhagen, Adam Everspaugh, Matthew Green, Tanja Lange, Thomas Ristenpart, Daniel J. Bernstein, Jake Maskiewicz, Hovav Shacham
**Read on**: 2026-05-14 (in lesson 3.12)
**Status**: full PDF (`assets/papers/checkoway-dualec-2014.pdf`)
**One-line**: 證明 Dual_EC_DRBG backdoor 在實際 TLS 部署中可被利用——對 RSA BSAFE-C, BSAFE-Java, Microsoft SChannel, OpenSSL-FIPS 等 library 各別 demo attack；後 Snowden 文件確認 NSA 確有 backdoor key c；移除整個 RNG 標準的可信度。

## Problem
2007 Shumow-Ferguson 在 rump session 指出 NIST SP 800-90A Dual_EC_DRBG 結構可能 backdoor: 兩個 hard-coded curve points P, Q if Q = c·P with c known, 持 c 者能 predict DRBG output。NIST 沒撤回；RSA Inc 把 Dual_EC 設為 BSAFE default (per Snowden 2013 文件，NSA $10M to RSA Inc)。

問題：理論 backdoor 是否在實際 TLS handshake 部署中 exploitable？

## Contribution
1. **完整端到端 attack demo** 對四個 library:
   - **RSA BSAFE-C v1.1 / BSAFE-Java**: Dual_EC default; attacker knows c → recover TLS premaster from session bytes。
   - **Microsoft SChannel**: Dual_EC option support; same attack。
   - **OpenSSL-FIPS**: Dual_EC option; attack works。
   - **Each TLS handshake 約 < 1 second 在普通 hardware**。
2. **Implementation-specific exploitability**：每個 library DRBG 使用方式不同 (reseed frequency, output bytes per call, additional input mixing) 影響 attack effort。RSA BSAFE 最 vulnerable, MS SChannel 中等, OpenSSL-FIPS 稍難但仍 feasible。
3. **Juniper ScreenOS 災難 (2015)**: 後續發現 Juniper 自家 firewall ScreenOS 用 Dual_EC + 自選 Q point (而非 NIST 默認); 2012-2013 期間有 unauthorized actor 替換了 Q → 持 c 之外的 actor 可 decrypt VPN traffic。Juniper 2015-12 公開 advisory。
4. **影響**:
   - NIST 2014-04 正式撤回 Dual_EC_DRBG。
   - RSA Inc 2013-09 停 default。
   - 各 library 移除 Dual_EC support。
   - 整個 NIST 公信力受打擊；後續 PQ 標準化過程更 transparent。

## Method (high-level)
**Dual_EC backdoor mechanism**:
```text
DRBG state: s ∈ E(F_p)
Per call:
    next_state = (s * P).x  (using x coordinate)
    output = (next_state * Q).x  (truncated)

If Q = c · P with attacker knows c:
    output_observed → some point R_o with R_o.x = output (recover full point by trying few candidates)
    R_o = next_state * Q = next_state * c * P = c * (next_state * P)
    So: c^(-1) * R_o = next_state * P = next state itself!
    Attacker recovers internal state from output → predict all future output.
```

**TLS attack**:
- TLS server uses Dual_EC for: server random, premaster (RSA pad), ephemeral DH share, IV。
- Attacker observes TLS handshake; sees server random (sent in clear)。
- Apply backdoor: server random → internal state → predict premaster → decrypt session。
- Tricky in practice: implementation may reseed or mix extra entropy. Attack 必須 reverse-engineer specific library's DRBG usage。

## Results
- 公開 demo 每個 library 約 < 1 sec attack。
- NIST 撤回 Dual_EC。
- Juniper ScreenOS 後續事件 (2015) 印證 nation-state actor 可實際 leverage。
- 整個 industry 對 NIST-pushed 算法 + magic constants 提高警惕。
- 後續 NIST PQ project 大幅提升 transparency (open submission, public Round 1-4 evaluation)。

## Limitations / what they don't solve
- 不證明 NSA 是 backdoor 持有者（雖然 Snowden 強烈暗示）。
- 不普遍化到其他 NIST-standardized algorithms (NIST curves P-256/P-384/P-521 是否 backdoor 仍 controversial)。
- 後續 ScreenOS 災難證明: 即使官方 backdoor 持有者控管，**也可被別人替換**。

## How it informs our protocol design
- **G6 不用 NIST P-curves**: 部分動機就是 Dual_EC 事件後對 NIST-pushed constants 的不信任。用 Curve25519 (Bernstein 公開 derivation)。
- **G6 RNG 必須**: no magic constants; 用 OS getrandom() not custom DRBG with embedded constants。
- **G6 spec 內 「nothing-up-my-sleeve」principle**: 任何 spec 中的 constant 必須 derivable 從 public process (SHA-256 of "G6 v1 nonce 1" 等)。
- **G6 教訓 #1**: 「Trust but verify」對 standards bodies 同樣適用。NIST 不是 immune to compromise。
- **G6 教訓 #2**: PQ migration 過程必須 fully transparent — 否則重蹈 Dual_EC 覆轍。

## Open questions
- **NIST P-curves backdoor possibility**: 雖無證據 backdoor，但 P-curves seeds (SHA-1 of unexplained "Wsigma" string) source 仍 controversial。
- **Other potential cryptographic backdoors in deployed systems**: 仍可能 undiscovered。
- **Standards body governance reform**: post-Snowden cryptographic standards 流程是否充分？

## References worth following
- Shumow-Ferguson *On the Possibility of a Back Door in the NIST SP800-90 Dual_EC_DRBG* (rump talk 2007) — 原 backdoor disclosure。
- Snowden documents on NSA Bullrun (2013) — context。
- Wertheimer *The Dual EC story* (NSA-related disclosure) — internal NSA perspective。
- Juniper ScreenOS advisory (2015-12) — backdoor 被竊用 incident。
