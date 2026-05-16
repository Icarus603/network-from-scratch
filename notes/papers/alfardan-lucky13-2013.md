# Lucky Thirteen: Breaking the TLS and DTLS Record Protocols
**Venue / Year**: IEEE Symposium on Security and Privacy 2013
**Authors**: Nadhem J. AlFardan, Kenneth G. Paterson
**Read on**: 2026-05-14 (in lesson 3.13)
**Status**: full PDF (`assets/papers/alfardan-lucky13-2013.pdf`)
**One-line**: 對 TLS 1.0-1.2 CBC + HMAC mode 的 timing attack——server 處理 padding vs MAC 錯誤的時間差 (~13 cycles, "Lucky 13") 作為 padding oracle, ~10^7 measurements 可解 plaintext bytes；驅動 TLS 1.3 全廢 CBC、強制 AEAD。

## Problem
TLS 1.0-1.2 RFC 8446 之前 默認 cipher suite 用 CBC mode + HMAC-SHA1/256，MAC-then-Encrypt structure (Bellare-Namprempre 2000 generic 不安全; Krawczyk 2001 specific 安全 if constant-time impl)。Vaudenay 2002 padding oracle 已警告。POODLE 2014 後續。Lucky 13 是 timing-based padding oracle 在 modern TLS server 仍 work 的具體 demo。

## Contribution
1. **Timing-based padding oracle on TLS-CBC**: 
   - Server decrypt → check padding → verify MAC。
   - If padding invalid: MAC computed over **fewer bytes** (no padding strip), 略快。
   - If padding valid but MAC invalid: MAC computed over **correct** length, 略慢 (~13 cycles)。
   - Attacker measure: 哪個 case → narrow padding。
2. **Plaintext recovery**:
   - For target ciphertext block c_target with last byte plaintext = ?:
   - Flip bits in preceding IV/cipher block, generate forged messages, observe server response timing。
   - ~10^7 measurements → 一個 plaintext byte recovered。
3. **In-the-wild scope**:
   - Test against OpenSSL, NSS, GnuTLS, BouncyCastle, Java JSSE, Microsoft SChannel, OS X SecureTransport, PolarSSL, Apple Common Crypto, IBM RACF。
   - 全部 vulnerable to some variant。
4. **修補 (interim)**: constant-time decryption code path that always processes the same length regardless of padding validity。但每 library 都得各自 patch。

## Method
**Setup**:
- TLS-CBC frame:
  ```
  IV ‖ Enc(plaintext ‖ MAC(plaintext) ‖ padding)
  ```
- Padding: PKCS#7-like; final byte indicates padding length。

**Attack**:
1. Attacker injects (e.g., via JavaScript) target plaintext into HTTPS request (cookie, password)。
2. Target ciphertext block c_target containing unknown plaintext byte。
3. Attacker constructs forged ciphertext: replace preceding IV/block bits, send to server。
4. Server decrypts → padding error or MAC error。
5. Time measurement: ~13-cycle difference reveals which。
6. Statistical analysis over millions of measurements: narrow down candidate plaintext byte。

**Optimization**: 用 multiplexing many TLS sessions; multiprocessing；statistical aggregation。

## Results
- 在 LAN 環境內 attack 在 hours 內成功。
- **OpenSSL, NSS, Java JSSE 等 immediate patch**：constant-time decrypt path。
- **Web browsers 部分緩解 by 拒絕 connection if cipher suite is CBC + old TLS**。
- **TLS 1.3 (RFC 8446) 完全廢 CBC, MAC-then-Encrypt, 強制 AEAD**.
- **Influenced TLS 1.2 best practice**: prefer GCM / ChaCha20-Poly1305 over CBC。

## Limitations / what they don't solve
- 需要 multiple measurements (~10^7) — practical 但非 instant。
- 假設 attacker 可 trigger many TLS connections to same server with same plaintext (BEAST-style)。
- Constant-time patch 後不再 vulnerable，但 patch 在 1990s-2000s legacy systems 緩慢部署。

## How it informs our protocol design
- **Proteus 全 AEAD record layer**：直接避免 CBC + MAC-then-Encrypt 整類風險。
- **Proteus 任何 server-side validation 必 constant-time**：
  - AEAD tag verify constant-time (libsodium / golang `crypto/subtle`)。
  - Sequence number validation constant-time。
  - Replay window check constant-time。
- **Proteus protocol-level error response 統一**:
  - 解密失敗 → silent drop, no response。
  - 握手錯誤 → 統一 close_notify, no error code 區分。
- **Proteus 教訓**: 「decrypt then validate」是 risk pattern；AEAD 是 single-step decrypt-and-verify，inherently safer。

## Open questions
- **Network-level timing measurement granularity**: with RTT ~ms vs cycle difference ~ns, 多少 measurements 才能 distinguish? Network jitter 是 attacker's enemy 但 statistical 仍 viable。
- **Other oracle-like patterns in protocol design**: 任何 multi-step validation 都可能洩 information。系統性 audit framework？
- **Spectre-class oracles in TLS implementations**: speculative execution path 可能 leak even with constant-time intent。

## References worth following
- Vaudenay *Security Flaws Induced by CBC Padding* (EUROCRYPT 2002) — padding oracle 形式化。
- Duong, Rizzo *BEAST attack* (2011) — TLS CBC chosen-boundary。
- POODLE (Möller-Duong-Kotowicz 2014) — SSL 3.0 padding oracle。
- DROWN (Aviram 等 USENIX Security 2016) — SSLv2 oracle 打 TLS 1.2。
- TLS 1.3 RFC 8446 — AEAD-only 設計 motivation。
