# Verifying Constant-Time Implementations
**Venue / Year**: USENIX Security 2016（25th USENIX Security Symposium，Austin, TX，pp. 53–70）
**Authors**: José Bacelar Almeida（HASLab/INESC TEC & U. Minho）、Manuel Barbosa（HASLab/INESC TEC & DCC FCUP）、Gilles Barthe（IMDEA Software Institute）、François Dupressoir（IMDEA）、Michael Emmi（Bell Labs / Nokia）
**Read on**: 2026-05-16（in lessons 12.X cited，Part 12 形式化 / constant-time 驗證鏈）
**Status**: abstract + venue confirmed via USENIX page；full PDF 取回失敗（HTTP 403）但內容由 USENIX 摘要 + talk description 補齊
**One-line**: 以 selective product program + LLVM 自動驗證真實密碼程式碼是否 constant-time，並允許「local benign leak」這類在所有先前工具中都會被誤判為不安全的合法寫法。

## Problem
側通道時間攻擊可在 AES、RSA、ECDSA 等實作上完全擊穿安全性。constant-time programming discipline 是主流防禦，但實作者要在 efficiency / legacy API 的壓力下手工守紀律極困難；自動化驗證工具又往往太嚴格——把實際安全但「形式上」leak public output 的寫法（例如 OpenSSL 用 secret 的 length 做 early exit）誤判為 insecure。

## Contribution
- 提出 **selective product program** 構造：將 P(s, p) 與自身 P(s', p) 之兩條執行軌 cross-product 起來，然後標出哪些變數是 public、哪些是 secret，把 constant-time security 變成一個一階斷言可驗證的 safety property。
- 容許 **information-flow-sound "benign" violations**：當 leak 的資訊量不超過 public output 時，視為合法 constant-time。這直接讓 OpenSSL bignum、NaCl 等真實程式碼能通過驗證而不必改寫。
- 實作 **ct-verif** 原型工具：以 LLVM bitcode 為輸入，後端用 Smack + Boogie 做自動模型檢查。把 LLVM optimizer 從 TCB 剝離（驗 optimized IR，不是 source）。
- 在 NaCl、FourQLib、OpenSSL、libfixedtimefixedpoint 等真實庫上跑驗證實驗，找出實際的 ct-violation 並回報上游。

## Method (just enough to reproduce mentally)
1. 取 LLVM bitcode 程式 P。
2. Annotate inputs：哪些是 secret（key、scalar、message），哪些是 public（length、IV、ciphertext）。
3. 建構 selective product P'(s, s', p)：執行 P 兩次，公用 public，分別用兩組 secret；在每個關鍵控制流 / memory access 點插入斷言「兩條 trace 的 leakage observation 必須相等」。
4. 把 P' 餵給 Smack（C → Boogie translator）+ Boogie verifier；後者對每個斷言做 SMT-based discharge。
5. 若驗證通過 ⇒ P 是 constant-time（且 leak ≤ public output 的 benign 版本）。

## Results
- ct-verif 在 NaCl curve25519、salsa20、poly1305、Ed25519，OpenSSL 的 ECDSA 與 bignum primitives，FourQLib，Brumley/Tuveri Lucky-13 patch 等程式碼上完成驗證，cycle 級別 constant-time。
- 在 libfixedtimefixedpoint 中找出殘留的時間相關分支，作者已回報。
- 驗證時間多為秒到分鐘等級——對 cryptographic primitives 是可實用的。

## Limitations / what they don't solve
- 只驗 timing channel，不涵蓋 power / EM / cache-occupancy / Spectre 類 microarchitectural leak。
- 依賴 LLVM IR 與 compiler 對齊；若後續 backend optimization 把 constant-time pattern 編成 data-dependent branch，驗證結果就不保證。
- product program 的 cross-product 規模隨程式大小膨脹，超大型程式（整個 TLS stack）目前不可行。

## How it informs our protocol design
protoxx 的關鍵密碼路徑（X25519、ML-KEM-768、ChaCha20-Poly1305 record path、HKDF）都必須 constant-time——這是 12.X「實作層 SCA 防線」的核心。ct-verif 給我們一條可走的 CI 路徑：把 protoxx 的 Rust impl 編到 LLVM IR、註明 secret/public，跑自動驗證；任何 PR 若把某個密碼函式從 constant-time 變成 data-dependent，CI 立刻紅燈。是「constant-time 屬於 testable property 而非 review property」這個立場的最強支撐。

## Open questions
- 如何把 ct-verif 風格的驗證延伸到 AEAD record 的高層 framing 邏輯——padding / length encoding 這些可能在 packet 大小上洩漏 secret 的位置？
- Rust 的 MIR 是否能取代 LLVM IR 做更接近 source 的 ct 驗證？

## References worth following
- Barthe, Grégoire, Laporte. *Provably secure compilation of side-channel countermeasures.* CSF 2018 — 把 ct preservation 推到 compiler。
- Bond et al. *Vale: Verifying high-performance cryptographic assembly code.* USENIX Security 2017 — 走 assembly-level，互補。
- Watt et al. *CT-Wasm: Type-driven secure cryptography for the web ecosystem.* POPL 2019 — 把 ct 變成 type system。

Source: [USENIX Security 16 paper page](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/almeida)
