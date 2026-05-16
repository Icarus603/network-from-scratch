# Post-Quantum TLS Without Handshake Signatures (KEMTLS)
**Venue / Year**: CCS 2020（ACM SIGSAC Conference on Computer and Communications Security，November 2020，DOI 10.1145/3372297.3423350）。IACR ePrint 2020/534。
**Authors**: Peter Schwabe（Radboud / MPI-SP）、Douglas Stebila（U. Waterloo）、Thom Wiggers（Radboud）
**Read on**: 2026-05-16（in lessons 12.X cited，protoxx PQ handshake 設計）
**Status**: full content via cryptojedi.org / kemtls.org / Cloudflare blog + IACR ePrint metadata
**One-line**: 把 TLS 1.3 的「server 用 signature 證明身分」改成「server 用 KEM 證明身分」（implicit authentication via long-term KEM），用 IND-CCA KEM 取代 PQ signature；handshake 流量比 PQ-signed TLS 1.3 小 ~39%、server CPU cycles 少 ~90%。

## Problem
TLS 1.3 server authentication 走 signature 路線。NIST PQC round-3 中，PQ signature（Dilithium、Falcon、SPHINCS+）的 public key + signature 大小遠大於 PQ KEM（Kyber、SIKE）的 pk + ciphertext。直接把 ECDSA 換成 Dilithium，handshake 會膨脹 KB 級——對 mobile / lossy 網路是真實的 deployability 阻礙。問題：能不能用便宜的 KEM 取代昂貴的 signature 做身分認證？

## Contribution
- 提出 **KEMTLS**：用 long-term KEM (KEMs) 做 server authentication，而非 signature。Server 的 certificate 裡是 KEM public key，client 對它做 encapsulation，能解開 ciphertext 即「隱式」證明持有對應 secret key。
- 兩個 KEM 角色：**KEMe**（ephemeral，前向保密）與 **KEMs**（static，server identity）。可分別選不同算法做 trade-off。
- 在 standard model 下做 reductionist proof（沿用 Dowling–Fischlin–Günther–Stebila 的 Multi-Stage 框架）：KEMTLS Multi-Stage-secure，前提是 H 抗碰撞、HKDF 是 PRF、HMAC 安全、KEMe IND-CPA、KEMs IND-CCA。
- 實測：使用 Kyber-512 / SIKEp434 / NTRU 等 instantiation，與 Dilithium / Falcon / SPHINCS+ signed TLS 1.3 相比，handshake bytes 從 3035 降至 1853（−39%），server CPU −90%（消除 PQ-sign）。
- 開源實作：基於 Rustls + PQClean + Open Quantum Safe。Cloudflare 後續用 Go 的 crypto/tls fork 做端到端 deployment 實驗。

## Method (just enough to reproduce mentally)
Handshake（server-only auth，比 TLS 1.3 多半個 RTT 完成 server auth、其餘相同）：

1. **Phase 1（ephemeral KE）**：Client → ClientHello(pk_e, r_c)。Server → ServerHello(ct_e ← Encaps(pk_e), r_s)。雙方解出 ss_e，HKDF 出 handshake key。
2. **Phase 2（server identity via KEM）**：Server 用 handshake key 加密送 certificate（內含 pk_s）。Client 對 pk_s 做 Encaps，得到 (ct_s, ss_s)，把 ct_s 加密送回。Server 用 sk_s 解出 ss_s。
3. 雙方把 ss_e || ss_s 餵進 HKDF 派生 application traffic secret。
4. Client 在 ss_s 取得後就可送加密 application data；server 第一個 application byte 比 TLS 1.3 晚半個 RTT（這是主要 trade-off）。

關鍵：server 沒做 signature，只是「能解 ct_s」的能力本身就構成 authentication——標準的 IND-CCA KEM 已蘊含這個性質。

## Results
- **Bandwidth**: level-1 配置下，PQ-signed TLS 1.3 最少 3035 bytes；KEMTLS 1853 bytes（−39%）。傳統 RSA+ECDH 1376 bytes 做對照。
- **Server CPU**: 用 Kyber-512 為 long-term KEM 時，server 端 cycles 相比 Dilithium-signed TLS 1.3 減少 ~90%。
- **Client first-flight**: server-only auth 場景下 KEMTLS client 與 TLS 1.3 一樣可在 1-RTT 後送 application data。
- 安全性：在 standard model 下證明 Multi-Stage secure；後續 Tamarin 形式化驗證也通過。

## Limitations / what they don't solve
- Server 第一個 application byte 比 TLS 1.3 晚半 RTT——對 server-push 重的應用是延遲懲罰。
- Long-term KEM 在 CA 簽發層需要新 X.509 OID 與 CT log 支援，目前仍是 IETF draft（AuthKEM）路線。
- 0-RTT resumption、client authentication 機制需要額外設計（paper 附錄 C 有描述但未完全形式化）。
- 抵抗 KEM-binding attack（Cremers et al. 2021）需要實作小心：必須是 IND-CCA 而非僅 IND-CPA。

## How it informs our protocol design
protoxx 的 PQ 路線就是 **X25519+ML-KEM-768 hybrid KEM + KEMTLS-style implicit auth**，這篇就是直接 blueprint。我們：
1. 採 hybrid KEM 為 KEMe（X25519 ⊕ ML-KEM-768），同時抗 classical & PQ 對手；
2. server identity 用 ML-KEM-1024（更保守）做 KEMs，避免 PQ signature 的尺寸與 side-channel 成本；
3. 把 KEMTLS 的 Multi-Stage 證明結構搬到我們的 handshake，標明哪些 HKDF label 對應哪個 stage key——這直接餵給 Part 11 的 Tamarin/ProVerif 模型。
4. server first-flight 延遲半 RTT 在 proxy 場景 (TCP/QUIC fallback) 可接受，因為 proxy 本來就不 server-push。

## Open questions
- KEMTLS 對 ECH (Encrypted Client Hello) 的整合：client public key 仍然會 leak SNI-class 資訊，是否要與 ECH 在同一個 ClientHello？
- 在 lossy network（Hysteria2 場景）下，多半 RTT 的 handshake 是否會被 GFW 的 probe-and-block 利用？

## References worth following
- Celi, Hoyland, Stebila, Wiggers. *A tale of two models: formal verification of KEMTLS via Tamarin.* ESORICS 2022 — 形式化驗證 KEMTLS。
- Bos et al. *Post-quantum key exchange — A new hope.* USENIX Security 2016 — Kyber 前身，KEMTLS 的 KEM 候選之一。
- Cremers, Düzlü, Fiedler, Fischlin, Janson. *BUFFing signature schemes beyond unforgeability.* IEEE S&P 2021 — KEM binding / authentication 細節。

Source: [eprint.iacr.org/2020/534](https://eprint.iacr.org/2020/534), [kemtls.org](https://kemtls.org/), [Cloudflare blog](https://blog.cloudflare.com/kemtls-post-quantum-tls-without-signatures/)
