# Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice (Logjam)
**Venue / Year**: CCS 2015
**Authors**: David Adrian, Karthikeyan Bhargavan, Zakir Durumeric, Pierrick Gaudry, Matthew Green, J. Alex Halderman, Nadia Heninger, Drew Springall, Emmanuel Thomé, Luke Valenta, Benjamin VanderSloot, Eric Wustrow, Santiago Zanella-Béguelin, Paul Zimmermann
**Read on**: 2026-05-14 (in lesson 3.6)
**Status**: full PDF (`assets/papers/adrian-logjam-2015.pdf`)
**One-line**: 證明 TLS 1.2 允許 server 在 ServerKeyExchange 中送 fresh DH parameters + 允許 EXPORT ciphersuite → MitM 可降級到 512-bit DH 用 pre-computed NFS table 解 → 8.4% Top 1M HTTPS sites vulnerable; 同時警告 1024-bit DH 對國家級對手 (NSA) 可能已被破解。

## Problem
1990 年代 US 出口管制限制密碼學產品到 512-bit。TLS 1.0 spec 為了向後相容保留 DHE_EXPORT cipher。2015 年 export 限制早撤但 cipher 還在 spec 內；多 server 仍 enable。同時 Snowden 文件 (2013) 暗示 NSA 對 1024-bit DH 有特定攻擊能力。

## Contribution
1. **Logjam Attack**:
   - MitM 截 ClientHello → 改成只支援 DHE_EXPORT。
   - Server 回 ServerKeyExchange with 512-bit p。
   - Pre-computed Number Field Sieve (NFS) table on common 512-bit primes (~1 week per prime) → real-time solve DH。
   - 結果：MitM 完整解開 session。
2. **Common primes 問題**：超過 80% TLS DHE servers 用 4 個常見 512-bit primes（Apache, mod_ssl 預設）。pre-compute one prime → break millions of connections。
3. **1024-bit DH 警告**：80% of top 1M websites used 1024-bit prime；7 most-common primes covered 92%。Authors estimate $100M cost + 1 year time for academic + nation-state to pre-compute one 1024-bit prime → break ~21% of HTTPS traffic.
4. **Internet-wide scan**：證實上述比例 via census。
5. **修補建議**：
   - 廢 EXPORT ciphersuites。
   - 移到 ≥ 2048-bit DH 或 ECDH。
   - 強制 named groups (RFC 7919) 避免 server-sent custom parameters。

## Method
**Logjam pre-computation**:
1. 取目標 512-bit prime p。
2. NFS 4 phases: polynomial selection (~hours), sieving (~1 week on 千核心), linear algebra (~hours), individual log (~minutes per DH).
3. After NFS table built, breaking single DH session ~90 seconds.

**MitM downgrade**:
1. Block ClientHello, modify cipher list to only DHE_EXPORT.
2. Server returns 512-bit DH params.
3. Both client and server proceed; MitM has table → recovers premaster.
4. MitM 解 record layer (still using HMAC-SHA1 MAC + AES-CBC), can now selectively modify。

## Results
- **TLS 1.3 (RFC 8446)** 完全廢 export ciphers, 強制 named groups。
- **TLS 1.2** servers 加速 phase out DHE_EXPORT。
- **RFC 7919 (2016)** standardize FFDHE2048/3072/4096/6144/8192 groups。
- **Major browser block**：Chrome / Firefox 2015 後 reject < 1024-bit DH。
- **NSA Tailored Access Operations** documents (subsequent leaks) confirmed 1024-bit attacks。

## Limitations / what they don't solve
- 不解決所有 downgrade attack（後續 SLOTH, ROBOT, DROWN）。
- Pre-computation only viable for fixed group; ephemeral random group safe but rarely used。
- ECDH 不在 attack scope（不同 problem structure）。

## How it informs our protocol design
- **G6 硬性決定**:
  1. **Hard-code curve**: X25519 only (PQ-hybrid Kyber768)；不 negotiable。
  2. **Transcript binding**: transcript hash 必含全 ciphersuite list；任何 negotiation 結果綁進 KDF info。
  3. **Reject downgrade**: client 若見到 unexpected group/cipher，abort connection。
  4. **No EXPORT-grade fallback**: spec 內無 export / weak option（即使為相容性）。
- **G6 教訓 #1**：「Negotiation flexibility is attack surface」。Hard-code 越少越好。
- **G6 教訓 #2**：「Common parameter pre-computation」對任何 fixed-group cryptography 是真實威脅。我們選 Curve25519 (Bernstein-derived constants, no national agency influence) 部分 motivation 在此。

## Open questions
- Quantum NFS 對 RSA 與 finite-field DH 的精確 cost reduction？
- Custom-group ephemeral DH 是否能 safely 重 enable？目前 IETF 共識 否。

## References worth following
- Aviram 等 *DROWN: Breaking TLS using SSLv2* (USENIX Security 2016) — cross-protocol attack 類似 spirit。
- Bhargavan-Leurent *SLOTH: Security Losses from Obsolete and Truncated Transcript Hashes* (NDSS 2016) — 對 transcript binding 的攻擊。
- Heninger 等 *Mining your Ps and Qs* (USENIX Security 2012) — weak RNG in TLS keys。
- RFC 7919 — FFDHE named groups。
