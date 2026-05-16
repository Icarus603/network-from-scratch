# Mining your Ps and Qs: Detection of Widespread Weak Keys in Network Devices
**Venue / Year**: USENIX Security 2012
**Authors**: Nadia Heninger, Zakir Durumeric, Eric Wustrow, J. Alex Halderman
**Read on**: 2026-05-14 (in lesson 3.12)
**Status**: full PDF (`assets/papers/heninger-pq-2012.pdf`)
**One-line**: 掃描全 IPv4 HTTPS / SSH server 發現 5.57% 共用 keys, 0.5% TLS hosts share RSA primes — GCD pair 立刻 factor；揭示嵌入式 device weak RNG 為大規模 cryptographic disaster；Proteus IoT 部署設計教訓。

## Problem
2010-2011 年 Heninger 觀察：許多嵌入式 device (routers, printers, VoIP) 在 first boot 時立刻 generate cryptographic key (SSH / TLS cert)。問題：boot 時 entropy pool 可能未 seeded — 多個 device 可能用 similar seed 產生 similar keys。

## Contribution
1. **Internet-wide scan** (2011): 掃描 HTTPS port 443 + SSH port 22 公網 IPv4. 收集 ~12.8 million public RSA keys + ~10 million DSA keys。
2. **Empirical findings**:
   - **5.57% TLS hosts share keys** (完全相同 cert)。
   - **0.5% TLS hosts share RSA primes** — 用 GCD(N_1, N_2) = p → factor both. 影響 ~30,000 unique hosts。
   - **2.69% SSH hosts share keys**。
   - **0.03% SSH DSA keys** with repeated nonces → DLP-solve direct attack。
3. **Root cause identification**:
   - **Linux kernel entropy pool 在 boot 早期 unseeded**。
   - Embedded device (routers, printers) 在 boot 後 10-60 sec 立即 generate key。
   - 多個同 model device 在類似 boot phase → 相同 entropy estimate → 相同 keys 或 share primes。
4. **Manufacturers identified**: Cisco, Juniper, Citrix, Allied Telesis, IronPort, Dell iDRAC, HP iLO, Trendnet routers, Fortinet appliances 等。
5. **修補 push**: Linux kernel adjustments to delay key gen until entropy sufficient; mfg notified to fix。

## Method
**Scan**:
- ZMap / Nmap-based public IPv4 scan (with rate limiting + opt-out).
- For each HTTPS / SSH host, fetch public key.

**Analysis**:
- **Identical keys**: sort by key value; cluster duplicates.
- **Shared primes**:
  - For all pairs (N_1, N_2) of distinct moduli, compute GCD(N_1, N_2).
  - If GCD > 1 (non-trivially)：shared prime found → factor。
  - Pairwise GCD too expensive (n²); use **Bernstein's batch GCD algorithm** O(M(N) log N)。
- **Repeated DSA nonces**: scan signatures with identical r value (per-signature ephemeral nonce). Detected in real-world DSA-using SSH server.

## Results
- **30,000 weak TLS hosts factored** in single scan。
- **Linux kernel changes**: 不准 KGen until entropy pool seeded; getrandom() syscall (2014, kernel 3.17) blocks at boot until 256-bit entropy.
- **Embedded mfg responses**: gradual firmware updates to add jitter entropy daemon, defer key gen, use TPM where available.
- **公開 factorable database** (factorable.net) 持續更新。
- **影響 NIST SP 800-90B (2018)** — entropy source standards。

## Limitations / what they don't solve
- 只看 RSA (factoring-detectable)。對 ECC keys 無類似 detection method（沒有 shared-curve weakness 對應）。
- 不檢測 keys 從 backdoored RNG (Dual_EC_DRBG-style) 出來。
- 後續 IoT 持續出新 weak key generators (smart TV, IoT sensor)。

## How it informs our protocol design
- **Proteus IoT deployment 必須**：
  - 等候 OS entropy seeded (getrandom blocking 模式) 再做 KGen。
  - Embedded mfg 必須 burn unique factory-time seed (with TPM if available)。
  - Spec 內定義 entropy compliance check; client refuses to start if entropy unavailable。
- **Proteus IoT 邊側 testing**：spec 包含 conformance test 驗 RNG 不 trivially weak。
- **Proteus 教訓 #1**: RNG 災難常發生在 deployment 早期；spec 必須 explicit RNG requirement，不只是 "use secure RNG"。
- **Proteus 教訓 #2**: 公開掃描+factor 是 detection 與 mitigation 的 powerful pattern；Proteus spec 可定義 self-audit mechanism。

## Open questions
- **ECC shared randomness detection**: 是否能類似 GCD-attack 對 ECC keys? Open。
- **Smartphone / mobile entropy**: 與 IoT 對比，mobile device 通常有 hardware RNG 但仍有 weak boot moments。
- **PQ key gen entropy requirement**: ML-KEM / ML-DSA 需要 large amount of randomness; weak RNG impact 仍待 study。

## References worth following
- Lenstra 等 *Public Keys* (CRYPTO 2012) — independent 同 timeframe 更大 dataset。
- Bernstein-Heninger-Lange-Lou-Valenta *Sliding right into disaster* (CHES 2017) — cache-timing attack on RSA。
- Hastings 等 *Weak Keys Remain Widespread in Network Devices* (IMC 2016) — 4 年後 follow-up scan。
- factorable.net — 持續 dataset。
