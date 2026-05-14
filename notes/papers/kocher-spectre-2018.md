# Spectre Attacks: Exploiting Speculative Execution
**Venue / Year**: IEEE Symposium on Security and Privacy 2019（disclosed January 2018）
**Authors**: Paul Kocher, Jann Horn, Anders Fogh, Daniel Genkin, Daniel Gruss, Werner Haas, Mike Hamburg, Moritz Lipp, Stefan Mangard, Thomas Prescher, Michael Schwarz, Yuval Yarom
**Read on**: 2026-05-14 (in lesson 3.13)
**Status**: full PDF (`assets/papers/kocher-spectre-2018.pdf`)
**One-line**: 利用 CPU 推測執行 + cache side-channel 跨 security boundary 讀任意記憶體；影響所有 modern Intel/AMD/ARM CPU；對「constant-time」 implementation 也構成威脅；引發 hardware/software 大規模 mitigation effort。

## Problem
Modern CPU 用 speculative execution 加速：branch prediction + out-of-order execution 預測 branch direction，speculatively 執行；若預測錯則 architectural state rollback。**但 microarchitectural state (cache) 不 rollback** → 對手可從 cache state 推 speculative path 的執行內容。

## Contribution
1. **Spectre Variant 1 (Bounds Check Bypass)**:
   ```c
   if (x < array1_size) {
       y = array2[array1[x] * 4096];
   }
   ```
   - Train branch predictor with valid x。
   - Pass x out of bounds (e.g., x → kernel address)。
   - CPU speculatively executes inner loads (reads kernel memory + cache prime)。
   - Cache state reveals array1[x] byte。
2. **Variant 2 (Branch Target Injection / BTI)**:
   - Train branch target buffer (BTB) to mispredict indirect branch target。
   - 跳到 victim 內 gadget that speculatively leaks memory。
3. **Cross-process / cross-VM leak**: 在 same CPU 上 attacker 與 victim 共用 BTB / cache → cross-tenant attack。
4. **Influence 後續 microarchitectural attack family**: Meltdown, ZombieLoad, RIDL, MDS, ÆPIC, Downfall 等。

## Method
**Spectre v1 詳細**:
```text
Attacker setup:
    array1: own array, size = K bytes
    array2: own array, 256 cache-line-sized entries (256 * 4096 byte buffer)

Training phase:
    For many iterations: pass x ∈ [0, K)
    Branch predictor learns "if (x < K) is true"

Attack phase:
    flush array2 from cache
    Pass x = SECRET_ADDR - array1_base  (out of bounds, points to kernel/victim memory)
    
    CPU speculatively executes:
        secret = array1[x]   (reads kernel byte!)
        y = array2[secret * 4096]   (loads cache line indexed by secret)
    
    Branch check eventually completes, x is out of bounds, CPU discards.
    But array2's cache line for index (secret * 4096) was loaded!

Probe:
    For i = 0..255:
        time_load(array2[i * 4096])
        If fast (in cache): i is the secret byte.
```

**對 cryptographic implications**:
- 即使 constant-time code, speculative execution may briefly access secret-dependent location → leak via cache。
- Compiler 必須 insert `lfence` 或 use speculative-load-hardening flags。

## Results
- **Industry-wide mitigation effort**:
  - OS kernels: KAISER / KPTI (Kernel Page Table Isolation)。
  - Compiler: -mretpoline (GCC), speculative-load-hardening (LLVM)。
  - Microcode: Intel + AMD updates for IBRS, IBPB, STIBP, RDTSCP serialization。
- **Performance impact**: 5-30% workload-dependent。
- **Triggered new sub-field**: microarchitectural cryptanalysis (Foreshadow, ZombieLoad, MDS, Downfall, GoFetch (2024))。
- **Hardware redesigns** ongoing: Intel Ice Lake+, AMD Zen 3+ partial mitigations。

## Limitations / what they don't solve
- 不完全解決 (full mitigation 需要 disable speculation → huge perf hit)。
- 不同 CPU 不同 variants vulnerable。
- ARM (Apple Silicon, mobile) 也受影響 (different specifics)。
- 2024 GoFetch 對 Apple M-series 的 constant-time crypto 仍可破。

## How it informs our protocol design
- **G6 implementation 必須 Spectre-aware**:
  - Compile with `-mretpoline` (x86) / equivalent ARM flag。
  - Critical crypto sections add `lfence` (x86) 或 `csdb` (ARM)。
  - Use speculative-load-hardening LLVM pass。
- **G6 對 cloud deployment 風險**:
  - Public cloud (AWS, GCP) 同 hardware tenant attack 仍 possible。
  - Dedicated tenancy 推薦 for high-security G6 server。
- **G6 教訓**: 「constant-time impl is enough」原則在 modern microarch 下被推翻；必須 hardware-aware crypto。

## Open questions
- **Generic Spectre-resistant cryptographic implementation**: 仍 active research; Vale, CryptoEng 等 attempt formal verification including speculation。
- **Hardware design for speculation-safe crypto**: 是否能在 hardware level 隔離 speculative state? Active CPU vendor R&D。
- **PQ crypto Spectre-safety**: ML-KEM / ML-DSA Spectre-resistant impls 仍 evolving。

## References worth following
- Lipp 等 *Meltdown* (USENIX Security 2018) — companion attack。
- van Schaik 等 *RIDL: Rogue In-Flight Data Load* (IEEE S&P 2019) — MDS variant。
- Hill 等 *Downfall* (USENIX Security 2023) — Intel-specific gather instruction leak。
- Vicarte 等 *Don't Mesh Around: Side-Channel Attacks and Mitigations on Mesh Interconnects* (USENIX Security 2024) — newer。
- Apple M-series GoFetch (NDSS 2024) — Apple Silicon-specific。
