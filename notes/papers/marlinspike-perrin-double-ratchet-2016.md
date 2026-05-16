# The Double Ratchet Algorithm
**Venue / Year**: Signal whitepaper 2016 (revision 1)
**Authors**: Moxie Marlinspike, Trevor Perrin
**Read on**: 2026-05-16 (in lesson 3.17)
**Status**: full whitepaper read (signal.org/docs/specifications/doubleratchet/). Companion formal analysis Cohn-Gordon et al. EuroS&P 2017 已有 precis (cohn-gordon-pcs-2016.md)。
**One-line**: 在 X3DH 之上的兩層 ratchet 結構：每訊息 fresh DH (Diffie-Hellman ratchet) + 每訊息 KDF 推進 chain key (symmetric ratchet)，給細粒度 FS + PCS。

## Problem
X3DH (Marlinspike-Perrin 2016) 給 initial shared secret，但若 device state 在某 t 洩漏，t 之前所有 + 之後所有訊息 全可解。需要 mechanism 讓:
1. 過去訊息 secret (FS) — chain key 不可逆推。
2. 未來訊息 (給定雙方各做一次 fresh DH) secret (PCS) — 從 compromise state "self-heal"。

且必須在 **async messaging** 場景（receiver 可能 offline）下工作。

## Contribution
**Double Ratchet 結構**: 兩個 ratchet 同時運作。

1. **Symmetric chain ratchet** (每訊息一步):
   - Chain key CK → KDF → (CK', mk)
   - mk 用作 AEAD key 加密單個訊息
   - 給 fine-grained FS

2. **DH ratchet** (每 direction switch 或顯式 rekey):
   - 生成新 ephemeral DH keypair
   - 與對方 latest ephemeral pk 做 DH
   - 更新 Root Key RK；從新 RK 派生新 chain key
   - 給 PCS

兩 ratchet 連動: DH ratchet 重置 chain ratchet。

## Method
**State**:
```
Per peer state:
    DHs (own ephemeral keypair)
    DHr (their latest ephemeral pk)
    RK   (root key)
    CKs  (sending chain key)
    CKr  (receiving chain key)
    Ns, Nr  (msg counters in current chains)
    PN     (msg count in previous send chain — for skipped-key handling)
    MKSKIPPED (cache of skipped msg keys for out-of-order)
```

**Sending**:
```
(CKs, mk) = KDF_CK(CKs)
header = (DHs.public, PN, Ns)
ciphertext = AEAD(mk, plaintext, AD = header)
Ns += 1
send (header, ciphertext)
```

**Receiving (with possible DH ratchet)**:
```
if header.DH != DHr:
    DH ratchet step:
        skip remaining keys in current CKr chain (cache them)
        DHr = header.DH
        (RK, CKr) = KDF_RK(RK, DH(DHs.private, DHr))
        DHs = generateDH()
        (RK, CKs) = KDF_RK(RK, DH(DHs.private, DHr))
        Ns = 0; Nr = 0
(CKr, mk) = KDF_CK(CKr)
plaintext = AEAD-Dec(mk, ciphertext, AD = header)
```

**Out-of-order handling**: skipped-message-keys cache; cap (per Signal default ~1000) + TTL。

## Results
- PCS healing window: 2 round trips (one each direction post-compromise).
- FS granularity: per-message.
- Out-of-order tolerance: bounded by cache cap.
- Bandwidth overhead: header carries 32-byte ephemeral pk + counters (~40 byte per msg).
- Used in Signal, WhatsApp (~3B users), Matrix, Wire.

## Limitations / what they don't solve
- DH ratchet 需要 fresh DH per direction switch → 計算成本 (~50µs/op).
- Cache 可被 DoS (eager send out-of-order msgs)。
- 不保護 **metadata** (sender/receiver identity, timing)。
- Async 模式下首訊息仍依賴 X3DH 的 one-time prekey；可能用盡時退到無 PCS 版。
- Cremers 等 2019 發現 Selfie attack (multi-device 場景下 self-impersonation)；後續 Signal spec 修補。

## How it informs our protocol design
Proteus v1 ratchet 設計（coarser than Signal，因 Proteus 是 synchronous proxy 非 IM）:
- **DH ratchet trigger**: 每 N records (默認 2^20) 或 T 秒 (默認 120) — 比 Signal 粗 (Signal: per direction switch);
- **Symmetric chain ratchet**: 每 record (與 Signal 一致, 為 FS);
- **Out-of-order**: 沿用 Signal skipped-key cache 設計, cap = 2^16;
- **Cost**: ratchet ~50µs/2min → negligible;
- **PCS guarantee**: ~2-min healing window (vs WireGuard rekey ~2-min;
   Proteus ratchet 比 WireGuard 重新 handshake 便宜 100×)。

這是 Proteus SOTA differentiator #4 (見 3.17 §4)。WireGuard 雖有 rekey 但每 2 分鐘做 full Noise IK；Proteus 在握手之間做輕量 ratchet。

## Open questions
- Hybrid PQ Double Ratchet: 當前所有 DH 為 X25519；換成 ML-KEM 後 ratchet 結構 需重設計 (Brendel-Fischlin-Günther 2022 開始)。
- Async PCS 與 PSK 0-RTT 整合的最佳實踐？
- Skipped-key cache 對 traffic-analysis 的影響 (cache 操作 timing 是否 leak)？
- Double Ratchet 在 UDP-based lossy network 下的 cache 上限調校。

## References worth following
- Cohn-Gordon, Cremers, Dowling, Garratt, Stebila, *A Formal Security Analysis of the Signal Messaging Protocol*, EuroS&P 2017 — 完整 PCS / FS proof。
- Alwen, Coretti, Dodis, *The Double Ratchet: Security Notions, Proofs, and Modularization*, EUROCRYPT 2019 — modular abstraction。
- Cremers 等, *Selfie attack on Signal X3DH*, 2019 — multi-device bug。
- Marlinspike, Perrin, *X3DH Key Agreement Protocol*, Signal whitepaper 2016。
- Brendel, Fischlin, Günther 2022 — hybrid PCS。
- signalapp/libsignal-protocol-rust src/ratchet/ — reference impl。
