# Post-Quantum TLS Without Handshake Signatures
**Venue / Year**: ACM CCS 2020
**Authors**: Peter Schwabe, Douglas Stebila, Thom Wiggers
**Read on**: 2026-05-16 (in lesson 3.17)
**Status**: cited from abstract + author preprint + Tamarin model (https://github.com/kemtls). Full deep read deferred to Phase II 4.5/4.6 + Phase III 11.3.
**One-line**: 第一個證明用 KEM (而非 signature) 做 TLS server authentication 是可行且 provably secure 的設計，PQ-era handshake 體積縮減 ~6 KB。

## Problem
TLS 1.3 server authentication 用 X.509 certificate + CertificateVerify signature。在 PQ 時代:
- Ed25519 sig: 64 byte → ML-DSA-65 sig: 3293 byte (+50×)
- Cert chain 中 CA sig 同樣放大
- 典型 PQ-TLS server handshake msg ~10 KB → 觸發 IP fragmentation、抗 amplification limits

當前主流 PQ-TLS plan 接受此 overhead，但對 lossy / GFW-adversarial 網路代價極高。

## Contribution
1. 提出 **KEMTLS protocol**: server cert 含 long-term KEM public key (而非 signature key); 認證透過「only the holder of sk can decap」implicit auth 達成。
2. 給出 reference impl + Tamarin formal model + computational proof (full paper).
3. 證明 mutual auth、forward secrecy、KCI-resistance 全保留。
4. 量測 handshake size ~50% 縮減 (PQ mode)，handshake latency 改善在 lossy network 顯著。
5. 提出 KEMTLS-PDK variant: 預先配發 server pk → 1-RTT。

## Method
**Core idea**: server certificate carries pk_KEM; first client→server message carries ciphertext encapsulating to pk_KEM。Server proves identity by decap-ing → derive session key materially affected by long-term sk_KEM。

**Protocol skeleton**:
```
Client Hello: KEMTLS extensions, supported groups, ephemeral KEM pk_e_c
Server Hello: cert (with pk_s_KEM), ephemeral ct_e_s = Encap(pk_e_c)
                derives ss_eph
Client→Server: ct_s = Encap(pk_s_KEM)
                derives ss_static (server-binding)
                session_key = KDF(ss_eph ‖ ss_static ‖ transcript)
Server: Decap(sk_s, ct_s) = ss_static
        verify via Finished MAC
```

**Authentication captured by**: only legitimate server with sk_s can decap ct_s; if MAC verifies, server is authenticated.

## Results
- ML-KEM-768 + Dilithium2 baseline TLS 1.3 ~10.4 KB handshake
- KEMTLS ML-KEM-768 only: ~3.5 KB handshake (-66%)
- KEMTLS-PDK: 1-RTT recovery vs TLS 1.3 1-RTT (no latency penalty)
- On 5% packet loss network: KEMTLS shows ~30% better median completion time

## Limitations / what they don't solve
- 沒 0-RTT support (KEMTLS spec 顯式 out of scope; Proteus 可以補)
- Client authentication 仍可用 signature 或 KEM-based (paper 給 both options)
- Server cert revocation 與 OCSP integration 未改變 (仍依賴 CA sign cert)
- 後續 Celi 等 2022 補 Tamarin 嚴格 proof 才 closure

## How it informs our protocol design
Proteus v1 Mode C: 採 KEMTLS-style server authentication (省 ~3.3 KB)。
- Server cert: pk_X25519 ‖ pk_ML-KEM-768, CA signs binding (offline)
- Handshake: 用 KEMTLS pattern; 但 client identity 仍用 Ed25519+ML-DSA hybrid sig (avoid 0-RTT 複雜化)
- Phase III 11.10 用 Tamarin 模型 (sigh template from Celi 等 2022) 驗證 Proteus KEMTLS-flavored handshake。

這是 Proteus SOTA differentiator #2 (見 3.17 §2)。

## Open questions
- KEMTLS + 0-RTT 怎麼設計？(Proteus 可貢獻方向)
- KEMTLS + ECH 整合？
- KEMTLS handshake 可被 fingerprint 嗎？(KEM ct size pattern；Proteus 用 Elligator2-style padding 平衡)
- KEMTLS-Mut (mutual KEM auth) 對 client identity privacy 的影響

## References worth following
- Celi, Hoyland, Stebila, Wiggers, *A Tale of Two Models: KEMTLS Tamarin Verification*, ESORICS 2022
- Bhargavan 等, *KEMTLS as a Replacement for Server Authentication in TLS 1.3*, CoNEXT WS 2023
- Sikeridis-Kampanakis-Devetsikiotis, *Post-Quantum Authentication in TLS 1.3*, NDSS 2020 (對手提案)
- IETF KEMTLS draft (kemtls-design WG，當前 active)
