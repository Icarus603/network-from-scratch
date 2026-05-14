# WireGuard: Next Generation Kernel Network Tunnel
**Venue / Year**: NDSS 2017
**Authors**: Jason A. Donenfeld（OSTIF / Edge Security）
**Read on**: 2026-05-14 (in lessons 5.5, 6.1 forthcoming)
**Status**: PDF 開放 https://www.wireguard.com/papers/wireguard.pdf；formal verification companion paper Donenfeld-Milner 2018 已下載到 assets/papers/wireguard-formal-verification.pdf
**One-line**: 用 Noise IK pattern + UDP + Curve25519 + ChaCha20Poly1305 + BLAKE2s 把 VPN 砍到 4000 行 kernel code 並 formally verifiable。

## Problem
- IPsec / OpenVPN 既複雜（cipher agility hellhole）又笨（IKE 兩階段協商太多 round trip + 配置複雜）
- VPN 不該是 monstrous 規格——應該是一個 narrow secure tunnel 工具
- formal verification 在 IPsec/OpenVPN 結構上不可行

## Contribution
1. **Crypto-Key Routing**: 把 peer identity (Curve25519 public key) 直接綁定到「允許的 inner IP 範圍」(AllowedIPs)；server-side routing table = (pubkey → allowed_ips) mapping
2. **Noise IK handshake**: 1.5-RTT, mutually authenticated, forward secret, identity hiding (responder pub key)
3. **Stateless UDP transport** with per-peer rolling timer for keep-alive
4. **4000 行 Linux kernel code** vs IPsec stack 數十萬行
5. **可 formal verify**: 後續 Donenfeld-Milner 2018 用 Tamarin 證明完整安全屬性

## Method
- Noise IK pattern (詳見 noiseprotocol.org)
- Curve25519 (Bernstein 2006) for ECDHE
- ChaCha20-Poly1305 for AEAD
- BLAKE2s for hash
- HKDF for key schedule
- Cookie reply mechanism for DoS protection（類似 QUIC Retry）
- Roaming via 連線狀態的 "endpoint" 動態更新（無 connection ID，但每收 valid encrypted packet 就 update peer endpoint）

## Results
- 整 codebase 4000 LOC（Linux kernel module）
- Throughput 接近 native（kernel implementation + AES-NI 缺席仍快 due to ChaCha20）
- 形式化證 in Tamarin (Donenfeld-Milner 2018): mutual authentication, secrecy, FS, identity hiding, KCI resistance
- 2020 merged into Linux mainline (kernel 5.6)
- Used by Mullvad, Cloudflare WARP (原版，後遷 MASQUE), ProtonVPN 等

## Limitations / what they don't solve
- **強指紋**: WireGuard handshake message size + UDP signature 對 GFW DPI 是 obvious WireGuard
- **無 retry-style anti-amplification primitive**（後續 cookie reply 部分緩解）
- **無 multipath / migration**（roaming via endpoint update 但無 path validation）
- **配置靜態**: peer 列表 hardcode，無 dynamic discovery
- **kernel-only deployment 主流**（雖有 wireguard-go user-space 但慢）

## How it informs our protocol design
- **Crypto-Key Routing 是反例**：在 anti-censorship 場景 peer identity 暴露反而是漏洞；我們協議不採此 routing model
- **Noise IK 為基礎 handshake**：但需擴展 anti-fingerprint
- **fully formally verified 是 viable**: 4000 LOC scale 可 prove；我們協議目標同樣 narrow scope
- **UDP transport + ChaCha20-Poly1305 + BLAKE2** stack 是 SOTA performant 基線
- **避免 WireGuard 強指紋的 lessons**: Part 11 必須對抗

## Open questions
- WireGuard over obfuscation layer (WireProxy, Cloak) 對 GFW 的有效度仍未 measure 完整
- Post-quantum WireGuard variant (PQ-WireGuard, draft) 的 handshake size 對 PMTU 影響
- WireGuard with 0-RTT key derivation (尚無)
- MASQUE-on-WireGuard 或 WireGuard-on-QUIC 的 hybrid 是否 viable

## References worth following
- Noise protocol framework spec (Perrin)
- Donenfeld-Milner 2018 *Formal Verification of WireGuard* (Tamarin proof, https://www.wireguard.com/papers/wireguard-formal-verification.pdf)
- Lipp-Blanchet-Bhargavan EuroS&P 2019 *A Mechanised Cryptographic Proof of WireGuard* (ProVerif)
- Dowling-Paterson 2018 *A Cryptographic Analysis of the WireGuard Protocol* (computational model)

---

**用於課程**：Part 5.5（Noise IK ProVerif）、Part 6.1（VPN internals 第一堂）、Part 11（protocol design baseline comparison）
