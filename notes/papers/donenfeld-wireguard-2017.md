# WireGuard: Next Generation Kernel Network Tunnel
**Venue / Year**: NDSS 2017
**Authors**: Jason A. Donenfeld
**Read on**: 2026-05-14 (in lesson 3.8)
**Status**: full PDF (`assets/papers/donenfeld-wireguard-2017.pdf`)
**One-line**: WireGuard 設計與 Linux kernel 實作的 whitepaper——用 Noise IK 握手 + ChaCha20-Poly1305 record + 極簡 4000 行 kernel code，徹底重新定義 VPN 該長什麼樣；G6 的 anti-censorship variant 直接 base on WireGuard。

## Problem
2017 年 VPN 三大方案：IPsec、OpenVPN、TLS-based。所有都有問題：
- **IPsec**：~150 RFC、可配置選項數千、配置 nightmare、attack surface 大。
- **OpenVPN**：~120k LoC、effective 但慢、SSL/TLS-based 帶入所有 TLS 缺陷。
- **TLS VPN**：TCP-over-TCP head-of-line blocking、TLS handshake 暴露 fingerprint。

需要：簡潔、快、安全、易部署的 modern VPN。

## Contribution
1. **Noise IK 為唯一 KE**：無 negotiation。Public key cryptography only X25519。Authentication only Ed25519 (handshake 內 implicit via static DH)。
2. **Record layer = ChaCha20-Poly1305 + per-direction 64-bit counter**：constant-time AEAD with hardware-friendly performance。
3. **Crypto agility through versioning, not negotiation**：spec v1 hard-codes Curve25519/ChaCha20/Poly1305/BLAKE2s。Future v2 是新 spec，不向後相容。**徹底避 Logjam-style downgrade attack**。
4. **Roaming via UDP-only stateless cryptokey routing**：sender IP 變化不影響 session；server 用 client static pk 自動 update endpoint。
5. **Anti-DoS** via MAC1 + cookie reply：MAC1 確認 client 有 server static pk (out-of-band 知識證明); cookie reply 確認 client 是 routable IP。
6. **Kernel implementation < 4000 LoC**：vs OpenVPN ~120k, strongSwan ~400k。Attack surface 顯著縮減。
7. **Performance**：~1 Gbps Linux kernel impl, vs OpenVPN ~200 Mbps, strongSwan ~700 Mbps (2017 hardware)。
8. **Rekey-after-time/messages** 給粗粒度 PCS。

## Method
**Handshake** (Noise_IK_25519_ChaChaPoly_BLAKE2s + MAC1/MAC2):
```text
Message 1 (initiator → responder):
    msg_type: 1 (handshake init)
    sender_index: random 4 byte
    unencrypted_ephemeral: 32 byte (initiator ephemeral X25519 pub)
    encrypted_static: 48 byte (AEAD-enc'd initiator static pub)
    encrypted_timestamp: 28 byte (AEAD-enc'd TAI64N timestamp, replay protect)
    mac1: 16 byte = MAC(BLAKE2s(label_mac1 ‖ responder_static_pub), msg_so_far)
    mac2: 16 byte = MAC(cookie, msg_so_far) or zeros

Message 2 (responder → initiator):
    msg_type: 2 (handshake response)
    sender_index, receiver_index: 4 byte each
    unencrypted_ephemeral: 32 byte
    encrypted_nothing: 16 byte (empty AEAD ciphertext, MAC binds transcript)
    mac1, mac2

After handshake:
    Derive (sender_key, receiver_key) = HKDF(ck, empty, 2)
    counter = 0
    Transport packets: msg_type=4, receiver_index, counter (8 byte), encrypted payload
```

**Cookie reply** (anti-DoS):
```text
If responder overloaded (e.g. CPU > 30%):
    Don't process handshake messages; instead respond:
    msg_type: 3
    encrypted_cookie: AEAD-Enc(MAC(secret, sender_ip), with key derived from initiator_static)
Client retries with cookie set into mac2 field.
```

**Cryptokey routing**：每 peer 有 (static_pk, allowed_ips) tuple。Server received packet from sender_index → look up peer state by static_pk → verify allowed source IP in allowed_ips。Sender IP 不重要——sender 可漫遊。

## Results
- **Linux kernel 5.6 (2020)** 主線採用。
- **Cross-platform deployments**: WireGuard-Go (mobile, macOS), BoringTun (Cloudflare Rust), wireguard-windows。
- **Cloudflare WARP, Mullvad VPN, Mozilla VPN, ProtonVPN, NordVPN** 全採用 (作為 alternative protocol)。
- **Lipp-Blanchet-Bhargavan 2019** EuroS&P 給出 mechanised ProVerif + CryptoVerif proof。
- **amneziawg / dpiVisor 等 obfuscation forks** 在 WireGuard 上加 GFW-evasion layer。

## Limitations / what they don't solve
- **可被 GFW 識別**：固定 handshake message 1 size (148 byte)、固定 type byte、UDP-only。Wu 等 2023 USENIX Security fully encrypted detection 對 WireGuard handshake 高識別率。
- **無 traffic obfuscation**：純加密無 cover-traffic / shape disguise。
- **PQ-vulnerable**：完全 X25519-based。
- **No identity protection 對 active attacker with responder static**：Noise IK 限制。

## How it informs our protocol design
- **G6 直接繼承 WireGuard 設計骨架**:
  - Noise IK base。
  - MAC1 + Cookie reply anti-DoS。
  - Rekey-after-time/messages。
  - Cryptokey routing (per-peer allowed_ips)。
- **G6 與 WireGuard 差異**:
  - 加 traffic obfuscation (Part 10 詳論)。
  - 加 PQ hybrid (Kyber768)。
  - 加 cover-traffic disguise on handshake message 1 (避免 fixed size + type byte detection)。
  - 加 fine-grained PCS via per-N-record ratchet。
- **G6 教訓 #1**：簡潔即安全。WireGuard 4000 LoC vs IPsec/OpenVPN 100k+ LoC 對應 attack surface 縮減。
- **G6 教訓 #2**：「No negotiation」是 anti-Logjam 的 architectural choice。

## Open questions
- **WireGuard 在 GFW 下生存策略**：amneziawg 是 obfuscation fork；更系統的方案？G6 嘗試解此。
- **WireGuard PQ migration**：當前無 PQ。Hybrid PSK 是過渡，full Kyber integration 仍 evolving。
- **Multi-path / connection migration**: WireGuard 不支援 simultaneous multiple peer endpoints；QUIC-style migration 可借鑑。

## References worth following
- Donenfeld *WireGuard whitepaper* (this paper).
- Lipp-Blanchet-Bhargavan *Mechanised WireGuard Proof* (EuroS&P 2019).
- Wu, Lin, Yin 等 *Detection of Fully Encrypted Traffic* (USENIX Security 2023) — GFW 對 WireGuard 的偵測。
- amneziawg / dpiVisor GitHub。
- Cloudflare BoringTun Rust impl。
