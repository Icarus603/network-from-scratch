# UDP Generic Receive Offload (UDP_GRO)
**Venue / Year**: Linux kernel mainline, kernel 5.0 (2019-03); RFC patchset on netdev 2018
**Authors**: Paolo Abeni (Red Hat), with Willem de Bruijn / Eric Dumazet review
**Read on**: 2026-05-16 (in lesson 2.15)
**Status**: commit available — `git show e20cf8d3f1f7`; commit message + cover letter on lore.kernel.org netdev
**One-line**: UDP_SEGMENT 的對稱物 — kernel/NIC 把連續同 5-tuple 的 UDP datagram 合併進單個 skb，應用層一次 recvmsg 拿一批

## Problem
GSO 解決了「送」這一側的 syscall 瓶頸，但「收」這一側仍然每 datagram 一次 socket queue insert + 一次 wake + 一次 recvmsg syscall。對稱地把單核接收上限卡在 ~150 MB/s。
UDP_GRO 之前只有 tunnel encapsulated 場景下的 inner-protocol GRO；plain UDP socket（QUIC/DNS/RTP）拿不到 GRO 紅利。

## Contribution
1. 引入 `SOL_UDP / UDP_GRO` setsockopt（QUIC 實作有時記作 `ENABLE_UDP_GRO`）讓 plain UDP socket 啟用 GRO。
2. 在 napi receive path 註冊 UDP-aware GRO callbacks（`udp_gro_receive` / `udp_gro_complete`），把連續同 5-tuple、同 TTL、同 IP option 的 UDP datagram 累積到單個 super-skb。
3. user-space 用 `recvmsg`（建議帶 `MSG_PEEK` + cmsg 探詢）拿到一個大 buffer，再附 `UDP_GRO` cmsg 給 segment size，自己切。
4. 與 NIC hardware UDP-GRO 對接（`NETIF_F_GRO_UDP_FWD`，但較少 NIC 支援硬體版）。

## Method
- 5-tuple 一致 + IP option 一致 + TTL 一致 + 相鄰到達 → 合併
- 合併單位上限 `UDP_MAX_SEGMENTS = 64`
- flush 觸發：non-matching 包到、napi budget 用完、`napi->gro_flush_timeout` 過、buffer 滿
- application: `setsockopt(fd, SOL_UDP, UDP_GRO, &one, sizeof(int))` → 後續 recvmsg 自動取得合併 buffer

## Results
patchset 報告：
- 單 stream QUIC server：1.4× throughput
- 多 stream / 高 PPS：~3× CPU efficiency
- Cloudflare 後來測：與 GSO 合用，整體 ~30× perf vs naive sendmsg/recvmsg

## Limitations
- 跨 NAT/middlebox 後 5-tuple 一致性容易破，GRO 合併效益降低（NIC RX queue 上未必相鄰）。
- 對手 inject 一個 spoofed 5-tuple 包能 trigger flush — 雖低危但是 side channel。
- ipv6 對等支援要到 5.5+；udp tunnel 內側支援要到 5.7+。
- 與 `MSG_PEEK` 互動有 subtleties；早期 5.0–5.4 有過 race condition 被修正。

## How it informs our protocol design
- server **必須開** UDP_GRO，否則 GSO 紅利只對稱一半。
- application-layer parser 要能處理「一次 recvmsg 拿到多個 logical datagram」的 case，不能假設 1 recvmsg = 1 datagram。
- congestion control 的 RTT measurement 要小心：若 GRO 把 4 個 packet 合併再交 app，app 看到的 arrival timestamp 只剩最後一個 — 中間 inter-arrival 信息丟失。要嘛收 RX timestamp (`SO_TIMESTAMPING`)，要嘛 protocol design 上不依賴細粒度 RTT。

## Open questions
- GRO 對「per-packet timing 重要」協議（例如有 explicit ack rate control）造成信息損失，能否設計 GRO-aware ack feedback？
- 硬體 UDP-GRO 在哪些 NIC 上 GA？2026 年生態調查待補。

## References worth following
- LWN 後續報導 — Article 789508（UDP GRO follow-up）
- Paolo Abeni 在 Netdev / LPC 上的 talks
- msquic / quinn 的 enable_udp_gro 整合 PR
- 後續 IPv6 / tunnel inner GRO 補丁系列
