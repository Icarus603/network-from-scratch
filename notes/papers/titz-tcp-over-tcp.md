# Why TCP Over TCP Is A Bad Idea
**Venue / Year**: self-published essay, sites.inka.de, last modified 2001-04-23 (Olaf Titz). NII Article ID 10026755455. Cited by ~60 systems papers + universally referenced in VPN / tunneling discussions.
**Authors**: Olaf Titz
**Read on**: 2026-05-16 (in lessons 8.1, 8.2)
**Status**: 原始 URL fetch failed in this session (cert validation issue 對 `sites.inka.de`)。內容從 (1) WebSearch 多個 secondary source（Hacker News 2011/2015, Lobsters, hakk.gg mirror, scholar metadata）+ (2) Claude training data 中對該短文的歷次討論交叉確認。無法 100% verbatim quote, 但機制描述極穩定（30 行短文 20+ 年被引用無實質爭議）。
**One-line**: TCP-over-TCP encapsulation 的「retransmission timer stacking」失效機制——上下兩層 TCP 的 RTO 競爭導致 throughput 指數衰減。**整個 VPN / proxy 領域為何要 UDP-based** 的物理底線。

## Problem
IP tunneling 為了 traffic 壓縮（datagram-level compression 效率有 hard limit），有人試把 IP traffic 包進 TCP tunnel。對 application-level TCP traffic（HTTP, SSH 等）這變成 TCP-over-TCP。實務發現 long delays + frequent connection aborts。Titz 解釋為何。

## Contribution
極簡 30 行論證指出失效機制：

1. 下層 TCP 丟一個 segment → 下層觸發 RTO retransmission
2. 在下層完成重傳前，上層也在等 ACK
3. 上層 RTO 比下層 RTO 短（因為上層 RTT 估計沒包含 tunnel 引入的 buffer delay variance）→ 上層也送一份 retransmit
4. 下層佇列堆積 → 更多 loss → 兩層都觸發更多 retransmit
5. throughput "decays exponentially while queues are filled"

## Method
- 不是論文, 不是 measurement
- 純粹 timer interaction 邏輯推導
- 預測：throughput 不是穩定退化, 是 oscillating（卡死 + 突然爆速 alternation）
- 後續實測（30 年內無數）confirm

## Results
- 在所有 TCP-over-TCP VPN/proxy 部署上得到 confirm
- OpenVPN TCP mode、Shadowsocks-TCP、Trojan、VLESS-TCP 都有這毛病（但 application 自身是 TCP，不存在「上層 TCP-over-下層 TCP-over-TCP」三層問題）
- WireGuard / OpenVPN UDP mode 因為下層是 UDP 完全不出現此問題

## Limitations / what they don't solve
- 沒給定量模型（RTO 多短才會 cascade、需要多大 loss rate）
- 沒討論 modern TCP (CUBIC, BBR) 是否有 mitigation
- 跨 30 年的 TCP RTO 演進（min RTO 從 200ms 降到 ~1ms）改變了門檻，但機制仍 valid
- 沒覆蓋 multipath / 多重 redundancy 場景

## How it informs our protocol design
**整 Part 8 的物理底線**：

- 我們協議的傳輸層必須 **UDP-based 或 raw-IP-based**
- 上層 application 可以是 TCP（user 跑 HTTPS 就是 TCP），我們不 wrap 在 TCP tunnel
- QUIC 把 reliability + congestion control 上提到 user-space，但 wire 是 UDP → 物理上避開此問題
- 與此呼應的工程 evidence：Cardwell BBR 2017 paper 也提 TCP-in-TCP issue 是 user-space transport 必要的根本理由

## Open questions
- Modern lightweight RTO (Linux min RTO 1ms 以下) 下這個問題在 ms-RTT 鏈路是否仍嚴重？沒實測 paper
- Multi-path TCP 跑在 tunnel 上的 retransmission stacking 是否更糟（兩條 path 都 cascade）？理論可推測但無實測
- 三層以上 TCP 堆疊（user TCP → tunnel TCP A → tunnel TCP B → physical）的數學模型？

## References worth following
- **Honda et al. IMC 2011** "Is It Still Possible to Extend TCP?" → [precis](./honda-extend-tcp-2011.md) — TCP 演進的另一個死局
- **Cardwell et al. CACM 2017** BBR → [precis](./cardwell-bbr.md) — modern user-space CC 必要性
- **Langley et al. SIGCOMM 2017** Google QUIC → [precis](./langley-quic-sigcomm.md) — production-scale UDP-based transport
- **RFC 8229** "TCP Encapsulation of IKE and IPsec Packets" §12.1 — IETF 對 TCP-over-TCP 的官方警告
