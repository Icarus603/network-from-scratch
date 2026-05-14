# The QUIC Transport Protocol: Design and Internet-Scale Deployment
**Venue / Year**: ACM SIGCOMM 2017, Los Angeles, Aug 2017, pp. 183–196. DOI: 10.1145/3098822.3098842
**Authors**: Adam Langley, Alistair Riddoch, Alyssa Wilk, Antonio Vicente, Charles Krasic, Dan Zhang, Fan Yang, Fedor Kouranov, Ian Swett, Janardhan Iyengar, Jeff Bailey, Jeremy Dorfman, Jim Roskind, Joanna Kulik, Patrik Westin, Raman Tenneti, Robbie Shade, Ryan Hamilton, Victor Vasiliev, Wan-Teh Chang, Zhongyi Shi（all Google）
**Read on**: 2026-05-14 (in lessons 4.7, 4.8, 4.9)
**Status**: PDF 開放（SIGCOMM 2017 program）；assets/papers/sigcomm-2017-quic.pdf 已存
**One-line**: Google 把 4 年 production-scale QUIC 部署經驗濃縮成「為什麼 TCP 死路一條、為什麼 UDP-based encrypted transport 是必然」的 systems paper——這是 IETF QUIC（RFC 9000/9001/9002）誕生的引信。

## Problem
Google 部署 HTTPS 規模到全球後遇到的牆：
1. **TCP head-of-line blocking** 在 HTTP/2 multiplexed streams 下放大（一個 packet loss 卡住所有 streams）
2. **TCP + TLS 握手延遲** = 1-3 RTT，行動 / 跨大洲 latency 殺手
3. **TCP 是 kernel-implemented**：Google 想 deploy 新 congestion control（BBR）卻被 OS 升級周期卡住，OS 卡 ISP，ISP 卡 user device
4. **Middlebox ossification**：TCP option negotiation 被 middlebox 鎖死，任何新 TCP feature 部署率慘
5. **Encryption layered on top of TCP** → metadata 仍洩漏（packet number、connection ID、sequence number）

## Contribution
1. **Design principle**：encryption is intrinsic, not layered；user-space implementation 避 kernel/middlebox 鎖
2. **Stream-based multiplexing** 在 transport 層內（不在 application 層上），單一 stream loss 不阻塞其他
3. **0-RTT 握手** for repeat connections（cached crypto state）
4. **Connection migration**：connection 由 connection ID 而非 5-tuple 識別 → IP 變動仍 keep alive
5. **Loss recovery 與 congestion control decoupled from TCP**：QUIC 可以無 OS 升級就部署 BBR、Cubic、PROD-specific 演算法
6. **Internet-scale deployment evidence**：7% 全網流量；Search 延遲 -8%（desktop）/ -3.6%（mobile）；YouTube rebuffer rate -18%（desktop）

## Method
- **A/B 實驗**：每個改動對 production traffic 跑 days-to-weeks A/B（Google flag system）
- **Iterative protocol design**：4 年內主 wire format 改了 40+ 次（QUIC ver Q025 → Q050）
- **Compromise with middlebox reality**：spec 演化中發現 ISP/firewall 對某些 QUIC pattern reject，需 mask
- **Performance measurement**：分 desktop vs mobile vs 不同地理區，每個 metric 細分 buckets

## Results
- 7% Internet traffic by paper time（2017 mid）
- Search median latency improvement 8% desktop, 3.6% mobile
- YouTube rebuffer improvement 18% desktop, 15.3% mobile
- Mobile 改善小於 desktop：mobile RTT 大，但 0-RTT 比例低（很多 cold start）
- 跨大洲（India, Indonesia）user 受益最大（高 RTT + 高 loss rate）

## Limitations
- 不是 IETF spec：Q025–Q050 wire format 與後續 RFC 9000 大不相同
- 不討論安全形式化（後續 IETF QUIC 才有）
- Connection migration 在 2017 仍 experimental
- 流量分析 + censorship 不在 scope

## How it informs our protocol design
- **User-space + UDP 是新 transport 的標配**
- **Streams 跟 connection 是 first-class abstractions**
- **0-RTT 是 marketing winning 但必須 careful design**（Part 4.5）
- **Connection ID-based identification** 是我們協議的核心 trick
- **加密層必須 intrinsic** — Plaintext metadata 是 ossification 與 fingerprint 的根
- **Iterative deployment** 才是 protocol 演化的真實機制

## Open questions（這份 paper 留下的）
- 真的 user-space 比 kernel-space 永遠快嗎？（後來 io_uring、XDP 等 kernel side 演化挑戰這條）
- Multi-path QUIC（draft-ietf-quic-multipath）是否能 production scale 部署？
- Connection migration 在 NAT-heavy 場景的真實成功率
- 行動裝置 CPU + battery cost — TCP 在 kernel 比較省電

## References worth following
- IETF QUIC WG: RFC 9000 (transport), 9001 (TLS integration), 9002 (loss/congestion), 9221 (datagrams), 9114 (HTTP/3)
- Rüth et al. *A First Look at QUIC in the Wild*. PAM 2018
- Kakhki et al. *Taking a Long Look at QUIC*. IMC 2017（同年 critical assessment）
- Marx et al. *Same Standards, Different Decisions: A Study of QUIC and HTTP/3 Implementation Diversity*. EPIQ workshop

---

**用於課程**：Part 4.7（QUIC transport）、Part 4.8（handshake）、Part 4.9（advanced）、Part 4.10（H3 + MASQUE）、Part 4.11（quic-go 對讀）、Part 11（我們協議 transport 選擇）
