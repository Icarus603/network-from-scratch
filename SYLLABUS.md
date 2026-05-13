# 從零到 SOTA：抗審查 + 高效能代理協議的研究級課程

> **學員**：Icarus（網路非專業，零理論基礎，但已能用 ccb 搭建 VPS 機場 + Clash Verge Rev 客戶端）
> **教師**：Claude（指導教授 + 研究夥伴角色）
> **承諾**：1.5~3 年，每週 10~20 小時投入
> **語言**：繁體中文授課，技術術語、論文名稱、原始碼識別子保留英文
> **形式**：理論授課 + 論文精讀 + 原始碼通讀 + 動手實作 + 對抗測試
> **狀態**：v2 — 從「能設計 demo 協議」改為「能設計 SOTA 級生產協議」

---

## 研究目標（重要：這份大綱的設計準繩）

設計並實作一個**新的代理協議 + 客戶端 + 服務端**，同時達成：

1. **抗審查 ≥ VLESS+REALITY 級別**
   - 對主動探測免疫（包含 GFW 已知所有探測手法 + 我們自己設想的新手法）
   - 對被動 DPI 識別免疫（含 ML 流量分類器，e.g. Beauty 系列、nProbe-DPI、流量指紋研究）
   - 對統計分析（封包大小分佈、時序、burst pattern、flow size）有可證明的混淆
   - 對抗 TLS 指紋（JA3/JA4/JA4+，含未來新指紋技術）
2. **效能 ≥ Hysteria2 / TUIC v5 級別**
   - 高丟包鏈路下單流吞吐 ≥ Hysteria2
   - 多流場景下無 head-of-line blocking
   - 0-RTT 連線、連線遷移
   - 在標準 VPS 硬體（1 vCPU / 1 GB RAM）下單實例 ≥ 5 Gbps 線速處理
3. **可部署性 ≥ 主流協議**
   - 單一 binary、無外部依賴
   - 可整合進 sing-box / mihomo / Xray
   - 配置複雜度不超過 VLESS+REALITY
4. **形式化保證**
   - 安全屬性用 ProVerif / Tamarin / CryptoVerif 驗證
   - 關鍵不變量用 TLA+ 規格化

**非目標**（明確排除以保持聚焦）：
- 不做 P2P / NAT 穿透
- 不做企業級 site-to-site VPN
- 不做行動裝置最佳化（先 desktop，行動端是後續工作）

---

## 課程結構：3 個 Phase / 12 個 Part / ~150 堂

```
Phase I  — 地基（Part 0~5，~50 堂，6~9 個月）
   建立網路 + 密碼學 + OS + 高效能 I/O 的研究級基礎
   讀透 ~30 篇論文，原始碼通讀 1 個專案（WireGuard）

Phase II — SOTA 解剖（Part 6~9，~50 堂，6~9 個月）
   把現有所有 SOTA 協議拆到能逐行解釋
   讀透 ~50 篇論文，原始碼通讀 3 個專案（Xray / sing-box / quic-go）
   建立 GFW 對抗測試平台

Phase III — 設計與實作（Part 10~12，~50 堂，6~12 個月）
   從威脅模型到 spec 到 implementation 到對抗測試到形式化驗證
   產出：協議規格書 + Go 實作 + 評測論文（可投 USENIX Security / NDSS）
```

---

## 完整 Part 列表

| Phase | Part | 主題 | 堂數 | 出口能力 |
|---|---|---|---|---|
| I | **0** | 定向、研究方法、文獻地圖 | 5 | 知道整門課的所有出處 |
| I | **1** | 網路：從電晶體到 BGP | 18 | 能讀懂 Linux TCP/IP stack 任一行 |
| I | **2** | 高效能 I/O 與 kernel 網路 | 14 | 會 epoll / io_uring / eBPF / XDP / DPDK |
| I | **3** | 密碼學：從數論到 PQ | 16 | 能設計一個 protocol 並用 ProVerif 驗證 |
| I | **4** | TLS / QUIC 內部完全解剖 | 12 | 逐 byte 解釋 TLS 1.3 + QUIC v1 握手 |
| I | **5** | 形式化方法 | 8 | TLA+ / ProVerif / Tamarin 入門 |
| II | **6** | 真 VPN 協議精讀 + 原始碼 | 10 | 通讀 wireguard-go，能寫 PR |
| II | **7** | 翻牆協議完整演化史與每個協議精讀 | 16 | SS / VMess / Trojan / VLESS / REALITY 逐行讀完 |
| II | **8** | QUIC 系協議深度 | 10 | Hysteria2 / TUIC / 自己 fork quic-go |
| II | **9** | 審查對抗：GFW 完整研究綜述 + 自建測試平台 | 14 | 能複現 GFW.report 所有實驗 |
| III | **10** | 對抗式流量分析與反制 | 12 | 跑通 Beauty / FlowPrint，能設計反制 |
| III | **11** | 設計階段：威脅模型、spec、形式化驗證 | 14 | 產出 RFC 級規格書與形式化證明 |
| III | **12** | 實作、評測、發表 | 24 | Go/Rust 實作、對抗測試、論文初稿 |

---

# Phase I：地基

> **目標**：把所有後續研究會用到的底層知識建立到「能跟領域內研究者對話」的水平。
> **出 Phase I 標準**：能獨立讀懂任何一篇 USENIX Security / SIGCOMM / NDSS 的網路安全論文。

---

## Part 0 — 定向、研究方法、文獻地圖（5 堂）

### 0.1 「VPN」這個詞被誤用了 30 年 ✅
拆三條線（真 VPN / 商業 VPN / 翻牆代理），建立後續座標系。

### 0.2 整門課的學習地圖
12 個 Part 的依賴圖、為什麼這個順序、什麼時候可以並行讀。

### 0.3 研究級學習方法論
- 怎麼讀論文（三遍法：skim → 結構 → 細節）。
- 怎麼追溯一個概念到原始出處（CCS、USENIX Security、NDSS、IEEE S&P、SIGCOMM、IMC、PoPETs 是哪些會議）。
- 怎麼用 Google Scholar / DBLP / arXiv / Cryptology ePrint 建文獻網。
- 怎麼用 git blame + commit message 讀大型專案歷史。

### 0.4 文獻地圖：你接下來要面對的 100 篇論文
按主題列出整門課的核心論文清單（會在對應 Part 精讀）：
- GFW 研究：~25 篇（GFW.report、Censored Planet、ICLab）
- 流量分析：~20 篇（Beauty、FlowPrint、Walkie-Talkie 等）
- TLS 指紋：~10 篇（JA3/JA4 原始論文、uTLS 設計）
- QUIC：~15 篇（含原始 SIGCOMM 論文 + 後續優化）
- 密碼協議形式化：~15 篇（Noise、TLS 1.3 證明、ProVerif/Tamarin 案例）
- 高效能網路：~15 篇（DPDK、XDP、io_uring）

### 0.5 工具鏈與環境準備
- macOS 開發機 + 兩台 Linux VPS（一台「中國境外」一台「模擬境內」）
- 必裝：Go、Rust、Python（uv）、Wireshark、tcpdump、tshark、nDPI、Zeek、ProVerif、TLA+、bpftrace
- 開實驗筆記的格式（每個實驗一個 ipynb 或 .md，含假設、方法、結果、結論）

---

## Part 1 — 網路：從電晶體到 BGP（18 堂）

> **深度準繩**：學完能在 Wireshark 抓任何封包逐 byte 解釋；能 patch Linux TCP stack 修小問題。

### 1.1 分層的真實意義（不是教科書版）
為什麼分層、什麼時候**該打破**分層（cross-layer optimization 是研究熱點）。

### 1.2 物理層：你不需要懂電壓，但要懂 PHY/MAC 介面
- 為什麼這影響零拷貝（zero-copy）設計
- DMA、ring buffer、NIC offload（TSO/GSO/GRO/LRO）
- **論文**：The Click Modular Router (TOCS 2000)

### 1.3 乙太網路與 L2：交換器內部
- MAC 學習、CAM 表、VLAN、STP 為什麼存在
- 為什麼資料中心改用 VXLAN / Geneve

### 1.4 IP 層：路由是個圖論問題
- 路由表 = trie 結構（Linux 用 LC-trie，FIB 設計）
- ECMP、policy routing、source routing
- **原始碼**：Linux `net/ipv4/fib_trie.c`

### 1.5 ARP / NDP / DHCP：「啟動時的兩三件事」
為什麼這些協議的設計缺陷會變成攻擊面（ARP spoofing 還活著）。

### 1.6 ICMP 深度：不只是 ping
- ICMP type/code 全表
- Path MTU Discovery 的細節（為什麼 PMTUD blackhole 是真實災難）
- 為什麼 GFW 用 ICMP 做 active probing

### 1.7 NAT 完整分類學
- Full Cone / Address-Restricted / Port-Restricted / Symmetric
- Carrier-Grade NAT (CGNAT) 對 P2P 與翻牆的影響
- **論文**：Behavior of and Requirements for Internet Firewalls and NATs (RFC 5382)

### 1.8 TCP 完整解剖（一）：連線管理
- 三次握手的狀態機完整圖（含所有邊界狀態：SYN_RECV、TIME_WAIT、FIN_WAIT_2）
- TCP Fast Open（RFC 7413）—— 為什麼 GFW 對 TFO 特別敏感
- 半開連線、SYN cookies、防 DoS

### 1.9 TCP 完整解剖（二）：可靠傳輸
- 序號、ACK、SACK、DSACK
- 重傳：RTO 計算（Karn's algorithm）、快速重傳、F-RTO、ER
- **原始碼**：Linux `net/ipv4/tcp_input.c`

### 1.10 TCP 完整解剖（三）：擁塞控制
- AIMD 的最優性證明
- Reno → NewReno → Cubic → BBR → BBRv3 完整演化
- **論文**：BBR: Congestion-Based Congestion Control (CACM 2017)
- 為什麼 Hysteria 的 Brutal 算法在「自私」假設下能 work

### 1.11 TCP 進階話題
- TCP Offload Engine、TSO/GSO/USO、為什麼開了之後 wireshark 看到 64K 「封包」
- Multipath TCP (MPTCP) — Apple 在用、可能的翻牆應用
- TCP-AO（RFC 5925）取代 TCP-MD5 的故事

### 1.12 UDP 完整解剖
- header 8 bytes 一一拆解
- UDP-Lite、UDP fragmentation 為什麼很糟
- UDP socket 的 connect() 為什麼有意義

### 1.13 IPv6 完整解剖
- 不只是「位址變長」：header 簡化、extension header、SLAAC、Privacy Extensions、Happy Eyeballs
- IPv6 在翻牆場景的優劣（GFW IPv6 部署狀態）
- **論文**：Measuring IPv6 Adoption (SIGCOMM 2014)

### 1.14 DNS 完整解剖
- 報文格式逐 byte
- 遞迴/迭代/權威、cache poisoning（Kaminsky 攻擊）
- DNSSEC 為什麼失敗、為什麼 DoH/DoT/DoQ 取而代之
- ECS（EDNS Client Subnet）對 CDN 與翻牆的雙刃影響
- **論文**：Where The Wild Things Are: Brute-Force SSH Attacks ... (DNS measurement 系列)

### 1.15 BGP：「網際網路為什麼會塞」的根本原因
- AS、Tier 1/2/3、IXP
- BGP 路由洩漏與劫持（YouTube/Pakistan 事件、AS7007 事件）
- **論文**：Investigating the Impact of DDoS Attacks on DNS Infrastructure
- 為什麼這對「中轉節點」「BGP 加速」這些機場行話有意義

### 1.16 CDN 與 Anycast
- Anycast 怎麼工作、CDN 的選路邏輯
- Cloudflare 的 IP 段、為什麼 CF Workers 能當免費中轉
- **論文**：A First Look at Modern Enterprise Traffic (IMC)

### 1.17 把所有東西串起來：「點開 google.com 的 50 ms」
真實 packet capture 的 frame-by-frame 講解：從 ARP 到 DNS 到 TCP+TLS 到 HTTP 到渲染。

### 1.18 Linux 網路 stack 巡禮
- skbuff 結構、netfilter hooks、qdisc、TC
- 一個封包從 NIC 到 socket 的完整路徑（圖 + 對應原始碼檔案）
- **原始碼**：Linux `net/core/dev.c`、`net/ipv4/ip_input.c`、`net/ipv4/tcp_ipv4.c`

---

## Part 2 — 高效能 I/O 與 kernel 網路（14 堂）

> **深度準繩**：學完能寫一個 1M qps 的 echo server；能用 eBPF 做 packet-level 監控；能解釋 io_uring 的 submission queue / completion queue 設計。

### 2.1 從 select 到 epoll 的演化
- select / poll 的 O(n) 為什麼是死路
- epoll 的 edge-triggered vs level-triggered 完整語意
- **原始碼**：Linux `fs/eventpoll.c`

### 2.2 io_uring：Linux I/O 的未來
- 設計哲學（無系統呼叫熱路徑）
- SQE/CQE、polling、registered files/buffers
- 為什麼 5.x kernel 出來後高效能網路全跳船
- **論文**：The io_uring Asynchronous I/O Interface (Axboe 2019)

### 2.3 零拷貝技術全解
- splice / sendfile / MSG_ZEROCOPY / SO_ZEROCOPY
- mmap 大頁、HUGETLB
- 為什麼 TLS 偏偏不能零拷貝（要加密內容），kTLS 怎麼解

### 2.4 kTLS：把 TLS 塞進 kernel
- kernel 4.13 引入的 kTLS、現在的 status
- 為什麼 nginx + kTLS 可以 sendfile 加密檔案
- **對我們的意義**：協議能不能受益於 kTLS

### 2.5 eBPF 入門：Linux 的可程式化革命
- 什麼是 eBPF、verifier 怎麼工作、JIT
- BCC / bpftrace / libbpf 工具鏈
- 一個簡單例子：監控 TCP 重傳

### 2.6 eBPF 進階：對網路的意義
- TC eBPF、socket filter、cgroup-bpf
- **對我們的意義**：能不能用 eBPF 做更早期的封包改寫、做客戶端側的協議實作

### 2.7 XDP：在驅動層處理封包
- XDP_PASS / XDP_DROP / XDP_TX / XDP_REDIRECT
- AF_XDP socket
- **論文**：The eXpress Data Path (CoNEXT 2018)

### 2.8 DPDK：完全 bypass kernel
- Poll-mode driver、大頁、NUMA-aware
- 為什麼資料中心和 CDN 用 DPDK
- **對我們的意義**：高端伺服器端能否選 DPDK

### 2.9 用戶態 TCP stack
- mTCP、F-Stack、Seastar、TCP/IP in userspace
- **論文**：mTCP: A Highly Scalable User-level TCP Stack (NSDI 2014)

### 2.10 macOS 上能做什麼
- kqueue（epoll 的對應物）
- Network Extension framework
- macOS 為什麼**沒有** eBPF/XDP 對等物（DTrace 算半個）

### 2.11 TUN/TAP 完整深度
- /dev/net/tun 的 ioctl 介面
- TUN 多 queue、IFF_TUN_EXCL、IFF_NO_PI
- macOS utun 與 Linux tun 的真實差異
- **原始碼**：Linux `drivers/net/tun.c`

### 2.12 網路命名空間 (netns)
- clone(CLONE_NEWNET) 內部
- veth pair、bridge、netns + iptables
- 怎麼用 netns 做協議測試環境

### 2.13 流量整形：tc / netem
- htb / fq / fq_codel / cake
- netem 模擬丟包/延遲/亂序——**這是我們對抗測試的核心工具**
- **對我們的意義**：怎麼用 netem 模擬「中美鏈路 5% 丟包 200ms RTT」

### 2.14 高效能網路的最終 picture
把上面 13 堂串起來：一個 packet 從 NIC（DMA + AF_XDP）到 user space（io_uring + zero-copy）到應用程式（協議邏輯）的完整最佳化路徑圖。

---

## Part 3 — 密碼學：從數論到後量子（16 堂）

> **深度準繩**：學完能讀懂任一篇 IACR ePrint 論文的 abstract 與 intro，能用 ProVerif 驗證自己設計的協議。

### 3.1 密碼學的目標分類學
機密性 / 完整性 / 認證 / 不可否認性 / 前向保密 / 後相容性。

### 3.2 對稱加密：從 block cipher 到現代 AEAD
- AES 的 Rijndael 設計、AES-NI 硬體加速
- 模式：ECB（為什麼是死的）、CBC、CTR、GCM、CCM
- ChaCha20 設計，為什麼軟體效能勝 AES
- **論文**：Authenticated Encryption: Relations among Notions (Bellare, Namprempre 2000)

### 3.3 雜湊函數
- Merkle-Damgård 結構、長度延伸攻擊
- SHA-2、SHA-3 (Keccak)、BLAKE2、BLAKE3
- KDF：HKDF（RFC 5869）、Argon2、scrypt

### 3.4 公鑰密碼學一：RSA
- 數論基礎（剛好夠：歐拉定理、CRT）
- RSA-OAEP / RSA-PSS、為什麼別用 textbook RSA
- **論文**：Twenty Years of Attacks on the RSA Cryptosystem (Boneh 1999)

### 3.5 公鑰密碼學二：橢圓曲線
- 群論到 ECDLP 的最短路徑
- Curve25519、Ed25519、Ristretto255
- **論文**：Curve25519: new Diffie-Hellman speed records (Bernstein 2006)

### 3.6 金鑰交換協議
- DH、ECDH、X25519
- **三方金鑰交換**：MQV、HMQV、Triple DH
- **論文**：The OPTLS Protocol and TLS 1.3 (Krawczyk, Wee 2015)

### 3.7 數位簽章
- ECDSA / EdDSA 的細節差異（為什麼 ECDSA 對隨機數敏感）
- Schnorr、BLS（聚合簽章）
- 證書透明度（CT）為什麼重要

### 3.8 Noise Protocol Framework 完整精讀
- 命名規則（IK / XK / NK / IX / XX...）
- 每個 pattern 的安全屬性
- WireGuard 的 Noise IK + cookie reply
- **論文**：The Noise Protocol Framework (Perrin 2018)

### 3.9 PAKE：用密碼做金鑰交換
- SRP、SPAKE2、OPAQUE
- **對我們的意義**：能不能用 PAKE 設計「弱認證強保護」的協議

### 3.10 零知識證明入門
- Sigma protocol、Schnorr identification
- zk-SNARK / zk-STARK 概念
- **對我們的意義**：未來協議能不能用 ZK 做匿名認證

### 3.11 後量子密碼（PQC）
- ML-KEM (Kyber)、ML-DSA (Dilithium)、SLH-DSA (SPHINCS+)
- TLS 1.3 hybrid X25519+Kyber 的部署現況（Cloudflare 2023~ 已部署）
- **對我們的意義**：SOTA 協議要不要 PQ-ready

### 3.12 隨機性
- /dev/random vs /dev/urandom 的爭論
- getrandom() 的勝利
- 為什麼很多協議因為 PRNG 出包（Debian OpenSSL、Sony PS3）

### 3.13 側信道攻擊概論
- Timing、cache、power、acoustic
- constant-time programming（為什麼 `if (a == b)` 可能洩密）
- **論文**：Lucky Thirteen: Breaking the TLS and DTLS Record Protocols

### 3.14 現代密碼工程實踐
- libsodium、ring、BoringSSL 的 API 哲學
- 「不要自己寫密碼學」 vs 「我們就是要設計新協議」的張力如何處理
- 必看：Cryptographic Right Answers (Latacora 2018)

### 3.15 形式化驗證入門
- ProVerif：基於 applied pi-calculus
- Tamarin：基於 multiset rewriting
- CryptoVerif：computational model
- 第一次親手用 ProVerif 驗證一個簡單 KE 協議

### 3.16 整合：設計協議的密碼學工具箱
從前 15 堂的工具，整理成一張「設計新協議時你會選什麼」的決策樹。
**這是 Phase I 密碼學的期末考。**

---

## Part 4 — TLS / QUIC 內部完全解剖（12 堂）

> **深度準繩**：學完能逐 byte 重現 TLS 1.3 ClientHello；能解釋 QUIC packet number space 為什麼這樣設計。

### 4.1 TLS 歷史：SSL 2 到 TLS 1.3 的血淚史
為什麼每一版都有重大漏洞（POODLE、BEAST、CRIME、Heartbleed、Logjam、ROBOT...）。

### 4.2 TLS 1.2 vs TLS 1.3 完整對比
握手次數、加密原語、moved-up 的東西。

### 4.3 TLS 1.3 握手完整解剖（RFC 8446 精讀）
逐 byte 拆 ClientHello / ServerHello / EncryptedExtensions / Certificate / CertificateVerify / Finished。

### 4.4 TLS 擴展深度
- SNI / ALPN / Supported Groups / Key Share / PSK
- Application-Layer Protocol Settings (ALPS)
- 每個擴展對指紋（JA3/JA4）的貢獻

### 4.5 0-RTT 與重放攻擊
- 為什麼 0-RTT 是把雙刃劍
- anti-replay 機制的取捨

### 4.6 ECH (Encrypted Client Hello) 完整解剖
- HPKE 是什麼
- ECH 的 outer/inner ClientHello
- Cloudflare 的部署、各國的反應、GFW 對 ECH 的態度
- **論文/draft**：draft-ietf-tls-esni-17

### 4.7 QUIC 完整解剖（一）：transport 層
- UDP datagram 上面的 packet number、frame、stream
- congestion control & loss recovery（RFC 9002）
- **論文**：The QUIC Transport Protocol: Design and Internet-Scale Deployment (SIGCOMM 2017)

### 4.8 QUIC 完整解剖（二）：握手
- QUIC + TLS 1.3 整合（RFC 9001）
- Initial / Handshake / 1-RTT packet
- Retry 機制與 token

### 4.9 QUIC 完整解剖（三）：進階
- 連線遷移（connection migration）
- 0-RTT in QUIC
- QUIC v2、QUIC datagram extension（RFC 9221）

### 4.10 HTTP/3 與 MASQUE
- HTTP/3 的 frame 結構
- MASQUE（Multiplexed Application Substrate over QUIC Encryption）— 把 QUIC 當隧道
- **對我們的意義**：MASQUE 是 SOTA 翻牆的潛在新方向

### 4.11 quic-go 原始碼通讀
逐目錄讀 quic-go，跟 RFC 9000/9001/9002 對照。
**這是 Part 4 的期末考之一**。

### 4.12 比較：HTTP/2 vs HTTP/3 vs MASQUE
從翻牆視角審視三者的優劣。

---

## Part 5 — 形式化方法（8 堂）

> **深度準繩**：學完能用 TLA+ 規格化你協議的關鍵不變量；用 ProVerif 證明 secrecy/authenticity。

### 5.1 為什麼要形式化
- TLS 1.3 設計時就跟 ProVerif/Tamarin 共同進化
- 沒形式化的協議出過什麼事（Needham-Schroeder 17 年才發現缺陷）

### 5.2 TLA+ 入門
- 狀態機建模、temporal logic、PlusCal
- 用 TLA+ 建模一個 SOCKS5 握手

### 5.3 TLA+ 進階
- TLC model checker、refinement
- Apalache（symbolic）

### 5.4 Applied Pi-Calculus 與 ProVerif
- 進程代數基礎
- ProVerif 的 Horn clause 後端
- 親手驗證 Diffie-Hellman

### 5.5 ProVerif 實戰：驗證 Noise IK
重現 WireGuard 論文裡的 ProVerif 證明。

### 5.6 Tamarin Prover
- multiset rewriting
- 與 ProVerif 的差異
- 驗證 TLS 1.3 的範例

### 5.7 CryptoVerif：computational model
為什麼有時候 symbolic 不夠、要 computational 證明。

### 5.8 設計協議的方法論：spec-first
從威脅模型 → 形式化規格 → 證明 → 實作的方法論流程。

---

# Phase II：SOTA 解剖

> **目標**：把現有所有 SOTA 協議拆解到「能逐行解釋 + 能說出每個設計取捨的歷史」。
> **出 Phase II 標準**：能在任何技術會議上跟 RPRX、Tobias、cnbatch 等核心開發者討論技術細節。

---

## Part 6 — 真 VPN 協議精讀 + 原始碼（10 堂）

### 6.1 IPsec 完整解剖
- ESP / AH / SA / SAD / SPD
- IKEv1 vs IKEv2
- 為什麼配置噩夢

### 6.2 OpenVPN 完整解剖
- TLS 控制通道 + 自訂資料通道
- 為什麼曾被 GFW 識別

### 6.3 WireGuard whitepaper 精讀
12 頁逐段拆解。

### 6.4 WireGuard 原始碼通讀（一）：握手
wireguard-go 的 noise.go、handshake.go 逐函數讀。

### 6.5 WireGuard 原始碼通讀（二）：資料路徑
device.go、send.go、receive.go。

### 6.6 WireGuard 原始碼通讀（三）：TUN/UDP 整合
跟 Part 2.11 接上。

### 6.7 為什麼 WireGuard 在中國被打
- 特徵：固定 handshake 大小、固定 type byte、UDP 流量模式
- amneziawg：對 WireGuard 的混淆 fork

### 6.8 BoringTun（Cloudflare 的 Rust 實作）對比
為什麼 Cloudflare 重寫一次、設計取捨差異。

### 6.9 WireGuard 在 kernel 的實作（Linux）
跟 wireguard-go 的差異、效能對比。

### 6.10 WireGuard 給我們的啟示
作為協議設計者，我們從 WireGuard 學到什麼、不該學什麼。

---

## Part 7 — 翻牆協議完整演化史（16 堂）

### 7.1 SOCKS / HTTP CONNECT：祖宗（RFC 1928 精讀）
完整握手狀態機。

### 7.2 Shadowsocks 第一代（2012~2017）
- 流加密 + 無認證的設計
- 為什麼被 GFW 主動探測打爆
- **論文**：How China Detects and Blocks Shadowsocks (IMC 2020)

### 7.3 Shadowsocks AEAD（2017~2022）
為什麼這個改版 + 改了什麼還不夠。

### 7.4 Shadowsocks 2022（SS-2022）
- Spec：https://shadowsocks.org/doc/sip022.html 精讀
- 固定金鑰 + 防重放 + user-key 分離

### 7.5 V2Ray VMess 完整解剖
- 報文格式
- alterID 為什麼後來廢除
- 設計缺陷史

### 7.6 V2Ray 傳輸層抽象
- TCP / mKCP / WebSocket / HTTP/2 / gRPC / QUIC
- 各自的隱藏特徵

### 7.7 Trojan 完整解剖
- 哲學：偽裝成 HTTPS
- fallback 設計
- 對主動探測的天然抗性

### 7.8 VLESS 完整解剖
- 為什麼把 VMess 的加密層去掉
- 報文格式逐 byte

### 7.9 XTLS-Vision 完整解剖
- 內層 TLS 直通的設計
- 為什麼能省一層加密還安全
- **原始碼**：Xray-core `proxy/vless/encoding/encoding.go`

### 7.10 REALITY 完整解剖（一）：威脅模型
為什麼自簽證書時代結束、為什麼必須借真實網站。

### 7.11 REALITY 完整解剖（二）：協議細節
- 借用 TLS 握手的精確機制
- short-id 的設計
- **原始碼**：Xray-core `transport/internet/reality/`

### 7.12 REALITY 完整解剖（三）：限制與已知攻擊
社群討論過的所有 REALITY 潛在弱點與作者回應。

### 7.13 Naïve / Snell / 其他小眾
快速掃過，知道生態還有什麼。

### 7.14 Xray-core 原始碼總覽
inbound/outbound/router 三段架構，讀路由匹配引擎。

### 7.15 sing-box 原始碼總覽
與 Xray 的設計差異，為什麼 sing-box 更模組化。

### 7.16 mihomo (Clash.Meta) 原始碼總覽
規則引擎深度、與 sing-box 的對比。

---

## Part 8 — QUIC 系協議深度（10 堂）

### 8.1 為什麼 QUIC 系協議是當前另一條主線
TCP-over-TCP、TCP-over-everything 的問題。

### 8.2 Hysteria v1 完整解剖
- 自訂 Brutal 擁塞控制
- QUIC 上的設計

### 8.3 Hysteria 2 完整解剖
- 與 v1 的差異
- HTTP/3 masquerading
- **原始碼**：HyNetwork/hysteria

### 8.4 TUIC v4 vs v5
- 為什麼從 v4 重新設計
- 報文格式、流管理

### 8.5 NaiveProxy 完整解剖
- 直接用 Chromium 的網路 stack
- 為什麼這對 TLS 指紋抗識別有獨特優勢

### 8.6 QUIC 在中國的命運
- 為什麼 GFW 對 QUIC 又愛又恨
- 已知的 QUIC 識別與封鎖事件

### 8.7 quic-go fork：讓 QUIC 更難識別
社群已有的 fork 在改什麼。

### 8.8 MASQUE 深度（接 4.10）
為什麼這可能是下一代翻牆協議的基礎。

### 8.9 自製 QUIC 變體：可行性分析
從零寫 QUIC 是不可能的，怎麼做最小改動達到目的。

### 8.10 QUIC 系給我們的啟示
作為協議設計者，速度方向我們從這裡學到什麼。

---

## Part 9 — 審查對抗：GFW 完整研究綜述 + 自建測試平台（14 堂）

### 9.1 GFW 架構與能力綜述
- 旁路 vs in-path
- DNS 污染、IP 封鎖、TCP RST 注入、SNI 黑名單、active probing、ML 流量分類
- **論文集**：GFW.report 全部論文（~25 篇）

### 9.2 GFW 對 SS 的識別與封鎖
- IMC 2020 那篇論文逐節精讀
- 復現他們的探測實驗（在你 VPS 上）

### 9.3 GFW 對 Trojan 的識別嘗試
社群觀察與已知封鎖案例。

### 9.4 GFW 對 VLESS+REALITY 的態度
為什麼到 2026 年還沒被大規模封。

### 9.5 GFW 對 QUIC / HTTP/3 的處理
封 UDP / 限速 / DPI 嘗試。

### 9.6 主動探測（Active Probing）完整研究
- **論文**：Examining How the Great Firewall Discovers Hidden Circumvention Servers (IMC 2015)
- **論文**：How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic (USENIX Security 2023)

### 9.7 全加密流量檢測（Fully Encrypted Traffic Detection）
USENIX Security 2023 那篇打到 SS/VMess 的論文細節。

### 9.8 流量指紋與 ML 分類
- 封包大小、時序、burst、flow size 特徵
- 經典工具：nDPI、Zeek、Beauty、FlowPrint
- **論文**：FlowPrint (NDSS 2020)

### 9.9 TLS 指紋全研究
- JA3 → JA3S → JA4/JA4+ → JA4S 演化
- uTLS 怎麼模擬 Chrome 指紋
- **論文**：Detection of Anomalous TLS Traffic ...

### 9.10 自建 GFW 模擬測試平台（一）：架構
- 兩台 VPS：一台「客戶端側」一台「伺服器側」
- 中間節點：Linux + tc + nftables + nDPI + Zeek + 自訂 ML 分類器

### 9.11 自建測試平台（二）：被動 DPI
nDPI 識別器的部署與規則寫法。

### 9.12 自建測試平台（三）：主動探測
復現 IMC 2015 論文的探測手法、可程式化探測客戶端。

### 9.13 自建測試平台（四）：ML 分類
訓練一個簡單 ML 分類器（CNN on packet size sequence），看能不能識別 VLESS+REALITY。

### 9.14 GFW 給我們的啟示
作為協議設計者，威脅模型要包含哪些對手能力。

---

# Phase III：設計與實作

> **目標**：產出新協議：spec + 形式化證明 + 兩個語言實作（Go + Rust） + 對抗評測 + 論文初稿。
> **出 Phase III 標準**：協議在自建測試平台上對抗所有已知識別手段；單實例吞吐 ≥ Hysteria2；論文可投 USENIX Security / NDSS。

---

## Part 10 — 對抗式流量分析與反制（12 堂）

### 10.1 流量分析的數學基礎
資訊理論視角：Shannon entropy、KL divergence。

### 10.2 經典統計指紋
- 封包大小直方圖、IAT (inter-arrival time)、burst pattern
- **論文**：Walkie-Talkie: An Efficient Defense Against Passive Website Fingerprinting

### 10.3 ML / DL 分類器
- CNN / LSTM / Transformer 對 packet sequence
- **論文**：Deep Fingerprinting (CCS 2018)

### 10.4 對抗式樣本（adversarial examples）
- 在流量上的對應：怎麼設計流量讓分類器分不出來
- **論文**：Adversarial Examples for Network Traffic Classification

### 10.5 流量混淆技術全綜述
- padding、splitting、morphing、constant-rate
- 各自的代價（頻寬 overhead）

### 10.6 obfs4 / meek / Snowflake 精讀
Tor 那邊的 pluggable transport 怎麼做。

### 10.7 規律性破壞（regularization disruption）
讓「沒有規律」本身不成為特徵。

### 10.8 連線級偽裝 vs 應用級偽裝
HTTPS 偽裝、瀏覽器偽裝、合法應用偽裝。

### 10.9 Probabilistic decoy traffic
混入假流量、cover traffic 的設計取捨。

### 10.10 SoK：Censorship Resistance
**論文**：SoK: Making Sense of Censorship Resistance Systems (PoPETs 2016) 完整精讀。

### 10.11 我們協議的反制設計：威脅 → 防禦對應表
把 Part 9 + Part 10 學到的所有對手能力整理成防禦設計清單。

### 10.12 反制設計的可證明性
能不能用形式化方法證明「對某類分類器免疫」（research-level open problem）。

---

## Part 11 — 設計階段：威脅模型、spec、形式化驗證（14 堂）

### 11.1 威脅模型完整撰寫
誰是對手 / 對手能做什麼 / 我們保證什麼 / 我們不保證什麼。

### 11.2 設計目標 / 非目標
精確版的「同時頂尖抗審查 + 頂尖速度」拆解成可衡量的子目標。

### 11.3 設計空間探索
- 傳輸：TCP / TLS / QUIC / MASQUE 選哪個
- 握手：Noise / TLS / 自訂
- 偽裝：REALITY-like / HTTPS / SSH / 視訊串流？
- 流量整形策略

### 11.4 主架構決策
做出第一版 design choice，寫成 design rationale 文件。

### 11.5 Spec 撰寫（一）：報文格式
RFC 風格，逐 byte 定義。

### 11.6 Spec 撰寫（二）：握手與狀態機
完整狀態機圖 + 偽碼。

### 11.7 Spec 撰寫（三）：錯誤處理與安全性考量
RFC 的「Security Considerations」section 要寫得跟 TLS 1.3 一樣詳盡。

### 11.8 Spec 撰寫（四）：可擴展性設計
版本協商、擴展機制、向前/向後相容。

### 11.9 形式化建模（一）：TLA+
規格化關鍵不變量。

### 11.10 形式化建模（二）：ProVerif
證明 secrecy / authenticity / forward secrecy。

### 11.11 形式化建模（三）：Tamarin（如有需要）
驗證更複雜的屬性。

### 11.12 設計 review：對著 Part 10 的威脅 → 防禦表逐項檢查
找出設計 hole，修。

### 11.13 第二版 spec
吸收 review 反饋，產出最終 spec v0.1。

### 11.14 設計階段總結
寫一份 design document，可以拿給領域內研究者 review。

---

## Part 12 — 實作、評測、發表（24 堂）

### 12.1 實作技術選型
Go vs Rust vs C，scope 與取捨。

### 12.2 實作（一）：核心密碼學原語
基於 ring / RustCrypto，constant-time。

### 12.3 實作（二）：握手
對著 spec 一字一句實作。

### 12.4 實作（三）：資料路徑
零拷貝、io_uring、AF_XDP（Linux）。

### 12.5 實作（四）：流量整形
Part 10 的反制設計落地。

### 12.6 實作（五）：客戶端整合
- 寫 sing-box plugin
- 寫 Clash 客戶端適配
- 訂閱格式設計

### 12.7 實作（六）：服務端
- 寫 panel（最小可用）
- 與 Caddy / Nginx 整合 fallback

### 12.8 fuzzing
go-fuzz / cargo-fuzz 對協議解析器。

### 12.9 單元測試與整合測試
覆蓋率目標 ≥ 80%。

### 12.10 互通性測試
不同實作（如未來別人也實作我們的協議）能不能互通。

### 12.11 效能 baseline
在統一測試環境量測 Hysteria2 / TUIC / VLESS+REALITY 的吞吐、延遲、CPU、記憶體。

### 12.12 效能評測（一）：吞吐
我們的協議 vs baseline。

### 12.13 效能評測（二）：高丟包鏈路
netem 模擬 5%/10%/15% 丟包下對比。

### 12.14 效能評測（三）：CPU / 記憶體
單實例極限。

### 12.15 抗審查評測（一）：被動 DPI
nDPI / Zeek / Beauty / FlowPrint 上跑。

### 12.16 抗審查評測（二）：主動探測
復現所有已知主動探測手法。

### 12.17 抗審查評測（三）：ML 分類
訓練幾個 SOTA 分類器試圖打我們。

### 12.18 真實環境測試
實際在中國境內節點測試（如有合作者）。

### 12.19 結果分析與設計反饋迭代
評測發現問題 → 回到 11 改 spec → 12 改實作。

### 12.20 文件撰寫
README / spec / 部署指南 / 開發者文件。

### 12.21 發布準備
GitHub release / 版本管理 / signature。

### 12.22 論文撰寫（一）：intro / related work
USENIX Security / NDSS 風格。

### 12.23 論文撰寫（二）：design / evaluation
重點 section。

### 12.24 結業：把所有東西打包
- 新協議完整 codebase
- spec v1.0
- 形式化證明
- 評測數據
- 論文初稿
- 一份「我學到什麼」反思文件

---

## 出口能力

完成這 12 個 Part 後你具備：

1. **kernel 工程師等級的網路 + I/O 知識**（Part 1, 2）— 能 patch Linux TCP stack、能寫 eBPF、能用 io_uring
2. **密碼工程師等級的協議設計能力**（Part 3, 5, 11）— 能設計、形式化驗證、實作密碼協議
3. **領域研究者等級的審查對抗知識**（Part 9, 10）— 能複現 GFW.report 級實驗、能評估新協議抗審查能力
4. **資深開發者等級的實作能力**（Part 12）— 能寫出生產級 Go/Rust 網路程式
5. **一個可能成為新 SOTA 的協議**（Part 11, 12）

---

## 教學基礎建設（不變）

- 每堂課文件結構模板（動機 / 概念 / 與經驗連結 / 練習 / 自我檢查 / 延伸）
- glossary.md 隨課成長
- qa/ 收隨堂答疑
- assets/ 放抓包、配置範例（脫敏）
- projects/ 放 Phase III 程式碼

## 進度與節奏

- 你決定每週投入時數
- 每堂結束我會出 self-check，沒過我們重講
- Part 1, 6, 7 有大量原始碼閱讀，會比其他 Part 慢
- Phase II 起每讀一篇論文要寫 1~2 頁讀書筆記放 `notes/papers/`

## 開課儀式

當你說「開始第 X.Y 堂」時，我會：
1. 創建 `lessons/part-N-name/X.Y-slug.md`
2. 按模板寫滿（含論文引用、原始碼路徑、可重現實驗步驟）
3. 更新 glossary.md
4. 在這份 SYLLABUS.md 對應條目加 ✅
