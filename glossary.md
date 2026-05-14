# 術語表（Glossary）

> 每堂課首次出現的術語會自動加進來。之後出現只用簡稱 + 連結，不重複解釋。
> 排序：按英文字母 / 縮寫，中文釋義跟在後面。

---

### GFW (Great Firewall)
**中文**：中國大陸防火長城
**所屬層**：跨層（DNS / TCP / TLS / 流量分析）
**首次出現**：[0.1 — VPN 這個詞被誤用了 30 年](lessons/part-0-orientation/0.1-vpn-misnomer.md)
**一句話**：對線 C（翻牆代理）整門課最主要的對手；它能做的事決定了協議要長什麼樣。

### L3 / L4 / L7
**中文**：第三層（網路層）/ 第四層（傳輸層）/ 第七層（應用層）
**所屬層**：分層模型本身
**首次出現**：[0.1](lessons/part-0-orientation/0.1-vpn-misnomer.md)
**一句話**：VPN 工作在 L3（接管 IP 封包），代理工作在 L4/L7（接管 TCP 連線或 HTTP 請求）；Part 1.1 會詳細展開分層。

### Threat Model
**中文**：威脅模型
**所屬層**：跨層概念
**首次出現**：[0.1](lessons/part-0-orientation/0.1-vpn-misnomer.md)
**一句話**：「你在防誰、那個對手能做什麼」；線 A 真 VPN 防監聽者，線 C 翻牆代理還要再防識別與封鎖。

### TUN / TAP
**中文**：用戶態虛擬網卡（TUN 走 L3 / TAP 走 L2）
**所屬層**：作業系統 / L2~L3
**首次出現**：[0.1](lessons/part-0-orientation/0.1-vpn-misnomer.md)（先提名字，Part 4.3 才正式拆解）
**一句話**：讓用戶態程式（WireGuard、Clash TUN Mode、sing-box）「假扮」成一張網卡接收/發送封包的機制。

### VPN (Virtual Private Network)
**中文**：虛擬私有網路
**所屬層**：L3（典型實作）
**首次出現**：[0.1](lessons/part-0-orientation/0.1-vpn-misnomer.md)
**一句話**：原始定義是「在公開網路上虛擬出一條私有的、能合併網段的加密通道」；今日這個詞被當成三件事在用（真 VPN / 商業 VPN / 翻牆代理）。

### WireGuard
**中文**：當代設計最簡潔的真 VPN 協議
**所屬層**：L3
**首次出現**：[0.1](lessons/part-0-orientation/0.1-vpn-misnomer.md)（提名字，Part 5.4 詳講）
**一句話**：用 Curve25519 + ChaCha20-Poly1305 + Noise IK 做完整套金鑰交換與加密，特徵明顯所以難翻牆，但設計上極乾淨。

### XTLS-Vision / REALITY
**中文**：VLESS 系協議的兩個關鍵增強
**所屬層**：L7 偽裝
**首次出現**：[0.1](lessons/part-0-orientation/0.1-vpn-misnomer.md)（提名字，Part 6.5 詳講）
**一句話**：XTLS-Vision 是效能優化（避免重複加密）；REALITY 是抗識別技術（借真實大網站的 TLS 握手做偽裝）。

### End-to-End Argument
**中文**：端到端論證
**所屬層**：跨層設計原則
**首次出現**：[1.1 — 分層的真實意義](lessons/part-1-networking/1.1-layering-truth.md)
**一句話**：Saltzer-Reed-Clark 1984 提出——某些功能只能在端點完整實作，下層做的只是 performance hint，不能取代端點實作；G6 設計時用來決定什麼放協議內、什麼留給 application。

### Fate Sharing
**中文**：命運共擔
**所屬層**：分散式系統 architecture
**首次出現**：[1.1](lessons/part-1-networking/1.1-layering-truth.md)
**一句話**：Reed 1976 / Clark 1988——connection state 放在 endpoint，不放在 router；router 掛了仍可繼續通訊（Internet survivability 第一的具體實踐）。

### Hourglass Model
**中文**：沙漏模型
**所屬層**：Internet architecture
**首次出現**：[1.1](lessons/part-1-networking/1.1-layering-truth.md)（補遺第 1 節）
**一句話**：IP 是中間 narrow waist，上層 application 與下層 link 都 diverse——這是 Internet 能 30 年 survive 的核心，但也是 GFW 能在 IP 層做 surveillance 的原因。

### ALF / ILP
**中文**：應用層分幀 / 整合層處理
**所屬層**：跨層設計原則
**首次出現**：[1.1](lessons/part-1-networking/1.1-layering-truth.md)
**一句話**：Clark & Tennenhouse 1990 提出——讓 application data unit 決定 packet boundary，避免層間 buffer size 不對齊產生效能 bug；QUIC 設計繼承這個思想。

### PEP (Performance Enhancing Proxy)
**中文**：效能增強代理
**所屬層**：middlebox / L4 違反 e2e
**首次出現**：[1.1](lessons/part-1-networking/1.1-layering-truth.md)（補遺第 1 節）
**一句話**：RFC 3135 定義的中間設備類型，刻意違反 end-to-end 來改善 perf（衛星鏈路 TCP accelerator 為主例）；GFW 是 adversarial 版的 PEP 概念延伸。

### Click Element
**中文**：Click 元件
**所屬層**：router architecture
**首次出現**：[1.1](lessons/part-1-networking/1.1-layering-truth.md)
**一句話**：Kohler 2000 提出——把 router 拆成 ~120 行 C++ 的可組合處理單位，用 directed graph 連起來；sing-box 的 inbound/outbound/route 三段式架構繼承這思想。

### DMA (Direct Memory Access)
**中文**：直接記憶體存取
**所屬層**：hardware / PCIe
**首次出現**：[1.2 — 物理層：你不需要懂電壓，但要懂 PHY/MAC 介面](lessons/part-1-networking/1.2-physical-and-phy-mac.md)
**一句話**：NIC 不透過 CPU 就能直接把 packet 寫進 host RAM（透過 PCIe）；是 zero-copy / kernel bypass 等技術的基石。

### NIC Ring Buffer
**中文**：NIC 環狀緩衝區
**所屬層**：driver / NIC interface
**首次出現**：[1.2](lessons/part-1-networking/1.2-physical-and-phy-mac.md)
**一句話**：NIC 跟 driver 共享的環狀資料結構，描述哪些 buffer 可以 DMA、寫到哪、讀到哪；ring 滿了 = packet 被丟，是 throughput 上限的物理體現。

### Receive Livelock
**中文**：接收活鎖
**所屬層**：kernel / interrupt
**首次出現**：[1.2](lessons/part-1-networking/1.2-physical-and-phy-mac.md)
**一句話**：Mogul 1997——pure interrupt-driven kernel 在高 packet rate 下吞吐量崩潰到 0；Linux NAPI / DPDK / netmap / XDP / io_uring 都是其解法的後代。

### NIC Offload (TSO/GSO/GRO/LRO/RSS)
**中文**：網卡卸載
**所屬層**：NIC hardware
**首次出現**：[1.2](lessons/part-1-networking/1.2-physical-and-phy-mac.md)
**一句話**：TSO 切大封包成 MTU、GSO/LRO 合併小封包、RSS 用 5-tuple hash 分到多 core；影響 anti-fingerprinting（wire 上 packet size 跟 app 看到的不同）。

### Zero-copy / Kernel Bypass
**中文**：零拷貝 / 內核旁路
**所屬層**：跨層 IO 設計
**首次出現**：[1.2](lessons/part-1-networking/1.2-physical-and-phy-mac.md)
**一句話**：netmap (2012) / DPDK / AF_XDP 等技術讓 user app 直接讀 NIC ring，跳過 kernel memcpy；單 core 可達 10G+ line rate。

### NAPI (New API)
**中文**：Linux 新網路 API
**所屬層**：Linux kernel
**首次出現**：[1.2](lessons/part-1-networking/1.2-physical-and-phy-mac.md)
**一句話**：2003+ Linux 將 Mogul 1997 polling-after-interrupt 思想 productize；現代所有 Linux NIC driver 用 NAPI 避免 livelock。

### PCIe / DMA Cost Model
**中文**：PCIe / DMA 成本模型
**所屬層**：hardware interconnect
**首次出現**：[1.2](lessons/part-1-networking/1.2-physical-and-phy-mac.md)
**一句話**：Neugebauer 2018——40+ Gbps NIC 時代 PCIe 本身是新瓶頸；Gen3 x8 64B packet 只剩 ~10 Gbps 可用頻寬（vs 物理層 62.96 Gbps）。

### STP / RSTP / MSTP (Spanning Tree Protocol)
**中文**：生成樹協議（家族）
**所屬層**：L2 / IEEE 802.1D
**首次出現**：[1.3 — 乙太網路與 L2](lessons/part-1-networking/1.3-ethernet-l2.md)
**一句話**：Perlman 1985 經典分散式演算法——在有迴路的 L2 拓樸上構造邏輯無迴路 forwarding tree；每 bridge O(1) state、O(diameter) 收斂；RSTP/MSTP 是後續改進；DC 已基本棄用，被 VXLAN+EVPN 取代。

### CAM / TCAM
**中文**：可定址內容記憶體 / 三態 CAM
**所屬層**：switch hardware
**首次出現**：[1.3](lessons/part-1-networking/1.3-ethernet-l2.md)
**一句話**：CAM 做 exact-match（MAC FDB），TCAM 做 ternary-match（含 mask，用於 ACL/route prefix）；TCAM 貴 5-10×，所以企業 switch ACL 條目上限是物理成本決定的。

### VLAN (IEEE 802.1Q) / QinQ
**中文**：虛擬區網 / 雙標籤 VLAN
**所屬層**：L2
**首次出現**：[1.3](lessons/part-1-networking/1.3-ethernet-l2.md)
**一句話**：4-byte tag 含 12-bit VID（上限 4094 個 VLAN）；QinQ (802.1ad) 雙 tag 突破至 ~16M；hyperscaler 規模這仍不夠，被 VXLAN 24-bit VNI 取代。

### VXLAN (RFC 7348)
**中文**：虛擬可擴展區網
**所屬層**：L2-over-L3 overlay
**首次出現**：[1.3](lessons/part-1-networking/1.3-ethernet-l2.md)
**一句話**：把 L2 frame 包進 UDP（port 4789）跨 L3 fabric 傳送；24-bit VNI 支援 16M virtual networks；overhead 50 byte（IPv4 underlay），是 DC overlay 的事實標準。

### Geneve (RFC 8926)
**中文**：泛用網路虛擬化封裝
**所屬層**：L2-over-L3 overlay
**首次出現**：[1.3](lessons/part-1-networking/1.3-ethernet-l2.md)
**一句話**：VXLAN 的 TLV-extensible 後繼者（UDP port 6081）；8-byte 固定 + 0~252 byte TLV options 攜帶 metadata / INT；Cilium 預設、VMware NSX-T 主用。

### EVPN (RFC 7432)
**中文**：以 BGP 為基礎的 L2/L3 VPN
**所屬層**：control plane for L2 overlay
**首次出現**：[1.3](lessons/part-1-networking/1.3-ethernet-l2.md)
**一句話**：用 MP-BGP 廣播 MAC + VNI 學習資訊，取代 VXLAN 原本的 flood-and-learn data-plane 學習；現代 DC fabric 主流 control plane。

### Fat-tree / Clos / Leaf-Spine
**中文**：胖樹 / Clos 多階段交換 / 葉脊
**所屬層**：DC physical topology
**首次出現**：[1.3](lessons/part-1-networking/1.3-ethernet-l2.md)
**一句話**：Al-Fares 2008 把 Leiserson 1985 fat-tree 移植到 DC fabric，用 commodity switch 達成全 bisection bandwidth；現代 hyperscaler 標準拓樸（leaf-spine 是 2-stage 簡化版）。

### TUN vs TAP
**中文**：用戶態虛擬網卡（L3 vs L2）
**所屬層**：OS / virtual interface
**首次出現**：[0.1](lessons/part-0-orientation/0.1-vpn-misnomer.md)（提名字）／[1.3](lessons/part-1-networking/1.3-ethernet-l2.md)（深度展開）
**一句話**：TUN 接 L3 IP packet（WireGuard/Tailscale 預設）、TAP 接 L2 Ethernet frame（含 ARP/broadcast，OpenVPN bridge mode）；G6 永遠不該走 TAP——任何 L2 broadcast 都是流量指紋的 anti-feature。

### LPM (Longest Prefix Match)
**中文**：最長前綴匹配
**所屬層**：L3 routing
**首次出現**：[1.4 IP 層：路由是個圖論問題](lessons/part-1-networking/1.4-ip-routing-graph.md)
**一句話**：IP 路由查找的核心問題——多條 prefix 都 match 目標 IP 時取最長者；不能用 hash table 因為 hash 只解 exact match，催生 30 年的 trie 結構演化。

### FIB vs RIB
**中文**：轉發表 vs 路由表
**所屬層**：L3 / control vs data plane
**首次出現**：[1.4](lessons/part-1-networking/1.4-ip-routing-graph.md)
**一句話**：RIB 是 control plane 持有的「所有候選路由」（從 BGP/OSPF/static 學來），FIB 是 data plane 已決定的「最佳路由」；分離模式是 30 年路由工業界教訓，G6 control/data plane 分離直接受此影響。

### PATRICIA / Radix Trie
**中文**：Patricia 樹 / Radix 樹（path-compressed binary trie）
**所屬層**：data structure
**首次出現**：[1.4](lessons/part-1-networking/1.4-ip-routing-graph.md)
**一句話**：Morrison 1968 提出——把「只有單一子節點」的長串節點壓成一個（path compression）；BSD 4.3+ 用作 routing table，但對 dense 部分壓縮無幫助。

### LC-trie
**中文**：層壓縮 + 路徑壓縮 Trie
**所屬層**：data structure / Linux kernel
**首次出現**：[1.4](lessons/part-1-networking/1.4-ip-routing-graph.md)
**一句話**：Nilsson & Karlsson 1999——PATRICIA 上加 level compression（dense 子樹展平為多分支），expected search depth = Θ(log log n)；Linux `net/ipv4/fib_trie.c` 直接祖先。

### Tree Bitmap (TBM)
**中文**：雙位圖樹
**所屬層**：data structure / router ASIC
**首次出現**：[1.4](lessons/part-1-networking/1.4-ip-routing-graph.md)
**一句話**：Eatherton, Varghese, Dittia 2004——固定 stride + internal/external bitmap + popcount 索引；硬體 pipeline 友善，Cisco CRS-1 起多數 ASIC FIB 用此家族。

### ECMP / WCMP
**中文**：等成本 / 加權成本多路徑
**所屬層**：L3 routing
**首次出現**：[1.4](lessons/part-1-networking/1.4-ip-routing-graph.md)
**一句話**：對等成本 (ECMP) / 不等成本 (WCMP) 的多條 next-hop 用 5-tuple flow hash 分流——同 flow 同 hash 同 path，避免 TCP reorder；QUIC connection migration 會觸發 rehash。

### Policy Routing (PBR) / fwmark
**中文**：基於策略的路由 / 防火牆標記
**所屬層**：Linux netfilter + routing
**首次出現**：[1.4](lessons/part-1-networking/1.4-ip-routing-graph.md)
**一句話**：Linux 多 routing table + `ip rule` + iptables/nftables 設 fwmark 的組合機制；Clash TUN mode / tun2socks / ss-redir 透明代理底層全靠這個。

### Source Routing / SRv6
**中文**：源路由 / IPv6 段路由
**所屬層**：L3
**首次出現**：[1.4](lessons/part-1-networking/1.4-ip-routing-graph.md)
**一句話**：LSRR/SSRR (RFC 791) 因 anonymity/DDoS 問題 1990s 起被全網 drop；SRv6 (RFC 8754) 把思想復活——信任域內 controller-driven traffic engineering；對 G6 是潛在的 path metadata side channel。

### BGP / RPKI / ROA
**中文**：邊界閘道協議 / RPKI 公鑰基礎設施 / 路由起源授權
**所屬層**：L3 inter-AS routing
**首次出現**：[1.4](lessons/part-1-networking/1.4-ip-routing-graph.md)
**一句話**：BGP-4 (RFC 4271) 是 internet 唯一 inter-AS routing 協議；RPKI (RFC 6480) 用 PKI 證明 prefix→AS 映射緩解 hijack；GFW 理論上有 BGP-level 封鎖能力但成本高、selectivity 低。

### ARP (RFC 826)
**中文**：地址解析協議
**所屬層**：L2/L3 between IPv4 and Ethernet
**首次出現**：[1.5 ARP / NDP / DHCP](lessons/part-1-networking/1.5-arp-ndp-dhcp.md)
**一句話**：Plummer 1982 設計的 IPv4↔MAC 解析協議，gratuitous learning + 無認證設計使 ARP spoofing 成為 LAN-level 攻擊基石，至 2026 仍是企業滲透測試標配。

### NDP (RFC 4861) / SLAAC (RFC 4862)
**中文**：IPv6 鄰居發現 / 無狀態地址自動配置
**所屬層**：ICMPv6 / L3
**首次出現**：[1.5](lessons/part-1-networking/1.5-arp-ndp-dhcp.md)
**一句話**：IPv6 砍 ARP/DHCP 一部分功能合併進 ICMPv6（NS/NA/RS/RA/Redirect）並支援用 RA prefix 直接 SLAAC 配址；仍無認證，rogue RA 是更強的 IPv6 ARP-spoof。

### SEND (RFC 3971) / CGA
**中文**：安全鄰居發現 / 密碼學生成地址
**所屬層**：ICMPv6 security
**首次出現**：[1.5](lessons/part-1-networking/1.5-arp-ndp-dhcp.md)
**一句話**：用 CGA 把 public key hash 進 IPv6 IID + 對 NDP 訊息簽章——正確設計但**無人部署**，因 PKI 缺、CPU cost、無 OS 默認；今日由 RA-Guard L2 filter 充當 pragmatic 替代。

### RA-Guard (RFC 6105/7113)
**中文**：路由通告防護
**所屬層**：L2 first-hop security
**首次出現**：[1.5](lessons/part-1-networking/1.5-arp-ndp-dhcp.md)
**一句話**：L2 switch 過濾 access port 上的 RA，僅 trunk/uplink 允許；RFC 7113 補洞要求解析整條 IPv6 header chain，但多數 commodity switch 仍只實作 stateless 版仍漏。

### DHCP (RFC 2131 / RFC 8415)
**中文**：動態主機設定協議
**所屬層**：L7 over UDP 67/68
**首次出現**：[1.5](lessons/part-1-networking/1.5-arp-ndp-dhcp.md)
**一句話**：DORA 四步握手配 IP + 100+ 種 options 推設定；無認證設計使任何 LAN 同網對手可變 rogue DHCP，TunnelVision 是最新一個 weaponized 案例。

### TunnelVision (CVE-2024-3661)
**中文**：DHCP option 121 繞 VPN 攻擊
**所屬層**：DHCP × OS routing × VPN
**首次出現**：[1.5](lessons/part-1-networking/1.5-arp-ndp-dhcp.md)
**一句話**：Cronce & Moratti 2024-05-06——同 LAN 對手用 rogue DHCP 推 option 121 注入 0.0.0.0/1 + 128.0.0.0/1 兩條 /1 路由，LPM 勝過 VPN 的 /0 default route，繞過所有 routing-based VPN（WG/OpenVPN/IPsec）；唯 Android 因未實作 option 121 免疫。

### SLAAC Privacy (RFC 8981) / Stable Opaque IID (RFC 7217)
**中文**：IPv6 隱私臨時地址 / 穩定但偽隨機 IID
**所屬層**：L3 IPv6 addressing
**首次出現**：[1.5](lessons/part-1-networking/1.5-arp-ndp-dhcp.md)
**一句話**：8981 用 random IID 取代 EUI-64 並定期 rotate（preferred ~1d）；7217 用 PRF(secret, prefix) 生成 stable-but-unlinkable IID；通常**並用**取兩者優點——G6 client identifier 設計參考此模式。

### MAC Randomization Defeat (Vanhoef 2016)
**中文**：MAC 隨機化被擊敗
**所屬層**：WiFi PHY/MAC
**首次出現**：[1.5](lessons/part-1-networking/1.5-arp-ndp-dhcp.md)
**一句話**：Vanhoef et al. 2016——即便 random MAC，probe IE 組合 + scrambler seed + SSID list + timing 四個 side channel 可達 ~95% deanonymize rate；G6 不能依賴 OS-level MAC randomization 做匿名保證。

### Captive Portal Detection (RFC 7710/8910/8908)
**中文**：強制門戶網路偵測
**所屬層**：DHCP/RA + HTTP
**首次出現**：[1.5](lessons/part-1-networking/1.5-arp-ndp-dhcp.md)
**一句話**：飯店/機場 WiFi 登入頁問題；OS 用 canary URL probe（Apple/Microsoft/Google 各家）+ RFC 8910 標準化 portal URL via DHCP option 114 / RA option；G6 client 啟動流程必須處理。

### ICMP (RFC 792 / 4443)
**中文**：互聯網控制訊息協議
**所屬層**：L3 control
**首次出現**：[1.6 ICMP 深度](lessons/part-1-networking/1.6-icmp-deep.md)
**一句話**：跑在 IP 之上的 control plane（IPv4 protocol 1 / IPv6 protocol 58）；無認證使其在過去 30 年反覆成為攻擊面與設計教訓來源，PMTUD / traceroute / NDP 全部都靠它。

### PMTUD 三代 (RFC 1191 / 4821 / 8899)
**中文**：路徑 MTU 探測協議家族
**所屬層**：transport-layer / network-layer 交介
**首次出現**：[1.6](lessons/part-1-networking/1.6-icmp-deep.md)
**一句話**：Classical（1990，ICMP-dependent，公網 ~28% blackhole）→ PLPMTUD（2007，TCP 自探）→ DPLPMTUD（2020，QUIC/SCTP/datagram 統一標準）；G6 必走 DPLPMTUD。

### PMTUD Blackhole
**中文**：路徑 MTU 探測黑洞
**所屬層**：L3/L4 互動
**首次出現**：[1.6](lessons/part-1-networking/1.6-icmp-deep.md)
**一句話**：firewall drop ICMP type 3 code 4 / ICMPv6 type 2，導致 sender 永遠收不到「packet too big」訊號，連線在大 packet 後 silently stall——公網 28% / IPv6 18% 普遍率。

### Active Probing (GFW)
**中文**：主動探測
**所屬層**：審查對手能力
**首次出現**：[1.6](lessons/part-1-networking/1.6-icmp-deep.md)
**一句話**：Ensafi et al. 2015 IMC——GFW passive 識別可疑流量後 1 秒~數天內從境內 IP 主動連目標 server replay protocol handshake，命中則永久封 IP+port；G6 必須在威脅模型內列為 first-class。

### Parrot is Dead 教訓
**中文**：完美模仿不可能
**所屬層**：審查對抗 architecture
**首次出現**：[1.6](lessons/part-1-networking/1.6-icmp-deep.md)（提及）；後續 Part 7/9 深入
**一句話**：Houmansadr, Brubaker, Shmatikov 2013——任何 obfuscation protocol 試圖模仿真實 protocol（如 Skype）的 active probing 全部可破；G6 走密碼學 indistinguishability 而非 protocol mimicry。

### NAT Behavior (RFC 4787 / RFC 5382)
**中文**：NAT 行為二維分類
**所屬層**：L3/L4 middlebox
**首次出現**：[1.7 NAT 完整分類學](lessons/part-1-networking/1.7-nat-taxonomy.md)
**一句話**：取代 RFC 3489 的 4-class「Cone」術語——把 NAT 行為拆成 mapping（EIM/Address-Dep/APDM）× filtering（EIF/Address-Dep/APDF）兩維；RFC 4787 REQ-1 強制 EIM、REQ-9 強制 hairpin。

### CGNAT (Carrier-Grade NAT, RFC 6888)
**中文**：電信級 NAT
**所屬層**：ISP infrastructure
**首次出現**：[1.7](lessons/part-1-networking/1.7-nat-taxonomy.md)
**一句話**：ISP 在客戶端家用 NAT 之外再加一層共享公網 IP 的 NAT，使用 100.64.0.0/10 私網池；中國 mobile ~70%、印度 ~80% 用戶在 CGN 下；對 G6 是 anonymity opportunity 也是 P2P/connection limit threat。

### Hole Punching (Ford 2005)
**中文**：穿洞
**所屬層**：NAT traversal
**首次出現**：[1.7](lessons/part-1-networking/1.7-nat-taxonomy.md)
**一句話**：Ford, Srisuresh, Kegel 2005 USENIX ATC 奠基——兩個 NAT 後 peer 同時送 packet 至對方 STUN-discovered mapping 繞過 filter；對 EIM 可行，對 APDM (Symmetric) 必須 TURN relay。

### STUN / TURN / ICE
**中文**：NAT 穿越工具集
**所屬層**：connectivity establishment
**首次出現**：[1.7](lessons/part-1-networking/1.7-nat-taxonomy.md)
**一句話**：STUN (RFC 8489) 探 external mapping；TURN (RFC 8656) 走 relay；ICE (RFC 8445) 整套含 4 種 candidate (host/srflx/prflx/relayed) 的 connectivity check framework；WebRTC 完全依賴。

### QUIC Connection Migration (RFC 9000 §9)
**中文**：QUIC 連線遷移
**所屬層**：L4 transport
**首次出現**：[1.7](lessons/part-1-networking/1.7-nat-taxonomy.md)
**一句話**：QUIC 用 connection ID 取代 4-tuple 作為連線識別 → NAT rebinding / WiFi-cellular 切換不斷連；PATH_CHALLENGE/RESPONSE 驗證新 path；G6 baseline 直接繼承。

### NAT64 / DNS64 / 464XLAT
**中文**：IPv6-only 環境訪問 IPv4 的翻譯機制
**所屬層**：L3/L7
**首次出現**：[1.7](lessons/part-1-networking/1.7-nat-taxonomy.md)
**一句話**：NAT64 (RFC 6146) 把 v4 嵌進 64:ff9b::/96 prefix；DNS64 (RFC 6147) 合成 AAAA；464XLAT (RFC 6877) 加 client-side translation 讓 v4-only app 在 v6-only 網路工作；G6 server 應 dual-stack。

### TCP State Machine (RFC 9293)
**中文**：TCP 狀態機
**所屬層**：L4 transport
**首次出現**：[1.8 TCP 連線管理](lessons/part-1-networking/1.8-tcp-connection-mgmt.md)
**一句話**：RFC 9293 (2022) consolidated TCP spec 取代 RFC 793 + 28 個後續 RFC；11 個 state（含 SYN_RECV/TIME_WAIT/FIN_WAIT 邊界），是分散式 state machine 教學經典與攻防戰場核心。

### SYN Cookies (Bernstein 1996)
**中文**：SYN 餅乾
**所屬層**：TCP server-side
**首次出現**：[1.8](lessons/part-1-networking/1.8-tcp-connection-mgmt.md)
**一句話**：把所有必要 state 編進 SYN+ACK 的 ISN（透過 MAC of 5-tuple+timestamp），讓 SYN flood 攻擊者徒勞——無 ACK = 無 state 分配；Linux SYN queue 將滿時自動啟用。

### TCP Fast Open (RFC 7413)
**中文**：TCP 快開
**所屬層**：L4 0-RTT
**首次出現**：[1.8](lessons/part-1-networking/1.8-tcp-connection-mgmt.md)
**一句話**：在 SYN 同時夾 data + cookie 達 0-RTT；middlebox 處理不一致 + GFW 早期 selective drop + 採用率低使其**事實淘汰**，但設計教訓直接影響 QUIC 0-RTT。

### Challenge ACK (RFC 5961) + Cao 2016 CVE-2016-5696
**中文**：挑戰 ACK 與其反作用攻擊
**所屬層**：TCP defense → side channel
**首次出現**：[1.8](lessons/part-1-networking/1.8-tcp-connection-mgmt.md)
**一句話**：RFC 5961 加 challenge ACK 防 Watson 2004 blind RST injection；Cao 2016 USENIX Security 揭露其 global rate limit (100/sec) 成為 cross-socket side channel——「shared state for security」反成更強漏洞；Linux 4.7 改為 per-socket 修補。

### RST Injection (GFW 主要工具)
**中文**：RST 注入
**所屬層**：TCP attack
**首次出現**：[1.8](lessons/part-1-networking/1.8-tcp-connection-mgmt.md)
**一句話**：on-path attacker（GFW）對識別為敏感的 TCP flow 雙向送偽造 RST 斷連，是 GFW 過去 10 年主要封鎖工具；QUIC 無 RST 概念是 G6 baseline 走 QUIC 的核心動機之一。

### SACK / DSACK (RFC 2018 / 2883)
**中文**：選擇性確認 / 重複選擇性確認
**所屬層**：TCP option
**首次出現**：[1.9 TCP 可靠傳輸](lessons/part-1-networking/1.9-tcp-reliable-delivery.md)
**一句話**：SACK 用 TCP option 帶最多 4 對 (left, right) range 告訴 sender「除 cumulative ACK 外還收到這些 block」；DSACK 進一步告知「重複收到」用於 spurious retx detection。

### Karn's Algorithm (1987)
**中文**：Karn 演算法
**所屬層**：TCP RTT estimator
**首次出現**：[1.9](lessons/part-1-networking/1.9-tcp-reliable-delivery.md)
**一句話**：Karn & Partridge 1987 SIGCOMM 提出——重傳的 segment 不算 RTT sample；保證 RTT estimator 永不被 retx ambiguity 污染；2026 所有 TCP/QUIC 仍用。

### Jacobson 1988 / RTT Estimator + AIMD
**中文**：Jacobson 1988 擁塞避免
**所屬層**：TCP congestion control + RTT estimation
**首次出現**：[1.9](lessons/part-1-networking/1.9-tcp-reliable-delivery.md)，[1.10](lessons/part-1-networking/1.10-tcp-congestion-control.md) 再深入
**一句話**：SIGCOMM '88 經典——把 4.3BSD TCP 加 7 個 algorithm 解 1986 congestion collapse；conservation of packets + AIMD + slow-start + RTO = SRTT + 4×RTTVAR；過去 40 年所有 TCP/QUIC 改進的源頭。

### RACK-TLP (RFC 8985, 2021)
**中文**：基於時間的損失偵測 + 尾部探測
**所屬層**：TCP / QUIC loss detection
**首次出現**：[1.9](lessons/part-1-networking/1.9-tcp-reliable-delivery.md)
**一句話**：Cheng, Cardwell et al. 2021 RFC 8985——RACK 用 per-segment timestamp 取代 3-dupACK 偵測 loss（對 reorder 友善、能 detect multiple loss）；TLP 用 probe 觸發 ACK feedback 避免 RTO；QUIC RFC 9002 loss detection 直接 derive。

### F-RTO (RFC 5682) / Spurious RTO Detection
**中文**：前向 RTO 復原
**所屬層**：TCP recovery
**首次出現**：[1.9](lessons/part-1-networking/1.9-tcp-reliable-delivery.md)
**一句話**：RTO 觸發後不立即縮窗，而送 2 個 new segment 探測——若 ACK 對應 new segment 則判定 RTO 是 spurious（如 mobile WiFi↔cellular 切換）並退出 recovery；mobile G6 必要。

### PRR (Proportional Rate Reduction, RFC 6937)
**中文**：比例速率縮減
**所屬層**：TCP recovery pacing
**首次出現**：[1.9](lessons/part-1-networking/1.9-tcp-reliable-delivery.md)
**一句話**：Mathis, Dukkipati, Cheng 2013——在 recovery 期間精確平衡 in-flight packet 與 ACK 釋放速率，避免 secondary burst loss；Linux 預設 enabled，G6 應 inherit。

### AIMD / Chiu-Jain 1989
**中文**：加性增乘性減 / Chiu-Jain 最優性
**所屬層**：congestion control 理論
**首次出現**：[1.10 TCP 擁塞控制](lessons/part-1-networking/1.10-tcp-congestion-control.md)
**一句話**：Chiu & Jain 1989 證明——在 binary congestion feedback 下，AIMD 是達到 fair allocation 與 high utilization 的 distributed 最優策略；AIAD/MIMD/MIAD 各自失敗；4 種 sender 策略中只有 AIMD 收斂到 fairness × efficiency line 交點。

### CUBIC (Ha-Rhee-Xu 2008, RFC 9438)
**中文**：CUBIC 擁塞控制
**所屬層**：L4 TCP/QUIC CC
**首次出現**：[1.10](lessons/part-1-networking/1.10-tcp-congestion-control.md)
**一句話**：cwnd 以最後 loss 為原點的三次函數增長——high-BDP 友善 + RTT-不敏感 + 接近 W_max 謹慎、遠離積極；Linux 預設、全網 65% server 採用；仍 loss-based。

### BBR (Cardwell 2017) / BBRv2 / BBRv3
**中文**：基於模型的擁塞控制
**所屬層**：L4 model-based CC
**首次出現**：[1.10](lessons/part-1-networking/1.10-tcp-congestion-control.md)
**一句話**：用 BtlBw + RTprop 兩個 path parameter 跑在 BDP 操作點——對 high-BDP / lossy link throughput +2~25× vs CUBIC、global median RTT -53%；但 fairness vs CUBIC 嚴重失衡，BBRv2/v3 加 ECN + loss-rate cap 修補；Google B4 / YouTube 全面部署。

### Hysteria Brutal CC (apernet 2023)
**中文**：自私擁塞控制
**所屬層**：L4 CC（翻牆專用）
**首次出現**：[1.10](lessons/part-1-networking/1.10-tcp-congestion-control.md)
**一句話**：固定 sending rate（user-set）+ 不對 loss/RTT 縮窗 + 對 loss 反而加速補償；對中國 lossy international link 比 BBR 快 5-10×，代價是完全放棄 fairness；G6 作為 opt-in option。

### ECN / L4S (RFC 3168 / 9330-9332)
**中文**：顯式擁塞通知 / 低延遲低損失可擴展吞吐
**所屬層**：IP + transport
**首次出現**：[1.10](lessons/part-1-networking/1.10-tcp-congestion-control.md)
**一句話**：ECN 用 IP header 2 bit 讓 router mark 取代 drop；L4S（2023）升級到 fine-grained ECN + scalable CC（Prague/DCTCP）達 sub-ms queueing delay；IETF 未來方向但部署慢。

### MPTCP (RFC 8684)
**中文**：多路徑 TCP
**所屬層**：L4 multipath
**首次出現**：[1.11 TCP 進階](lessons/part-1-networking/1.11-tcp-advanced.md)
**一句話**：單一邏輯連線跨多 subflow（各 4-tuple），上層 app 看單一 socket；Apple iOS Siri 全球 10 億+ device 部署；RFC 6356 LIA coupled CC 確保「do no harm」於其他 single-path flow；G6 baseline 不採用但 v2 可考慮 multipath QUIC。

### TCP-AO (RFC 5925)
**中文**：TCP 認證選項
**所屬層**：L4 transport security
**首次出現**：[1.11](lessons/part-1-networking/1.11-tcp-advanced.md)
**一句話**：取代 RFC 2385 TCP-MD5；HMAC-SHA-256 + per-connection traffic key（從 master + ISN derive）+ in-band key rotation + replay protection；BGP / LDP / RPKI / G6 control channel 設計範本。

### USO / TSO / GSO / GRO (NIC Offload)
**中文**：UDP/TCP 分片卸載
**所屬層**：NIC + kernel
**首次出現**：[1.2](lessons/part-1-networking/1.2-physical-and-phy-mac.md)（提及）；[1.11](lessons/part-1-networking/1.11-tcp-advanced.md) 深入
**一句話**：TSO/GSO 把大 SKB 切成 MTU-size packet 由 NIC 或 kernel 處理；USO（Linux 4.18+）為 UDP/QUIC 同類功能，對 QUIC throughput +10× 級；GRO 為接收側合併；G6 server production 必須啟用。

### UDP (RFC 768) + UDP Usage Guidelines (RFC 8085)
**中文**：用戶資料報協議與其應用準則
**所屬層**：L4 transport
**首次出現**：[1.12 UDP 完整解剖](lessons/part-1-networking/1.12-udp-anatomy.md)
**一句話**：Postel 1980 RFC 768 三頁定義 8-byte header；RFC 8085 BCP 145 codify 所有 UDP 應用設計準則（CC、checksum、message size、middlebox、ECN）；QUIC explicitly inherit。

### IP Fragmentation 災難
**中文**：IP 分片問題
**所屬層**：L3-L4 互動
**首次出現**：[1.12](lessons/part-1-networking/1.12-udp-anatomy.md)
**一句話**：UDP 不切 segment 直接靠 IP 分片——一個 fragment 丟 → 整 datagram 丟（effective loss rate × k）；多 firewall drop 分片；NAT 處理不一致；G6 鐵律「永禁分片」+ DF=1 + DPLPMTUD。

### UDP connect() Semantics
**中文**：UDP 連接的真實意義
**所屬層**：socket API
**首次出現**：[1.12](lessons/part-1-networking/1.12-udp-anatomy.md)
**一句話**：UDP `connect()` 不建連線但啟用三效果：filter 非 peer packet、default destination、kernel fast path；G6 client 用 connected socket，G6 server 必 unconnected (multi-client)。

### UDP-Lite (RFC 3828)
**中文**：輕量 UDP（部分 checksum）
**所屬層**：L4 transport variant
**首次出現**：[1.12](lessons/part-1-networking/1.12-udp-anatomy.md)
**一句話**：允許 checksum 只覆蓋 packet 前 N byte，讓 audio/video application 容忍 payload byte 損壞；middlebox 對非標準 protocol number drop 使其無 deployment；G6 不採用。

### IPv6 (RFC 8200) Header & Extension Headers
**中文**：IPv6 與其擴展頭
**所屬層**：L3
**首次出現**：[1.13 IPv6 完整解剖](lessons/part-1-networking/1.13-ipv6-anatomy.md)
**一句話**：40-byte fixed header + chained extension headers (HBH/Routing/Fragment/AH/ESP/Dest Options)；header checksum removed；fragmentation 只 source 做；EH 在公網 drop rate 高 (RFC 7872 ~30-50%)，G6 不應使用 EH。

### Happy Eyeballs v2 (RFC 8305)
**中文**：快樂眼球 v2
**所屬層**：dual-stack client UX
**首次出現**：[1.13](lessons/part-1-networking/1.13-ipv6-anatomy.md)
**一句話**：Schinazi & Pauly 2017——dual-stack client 同時試 IPv6 + IPv4 connection、race who connects first；改善 partial-broken v6 path 40× latency；DNS query 也 happy eyeball（AAAA 先發 + 50ms 後 A）；250ms Connection Attempt Delay 給 v6 head start；G6 client mandatory。

### RFC 6724 Default Address Selection
**中文**：IPv6 預設地址選擇
**所屬層**：socket / getaddrinfo
**首次出現**：[1.13](lessons/part-1-networking/1.13-ipv6-anatomy.md)
**一句話**：dual-stack OS 對候選 (src, dst) address pair 排序的 9 條 rule；不同 OS 實作不一致是 dual-stack deployment hidden complexity；G6 client 應 RFC 6724 compliant。

### IPv6 Privacy: 8981 + 7217 並用
**中文**：IPv6 隱私雙機制
**所屬層**：SLAAC IID derivation
**首次出現**：[1.5](lessons/part-1-networking/1.5-arp-ndp-dhcp.md)、[1.13](lessons/part-1-networking/1.13-ipv6-anatomy.md)
**一句話**：RFC 7217 stable opaque IID (PRF-derived from secret + prefix) 給 inbound reachability + RFC 8981 temporary random IID 給 outbound privacy；G6 client 應 enforce 兩者並用。

### Czyz 2014 IPv6 Adoption Measurement
**中文**：IPv6 部署量測
**所屬層**：measurement
**首次出現**：[1.13](lessons/part-1-networking/1.13-ipv6-anatomy.md)
**一句話**：Czyz et al. SIGCOMM 2014——12 metrics + 10 datasets；IPv6 prefix 2004-2014 增 37×、traffic 年增 400%；2024 update：全球 ~45% user IPv6 capable，India 75%；G6 dual-stack mandatory。

### DNS (RFC 1034/1035) + Resource Records
**中文**：域名系統與資源記錄
**所屬層**：L7 application protocol
**首次出現**：[1.14 DNS 完整解剖](lessons/part-1-networking/1.14-dns-anatomy.md)
**一句話**：Mockapetris 1987 奠基；4-section 報文（Header/Question/Answer/Authority/Additional）；典型 RR 種類 A/AAAA/CNAME/MX/TXT/NS/SOA/SRV/CAA/HTTPS(RFC 9460)/SVCB；現代 HTTPS RR 整合 ALPN+IP hint+ECH config。

### Kaminsky 2008 DNS Cache Poisoning + RFC 5452
**中文**：Kaminsky 快取污染
**所屬層**：DNS attack + mitigation
**首次出現**：[1.14](lessons/part-1-networking/1.14-dns-anatomy.md)
**一句話**：2008 Kaminsky 發現用 random subdomain query 觸發 outgoing → 注 forged response 含 NS pointing to attacker；RFC 5452 用 source port randomization 把 entropy 從 16-bit 推到 32-bit 解；2020 fragmentation reload 復活該攻擊。

### DNSSEC (RFC 4033-4035) — Failed Standard
**中文**：DNS 安全擴展（失敗）
**所屬層**：DNS authentication
**首次出現**：[1.14](lessons/part-1-networking/1.14-dns-anatomy.md)
**一句話**：對 RR 簽章配 zone key + DS chain of trust；理論完美但 deployment ~5-15%、resolver validation ~1-3%；複雜性 + NSEC enumeration + algorithm rollover 痛 + errors 比 unprotected 更糟；G6 不依賴。

### DoT / DoH / DoQ (RFC 7858 / 8484 / 9250)
**中文**：加密 DNS 三件套
**所屬層**：DNS transport security
**首次出現**：[1.14](lessons/part-1-networking/1.14-dns-anatomy.md)
**一句話**：DoT (TLS over TCP/853, 2016) / DoH (HTTPS, 2018, port 443 與 HTTPS 混合難 block) / DoQ (QUIC, dedicated UDP/853, 2022, 0-RTT 快但同 DoT 易 selective block)；G6 bootstrap：DoH > DoQ > 預配 IP。

### ECS (EDNS Client Subnet, RFC 7871)
**中文**：EDNS 客戶端子網
**所屬層**：DNS EDNS option
**首次出現**：[1.14](lessons/part-1-networking/1.14-dns-anatomy.md)
**一句話**：resolver 把 client subnet (/24 IPv4 或 /48 IPv6) 透過 EDNS 傳給 authoritative，使 CDN 選 edge IP 對 client geo 友善；隱私洩漏 client geographic location；Cloudflare 不傳 by default。

### ECH (Encrypted Client Hello) + HTTPS RR (RFC 9460)
**中文**：加密 ClientHello + HTTPS 記錄
**所屬層**：TLS + DNS
**首次出現**：[1.14](lessons/part-1-networking/1.14-dns-anatomy.md)
**一句話**：HTTPS RR (type 65) 在 DNS 階段同傳 ALPN/IP hint/ECH config；ECH 把 ClientHello 內 SNI 加密；2024+ GFW 對 ECH 部分 selective drop；G6 publish HTTPS RR 是 mandatory，但需 ECH-less fallback。

### Hoang 2021 GFWatch — GFW DNS Censorship Measurement
**中文**：GFW DNS 審查量測
**所屬層**：censorship measurement
**首次出現**：[1.14](lessons/part-1-networking/1.14-dns-anatomy.md)；[1.6 ICMP](lessons/part-1-networking/1.6-icmp-deep.md) reference
**一句話**：Hoang et al. USENIX Sec 2021——411M domain/day × 9 月發現 311K 受審查域名、3 個 injector（Injector 2 負責 99%）、11 組 forged IP、41K 無辜 overblocking、77K 受 public resolver spillover；G6 server domain 命名與 client bootstrap 直接依此設計。

### DDR (RFC 9462) + Encrypted DNS Discovery
**中文**：發現指定解析器
**所屬層**：DNS auto-config
**首次出現**：[1.14](lessons/part-1-networking/1.14-dns-anatomy.md)
**一句話**：client 啟動時用 plain DNS resolver IP 查 `_dns.resolver.arpa.` SVCB → 拿到該 resolver 的 DoH/DoT/DoQ endpoint；對應 RFC 9463 透過 DHCP/RA option 推 encrypted DNS endpoint；G6 client opportunistic 採用。

### Tier 1/2/3 ISP + IXP
**中文**：ISP 分層與 IXP
**所屬層**：BGP economics
**首次出現**：[1.15 BGP](lessons/part-1-networking/1.15-bgp-internet-routing.md)
**一句話**：Tier 1 不付任何人 transit（settlement-free peering 即可全球可達，~15-20 個如 AT&T/Telia/NTT/Tata）；Tier 2 部分付；Tier 3 全付 transit；IXP（DE-CIX/AMS-IX/LINX/HKIX 等）為多 AS 互換流量物理 location。

### BGP Best Path Selection (13 steps)
**中文**：BGP 最佳路徑選擇
**所屬層**：L3 control
**首次出現**：[1.15](lessons/part-1-networking/1.15-bgp-internet-routing.md)
**一句話**：RFC 4271 §9.1 13 步決策——validity → WEIGHT → LOCAL_PREF → 本地起源 → AS_PATH 短 → ORIGIN 低 → MED 低 → eBGP > iBGP → IGP cost → 老/router ID/neighbor IP tiebreaker；LOCAL_PREF 是 AS-wide policy 工具。

### BGP Path Attributes (LOCAL_PREF / AS_PATH / MED / COMMUNITY)
**中文**：BGP 路徑屬性
**所屬層**：L3 BGP
**首次出現**：[1.15](lessons/part-1-networking/1.15-bgp-internet-routing.md)
**一句話**：LOCAL_PREF 為 AS-wide outbound policy（最高勝、override AS_PATH）；AS_PATH prepending 是常用 traffic engineering 但 APNIC 警告勿 > 5；COMMUNITY 是 32-bit tag（無正式語意，ISP 之間 convention）。

### China Telecom 2010 BGP Hijack
**中文**：中國電信 2010 BGP 劫持
**所屬層**：BGP incident
**首次出現**：[1.15](lessons/part-1-networking/1.15-bgp-internet-routing.md)
**一句話**：2010-04-08 AS23724 誤 announce ~37K prefix（含 .gov/.mil/Dell/CNN 等）18 分鐘，15% 全球 traffic 被 redirect；意外 vs 故意至今未定論；推動 RPKI 加速部署。

### CN2 GIA / 「BGP 加速」/ 中轉節點
**中文**：中國電信優質國際線路與機場行話
**所屬層**：BGP economics + traffic engineering
**首次出現**：[1.15](lessons/part-1-networking/1.15-bgp-internet-routing.md)
**一句話**：CN2 GIA (AS4809) 是 China Telecom 商業優質國際線路（價格 $$$ × ChinaNet）；「BGP 加速 / 中轉節點」實際是「**機房選 transit + 在合適 AS 加 relay VPS**」，無神奇技術；G6 server 部署應選 IXP-rich 城市 + 對中峰值優化 transit。

### Griffin-Wilfong 1999 BGP Non-Convergence
**中文**：BGP 不收斂性
**所屬層**：distributed system theory
**首次出現**：[1.15](lessons/part-1-networking/1.15-bgp-internet-routing.md)
**一句話**：SIGCOMM 1999 證明 BGP 在 expressive policy 下動態系統可能不收斂、永久 oscillation；對 G6 control plane 反面教訓——不要設計可表達任意 policy 的 protocol，採 Raft/Paxos 等 proven algorithm。

### BGPsec (RFC 8205) — Failed Standard
**中文**：BGPsec 失敗標準
**所屬層**：BGP security
**首次出現**：[1.15](lessons/part-1-networking/1.15-bgp-internet-routing.md)
**一句話**：每 AS 對 AS_PATH 加 signature 達 path integrity；signature 巨大化 + CPU/memory cost + algorithm rollover 痛使 deployment ~0%；RPKI ROA 仍是部分解。

### Anycast (CDN)
**中文**：任播
**所屬層**：BGP + routing
**首次出現**：[1.16 CDN/Anycast](lessons/part-1-networking/1.16-cdn-anycast.md)
**一句話**：同一 IP prefix 從多個物理 POP 同時 BGP announce，BGP best-path 自動把 client 導到最近；Cloudflare/Bing/Google DNS 用；Calder 2015 IMC 量測 80% client geo-optimal、20% sub-optimal；G6 baseline 不採用（一封全封）。

### Domain Fronting (Fifield 2015)
**中文**：域名前置
**所屬層**：HTTPS over CDN
**首次出現**：[1.16](lessons/part-1-networking/1.16-cdn-anycast.md)
**一句話**：Fifield et al. PoPETs 2015——TLS SNI 標 allowed.com（censor 放行）+ HTTP Host header 標 forbidden.com（加密內 censor 看不見）+ CDN 看 Host route 到 forbidden origin；2018+ Google/AWS/Azure 主動禁，Cloudflare/Fastly 部分允許；ECH 取代中。

### Cloudflare Workers / Lambda@Edge / Fastly Compute@Edge
**中文**：邊緣 serverless 計算
**所屬層**：CDN compute
**首次出現**：[1.16](lessons/part-1-networking/1.16-cdn-anycast.md)
**一句話**：在 CDN POP 上跑 JavaScript / WASM；典型 5ms cold start, <1ms warm；G6 可用作 endpoint discovery / control plane / lightweight relay，但 ToS 對 circumvention use 模糊。

### iCloud Private Relay (Apple, 2021)
**中文**：iCloud 私密轉送
**所屬層**：production VPN architecture
**首次出現**：[1.16](lessons/part-1-networking/1.16-cdn-anycast.md)
**一句話**：兩跳 trust split 設計——Apple-operated ingress（知身份不知目標）+ CDN-operated egress（知目標不知身份）；MASQUE over QUIC；千萬 user scale 部署；GFW 完全封；G6 v2 可考慮 architecture reference。

### Cloudflare WARP / cloudflared / Spectrum / Magic Transit
**中文**：Cloudflare 全家桶（VPN/Tunnel/L4 proxy/DDoS）
**所屬層**：CDN-based VPN/Tunneling
**首次出現**：[1.16](lessons/part-1-networking/1.16-cdn-anycast.md)
**一句話**：WARP 為 consumer VPN（WireGuard + MASQUE）；cloudflared 讓 origin 主動 outbound tunnel 隱藏 IP；Spectrum 是 L4 任意 TCP/UDP proxy；Magic Transit 是 L3 DDoS protection；G6 deployment 可選擇 partial 採用。

### Refraction Networking / Conjure / Slitheen
**中文**：折射網路
**所屬層**：transport-layer circumvention
**首次出現**：[1.16](lessons/part-1-networking/1.16-cdn-anycast.md)（提及）；Part 7/10 詳述
**一句話**：Bocovich-Goldberg 2016 Slitheen / 2019 Conjure (CCS)——讓 censored client 透過「**正常 HTTPS 流量到 decoy site**」與 ISP-cooperative decoy router 達 circumvention；ISP cooperation required，部署 limited。

### sk_buff (SKB)
**中文**：Linux 網路 stack 中心資料結構
**所屬層**：Linux kernel
**首次出現**：[1.18 Linux 網路 stack](lessons/part-1-networking/1.18-linux-network-stack.md)
**一句話**：用 4 個 pointer (head/data/tail/end) 表達線性 buffer 內 3 個 boundary——packet 過各 protocol layer 時只調 pointer 不 memcpy；是 Linux network stack zero-copy 設計核心。

### Netfilter Hooks + nftables vs iptables vs eBPF
**中文**：Netfilter 框架與 packet 過濾工具演化
**所屬層**：Linux netfilter
**首次出現**：[1.18](lessons/part-1-networking/1.18-linux-network-stack.md)
**一句話**：5 個 hook (PREROUTING/INPUT/FORWARD/OUTPUT/POSTROUTING)；iptables (legacy linear scan) → nftables (modern, expression-based) → eBPF (programmable, 5-10× 快); G6 killswitch 用 nftables baseline。

### TC qdisc (fq / fq_codel / cake / mq)
**中文**：流量控制 / 佇列規則
**所屬層**：Linux egress
**首次出現**：[1.18](lessons/part-1-networking/1.18-linux-network-stack.md)
**一句話**：dev_queue_xmit → qdisc → driver；fq_codel 為現代 Linux default（fair queue + CoDel AQM）；BBR pacing 必須 fq qdisc 配合；cake 整合 shaper+FQ+AQM+DiffServ。

### XDP (eXpress Data Path) + AF_XDP
**中文**：高性能封包處理路徑
**所屬層**：Linux driver-layer eBPF
**首次出現**：[1.18](lessons/part-1-networking/1.18-linux-network-stack.md)
**一句話**：在 driver layer 跑 eBPF program（pre-skb），支援 DROP/PASS/TX/REDIRECT 動作；Facebook Katran ~30M pps per core；AF_XDP 為 user space zero-copy socket via XDP。

### Linux NAPI Path + softirq budget
**中文**：Linux 接收路徑 + softirq 預算
**所屬層**：Linux kernel networking
**首次出現**：[1.2](lessons/part-1-networking/1.2-physical-and-phy-mac.md)（提及）；[1.18](lessons/part-1-networking/1.18-linux-network-stack.md) 深度展開
**一句話**：NIC HardIRQ → NAPI schedule softirq → net_rx_action → napi_poll → __netif_receive_skb → protocol dispatch；netdev_budget=300 packets / netdev_budget_usecs=2ms 為 polling cycle 上限。

---

## Part 4 — TLS / QUIC 內部完全解剖

### TLS 1.3 (RFC 8446)
**中文**：傳輸層安全 v1.3
**所屬層**：L5 / cryptographic transport
**首次出現**：[4.1](lessons/part-4-tls-quic/4.1-tls-history-bloodshed.md)、[4.2](lessons/part-4-tls-quic/4.2-tls12-vs-tls13.md)、[4.3](lessons/part-4-tls-quic/4.3-tls13-handshake-byte-level.md)
**一句話**：1995-2018 二十三年密碼學教訓的結晶；ban-by-default 設計（移除 RSA-KE、CBC、compression、renegotiation、MD5/SHA-1）；1-RTT 為 normal，0-RTT 為 PSK 模式；TLS 1.3 是第一個 spec-driven formal verification co-design 的 IETF 協議。

### Bleichenbacher Attack
**中文**：RSA-PKCS#1 v1.5 padding oracle 攻擊
**所屬層**：cryptographic primitive
**首次出現**：[4.1](lessons/part-4-tls-quic/4.1-tls-history-bloodshed.md)
**一句話**：1998 Bleichenbacher CRYPTO 開創的 chosen-ciphertext attack；20 年後仍以 ROBOT (2018) 形態存在；TLS 1.3 直接拿掉 RSA-KE 是這條 attack 的根本修補。

### POODLE / BEAST / CRIME / Lucky13 / Logjam / DROWN / ROBOT / Heartbleed / FREAK
**中文**：TLS 1.0-1.2 時代 9 大攻擊
**所屬層**：vary (record layer / handshake / RSA-KE / DH / implementation)
**首次出現**：[4.1](lessons/part-4-tls-quic/4.1-tls-history-bloodshed.md)
**一句話**：1.3 ban-by-default 設計每個被砍項目背後對應的具體 attack；理解這 9 個就理解 1.3 為何長那樣。

### Krawczyk Encrypt-then-MAC
**中文**：先加密後 MAC 定理
**所屬層**：cryptographic composition
**首次出現**：[4.1](lessons/part-4-tls-quic/4.1-tls-history-bloodshed.md)
**一句話**：Krawczyk 2001 CRYPTO 證明 EtM 在 generic composition 下是唯一 always-secure 順序；TLS 1.0-1.2 的 MAC-then-encrypt 在 CBC mode 下因巧合不爆但 Lucky13 把巧合也打破；TLS 1.3 強制 AEAD = fused EtM。

### Downgrade Resilience
**中文**：抗降版安全性
**所屬層**：handshake security
**首次出現**：[4.1](lessons/part-4-tls-quic/4.1-tls-history-bloodshed.md)、[4.2](lessons/part-4-tls-quic/4.2-tls12-vs-tls13.md)
**一句話**：Bhargavan et al. S&P 2016 形式化框架；協議 negotiation 參數必須被 transcript hash bind + downgrade sentinel；TLS 1.3 用 `supported_versions` + ServerHello.random 末 8 byte 常數雙保險。

### HKDF / HKDF-Expand-Label
**中文**：HMAC-based Key Derivation Function
**所屬層**：cryptographic primitive
**首次出現**：[4.2](lessons/part-4-tls-quic/4.2-tls12-vs-tls13.md)、[4.3](lessons/part-4-tls-quic/4.3-tls13-handshake-byte-level.md)
**一句話**：Krawczyk 2010 提出，HKDF-Extract(salt, IKM) + HKDF-Expand(PRK, info, len) 兩階段 KDF；TLS 1.3 用 `HKDF-Expand-Label(secret, "tls13 " + label, context, len)` 派生 secret；prefix `"tls13 "` / `"quic "` / `"dtls13 "` 防 cross-protocol attack。

### Transcript Hash Binding
**中文**：握手紀錄 hash 綁定
**所屬層**：handshake security
**首次出現**：[4.3](lessons/part-4-tls-quic/4.3-tls13-handshake-byte-level.md)
**一句話**：所有 negotiation 參數透過 hash chain 灌入 key derivation；攻擊者無法讓 honest endpoints commit 不同 transcript（與 hash collision resistance 衝突）；新協議的標配。

### Key Schedule (TLS 1.3)
**中文**：三段式 HKDF 密鑰排程
**所屬層**：handshake key derivation
**首次出現**：[4.2](lessons/part-4-tls-quic/4.2-tls12-vs-tls13.md)
**一句話**：HKDF-Extract(PSK) → Early Secret → HKDF-Extract(ECDHE) → Handshake Secret → HKDF-Extract(0) → Master Secret；每階段獨立 derive client/server traffic secret + exporter；PSK + ECDHE 混合 entropy 才能拿 application key。

### Selfie Attack
**中文**：自反射攻擊
**所屬層**：TLS 1.3 PSK mode
**首次出現**：[4.1](lessons/part-4-tls-quic/4.1-tls-history-bloodshed.md)、[4.5](lessons/part-4-tls-quic/4.5-zero-rtt-and-replay.md)
**一句話**：Drucker-Gueron 2019 ePrint 2019/347；TLS 1.3 PSK 模式無 role binding 漏洞，attacker 把 client 的 ClientHello 反射回同一 endpoint 完成 self-handshake；揭示 formal proof 對 PSK identity 假設的盲區。

### JA3
**中文**：TLS Client Hello 指紋
**所屬層**：fingerprint
**首次出現**：[4.4](lessons/part-4-tls-quic/4.4-tls-extensions-ja3-ja4.md)
**一句話**：Althouse et al. (Salesforce 2017) 對 ClientHello 5 個 field (version, ciphers, extensions, groups, EC point formats) concat + MD5；2023 Chrome 起隨機化 extension 順序使 JA3 對 modern browser 大幅失效。

### JA4 / JA4+
**中文**：JA3 的次世代 fingerprint
**所屬層**：fingerprint
**首次出現**：[4.4](lessons/part-4-tls-quic/4.4-tls-extensions-ja3-ja4.md)
**一句話**：FoxIO LLC 2023 推出；對 cipher / extension 排序後 hash 抵抗 randomization；3 段 `{a}_{b}_{c}` human-readable + 涵蓋 QUIC (q variant) + ALPN 編碼進 fingerprint；JA4+ 套件含 JA4S/JA4H/JA4X/JA4T/JA4SSH 等。

### GREASE (RFC 8701)
**中文**：抗 ossification 隨機擴展
**所屬層**：TLS / QUIC anti-ossification
**首次出現**：[4.4](lessons/part-4-tls-quic/4.4-tls-extensions-ja3-ja4.md)、[4.9](lessons/part-4-tls-quic/4.9-quic-advanced.md)
**一句話**：Google 2016 提出，client 在 ClientHello 加入 reserved-value (例如 `0x?A?A` pattern) 強迫 server 容忍 unknown；JA3/JA4 計算時 filter；is/not 的存在本身仍是 binary fingerprint。

### uTLS
**中文**：Go 層 TLS ClientHello 模仿
**所屬層**：library
**首次出現**：[4.4](lessons/part-4-tls-quic/4.4-tls-extensions-ja3-ja4.md)
**一句話**：refraction-networking/utls fork Go crypto/tls 加 ClientHelloSpec 指定 fingerprint；xray-core / sing-box / hysteria2 / Naïve 都用；對 byte-perfect mimic 有效但對 statistical fingerprint (Wu-FEP 2023) 99% 仍被識別。

### REALITY
**中文**：借用真實 TLS server handshake 的代理路線
**所屬層**：proxy transport
**首次出現**：[4.4](lessons/part-4-tls-quic/4.4-tls-extensions-ja3-ja4.md)
**一句話**：RPRX 設計、xray-core 實作；不模仿而是「借用」真實 server 的 ClientHello+ServerHello 全程，proxy 只在 Certificate 階段替換；indistinguishability 接近 perfect 但 inner 協議受限；Part 7.6 詳。

### 0-RTT / Early Data
**中文**：零來回延遲提早資料
**所屬層**：TLS 1.3 handshake
**首次出現**：[4.5](lessons/part-4-tls-quic/4.5-zero-rtt-and-replay.md)
**一句話**：PSK 模式下第一個 flight 攜帶 application data；Fischlin-Günther 2017 證明結構性無 forward secrecy + 無 replay resilience；RFC 8446 §8 + RFC 8470 (HTTP 425) 限制 idempotent only。

### Anti-Replay (TLS 1.3)
**中文**：反重放機制
**所屬層**：TLS 1.3 0-RTT
**首次出現**：[4.5](lessons/part-4-tls-quic/4.5-zero-rtt-and-replay.md)
**一句話**：RFC 8446 §8 三種 mechanism — Single-Use PSK、ClientHello Recording、Freshness via obfuscated_ticket_age；spec 不強制選哪一個，Cloudflare 用 #3、AWS CloudFront 用 #1。

### Puncturable PRF (PPRF)
**中文**：可穿孔偽隨機函數
**所屬層**：advanced cryptographic primitive
**首次出現**：[4.5](lessons/part-4-tls-quic/4.5-zero-rtt-and-replay.md)
**一句話**：GGM tree-based PRF + delete entry；Derler 2017 + Aviram-Gellert-Jager 2021 用以實現 forward-secret 0-RTT；理論可行但 production 部署為零（記憶體成本 GB 級）。

### ECH (Encrypted Client Hello)
**中文**：加密客戶端問候
**所屬層**：TLS extension
**首次出現**：[4.6](lessons/part-4-tls-quic/4.6-ech-encrypted-client-hello.md)
**一句話**：draft-ietf-tls-esni（2018 ESNI → 2021 改名 ECH → 2025+ draft-25 仍未 RFC）；用 HPKE 把整個 inner ClientHello 加密放進 outer ClientHello payload；privacy 依賴 anonymity set；GFW 2024+ 觀察 selective throttling。

### HPKE (RFC 9180)
**中文**：混合公鑰加密
**所屬層**：cryptographic primitive
**首次出現**：[4.6](lessons/part-4-tls-quic/4.6-ech-encrypted-client-hello.md)
**一句話**：Barnes-Bhargavan-Lipp-Wood 2022 標準化的 KEM+KDF+AEAD 組合；4 modes (base/psk/auth/auth_psk)；ECH / OHTTP / MLS 都用 HPKE 作底；預設 X25519 + HKDF-SHA256 + ChaCha20-Poly1305。

### ECHConfig / Anonymity Set
**中文**：ECH 配置 / 匿名集
**所屬層**：ECH deployment
**首次出現**：[4.6](lessons/part-4-tls-quic/4.6-ech-encrypted-client-hello.md)
**一句話**：ECHConfig 含 server KEM public key + cipher_suites + public_name + maximum_name_length；client 透過 DNS HTTPS RR (RFC 9460) 或 out-of-band 取得；ECH privacy 形式化為 anonymity set 內 server identity indistinguishability。

### QUIC (RFC 9000)
**中文**：UDP-based 多路復用安全傳輸
**所屬層**：L4 transport
**首次出現**：[4.7](lessons/part-4-tls-quic/4.7-quic-transport.md)
**一句話**：Langley 等 2017 SIGCOMM Google production deployment 結晶；UDP + 加密 + 多 stream + connection ID migration + user-space implementation；2021 RFC 9000/9001/9002 出。

### Connection ID
**中文**：連線識別碼
**所屬層**：QUIC transport
**首次出現**：[4.7](lessons/part-4-tls-quic/4.7-quic-transport.md)、[4.9](lessons/part-4-tls-quic/4.9-quic-advanced.md)
**一句話**：替代 TCP 5-tuple；QUIC connection 由 DCID 識別，client/server 可各 issue 多個 CID via NEW_CONNECTION_ID frame；rotation 防 passive traffic correlation；mobile migration 的核心 enabler。

### Packet Number Encryption / Header Protection
**中文**：包編號加密 / 頭部保護
**所屬層**：QUIC transport security
**首次出現**：[4.7](lessons/part-4-tls-quic/4.7-quic-transport.md)、[4.8](lessons/part-4-tls-quic/4.8-quic-handshake.md)
**一句話**：RFC 9001 §5.4；用 HKDF-derived HP key 對 packet 末 16 byte sample 做 AES-ECB / ChaCha20 算 mask，XOR 進 packet number 與 byte 0；middlebox 看不到 packet number，不能注入 RST 或 modify packets。

### Packet Number Space
**中文**：包編號空間
**所屬層**：QUIC transport
**首次出現**：[4.7](lessons/part-4-tls-quic/4.7-quic-transport.md)、[4.8](lessons/part-4-tls-quic/4.8-quic-handshake.md)
**一句話**：RFC 9000 §12.3；QUIC 用三個獨立 packet number space (Initial / Handshake / Application)，各自從 0 增；每 space 用獨立 keys + ACK 管理，避免 cross-context AEAD nonce reuse。

### QUIC Initial Keys
**中文**：QUIC 初始密鑰
**所屬層**：QUIC handshake
**首次出現**：[4.8](lessons/part-4-tls-quic/4.8-quic-handshake.md)
**一句話**：RFC 9001 §5.2；從 well-known salt + client DCID 透過 HKDF derive；公開可推導 → 任何 observer 可解；但 middlebox modification 仍會 break AEAD；GFW 識別 QUIC 入口的關鍵。

### Retry (QUIC)
**中文**：重發機制
**所屬層**：QUIC handshake / anti-amplification
**首次出現**：[4.8](lessons/part-4-tls-quic/4.8-quic-handshake.md)
**一句話**：server 對未驗證 client IP 發 Retry packet 帶 server-encrypted token；client 重發 Initial 帶 token；anti-amplification 限制 3x 直到 IP validated；NEW_TOKEN frame 跨 connection 預驗。

### Connection Migration
**中文**：連線遷移
**所屬層**：QUIC transport
**首次出現**：[4.9](lessons/part-4-tls-quic/4.9-quic-advanced.md)
**一句話**：RFC 9000 §9；client IP/port 變化後用同一 DCID 繼續傳；server 對新 path 做 PATH_CHALLENGE / PATH_RESPONSE 驗證；handle NAT rebinding vs intentional migration；移動裝置不斷線的根基。

### DATAGRAM Frame (RFC 9221)
**中文**：QUIC 不可靠資料報擴展
**所屬層**：QUIC frame
**首次出現**：[4.9](lessons/part-4-tls-quic/4.9-quic-advanced.md)、[4.10](lessons/part-4-tls-quic/4.10-http3-and-masque.md)
**一句話**：QUIC 內的 UDP-like unreliable + unordered payload；加密 + integrity 仍適用；MASQUE CONNECT-UDP/IP/Ethernet + Hysteria2 + TUIC v5 都用以避免雙重 reliable layer 的 HoL blocking。

### QUIC v2 (RFC 9369)
**中文**：QUIC 第二版
**所屬層**：QUIC wire format
**首次出現**：[4.9](lessons/part-4-tls-quic/4.9-quic-advanced.md)
**一句話**：anti-ossification 改 version=0x6b3343cf + 換 Initial salt + 換 long packet type ordering；wire-incompatible with v1；2026 已部分 production 部署。

### HTTP/3 (RFC 9114)
**中文**：HTTP over QUIC
**所屬層**：L7 application
**首次出現**：[4.10](lessons/part-4-tls-quic/4.10-http3-and-masque.md)、[4.12](lessons/part-4-tls-quic/4.12-h2-vs-h3-vs-masque.md)
**一句話**：HTTP/2 的 QUIC 重寫；frame 列表更短（PING/PRIORITY/WINDOW_UPDATE 搬到 QUIC layer）；每個 request 一條 QUIC bidi stream；三條 control stream (HTTP/3 control + QPACK encoder + decoder)。

### QPACK (RFC 9204)
**中文**：HTTP/3 field 壓縮
**所屬層**：L7 compression
**首次出現**：[4.10](lessons/part-4-tls-quic/4.10-http3-and-masque.md)
**一句話**：HPACK (HTTP/2) 的 QUIC 重設計；分 encoder stream / decoder stream 處理 reorder；reference index 受 receiver ack 限制；對 stream multiplexing 友善但增加 RTT。

### MASQUE
**中文**：HTTP/3 上的多協議代理
**所屬層**：application-layer tunneling
**首次出現**：[4.10](lessons/part-4-tls-quic/4.10-http3-and-masque.md)、[4.12](lessons/part-4-tls-quic/4.12-h2-vs-h3-vs-masque.md)
**一句話**：Multiplexed Application Substrate over QUIC Encryption；RFC 9297 (Capsule) + 9298 (CONNECT-UDP) + 9484 (CONNECT-IP) + draft (CONNECT-Ethernet)；Cloudflare WARP + Apple iCloud Private Relay 採用；anonymity set 跟整個 CDN 共用，是 indirect-fire anti-censorship 武器。

### CONNECT-UDP / CONNECT-IP / CONNECT-Ethernet
**中文**：HTTP CONNECT 的 UDP / IP / 以太網變體
**所屬層**：MASQUE
**首次出現**：[4.10](lessons/part-4-tls-quic/4.10-http3-and-masque.md)
**一句話**：RFC 9298 / 9484 / draft；HTTP/3 Extended CONNECT method 配 `:protocol = connect-udp|connect-ip|connect-ethernet`；inner payload 走 HTTP Datagram (via QUIC DATAGRAM frame)；分別 tunnel L4/L3/L2 traffic。

### HTTP Datagram / Capsule Protocol (RFC 9297)
**中文**：HTTP 不可靠資料報與膠囊協議
**所屬層**：HTTP datagram
**首次出現**：[4.10](lessons/part-4-tls-quic/4.10-http3-and-masque.md)
**一句話**：兩條 wire path — Path A (QUIC DATAGRAM frame, unreliable, fast) 與 Path B (Capsule on HTTP stream, reliable, H2-fallback)；MASQUE 預設 Path A；capsule TLV 結構 `{type, length, value}` 可擴展。

### quic-go
**中文**：純 Go QUIC implementation
**所屬層**：implementation
**首次出現**：[4.11](lessons/part-4-tls-quic/4.11-quic-go-source-walk.md)
**一句話**：Marten Seemann 主導；~70K LOC；caddy/sing-box/xray-core 部署；目錄結構 (connection.go / packet_packer.go / internal/{handshake,ackhandler,congestion,flowcontrol,wire}) 對應 RFC 9000-9002 各 section；單 goroutine state machine + sub-goroutines for I/O。


---

## Part 2 — 高效能 I/O 與 kernel 網路

### epoll
**中文**：Linux scalable I/O readiness 機制
**所屬層**：kernel syscall
**首次出現**：[2.1](lessons/part-2-high-perf-io/2.1-select-poll-epoll.md)
**一句話**：紅黑樹維護 interest set + 雙向 ready list + per-fd wait queue callback；ET/LT 兩 mode，ET 必須 drain 到 EAGAIN；C10K 後 server 標配；G6 server fallback path。

### kqueue
**中文**：BSD/macOS 的 scalable event notification
**所屬層**：kernel syscall
**首次出現**：[2.1](lessons/part-2-high-perf-io/2.1-select-poll-epoll.md)、[2.10](lessons/part-2-high-perf-io/2.10-macos.md)
**一句話**：Lemon ATC 2001；filter (READ/WRITE/SIGNAL/TIMER/VNODE/PROC/USER) + udata 統一各種 event source；EV_CLEAR = ET；G6 macOS client 核心。

### Edge-Triggered (ET) / Level-Triggered (LT)
**中文**：邊緣觸發 / 電平觸發
**所屬層**：epoll/kqueue 語意
**首次出現**：[2.1](lessons/part-2-high-perf-io/2.1-select-poll-epoll.md)
**一句話**：ET 只在狀態變化瞬間通知，必須 drain 到 EAGAIN；LT 反覆通知；G6 server worker 預期用 ET。

### EPOLLEXCLUSIVE
**中文**：epoll 排他喚醒 flag
**所屬層**：epoll
**首次出現**：[2.1](lessons/part-2-high-perf-io/2.1-select-poll-epoll.md)
**一句話**：Linux 4.5 引入；解決多 process epoll_wait 同 listen fd 時 thundering herd；只喚醒 1 個。

### SO_REUSEPORT
**中文**：socket bind port 共用 flag
**所屬層**：socket option
**首次出現**：[2.1](lessons/part-2-high-perf-io/2.1-select-poll-epoll.md)、[2.6](lessons/part-2-high-perf-io/2.6-ebpf-network.md)
**一句話**：Linux 3.9；多 socket 可 bind 同 (addr,port)，kernel 用 5-tuple hash 分配 incoming；G6 server N worker 標配。

### SO_ATTACH_REUSEPORT_EBPF
**中文**：可程式化 reuseport 分配
**所屬層**：socket option + eBPF
**首次出現**：[2.6](lessons/part-2-high-perf-io/2.6-ebpf-network.md)
**一句話**：用 BPF program 自訂 reuseport hash 策略；G6 用 per-client-IP affinity + CPU load balance。

### io_uring
**中文**：Linux 共享 ring 異步 I/O
**所屬層**：kernel syscall
**首次出現**：[2.2](lessons/part-2-high-perf-io/2.2-io-uring.md)
**一句話**：Axboe 2019；SQ + CQ + SQE/CQE mmap 共享 ring；SQPOLL 模式 0 syscall fast path；registered files/buffers 移除 fdget/page pin cost；G6 server 主路徑。

### SQE / CQE
**中文**：Submission/Completion Queue Entry
**所屬層**：io_uring
**首次出現**：[2.2](lessons/part-2-high-perf-io/2.2-io-uring.md)
**一句話**：io_uring 提交與完成事件 entry；SQE 64B / CQE 16B (或 CQE32)；user_data 是 user-kernel 不解讀欄位，常塞 ctx pointer。

### IORING_SETUP_SQPOLL / DEFER_TASKRUN / SINGLE_ISSUER
**中文**：io_uring 三個關鍵 setup flag
**所屬層**：io_uring
**首次出現**：[2.2](lessons/part-2-high-perf-io/2.2-io-uring.md)
**一句話**：SQPOLL = kernel thread poll SQ 達 0 syscall；DEFER_TASKRUN + SINGLE_ISSUER = async work 在 issuer task context 跑（6.1+），避開 io-wq thread pool 的 credential 安全 surface。

### IORING_OP_*
**中文**：io_uring opcode
**所屬層**：io_uring
**首次出現**：[2.2](lessons/part-2-high-perf-io/2.2-io-uring.md)
**一句話**：~50 個 op 涵蓋 read/write/recv/send/recvmsg/sendmsg/accept/connect/openat/timeout/poll_add/splice 等；multishot accept/recv 一個 SQE 持續產生 CQE。

### IO_LINK
**中文**：io_uring 鏈式提交
**所屬層**：io_uring flag
**首次出現**：[2.2](lessons/part-2-high-perf-io/2.2-io-uring.md)
**一句話**：IOSQE_IO_LINK 把多個 SQE 串成 chain；前一個成功才執行下一個；失敗則整鏈 -ECANCELED。

### Multishot Accept / Recv
**中文**：io_uring 多發提交
**所屬層**：io_uring
**首次出現**：[2.2](lessons/part-2-high-perf-io/2.2-io-uring.md)
**一句話**：5.19+/6.0+；一個 SQE 持續產生 CQE（IORING_CQE_F_MORE），listen socket accept loop 用 1 個 SQE 解決。

### Registered Files / Buffers / Buf Ring
**中文**：io_uring 預註冊資源
**所屬層**：io_uring
**首次出現**：[2.2](lessons/part-2-high-perf-io/2.2-io-uring.md)、[2.3](lessons/part-2-high-perf-io/2.3-zero-copy.md)
**一句話**：register_files 移除 fdget atomic；register_buffers 預先 pin user page；register_buf_ring (5.19+) ring-based buffer supply；G6 server 配 hugepage 必開。

### SEND_ZC / SENDMSG_ZC
**中文**：io_uring 零拷貝送出
**所屬層**：io_uring
**首次出現**：[2.2](lessons/part-2-high-perf-io/2.2-io-uring.md)
**一句話**：底層走 MSG_ZEROCOPY page pinning，產生兩個 CQE（kernel 收到 + 實際送完 page ref 釋放）；小 msg 反而慢，threshold ~16KB；G6 大 msg 用。

### Zero-Copy I/O
**中文**：零拷貝
**所屬層**：跨 OS 概念
**首次出現**：[2.3](lessons/part-2-high-perf-io/2.3-zero-copy.md)
**一句話**：byte 在 kernel/user 路徑上完整 copy 次數降到 0 或 1；對加密協議下界 = 1（除非 NIC offload）；G6 in-place AEAD + io_uring SEND_ZC 達 user 1 touch。

### splice / sendfile / vmsplice / tee
**中文**：Linux 零拷貝 syscall 家族
**所屬層**：kernel syscall
**首次出現**：[2.3](lessons/part-2-high-perf-io/2.3-zero-copy.md)
**一句話**：sendfile = in-kernel file→socket pass-through；splice = 任一端 pipe 的 byte stream forward；vmsplice = user buffer page-move 進 pipe；tee = pipe→pipe page-clone；G6 加密斷鏈，不適用。

### MSG_ZEROCOPY / SO_ZEROCOPY
**中文**：socket-level 零拷貝 send
**所屬層**：socket option + send flag
**首次出現**：[2.3](lessons/part-2-high-perf-io/2.3-zero-copy.md)
**一句話**：Dumazet Linux 4.14；kernel 不 copy buffer，page pin 進 skb；completion 透過 recvmsg(MSG_ERRQUEUE) 拿；break-even ~10-16KB。

### TCP_ZEROCOPY_RECEIVE
**中文**：TCP 接收端零拷貝
**所屬層**：socket option
**首次出現**：[2.3](lessons/part-2-high-perf-io/2.3-zero-copy.md)
**一句話**：getsockopt mmap user buffer 收 packet；alignment 限制嚴，only Google scale 用；G6 不採用。

### MAP_HUGETLB / Hugepage
**中文**：大頁面
**所屬層**：mm
**首次出現**：[2.3](lessons/part-2-high-perf-io/2.3-zero-copy.md)、[2.8](lessons/part-2-high-perf-io/2.8-dpdk.md)
**一句話**：2MB / 1GB page；大幅減 TLB pressure；DPDK 必用，io_uring buf_ring + G6 server 應用；sysctl vm.nr_hugepages 預配。

### In-place AEAD
**中文**：原地加密
**所屬層**：crypto + memory layout
**首次出現**：[2.3](lessons/part-2-high-perf-io/2.3-zero-copy.md)
**一句話**：ChaCha20-Poly1305 / AES-GCM 支援 plaintext / ciphertext 同 buffer；省一次 copy；G6 user-space crypto 必用此 pattern。

### kTLS
**中文**：kernel TLS
**所屬層**：socket ULP
**首次出現**：[2.4](lessons/part-2-high-perf-io/2.4-ktls.md)
**一句話**：Linux 4.13；setsockopt(TCP_ULP="tls") 把 TLS record 加解密放 kernel；支援 sendfile + TLS；nginx/Netflix 用；G6 不適用（framing 非 TLS record）。

### NIC TLS Offload
**中文**：硬體 TLS 加解密
**所屬層**：NIC firmware
**首次出現**：[2.4](lessons/part-2-high-perf-io/2.4-ktls.md)
**一句話**：Mellanox ConnectX-5+/Chelsio T6+ 內建 AES-GCM inline；host CPU 0 touch；廠商鎖；VPS 級硬體沒。

### eBPF
**中文**：extended Berkeley Packet Filter
**所屬層**：kernel programmability framework
**首次出現**：[2.5](lessons/part-2-high-perf-io/2.5-ebpf-intro.md)
**一句話**：64-bit register VM + verifier + JIT + map + helper + CO-RE；可程式化 kernel 30+ hook point；G6 用於 observability、self-fingerprint、DDoS filter、worker dispatch。

### BPF Verifier
**中文**：BPF 靜態驗證器
**所屬層**：kernel/bpf/verifier.c
**首次出現**：[2.5](lessons/part-2-high-perf-io/2.5-ebpf-intro.md)
**一句話**：abstract interpretation 確保程式有界、無 OOB、無 UAF；sound but incomplete；Gershuni PLDI 2019 形式化；G6 寫 BPF 要 verifier-friendly。

### CO-RE (Compile Once Run Everywhere)
**中文**：BPF 跨 kernel 版本可攜
**所屬層**：libbpf + BTF
**首次出現**：[2.5](lessons/part-2-high-perf-io/2.5-ebpf-intro.md)
**一句話**：Nakryiko 2019；clang 編譯記錄 BTF relocation hint，libbpf load 時依 host kernel BTF 修正欄位 offset；production deploy 標配。

### BTF (BPF Type Format)
**中文**：BPF type 結構描述
**所屬層**：debug info subset
**首次出現**：[2.5](lessons/part-2-high-perf-io/2.5-ebpf-intro.md)
**一句話**：kernel 自己 /sys/kernel/btf/vmlinux；用 bpftool btf dump 產生 vmlinux.h 供 BPF 程式 include。

### BPF Map
**中文**：BPF kv store
**所屬層**：eBPF
**首次出現**：[2.5](lessons/part-2-high-perf-io/2.5-ebpf-intro.md)
**一句話**：~30 種 type (hash/array/lru_hash/percpu/sockmap/devmap/cpumap/xskmap/ringbuf/...)；user / BPF program 共享狀態的橋樑。

### BPF Ring Buffer (BPF_MAP_TYPE_RINGBUF)
**中文**：BPF 新一代環形緩衝
**所屬層**：BPF map
**首次出現**：[2.5](lessons/part-2-high-perf-io/2.5-ebpf-intro.md)
**一句話**：Linux 5.8+；取代 PERF_EVENT_ARRAY；single-producer multi-consumer；bpf_ringbuf_reserve/submit；G6 telemetry 用。

### bpftrace / BCC / libbpf
**中文**：BPF 三大開發工具鏈
**所屬層**：user-space tooling
**首次出現**：[2.5](lessons/part-2-high-perf-io/2.5-ebpf-intro.md)
**一句話**：bpftrace = DTrace-like one-liner；BCC = Python 中型 tracer；libbpf = production-grade C/Rust loader 配 CO-RE。

### TC eBPF (cls_bpf)
**中文**：traffic control 上 BPF classifier
**所屬層**：Linux QoS subsystem
**首次出現**：[2.6](lessons/part-2-high-perf-io/2.6-ebpf-network.md)
**一句話**：Borkmann NetDev 2016；packet 進 / 出 stack 時跑 BPF；含 ingress / egress；G6 server 用於 egress 抗指紋檢驗。

### Sockmap / sk_msg / sk_skb
**中文**：BPF socket-to-socket redirect 框架
**所屬層**：BPF + socket
**首次出現**：[2.6](lessons/part-2-high-perf-io/2.6-ebpf-network.md)
**一句話**：kernel 內 socket pointer map + sk_redirect helper；user-space 0 touch proxy；plaintext only；G6 baseline mode 可考慮，加密主流量不適用。

### cgroup-bpf
**中文**：cgroup 級 BPF program attach
**所屬層**：cgroup + BPF
**首次出現**：[2.6](lessons/part-2-high-perf-io/2.6-ebpf-network.md)
**一句話**：connect4/6、sendmsg4/6、sock_create、sockops、setsockopt 等 attach type；G6 client transparent proxy 用 connect4 redirect。

### SK_LOOKUP
**中文**：BPF 動態 socket 派發
**所屬層**：BPF program type
**首次出現**：[2.6](lessons/part-2-high-perf-io/2.6-ebpf-network.md)
**一句話**：Linux 5.9+；packet 進來時 BPF 決定派給哪個 listen socket；可實作單 port 多服務（REALITY-style 共用 443）。

### sockops + bpf_setsockopt
**中文**：BPF 動態 TCP 調參
**所屬層**：cgroup-bpf
**首次出現**：[2.6](lessons/part-2-high-perf-io/2.6-ebpf-network.md)
**一句話**：sockops hook 在 TCP state change 時觸發；BPF 內呼 bpf_setsockopt 改 TCP_CONGESTION、TCP_NOTSENT_LOWAT 等；G6 動態切 BBR/CUBIC。

### XDP (eXpress Data Path)
**中文**：driver-level eBPF packet 處理
**所屬層**：NIC driver hook
**首次出現**：[2.7](lessons/part-2-high-perf-io/2.7-xdp.md)
**一句話**：Høiland-Jørgensen CoNEXT 2018；packet 還沒 alloc skb 前跑 BPF；XDP_DROP/PASS/TX/REDIRECT 四 verdict；單核 24 Mpps；G6 server DDoS 防線。

### XDP_REDIRECT + devmap/cpumap/xskmap
**中文**：XDP redirect 三種 map
**所屬層**：XDP
**首次出現**：[2.7](lessons/part-2-high-perf-io/2.7-xdp.md)
**一句話**：devmap = 送到另一 netdev；cpumap = 送到指定 CPU；xskmap = 送到 AF_XDP socket；分別對應 router-style / load-balance / user-space-zero-copy。

### AF_XDP
**中文**：XDP-fed user-space zero-copy socket
**所屬層**：socket family
**首次出現**：[2.7](lessons/part-2-high-perf-io/2.7-xdp.md)
**一句話**：UMEM (mmap user buffer) + FILL/COMPLETION/RX/TX 4 ring；NIC DMA 直接寫進 user page；DPDK-like 性能但不獨佔 NIC；G6 極致 mode 候選。

### DPDK (Data Plane Development Kit)
**中文**：用戶態 packet I/O 框架
**所屬層**：user-space
**首次出現**：[2.8](lessons/part-2-high-perf-io/2.8-dpdk.md)
**一句話**：Intel 主導；PMD + UIO/VFIO + hugepage + mempool + ring + lcore；完全 bypass kernel；NFV/5G UPF/HFT 標配；G6 不採用（太重，無 stack）。

### PMD (Poll-Mode Driver)
**中文**：用戶態輪詢驅動
**所屬層**：DPDK
**首次出現**：[2.8](lessons/part-2-high-perf-io/2.8-dpdk.md)
**一句話**：NIC 從 kernel 拔掉，由 user-space DPDK 直接 mmap PCI BAR + busy-poll；無 IRQ；latency variance 極低；DPU 設計思想直系。

### UIO / VFIO
**中文**：Linux 暴露 PCI 給 user-space 兩條路
**所屬層**：kernel
**首次出現**：[2.8](lessons/part-2-high-perf-io/2.8-dpdk.md)
**一句話**：UIO 古老無 IOMMU 隔離；VFIO 用 IOMMU 安全模型，現代必選；dpdk-devbind.py 切換。

### mTCP / F-Stack / Seastar / smoltcp / netstack3
**中文**：user-space TCP stack 家族
**所屬層**：user-space transport
**首次出現**：[2.9](lessons/part-2-high-perf-io/2.9-userspace-tcp.md)
**一句話**：mTCP NSDI 2014 學術；F-Stack = FreeBSD TCP + DPDK 工業；Seastar = C++ TPC runtime；smoltcp = Rust no_std 嵌入式；netstack3 = Fuchsia Rust；G6 不採用 server，client TUN path 用 smoltcp。

### Share-Nothing Thread-Per-Core (TPC)
**中文**：共享一無的執行緒模型
**所屬層**：runtime architecture
**首次出現**：[2.8](lessons/part-2-high-perf-io/2.8-dpdk.md)、[2.9](lessons/part-2-high-perf-io/2.9-userspace-tcp.md)
**一句話**：每 core 獨立 state、無 cross-core lock、靠 lock-free ring 通訊；DPDK lcore / Seastar / monoio 都這設計；G6 server runtime 採用。

### Network Extension (NE) framework
**中文**：macOS/iOS 系統網路擴展
**所屬層**：macOS userspace + system process
**首次出現**：[2.10](lessons/part-2-high-perf-io/2.10-macos.md)
**一句話**：Apple 強制 VPN/firewall/DNS 走 NE 不可 kext；NEPacketTunnelProvider / NETransparentProxyProvider / NEFilter / NEDNSProxyProvider 等子類；需 entitlement + notarization；G6 macOS client 必經之路。

### NEPacketTunnelProvider
**中文**：macOS 全隧道 VPN 提供者
**所屬層**：NE
**首次出現**：[2.10](lessons/part-2-high-perf-io/2.10-macos.md)
**一句話**：接管整個 device 流量；NEPacketTunnelFlow.readPackets/writePackets API；iOS only support 此種；G6 跨 macOS/iOS 必有。

### NETransparentProxyProvider
**中文**：macOS 11+ 透明流量代理提供者
**所屬層**：NE
**首次出現**：[2.10](lessons/part-2-high-perf-io/2.10-macos.md)
**一句話**：socket flow level (NEAppProxyFlow)；只攔截條件命中的 flow（per-app/per-host）；iOS 不支援；G6 macOS client 預期主路徑。

### utun
**中文**：macOS L3 虛擬介面
**所屬層**：macOS BSD layer
**首次出現**：[2.10](lessons/part-2-high-perf-io/2.10-macos.md)、[2.11](lessons/part-2-high-perf-io/2.11-tun-tap.md)
**一句話**：socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) + UTUN_CONTROL_NAME；強制 4-byte AF prefix；無 multi-queue/NAPI/GSO；無 IFF_NO_PI 對等。

### DTrace
**中文**：macOS/Solaris 動態追蹤
**所屬層**：tracing
**首次出現**：[2.10](lessons/part-2-high-perf-io/2.10-macos.md)
**一句話**：Sun 2003 起源，Apple 移植；macOS 的「半個 eBPF」；M1+ SIP 限制；G6 macOS observability 替代方案。

### TUN / IFF_TUN / IFF_NO_PI / IFF_MULTI_QUEUE
**中文**：Linux TUN device + 關鍵 flag
**所屬層**：drivers/net/tun.c
**首次出現**：[2.11](lessons/part-2-high-perf-io/2.11-tun-tap.md)
**一句話**：open(/dev/net/tun) + ioctl(TUNSETIFF)；IFF_NO_PI 移除 4-byte packet info prefix（必開）；IFF_MULTI_QUEUE 多 fd 對一 interface；IFF_NAPI 5.5+ batch；IFF_VNET_HDR + GSO 大段 segment。

### wireguard-go `Device` interface
**中文**：跨平台 TUN abstraction trait
**所屬層**：user-space lib
**首次出現**：[2.11](lessons/part-2-high-perf-io/2.11-tun-tap.md)
**一句話**：File/Read/Write/Flush/MTU/Name/Events/Close/BatchSize；wireguard-go tun/ 子目錄；Linux/macOS/Windows/iOS/BSD/netstack 各實作；G6 client TUN trait 直接抄。

### Network Namespace (netns)
**中文**：Linux 網路命名空間
**所屬層**：kernel isolation
**首次出現**：[2.12](lessons/part-2-high-perf-io/2.12-netns.md)
**一句話**：Biederman 2007；隔離 netdev/routing/netfilter/conntrack/BPF/sysctl 一整套 stack；ip netns add 用 bind mount pin；G6 整合測試骨架。

### veth pair
**中文**：虛擬乙太網對
**所屬層**：drivers/net/veth.c
**首次出現**：[2.12](lessons/part-2-high-perf-io/2.12-netns.md)
**一句話**：point-to-point virtual ethernet；ip link add ... type veth peer name ... 一邊送另一邊收；container 網路骨架；支援 XDP。

### containerlab / mininet
**中文**：netns 拓樸自動化工具
**所屬層**：testing tooling
**首次出現**：[2.12](lessons/part-2-high-perf-io/2.12-netns.md)
**一句話**：用 YAML 描述網路拓樸自動拉起 netns + veth + 各節點 container；G6 整合測試直接用。

### tc / qdisc
**中文**：Linux traffic control / queueing discipline
**所屬層**：net/sched
**首次出現**：[2.13](lessons/part-2-high-perf-io/2.13-tc-netem.md)
**一句話**：每 NIC root qdisc + child class 樹狀；classful (HTB/HFSC/PRIO) vs classless (pfifo/fq/fq_codel/cake/netem)；G6 server 預設 fq_codel。

### fq / fq_codel
**中文**：Fair Queue 與 fq_codel
**所屬層**：qdisc
**首次出現**：[2.13](lessons/part-2-high-perf-io/2.13-tc-netem.md)
**一句話**：fq = per-flow FIFO + pacing（配 BBR 必要）；fq_codel = per-flow + CoDel AQM（RFC 8290）；Linux 5.x default；G6 server fq + BBR。

### CAKE
**中文**：Common Applications Kept Enhanced qdisc
**所屬層**：qdisc
**首次出現**：[2.13](lessons/part-2-high-perf-io/2.13-tc-netem.md)
**一句話**：Høiland-Jørgensen 2018 / arXiv:1804.07617；fq_codel 後繼，內建 shaping + ISP overhead 補償 + per-host fairness + DiffServ；OpenWrt SQM 預設；G6 文件建議家用 router 開。

### CoDel (Controlled Delay)
**中文**：受控延遲 AQM 演算法
**所屬層**：AQM
**首次出現**：[2.13](lessons/part-2-high-perf-io/2.13-tc-netem.md)
**一句話**：Nichols-Jacobson CACM 2012；用 packet sojourn time 而非 queue 長度當 drop 訊號；5ms/100ms 兩個常數；解決 bufferbloat。

### Bufferbloat
**中文**：緩衝臃腫
**所屬層**：networking 病灶
**首次出現**：[2.13](lessons/part-2-high-perf-io/2.13-tc-netem.md)
**一句話**：Gettys 2010 命名；大 buffer + tail drop → 高 latency under load；fq_codel/cake/BBR 是 cure；G6 client 在 user router 後易受影響。

### BBR (Bottleneck Bandwidth and Round-trip propagation)
**中文**：Google 的 model-based congestion control
**所屬層**：TCP CC
**首次出現**：[2.13](lessons/part-2-high-perf-io/2.13-tc-netem.md)
**一句話**：Cardwell CACM 2017；持續 estimate BtlBw + RTprop，pacing 不 fill buffer，對 loss 不過度反應；lossy 鏈路下比 CUBIC 強 10-80×；G6 server 必開（配 fq pacing）。

### netem
**中文**：Linux 網路模擬器 qdisc
**所屬層**：qdisc
**首次出現**：[2.13](lessons/part-2-high-perf-io/2.13-tc-netem.md)
**一句話**：tc qdisc add ... netem delay/loss/reorder/duplicate/corrupt/rate；4-state Gilbert loss model；G6 對抗測試模擬「中美鏈路 50Mbps + 100ms RTT + 5% loss」canonical scenario。

### NAPI (New API)
**中文**：Linux 收包 IRQ/poll 混合
**所屬層**：net/core
**首次出現**：[2.14](lessons/part-2-high-perf-io/2.14-final-picture.md)
**一句話**：Mogul-Ramakrishnan TOCS 1997 livelock 啟發；high-load 時 disable IRQ + poll batch；現代 NIC driver 標配；epoll busy_poll 跟 NAPI 整合。

### PCIe / Endpoint Networking Bottleneck
**中文**：PCIe 鏈路是 100Gbps NIC 的隱形天花板
**所屬層**：硬體 + interconnect
**首次出現**：[2.14](lessons/part-2-high-perf-io/2.14-final-picture.md)
**一句話**：Neugebauer SIGCOMM 2018；PCIe TLP overhead + NUMA + cache coherence 把 100Gbps 實際吃到 70Gbps 以下；DPU 演化動因之一。

### Click Modular Router
**中文**：模組化封包處理 graph
**所屬層**：軟體 router architecture
**首次出現**：[2.14](lessons/part-2-high-perf-io/2.14-final-picture.md)
**一句話**：Kohler TOCS 2000；directed graph of element 描述 packet path；VPP/Cilium 後繼；G6 server packet processing 內部抽象。

### Stack Specialization
**中文**：協議堆疊特化
**所屬層**：systems design philosophy
**首次出現**：[2.9](lessons/part-2-high-perf-io/2.9-userspace-tcp.md)、[2.14](lessons/part-2-high-perf-io/2.14-final-picture.md)
**一句話**：Marinos SIGCOMM 2014；general-purpose stack 必然 overhead，為 application 量身打造 stack 可大幅減 code；G6 是「為 proxy 量身打造的 transport」。

### Byte Touch Count
**中文**：byte 觸碰次數
**所屬層**：performance modeling
**首次出現**：[2.3](lessons/part-2-high-perf-io/2.3-zero-copy.md)
**一句話**：packet 從 NIC RX 到 NIC TX 路徑上 CPU load/store 次數；加密協議下界 = 1（加密本身）；G6 目標穩定達 1。
