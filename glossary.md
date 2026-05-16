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
**首次出現**：[1.2](lessons/part-1-networking/1.2-physical-and-phy-mac.md)（提及）；[1.11](lessons/part-1-networking/1.11-tcp-advanced.md) 深入；[2.15](lessons/part-2-high-perf-io/2.15-udp-fastpath.md) UDP 端深入
**一句話**：TSO/GSO 把大 SKB 切成 MTU-size packet 由 NIC 或 kernel 處理；USO（Linux 4.18+）為 UDP/QUIC 同類功能，對 QUIC throughput +10× 級；GRO 為接收側合併；G6 server production 必須啟用。

### UDP_SEGMENT (UDP GSO socket option)
**中文**：UDP 分段卸載 socket 選項
**所屬層**：kernel UDP（kernel 4.18+）
**首次出現**：[2.15 UDP 高效能路徑](lessons/part-2-high-perf-io/2.15-udp-fastpath.md)
**一句話**：`setsockopt(fd, SOL_UDP, UDP_SEGMENT, &gso_size, ...)` 或 cmsg；單次 sendmsg 最多 64 KB / 64 segments；kernel 自動切成獨立完整 UDP datagram（**非** IP fragments）；commit `bec1f6f697` (de Bruijn)。

### UDP_GRO (UDP GRO socket option)
**中文**：UDP 接收合併 socket 選項
**所屬層**：kernel UDP（kernel 5.0+）
**首次出現**：[2.15](lessons/part-2-high-perf-io/2.15-udp-fastpath.md)
**一句話**：`setsockopt(fd, SOL_UDP, UDP_GRO, &one, ...)`；同 5-tuple、TTL、IP option 的連續 UDP 包合併入單個 skb，recvmsg 帶 cmsg 告訴 app segment 切點；commit `e20cf8d3f1f7` (Abeni)。

### sendmmsg / recvmmsg
**中文**：批次 datagram 收發 syscall
**所屬層**：kernel socket syscall（Linux 3.0+ sendmmsg / 2.6.33+ recvmmsg）
**首次出現**：[2.2 io_uring](lessons/part-2-high-perf-io/2.2-io-uring.md)（提及）；[2.15](lessons/part-2-high-perf-io/2.15-udp-fastpath.md) 深入
**一句話**：一次 syscall 收/發多個 datagram（含目的地不同的多 peer），與 UDP_SEGMENT 兩層批次疊加是 QUIC 跑滿 10 Gbps 的標準配方。

### EDT (Earliest Departure Time) pacing model
**中文**：最早出發時戳 pacing 模型
**所屬層**：kernel sch_fq + app（Linux 4.20+）
**首次出現**：[2.13 tc/netem](lessons/part-2-high-perf-io/2.13-tc-netem.md)（提及）；[2.15](lessons/part-2-high-perf-io/2.15-udp-fastpath.md) 深入
**一句話**：應用層用 `SO_TXTIME` + `SCM_TXTIME` cmsg 給每個 packet 標未來時戳，sch_fq 按時戳出隊；把 pacing 計算從 kernel 推回 app（讓 app 端 BBR 直接精控）；Dumazet & Jacobson 2018 (LWN-752184)。

### SO_TXTIME / SCM_TXTIME
**中文**：發送時戳 socket option
**所屬層**：kernel socket / cmsg
**首次出現**：[2.15](lessons/part-2-high-perf-io/2.15-udp-fastpath.md)
**一句話**：EDT model 的 user-space API；clockid 通常 `CLOCK_TAI`；G6 pacing 設計的硬性 API 對齊目標。

### BQL (Byte Queue Limits)
**中文**：驅動發送隊列字節限制
**所屬層**：kernel NIC driver（Linux 3.3+）
**首次出現**：[2.15](lessons/part-2-high-perf-io/2.15-udp-fastpath.md)
**一句話**：動態限制 driver 向 NIC TX ring push 的字節數，把 TX ring bufferbloat 從 5 ms 壓到 ~200 μs；BBR-style CC 在無 BQL 環境下 RTT measure 失真、bottleneck bandwidth 估錯；Tom Herbert 2011。

### AF_PACKET + PACKET_MMAP / TPACKET_V3
**中文**：高效能 user-space raw packet capture / inject
**所屬層**：kernel L2 / user-space
**首次出現**：[2.15](lessons/part-2-high-perf-io/2.15-udp-fastpath.md)
**一句話**：mmap-based 環狀緩衝把 packet 從 kernel 零拷貝給 user，比 libpcap default backend 快 ~10×；G6 evaluation 用來抓「未被 app buffer 模糊」的真實時序給 DPI mock。

### CID-aware reuseport BPF
**中文**：連線標識感知的 SO_REUSEPORT 分發 BPF 程式
**所屬層**：socket layer (sk_reuseport BPF program type)
**首次出現**：[2.15](lessons/part-2-high-perf-io/2.15-udp-fastpath.md)
**一句話**：QUIC 因 NAT 換 port 會使 5-tuple hash 漂移、worker 切換破壞 state；解法是用 sk_reuseport eBPF 解析 QUIC short header 取 CID 做分發；G6 server 多核擴展必備、且收窄了我們 CID 結構設計（前 8B 必須 routing-stable）。

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

## Part 3 進階補遺（3.17）

### Committing AEAD / CMTD
**所屬層**：對稱密碼學
**首次出現**：[3.17](lessons/part-3-cryptography/3.17-advanced-frontiers.md) §1
**一句話**：AEAD 的 key-/context-commitment 性質——確保 ciphertext 在 ≠ key 下不可能同時 decrypt 成功；標準 ChaCha20-Poly1305 / AES-GCM 都不滿足，被 partitioning oracle attack 利用（Telegram 2022 中招）。

### CTX (Context Commitment Transform)
**所屬層**：AEAD generic transform
**首次出現**：[3.17](lessons/part-3-cryptography/3.17-advanced-frontiers.md) §1
**一句話**：Bellare-Hoang EUROCRYPT 2022 提出，在現有 AEAD 後接一個 HMAC-based commit tag，達 CMT-4 安全 (最強)；G6 採用，每 record +16 byte (~1.5% MTU overhead)。

### Partitioning Oracle Attack
**所屬層**：適用對 password-derived key AEAD 的攻擊
**首次出現**：[3.17](lessons/part-3-cryptography/3.17-advanced-frontiers.md) §1
**一句話**：Len-Grubbs-Ristenpart USENIX Security 2021。攻擊者送一個 multi-key-valid ciphertext，server 一次互動可排除 2^k password candidate；Albrecht 等 IEEE S&P 2022 用之完整 break Telegram MTProto。

### KEMTLS
**所屬層**：握手協議家族
**首次出現**：[3.17](lessons/part-3-cryptography/3.17-advanced-frontiers.md) §2
**一句話**：Schwabe-Stebila-Wiggers CCS 2020。用 server long-term KEM (decap capability) 替代 server signature 做 implicit authentication；PQ mode 下握手減 ~6 KB；G6 v1 採 Mode C (KEMTLS server + signature client)。

### Hybrid KEM Combiner
**所屬層**：PQ KE
**首次出現**：[3.11](lessons/part-3-cryptography/3.11-post-quantum.md)、[3.17](lessons/part-3-cryptography/3.17-advanced-frontiers.md) §3
**一句話**：將 classical KEM (X25519) 與 PQ KEM (ML-KEM) combine 成 hybrid KEM 的構造；Bindel-Brendel-Fischlin-Goncalves-Stebila PQCrypto 2019 證明 "ciphertext + KDF" 構造 IND-CCA2 OR-secure (任一 component 安全則 hybrid 安全)；G6 hybrid spec 直接套用。

### Double Ratchet
**所屬層**：cryptographic ratchet
**首次出現**：[3.1](lessons/part-3-cryptography/3.1-crypto-goals-taxonomy.md)、[3.6](lessons/part-3-cryptography/3.6-key-exchange.md)、[3.17](lessons/part-3-cryptography/3.17-advanced-frontiers.md) §4
**一句話**：Marlinspike-Perrin 2016 Signal protocol。DH ratchet (粗) + symmetric chain ratchet (細) 兩層；每 message FS、每 round-trip PCS；G6 採 coarser-grained 版 (per N records 而非 per message)。

### PCS Healing Window
**所屬層**：AKE 安全性質
**首次出現**：[3.6](lessons/part-3-cryptography/3.6-key-exchange.md)、[3.17](lessons/part-3-cryptography/3.17-advanced-frontiers.md) §4
**一句話**：對手洩漏 state at time t 後，協議自動恢復 secrecy 所需時間；Signal ~1 message；G6 ~2 minutes (與 WireGuard rekey 同階)；衡量「snapshot adversary」防禦能力。

### Domain Separation (Label Discipline)
**所屬層**：hash / KDF 工程
**首次出現**：[3.3](lessons/part-3-cryptography/3.3-hash-functions-kdf.md)、[3.17](lessons/part-3-cryptography/3.17-advanced-frontiers.md) §5
**一句話**：不同 context 用 unique label 隔離 hash 輸入空間；TLS 1.3 用 "tls13 " prefix; G6 用 "g6_v1__ " prefix；防 cross-protocol / cross-version key reuse；對應 indifferentiability 工程實踐。

### Indifferentiability
**所屬層**：hash function 理論
**首次出現**：[3.3](lessons/part-3-cryptography/3.3-hash-functions-kdf.md)、[3.17](lessons/part-3-cryptography/3.17-advanced-frontiers.md) §5
**一句話**：Maurer-Renner-Holenstein TCC 2004。hash 對 random oracle 不可區分；SHA-3 sponge inherently indifferentiable，SHA-2 MD 不是 (Coron-Dodis 等 2005)；G6 透過 HMAC/HKDF wrapper 解決 SHA-2 indifferentiability gap。

### Robust AE (RAE)
**所屬層**：AEAD 強化版
**首次出現**：[3.2](lessons/part-3-cryptography/3.2-symmetric-aead.md)、[3.17](lessons/part-3-cryptography/3.17-advanced-frontiers.md) §6
**一句話**：Rogaway-Shrimpton EUROCRYPT 2006 提出，AEAD 對任意 input 都產 IND-CCA + INT-CTXT 並 constant-time abort；G6 mandate RAE-style 錯誤路徑防 timing-oracle。

### Beyond-Birthday-Bound (BBB) Security
**所屬層**：AEAD 安全 bound
**首次出現**：[3.2](lessons/part-3-cryptography/3.2-symmetric-aead.md)、[3.17](lessons/part-3-cryptography/3.17-advanced-frontiers.md) §6
**一句話**：AEAD 安全 bound 超越 q²/2^128 standard birthday；AES-GCM-SIV (q³/2^256)、XChaCha20 (24-byte nonce 把 ~2^32 推到 ~2^48 records-per-key)；G6 採 XChaCha20-Poly1305 為 record cipher。

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

---

## Part 5 — 形式化方法

### Needham-Schroeder Public-Key Protocol
**中文**：Needham-Schroeder 公鑰協議
**所屬層**：authenticated key exchange
**首次出現**：[5.1](lessons/part-5-formal-methods/5.1-why-formalize.md)
**一句話**：Needham & Schroeder CACM 1978 三步 nonce exchange；1978-1995 沒人發現 MITM；Lowe 1996 用 FDR 找出 attack + NSL fix 加 responder identity；formal verification 必要性的最 striking 例證。

### Dolev-Yao Model
**中文**：Dolev-Yao 對手模型
**所屬層**：cryptographic adversary model
**首次出現**：[5.1](lessons/part-5-formal-methods/5.1-why-formalize.md)、[4.1](lessons/part-4-tls-quic/4.1-tls-history-bloodshed.md)
**一句話**：Dolev & Yao IEEE TIT 1983；attacker 完全控制 wire (read/inject/drop/replay) 但密碼學原語視 ideal；symbolic model 的標準 adversary; ProVerif/Tamarin 內建。

### Lowe's Authentication Hierarchy
**中文**：Lowe 認證階層
**所屬層**：formal definition
**首次出現**：[5.1](lessons/part-5-formal-methods/5.1-why-formalize.md)
**一句話**：Lowe CSFW 1997 把「authentication」拆 4 層 — aliveness / weak agreement / non-injective agreement / injective agreement；每層對 attack 免疫度遞增；Selfie attack 違反 injective agreement。

### Safety vs Liveness Property
**中文**：安全性 vs 活性
**所屬層**：formal property classification
**首次出現**：[5.2](lessons/part-5-formal-methods/5.2-tla-plus-intro.md)
**一句話**：Lamport 1977 經典分類；safety = 「不好的事永遠不發生」(`[][Inv]`); liveness = 「好的事最終會發生」(`<>Goal`)；需 fairness 假設證明 liveness。

### TLA+
**中文**：Temporal Logic of Actions + ZF set theory specification language
**所屬層**：formal specification
**首次出現**：[5.2](lessons/part-5-formal-methods/5.2-tla-plus-intro.md)、[5.3](lessons/part-5-formal-methods/5.3-tla-plus-advanced.md)
**一句話**：Lamport 1994 logic + 1999 language；spec = `Init /\ [][Next]_vars /\ Fairness`；AWS DynamoDB/S3/EBS 部署；TLC explicit-state + Apalache symbolic + TLAPS proof system 三 backend。

### TLC / Apalache
**中文**：TLA+ model checkers
**所屬層**：verification tool
**首次出現**：[5.3](lessons/part-5-formal-methods/5.3-tla-plus-advanced.md)
**一句話**：TLC (Yu-Manolios-Lamport 1999) explicit-state BFS over reachable states；Apalache (Konnov 2019) symbolic with SMT solver；前者對 finite model 完整；後者對 unbounded data type bounded-depth 強。

### PlusCal
**中文**：TLA+ procedural language frontend
**所屬層**：spec frontend
**首次出現**：[5.2](lessons/part-5-formal-methods/5.2-tla-plus-intro.md)
**一句話**：Lamport 設計，編譯到 TLA+；syntax 像 imperative pseudo-code；初學者友善但 state space 較 hand-written TLA+ 大；對 protocol modeling 通常 hand-written TLA+ 更乾淨。

### Refinement (TLA+)
**中文**：規格精化
**所屬層**：spec methodology
**首次出現**：[5.3](lessons/part-5-formal-methods/5.3-tla-plus-advanced.md)
**一句話**：low-level spec `L` refines high-level spec `H` iff `L => H` (temporal implication)；對 layered design 必要；TLA+ 用 `INSTANCE` keyword + refinement mapping function 表達。

### Inductive Invariant
**中文**：歸納不變量
**所屬層**：proof technique
**首次出現**：[5.3](lessons/part-5-formal-methods/5.3-tla-plus-advanced.md)
**一句話**：`I` inductive iff `Init => I` AND `(I /\ Next) => I'`；對 unbounded state 唯一可行 proof technique；強於 reachable invariant；用 TLAPS 或 Apalache 部分自動 derive。

### Applied Pi-Calculus
**中文**：applied 進程代數
**所屬層**：formal model language
**首次出現**：[5.4](lessons/part-5-formal-methods/5.4-applied-pi-calculus-proverif.md)
**一句話**：Abadi & Fournet POPL 2001 extension of pi-calculus (Milner 1989)；加 function symbols + equational theory + active substitution；ProVerif 的 input language；對 cryptographic protocol 表達自然。

### ProVerif
**中文**：cryptographic protocol verifier
**所屬層**：symbolic verification tool
**首次出現**：[5.4](lessons/part-5-formal-methods/5.4-applied-pi-calculus-proverif.md)、[5.5](lessons/part-5-formal-methods/5.5-proverif-noise-ik.md)
**一句話**：Blanchet CSFW 2001（Test of Time CSF 2023）；把 applied pi-calculus 抽象為 Horn clauses + resolution 求 attacker derivability；unbounded sessions; TLS 1.3 / Signal / WireGuard / MLS / ECH 主要 verifier。

### Horn Clause Abstraction
**中文**：Horn 子句抽象
**所屬層**：ProVerif internal
**首次出現**：[5.4](lessons/part-5-formal-methods/5.4-applied-pi-calculus-proverif.md)
**一句話**：把 protocol step 表示為 `att(M1) /\ ... /\ att(Mn) => att(M)` 形式; ProVerif 用 resolution 求 `att(secret)` 是否 derivable；over-approximation 可能有 false positive。

### Noise Protocol Framework
**中文**：Noise 協議框架
**所屬層**：handshake pattern family
**首次出現**：[5.5](lessons/part-5-formal-methods/5.5-proverif-noise-ik.md)
**一句話**：Trevor Perrin 設計；不是單一 protocol 而是 family；每 pattern 由 letter token 組合 (e, s, es, ee, se, ss)；NN/NK/NX/KK/XX/IK 各 trade-off; WireGuard 用 IK; Signal X3DH 啟發自 Noise。

### Noise IK
**中文**：Noise IK handshake pattern
**所屬層**：handshake pattern
**首次出現**：[5.5](lessons/part-5-formal-methods/5.5-proverif-noise-ik.md)
**一句話**：Immediate initiator key + known responder key；message 1 含 ephemeral + encrypted initiator static + DH(es, ss)；message 2 含 ephemeral + DH(ee, se)；mutual auth + FS + identity hiding (responder)；WireGuard 採用。

### WireGuard
**中文**：next-generation VPN protocol
**所屬層**：VPN
**首次出現**：[5.5](lessons/part-5-formal-methods/5.5-proverif-noise-ik.md)、Part 6 (forthcoming)
**一句話**：Donenfeld NDSS 2017; Noise IK + Curve25519 + ChaCha20-Poly1305 + BLAKE2s; 4000 LOC kernel impl; Donenfeld-Milner 2018 Tamarin + Lipp-Blanchet-Bhargavan 2019 ProVerif 完整 verify; **但 wire 強指紋對 GFW 透明**。

### Noise Explorer
**中文**：自動化 Noise variants verifier
**所屬層**：verification tool
**首次出現**：[5.5](lessons/part-5-formal-methods/5.5-proverif-noise-ik.md)
**一句話**：Kobeissi-Nicolas-Bhargavan EuroS&P 2019；輸入 Noise pattern notation，自動生成 ProVerif + Tamarin spec 並 verify；100+ Noise variant 對比工具。

### Tamarin Prover
**中文**：symbolic protocol verifier
**所屬層**：verification tool
**首次出現**：[5.6](lessons/part-5-formal-methods/5.6-tamarin-prover.md)
**一句話**：Meier-Schmidt-Cremers-Basin CAV 2013；multiset rewriting + first-order logic + backwards reasoning；對 DH algebraic + multi-stage AKE + stateful protocol 強於 ProVerif；TLS 1.3 / WireGuard / 5G-AKA / EMV / MLS 主力 verifier。

### Multiset Rewriting
**中文**：multiset 改寫系統
**所屬層**：Tamarin internal
**首次出現**：[5.6](lessons/part-5-formal-methods/5.6-tamarin-prover.md)
**一句話**：rule `[premise_facts] --[ action ]--> [conclusion_facts]`；state = multiset of facts；linear (consumed) vs persistent (`!`-prefix) facts；對 mutable global state 自然。

### CryptoVerif
**中文**：computational model verifier
**所屬層**：verification tool
**首次出現**：[5.7](lessons/part-5-formal-methods/5.7-cryptoverif.md)
**一句話**：Blanchet IEEE TDSC 2008；同樣 Blanchet 設計 in computational model；自動 game transformation 給 tight ε bound on attacker advantage；TLS 1.3 record limit + WireGuard tight bound 來源；比 ProVerif 慢，需要 user-provided cryptographic axioms。

### Game-Based Proof
**中文**：賽局證明
**所屬層**：cryptographic methodology
**首次出現**：[5.7](lessons/part-5-formal-methods/5.7-cryptoverif.md)
**一句話**：Bellare-Rogaway CRYPTO 1993 + Bellare EUROCRYPT 2006；security 透過 game (challenger vs adversary) 形式化；advantage = `|Pr[A wins] - 1/2|`；secure iff advantage negligible for PPT adversary。

### IND-CPA / IND-CCA / UF-CMA
**中文**：標準 security 定義集合
**所屬層**：cryptographic primitive
**首次出現**：[5.7](lessons/part-5-formal-methods/5.7-cryptoverif.md)
**一句話**：IND-CPA = indistinguishability under chosen-plaintext attack (對稱加密)；IND-CCA = under chosen-ciphertext attack；UF-CMA = unforgeability under chosen-message attack (signature)；現代密碼學 primitive 標準目標。

### Game Transformation
**中文**：賽局變換
**所屬層**：CryptoVerif technique
**首次出現**：[5.7](lessons/part-5-formal-methods/5.7-cryptoverif.md)
**一句話**：把 game $G_i$ 變換成 $G_{i+1}$ 累積 ε cost；最終 reduce 到 ideal game (perfect secrecy)；total advantage bound = sum of ε per transformation；TLS 1.3 record layer proof 30+ transformations。

### Spec-First Methodology
**中文**：規格優先方法論
**所屬層**：design methodology
**首次出現**：[5.8](lessons/part-5-formal-methods/5.8-spec-first-methodology.md)、[5.1](lessons/part-5-formal-methods/5.1-why-formalize.md)
**一句話**：先寫 threat model → 先 spec → 先 verify → 才寫 implementation；TLS 1.3 是 IETF 第一個此模式 RFC；spec / proof / impl 同 repo + cross-reference；PhD-level 設計協議 standard。

### Lightweight Formal Methods (LFM)
**中文**：輕量化形式化方法
**所屬層**：methodology
**首次出現**：[5.8](lessons/part-5-formal-methods/5.8-spec-first-methodology.md)
**一句話**：Bornholt et al. SOSP 2021；對 critical component 做 partial verification + executable model + property test；對 less critical part 採 LFM 省 cost；AWS S3 production case。

### Annotated RFC
**中文**：交叉參照規格
**所屬層**：documentation
**首次出現**：[5.8](lessons/part-5-formal-methods/5.8-spec-first-methodology.md)
**一句話**：Cremers TLS 1.3 CCS 2017 best practice；spec prose 每段對 Tamarin rule / ProVerif process 一一對應；reviewer auditable; 我們協議 Part 11.10 採此模板。


### IND-CPA / IND-CCA1 / IND-CCA2
**中文**：選擇明文 / 選擇密文（非適應性 / 適應性）攻擊下的不可區分性
**所屬層**：密碼學安全定義
**首次出現**：[3.1 — 密碼學的目標分類學](lessons/part-3-cryptography/3.1-crypto-goals-taxonomy.md)
**一句話**：對手能挑明文（CPA）或密文（CCA）並查 oracle，仍無法在兩個等長明文間區分密文對應哪一個；現代加密最低門檻是 IND-CCA2，G6 record layer 必須達成。

### EUF-CMA / sUF-CMA
**中文**：Existential / Strong Unforgeability under Chosen-Message Attack
**所屬層**：密碼學安全定義（簽章 / MAC）
**首次出現**：[3.1](lessons/part-3-cryptography/3.1-crypto-goals-taxonomy.md)
**一句話**：對手在 adaptively 查 signing oracle 後仍無法產生新訊息（EUF）或新對 (m, σ)（sUF）的有效簽章；GMR 1988 給出原始定義；G6 用 Ed25519 達成 sUF-CMA。

### AEAD (Authenticated Encryption with Associated Data)
**中文**：帶附加資料的認證加密
**所屬層**：對稱加密 primitive
**首次出現**：[3.1](lessons/part-3-cryptography/3.1-crypto-goals-taxonomy.md)
**一句話**：合機密 (IND-CCA2) + 完整 (INT-CTXT) 為一原語；現代協議 record layer 標配；ChaCha20-Poly1305、AES-GCM 是 G6 候選。

### INT-PTXT / INT-CTXT
**中文**：明文 / 密文完整性
**所屬層**：密碼學安全定義
**首次出現**：[3.1](lessons/part-3-cryptography/3.1-crypto-goals-taxonomy.md)
**一句話**：INT-PTXT 防止對手讓 Dec 接受對應新明文的密文；INT-CTXT 進一步禁止任何新密文（即使對應舊明文）；現代 AEAD 必達 INT-CTXT。

### Forward Secrecy (FS / PFS)
**中文**：前向保密
**所屬層**：AKE 安全屬性
**首次出現**：[3.1](lessons/part-3-cryptography/3.1-crypto-goals-taxonomy.md)（Diffie 1976 萌芽；DOW 1992 正式化）
**一句話**：長期金鑰 t 時刻外洩，**早於** t 完成的 session 仍安全；G6 必達，由 ephemeral X25519 達成。

### PCS (Post-Compromise Security)
**中文**：後折損安全性
**所屬層**：AKE 安全屬性
**首次出現**：[3.1](lessons/part-3-cryptography/3.1-crypto-goals-taxonomy.md)（Cohn-Gordon-Cremers-Garratt CSF 2016）
**一句話**：t 時刻長期金鑰外洩 + 對手之後離開／無持續 active，**晚於** t 的 session 重新安全；Signal Double Ratchet 是代表；G6 用 per-N-record DH ratchet 達成粗粒度版。

### KCI Resistance (Key Compromise Impersonation)
**中文**：金鑰折損冒充抗性
**所屬層**：AKE 安全屬性
**首次出現**：[3.1](lessons/part-3-cryptography/3.1-crypto-goals-taxonomy.md)
**一句話**：A 的 LTK 被偷後，對手仍**不能假冒 B 對 A 講話**；plain DH 沒這屬性，SIGMA-I（Krawczyk 2003）有；G6 用 SIGMA-I 結構達成。

### UKS (Unknown Key Share)
**中文**：未知金鑰共享攻擊
**所屬層**：AKE 攻擊類別
**首次出現**：[3.1](lessons/part-3-cryptography/3.1-crypto-goals-taxonomy.md)
**一句話**：A 與 B 完成 handshake 並對共享 key 一致，但雙方註冊的對方身份不一致；STS 1992 有此 bug，SIGMA 用 MAC 綁 identity 修補；G6 transcript 必含雙方 ID。

### SIGMA / SIGMA-I
**中文**：SIGn-and-MAc 結構的認證 DH
**所屬層**：AKE 設計範式
**首次出現**：[3.1](lessons/part-3-cryptography/3.1-crypto-goals-taxonomy.md)（Krawczyk CRYPTO 2003）
**一句話**：簽 ephemeral DH share + MAC 綁 identity；TLS 1.3、IKEv2、Noise IK 的學術根基；G6 採用其 identity protection (SIGMA-I) 變體。

### Dolev-Yao Model
**中文**：Dolev-Yao 對手模型
**所屬層**：protocol verification 抽象
**首次出現**：[3.1](lessons/part-3-cryptography/3.1-crypto-goals-taxonomy.md)（Dolev-Yao IEEE TIT 1983）
**一句話**：對手控制整個網路（讀寫刪重排注入）但不能破密碼學原語；ProVerif、Tamarin、Scyther 等所有 symbolic verifier 的根基。

### Random Oracle Model (ROM)
**中文**：隨機 oracle 模型
**所屬層**：密碼學證明 model
**首次出現**：[3.1](lessons/part-3-cryptography/3.1-crypto-goals-taxonomy.md)（Bellare-Rogaway CCS 1993）
**一句話**：把 hash function 當 truly random function 證明；Canetti-Goldreich-Halevi 1998 證明 ROM 不嚴格 sound 但實務上仍是 standard heuristic；G6 證明盡量 standard model。

### Replay Resistance
**中文**：重放抗性
**所屬層**：protocol-level 安全屬性
**首次出現**：[3.1](lessons/part-3-cryptography/3.1-crypto-goals-taxonomy.md)
**一句話**：對手錄下訊息事後重送會被拒；通常用 sequence counter 嵌入 AEAD nonce + receiver window 達成；0-RTT 是著名例外。

### CK / eCK Model
**中文**：Canetti-Krawczyk / extended CK 模型
**所屬層**：AKE 安全 model
**首次出現**：[3.1](lessons/part-3-cryptography/3.1-crypto-goals-taxonomy.md)（Canetti-Krawczyk EUROCRYPT 2001 / LaMacchia-Lauter-Mityagin 2007）
**一句話**：定義 AKE 中對手能查哪些 oracle（session-key、ephemeral、long-term）；G6 spec 必須宣告其證明採用哪個 model。

### Concrete Security
**中文**：具體安全性
**所屬層**：密碼學定義範式
**首次出現**：[3.1](lessons/part-3-cryptography/3.1-crypto-goals-taxonomy.md)（BDJR FOCS 1997）
**一句話**：把 asymptotic「negligible」改為 explicit `Adv ≤ q²/2^n` 形式；現代 RFC（如 RFC 8446 Appendix E）寫法的根基；G6 spec 必含 concrete bound。

### AES / Rijndael
**中文**：高級加密標準 / Rijndael 演算法
**所屬層**：對稱 block cipher
**首次出現**：[3.2 對稱加密](lessons/part-3-cryptography/3.2-symmetric-aead.md)
**一句話**：Daemen-Rijmen 1998 設計，1997-2000 NIST 競賽勝出，FIPS 197 (2001) 標準化；128-bit block，128/192/256-bit key；G6 在硬體加速場景用 AES-256-GCM。

### AES-NI / PCLMULQDQ
**中文**：AES 硬體指令集 / Carryless multiply
**所屬層**：CPU 指令集 / 硬體加速
**首次出現**：[3.2](lessons/part-3-cryptography/3.2-symmetric-aead.md)（Intel 2008 Westmere 起；ARMv8 對應 AES + PMULL）
**一句話**：把 AES round 與 GHASH GF(2^128) 乘法降到 1 cycle/op；單核 80 Gbps line-rate AES-GCM 的物理基礎；G6 hardware-fast path 必依賴。

### ChaCha20
**中文**：Bernstein 設計的 ARX stream cipher
**所屬層**：對稱加密
**首次出現**：[3.2](lessons/part-3-cryptography/3.2-symmetric-aead.md)（Bernstein 2008，Salsa20 改良）
**一句話**：256-bit key、20-round ARX 設計，無 S-box 天然 constant-time，軟體效能 ~1.5 c/b (SIMD)；RFC 8439 標準化；G6 預設 cipher。

### Poly1305
**中文**：Z_p (p=2^130-5) 多項式評估 MAC
**所屬層**：對稱 MAC
**首次出現**：[3.2](lessons/part-3-cryptography/3.2-symmetric-aead.md)（Bernstein FSE 2005）
**一句話**：Carter-Wegman ε-AXU MAC + one-time mask；ε ≤ 8L/2^106；常與 ChaCha20 配對成 RFC 8439 AEAD。

### AEAD modes (GCM / CCM / OCB / GCM-SIV)
**中文**：AEAD 模式族
**所屬層**：對稱加密 mode
**首次出現**：[3.2](lessons/part-3-cryptography/3.2-symmetric-aead.md)
**一句話**：GCM = CTR + GHASH（最普及）；CCM = CTR + CBC-MAC（IoT）；OCB3 = single-pass tweakable（最快但 IPR 歷史拖累）；GCM-SIV = misuse-resistant；G6 default ChaCha20-Poly1305 + AES-GCM HW fallback + GCM-SIV for 0-RTT。

### Forbidden Attack
**中文**：GCM nonce 重用 → recover GHASH H 攻擊
**所屬層**：對稱加密 cryptanalysis
**首次出現**：[3.2](lessons/part-3-cryptography/3.2-symmetric-aead.md)（Joux 2006 NIST comment）
**一句話**：同 (key, IV) 兩 message → 多項式系統 → recover H = AES_K(0) → 完全打破 INT-CTXT；TLS 1.3 nonce 構造規則的源頭；G6 用 deterministic counter 結構避免。

### Carter-Wegman / ε-AXU
**中文**：Universal hash + one-time pad → MAC 範式
**所屬層**：MAC 設計理論
**首次出現**：[3.2](lessons/part-3-cryptography/3.2-symmetric-aead.md)（Carter-Wegman JCSS 1979/1981）
**一句話**：universal hash family + 每 message 新 nonce derived key → provably secure MAC，可平行；Poly1305、GHASH、UMAC 都是此範式。

### ECB Penguin
**中文**：ECB 模式 deterministic 災難可視化
**所屬層**：對稱加密 mode 教訓
**首次出現**：[3.2](lessons/part-3-cryptography/3.2-symmetric-aead.md)
**一句話**：ECB 對相同 plaintext block 給相同 ciphertext block；用 Tux 圖加密後 outline 仍清晰可見；ECB 連 IND-CPA 都做不到，現代 spec 全禁。

### Cache-timing Attack
**中文**：cache 行為差異洩 secret
**所屬層**：side-channel
**首次出現**：[3.2](lessons/part-3-cryptography/3.2-symmetric-aead.md)（Bernstein 2005 cache-timing on AES T-table）
**一句話**：T-table-based AES 軟體實作 cache 行為依賴 plaintext，遠程觀察可 recover key；G6 禁用 T-table impl，必用 AES-NI 或 bitsliced。

### Multi-User Security
**中文**：多使用者安全模型
**所屬層**：密碼學安全模型
**首次出現**：[3.2](lessons/part-3-cryptography/3.2-symmetric-aead.md)（Bellare-Tackmann CRYPTO 2016）
**一句話**：μ users 各自有 key；對手對任一 user 的 advantage 算總；GCM bound 在 μ × q × ℓ ≤ 2^60 大致 secure；G6 spec 必含 multi-user analysis。

### Misuse-Resistant AE (MRAE) / SIV
**中文**：抗誤用認證加密 / Synthetic IV
**所屬層**：AEAD 設計範式
**首次出現**：[3.2](lessons/part-3-cryptography/3.2-symmetric-aead.md)（Rogaway-Shrimpton EUROCRYPT 2006）
**一句話**：nonce 重用只洩 message equality，不洩 key；GCM-SIV (RFC 8452) 是 deployment；G6 0-RTT data 用此防護。

### Merkle-Damgård Construction
**中文**：Merkle-Damgård 雜湊結構
**所屬層**：hash function 設計範式
**首次出現**：[3.3 雜湊函數](lessons/part-3-cryptography/3.3-hash-functions-kdf.md)（Merkle 1979 / Damgård 1989）
**一句話**：把任意長 input 切 block 用 fixed-size compression function 迭代；SHA-2 family 用此；致命 length-extension vulnerability。

### Length-Extension Attack
**中文**：長度延伸攻擊
**所屬層**：hash function 缺陷
**首次出現**：[3.3](lessons/part-3-cryptography/3.3-hash-functions-kdf.md)
**一句話**：給 H(M)，無需知 M 即可算 H(M ‖ pad ‖ X)；Flickr 2009 真實災難；HMAC 為主修補。

### Sponge Construction / Keccak / SHA-3
**中文**：海綿構造 / Keccak 演算法 / SHA-3 標準
**所屬層**：hash function 範式
**首次出現**：[3.3](lessons/part-3-cryptography/3.3-hash-functions-kdf.md)（Bertoni-Daemen-Peeters-Van Assche 2011；FIPS 202 2015）
**一句話**：state = rate + capacity，capacity 永不外露 → 天然無 length-extension；SHA-3 / SHAKE / Ascon 都是 sponge。

### HMAC
**中文**：Hash-based Message Authentication Code
**所屬層**：MAC 構造
**首次出現**：[3.3](lessons/part-3-cryptography/3.3-hash-functions-kdf.md)（Bellare-Canetti-Krawczyk CRYPTO 1996, RFC 2104）
**一句話**：`HMAC = H(K' ⊕ opad ‖ H(K' ⊕ ipad ‖ m))`；防 length-extension 的 nested 結構；G6 KDF 與 transcript bind 全用 HMAC-SHA-256。

### HKDF (Extract-then-Expand)
**中文**：兩段式金鑰派生
**所屬層**：KDF 設計
**首次出現**：[3.3](lessons/part-3-cryptography/3.3-hash-functions-kdf.md)（Krawczyk CRYPTO 2010, RFC 5869）
**一句話**：Extract 把 high-entropy biased input → uniform PRK；Expand 把 PRK + info → arbitrary-length keystream；TLS 1.3 / Noise / Signal / WireGuard 共同 KDF。

### BLAKE2 / BLAKE3
**中文**：ARX-based 現代雜湊家族
**所屬層**：hash function
**首次出現**：[3.3](lessons/part-3-cryptography/3.3-hash-functions-kdf.md)
**一句話**：BLAKE2 (Aumasson 2013, RFC 7693) ~3 c/b、WireGuard 用；BLAKE3 (2020) 加 Merkle tree + SIMD 達 ~0.5 c/b；G6 hash agility 候選。

### Argon2 (i / d / id)
**中文**：Memory-hard 密碼雜湊
**所屬層**：password hashing
**首次出現**：[3.3](lessons/part-3-cryptography/3.3-hash-functions-kdf.md)（Biryukov-Dinu-Khovratovich EuroS&P 2016）
**一句話**：PHC 2015 winner；OWASP/NIST 推薦 Argon2id；G6 PSK-from-passphrase 模式必用。

### scrypt
**中文**：第一代 sequential memory-hard KDF
**所屬層**：password hashing / KDF
**首次出現**：[3.3](lessons/part-3-cryptography/3.3-hash-functions-kdf.md)（Percival BSDCan 2009, RFC 7914）
**一句話**：用大記憶體 sequential operation 對抗 GPU/ASIC 暴力；後被 Argon2 超越。

### Memory-Hard Function (MHF)
**中文**：記憶體硬函數
**所屬層**：密碼設計範式
**首次出現**：[3.3](lessons/part-3-cryptography/3.3-hash-functions-kdf.md)
**一句話**：computing function 需大量 memory，attacker 用 GPU/ASIC 平行優勢失效；TA-product 是衡量指標。

### SHAttered
**中文**：第一個實際 SHA-1 collision
**所屬層**：hash cryptanalysis
**首次出現**：[3.3](lessons/part-3-cryptography/3.3-hash-functions-kdf.md)（Stevens 等 CRYPTO 2017）
**一句話**：~$110k cloud cost 算出兩 PDF 同 SHA-1；2017 後 SHA-1 完全棄用；G6 強制 SHA-256+。

### Random Oracle (Indifferentiability)
**中文**：隨機 oracle 不可區分性
**所屬層**：hash function security model
**首次出現**：[3.3](lessons/part-3-cryptography/3.3-hash-functions-kdf.md)（Maurer-Renner-Holenstein TCC 2004）
**一句話**：sponge 構造在 PRP 假設下與 RO indifferentiable；MD construction 不是；指導 G6 hash 選擇。

### RSA Problem / FACT
**中文**：RSA 問題 / 整數分解問題
**所屬層**：computational hardness assumption
**首次出現**：[3.4 公鑰密碼學一：RSA](lessons/part-3-cryptography/3.4-rsa.md)（Rivest-Shamir-Adleman CACM 1978）
**一句話**：給 (N, e, c)，計算 m = c^d；安全性 anchor 在 N 的 factorization；Shor 1994 量子可解。

### RSA-OAEP / RSA-PSS
**中文**：RSA 加密 / 簽章的安全 padding
**所屬層**：公鑰密碼 padding scheme
**首次出現**：[3.4](lessons/part-3-cryptography/3.4-rsa.md)（Bellare-Rogaway EUROCRYPT 1994 / 1996, PKCS#1 v2）
**一句話**：OAEP 給 IND-CCA2 RSA encryption；PSS 給 EUF-CMA RSA signature with tight reduction；PKCS#1 v1.5 完全棄用。

### Bleichenbacher Padding Oracle
**中文**：Bleichenbacher padding oracle 攻擊
**所屬層**：protocol-level attack
**首次出現**：[3.4](lessons/part-3-cryptography/3.4-rsa.md)（Bleichenbacher CRYPTO 1998）
**一句話**：PKCS#1 v1.5 padding 錯誤回應作 oracle，~10^6 queries 解 plaintext；ROBOT 2018 證明 20 年後仍在 wild；G6 從不依賴任何 server-side validation 差異化回應。

### Coppersmith's Method
**中文**：Coppersmith 多項式小根尋找法
**所屬層**：lattice-based cryptanalysis
**首次出現**：[3.4](lessons/part-3-cryptography/3.4-rsa.md)（Coppersmith EUROCRYPT 1996）
**一句話**：給 polynomial mod n of degree d，找 |x| < n^(1/d) 的所有 root；對 RSA small e / partial-known plaintext 攻擊的基礎。

### Wiener Attack / Boneh-Durfee
**中文**：RSA 小私鑰攻擊
**所屬層**：RSA cryptanalysis
**首次出現**：[3.4](lessons/part-3-cryptography/3.4-rsa.md)
**一句話**：Wiener 1990 d < n^(1/4)；Boneh-Durfee 1999 d < n^0.292；現代 RSA 強制 random d, 此攻擊不適用但 spec validator 要 check。

### RSA Blinding
**中文**：RSA 盲化
**所屬層**：side-channel defense
**首次出現**：[3.4](lessons/part-3-cryptography/3.4-rsa.md)（Kocher 1996）
**一句話**：解密前 multiply by random r^e，解密後 multiply by r^-1；防 timing / power side-channel；現代 RSA 實作 mandatory。

### ECDLP (Elliptic Curve Discrete Logarithm Problem)
**中文**：橢圓曲線離散對數問題
**所屬層**：computational hardness
**首次出現**：[3.5 ECC](lessons/part-3-cryptography/3.5-elliptic-curves.md)（Miller 1985 / Koblitz 1987）
**一句話**：給 P, Q=nP，找 n；best classical attack Pollard's rho O(√n)；256-bit curve → 128-bit security；Shor 量子可解。

### Curve25519 / X25519
**中文**：Bernstein 設計的 ECC 曲線 / 對應 ECDH
**所屬層**：橢圓曲線
**首次出現**：[3.5](lessons/part-3-cryptography/3.5-elliptic-curves.md)（Bernstein PKC 2006；RFC 7748）
**一句話**：prime 2^255-19 + Montgomery form；128-bit security；32-byte pk；clamping + Montgomery ladder 給 constant-time；G6 key exchange 必選。

### Ed25519 / EdDSA
**中文**：Edwards-curve digital signature
**所屬層**：數位簽章
**首次出現**：[3.5](lessons/part-3-cryptography/3.5-elliptic-curves.md)（Bernstein 等 CHES 2011；RFC 8032）
**一句話**：Schnorr-style + deterministic nonce + sUF-CMA + 64-byte sig + ~50k cycle sign；徹底取代 ECDSA 於 modern protocol；G6 簽章用此。

### Edwards Curve / Twisted Edwards
**中文**：Edwards 形式橢圓曲線
**所屬層**：橢圓曲線 representation
**首次出現**：[3.5](lessons/part-3-cryptography/3.5-elliptic-curves.md)（Edwards 2007 / Bernstein-Lange 2007 generalized）
**一句話**：a x² + y² = 1 + d x² y²；unified complete addition formula → constant-time impl 容易；edwards25519 / curve448 採用。

### Montgomery Ladder
**中文**：Montgomery 階梯
**所屬層**：scalar multiplication algorithm
**首次出現**：[3.5](lessons/part-3-cryptography/3.5-elliptic-curves.md)
**一句話**：每 iteration 一個 add + 一個 double；operation count 固定不依賴 scalar bits；X25519 標準 algorithm。

### Clamping
**中文**：scalar 截位
**所屬層**：X25519 設計 trick
**首次出現**：[3.5](lessons/part-3-cryptography/3.5-elliptic-curves.md)
**一句話**：清低 3 bit (eliminate cofactor) + 設 bit 254 (fixed ladder length) + 清高 bit (in scalar field)；單一操作防三類攻擊。

### Cofactor / Ristretto255
**中文**：cofactor / Ristretto255 商群
**所屬層**：橢圓曲線 group structure
**首次出現**：[3.5](lessons/part-3-cryptography/3.5-elliptic-curves.md)（Hamburg CRYPTO 2015 Decaf；Ristretto255 IETF draft）
**一句話**：cofactor 8 在 Edwards25519 帶來 protocol 陷阱；Ristretto255 商 quotient out 形成 prime-order group；G6 advanced protocol 用此。

### SafeCurves
**中文**：橢圓曲線安全評估標準
**所屬層**：ECC curve selection
**首次出現**：[3.5](lessons/part-3-cryptography/3.5-elliptic-curves.md)（Bernstein-Lange 2014+）
**一句話**：九項 curve safety criteria；Curve25519 全綠，NIST P-curves 多項紅；G6 選 curve 必須 SafeCurves 全綠。

### Elligator
**中文**：曲線點 ↔ 隨機 byte 雙射
**所屬層**：ECC point encoding
**首次出現**：[3.5](lessons/part-3-cryptography/3.5-elliptic-curves.md)（Bernstein-Hamburg-Krasnova-Lange 2013）
**一句話**：把 curve point map 成 indistinguishable-from-random 32 byte；G6 cover-traffic 用於把 ephemeral pk 偽裝為 random padding。

### Signature Malleability
**中文**：簽章可變形性
**所屬層**：signature security
**首次出現**：[3.5](lessons/part-3-cryptography/3.5-elliptic-curves.md)
**一句話**：給 valid (M, σ) 找 σ' ≠ σ 也 valid；ECDSA (r, s) ↔ (r, -s) 有此問題；Ed25519 deterministic 設計免疫；Bitcoin BIP-66 enforce low-s 修補。

### Schnorr Signature
**中文**：Schnorr 簽章
**所屬層**：signature scheme family
**首次出現**：[3.5](lessons/part-3-cryptography/3.5-elliptic-curves.md)（Schnorr 1989）
**一句話**：R = rG; c = H(R, A, M); s = r + c·sk; 短 + tight EUF-CMA reduction；Ed25519 是 deterministic Schnorr。

### MQV / HMQV
**中文**：implicit-authentication DH protocol family
**所屬層**：AKE
**首次出現**：[3.6 金鑰交換協議](lessons/part-3-cryptography/3.6-key-exchange.md)（MQV 1995；HMQV CRYPTO 2005）
**一句話**：結合 long-term + ephemeral key 直接 compute shared secret 達 implicit auth；HMQV 給 CK model formal proof；G6 不選（偏 SIGMA-I 結構）。

### X3DH (Extended Triple DH)
**中文**：擴展三重 DH
**所屬層**：asynchronous AKE
**首次出現**：[3.6](lessons/part-3-cryptography/3.6-key-exchange.md)（Marlinspike-Perrin 2016, Signal whitepaper）
**一句話**：4-DH combine (IK + SPK + EK + OPK) → asynchronous auth + FS + PCS seed；Signal/WhatsApp 部署；G6 借鑑 multi-DH combine 思想。

### Noise Protocol Framework
**中文**：Noise 協議框架
**所屬層**：AKE design framework
**首次出現**：[3.6](lessons/part-3-cryptography/3.6-key-exchange.md)（Perrin 2016, rev 34 2018）
**一句話**：用 (e, s, ee, es, se, ss, psk) DSL 描述握手 pattern；WireGuard (Noise IK)、Lightning Network 等採用；G6 採用 Noise IK 變體。

### Static / Ephemeral Key Combination
**中文**：靜態 / 短暫金鑰組合
**所屬層**：AKE 設計
**首次出現**：[3.6](lessons/part-3-cryptography/3.6-key-exchange.md)
**一句話**：static-static DH 認證 identity；ephemeral-ephemeral DH 給 FS；混合給 mutual auth + FS + KCI；G6 hybrid。

### Logjam / Downgrade Attack
**中文**：Logjam 降級攻擊
**所屬層**：protocol-level attack
**首次出現**：[3.6](lessons/part-3-cryptography/3.6-key-exchange.md)（Adrian 等 CCS 2015）
**一句話**：MitM 降級 TLS 到 512-bit DHE_EXPORT，用 pre-computed NFS table 即時解 DH；G6 設計教訓——hard-code cipher, no negotiation。

### Selfie Attack
**中文**：自我攻擊
**所屬層**：multi-device AKE 缺陷
**首次出現**：[3.6](lessons/part-3-cryptography/3.6-key-exchange.md)（Cremers 等 2019 on Signal X3DH）
**一句話**：multi-device 同 user 場景下，attacker 讓 device 跟自己對話；修補：identifier binding into transcript / KDF info。

### Forking Lemma
**中文**：分叉引理
**所屬層**：signature security proof
**首次出現**：[3.6](lessons/part-3-cryptography/3.6-key-exchange.md)（Pointcheval-Stern 1996）
**一句話**：對 Schnorr-style signature 的 ROM-based EUF-CMA reduction 核心 technique；通過 rewinding adversary 兩次提取 sk；Ed25519 / ECDSA / BLS 證明均用此。

### BLS Signature
**中文**：Boneh-Lynn-Shacham 配對簽章
**所屬層**：pairing-based signature
**首次出現**：[3.7 數位簽章](lessons/part-3-cryptography/3.7-digital-signatures.md)（Boneh-Lynn-Shacham ASIACRYPT 2001）
**一句話**：σ = sk · HashToCurve(M)；verify 用 bilinear pairing；signature 短 + 天然 aggregation；Ethereum 2.0、Filecoin 部署；G6 不直接用但 future group mode 候選。

### Fiat-Shamir Heuristic
**中文**：Fiat-Shamir 轉換
**所屬層**：signature design technique
**首次出現**：[3.7](lessons/part-3-cryptography/3.7-digital-signatures.md)（Fiat-Shamir CRYPTO 1986）
**一句話**：把 interactive identification protocol 透過 hash challenge 變 non-interactive signature；Schnorr / Ed25519 / Dilithium 全用此。

### MuSig / MuSig2 / FROST
**中文**：多方 Schnorr 簽章方案
**所屬層**：multi-party signature
**首次出現**：[3.7](lessons/part-3-cryptography/3.7-digital-signatures.md)
**一句話**：MuSig (Maxwell 等 2018) n-of-n key aggregation；MuSig2 (Nick 等 2020) 兩輪；FROST (Komlo-Goldberg 2020) t-of-n threshold。

### ECDSA Malleability / Low-S Normalization
**中文**：ECDSA 簽章可變形性 / 低 s 規範化
**所屬層**：ECDSA implementation defense
**首次出現**：[3.7](lessons/part-3-cryptography/3.7-digital-signatures.md)
**一句話**：(r, s) ↔ (r, -s mod n) 都 valid → malleability；Bitcoin BIP-66 enforce s ≤ n/2；G6 verify ECDSA 必加此 check。

### Certificate Transparency (CT)
**中文**：證書透明度
**所屬層**：PKI accountability
**首次出現**：[3.7](lessons/part-3-cryptography/3.7-digital-signatures.md)（Laurie RFC 6962 2013 / RFC 9162 2021）
**一句話**：公開 append-only Merkle log 記錄所有 issued cert；CA 無法秘密發 cert；Chrome 2018+ 強制 SCT；G6 可借鑑做 update log。

### Threshold Signature / DKG
**中文**：門檻簽章 / 分散式金鑰生成
**所屬層**：multi-party crypto
**首次出現**：[3.7](lessons/part-3-cryptography/3.7-digital-signatures.md)
**一句話**：t-of-n parties 才能簽；DKG (Pedersen 1991) 分散生成 key；BLS / Schnorr 變體；G6 future server key management 候選。

### Noise Pattern DSL (NN/NK/NX/IK/XK/XX...)
**中文**：Noise pattern 描述語言
**所屬層**：AKE protocol DSL
**首次出現**：[3.8 Noise](lessons/part-3-cryptography/3.8-noise-protocol-framework.md)（Perrin 2018 rev 34）
**一句話**：用 e/s/ee/es/se/ss/psk tokens 機械描述 handshake；12 個 fundamental patterns 涵蓋多數 AKE 場景。

### Noise IK Pattern
**中文**：Noise initiator-known pattern
**所屬層**：Noise AKE
**首次出現**：[3.8](lessons/part-3-cryptography/3.8-noise-protocol-framework.md)
**一句話**：1-RTT, responder static pre-known, mutual auth, initiator identity encrypted；WireGuard 採用；G6 base pattern。

### WireGuard MAC1 / MAC2 / Cookie Reply
**中文**：WireGuard anti-DoS 機制
**所屬層**：handshake DoS defense
**首次出現**：[3.8](lessons/part-3-cryptography/3.8-noise-protocol-framework.md)（Donenfeld NDSS 2017）
**一句話**：MAC1 確認 client 知 server static pk；Cookie Reply 確認 client 是 routable IP；G6 借用此機制 + cover-traffic disguise。

### Cryptokey Routing
**中文**：金鑰路由
**所屬層**：VPN routing model
**首次出現**：[3.8](lessons/part-3-cryptography/3.8-noise-protocol-framework.md)
**一句話**：peer 由 static pk 識別而非 IP；允許 roaming + 自動 endpoint update；WireGuard 標誌設計；G6 採用。

### HandshakeState / SymmetricState / CipherState
**中文**：Noise framework 三層 state machine
**所屬層**：Noise 內部 abstraction
**首次出現**：[3.8](lessons/part-3-cryptography/3.8-noise-protocol-framework.md)
**一句話**：HandshakeState 管 ephemeral/static keys；SymmetricState 管 ck + h；CipherState 管 (k, n) AEAD state；G6 直接繼承。

### PSK in Noise
**中文**：Noise PSK 混入機制
**所屬層**：post-quantum hybrid
**首次出現**：[3.8](lessons/part-3-cryptography/3.8-noise-protocol-framework.md)
**一句話**：MixKeyAndHash(psk) 把 PSK 混入 chaining key；out-of-band 安全分發 PSK → 即使 ECDH 被 Shor 破仍保密；G6 PQ 過渡用。

### PAKE (Password-Authenticated Key Exchange)
**中文**：密碼認證金鑰交換
**所屬層**：AKE family
**首次出現**：[3.9 PAKE](lessons/part-3-cryptography/3.9-pake.md)（Bellovin-Merritt EKE IEEE S&P 1992）
**一句話**：使用者只有 password (~40-bit entropy) 仍能 secure KE；passive observer 不能 offline dictionary attack；G6 PSK-from-passphrase mode 用。

### Balanced vs Augmented PAKE
**中文**：對等 / 增強 PAKE
**所屬層**：PAKE 分類
**首次出現**：[3.9](lessons/part-3-cryptography/3.9-pake.md)
**一句話**：balanced 雙方對等知 password (SPAKE2, EKE, CPace)；augmented server 只存 verifier (SRP, OPAQUE)；G6 用 augmented OPAQUE。

### SPAKE2
**中文**：Simple Password-based Encrypted Key Exchange
**所屬層**：Balanced PAKE
**首次出現**：[3.9](lessons/part-3-cryptography/3.9-pake.md)（Abdalla-Pointcheval CT-RSA 2005, RFC 9382 2023）
**一句話**：用 magic constants M, N + password-derived scalar w 構造 balanced PAKE；簡單、無 patent；G6 antiDoS pre-handshake 候選。

### OPAQUE
**中文**：增強型 PAKE with pre-computation resistance
**所屬層**：Augmented PAKE
**首次出現**：[3.9](lessons/part-3-cryptography/3.9-pake.md)（Jarecki-Krawczyk-Xu EUROCRYPT 2018, RFC 9807 2025）
**一句話**：OPRF + envelope + AKE 三段；server compromise 後仍須 online OPRF query 才能 brute-force；WhatsApp / 1Password 部署；G6 passphrase 模式必用。

### OPRF (Oblivious PRF)
**中文**：不可知 PRF
**所屬層**：cryptographic primitive
**首次出現**：[3.9](lessons/part-3-cryptography/3.9-pake.md)
**一句話**：client 給 x server 回 F_k(x) but server 不學 x, client 不學 k；OPAQUE 核心；Privacy Pass / blind signature 也用。

### Pre-computation Attack
**中文**：預計算攻擊
**所屬層**：PAKE / password storage attack
**首次出現**：[3.9](lessons/part-3-cryptography/3.9-pake.md)
**一句話**：攻陷 server 偷 verifier 後在自己 hardware 離線 brute-force；OPAQUE 從根本防範。

### Zero-Knowledge Proof (ZK)
**中文**：零知識證明
**所屬層**：cryptographic primitive
**首次出現**：[3.10 ZK](lessons/part-3-cryptography/3.10-zero-knowledge.md)（Goldwasser-Micali-Rackoff STOC 1985 / SICOMP 1989）
**一句話**：P 可證 statement 為真且 V 學不到 witness 任何 information；Ed25519 是 NIZK Schnorr 的 special case；Zcash / StarkNet 等部署。

### Sigma Protocol
**中文**：Σ-協議（3-move 互動證明）
**所屬層**：ZK protocol family
**首次出現**：[3.10](lessons/part-3-cryptography/3.10-zero-knowledge.md)
**一句話**：(commit, challenge, response) three-move structure；HVZK + special soundness；Fiat-Shamir 可變 NIZK；Schnorr identification 是經典範例。

### zk-SNARK / zk-STARK
**中文**：簡潔 / 透明 ZK argument
**所屬層**：modern ZK system
**首次出現**：[3.10](lessons/part-3-cryptography/3.10-zero-knowledge.md)（Groth16 EUROCRYPT 2016 / Ben-Sasson 等 2018）
**一句話**：SNARK proof ~200 byte but trusted setup + pairing；STARK ~100 KB but transparent + PQ-safe；G6 future anonymous auth 候選。

### Trusted Setup / CRS
**中文**：可信設置 / 公開參考字串
**所屬層**：ZK preprocessing
**首次出現**：[3.10](lessons/part-3-cryptography/3.10-zero-knowledge.md)
**一句話**：Groth16 SNARK 需要 setup ceremony 生成 CRS，toxic waste 必須銷毀；Zcash 用 multi-party ceremony 確保 only need ONE honest participant。

### Bulletproofs
**中文**：bulletproofs ZK 證明
**所屬層**：ZK protocol
**首次出現**：[3.10](lessons/part-3-cryptography/3.10-zero-knowledge.md)（Bünz 等 IEEE S&P 2018）
**一句話**：無 trusted setup, short proofs (~700 byte for range)；Monero 部署；G6 confidential subscription 候選。

### Shor's Algorithm
**中文**：Shor 量子分解 / 離散對數演算法
**所屬層**：quantum cryptanalysis
**首次出現**：[3.11 後量子](lessons/part-3-cryptography/3.11-post-quantum.md)（Shor 1994 / SIAM J. Comp. 1997）
**一句話**：量子電腦 polynomial time 解 FACT / DLP / ECDLP；殺死 RSA / DH / ECC；觸發 NIST PQ 競賽；G6 必 PQ hybrid。

### Grover's Algorithm
**中文**：Grover 量子搜索
**所屬層**：quantum cryptanalysis
**首次出現**：[3.11](lessons/part-3-cryptography/3.11-post-quantum.md)（Grover STOC 1996）
**一句話**：對稱 key search quadratic speedup O(2^n) → O(2^(n/2))；AES-256 quantum 仍 128-bit safe；AES-128 quantum 64-bit (不夠)。

### ML-KEM (Kyber)
**中文**：Module-Lattice-based KEM
**所屬層**：post-quantum KEM
**首次出現**：[3.11](lessons/part-3-cryptography/3.11-post-quantum.md)（FIPS 203 2024，原 CRYSTALS-Kyber）
**一句話**：基於 Module-LWE problem；ML-KEM-768 = 1184-byte pk + 1088-byte ct + 110k cycles encap；G6 hybrid with X25519。

### ML-DSA (Dilithium)
**中文**：Module-Lattice-based signature
**所屬層**：post-quantum signature
**首次出現**：[3.11](lessons/part-3-cryptography/3.11-post-quantum.md)（FIPS 204 2024，原 CRYSTALS-Dilithium）
**一句話**：lattice Fiat-Shamir with aborts；ML-DSA-65 = 1952-byte pk + 3293-byte sig + 700k cycles sign；G6 hybrid with Ed25519。

### SLH-DSA (SPHINCS+)
**中文**：Stateless Hash-based digital signature
**所屬層**：post-quantum signature
**首次出現**：[3.11](lessons/part-3-cryptography/3.11-post-quantum.md)（FIPS 205 2024，原 SPHINCS+）
**一句話**：純 hash-based, multi-tree Merkle 結構; ~17 KB sig but 最 conservative 對未來 cryptanalysis；G6 root signing backup。

### FN-DSA (Falcon)
**中文**：NTRU-lattice signature
**所屬層**：post-quantum signature
**首次出現**：[3.11](lessons/part-3-cryptography/3.11-post-quantum.md)
**一句話**：~666-byte sig but floating-point impl 引入 side-channel risk；G6 不選 v1 default，future evaluate。

### Hybrid PQ Mode
**中文**：混合後量子模式
**所屬層**：PQ deployment strategy
**首次出現**：[3.11](lessons/part-3-cryptography/3.11-post-quantum.md)
**一句話**：classical + PQ concatenated; 任一 break 不致命；過渡期 standard practice。

### Harvest Now Decrypt Later
**中文**：先存後解
**所屬層**：long-term threat model
**首次出現**：[3.11](lessons/part-3-cryptography/3.11-post-quantum.md)
**一句話**：對手錄存今天加密流量，等未來量子電腦解開；對長壽 information critical；G6 hybrid 立即部署的核心動機。

### SIKE Disaster
**中文**：SIKE 災難（Castryck-Decru 2022）
**所屬層**：PQ cryptanalysis
**首次出現**：[3.11](lessons/part-3-cryptography/3.11-post-quantum.md)
**一句話**：~25 年 isogeny-based research SIKE 被 1 小時 laptop 破；教訓 G6 只用 NIST-standardized PQ。

### CSPRNG (Cryptographically Secure PRNG)
**中文**：密碼學安全的偽隨機數生成器
**所屬層**：cryptographic primitive
**首次出現**：[3.12 隨機性](lessons/part-3-cryptography/3.12-randomness.md)
**一句話**：output 與 uniform distribution computationally indistinguishable；現代 Linux 用 ChaCha20-based；G6 必用 OS getrandom()。

### getrandom() syscall
**中文**：Linux/POSIX 安全隨機 syscall
**所屬層**：OS interface
**首次出現**：[3.12](lessons/part-3-cryptography/3.12-randomness.md)（Linux 3.17 2014）
**一句話**：block until entropy pool seeded then non-blocking secure random output；G6 mandatory entropy source。

### Dual_EC_DRBG
**中文**：NSA backdoored RNG 標準
**所屬層**：cryptographic standard scandal
**首次出現**：[3.12](lessons/part-3-cryptography/3.12-randomness.md)（NIST SP 800-90A 2007, 撤回 2014）
**一句話**：基於 ECC 的 DRBG with hard-coded constants P, Q；若 Q = c·P with known c, holder 可預測輸出；Snowden 2013 證實 NSA backdoor。

### Nothing-Up-My-Sleeve Constants
**中文**：無暗藏動機之常數
**所屬層**：cryptographic design principle
**首次出現**：[3.12](lessons/part-3-cryptography/3.12-randomness.md)
**一句話**：spec 中常數必須來自 public verifiable process (SHA of well-known string)；Curve25519 / SHA-3 都符合；NIST P-curves seeds 仍 controversial。

### Debian OpenSSL 2008 (Bug #363516)
**中文**：Debian OpenSSL 弱 RNG 災難
**所屬層**：RNG failure incident
**首次出現**：[3.12](lessons/part-3-cryptography/3.12-randomness.md)
**一句話**：Debian 修補 Valgrind warning 意外移除 OpenSSL entropy mixing；2006-2008 generated keys entropy 只 PID (~32k possible)；需 mass key rotation。

### Heninger Ps-and-Qs / Lenstra Public Keys
**中文**：嵌入式 device 弱 key 大規模調查
**所屬層**：empirical security study
**首次出現**：[3.12](lessons/part-3-cryptography/3.12-randomness.md)（USENIX Security 2012 / CRYPTO 2012）
**一句話**：~5% TLS hosts share keys / ~0.5% share RSA primes → GCD factor；root cause boot-time entropy deficit；G6 IoT 部署設計關鍵教訓。

### Min-entropy / Leftover Hash Lemma
**中文**：min-entropy / 剩餘哈希引理
**所屬層**：cryptographic information theory
**首次出現**：[3.12](lessons/part-3-cryptography/3.12-randomness.md)（Impagliazzo-Levin-Luby STOC 1989）
**一句話**：universal hash 應用於 min-entropy source 可 extract uniform output；HKDF Extract step 的理論根據。

### Side-Channel Attack (SCA)
**中文**：側信道攻擊
**所屬層**：implementation-level cryptanalysis
**首次出現**：[3.13 側信道](lessons/part-3-cryptography/3.13-side-channels.md)（Kocher CRYPTO 1996）
**一句話**：通過 timing / cache / power / EM 等 observable 推 secret；G6 implementation 必 constant-time。

### Constant-Time Programming
**中文**：恆時程式設計
**所屬層**：cryptographic implementation discipline
**首次出現**：[3.13](lessons/part-3-cryptography/3.13-side-channels.md)
**一句話**：no secret-dependent branch / memory access / division；用 mask + bitwise ops 替代；G6 必驗證 via ctgrind/dudect。

### Lucky Thirteen
**中文**：Lucky 13 timing 攻擊
**所屬層**：TLS protocol attack
**首次出現**：[3.13](lessons/part-3-cryptography/3.13-side-channels.md)（AlFardan-Paterson IEEE S&P 2013）
**一句話**：TLS-CBC + HMAC server 處理 padding vs MAC error 時間差 ~13 cycles → padding oracle；驅動 TLS 1.3 AEAD-only。

### Spectre / Meltdown
**中文**：推測執行 microarchitectural 攻擊
**所屬層**：CPU-level side-channel
**首次出現**：[3.13](lessons/part-3-cryptography/3.13-side-channels.md)（Kocher / Lipp 2018-2019）
**一句話**：跨 security boundary 透過 speculative execution + cache side-channel 讀任意 memory；甚至 constant-time impl 不夠；G6 必加 lfence + speculative load hardening。

### Hertzbleed
**中文**：CPU 頻率時序洩漏
**所屬層**：microarch side-channel
**首次出現**：[3.13](lessons/part-3-cryptography/3.13-side-channels.md)（Wang 等 USENIX Security 2022）
**一句話**：CPU 動態頻率管理依賴計算內容 → remote timing leak 即使 constant-time impl；G6 推薦 disable Turbo Boost in production。

### Flush+Reload / Prime+Probe
**中文**：快取側信道技術
**所屬層**：cache attack 範式
**首次出現**：[3.13](lessons/part-3-cryptography/3.13-side-channels.md)（Yarom-Falkner USENIX Security 2014）
**一句話**：flush 特定 cache line, 等 victim 操作, reload + 測時間判 victim 是否 access 該 line；Spectre / Meltdown 利用此 building block。

### NaCl Philosophy
**中文**：NaCl 設計哲學
**所屬層**：cryptographic library API design
**首次出現**：[3.14 密碼工程](lessons/part-3-cryptography/3.14-crypto-engineering.md)（Bernstein 等 NaCl 2009 / LATINCRYPT 2012）
**一句話**：Operations not algorithms / Hard to misuse / Constant-time inside / Hyperoptimized；libsodium / ring / monocypher 全繼承。

### Cryptographic Right Answers
**中文**：密碼學正確答案
**所屬層**：modern crypto engineering survey
**首次出現**：[3.14](lessons/part-3-cryptography/3.14-crypto-engineering.md)（Latacora blog 2018）
**一句話**：每 use case 給「單一正確選擇」（ChaCha20-Poly1305, HKDF-SHA-256, Argon2id, Ed25519, X25519...）；G6 全採。

### libsodium / ring / BoringSSL
**中文**：modern crypto library 三大主流
**所屬層**：cryptographic library
**首次出現**：[3.14](lessons/part-3-cryptography/3.14-crypto-engineering.md)
**一句話**：libsodium (C, NaCl-compat) / ring (Rust, BoringSSL-derived) / BoringSSL (Google internal); G6 用 ring。

### HACL* / EverCrypt
**中文**：形式化驗證的密碼庫
**所屬層**：verified crypto
**首次出現**：[3.14](lessons/part-3-cryptography/3.14-crypto-engineering.md)（Zinzindohoué 等 CCS 2017 / Bhargavan 等 IEEE S&P 2020）
**一句話**：F* 語言 + Vale assembly 驗證 ChaCha20-Poly1305 / Curve25519 / Ed25519 等；性能 within 10-30% of hand-tuned；G6 future evaluate。

### "Don't roll your own crypto"
**中文**：別自製密碼學
**所屬層**：crypto engineering principle
**首次出現**：[3.14](lessons/part-3-cryptography/3.14-crypto-engineering.md)
**一句話**：別實作 primitive (AES, SHA, ECC) 也別設計新 primitive；但 protocol composition 可設計 — G6 嚴格遵守此邊界。

### Algorithm Agility / Crypto Agility
**中文**：密碼學敏捷性
**所屬層**：protocol design
**首次出現**：[3.14](lessons/part-3-cryptography/3.14-crypto-engineering.md)
**一句話**：太多 agility 引發 Logjam downgrade；太少難 PQ migrate；G6 採 version-based agility (no per-handshake negotiation)。

### ProVerif
**中文**：基於 applied pi-calculus 的 protocol verifier
**所屬層**：formal verification tool
**首次出現**：[3.15 形式化驗證](lessons/part-3-cryptography/3.15-formal-verification.md)（Blanchet CSFW 2001）
**一句話**：把 protocol 翻譯為 Horn clauses + SLD resolution 自動證 secrecy / auth；TLS 1.3 / Noise / MLS / WireGuard 等 IETF spec verify 主工具；G6 Phase III 11.10 必用。

### Tamarin
**中文**：基於 multiset rewriting 的 protocol verifier
**所屬層**：formal verification tool
**首次出現**：[3.15](lessons/part-3-cryptography/3.15-formal-verification.md)（Meier-Schmidt-Cremers-Basin CAV 2013）
**一句話**：表達力強處理 stateful protocols (Signal ratchet, 5G AKA)；G6 ratchet / multi-device 部分用 Tamarin。

### CryptoVerif
**中文**：computational sound 的 protocol verifier
**所屬層**：formal verification tool
**首次出現**：[3.15](lessons/part-3-cryptography/3.15-formal-verification.md)（Blanchet IEEE S&P 2008）
**一句話**：在 computational model 透過 game transformation chain 證明；WireGuard handshake formal proof 用此；G6 handshake computational proof 用。

### F* / miTLS / EverCrypt
**中文**：implementation-level verification
**所屬層**：verified implementation
**首次出現**：[3.15](lessons/part-3-cryptography/3.15-formal-verification.md)
**一句話**：F\* 語言寫 cryptographic implementations + mechanised proof of functional correctness + side-channel resistance；Project Everest 整合。

### Lowe's Needham-Schroeder Bug
**中文**：Lowe 1995 對 NS protocol 的攻擊
**所屬層**：protocol verification milestone
**首次出現**：[3.15](lessons/part-3-cryptography/3.15-formal-verification.md)（Lowe IPL 1995）
**一句話**：1978 設計的 Needham-Schroeder 17 年後被 FDR model checker 找到 MitM bug；現代 protocol design 必 formal verify 教訓的源頭。

### Noise Explorer
**中文**：Noise pattern 自動驗證工具
**所屬層**：automated formal verification
**首次出現**：[3.15](lessons/part-3-cryptography/3.15-formal-verification.md)（Kobeissi-Bhargavan-Beurdouche EuroS&P 2019）
**一句話**：對所有 Noise patterns 自動 generate ProVerif models + verify 18 properties；G6 借用作 baseline。

### Hyperproperty
**中文**：超屬性（針對「軌跡集合」而非單一軌跡的 property）
**所屬層**：formal methods foundation
**首次出現**：[5.9](lessons/part-5-formal-methods/5.9-hyperproperties-observational-equivalence.md)（Clarkson-Schneider CSF 2008 / JCS 2010）
**一句話**：trace property 講「每條 trace 都對」，hyperproperty 講「整個 trace set 之間的關係」；privacy / non-interference / unlinkability 全都是 hyperproperty，secrecy 才是 trace property。

### Observational Equivalence
**中文**：觀測等價（applied pi-calculus 對 privacy 的原生 primitive）
**所屬層**：symbolic verification
**首次出現**：[5.9](lessons/part-5-formal-methods/5.9-hyperproperties-observational-equivalence.md)（Abadi-Fournet POPL 2001）
**一句話**：兩個 process $P \approx Q$ iff 對任意 attacker context $C[\cdot]$ 觀測結果不可區分；ProVerif `choice[A,B]` / Tamarin `diff` 都實作這條等價。

### Diff-Equivalence
**中文**：差分等價（ProVerif/Tamarin 的 biprocess equivalence）
**所屬層**：tooling
**首次出現**：[5.9](lessons/part-5-formal-methods/5.9-hyperproperties-observational-equivalence.md)（Blanchet-Abadi-Fournet JLAP 2008）
**一句話**：在 spec 內用 `choice[A,B]` 或 `diff(A,B)` 同時 model 兩個 world，要求結構對齊；ECH outer/inner SNI privacy 用這條 verify。

### Unlinkability
**中文**：不可關聯性
**所屬層**：privacy property
**首次出現**：[5.9](lessons/part-5-formal-methods/5.9-hyperproperties-observational-equivalence.md)（Hirschi-Baelde-Delaune S&P 2016）
**一句話**：兩個 session 來自同一 user 或不同 user 對攻擊者不可區分；WireGuard 預設不提供（peer pub key 是 linker），我們協議要設計 ratcheted pseudonym 達 session-bounded unlinkability。

### HyperLTL
**中文**：超線性時序邏輯（state-machine 級 hyperproperty）
**所屬層**：formal methods
**首次出現**：[5.9](lessons/part-5-formal-methods/5.9-hyperproperties-observational-equivalence.md)（Finkbeiner-Rabe-Sánchez CAV 2015）
**一句話**：在 LTL 上加「對任意兩條 path π, π'」量化，能寫 non-interference / observational determinism；對 TLA+ transport state machine 寫 hyperinvariant 用。

### PRISM / Storm
**中文**：probabilistic model checker（精確）
**所屬層**：tooling
**首次出現**：[5.10](lessons/part-5-formal-methods/5.10-probabilistic-statistical-fm.md)（Kwiatkowska et al. CAV 2011 / Hensel et al. STTT 2022）
**一句話**：對 DTMC / MDP / CTMC 算 PCTL property 的 exact probability；對 traffic vs cover 的 total variation distance 精確 compute。

### Statistical Model Checking (SMC)
**中文**：統計模型檢驗
**所屬層**：tooling
**首次出現**：[5.10](lessons/part-5-formal-methods/5.10-probabilistic-statistical-fm.md)（Younes-Simmons IC 2006）
**一句話**：用 simulation + hypothesis testing 估 probabilistic property；trade exact for scale；對大 traffic model 必選。

### Total Variation Distance ($d_{TV}$)
**中文**：總變差距離
**所屬層**：statistical foundation
**首次出現**：[5.10](lessons/part-5-formal-methods/5.10-probabilistic-statistical-fm.md)
**一句話**：兩個 distribution 對 optimal distinguisher 的 advantage 上界；對單包 distribution 算 $\frac{1}{2}\sum_x |P(x)-Q(x)|$；i.i.d. 多 sample 後 advantage 對 $N$ 增大趨近 1。

### Wu-FEP Adversary
**中文**：Wu-Ensafi-Crandall 對「fully encrypted protocols」的 ML classifier
**所屬層**：threat model
**首次出現**：[5.10](lessons/part-5-formal-methods/5.10-probabilistic-statistical-fm.md)（Wu et al. USENIX Security 2023）
**一句話**：GFW 對 "看起來隨機" 的流量用 entropy / size / IAT 等 features 訓的 classifier；G6 形式化的對手定義基準。

### Universal Composability (UC)
**中文**：通用可組合性
**所屬層**：cryptographic composition framework
**首次出現**：[5.11](lessons/part-5-formal-methods/5.11-composition-implementation-fm.md)（Canetti FOCS 2001 / journal 2020）
**一句話**：最強的 composition framework — 協議 UC-realize ideal functionality ⇒ 在任意 environment 內 composable；但 TLS 1.3 不滿足 full UC，實務改用 weaker composition。

### Multi-Stage Key Exchange (MSKE)
**中文**：多階段密鑰交換 composition framework
**所屬層**：cryptographic composition
**首次出現**：[5.11](lessons/part-5-formal-methods/5.11-composition-implementation-fm.md)（Fischlin-Günther CCS 2014；Dowling-FGS JCS 2021 TLS 1.3 完整）
**一句話**：對協議產出的 sequence of keys (Initial/Handshake/Application/0-RTT) 各自 prove secrecy/auth/FS/replayability，再用 composition theorem 黏成 channel security。

### ACCE (Authenticated Confidential Channel Establishment)
**中文**：authenticated channel composition model
**所屬層**：cryptographic composition
**首次出現**：[5.11](lessons/part-5-formal-methods/5.11-composition-implementation-fm.md)（Jager-Kohlar-Schäge-Schwenk CRYPTO 2012）
**一句話**：「AKE-secure + record-AEAD-secure ⇒ ACCE-secure channel」；TLS 1.2/1.3 + WireGuard 都用這個 framework 證明完整 channel security。

### HACL\* / Project Everest
**中文**：F\* 寫的 verified crypto library + 整套 verified HTTPS stack
**所屬層**：verified implementation
**首次出現**：[5.11](lessons/part-5-formal-methods/5.11-composition-implementation-fm.md)（Bhargavan et al. SNAPL 2017；Protzenko et al. S&P 2019）
**一句話**：F\* spec ⇒ KreMLin 提取 verified C / Rust / WebAssembly；ChaCha20-Poly1305 / Curve25519 / Ed25519 等 production-ready；Mozilla NSS、Linux kernel 已 deploy。

### Cryspen hax
**中文**：Rust → F\* / Coq 翻譯工具
**所屬層**：verified implementation
**首次出現**：[5.11](lessons/part-5-formal-methods/5.11-composition-implementation-fm.md)
**一句話**：Rust subset 可被 hax 提取成 F\* model 後 mechanically verify；若我們協議選 Rust 寫 (e.g. fork quinn) 是進入 formal verification 的 ramp。

### Hybrid KEM / X-Wing
**中文**：post-quantum + classical 混合密鑰封裝
**所屬層**：post-quantum
**首次出現**：[5.11](lessons/part-5-formal-methods/5.11-composition-implementation-fm.md)（Bos-Stebila et al. PQCrypto 2020；Connolly et al. CFRG draft 2024）
**一句話**：ML-KEM-768 + X25519 用 KDF combine 成單一 shared secret；安全性繼承兩者的 min；2027-2028 ship 的 SOTA 協議默認 baseline。

### KEMTLS
**中文**：signature-free post-quantum TLS handshake
**所屬層**：post-quantum
**首次出現**：[5.11](lessons/part-5-formal-methods/5.11-composition-implementation-fm.md)（Schwabe-Stebila-Wiggers CCS 2020）
**一句話**：用 KEM 取代 server signature 大幅減小 PQC handshake size；對 anti-fingerprint 的 packet size 預算也友好。

### TCP Meltdown (Olaf Titz 2001)
**中文**：TCP-over-TCP 重傳定時器堆疊崩潰
**所屬層**：L4 跨層失效機制
**首次出現**：[8.1](lessons/part-8-quic-protocols/8.1-quic-as-second-line.md)
**一句話**：上下兩層 TCP 各自的 RTO 競爭使重傳隊列爆炸增長, throughput 指數衰減; 所有 VPN/proxy 必須 UDP-based 的物理底線。

### TCP Ossification (Honda IMC 2011)
**中文**：TCP 因 middlebox 干涉而無法演進
**所屬層**：L4 部署現實
**首次出現**：[8.1](lessons/part-8-quic-protocols/8.1-quic-as-second-line.md)
**一句話**：~6.5% path 完全 strip 新 TCP option, ~14% MPTCP 異常, ~25% 修改 SEQ/ACK; QUIC 改 UDP-based 的根本原因。

### QUIC Invariants (RFC 8999)
**中文**：QUIC 跨版本不可變 wire 欄位
**所屬層**：L4 normative spec
**首次出現**：[8.1](lessons/part-8-quic-protocols/8.1-quic-as-second-line.md)
**一句話**：long header bit 7, fixed bit, version 欄位, DCID/SCID format 必須跨版本固定; 我們協議若做 QUIC variant 必遵守。

### QUIC v2 (RFC 9369)
**中文**：QUIC 第二版（測試 ossification 用）
**所屬層**：L4 spec
**首次出現**：[8.6](lessons/part-8-quic-protocols/8.6-quic-in-china.md)、[8.9](lessons/part-8-quic-protocols/8.9-custom-quic-variant.md)
**一句話**：version 號 = 0x6b3343cf, initial salt 不同; GFW 2024-04 SNI 過濾 hardcoded v1, 用 v2 立即 bypass; 我們協議的 base transport candidate。

### Brutal CC
**中文**：用戶宣告速度、不退讓的擁塞控制
**所屬層**：L4 / congestion control
**首次出現**：[8.2](lessons/part-8-quic-protocols/8.2-hysteria-v1.md)
**一句話**：cwnd = bps × RTT × 2 / ackRate, ackRate floor 0.8; 對單 user 高速有效, 對 shared 網路是 cheating (違反 TCP-friendly fairness)。

### Hysteria v1 / v2
**中文**：QUIC-based proxy, Brutal CC + masquerade
**所屬層**：L7 proxy protocol
**首次出現**：[8.2](lessons/part-8-quic-protocols/8.2-hysteria-v1.md)、[8.3](lessons/part-8-quic-protocols/8.3-hysteria-v2.md)
**一句話**：v1 用自訂 binary handshake + XOR obfs, 易被 probe; v2 改 HTTP/3 POST /auth + Salamander obfs + masquerade backend; UDP relay 走 QUIC datagram。

### Salamander Obfuscation
**中文**：Hysteria 2 的 per-packet BLAKE2b XOR obfuscation
**所屬層**：L4 wire image
**首次出現**：[8.3](lessons/part-8-quic-protocols/8.3-hysteria-v2.md)
**一句話**：8-byte random salt + BLAKE2b-256(key+salt) XOR payload; 比 v1 fixed-XOR 強, 但仍中 Wu USENIX Sec 2023 fully-encrypted detection。

### TUIC v5
**中文**：QUIC-based proxy, TLS exporter auth
**所屬層**：L7 proxy protocol
**首次出現**：[8.4](lessons/part-8-quic-protocols/8.4-tuic-v4-v5.md)
**一句話**：VER|TYPE|OPT 命令格式, Auth/Connect/Packet/Dissociate/Heartbeat 5 命令; password 透過 TLS Keying Material Exporter 不出 wire; Full Cone NAT 支援。

### TLS Keying Material Exporter (RFC 8446 §7.5)
**中文**：TLS session-bound 衍生密鑰機制
**所屬層**：L5 crypto
**首次出現**：[8.4](lessons/part-8-quic-protocols/8.4-tuic-v4-v5.md)
**一句話**：HKDF-Expand-Label(exporter_master_secret, "EXPORTER-XX", context, len); session-bound, replay-resistant; TUIC v5 / Channel Binding (RFC 5056) 經典應用。

### Full Cone NAT (RFC 5128)
**中文**：對外固定 source port, 接受任意 source 回包
**所屬層**：L3-L4 NAT 行為
**首次出現**：[8.4](lessons/part-8-quic-protocols/8.4-tuic-v4-v5.md)
**一句話**：P2P 遊戲 / WebRTC / Valorant 必要; TUIC v5 設計上每 ASSOC_ID 固定 outbound port。

### NaiveProxy
**中文**：直接借用 Chromium net stack 的 proxy
**所屬層**：L7 proxy protocol
**首次出現**：[8.5](lessons/part-8-quic-protocols/8.5-naiveproxy.md)
**一句話**：fork Chromium net/, 砍到 0.3% 原 size; TLS / H/2 fingerprint 自動跟 Chrome 同步; Caddy + forwardproxy plugin 做 server side。

### Probe Resistance
**中文**：對主動 probing 假裝不是 proxy
**所屬層**：anti-censorship 設計
**首次出現**：[8.5](lessons/part-8-quic-protocols/8.5-naiveproxy.md)
**一句話**：未認證 user 看到 fallback 真 web server 內容; REALITY 在 TLS layer 做 (Part 7), NaiveProxy forwardproxy 在 H/2 application layer 做。

### SNI Slicing
**中文**：把 TLS ClientHello SNI extension 拆跨多 QUIC CRYPTO frame 上不同 UDP datagram
**所屬層**：anti-censorship
**首次出現**：[8.6](lessons/part-8-quic-protocols/8.6-quic-in-china.md)、[8.7](lessons/part-8-quic-protocols/8.7-quic-go-forks.md)
**一句話**：因 GFW 不重組 CRYPTO frame across UDP packet, SNI 拆兩半 GFW 看不到; Firefox 137、quic-go v0.52.0、Hysteria、V2Ray 2025-08 部署。

### Jumbo Initial
**中文**：QUIC Initial packet 強制跨多 UDP datagram
**所屬層**：anti-censorship
**首次出現**：[8.6](lessons/part-8-quic-protocols/8.6-quic-in-china.md)
**一句話**：Chrome 2024-09 Kyber768 commit 意外觸發, GFW 不重組 UDP fragments → 漏抓 SNI; QUIC anti-censorship 主流 bypass 技術。

### Availability Attack (Zohaib 2025)
**中文**：用 GFW SNI 過濾當武器, spoof packet 觸發任意 3-tuple 180s block
**所屬層**：threat model
**首次出現**：[8.6](lessons/part-8-quic-protocols/8.6-quic-in-china.md)
**一句話**：Mallory spoof Alice 源 IP 連 Bob, payload = QUIC Initial w/ 禁 SNI → GFW 觸發 (Alice, Bob, port) 180s drop; 對 DNS over UDP 等服務真實威脅。

### Diurnal Pattern (GFW QUIC)
**中文**：GFW QUIC 解 Initial 阻擋率隨流量負載日週期變化
**所屬層**：observed measurement
**首次出現**：[8.6](lessons/part-8-quic-protocols/8.6-quic-in-china.md)
**一句話**：早 4-6 AM ~80% 阻擋, 晚 6-9 PM ~30%; 證實 GFW 解 Initial 是計算瓶頸; 設計上可故意拉高 解 cost 利用此弱點。

### apernet/quic-go
**中文**：Hysteria 維護的 anti-censorship 改造版 quic-go
**所屬層**：implementation
**首次出現**：[8.7](lessons/part-8-quic-protocols/8.7-quic-go-forks.md)
**一句話**：Xray-core 透過 github.com/apernet/quic-go import; 提供 SNI slicing / jumbo Initial / grease / 自訂 Initial salt 等 anti-censorship feature。

### QUICstep
**中文**：用 QUIC connection migration 做 SNI hiding 的 bypass
**所屬層**：anti-censorship technique
**首次出現**：[8.6](lessons/part-8-quic-protocols/8.6-quic-in-china.md)、[8.10](lessons/part-8-quic-protocols/8.10-takeaways.md)
**一句話**：handshake 走 encrypted side channel, 完成後 migrate 到 direct path; PETS 2026(1) Tehrani et al.; 我們協議須支援 connection migration。

### Connection Migration (RFC 9000 §9)
**中文**：QUIC 客戶端 IP/port 變動但 connection 持續
**所屬層**：L4 QUIC feature
**首次出現**：[8.6](lessons/part-8-quic-protocols/8.6-quic-in-china.md)、[8.10](lessons/part-8-quic-protocols/8.10-takeaways.md)
**一句話**：connection 由 connection ID 識別, 不靠 5-tuple; 行動 client 換網斷不掉, 也是 anti-censorship 工具。

### iCloud Private Relay
**中文**：Apple 兩 hop oblivious proxy, CONNECT-UDP 部署
**所屬層**：production deployment case
**首次出現**：[8.8](lessons/part-8-quic-protocols/8.8-masque-deep.md)
**一句話**：ingress (Apple) + egress (Cloudflare/Akamai/Fastly) 兩 hop, 無單方知道 (who, what); 在中國從 2021 起被擋 (mask-iphost.icloud.com SNI)。

### Cloudflare WARP MASQUE
**中文**：Cloudflare 從 WireGuard 遷到 MASQUE 的 production case
**所屬層**：production deployment case
**首次出現**：[8.8](lessons/part-8-quic-protocols/8.8-masque-deep.md)
**一句話**：2024+ 部署 CONNECT-IP over HTTPS/QUIC, wire image = 普通 Cloudflare HTTPS; Diniboy1123/usque 是 Go 第三方 re-impl。

### QUIC Version Aliasing (draft-thomson)
**中文**：私下約定 random version 號做 anti-censorship
**所屬層**：proposed mechanism
**首次出現**：[8.9](lessons/part-8-quic-protocols/8.9-custom-quic-variant.md)
**一句話**：client/server 預共享 version table, 隨機選一個; 違反 IETF spec, 風險 middlebox drop unknown version; 未被 WG 採納。

### Wire Image Mimicry
**中文**：wire 上看起來像某個合法 protocol
**所屬層**：anti-censorship 設計
**首次出現**：[8.8](lessons/part-8-quic-protocols/8.8-masque-deep.md)、[8.10](lessons/part-8-quic-protocols/8.10-takeaways.md)
**一句話**：對比 wire-image 隨機化, mimicry 是「假裝是 X」; Houmansadr NDSS 2013 "Parrot is Dead" 警告 mimicry 永遠落後但 MASQUE/REALITY 路線重新驗證可行。
---

# Part 9 — 審查對抗：GFW 完整研究

### Active Probing
**中文**：主動探測
**所屬層**：censor capability
**首次出現**：[9.1](lessons/part-9-gfw-research/9.1-gfw-architecture-overview.md)（Ensafi et al. IMC 2015）
**一句話**：censor 主動向疑似 proxy server 發起 TCP/UDP connect 與 payload，觀察 response 以識別協議家族；GFW 的 confirmation 手段。

### Probe Family
**中文**：探測族
**所屬層**：active probing taxonomy
**首次出現**：[9.2](lessons/part-9-gfw-research/9.2-gfw-shadowsocks-detection.md)（Alice et al. IMC 2020）
**一句話**：同類但變異的 probe 集合；GFW 對 SS 用 7 family（replay、mutation、random、truncated、concatenated）。

### Probe-resistant Protocol
**中文**：抗探測協議
**所屬層**：design property
**首次出現**：[9.6](lessons/part-9-gfw-research/9.6-active-probing-deep-dive.md)（Frolov, Wampler, Wustrow NDSS 2020）
**一句話**：對 active probe 不洩漏身份的協議；obfs4 silent-hold L1，MTProto perpetual-read L2，REALITY real-backend forward L3。

### Residual Censorship
**中文**：殘留封鎖
**所屬層**：blocking behavior
**首次出現**：[9.1](lessons/part-9-gfw-research/9.1-gfw-architecture-overview.md)
**一句話**：GFW 識別流量後對 (src_IP, dst_IP, dst_port) 在後續 90–180 秒繼續封鎖；對流量設計造成 retry 邏輯難題。

### Fully-Encrypted Traffic (FET)
**中文**：全加密協議流量
**所屬層**：traffic class
**首次出現**：[9.7](lessons/part-9-gfw-research/9.7-fully-encrypted-traffic-detection.md)（Wu et al. USENIX Security 2023）
**一句話**：沒有 plaintext header 的協議流量（SS、VMess、obfs4）；GFW 2021-11 起以 5 條 byte-level heuristic 純被動偵測。

### Exemption Rule
**中文**：排除規則
**所屬層**：FET detection
**首次出現**：[9.7](lessons/part-9-gfw-research/9.7-fully-encrypted-traffic-detection.md)
**一句話**：GFW FET detector 用 5 條規則（popcount、printable-ratio、protocol-prefix）作 OR-of-exemptions；命中任一即放行。

### Popcount Heuristic
**中文**：1-bit 計數啟發式
**所屬層**：FET detection rule Ex1
**首次出現**：[9.7](lessons/part-9-gfw-research/9.7-fully-encrypted-traffic-detection.md)
**一句話**：對 first segment 計算 mean popcount per byte，落在 (3.4, 4.6) 範圍以外即放行；隨機 byte 期望 ≈ 4。

### Probabilistic Blocking
**中文**：機率封鎖
**所屬層**：blocking policy
**首次出現**：[9.7](lessons/part-9-gfw-research/9.7-fully-encrypted-traffic-detection.md)
**一句話**：GFW 對 FET trigger 以 ~26.3% 機率封鎖，控制 collateral damage；對 evader 而言意味多次重試可能繞過。

### SNI Sniffing
**中文**：SNI 嗅探
**所屬層**：DPI capability
**首次出現**：[9.1](lessons/part-9-gfw-research/9.1-gfw-architecture-overview.md)
**一句話**：GFW 解析 TLS ClientHello 的 server_name extension，對黑名單命中即注入 RST + 殘留封鎖。

### Handshake Stealing
**中文**：握手盜用
**所屬層**：circumvention pattern
**首次出現**：[9.4](lessons/part-9-gfw-research/9.4-gfw-vless-reality-status.md)（REALITY by RPRX）
**一句話**：server 模擬 cover server 的 TLS handshake（用借用 cert + 派生 auth key 簽 ServerHello），失敗認證 fallback 給真 backend；REALITY 核心。

### IP-SNI Mismatch
**中文**：IP-SNI 對應不一致
**所屬層**：cross-feature passive detection
**首次出現**：[9.3](lessons/part-9-gfw-research/9.3-gfw-trojan-detection.md)
**一句話**：client 連到 IP_S 但 ClientHello.SNI 指向 example.com，若 IP_S 不在 example.com 對應 ASN → 可疑；對 Trojan 致命的訊號。

### TLS-in-TLS
**中文**：TLS 內隧道
**所屬層**：traffic shape leak
**首次出現**：[9.3](lessons/part-9-gfw-research/9.3-gfw-trojan-detection.md)
**一句話**：TLS 流量內承載另一個加密協議；packet size、burst pattern、record size 分布與真實 browsing 不同，是 traffic-shape classifier 主要 feature。

### QUIC Initial Decryption
**中文**：QUIC 起始包解密
**所屬層**：QUIC censorship
**首次出現**：[9.5](lessons/part-9-gfw-research/9.5-gfw-quic-http3.md)（Zohaib et al. USENIX Security 2025）
**一句話**：QUIC v1 的 Initial packet 用 publicly-derivable key 加密；GFW 2024-04 起 at-scale 解密提取 SNI 並 block。

### SNI-Slicing
**中文**：SNI 切片
**所屬層**：QUIC circumvention
**首次出現**：[9.5](lessons/part-9-gfw-research/9.5-gfw-quic-http3.md)
**一句話**：把 TLS ClientHello 的 SNI 跨多個 UDP datagram 切割，利用 GFW 不重組 Initial 的限制 bypass QUIC SNI filter；quic-go v0.52+ 已實作。

### TCB Teardown
**中文**：TCB 拆解
**所屬層**：TCP-layer evasion
**首次出現**：[9.1](lessons/part-9-gfw-research/9.1-gfw-architecture-overview.md)（Khattak et al.; Bock et al. CCS 2019）
**一句話**：傳送格式異常但合法的 TCP segment 讓 GFW per-flow TCB 失效，後續流量 bypass DPI；Geneva 自動發現的 evasion 之一。

### JA3 / JA3S
**中文**：客戶端 / 服務器 TLS 指紋（2017 規格）
**所屬層**：TLS fingerprint
**首次出現**：[9.9](lessons/part-9-gfw-research/9.9-tls-fingerprinting.md)（Althouse, Salesforce 2017）
**一句話**：對 ClientHello / ServerHello 的 (version, ciphers, extensions, curves, point_formats) hash 為 MD5；censor 用其識別罕見 mimicry tool。

### JA4 / JA4+
**中文**：JA3 後繼指紋家族（2023+）
**所屬層**：TLS / HTTP / TCP fingerprint
**首次出現**：[9.9](lessons/part-9-gfw-research/9.9-tls-fingerprinting.md)（Althouse, FoxIO 2023+）
**一句話**：a-b-c 結構 SHA256-truncated，sort cipher/ext 後 hash；JA4 (TLS Client)、JA4S (Server)、JA4H (HTTP)、JA4X (Cert)、JA4SSH、JA4T (TCP)。

### uTLS
**中文**：Go crypto/tls fork，可自訂 ClientHello
**所屬層**：TLS mimicry library
**首次出現**：[9.9](lessons/part-9-gfw-research/9.9-tls-fingerprinting.md)（Frolov & Wustrow NDSS 2019）
**一句話**：refraction-networking/utls，允許 caller assemble 任意 ClientHello（byte-level Chrome / Firefox preset）；現代 circumvention 必備。

### Cover SNI / Cover Backend
**中文**：偽裝域名 / 偽裝後端
**所屬層**：circumvention deployment
**首次出現**：[9.4](lessons/part-9-gfw-research/9.4-gfw-vless-reality-status.md)
**一句話**：client 用熱門未被封鎖 domain 作 SNI，失敗認證時 server forward 給真實 backend；REALITY / Trojan / domain fronting 共用模式。

### Domain Fronting
**中文**：域名前置
**所屬層**：circumvention technique
**首次出現**：[9.1](lessons/part-9-gfw-research/9.1-gfw-architecture-overview.md)
**一句話**：client TLS SNI 用 cover domain（CDN-hosted），HTTP Host header 用真正目標；CDN 把流量 route 給真 backend；2018 主流 CDN 已封閉此 path。

### Refraction Networking
**中文**：折射網路
**所屬層**：circumvention architecture
**首次出現**：[9.1](lessons/part-9-gfw-research/9.1-gfw-architecture-overview.md)
**一句話**：ISP 合作的 station 在中轉路徑上劫持特殊 client → 改向 covert proxy；Conjure / TapDance 為代表。

### nDPI
**中文**：開源 DPI 庫
**所屬層**：testbed tooling
**首次出現**：[9.8](lessons/part-9-gfw-research/9.8-traffic-fingerprint-ml.md)（ntop）
**一句話**：C library，識別 ~280 protocol，per-protocol detector 寫在 `src/lib/protocols/`；testbed 離線 pcap 分析常用。

### Zeek
**中文**：network analysis framework
**所屬層**：testbed tooling
**首次出現**：[9.8](lessons/part-9-gfw-research/9.8-traffic-fingerprint-ml.md)
**一句話**：原 Bro，scriptable NIDS，event-driven Zeek script；TLS / HTTP / DNS 內建 dissector；testbed online flow analysis 用。

### FlowPrint
**中文**：semi-supervised app fingerprinter
**所屬層**：traffic classification
**首次出現**：[9.8](lessons/part-9-gfw-research/9.8-traffic-fingerprint-ml.md)（van Ede et al. NDSS 2020）
**一句話**：用 destination IP + SNI + cert 聚類 flow，semi-supervised 識別 app；89% closed-world, 93% precision on unseen apps；proxy single-destination 是其弱點。

### Deep Fingerprinting (DF)
**中文**：1D CNN website fingerprinting attack
**所屬層**：DL traffic classification
**首次出現**：[9.8](lessons/part-9-gfw-research/9.8-traffic-fingerprint-ml.md)（Sirinam et al. CCS 2018）
**一句話**：對 Tor traffic ±1-direction packet sequence 跑 4-block 1D CNN，~98% closed-world accuracy；hand-crafted feature 時代結束的標誌。

### Geneva
**中文**：GA-evolved censorship evasion
**所屬層**：evasion automation
**首次出現**：[9.1](lessons/part-9-gfw-research/9.1-gfw-architecture-overview.md)（Bock et al. CCS 2019）
**一句話**：以 drop/tamper/duplicate/fragment 四 primitive 透過 GA 自動找 TCP-layer 評估 evasion；對 GFW、印度、Kazakhstan censor 都成功 re-derive 已知策略並發現新策略。

### Honeypot Bridge
**中文**：蜜罐橋
**所屬層**：measurement methodology
**首次出現**：[9.6](lessons/part-9-gfw-research/9.6-active-probing-deep-dive.md)
**一句話**：研究者故意暴露的 proxy/bridge，用來收集 GFW prober probe；Ensafi/Alice/Wu 系列論文核心方法。

### Prober Pool
**中文**：探測 IP 池
**所屬層**：GFW infrastructure
**首次出現**：[9.2](lessons/part-9-gfw-research/9.2-gfw-shadowsocks-detection.md)
**一句話**：GFW 用來發送 active probe 的 source IP 集合；2020 觀察 12k+ IP 但 TCP timestamp 顯示背後僅十幾台中央主機。

### nfqueue
**中文**：Linux 用戶空間封包處理
**所屬層**：testbed tooling
**首次出現**：[9.10](lessons/part-9-gfw-research/9.10-testbed-architecture.md)
**一句話**：netfilter 把封包 queue 給 user-space 處理；Python+scapy 即可實作 testbed 級 censor decisions；性能不如 XDP 但開發簡單。

### Adversarial Indistinguishability (ε)
**中文**：對手不可區分性
**所屬層**：protocol security goal
**首次出現**：[9.13](lessons/part-9-gfw-research/9.13-testbed-ml-classifier.md)
**一句話**：對 PPT 對手 A，協議流量 vs cover 流量的區分 advantage ≤ ε；circumvention 安全的 game-based 主指標。

### Cover Traffic
**中文**：偽流量
**所屬層**：traffic defense
**首次出現**：[9.8](lessons/part-9-gfw-research/9.8-traffic-fingerprint-ml.md)
**一句話**：實際無功能的填充流量，用來模仿正常 browsing 的 multi-destination + waterfall 特徵；Walkie-Talkie / Conjure 使用。

---

## Part 11 — 設計階段

### Capability Matrix
**中文**：對手能力矩陣
**所屬層**：threat modeling
**首次出現**：[11.1](lessons/part-11-design/11.1-threat-model.md)
**一句話**：把對手可做的事按 ID（C1, C2, ...）列表，每條 in-scope 必對應 defense 與 verification; G6 在 C1–C7、C9–C12 in-scope。

### ε_CAR (Distinguishing Advantage for Censorship Resistance)
**中文**：抗審查可區分度
**所屬層**：anti-censorship 評估
**首次出現**：[11.1](lessons/part-11-design/11.1-threat-model.md)
**一句話**：classifier 區分 G6 與 cover protocol 的 advantage，定義仿 IND game (Tschantz FOCI 2016)；G6 target ε_short ≤ 0.20, ε_stretch ≤ 0.30。

### Mosca's Theorem / SNDL
**中文**：「現在收集、未來解密」威脅模型
**所屬層**：PQ 威脅
**首次出現**：[11.1](lessons/part-11-design/11.1-threat-model.md)
**一句話**：Mosca 2018 給的 migration 時程公式；G6 因此 mandatory hybrid PQ KEM。

### KCI (Key Compromise Impersonation) Resistance
**中文**：金鑰妥協冒充抗性
**所屬層**：handshake security
**首次出現**：[11.1](lessons/part-11-design/11.1-threat-model.md)
**一句話**：Krawczyk HMQV 2005 定義；client SK 洩後，attacker 仍不能假冒 honest server 對 client；G6 由 server TLS cert + signature 達成。

### PCS (Post-Compromise Security)
**中文**：後妥協安全
**所屬層**：handshake / ratchet security
**首次出現**：[11.6](lessons/part-11-design/11.6-spec-handshake-state.md)（Cohn-Gordon-Cremers-Garratt JoC 2016）
**一句話**：key reveal 後，未來 ratchet 之後的 key 仍 secret；G6 v0.1 KEYUPDATE 達 PCS-weak（Tamarin 已驗）。

### REALITY / SNI Borrowing
**中文**：借用真實 popular SNI + auth-fail forward
**所屬層**：anti-active-probing
**首次出現**：[11.3](lessons/part-11-design/11.3-design-space.md)
**一句話**：xtls/reality 設計；server 對 auth-fail connection 直接 forward 給真實 cover server，attacker 看到的是 cover 的真實 TLS cert / response。

### MASQUE (CONNECT-UDP/IP over HTTP/3)
**中文**：HTTP/3 內的 UDP/IP proxy
**所屬層**：transport substrate
**首次出現**：[11.3](lessons/part-11-design/11.3-design-space.md)（RFC 9297/9298/9484）
**一句話**：IETF MASQUE WG 的 proxy 規格；G6-γ 選此作 primary transport，inner 不是 TLS 故 architectural 規避 TLS-in-TLS 攻擊。

### TLS-in-TLS Detection
**中文**：TLS-in-TLS 結構性洩漏
**所屬層**：anti-censorship 攻擊面
**首次出現**：[11.3](lessons/part-11-design/11.3-design-space.md)（Xue USENIX 2024）
**一句話**：outer TLS-over-TCP 內跑 inner TLS，inner record 邊界由 outer 段碎洩漏；G6-γ MASQUE 架構規避。

### Hybrid KEM
**中文**：classical + PQ 並聯 KEM
**所屬層**：post-quantum migration
**首次出現**：[11.4](lessons/part-11-design/11.4-architecture-decision.md)（Bindel PQCrypto 2019）
**一句話**：G6 用 KDF(X25519 ‖ ML-KEM-768)；攻擊者必須同時 break 兩個分支才得 secret。

### GREASE
**中文**：Generate Random Extensions And Sustain Extensibility
**所屬層**：anti-ossification
**首次出現**：[11.8](lessons/part-11-design/11.8-spec-extensibility.md)（RFC 8701）
**一句話**：在 ClientHello 內隨機插入無意義 codepoint，防 middlebox 凝固 + 維持 wire-level multiplicity。

### Cover Protocol Pinning
**中文**：cover protocol 鎖死
**所屬層**：CAR-1
**首次出現**：[11.2](lessons/part-11-design/11.2-goals-non-goals.md)
**一句話**：ε_CAR 必相對 specific cover distribution 才有意義；G6 鎖 TLS 1.3 over UDP-443 (H3) to popular CDN。

### Active Probing
**中文**：主動探測
**所屬層**：CAR-2 攻擊面
**首次出現**：[11.1](lessons/part-11-design/11.1-threat-model.md)（Ensafi 2015、Frolov 2020）
**一句話**：censor 對可疑 IP 主動發 probe 試探回應；REALITY-style fallback 是 SOTA 應對。

### Goodput vs Throughput
**中文**：goodput 排除 retransmit/padding 的 effective bandwidth
**所屬層**：performance metric
**首次出現**：[11.2](lessons/part-11-design/11.2-goals-non-goals.md)（Cardwell BBR CACM 2017）
**一句話**：G6 PERF-1 用 goodput ≥ 0.95 BDP, 不是 raw throughput。

### Cell Padding
**中文**：固定 cell 大小填充
**所屬層**：CAR-1 padding
**首次出現**：[11.3](lessons/part-11-design/11.3-design-space.md)
**一句話**：每 UDP datagram round-up 到 1280 bytes (G6 spec)，去除 size feature。

### Cover-Distribution Sampling
**中文**：採樣 cover 分佈整形
**所屬層**：CAR-1 advanced shaping
**首次出現**：[11.3](lessons/part-11-design/11.3-design-space.md)
**一句話**：不只 fixed-cell，IAT + size 採樣自 cover protocol 分佈，TVD 下界以 Le Cam's lemma 給 ε_CAR 上界。

### Polymorphism vs Mimicry
**中文**：多形變化 vs 模仿
**所屬層**：CAR design philosophy
**首次出現**：[11.3](lessons/part-11-design/11.3-design-space.md)（Houmansadr S&P 2013 "Parrot is dead"）
**一句話**：mimicry 任一 semantic 不對就死；polymorphism 仰賴 distribution coverage 不仰賴 semantic equivalence; G6 採 polymorphism。

### Fallback Forwarding
**中文**：auth-fail 透傳給真 cover
**所屬層**：anti-active-probing 機制
**首次出現**：[11.4](lessons/part-11-design/11.4-architecture-decision.md)
**一句話**：G6 server 對 auth-fail connection 整段 bytes forward 給真 cover；attacker 看 cover 的真實回應; spec 要 < 1ms p99 budget。

### Adversarial Reading
**中文**：對抗式 review
**所屬層**：design review methodology
**首次出現**：[11.12](lessons/part-11-design/11.12-design-review.md)
**一句話**：design review 不是 confirming spec, 是 attack spec 找漏洞；G6 v0.1 從 v0.0 經此 review 加 10 條 normative fix。

### Residual Risk
**中文**：殘餘風險（已 known but explicitly 接受）
**所屬層**：threat modeling
**首次出現**：[11.1](lessons/part-11-design/11.1-threat-model.md)（NIST SP 800-30 風格）
**一句話**：每條 in-scope capability 對應一個 defense + 可能仍有 residual; spec §11.16 明列接受項。

### BCP 14 (RFC 2119 / RFC 8174)
**中文**：MUST / SHOULD / MAY 規範用詞
**所屬層**：spec writing
**首次出現**：[11.5](lessons/part-11-design/11.5-spec-wire-format.md)
**一句話**：IETF normative keyword convention; G6 spec strictly 遵循。

### Conformance Test Vectors
**中文**：符合性測試向量
**所屬層**：spec writing
**首次出現**：[11.13](lessons/part-11-design/11.13-spec-v01.md)
**一句話**：spec 內附 byte-exact test vectors 確保多 impl 互通; G6 v0.1 deferred 到 Part 12 reference impl 一起 release。

### Bloom Filter (anti-replay)
**中文**：機率資料結構濾重複
**所屬層**：anti-replay
**首次出現**：[11.6](lessons/part-11-design/11.6-spec-handshake-state.md)（Bloom 1970）
**一句話**：G6 用 sliding 1-hour Bloom 過 nonce, FPR ≤ 10⁻⁹; false positive 觸發 fallback (safe)。

### Forward-only Ratchet (KDF-only)
**中文**：單向 KDF ratchet
**所屬層**：handshake ratchet
**首次出現**：[11.6](lessons/part-11-design/11.6-spec-handshake-state.md)
**一句話**：K_{n+1} = HKDF(K_n, label)；簡單但只達 PCS-weak（PCS-strong 需注入 fresh randomness, 1 RTT 代價）。
