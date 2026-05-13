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
