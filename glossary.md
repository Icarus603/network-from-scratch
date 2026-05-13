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
