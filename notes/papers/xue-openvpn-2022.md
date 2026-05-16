# OpenVPN is Open to VPN Fingerprinting
**Venue / Year**: USENIX Security 2022 (Distinguished Paper Award + 2022 Internet Defense Prize First Place)
**Authors**: Diwen Xue, Reethika Ramesh, Arham Jain (U. Michigan); Michalis Kallitsis (Merit Network); J. Alex Halderman (U. Michigan); Jedidiah R. Crandall (ASU / Breakpointing Bad); Roya Ensafi (U. Michigan)
**Read on**: 2026-05-16 (in lesson 6.2)
**Status**: full PDF (`assets/papers/xue-openvpn-2022.pdf`)
**One-line**: OpenVPN 的死刑判決書——用三條 byte/size/probe fingerprint + two-phase（passive→active）framework，在 1M-user ISP 規模下以 >85% recall + 極低 FP 識別 OpenVPN 流，並證明所有現有 tls-crypt 系列鎧甲擋不住。

## Problem
2020 前的 VPN fingerprinting 多依賴 ML，FP 高且需大量訓練資料。Xue et al. 想證明：可以用**確定性、低成本、可審計**的方式，把 OpenVPN（the most popular commercial VPN protocol）打到 ISP-scale 可實用偵測。

## Contribution
1. **三條 protocol-level fingerprint**：
   - **#1 byte pattern**：第一封 packet 第一 byte 固定 0x38（client）/0x40（server）等 opcode 高位，即使啟用 tls-crypt 仍明文。
   - **#2 packet size sequence**：OpenVPN handshake 的 ACK + control 序列有極可預測的 size pattern。
   - **#3 server response to active probe**：對 OpenVPN server 發精心構造 `P_CONTROL_HARD_RESET_CLIENT_V2`，server 在某些 tls-crypt 配置下仍回應。
2. **Two-phase detection framework**：phase 1 passive DPI 過濾、phase 2 active probe 確認；此 framework 之後被 Wu 2023 完整移植到 fully-encrypted protocol 偵測，**成為 GFW 研究新典範**。
3. **ISP-scale 實驗**：與一家 ~1M user ISP partnership，在真實流量上驗證 >85% recall + <0.1% FP。
4. **對所有 tls-crypt 配置（含 v1/v2）測試**：證明現有 OpenVPN 鎧甲均失效。
5. **commercial VPN 服務測試**：對 41 個主流商業 VPN providers，34 個用 OpenVPN-default 配置可被偵測。

## Method
- **passive analysis**：對 OpenVPN 各版本與配置變體的 packet captures 做 byte-level + size-level 統計。
- **active probing**：對若干公開 OpenVPN endpoint 發送各種 fuzz payload，觀察響應。
- **真實流量驗證**：與 ISP 合作，在 mirror 流量上跑兩階段 detector，N 天累計樣本。
- **倫理**：與 USENIX ethics 嚴格協商，所有實驗在 partner ISP 內進行，不主動 probe 第三方 server。

## Results
- OpenVPN 在 nation-state ISP 對手下**結構性失效**——這不是一個 bug 而是 protocol design 缺陷。
- 直接導致 OpenVPN-based 商業 VPN 在中國等對手環境下大規模轉向 WG / SS / VLESS / Hysteria。
- 啟發後續 fully-encrypted protocol detection 研究（Wu 2023）。

## Limitations / what they don't solve
- 不破密碼學——只破 **identifiability**。tunnel 內容仍安全。
- 對 OpenVPN-over-obfuscation（obfsproxy / stunnel / Xray-mux 內包 OpenVPN）不直接適用——但那時等於不是 OpenVPN protocol-level identifiable。
- 對 OpenVPN 3.x（基於 OpenVPN3 library）也部分適用但作者未全面測試。

## How it informs our protocol design
**G6 必須滿足的 design constraints**（每一條都直接來自這篇）：
1. **首封 packet 不能有 fixed-pattern byte**——所有 protocol-identifying bits 必須在 AEAD 內。
2. **packet size sequence 必須是可控的**——day-1 設計 size padding / packet length blending。
3. **server 對任何 invalid packet 沒有可區分 response**——probe resistance is a hard requirement。
4. **不能採用「明文 opcode + AEAD inner」這種折衷**——OpenVPN 就是這樣死的。
5. **two-phase framework 是現代 GFW 偵測的標準**——我們必須對 phase 1 與 phase 2 都有對策。

## Open questions
- 此 framework 對 WireGuard / Trojan / VLESS 的可移植性？（Wu 2023 部分回答；[6.7](../../lessons/part-6-vpn-internals/6.7-wireguard-blocked-china.md) 完整討論。）
- 是否能設計出**正式可證明** probe-resistant 的 protocol？目前的 REALITY、Conjure 都是 ad-hoc。
- ML-based detection 與 deterministic protocol-level detection 的混合，是否會是 nation-state 的下一步？

## References worth following
- Ensafi-Crandall-Winter 2015 IMC（GFW active probing 起源）
- Frolov et al. 2019 USENIX Sec *Conjure*（refraction-based probe resistance）
- Wu et al. 2023 USENIX Sec *fully-encrypted detection*（同 framework）
- Frolov-Wustrow 2019 NDSS *The use of TLS in Censorship Circumvention*（TLS-shape leak）
