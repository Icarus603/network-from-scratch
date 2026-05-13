# VPN / 代理 完整理論課程大綱

> **學員**：Icarus（網路非專業，零理論基礎，但已能用 ccb 搭建 VPS 機場 + Clash Verge Rev 客戶端）
> **教師**：Claude（在這個 repo 裡長期授課）
> **目標**：從「能用」到「理解原理」到「能自己設計一個翻牆協議」
> **語言**：繁體中文授課，技術術語保留英文原文
> **形式**：純授課文本（不依賴外部教科書），配少量「打開終端看一眼」的小練習，不寫程式直到 Part 10
> **節奏**：你決定。一堂課大約 15~30 分鐘閱讀量，所有圖示用 ASCII / Mermaid，可在終端看

---

## 整體結構（10 個 Part，共 ~60 堂課）

| Part | 主題 | 堂數 | 你學完能回答 |
|---|---|---|---|
| **0** | 定向與心智模型 | 3 | 「我每天用的『VPN』到底是不是 VPN？」 |
| **1** | 網路基礎五大概念 | 6 | 「一個封包從我筆電到 Google 經過了什麼？」 |
| **2** | 傳輸層與應用層 | 7 | 「為什麼 Hysteria 比 SS 在丟包時順？」 |
| **3** | 密碼學與 TLS | 6 | 「TLS 1.3 握手裡 SNI 為什麼是個大問題？」 |
| **4** | 作業系統的網路堆疊 | 6 | 「Clash 的 TUN Mode 點下去發生了什麼？」 |
| **5** | 真 VPN 協議家族 | 5 | 「為什麼 WireGuard 是設計上的勝利？」 |
| **6** | 代理協議家族（翻牆系） | 8 | 「SS → VMess → Trojan → VLESS+REALITY 為什麼一直在演化？」 |
| **7** | 機場（一鍵腳本）解剖 | 5 | 「我用 ccb 搭出來的東西，每個元件在做什麼？」 |
| **8** | 客戶端與規則引擎 | 5 | 「Clash 設定檔每一行我都能講出設計理由」 |
| **9** | 審查對抗與流量分析 | 4 | 「GFW 怎麼識別代理？協議怎麼躲？」 |
| **10** | 設計你自己的協議 | 5 | 「我能寫出一份協議規格書並用 Go 實作 MVP」 |

---

# Part 0 — 定向與心智模型

> **目的**：把你腦中既有的「VPN / 翻牆 / 代理 / 機場」這堆混在一起的詞拆乾淨，建立後續所有學習的座標系。

### 0.1 「VPN」這個詞被誤用了 30 年
- 真 VPN（Virtual **Private Network**）的原始定義：把兩個遠端網路「合併」成一個私有網路。
- 商業 VPN 服務商（NordVPN 之類）做的事：「加密代理」+ 賣「翻牆」當賣點。
- 中文圈翻牆生態（你在玩的）：**根本不是 VPN，是加密代理 + 規則分流**。
- 三者的設計目標、威脅模型、技術選型完全不同——本課會把三條線都教，但你要知道分界。

### 0.2 我們這門課的學習地圖
- 用一張 ASCII 圖把 10 個 Part 串起來，讓你隨時知道「我現在在地圖哪裡」。
- 解釋為什麼順序是「網路 → 密碼 → OS → 真 VPN → 代理 → 機場 → 客戶端 → 對抗 → 設計」。

### 0.3 給零基礎的學習契約
- 每堂課的固定結構：**動機 → 概念 → 圖示 → 小練習 → 自我檢查問題 → 與你經驗的連結**。
- 我會反覆把新概念**掛回你已經會用的 Clash 設定**上（這是你最強的錨點）。
- 不懂就問，**問得「笨」沒關係**——這是你的學習筆記，不是論文。

---

# Part 1 — 網路基礎五大概念

> **目的**：建立「封包是如何從一台電腦到另一台」的物理直覺。後面所有東西都是這個問題的變奏。

### 1.1 分層（Layering）：為什麼要分層？
- 一個歷史悲劇：早期網路每換一種媒介就得重寫整套軟體。
- 分層的好處用「郵局比喻」講：信封 / 郵局 / 卡車 / 高速公路，誰換了不影響別人。
- OSI 七層 vs TCP/IP 四層 的真實意義（**OSI 是教學模型，TCP/IP 是現實**）。

### 1.2 封裝（Encapsulation）：VPN 的本體就是這四個字
- 一個 HTTP 請求 → TCP 段 → IP 封包 → 乙太網路框架。
- ASCII 拆解一個真實封包的每一層 header。
- **關鍵頓悟**：「VPN 就是在外面再多包一層」「代理就是改最外層的目的地」。

### 1.3 位址系統：MAC / IP / Port / Domain
- 為什麼一台電腦需要四種「名字」？
- 各自在哪一層、解決什麼問題。
- 私有 IP 範圍（`10.0.0.0/8` / `172.16.0.0/12` / `192.168.0.0/16`）為什麼存在。

### 1.4 路由（Routing）：封包如何「走」
- 路由器的工作：看目的 IP，查路由表，決定下一跳，**僅此而已**。
- 路由表怎麼讀（用 macOS `netstat -rn` 真實輸出講）。
- 「預設路由 `default` / `0.0.0.0/0`」為什麼是 VPN 全局模式的命門。

### 1.5 名字與位址的解析：DNS 與 ARP
- DNS 遞迴查詢全流程（root → TLD → authoritative）。
- DNS 為什麼是明文、為什麼會被污染、DoH/DoT/DoQ 在解什麼。
- ARP：在本地網段把 IP 換成 MAC——你之後會看到「ARP 欺騙」是無數攻擊的起點。

### 1.6 把它串起來：「打開 google.com 的 30 毫秒」
- 一場慢動作回放：從你按 Enter 開始，到頁面顯示，發生了**幾十次**封包來回。
- 帶你看：DNS 查詢 → TCP 三次握手 → TLS 握手 → HTTP 請求 → 渲染。
- 這堂結束你應該能畫出整張流程圖。**這是 Part 1 的期末考。**

---

# Part 2 — 傳輸層與應用層

> **目的**：把 TCP / UDP / HTTP / DNS 這四個你天天碰但從沒看過內部的東西打開。

### 2.1 TCP：可靠傳輸是怎麼「假裝」出來的
- IP 是不可靠的（會丟、會亂序、會重複），TCP 在它之上「演」出可靠。
- 三次握手：為什麼三次不是兩次（防止舊的 SYN 復活）。
- 四次揮手 + TIME_WAIT：為什麼伺服器重啟有時得等兩分鐘。
- 序號、ACK、重傳、滑動窗口——用「兩個人傳紙條」的故事講。

### 2.2 TCP 擁塞控制：網路為什麼會「堵車」
- AIMD（加性增、乘性減）的直覺。
- Reno / Cubic / **BBR**：為什麼 Hysteria 自己重做擁塞控制。
- **Bufferbloat**：為什麼你家路由器太貴反而更卡。

### 2.3 UDP：什麼都不做的快樂
- UDP header 只有 8 bytes，對比 TCP 的 20+。
- 無連線、無順序、無重傳——所有「自己重做傳輸層」的協議都建在它上。
- DNS、QUIC、WireGuard、Hysteria 為什麼都選 UDP。

### 2.4 QUIC：建在 UDP 上的「下一代 TCP」
- 為什麼 Google 要重新發明傳輸層（TCP 已經僵化在 OS kernel 裡）。
- QUIC = TLS 1.3 + 多工 + 0-RTT + 連線遷移。
- HTTP/3 就是 HTTP over QUIC。
- **為什麼這對翻牆特別重要**：QUIC 流量看起來就像普通 HTTPS，難封鎖。

### 2.5 HTTP/1.1 / 2 / 3：同一個語意，三種傳輸
- HTTP/1.1 的隊頭阻塞（head-of-line blocking）。
- HTTP/2 的多工（multiplexing）和 server push。
- HTTP/3 解決了什麼新問題、為什麼又出現新的隊頭阻塞。

### 2.6 DNS 深入
- 記錄類型：A / AAAA / CNAME / MX / TXT / SRV / HTTPS。
- 解析器（resolver）vs 權威伺服器（authoritative）。
- DNS 污染、DNS 劫持、DNS 洩漏——為什麼 Clash 要有複雜的 `dns:` 段。
- `fake-ip` 模式為什麼能加速、又為什麼會搞壞某些 app。

### 2.7 套接字（Socket）：所有網路程式的入口
- Socket 是 OS 給應用程式的「插座」抽象。
- TCP socket vs UDP socket 在系統呼叫上的差別。
- 為什麼一個 port 同時可以被多個連線使用（五元組：src IP, src Port, dst IP, dst Port, protocol）。

---

# Part 3 — 密碼學與 TLS

> **目的**：你不需要會密碼學的數學，但你必須能用「分類學」一眼認出每個協議用了什麼工具。

### 3.1 密碼學的最小分類學
- 三大類工具：對稱加密 / 非對稱加密 / 雜湊。
- 對稱：AES、ChaCha20——快、雙方共享同一把鑰匙、解決「機密性」。
- 非對稱：RSA、ECDH、Ed25519——慢、解決「金鑰交換」與「身份驗證」。
- 雜湊：SHA-256、BLAKE2、BLAKE3——單向、解決「完整性」。

### 3.2 AEAD：現代加密的事實標準
- 為什麼「光加密不行」——你還需要證明「沒被改過」。
- AEAD = Authenticated Encryption with Associated Data。
- AES-GCM vs ChaCha20-Poly1305：硬體加速 vs 軟體效能。
- Shadowsocks、WireGuard、TLS 1.3 為什麼全用 AEAD。

### 3.3 金鑰交換：兩個陌生人如何在公開頻道商定密碼
- Diffie-Hellman 的「混色比喻」——這個比喻是密碼學教學界的傳家寶。
- ECDH（橢圓曲線版）：為什麼用 Curve25519。
- **前向保密（PFS）**：為什麼長期金鑰洩漏不該影響歷史流量。

### 3.4 公鑰基礎設施（PKI）與證書
- 證書到底是什麼？答：**一個被 CA 簽名的「公鑰 + 身份」聲明**。
- CA 信任鏈為什麼能成立，又為什麼是個社會工程災難。
- Let's Encrypt 怎麼讓 HTTPS 普及、ACME 協議的工作流程。
- 自簽憑證 vs 真實憑證——你機場的 Trojan/VLESS 用哪一種、為什麼。

### 3.5 TLS 1.3 握手 ⭐
- 完整握手流程（一個封包一個封包帶你看）。
- ClientHello 裡的關鍵欄位：**SNI、ALPN、cipher suites、key share**。
- 0-RTT 為什麼好、又為什麼有重放攻擊風險。
- **為什麼 SNI 是審查的命門**——你看這節就懂為什麼後面 REALITY 要造假 SNI。

### 3.6 Noise Protocol Framework
- WireGuard 用的金鑰交換框架，比 TLS 簡潔十倍。
- IK / XK / NK 等模式的命名規則。
- 為什麼「無狀態握手」對 VPN 特別重要。

---

# Part 4 — 作業系統的網路堆疊

> **目的**：你 Clash 點「TUN Mode」那一秒，OS 內部發生什麼？

### 4.1 從 Socket 到網卡：封包在 kernel 的旅程
- 應用程式 `write()` 之後，封包經過：socket buffer → TCP/IP stack → qdisc → driver → NIC。
- 收包反過來。
- 為什麼這趟旅程是「中斷驅動」的。

### 4.2 路由表與規則路由（policy routing）
- 路由表細讀：destination / gateway / flags / interface。
- macOS 與 Linux 的差異。
- **多路由表 / policy routing**：Linux 的 `ip rule`、macOS 的限制。
- VPN 全局 vs 分流 在路由表上的真實表現。

### 4.3 TUN / TAP：用戶態程式如何「假扮」成網卡 ⭐
- TUN（L3，收發 IP 封包）vs TAP（L2，收發乙太網路框架）。
- macOS 的 `utun`、Linux 的 `/dev/net/tun`。
- WireGuard、Clash TUN Mode、sing-box `tun-in`、tun2socks——**全是這個機制**。
- 一張流程圖：封包如何被「劫持」進你的 Clash 程式再送出去。

### 4.4 防火牆與 NAT：pf / iptables / nftables
- 包過濾（packet filter）的概念。
- macOS `pf` 語法簡介（不必精通，懂得讀就好）。
- Linux `iptables` 五張表（filter / nat / mangle / raw / security）的設計。
- **NAT 三種類型**（Full Cone / Restricted / Symmetric）為什麼影響 P2P。

### 4.5 macOS 上的網路特色
- `scutil --dns` 讀系統 DNS 設定（跟 Linux 的 `/etc/resolv.conf` 差很多）。
- System Extension 與 Network Extension（為什麼某些 VPN app 要你輸密碼）。
- `utun` 編號規則、為什麼 Clash 開了之後你看到 `utun4 / utun5`。

### 4.6 Linux 的「網路命名空間（netns）」
- 把一個 process 關進獨立的網路堆疊。
- Docker、K8s 網路、現代 VPN 客戶端隔離的基礎。
- 為什麼 macOS **沒有對等物**（這點要老實講）。

---

# Part 5 — 真 VPN 協議家族

> **目的**：在進入翻牆協議前，先把「正統」VPN 學完。學完這 part 你就知道 Clash 玩的是另一條路。

### 5.1 VPN 的本體：在 L3 加密通道
- 為什麼 VPN 要在 L3：為了能「合併網段」。
- 站對站（site-to-site）vs 遠端存取（remote access）。
- Split tunneling vs full tunneling：Clash 的「規則模式」其實就是 split tunneling 的一種。

### 5.2 IPsec / IKEv2：企業級老大哥
- ESP / AH / SA 三個核心概念。
- IKEv2 兩階段協商。
- 為什麼配置噩夢——一個 RFC 引另一個 RFC，引到天邊。
- 蘋果生態為什麼偏愛 IKEv2（iOS 內建支援）。

### 5.3 OpenVPN：建在 TLS 上的 VPN
- 用 TLS 做控制通道、用自己的協議做資料通道。
- TCP 模式 vs UDP 模式。
- 為什麼配置文件一堆 `--xxx` 參數、`.ovpn` 是怎麼長出來的。
- 為什麼曾被 GFW 識別封鎖（特徵明顯）。

### 5.4 WireGuard ⭐ 設計上的勝利
- whitepaper 精讀（12 頁，本課會逐段拆解）。
- 為什麼「無 cipher 協商」是優點（OpenVPN/IPsec 的協商複雜度 = 攻擊面）。
- Curve25519 + ChaCha20-Poly1305 + BLAKE2s + Noise IK：一套到底。
- 「Cryptokey Routing」概念：peer 的公鑰**就是**身份。
- 為什麼 macOS 上要用 `wireguard-go`（userspace），Linux 卻在 kernel。

### 5.5 三者對比表
- 加密、握手、配置複雜度、效能、被識別風險、行動端體驗。
- **為什麼 WireGuard 不是翻牆首選**（特徵太明顯、純 UDP 易封）。
- 這節也會解釋「為什麼商業 VPN 還在用 OpenVPN/IKEv2」（相容性 + 不需要躲審查）。

---

# Part 6 — 代理協議家族（翻牆系）

> **目的**：你機場跑的就是這條線。按演化順序講，看到「為什麼要發明下一個」的張力。

### 6.1 HTTP CONNECT 與 SOCKS5（RFC 1928）：所有代理的祖宗
- HTTP 代理的 GET 模式 vs CONNECT 模式。
- SOCKS5 完整握手流程（auth → request → reply）。
- 為什麼「沒加密」在 2008 年還能用、現在不行。
- Clash 同時開 HTTP / SOCKS5 入站 port——這節學完你就懂在做什麼。

### 6.2 Shadowsocks：把 SOCKS5 加密
- 起源故事（clowwindy 與 GFW 的軍備競賽）。
- 第一代設計缺陷（流加密 + 無認證 → 被主動探測打爆）。
- AEAD 改版（2017）的設計變化。
- **SS-2022（AEAD-2022）**：當前最現代版本，固定金鑰、防重放、user-key 分離。

### 6.3 V2Ray / VMess
- 為什麼從 SS 跳到 VMess：要使用者驗證、要多傳輸層。
- VMess 認證機制（時間敏感的 alterID，後來廢除）。
- **傳輸層抽象**：TCP / mKCP / WebSocket / HTTP/2 / gRPC / QUIC。
- 為什麼 WebSocket + TLS + Nginx 反代 成為機場黃金組合。

### 6.4 Trojan：哲學翻轉
- 不混淆，**直接偽裝成 HTTPS**。
- 設計極簡：握完 TLS 後第一個 byte 是密碼，對就轉發、錯就「丟給 fallback 網站」。
- 為什麼 fallback 網站要是個真實能瀏覽的網頁。
- 對 GFW 主動探測的天然抗性。

### 6.5 VLESS + XTLS / REALITY ⭐ 當前最前沿
- VLESS：把 VMess 的加密層去掉（反正外面有 TLS）。
- XTLS-Vision：把內層 TLS 直接「直通」，省一層加密。
- **REALITY**：不用自己的證書，**借用真實大網站的 TLS 握手**——連主動探測都裝不出破綻。
- 設計細節：怎麼借、為什麼不會被識破、限制在哪。

### 6.6 Hysteria / Hysteria2 / TUIC：QUIC 系
- 為什麼又一波協議跑去 UDP。
- Hysteria 的 BBR-based 自訂擁塞控制（賭高丟包網路）。
- TUIC v5 的設計選擇。
- 為什麼這幾個在「家寬出國線路差」場景特別香。

### 6.7 Naïve / Snell / 其他小眾
- 簡介式介紹，知道生態還有什麼。
- 各自解決的細分問題。

### 6.8 sing-box / mihomo（Clash.Meta）：協議大一統核心
- 為什麼最後大家收斂到「一個核心跑所有協議」。
- 入站（inbound）/ 出站（outbound）/ 路由（route）三段架構。
- 你的 Clash Verge Rev 底下跑的是哪個？怎麼看？

---

# Part 7 — 機場（一鍵腳本）解剖

> **目的**：你用 ccb 一鍵搭出來的東西，每個元件在做什麼？這一 part 是給你「服務端」的視角。

### 7.1 機場的標準服務端架構
- 一個典型節點：**入口（443）→ TLS 終結 → 協議解碼 → 出口轉發**。
- Nginx / Caddy 反代的角色：分流 `/ws-vmess` 給 v2ray、其他給 fallback 網站。
- 為什麼要套一個 CDN（Cloudflare）：隱藏真實 IP、套一層 TLS 指紋偽裝。

### 7.2 ccb / x-ui / 3x-ui / Marzban 這些一鍵腳本到底裝了什麼
- 拆解：核心程序（xray/sing-box）+ Web 面板 + 反代 + 證書自動化（acme.sh / certbot）+ systemd 服務。
- 為什麼一個 VPS 能跑十幾個協議在同一個 443 port 上（**SNI / ALPN / path 分流**）。
- 訂閱（subscription）格式：`ss://`, `vmess://`, `vless://`, `trojan://` 的 base64 結構。

### 7.3 證書與域名
- 為什麼機場要綁域名（Trojan/VLESS 沒域名就跑不起來）。
- acme.sh 自動申請 Let's Encrypt 流程。
- DNS-01 vs HTTP-01 驗證的差別。

### 7.4 多入口 / 多出口 / 中轉
- 「中轉節點」的概念（落地 IP 與入口 IP 分離）。
- 為什麼有「BGP 中轉」「IEPL 專線」這些行話。
- 分流到 Cloudflare Workers / WARP 出去的玩法。

### 7.5 你的訂閱檔解剖
- 真的把你訂閱檔的某一個節點拆開（使用範例，不讀你 confidential/）。
- 每個欄位（`server` / `port` / `uuid` / `tls.sni` / `transport.path` / `flow`）對應前面學的哪個概念。

---

# Part 8 — 客戶端與規則引擎

> **目的**：把 Clash Verge Rev 從「黑盒子」變「玻璃盒」。

### 8.1 Clash 系核心的內部架構
- mihomo（Clash.Meta）三段：**inbound → matcher（rule engine）→ outbound**。
- 為什麼能同時開 HTTP / SOCKS5 / TUN / TProxy / Mixed 入站。
- 連線生命週期完整追蹤。

### 8.2 規則引擎（Rule Engine）
- 規則類型：DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR / GEOIP / GEOSITE / PROCESS-NAME / RULE-SET。
- 匹配順序（從上到下、第一個命中即停）。
- `MATCH` 兜底規則的重要性。
- 為什麼「規則越長不一定越慢」（rule-set + mph 索引）。

### 8.3 代理組（Proxy Group）
- `select` / `url-test` / `fallback` / `load-balance` / `relay` 各自的語意。
- 嵌套代理組的設計模式。
- 為什麼「自動選擇」測速會誤判。

### 8.4 DNS 段：Clash 最複雜的 50 行
- `enhanced-mode`: `redir-host` vs `fake-ip` 的根本差別。
- `nameserver` / `fallback` / `nameserver-policy` 各自何時觸發。
- 為什麼會「DNS 洩漏」、Clash 怎麼防。
- `fake-ip-filter` 為什麼要配（某些 app 會壞）。

### 8.5 TUN Mode 的全景
- 點下 TUN 那一秒：建立 utun → 改路由表 → 接管全部流量 → tun2socks → 規則引擎 → outbound。
- macOS 上需要的權限、為什麼第一次開要輸密碼。
- TUN Mode vs 系統代理 vs Enhanced Mode 的取捨。

---

# Part 9 — 審查對抗與流量分析

> **目的**：理解「為什麼一年要換一次協議」。這是整門課的高潮。

### 9.1 GFW 怎麼工作（公開研究綜述）
- 旁路 vs 在路徑上（on-path vs in-path）的差異。
- DNS 污染、IP 封鎖、TCP RST 注入、SNI 黑名單。
- 引用 GFW.report 的關鍵發現。

### 9.2 深度封包檢測（DPI）與流量指紋
- 協議識別：靠 magic bytes、靠握手指紋、靠統計特徵。
- **JA3 / JA4**：TLS ClientHello 指紋技術。
- 為什麼「裝得像 Chrome」是現代代理的剛需（uTLS 庫）。
- 機器學習流量分類（封包大小、時序、burst pattern）。

### 9.3 主動探測（Active Probing）
- GFW 對可疑 IP 主動送奇怪封包，看你怎麼回。
- Shadowsocks 早期被打爆的歷史。
- Trojan 用「fallback 網站」抗探測的設計巧思。
- REALITY 為什麼是「主動探測終結者」。

### 9.4 域前置 / SNI 偽造 / ECH
- Domain Fronting 的興衰（Google/AWS 為何關閉）。
- ECH（Encrypted Client Hello）：把 SNI 也加密，TLS 1.3 的最後一塊拼圖。
- ECH 部署現況（Cloudflare 已支援，但⋯⋯）。

---

# Part 10 — 設計你自己的協議

> **目的**：把前 9 part 學的東西匯流，**和我（ccb 輔助）一起設計並實作一個你自己的代理協議**。
> **這是動手 part，會開始寫程式（Go），但每一行都會解釋。**

### 10.1 需求分析：你的協議要解決什麼問題？
- 引導式提問：你最在意效能、抗封鎖、還是簡潔？
- 寫一份「設計目標 / 非目標 / 威脅模型」文件。

### 10.2 協議規格書（Spec）撰寫
- 學 RFC 風格寫一份 `SPEC.md`：握手、frame 格式、狀態機、錯誤處理。
- 用 ASCII 圖畫出 frame layout（像 RFC 那樣）。

### 10.3 MVP 實作（Go）
- 在這個 repo 開 `projects/myproto-go/`。
- 一個最小可跑的 client + server，走 TCP，先不加密。
- 跑通「瀏覽器 → SOCKS5 → myproto client → myproto server → 目標網站」。

### 10.4 加上 TLS 偽裝
- 套一層 TLS（用 Trojan 思路）。
- 加 fallback 網站。
- 對著 wireshark 看流量像不像普通 HTTPS。

### 10.5 對抗測試與下一步
- 用 nDPI / Zeek 嘗試識別自己的協議。
- 列出「如果要對抗 GFW，下一步該加什麼」（uTLS、流量整形、padding⋯⋯）。
- 寫一篇結業心得 `lessons-learned.md`。

---

## 附錄：教學基礎建設

### A. 每堂課文件結構模板
每堂課都用統一結構，方便你日後翻找：
```markdown
# 課堂 X.Y — 標題

## 學前知道
- 前置課：...
- 預計閱讀時間：...

## 動機
為什麼要學這個？

## 核心概念
（主體內容，配 ASCII / Mermaid 圖）

## 與你經驗的連結
這對應你 Clash 設定的哪一段？

## 小練習
（一兩個終端指令觀察題，不寫程式）

## 自我檢查
3~5 個問題，能答出來就過關。

## 延伸（可跳過）
更深入的話題與外部閱讀。
```

### B. 術語表（`glossary.md`）
- 每堂首次出現的術語會自動加入術語表。
- 之後出現只用簡稱 + 連結，不重複解釋。

### C. 隨堂答疑（`qa/`）
- 你在學習過程中問的「不在大綱裡」的問題，我會把問答存成 `qa/YYYY-MM-DD-topic.md`。
- 不污染主課程結構，但能 grep 翻找。

### D. 進度與你的節奏
- 你決定一週上幾堂。
- 每堂結束我會問你「自我檢查通過了嗎？」沒過我們重講或加練習。
- **學完整門課的合理節奏：3~6 個月**。比想像中快——因為你已經有實作直覺，只是缺名字。

---

## 開課儀式

當你說「開始第 0.1 堂」時，我會：
1. 在 `lessons/part-0-orientation/` 下生成 `0.1-vpn-misnomer.md`
2. 按上面的「課堂文件結構模板」寫滿
3. 把新術語寫進 `glossary.md`
4. 在這個 SYLLABUS.md 的對應條目旁加上 ✅

準備好了就告訴我。
