# REALITY — protocol spec + threat model

**Source**:
- README (中/英): https://github.com/XTLS/REALITY (`README.zh.md` 在當前 main 已 404，內容併入 `README.en.md`)
- Xray-core 實作：
  - `transport/internet/reality/reality.go`
  - `transport/internet/reality/config.go`
  - 上述兩檔 import 的 `github.com/xtls/reality`（伺服器側真正的 handshake / fallback 邏輯）
- 社群討論：XTLS/Xray-core Issues #2768、Discussion #2233、Discussion #3269（Iran 阻斷實測）
- 第三方解析：ObjShadow blog `how-reality-works`、DeepWiki `XTLS/Xray-examples` REALITY deep dive
- GFW.report 背景：`gfw.report/blog/v2ray_weaknesses/en/`（REALITY 設計動機之一，VMess 主動探測歷史）

**Fetched**: 2026-05-16 (for lessons 7.10, 7.11, 7.12)

## Threat model

REALITY 的對手是 **on-path 主動探測 + SNI/IP 白名單型** 審查者（典型範例：GFW、Iran 的 MCI）。具體要防：

1. **Active probing → certificate-chain 攻擊**：審查者連到可疑伺服器，要求一個合法的 server certificate；常規 self-signed proxy 會立刻露餡。
2. **Server TLS fingerprint**：傳統 proxy 自簽 TLS，server-side JA3S/憑證鏈可區分。
3. **SNI whitelist + 有 cert pinning 的中間人**：例如福建移動 2022 起部署的「只放行白名單域名 TLS、其餘 reset」策略。
4. **MITM redirect of ClientHello**：審查者把 ClientHello 重導去白名單真站，比對是否同一憑證。

REALITY **不防**：traffic-volume 統計分析、TLS-in-TLS packet-length 指紋（除非搭配 XTLS-Vision 流控）、被 port-forwarding 行為分類器掃出（見 §Known weaknesses）。它是**TLS handshake-level 隱蔽**，不是流量混淆。

形式化威脅模型對應：Dolev-Yao 中的 active on-path adversary，但**無法 enumerate 出 distribution channel 上分發的 X25519 公鑰**（鑰匙以帶外方式給 client，類似 obfs4 node-id + pubkey 的信任假設）。

## Wire-format / handshake

REALITY 把 auth-key 藏在 **TLS 1.3 ClientHello 的 SessionID 欄位**（32 bytes）裡，對審查者看起來就是一次標準 TLS 1.3 對白名單目標站的握手。

**Client (UClient, `reality.go:121-238`)**:

1. 用 uTLS 假冒指紋（預設 chrome）建 TLS 1.3 ClientHello。
2. 強制 `SessionId = make([]byte, 32)`。前 16 bytes 編碼為：
   - `[0:3]`：Xray version（`core.Version_x/y/z`）；`[3]=0`。
   - `[4:8]`：Unix timestamp (BE uint32)。
   - `[8:16]`：`config.ShortId`（8 bytes）。
3. 從 ClientHello 的 `KeyShare` 取出 client X25519 ECDHE 私鑰，與 `config.PublicKey`（伺服器靜態 X25519 公鑰）做 ECDH，得 shared secret。
4. `HKDF-SHA256(shared, salt=hello.Random[:20], info="REALITY")` → `AuthKey`。
5. `AES-GCM(AuthKey)` 以 `hello.Random[20:]`（12 bytes）為 nonce，**對 SessionID 前 16 bytes 做 AEAD-Seal**，AAD = 整個 `hello.Raw`。密文（含 16-byte tag）寫回 SessionID（總長 32 bytes）。
6. 送出 ClientHello。

**Server (`github.com/xtls/reality` 套件，未在 xray-core repo)**:

1. 解析 ClientHello，取出 SessionID 與 client X25519 公鑰。
2. 用伺服器 `PrivateKey` 與 client pubkey 做 ECDH，HKDF 同樣派生 `AuthKey`。
3. 試 AEAD-Open SessionID。
4. **失敗 → fallback**：把整條 TCP 連線**透明轉發到 `Dest`**（真實白名單站，如 `dl.google.com:443`）。審查者拿到的就是真站的真憑證，無法區分。
5. **成功 → 檢查**：
   - timestamp 與本機 `time.Now()` 差距 < `MaxTimeDiff`（防 replay）。
   - `ShortId ∈ ServerNames` 對應的合法集合。
   - client 版本介於 `[MinClientVer, MaxClientVer]`。
   - SNI ∈ `ServerNames`。
6. 通過後，**伺服器自簽臨時憑證**並用 `HMAC-SHA512(AuthKey, server_pubkey_ed25519)` 做簽章；client 在 `VerifyPeerCertificate` (`reality.go:76-119`) 驗 HMAC，匹配則 `Verified = true`，後續走真正的 VLESS+XTLS 流量。
7. 若客戶端發現 `!Verified`（收到的是真站憑證），說明發生 MITM/redirect，啟動 **SpiderX**：開 goroutine 對白名單站發 HTTP/2 請求假裝是普通瀏覽，蒐集 `href=` 路徑做更多偽裝請求（`reality.go:179-235`），最後回 `errors.New("REALITY: processed invalid connection")`。

## Critical fields

**Server-side** (`Config.GetREALITYConfig`, `config.go:16-59`)：
- `Dest`：fallback 目標，握手失敗時透明 forward 到此。**必填**，格式同 VLESS fallbacks 的 dest。
- `Xver`：PROXY protocol 版本（0/1/2）。
- `PrivateKey`：X25519 私鑰（32 bytes）。`xray x25519` 產生。
- `ServerNames`：合法 SNI 集合，client 必須挑其中之一作為 ClientHello SNI。
- `ShortIds`：8-byte ID 集合，多 client 區分用；空字串視為一個 zero-fill ID。
- `MaxTimeDiff`：timestamp 容差（毫秒）。
- `MinClientVer`/`MaxClientVer`：限縮 client 版本。
- `Mldsa65Seed`：可選，啟用 ML-DSA-65 後量子簽名強化憑證驗證。
- `LimitFallbackUpload/Download`：fallback 後的速率限制（防審查者用 fallback 通道做 DoS 或流量放大偵測）。
- `MasterKeyLog`：debug 用 TLS master key dump（**生產環境必須關閉**）。

**Client-side** (`Config` struct in xray-core，欄位散落於 protobuf 定義)：
- `ServerName`：要發送的 SNI（必須在伺服器的 `ServerNames` 集合裡）。
- `Fingerprint`：uTLS 模仿哪個瀏覽器，預設 `chrome`，可選 `firefox`/`safari`/`ios`/`edge`/`360`/`qq`/`random`。
- `PublicKey`：伺服器 X25519 公鑰。
- `ShortId`：對應的 8-byte ID（hex 字串）。
- `SpiderX`：MITM 時偽裝 HTTP 爬蟲的初始 path。
- `Mldsa65Verify`：可選，後量子簽名驗證公鑰。

## Known weaknesses (community-reported)

1. **TLS-in-TLS packet-length 指紋**（README 自己承認）：REALITY 只解決 handshake；若 inner 載荷是另一層 TLS（trojan/ss + TLS），雙層加密的 record 大小分布可區分。XTLS-Vision 流控設計上把 inner TLS record 直接 splice，避免雙重加密，是配套必備。
2. **流量體積/CPU spike 偵測**（Iran 實測，Discussion #3269）：高流量 VPS 在 ~2 小時內被 GFW/MCI 標記後封 IP，低流量 VPS 可活一週以上。推測 GFW 對「白名單域名但流量 profile 不像真實 web」做統計學偵測。
3. **Port-forwarding 行為**（Issue #2768 討論）：對審查者來說 REALITY 結構就是 port forward，若採用激進策略阻斷所有 port forwarding 即可全滅。
4. **SNI/DNS 重設攻擊**：Iran 系統對 `discord.com` 等 SNI 強制把 dest 改為 Cloudflare 真實 IP，使 client 無法觸到真正的 REALITY server——選 `Dest` 時要避開 GFW/MCI 會 SNI rewrite 的域名。
5. **同機共存弱協議**：REALITY 與 vanilla VMess/SS 共置同一 IP，弱協議被偵測時整個 IP 被連坐。
6. **SpiderX 行為本身可指紋化**：MITM 後的 HTTP 爬蟲流量（`href=` 正則匹配 + 隨機 cookie padding）若被審查者長期觀測，本身就是 REALITY 的副指紋。

## Source of truth (code citation with line numbers)

- `transport/internet/reality/reality.go:121-238` — `UClient`：ClientHello 構造、SessionID AEAD 封裝、SpiderX MITM 偽裝路徑。
- `transport/internet/reality/reality.go:142-173` — SessionID 的 16-byte payload 佈局（version / timestamp / shortId）與 `aead.Seal`。
- `transport/internet/reality/reality.go:155-168` — X25519 ECDH + HKDF 派生 `AuthKey`。
- `transport/internet/reality/reality.go:76-119` — `VerifyPeerCertificate`：HMAC-SHA512(AuthKey, ed25519_pubkey) 驗證 + 可選 ML-DSA-65 後量子驗證。
- `transport/internet/reality/reality.go:179-235` — fallback / SpiderX HTTP 爬蟲。
- `transport/internet/reality/reality.go:52-55` — `Server()` wrapper，真正的 fallback 邏輯在外部 `github.com/xtls/reality` 套件（**待補：拉該 repo 寫第二份 spec**）。
- `transport/internet/reality/config.go:16-59` — `GetREALITYConfig`：把 protobuf `Config` 轉成 `reality.Config`，所有 server 欄位映射在此。
- `transport/internet/reality/config.go:50-57` — `ServerNames` / `ShortIds` 從 list 轉成 `map[string]bool` / `map[[8]byte]bool`，O(1) 查表。
