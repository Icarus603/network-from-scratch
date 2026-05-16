# The Click Modular Router

**Venue / Year**: ACM Transactions on Computer Systems 18(3), August 2000, pp. 263-297. Earlier version at SOSP 17, December 1999.
**Authors**: Eddie Kohler, Robert Morris, Benjie Chen, John Jannotti, M. Frans Kaashoek (MIT Laboratory for Computer Science)
**Read on**: 2026-05-14 (in lesson 1.1)
**Status**: full PDF (29 pages) at `assets/papers/tocs-2000-kohler-click.pdf` (read pp. 1-12 in detail; pp. 13-29 cover IP router config, extensions, kernel/user-level, evaluation)
**One-line**: 把 router 從 monolithic kernel 重寫成**可組合的 element graph**——160 行 C++ 的 Element class + connection graph 就能描述完整 IP router；DiffServ / RED / multi-queue 等 extension 只要加 1~2 個 element，效能達商用 router 的 4 倍。

## Problem

1990s 末的 router（Cisco IOS / Juniper JunOS / Linux router）有共同問題：

- **Closed**：admin 不能加 feature，只能 toggle config flag
- **Static**：feature 寫死在 kernel，要改就要全 kernel rebuild
- **Inflexible**：第三方軟體要 hook 進 forwarding path 極困難
- **Inextensible**：fundamental 屬性如 packet dropping policy（RED 等）仍在學界 active research，但 production router 改不動

→ 想做新的 forwarding behavior（Differentiated Services、active queue management、tunneling）都很痛苦。

## Contribution

1. **Element 抽象**：每個 packet processing 函數是一個 C++ class（subclass of `Element`）
   - 例：`DecIPTTL`（decrement TTL + checksum）、`Queue`、`Classifier`、`RED`、`IPFragmenter`
   - 每個 element ~120 行 C++
   - 完整 IP router = **16 個 element 連在一起**
2. **Connection 抽象**：element 之間的 directed graph
   - Push 連接：source 主動推 packet 下去（device 收到 packet 後推下去）
   - Pull 連接：sink 主動拉 packet 上來（device 想送 packet 時拉上來）
   - 中間 element 可以是 **agnostic**——根據 connect 的對端是 push 或 pull 自動 specialize
3. **Configuration language**：declarative DSL 描述 router
   ```
   FromDevice(eth0) -> Counter -> Discard;
   ```
   ——一行就是個 router
4. **Flow-based router context**：element 可以動態查詢 packet flow 的下游/上游 elements
   - 例：RED 可以自動找到下游最近的 Queue 來測量 queue length
   - 比 strict layering 更 flexible，比 global naming 更 robust
5. **Hot swap**：router config 可以原子替換而不丟 packet
6. **Performance**：在 700MHz Pentium III 上達 **333,000 packets/second** （64-byte minimum-size），比同 hardware 上的 Linux router 快 4 倍

## Method

### Architecture
- C++ subclass `Element`：~20 virtual functions
- 只 3 個 virtual function 在 runtime path 上：`push` / `pull` / `run_scheduled`
- 其他用於 init / config / introspection

### Concrete IP router (paper's Section 3, Fig 8)
16 個 element forwarding path：
```
FromDevice → Classifier → ARPResponder/Strip
→ CheckIPHeader → GetIPAddress → LookupIPRoute
→ DropBroadcasts → CheckPaint → IPGWOptions
→ FixIPSrc → DecIPTTL → IPFragmenter
→ ARPQuerier → ToDevice
```
Each step is one element.

### Evaluation
- 用 PC + 16 NIC 跟商用 router 對打
- Metric: **maximum loss-free forwarding rate** (Mogul/Ramakrishnan-style)
- 對照組：standard Linux router，modified Linux router (with their device-handling extensions)

### Extensions evaluated
- Random Early Detection (RED) variants — 4 種 RED 只用 1 element
- DiffServ — 加 2 element
- Tunneling — 加 1 element
- Per-flow scheduling

## Results

- **333 Kpps** on 700MHz Pentium III with 64-byte packets, single thread, kernel-mode
- **4× faster** than standard Linux router on same hardware
- 比 modified Linux router（含他們的 driver 改進）也略快——證明 modular 架構**沒有 perf 代價**
- Hot-swap install：50-element config 在 < 0.1 sec 內裝好

## Limitations / what they don't solve

- **Single-thread**：論文時代 single CPU 為主；multi-core/SMP 的 Click 是後續工作（RouteBricks 等）
- **No flow-based scheduling**：每個 element 只能 schedule 自己，不能 per-flow CPU scheduling（後來 ClickNP / FastClick 補上）
- **Kernel module 安全性**：Click 跑在 kernel mode 才有 perf；user mode 慢很多。這跟 eBPF/XDP 的設計取捨對立（XDP 用 verifier 保證 safety）
- **Composability 的代價**：太細的 element 會增加 vfunc call overhead；coarse element 又失去 modularity 好處——「正確的 granularity」是 art not science
- **沒處理 adversarial packets**：Click 假設 packet 是 well-formed；fuzzed/malicious packet 在某些 element 內部解析會 crash
- **沒處理 stateful protocols**：適合 stateless forwarding（IP/L2）；TCP NAT 之類 stateful 處理不是 Click 強項

## How it informs our protocol design

對 Proteus 的**架構級**啟發：

### 1. **Proteus spec 應該模組化成 element**
- 加密 element / 握手 element / 流控 element / 偽裝 element / fallback element
- 每個 element 用 ~200 行寫完
- spec 描述 element 介面 + connection graph，不寫 monolithic state machine

### 2. **與 sing-box / mihomo 的對應**
- sing-box 的 inbound / outbound / route 三段 = Click 思想的 proxy 版本
- 我們協議要設計成**能整合進 sing-box 作為一個 outbound element**
- 這直接影響 Phase III 12.6 客戶端整合

### 3. **Push vs Pull 對應 Phase III 設計**
- Server 接到 GFW 的 active probe → push processing（被動觸發）
- Server 主動傳資料給 client → pull processing（client request 觸發）
- 兩種模式並存的 element graph 設計值得借鑒

### 4. **Hot swap → 0-downtime upgrade**
- Proteus 的 production deployment 應該支援 hot reload
- 機場運維時改 config 不該斷使用者連線
- Click 的 hot swap mechanism 是 reference design

### 5. **Element 的 fine-grained reusability**
- 同一個「TLS 握手 element」可以被 Proteus server / client / GFW simulator / evaluation harness 共用
- 對應 Phase III 11.5 spec 的設計：spec 不只描述「on the wire」，還描述「element interface」

### 6. **Flow-based router context = 跨 element 通信**
- Proteus 的 anti-replay element 可能要查詢 connection state element
- 不要 hardcode pointer，用 flow-based context 讓 element 自動 discover 對方
- 這跟 Crowcroft 警告的「層間 hard-wired interface 出 bug」對齊

## Open questions

- **Click 在 100Gbps NIC 時代的相關性**？2000 年 333 Kpps 是 wonder；2026 年 100GbE 線速要 ~150 Mpps（450× higher）。Click 經 ClickNP / FastClick / DPDK 整合後仍能跟得上嗎？
- **Click + eBPF/XDP 整合**？XDP 是 kernel-side 的「element」式 packet processing；能不能把 Click element 直接編譯成 XDP program？
- **Adversarial Click element**：能不能用 Click 模擬 GFW？把 nDPI / Suricata 包成 element，組成 GFW pipeline——這正是 Phase III 12.x 評測平台該做的
- **Click + 形式化驗證**：每個 element 是 small enough 可以 ProVerif/TLA+ 驗證；組合的 element graph 能否 compositionally 驗證？開放
- **Kohler 後來的工作**：去 UCLA 後 Kohler 主導 multikernel / multicore router (NetMap, ClickNP)；他現在在做什麼跟 Proteus 設計有關？

## References worth following

論文引用中對我們最 relevant：

- **Saltzer-Reed-Clark 1984** End-to-End — 已建檔，是 element 抽象「為什麼 functions should be replaceable」的設計原則
- **Lampson & Sproull 1979** An open operating system for a single-user machine — 「functions should be replaceable」的 OS 版本
- **Clark 1985** The Structuring of Systems Using Upcalls — push vs pull (paper 中 pull = upcall) 的設計概念
- **Hutchinson & Peterson 1991** The x-Kernel — 早期 modular networking system
- **McCanne & Jacobson 1993** BPF — Click user-level driver 用 BPF；同時 BPF 後來發展成 eBPF/XDP
- **Floyd & Jacobson 1993** RED — Click 的 dropping policy element
- **Mogul & Ramakrishnan 1997** Eliminating Receive Livelock — Click 採用其 device polling 方法

延伸：
- **Crowcroft 1992** Is Layering Harmful — 已建檔，Click 是其工程答案
- **RouteBricks** (SOSP 2009) — Click 的 multicore 後續
- **FastClick** (ANCS 2015) — Click + DPDK
- **ClickNP** (SIGCOMM 2016) — Click + FPGA
- **Linux XDP** (CoNEXT 2018) — Click 思想的 kernel 內現代版

## 跨札記連結

- **與 Saltzer 1984**：Click 是 e2e 思想的 router-side 實現——把 function 「placement」變成 dynamic decision，每個 element 可選擇 push/pull 對應 e2e 的 directionality
- **與 Clark 1988**：Click 體現了 Clark 7 priority 中的 "multiple types of service"——同一 router 上同時跑 IP-only forwarding + DiffServ + IPSec tunnel 各成 element graph
- **與 Crowcroft 1992**：Crowcroft 警告 layering 出 perf bug；Click 提出 element graph 取代 strict layer，**避免**了 Crowcroft 描述的層間 boundary effect
- **直接 inform** Phase III 11.5 spec 模組化方式——element interface + connection graph
- **直接 inform** Phase III 12.6 客戶端整合（sing-box plugin 設計繼承 Click）
- **直接 inform** Phase III 12.x GFW 模擬器架構——把 nDPI / Suricata / Zeek 串成 Click-style element graph
- **直接 inform** Phase II 6.4–6.6 wireguard-go 通讀（WireGuard 內部 architecture 也是 element-like）
