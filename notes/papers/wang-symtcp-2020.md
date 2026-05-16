# SymTCP: Eluding Stateful Deep Packet Inspection with Automated Discrepancy Discovery

**Venue / Year**: NDSS 2020
**Authors**: Zhongjie Wang, Shitong Zhu, Yue Cao, Zhiyun Qian, Chengyu Song, Srikanth V. Krishnamurthy, Kevin S. Chan, Tracy D. Braun
**Read on**: 2026-05-16（in lesson [[1.8-tcp-connection-mgmt]] 引用）
**Status**: 主要從 NDSS 官方 PDF 摘要 + WebFetch 內容擷取；具體 discrepancies 例子需後續精讀完整 PDF
**One-line**: 用 symbolic execution 自動找 end-host TCP stack 與 DPI box 狀態機之間的解讀差異——只要兩者對「這個 packet 該被當什麼」答案不同，就有 evasion。

## Problem
- Stateful DPI（Snort、Zeek、GFW 的 TCP reassembly engine）要在 stream-level 重組 TCP packet 才能對 application payload 做 pattern match / fingerprint。
- 重組需要實作完整 TCP 狀態機；但 DPI 與真實 OS TCP stack 的實作**不可能完全一致**——SACK semantics、PAWS、Christmas tree flag、reordering buffer 大小、SYN-data behavior 等都有實作差異。
- 攻擊面：構造一個 packet sequence，讓 **DPI 認為某個 byte 是 X，但 end-host 認為是 Y** → application 層收到的東西不被 DPI 看見。

## Threat Model
- 對手：可以發 packet 通過 DPI 到 end-host 的 attacker（censor 視角：可以從牆內發 packet 到牆外 server）。
- 假設：DPI 是 on-path stateful，但實作未必 perfect compliance。
- 目標：讓 application-layer payload 被 end-host 接收但被 DPI 漏掉（即 DPI 重組成不同 byte stream）。

## Contribution
1. **方法論**：把 Linux kernel TCP code path 用 KLEE-like symbolic execution 探索，發現所有「DPI 與 Linux 行為分歧」的 input。
2. **自動化**：不靠人工 fuzz——symbolic exec 提供完整覆蓋的 evasion strategy 庫。
3. **Evasion 庫**：產出可直接套用到 censorship circumvention 與 IDS evasion 的具體 packet 構造模式。

## Method
- 對 Linux TCP stack 做 path-sensitive symbolic execution：每個 packet 從 `tcp_v4_rcv` 到 socket buffer 的分支被分支地探索。
- 對 DPI（如 Snort、Zeek、GFW 模型）做相同分析。
- **Discrepancy = state divergence**：找到一條 input sequence，使兩邊狀態機到達不同 final state。
- 自動產生 PCAP 與測試腳本，並對 Snort / Zeek / GFW（live test）驗證。

## Results
- **Snort**：發現多類 evasion strategies（具體數字需查全文）。
- **Zeek**：同樣 vulnerable。
- **GFW**：對 live GFW 測試成功 evade keyword filter 多種觀察 pattern。
- **代表 evasion 類**（概念性，需 PDF 詳查）：
  - In-window RST manipulation（DPI 認為 connection 終止，end-host 不認）
  - Bogus retransmit with overlap（DPI 與 end-host 對 overlap 區段 priority 規則不同）
  - URG pointer + TCP segment reassembly edge case
  - PAWS / timestamp 不同步

## Limitations
- Symbolic exec 對 Linux kernel 的 path coverage 仍受 timeout / state explosion 限制。
- 找到的 evasion 是 **per-DPI-version**：DPI 廠商可 patch 個別 discrepancies。
- 未涵蓋 hardware-accelerated DPI（FPGA-based）。
- Evasion 通常需 attacker 與 victim 雙邊配合 packet 生成——不像 fronting 那種 transparent 方案。

## How it informs our protocol design
**G6 的 anti-DPI 設計直接相關**：
1. **不只是 payload 加密**：即便整個 G6 流量都加密，TCP layer 仍可被 GFW 用「state divergence active probe」識別（Wang 2020 的工具就能用來生成這種 probe）。
2. **G6 server 應**：
   - 用 vanilla Linux TCP stack（最常見 → DPI 對它最熟悉，但也是 evasion 工具庫最豐富）；或
   - 用 specialized userspace stack（[[marinos-network-stack-specialization-2014]]）——但 stack 本身的 idiosyncratic behavior 變成新 fingerprint surface。
3. **G6 client 應**：避免使用可被 SymTCP-style discrepancy 識別的 TCP option 組合；TFO、PAWS、Selective ACK 的開啟組合需 Part 11 設計時考慮。
4. **更深 implication**：依賴 TCP 作 transport → 必然繼承 TCP discrepancy attack surface。**QUIC over UDP 把這層攻擊面消除**（QUIC 端對端加密所有 transport state）—— 這是 Part 8.x QUIC protocol 課與 Part 11.3 transport 選擇的論證主軸之一。

## Open questions
- 對 QUIC：QUIC 的 connection ID + packet number encoding 是否有類似 discrepancy？目前 quic-go / quinn / mvfst 實作差異對 DPI 識別影響？
- 對抗式 ML DPI（不依賴 strict state machine 而用 flow embedding 分類）：SymTCP 的方法是否還適用？
- Defender 可否反過來用 SymTCP 找 DPI 自身 bug 並 patch？

## References worth following
- Cao et al., **Off-Path TCP Exploits** (USENIX Sec 2016) — CVE-2016-5696 [[cao-tcp-side-channel]]
- Feng et al., **IPID side channel** (CCS 2020)
- Bock et al., **Geneva** (CCS 2019) — automated discovery of censor middlebox evasions
- Bock et al., **Weaponizing Middleboxes for TCP Reflected Amplification** (USENIX Sec 2021)
- 後續 [[1.6-icmp-deep]] 引用的 Ensafi GFW probing 工作 [[ensafi-gfw-probing]]
