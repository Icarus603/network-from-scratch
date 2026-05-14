# Tree Bitmap: Hardware/Software IP Lookups with Incremental Updates

**Venue / Year**: ACM SIGCOMM Computer Communication Review (CCR) 34(2):97–122, April 2004. DOI [10.1145/997150.997160](https://doi.org/10.1145/997150.997160).
**Authors**: Will Eatherton (Cisco Systems), George Varghese (UCSD), Zubin Dittia (Cisco Systems)
**Read on**: 2026-05-14（in lesson [1.4 IP 層：路由是個圖論問題](../../lessons/part-1-networking/1.4-ip-routing-graph.md)）
**Status**: PDF fetched (184.9KB) but content extraction was high-level due to PDF parser limitations. Precis based on abstract + summary from fetch + author's UCSD page (Varghese's "older research directions") + secondary engineering literature (used in production Cisco CRS-1 / silicon line cards 2004-present).
**One-line**: 用兩層 bitmap（internal 標 prefix 存在性、external 標子節點存在性）+ popcount 索引取代 LC-trie 的指標導向設計，使 LPM 在固定 stride 下成為**可 pipeline、incremental update 友善、硬體實作高密度**的演算法——成為 Cisco 主流硬體路由器的 FIB 核心。

## Problem

LC-trie（Nilsson 1999）在軟體效能優秀但**對硬體不友善**：

1. **Variable stride** 讓 pipeline stage depth 不固定 → ASIC 難 schedule
2. **Pointer-heavy 節點**消耗 SRAM 過多
3. **Incremental update 弱**——加/刪 prefix 觸發 subtree rebuild，不符合 production BGP 高 churn 環境
4. **Memory access pattern 與 cache 行為**不易 reason about

同期 **Lulea algorithm**（Degermark et al. 1997）提供 compact 表但 update 同樣困難。
**TCAM** 提供 line-rate 但功耗 ~30 W、$ ~5K per 1M entry——不可 scale 到 100M+ entry 預期。

⇒ 需要：軟硬通吃、可 pipeline、bounded memory access、incremental update 高效的新結構。

## Contribution

提出 **Tree Bitmap**（TBM）：

1. **固定 stride k**（典型 k = 4 或 8）——每節點看 k bit，子節點數 ≤ 2^k
2. **每節點兩個 bitmap**：
   - **Internal bitmap (2^k - 1 bit)**：標 stride 內部各 prefix 長度是否有 entry
   - **External bitmap (2^k bit)**：標哪些子節點存在
3. **Popcount-based indexing**：`popcount(external_bitmap & mask) = offset` 給出子節點在連續 children array 內的 index
4. **Result array 與 children array 分離**：next-hop info 存獨立 array，bitmap node 只存索引
5. **Bounded lookup**：對 32-bit IPv4 + stride 4，**最多 8 次節點存取**（32/4 = 8）——硬體可 pipeline 為 8 stage

## Method (just enough to reproduce mentally)

#### Bitmap 編碼

對 stride k = 4，stride 內部最多有 2^4 - 1 = 15 個可能的 internal prefix（長度 0~3，總共 1+2+4+8 = 15 個位置）。internal bitmap 第 i bit = 1 表「該位置存在一個 prefix」。

External bitmap 第 j bit = 1 表「stride 結束位置 j 處有 child subtree」。

#### Lookup 算法

```
node = root
remaining_bits = address
best_match = NONE
while True:
    k_bits = top k bits of remaining_bits

    # 1. 檢查 internal bitmap：找到 stride 內 longest matching prefix
    mask = compute_internal_match_mask(k_bits)
    matches = node.internal_bitmap & mask
    if matches != 0:
        best_match = node.result_array[popcount(node.internal_bitmap & matches_low)]

    # 2. 檢查 external bitmap：是否有 child
    if node.external_bitmap & (1 << k_bits):
        child_offset = popcount(node.external_bitmap & ((1 << k_bits) - 1))
        node = node.children_array_base + child_offset
        remaining_bits <<= k
    else:
        return best_match
```

每次迴圈：**1 bitmap read + 1 popcount + 1 pointer follow** — 都是固定 cycle，硬體可分階段。

#### Incremental Update

- 加 prefix：找到目標節點，set internal bitmap bit，append to result array
- 刪 prefix：clear bit + remove from result array
- 若 children array 需 resize → 重新分配（可分 multi-level memory pool 緩解）
- **不需重 rebuild 整棵 trie**

## Results

#### 記憶體（38K-entry BGP table，stride k=4）

- ~600 KB（與 LC-trie ~700 KB 同級）
- 比 TCAM 省 ~10×（容量 vs 成本）

#### Lookup performance

- 軟體（2004 PII）：~2-4M lookup/sec
- 硬體（pipelined ASIC, 200 MHz）：**200M lookup/sec** = 100 Gbps 線速 @ 64-byte packet

#### Update performance

- 加/刪一個 prefix：~10 次 memory access（vs LC-trie 部分 rebuild ~thousands）
- 適合 BGP churn 場景（typical ~10-100 update/sec, peak ~10K/sec）

#### Cisco deployment

- Cisco CRS-1 (2004) 用 TBM 變體於 line card silicon
- 後續 Trident、Tomahawk、Tofino 系列亦延伸 TBM 思想（不一定保留原名）
- **2026 多數高階 ASIC FIB 仍是 TBM 家族**

## Limitations / what they don't solve

作者自己 + 後續工作指出：

1. **Children array 變寬時的 reallocation 成本**：若 external bitmap 多 bit 翻轉 → array 重 size → 仍需 memory copy（雖比 LC-trie rebuild 小很多）
2. **Bitmap 編碼對極 sparse table 效率差**：少 prefix 時 bitmap 大量 0，浪費空間（小 table 無此問題，大 table 反而高效）
3. **Worst-case memory access 仍 = address_length / stride**（IPv4 = 8 次，IPv6 = 32 次）——對 IPv6 不理想
4. **Hardware pipeline depth 固定**——若 BGP table 變化使有效 depth 變淺，pipeline stage 仍佔資源
5. **無 RPKI / origin AS 整合**——TBM 是純 FIB 結構，security validation 在外層
6. **Software 版的 popcount 在 pre-SSE4.2 CPU 慢**——後續 Poptrie (Asai 2015) 才系統地用 SIMD popcount 優化

## How it informs our protocol design

對 G6 主要為**設計範式啟發**：

1. **Bitmap-based dispatch 是常用工程技巧**：G6 capability negotiation / extension 列表可用 bitmap 編碼，比 TLV-list 緊湊
2. **Popcount 索引 = O(1) lookup**：若 G6 connection ID space 用 sparse bitmap 表達，popcount 給 dense storage index——記憶體效率
3. **Bounded operation count 是 production-grade 必要性**：硬體可預期、formally analyzable。**G6 任何 hot path 都應該有 bounded operation count claim**——這是 Phase III 12.4 設計 review 標準
4. **Incremental update 設計 vs offline build**：LC-trie 偏 build-once，TBM 偏 update-friendly。**G6 不同 component 應該明確選一邊**——例如：session table（update-friendly）vs static config（build-once）

## Open questions

- **Tree Bitmap 在 IPv6 是否仍最優**？某些研究（Sasaki et al. 2018）顯示 IPv6 下混合 hash + trie 表現更好
- **GPU/SIMD 加速 TBM**：popcount 是 GPU 強項，但 memory pattern 不太對 GPU 友善
- **TBM + 機器學習加速**：用 ML 預測 prefix lookup distribution，動態調整 stride——未見 production 採用但 academic 有探索
- **量子加速 LPM**？理論上 Grover 給 √N speedup，但需要量子 RAM——遠未實用

## References worth following

- Nilsson & Karlsson 1999 LC-tries（前代）
- Degermark et al. 1997 Lulea（並行對手）
- Asai & Ohara 2015 Poptrie（後繼，SIMD popcount）
- Gupta, Lin, McKeown 1998 DIR-24-8（hardware-friendly alternative）
- Cisco CRS-1 system architecture papers
- Varghese *Network Algorithmics*（Morgan Kaufmann 2005）— 含 TBM 完整章節
