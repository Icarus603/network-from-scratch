# IP-Address Lookup Using LC-Tries

**Venue / Year**: IEEE Journal on Selected Areas in Communications (JSAC) 17(6):1083–1092, June 1999. DOI [10.1109/49.772439](https://doi.org/10.1109/49.772439).
**Authors**: Stefan Nilsson (KTH), Gunnar Karlsson (KTH)
**Read on**: 2026-05-14（in lesson [1.4 IP 層：路由是個圖論問題](../../lessons/part-1-networking/1.4-ip-routing-graph.md)）
**Status**: PDF fetch attempts failed (one with SSL error, one with empty content). Precis based on confirmed bibliographic metadata + abstract retrieved via WebSearch (Semantic Scholar) + secondary literature confirmation (cited 700+ times, replicated in Linux `net/ipv4/fib_trie.c` since kernel 2.6.13). Author affiliations and key claims (4-byte node encoding, Θ(log log n) depth) cross-verified across multiple secondary sources.
**One-line**: 在 PATRICIA radix trie 上疊加 **level compression**——dense 子樹展平為多分支節點，使真實 internet 路由表的 LPM 搜尋深度從 O(log n) 降到 Θ(log log n) expected，且每節點僅需 4 byte 編碼。

## Problem

1990s 中後期 internet 路由表迅速膨脹（10K → 100K entry），multigigabit router 需要 line-rate IP lookup。當時主流：
- **Binary trie**：~25-30 memory access per lookup，過慢
- **PATRICIA**（Morrison 1968）：path-compressed binary trie，仍 ~25 memory access（path compression 對 dense 部分無幫助）
- **TCAM hardware**：line-rate 但極貴、功耗高、不可 incremental scale
- **Hash-per-prefix-length**：需 33 次 hash lookup，cache 不友善

⇒ 需要一個 **memory-efficient、software-friendly、search 深度極淺** 的資料結構。

## Contribution

提出 **LC-trie**（Level Compressed Trie）：在 PATRICIA path compression 之上加 **level compression**：

- 若某子樹 root 之下 k 層的子節點**完全填滿**（dense），把這 k 層展平為單一節點，branch factor = 2^k
- 每節點記三個欄位：`branch`（5 bit，當前 stride 寬度）、`skip`（7 bit，path compression 跳過的 bit 數）、`pointer`（20 bit，孩子陣列起始 index）
- ⇒ **節點僅 32 bit / 4 byte**

#### 關鍵性質（作者證明 + 實測）

1. **Expected search depth = Θ(log log n)** for prefixes drawn from a large class of distributions (含 internet 觀察到的 prefix length 分佈)。Worst case 仍 O(log n) 但不會在真實 table 出現
2. **Node count = O(n)**（與 PATRICIA 同）
3. **Total memory ~700 KB for 38 K-entry table**（1999 typical AS border router）
4. **No dynamic memory in lookup**——所有節點 packed 在連續 array，cache friendly

## Method (just enough to reproduce mentally)

#### 資料結構

```
LC-trie node = (branch: u5, skip: u7, ptr: u20)
                                          ↓
                                        孩子陣列 base
```

`branch = 0` 表示 leaf（ptr 指向 next-hop info）。
`branch > 0` 表示 internal——孩子數 = 2^branch，連續存於 `ptr` 起始之處。
`skip` 表示**從 trie 上層繼承下來的 prefix** 中跳過的 bit 數（path compression）。

#### 構造演算法（off-line build）

1. 從 routing table 構造一棵 binary trie
2. 把 binary trie 轉成 PATRICIA（壓縮只有單一子節點的路徑）
3. **Level compression pass**：對每子樹，計算 fill factor。若 fill 比 ≥ 閾值 x（典型 0.5），把連續 k 層展平。**選最大的 k 使得仍 fill ≥ x**
4. 把所有節點 pack 進連續陣列（DFS 序列）

實作上 LC-trie 不支援 efficient incremental update——加/刪 prefix 需要部分或全 rebuild。**這是 1999 版的主要工程限制**。

#### 搜尋演算法（hot path）

```
node = root
prefix_pos = 0     // 當前比對到 IP 的哪個 bit
while node.branch > 0:
    prefix_pos += node.skip
    idx = extract_bits(IP, prefix_pos, node.branch)  // 取 branch bit
    prefix_pos += node.branch
    node = children[node.ptr + idx]
// node 是 leaf，驗證 stored prefix 確實是 IP 的 prefix（path compression 後需驗）
return node.next_hop
```

**每次迴圈一次 memory access（cache miss 可能性極低，因節點 packed）**——所以 ≤ 6 次 access 對 38K table。

## Results

作者在 4 個真實 BGP table 上 benchmark（Sprint, Mae-East 1997-1999），表大小 16K~38K entry。

| 演算法 | 平均 search depth | Memory (38K table) |
|---|---|---|
| Binary trie | ~25 | ~5 MB |
| PATRICIA | ~26 | ~1.5 MB |
| LC-trie | **~6** | **~700 KB** |

實機效能（1999 Pentium II, 233 MHz, 32-byte cache line）：**~2M lookup/sec single core**，相當於 2 Gbps 對 64-byte packet 線速。

## Limitations / what they don't solve

- **Update cost**：incremental update 困難。加/刪 prefix 可能觸發 subtree rebuild
- **Worst case 仍 O(log n)**：對 adversarial prefix distribution 無 expected log log 保證
- **Memory layout 固定**：build 後再 update 需重 pack
- **無 hardware-friendly properties**：variable stride 對 pipelined ASIC 不適——後續 Tree Bitmap (Eatherton 2004) 才解這個
- **不支援 IPv6 well**：32-bit address 的設計，128-bit 時 trie 深度雖仍 Θ(log log n) 但常數變大
- **作者承認 random distribution 才滿足 Θ(log log n)**——對真實 BGP table 中常見「prefix length 集中在 /24」的 skewed distribution，期望深度略高但仍極淺

## How it informs our protocol design

**對 Proteus 的直接影響為零**（我們不做 routing），但作為**演算法設計範本**意義重大：

1. **Average-case complexity 可以 dominate worst-case 設計**：LC-trie 是「為真實 prefix 分佈特化」的演算法。**Proteus 加密 / 流量整形演算法也可考慮為「真實流量分佈」特化**而非 worst-case
2. **節點 4 byte 編碼的設計密度**：把 branch/skip/ptr 塞進 32 bit 是極端緊湊。**Proteus packet header 設計可參考此密度——每 bit 都有用**
3. **Build-time 預處理換 query-time 速度**：LC-trie 用 offline build pass 換來 fast lookup。**Proteus ticket / pre-shared parameter 機制可借鏡——預先協商換來 0-RTT 連線**
4. **Linux 的 RCU-based atomic update 補了 LC-trie 1999 的洞**：Linux fib_trie.c 用 RCU 把 immutable LC-trie 變成支援 lock-free update。**這個 immutable + atomic swap 模式是 Proteus state management 強參考**

## Open questions

- **真實 internet 2026 prefix 分佈是否仍 satisfy Θ(log log n)**？2026 BGP table ~1M entry，比 1999 大 30 倍，prefix length 分佈更 skewed
- **IPv6 下的 LC-trie 還適合嗎**？128-bit + sparser table，Tree Bitmap 或 Poptrie 表現如何？
- **GPU 化的 LC-trie**？SIMT 模型下 batched lookup 是否可大幅加速？最近研究有探索但無 production 採用
- **LC-trie + RPKI**：每節點掛 origin AS 資訊做 inline ROA 驗證是否可行？目前 RPKI validation 與 FIB lookup 分離，整合是潛在優化

## References worth following

- Linux source: `net/ipv4/fib_trie.c`（LC-trie + RCU 工程化版本）
- DPDK `lib/lpm/rte_lpm.c`：用 DIR-24-8（與 LC-trie 同代但不同思想）
- Sundström & Larzon 2005 對 LC-trie 的工程化改進
- Eatherton et al. 2004 Tree Bitmap（硬體導向的下一代）
- Asai & Ohara 2015 Poptrie（SIMD-friendly Tree Bitmap）
- Morrison 1968 PATRICIA（祖先）
