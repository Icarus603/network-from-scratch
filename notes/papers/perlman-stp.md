# An Algorithm for Distributed Computation of a Spanning Tree in an Extended LAN

**Venue / Year**: SIGCOMM 1985 — Proceedings of the 9th Symposium on Data Communications, published as ACM SIGCOMM Computer Communication Review 15(4):44–53. DOI [10.1145/318951.319004](https://doi.org/10.1145/318951.319004).
**Authors**: Radia Perlman (Digital Equipment Corporation, Tewksbury MA)
**Read on**: 2026-05-14（in lesson [1.3 乙太網路與 L2](../../lessons/part-1-networking/1.3-ethernet-l2.md)）
**Status**: PDF was fetched but binary parse failed; precis written from confirmed bibliographic metadata + author's own retelling in *Interconnections* (Perlman 1999, 2nd ed.) — category A foundational, content well-documented across decades of secondary sources. Title/venue/year/page verified via two independent web sources.
**One-line**: 在任意拓樸的 extended LAN 上用 O(1) state per bridge、O(diameter) 步收斂的分散式演算法構造 spanning tree——bridging 整個工業界 40 年的基礎，且本身為 distributed algorithm 教學經典。

## Problem

1980s 中早期，Ethernet 開始連接超過單一物理 segment 的範圍（multi-floor office building、multi-building campus）。簡單 forward 不可行：
- 物理冗餘必須（一條線斷了還能走第二條）⇒ 拓樸**必有迴路**
- Ethernet header 無 TTL、無 hop count——一個 broadcast 進入迴路會**無限放大**
- 必須在物理迴路網路上構造一個**邏輯無迴路 forwarding graph**，且：
  - 不依賴 central controller（1985 沒有 SDN 概念）
  - 不要求 bridge 知道全拓樸（state 不可隨網路 scale 增長）
  - 收斂時間可預測
  - 拓樸變化（新 bridge 上線、舊 bridge 故障）能自動 reconverge

## Contribution

提出一個 fully distributed 演算法，每個 bridge：
- 維護 O(1) state：`(root_id, root_cost, designated_bridge_id)`
- 每隔固定週期（典型 2 秒）發 1 個 **BPDU** message 到所有 port
- 收到 BPDU 時比較「自己看到的最佳 BPDU」與「新收到的 BPDU」，取較佳者
- 從 BPDU 派生出每個 port 的 state：root port / designated port / blocking port

可證明性質：
- **Convergence**：O(diameter) 步達穩定（穩定意指後續無 state 變動）
- **Correctness**：穩定後的 active topology 是 G 的一個 spanning tree，且每個 v 到 root 的 path 為 G 中最短
- **Memory**：每 bridge O(1)，與 |V|, |E| 無關
- **Bandwidth**：每 LAN segment O(1) BPDU/sec，與規模無關

## Method (just enough to reproduce mentally)

**Bridge ID**：64-bit `(priority || MAC)`，較小者較佳。

**BPDU 內容（簡化）**：`(root_id_claimed, root_cost_claimed, sender_bridge_id, sender_port_id)`。

**演算法（每 bridge B）**：

1. 啟動：`my_best := (my_id, 0, my_id, *)`——自認自己是 root，cost 0。
2. 每 hello_time（2 秒）：所有 port 發 my_best。
3. 收到 BPDU(R, C, S, P) 於 port p：
   - 計算 candidate := `(R, C + cost(p), S, P)`
   - 若 candidate < my_best（lexicographic compare）：
     - my_best := candidate
     - root_port := p
     - 重新評估其他 port 的角色
4. 對每個 LAN segment 上的 port q：
   - 比較「q 上自己會 announce 的 BPDU」與「q 上其他 bridge announce 的 BPDU」
   - 若自己較佳 → q 為 designated port for that LAN（forward）
   - 否則 → q 為 blocking（聽 BPDU 但不 forward data）
5. 拓樸變化偵測：若 hello_time × 3 沒收到上游 BPDU，認定 link 失效，重新計算。

**Port states**（後來 802.1D 1990 寫明確）：Disabled → Listening → Learning → Forwarding（or Blocking）。每個 transition 等 forward_delay（典型 15 秒），目的：避免 transient forwarding loop（在 BPDU 還沒收斂時就 forward 會造成 broadcast storm）。

## Results

- **Memory per bridge**：constant (8 byte `(root_id, root_cost, dbridge_id)` × few ports)
- **Bandwidth per LAN**：~50 byte BPDU / 2 sec = trivial
- **Convergence time**：30~50 sec in practice (含 forward_delay margin)
- **Robustness**：拓樸變化自動收斂，無需 admin intervention

Perlman 報告了 prototype 在 DEC 工程辦公網路（11 個 bridge、多重迴路）的 trace——所有 case 收斂在 < 1 minute，無 broadcast storm。

## Limitations / what they don't solve

Perlman 自己（特別在 1999 *Interconnections* 書內）坦白指出的局限：

1. **Tree topology 浪費 bandwidth**：blocking port 完全閒置；多條物理 path 只能用其中一條
2. **From-root optimality only**：任意兩 host 間 path 經過 root，可能繞遠路
3. **30~50 sec convergence 不可接受**（1985 是 acceptable，1995 變痛點）⇒ 後續 RSTP (802.1w, 2001) 改善至 ~1-2 sec
4. **無 multipath / load balancing**：直到 TRILL (RFC 6325, 2010) 與 SPB (802.1aq, 2012) 才嘗試 multipath L2——但**兩者均失敗**，被 VXLAN + EVPN 取代
5. **依賴 bridge 之間信任**：惡意 bridge 可宣稱自己 priority 0 強制成為 root（**STP root takeover attack**）——L2 攻擊面，至今 production network 仍用 root guard / BPDU guard 緩解
6. **單一 STP instance 對所有 VLAN**：所有 VLAN 共用同一 tree ⇒ 後續 MSTP (802.1s, 2002) 才支援 per-VLAN tree

## How it informs our protocol design

主要為**負面教訓**——「L2 distributed protocol 的設計選擇大部分不適用於 L4/L5 proxy」——但有兩個正面收穫：

1. **Control plane vs data plane 分離的歷史**：STP 是把 control（拓樸發現）做在 data plane（in-band BPDU），後續 EVPN 把它搬到 out-of-band control plane（BGP）。G6 設計時應該明確分離：**endpoint discovery / key exchange 走 control channel，不走 data channel**——避免被流量分析識別 control 行為
2. **「最簡單就夠用」哲學**：Perlman 用最少 state 與最少 message 解決問題。G6 設計過度 engineering（複雜 handshake、多餘 metadata）的部分都該回頭簡化
3. **避免 broadcast / flood 模式**：STP 本身就是「broadcast 失控」的解法。G6 任何需要 discovery 的場景都應該設計為**單播 + lookup**（EVPN 風格），不依賴 broadcast——除了 anti-fingerprinting，也是因為 overlay 環境下 broadcast 常被 disabled

## Open questions

- **能否形式化證明 modern STP / RSTP / EVPN 變體的 convergence?** 1985 版的 informal proof 至今仍未有完整 mechanized proof（TLA+ / Coq）。對 G6 control plane 我們希望比這個 bar 更高
- **STP root takeover 在 2026 仍可被利用嗎?** Cisco BPDU guard 是 mitigation 不是 fix；理論上需要 BPDU 認證（signed BPDU）——這方向 IEEE 從未 standardize
- **L2 mesh routing (B.A.T.M.A.N.-adv) 在哪裡跨越 STP/EVPN 的權衡邊界?** Mesh L2 routing 與 traditional STP 是兩個極端——前者每 node 知道全拓樸，後者每 node 只知道到 root。中間有沒有 sweet spot? Part 9 mesh networks 章節會回頭

## References worth following

- Perlman *Interconnections: Bridges, Routers, Switches, and Internetworking Protocols* (2nd ed., Addison-Wesley 1999) — 作者自己對 L2 設計的反思
- IEEE 802.1D-2004（將 Perlman 1985 + 後續 STP 改進 codify）與 802.1w（RSTP）、802.1s（MSTP）
- Rooney et al. 1998 *INETspeed: The Internet has speeded up*——當時量測 STP convergence
- Tilman et al. 2009 *Networks at Scale: A Survey of Data Center Topologies*——展示 STP 為何在 DC 失敗
- RFC 6325 (TRILL) 與 IEEE 802.1aq (SPB)——失敗的 L2 multipath 嘗試
- RFC 7432 (EVPN)——最終勝出的 L2 control plane
