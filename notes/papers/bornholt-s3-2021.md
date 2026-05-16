# Using Lightweight Formal Methods to Validate a Key-Value Storage Node in Amazon S3
**Venue / Year**: SOSP 2021（28th ACM Symposium on Operating Systems Principles，Best Paper Award），DOI 10.1145/3477132.3483540
**Authors**: James Bornholt、Rajeev Joshi、Vytautas Astrauskas、Brendan Cully、Bernhard Kragl、Seth Markle、Kyle Sauri、Drew Schleit、Grant Slatton、Serdar Tasiran、Jacob Van Geffen、Andrew Warfield（Amazon Web Services）
**Read on**: 2026-05-16（in lessons 12.X cited，protoxx CI 與 reference model 的工程範本）
**Status**: full content via Amazon Science page + Murat Buffalo summary + SOSP slides；PDF metadata 確認
**One-line**: 在 S3 ShardStore（>40K LoC Rust）上不做 full verification，改用「reference model + property-based testing + stateless model checking」三段組合：把可驗的部分自動驗、可測的部分自動測；落地後攔下 16 個會進 production 的 bug——展示 lightweight formal methods 在持續開發團隊中真的工作。

## Problem
工業界要採用形式方法的最大障礙：(a) full verification（Coq、Isabelle）週期太長，跟不上 feature 開發；(b) 純靠 unit test 抓不到 crash consistency / concurrency 等 subtle bug；(c) 大部分 SWE 不是形式方法專家。S3 ShardStore 是新的 LSM-tree-based KV storage node，要 (i) crash consistent（不靠 WAL，靠 soft updates）、(ii) 高並行、(iii) 持續演進。怎麼讓正確性保證跟得上 release cadence？

## Contribution
- **Reference model 範式**：對 ShardStore 每個 component 寫一個 **同語言（Rust）、同 API 介面、極簡實作** 的 reference model（如 `ReferenceIndex` 用 HashMap 取代真正的 LSM-tree）。它**就是 specification**——可執行、可被 unit test 直接 mock 進去。
- **三段分治**對 crash + concurrency 屬性的拆分：
  1. **Sequential crash-free**：proptest 檢 impl 是否 refine reference model。
  2. **Sequential crashing**：refine reference model 標出「crash 後哪些資料可丟」，再 proptest。
  3. **Concurrent crash-free**：stateless model checking（Loom + Shuttle）。
  4. Concurrent + crashing 留 future work。
- **工具鏈**：proptest（property-based testing in Rust）、Loom（CDSChecker 風格的 sound bounded model checker）、Shuttle（隨機 interleaving，scale 較大但 unsound）。
- **可被非形式方法專家延伸**：reference model 用 Rust，與 production code 同 repo、同 review process；engineer 加新 feature 同時寫 reference 更新。
- **量化結果**：方法論在開發週期中**攔下 16 個會 escape 到 production 的 bug**，包括 crash consistency 與並行 race。

## Method (just enough to reproduce mentally)
1. **Reference model**：對每個 component（Index、Log、ShardStore top-level）寫一個簡化 Rust 實作，作 mock。`ReferenceIndex` 用 `HashMap<ShardId, ChunkLocator>` 取代 LSM-tree。
2. **Property-based test**：定義 operation enum `IndexOp = Get | Put | Delete | Reclaim | Reboot`；proptest 生成 random sequence，分別 apply 到 impl 與 reference，檢查 observable output 相等。
3. **Crash model**：在 sequence 中隨機插入 crash point，模擬 disk 中可能的中間狀態；reference model 提供「crash 後 valid state set」predicate；proptest 檢 impl 的 crash recovery 落在該 set 內。
4. **Concurrent model checking**：對關鍵 lock-free primitive（sharded RwLock）用 Loom sound 檢查所有 interleaving；對大型 end-to-end harness 用 Shuttle 隨機 interleaving、跑數萬次。
5. **CI 整合**：所有檢查跑在每個 PR；reference model 與 production code 同一個 review。

## Results
- ShardStore 上線前在 CI 攔下 16 個 escape-class bug。
- 涵蓋 component 範圍廣（Index、Log、recovery、concurrent primitives）。
- 非形式方法 engineer 也能 follow pattern 加新 property——這是 paper 的核心 social claim。
- ShardStore 進入 production 後成為 S3 的關鍵儲存節點實作。

## Limitations / what they don't solve
- 不做 deep functional verification（不證 LSM-tree algorithm 的正確性，只證 impl refine reference）。
- Concurrent + crash 的組合留 future work。
- Reference model 本身可能有 bug——這個風險靠「reference 極簡」與「reference 直接被 unit test mock」緩解，但理論上仍是 TCB。
- 不抓 timing 漏洞、不抓 spec 與用戶期望的 mismatch。

## How it informs our protocol design
這是 protoxx **「lightweight formal methods 在工程上怎麼落地」最直接的範本**：
1. **每個 protoxx core component 配一個 reference model**：handshake state machine、AEAD record layer、Frame parser、congestion controller 各一個。用同樣 Rust 寫、放在 `protoxx/reference/`，CI 跑 conformance test。
2. **Crash model 對應到 network**：把 ShardStore 的「crash 後 valid state」對應到 protoxx 的「packet loss / reorder 後 valid state」。proptest 在 wire 上注入 loss/reorder/duplicate，檢查 impl 與 reference 仍同步。
3. **Concurrent**：QUIC stream 多路並行的 race 用 Loom（對 sharded congestion state）或 Shuttle（對 end-to-end stress）跑。
4. **可被「非形式方法 review」**：reference model 本身就是文件——任何 reviewer 不需懂 Tarski 也能讀 Rust。這是 12.X 的工程哲學。

## Open questions
- 對 protoxx 而言，reference model 與 Tamarin / ProVerif spec 是否該自動互生？目前是兩套人工同步。
- 在 lossy network 場景下，soft updates 的 storage assumptions 是否直接對映 packet ordering？

## References worth following
- Joshi, Lamport, et al. *Stateless Model Checking with PolyAML.* 系列 — 並行驗證理論基礎。
- Newcombe et al. *How Amazon Web Services Uses Formal Methods.* CACM 2015 — AWS 早期 TLA+ 使用回顧。
- Wilcox et al. *Verdi: A framework for implementing and formally verifying distributed systems.* PLDI 2015 — 同主題的 heavy-weight 對照。

Source: [Amazon Science publication page](https://www.amazon.science/publications/using-lightweight-formal-methods-to-validate-a-key-value-storage-node-in-amazon-s3), [Paper PDF](https://assets.amazon.science/77/5e/4a7c238f4ce890efdc325df83263/using-lightweight-formal-methods-to-validate-a-key-value-storage-node-in-amazon-s3-2.pdf), [SOSP 2021 talk](https://www.youtube.com/watch?v=YdxvOPenjWI)
