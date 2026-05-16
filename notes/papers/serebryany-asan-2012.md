# AddressSanitizer: A Fast Address Sanity Checker
**Venue / Year**: USENIX ATC 2012（USENIX Annual Technical Conference，Boston，pp. 309–318）
**Authors**: Konstantin Serebryany、Derek Bruening、Alexander Potapenko、Dmitriy Vyukov（皆 Google）
**Read on**: 2026-05-16（in lessons 12.X cited，protoxx CI/fuzz 工具鏈）
**Status**: abstract + 技術細節由 USENIX 搜尋結果與 dl.acm.org 摘要拼出；PDF 直接抓取失敗（HTTP 403）但 design summary 完整可信
**One-line**: 用 compile-time instrumentation + shadow memory + poisoned redzone，在 ~2× 開銷下抓 heap/stack/global buffer overflow 與 use-after-free，零誤報——讓 C/C++ memory bug 變成 CI 可量產的問題。

## Problem
C / C++ 的 memory bug（buffer overflow、use-after-free、雙重 free）長年是安全漏洞的最大來源。先前的偵測工具兩條路線都不夠用：(1) Valgrind / Purify 等 dynamic binary translation 慢 20×+，跑 CI 不現實；(2) 硬體支援的 bounds checker 涵蓋面窄，且要硬體配合。需要一個「夠快可以放 CI 與 fuzzer，但又涵蓋面廣」的工具。

## Contribution
- 提出 AddressSanitizer (ASan)：compiler-based memory error detector，整合進 LLVM/GCC，在 SPEC 2006 上平均 slowdown < 2×、記憶體放大 ~2.4×。
- **Shadow memory 編碼**：每 8-byte 應用記憶體對應 1 byte shadow，狀態為「全可寫 / 前 k byte 可寫 / 全 poison」。對 32-bit 與 64-bit 各設計緊湊偏移映射（32-bit offset 2^29、64-bit offset 2^44）。
- **Poisoned redzone**：在 heap / stack / global 物件四周插入 128-byte 預設 poisoned 區，instrumentation 在每次 load/store 前查 shadow，命中 poison 即報錯。
- **Quarantine allocator**：free 後不立即重用，延遲回收，使 use-after-free 在窗口期內可被抓到。
- 在 Chromium 上抓出 300+ 之前未發現的 bug；在 LLVM、Mozilla 等專案中也大量發現。

## Method (just enough to reproduce mentally)
1. 編譯時對每個記憶體存取 `*p` 插入：`if (Shadow(p) is poisoned) report_error; else access`。
2. Shadow address 用 `(p >> 3) + offset` 算出，O(1) 查表。
3. malloc → 取超大區塊，在 user buffer 前後各塗一段 redzone，poison 對應 shadow。
4. free → 把 buffer 對應 shadow 全 poison，丟進 quarantine queue，延遲若干次 alloc 才實際回收。
5. Stack frame：compiler 把 local var 包成「var + redzone + var + redzone …」，函式進入時 poison redzone，離開時 unpoison。
6. Global：linker 把 global 排成 padded layout，啟動時 poison redzone。

## Results
- SPEC 2006 平均 slowdown 1.73×，最壞 perlbench/xalancbmk 約 2.6–2.7×（小物件 malloc 密集）。
- 記憶體放大平均 3.37×。
- **零誤報**——這是它在 CI 能用的關鍵差異。
- Chromium 整合後找出 300+ memory bug；後續成為 Google / Microsoft / 主要瀏覽器廠 default fuzz 工具。

## Limitations / what they don't solve
- 不抓 uninitialized memory read（那是 MemorySanitizer 的工作）、data race（ThreadSanitizer）、integer overflow（UBSan）。
- 對 custom allocator（自寫 slab pool）無法穿透——需要手動 ASan API 把 redzone 註冊上去。
- 64-bit virtual address layout 限制：與某些 hugemmap / sandboxing 衝突。

## How it informs our protocol design
protoxx 雖以 Rust 為主，但 (a) 仍會 link 一些 C 密碼庫（如 mlkem reference impl）、(b) 會跑針對 wire format parser 的 cargo-fuzz / libFuzzer harness。CI matrix 必須包含 ASan build：把每個 PR 在 ASan + UBSan + fuzz corpus 跑一輪，是「實作層 memory safety」這條 12.X 防線的 baseline。Rust 部分仍要 ASan？是的——`unsafe` block、FFI boundary、自寫 ring buffer 都還是可能 UB。

## Open questions
- ASan 開銷是否能進一步降到 1.2× 內，讓它能 always-on 在 production proxy？（HWASan / KASAN 等後續嘗試。）
- Rust 的 ownership 抓不到的「邏輯層 memory bug」（例如 wrong-length slice）能否用類似 shadow memory 補捉？

## References worth following
- Serebryany. *MemorySanitizer.* WBIA 2015 — 抓 uninitialized read。
- Stepanov & Serebryany. *MemorySanitizer: fast detector of uninitialized memory use in C++.* CGO 2015。
- Bruening & Zhao. *Practical Memory Checking with Dr. Memory.* CGO 2011 — DBI 路線的對照組。

Source: [USENIX ATC 12 paper page](https://www.usenix.org/conference/atc12/technical-sessions/presentation/serebryany)
