# The First Collision for Full SHA-1 (SHAttered)
**Venue / Year**: CRYPTO 2017
**Authors**: Marc Stevens, Elie Bursztein, Pierre Karpman, Ange Albertini, Yarik Markov
**Read on**: 2026-05-14 (in lesson 3.3)
**Status**: abstract-only（shattered.io 站 2026 年 PDF 鏡像 server-side rate limit 阻擋；引用內容綜合自 IACR proceedings + Google security blog + 訓練資料）。
**One-line**: 用 ~6500 CPU-years + 110 GPU-years 算出兩個不同 PDF 文檔具有相同 SHA-1 hash；證實 Wang 2005 理論攻擊 12 年後變實作；徹底結束 SHA-1 在 cert / signature / Git 等需要 collision-resistance 場景的可信度。

## Problem
2005 Wang 給 SHA-1 collision attack 理論複雜度 2^69（後續改進到 2^61）。但「理論可破」與「實際有人破」是兩件事。Web PKI、Git、PGP 等仍依賴 SHA-1。需要 demonstrate 實際 collision 才能推動 industry migration。

## Contribution
1. **第一個實際 SHA-1 full collision**：兩個不同 PDF 文檔 (`shattered-1.pdf`, `shattered-2.pdf`) 計算 SHA-1 完全相同 (`38762cf7…`)。
2. **PDF chosen-prefix attack 應用**：兩 PDF 內含相同 hash 但顯示完全不同內容（一張 logo 圖一藍一紅）。利用 PDF 的 JPEG embedded objects 編碼差異。
3. **計算成本**：~9 quintillion (9 × 10^18) SHA-1 invocations。Google + CWI 共用 2017 年 cloud：~$110k。
4. **影響：CA/B Forum 立即禁 SHA-1 in new certs**（已 phase-out 中但加速完成）。Git 提出 SHA-256 transition plan。
5. **後續：2020 Leurent-Peyrin 提出 chosen-prefix collision** at ~$45k cost — 更危險（攻擊可選兩 prefix，產生對 PGP web of trust 的真實攻擊）。

## Method
**框架**：
1. Find 90 collision blocks in SHA-1 internal state via differential characteristic + message modification (Wang framework)。
2. Apply two parallel chosen-prefix attacks on first 9 SHA-1 blocks (576 bytes) of two different PDF prefixes。
3. Use specially crafted JPEG embedded in PDF such that 2 different display bytes produce 2 different visual outputs。

**Cloud computation**：
- Phase 1: 6500 CPU-years (≈ 100 CPU × 65 years)。
- Phase 2: 110 GPU-years (≈ 1000 GPU × 40 days)。
- Total cost: ~$110,000 (Amazon spot pricing 2017)。

## Results
- **2017-02-23 公開**：Google + CWI 聯合宣布 SHAttered。
- **CA/B Forum** 立即禁 SHA-1 in any new public cert（已 phase out 但 SHAttered 後 Cloudflare 等 CDN 主動 reject）。
- **Git Linus 接受 transition** to SHA-256 (Git 2.29+)，仍進行中 2026。
- **GitHub 2018** 加 SHA-1 collision detection (`SHA1DC`) 防 SHAttered-style file injection。
- **PGP web of trust** 2020 Leurent-Peyrin chosen-prefix collision 後再受打擊。

## Limitations / what they don't solve
- 不破 HMAC-SHA1（仍 secure 因 HMAC 結構）。
- 不破 SHA-2 / SHA-3 / BLAKE 等 different-design hash。
- 不破 SHA-1 preimage（仍 ~2^160 brute force）。
- 攻擊有 controlled prefix constraint（不能任意挑兩文檔）；Leurent-Peyrin 2020 才解此限制。

## How it informs our protocol design
- **Proteus 絕不用 SHA-1**（已是 industry baseline）。
- **Proteus hash agility 設計**：spec 內定義 hash_id field 與 negotiation 機制；想像 SHA-256 在 2040 年遭遇類似攻擊時的升級路徑。
- **Proteus 教訓**：理論破解到實作破解的時間是 12 年（Wang 2005 → SHAttered 2017）。為 Proteus spec 中的 256-bit hash 安全聲明，假設「至少 30 年安全」是合理的——但要設計 graceful 升級。
- **Proteus 文件級 hash binding（如有 cover document hash）**：必用 SHA-256+ 或 BLAKE2/3。

## Open questions
- 同樣 framework 是否能對 SHA-256 round-reduced 破？至 2026 best 是 46/64-round semi-free-start。
- Quantum adversary 對 Wang/SHAttered framework 的 Grover speedup 精確 implication？
- 經濟可行的 chosen-prefix collision against SHA-256 在量子算力 1B+ qubits 時的 cost model？

## References worth following
- Stevens *Counter-cryptanalysis* (CRYPTO 2013) — pre-shattered 預警工作。
- Leurent, Peyrin *SHA-1 is a Shambles* (USENIX Security 2020) — chosen-prefix collision。
- Stevens 等 *Counter-cryptanalysis applied to SHA-1* — SHAttered 對應的 detection technique。
- Cryptographic Algorithm Validation Program (NIST CAVP) deprecation timeline。
