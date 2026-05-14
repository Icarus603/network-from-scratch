# The TAMARIN Prover for the Symbolic Analysis of Security Protocols
**Venue / Year**: CAV 2013, LNCS 8044, pp. 696–701. DOI: 10.1007/978-3-642-39799-8_48
**Authors**: Simon Meier（ETH Zürich）, Benedikt Schmidt（ETH Zürich → IMDEA）, Cas Cremers（ETH Zürich → Oxford → CISPA）, David Basin（ETH Zürich）
**Read on**: 2026-05-14 (in lesson 5.6)
**Status**: PDF 開放 https://people.cispa.io/cas.cremers/downloads/papers/MSCB2013-Tamarin.pdf；已下載到 assets/papers/cav-2013-tamarin.pdf
**One-line**: 把 multiset rewriting + first-order logic + backwards reasoning 結合，做出第一個對 unbounded sessions + Diffie-Hellman algebraic 同時 sound 的 automated symbolic prover——TLS 1.3、WireGuard、5G-AKA、MLS 都靠它。

## Problem
- ProVerif 對「stateful protocol」 + 「DH equation」處理不夠完整
- 業界 protocol（IKEv2、TLS、WireGuard）都依賴 DH algebraic properties (g^(xy) = g^(yx))
- 需要：
  1. **Mutable global state** (e.g. PKI database, anti-replay window)
  2. **Equational theories**（DH, XOR, bilinear pairing）
  3. **Unbounded sessions**
  4. **Interactive + automated** proof construction

## Contribution
1. **Multiset rewriting**: protocol step 寫成 multiset transformation rules，自然 model concurrent state
2. **Equational reasoning** via unification modulo theory
3. **Backwards reasoning** from goal: 從 attacker's desired knowledge 倒推
4. **Property specification** via first-order logic + temporal trace properties
5. **Interactive + automated**: 可以在 GUI 內 partial unfold, 半自動 prove
6. **Open-source Haskell impl**: tamarin-prover.com

## Method
- **Multiset rewriting**: rule `[Facts_in] -- [Actions] --> [Facts_out]`
  - `Facts_in`: multiset of facts that must hold (e.g., `In(M)` = a message M is on the network, `Fr(k)` = k is fresh)
  - `Facts_out`: facts generated (e.g., `Out(M)`, `State(...)`)
  - `Actions`: logged events for property reasoning
- **Properties**: 用 first-order logic + temporal:
  ```
  lemma secrecy:
    "All k #i. Secret(k) @ #i ==> not(Ex #j. K(k) @ #j)"
  ```
  讀作：對任何 k, 在時點 i 標記 Secret，則 attacker 從未 know k.
- **Backwards reasoning**: 對 negated goal 用 constraint solving, 試找 trace witnessing；找不到 → property 成立

## Results
- **Open-source** 持續維護 (tamarin-prover.com)
- 主要應用：
  - **TLS 1.3** (Cremers-Horvat-Hoyland-Scott-van der Merwe CCS 2017) — Part 4.1 precis
  - **5G-AKA** (Basin-Dreier-Hirschi-Radomirovic-Sasse-Stettler CCS 2018) — 5G 認證協議
  - **WireGuard** (Donenfeld-Milner 2018) — Noise IK
  - **MLS** (RFC 9420 Messaging Layer Security) — group chat
  - **EMV** (Basin-Sasse-Toro-Pozo USENIX Security 2021) — credit card payment
- 與 ProVerif 對比：Tamarin 對 DH algebraic + stateful protocol 更強；ProVerif 對純 Dolev-Yao secrecy 更快

## Limitations / what they don't solve
- **不能 model probability**：無 computational reasoning
- **Termination not guaranteed**: protocol 複雜可能跑不完
- **Equational theory 限定**: AC, XOR, DH, bilinear, multiset — 不支援任意 equation
- **Learning curve**: 比 ProVerif 陡，rule-based syntax 對 protocol designer less natural

## How it informs our protocol design
- **DH algebraic check**: 我們協議的 X25519 + key derive 用 Tamarin 證 DH-related secrecy
- **Stateful check**: anti-replay window monotonic update 用 Tamarin model
- **TLS 1.3 風格 multi-stage key exchange**: 用 Tamarin 證每階段 key independence
- **Annotated RFC 風格**: Cremers et al. CCS 2017 把 RFC prose annotate 對應 Tamarin rules — Part 11.10 我們協議 spec 仿照此 workflow

## Open questions
- **Anti-fingerprint / statistical** indistinguishability 仍超出 Tamarin scope
- **Quantum adversary** model — partial work but no standard framework
- **Coverage 對 implementations**: Tamarin spec ≠ Go/Rust code; bridge 仍 open

## References worth following
- Cremers TLS 1.3 work series (S&P 2016, CCS 2017)
- Basin 5G-AKA series
- Schmidt thesis *Formal analysis of key exchange protocols and physical protocols* (ETH 2012)
- Tamarin manual: https://tamarin-prover.com/manual/

---

**用於課程**：Part 5.6（Tamarin 核心）、Part 11.10（我們協議 verification workflow）、Part 4.1（已建立 Cremers TLS 1.3 對比）
