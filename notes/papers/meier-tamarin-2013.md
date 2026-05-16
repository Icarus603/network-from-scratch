# The TAMARIN Prover for the Symbolic Analysis of Security Protocols
**Venue / Year**: Computer Aided Verification (CAV) 2013
**Authors**: Simon Meier, Benedikt Schmidt, Cas Cremers, David Basin
**Read on**: 2026-05-14 (in lesson 3.15)
**Status**: abstract-only（CISPA mirror PDF only HEAD returned 2.2k 應為 server gating；引用綜合自 CAV 2013 proceedings + Tamarin manual + 訓練資料）
**One-line**: Tamarin 工具——基於 multiset rewriting + interactive backward proof 的 protocol verifier；表達力比 ProVerif 強，能處理 stateful protocols (Signal Double Ratchet, 5G AKA)；TLS 1.3, MLS, Noise 等 IETF spec 形式化 verification 的 second pillar。

## Problem
ProVerif 1.0 (2001) 對 unbounded sessions secrecy 證明強，但對 stateful protocols (e.g., Signal Double Ratchet 中 ratchet step depends on previous state) 表達力有限。需要更 general framework。

## Contribution
1. **Multiset Rewriting Framework**:
   - State = multiset of facts。
   - Rules: `Premises --[ ActionFacts ]-> Conclusions`。
   - Premise facts consumed; conclusion facts produced; action facts logged in trace。
2. **Backward search with smart heuristics**:
   - 從 violation goal backward search through rules。
   - Smart simplification + cycle detection。
   - Interactive mode: user 可 guide search via lemma hints。
3. **Inductive lemma support**:
   - 對 unbounded protocols 證 invariants。
   - User 提供 inductive helper lemmas; Tamarin 證 each step。
4. **Stateful protocol natively supported**:
   - 每 ratchet step 可作 stateful rule with persistent / linear facts。
   - Signal Double Ratchet, 5G AKA 等可 directly model。
5. **DH equational theory built-in**: handle bilinear maps, XOR, exp commutativity natively。

## Method (high-level)
**Spec language**:
```text
rule Generate_Identity:
    [ Fr(~ltk) ]
    --[ ]->
    [ !Ltk($A, ~ltk), !Pk($A, 'g'^~ltk), Out('g'^~ltk) ]

rule Init_Session:
    [ !Ltk($A, sk), Fr(~eph) ]
    --[ Started($A) ]->
    [ State1($A, sk, ~eph), Out('g'^~eph) ]

rule Receive_and_Compute:
    [ State1($A, sk, eph), In(gy), !Pk($B, pk_b) ]
    --[ Established($A, $B, gy^eph) ]->
    [ !Established($A, $B, gy^eph) ]

lemma session_key_secret:
    "All A B k #i. Established(A, B, k) @ i ==> not (Ex #j. K(k) @ j)"
```

`!` = persistent fact (永遠 true)；無 `!` = linear (consumed after use)。

**Proof process**:
1. Tamarin 自動 search proof; success → property holds。
2. 找到 attack trace → output sequence of rule applications leading to violation。
3. 不 terminate → user provide inductive lemmas to break cycles。

## Results
- **5G AKA verification (Cremers-Dehnel-Wedl 2018, IEEE S&P)**: 找到 spec ambiguities + 驗證修正 — 採進 3GPP 5G spec final。
- **Signal Double Ratchet (Cohn-Gordon 等 EuroS&P 2017)**: 完整 PCS proof in Tamarin。
- **TLS 1.3 (Cremers-Horvat-Hoyland-Scott-van der Merwe CCS 2017)**: comprehensive symbolic analysis。
- **MLS (RFC 9420)** TreeKEM verification。
- **EMV payment protocol**: found multiple bugs。
- **OPAQUE** Tamarin model 為 RFC 9807 提供 evidence。

## Limitations / what they don't solve
- **Steeper learning curve than ProVerif**: 需理解 multiset rewriting + linear logic-style facts。
- **Termination 仍 issue**: 複雜 stateful protocol may not terminate without lemma hints。
- **Symbolic only**: 同 ProVerif 不 capture computational attacks。
- **Performance variable**: 對 small protocols 快; 對 large + stateful 可能 hours-days。

## How it informs our protocol design
- **Proteus stateful protocol parts (ratchet, PSK schedule) 用 Tamarin model**：
  - Per-N-record DH ratchet step。
  - Multi-device handling (avoid Selfie attack)。
  - PCS proof。
- **Proteus 與 Signal-style ratchet 對比 evaluation 用 Tamarin**:
  - 證 Proteus ratchet 達 Signal-equivalent PCS。
  - 證 Proteus PSK schedule 不 leak。
- **Proteus 教訓**: stateful protocol 必須 Tamarin (or equivalent stateful tool); ProVerif alone 不夠。

## Open questions
- **Tamarin-CryptoVerif coupling**: symbolic + computational integration 仍 active。
- **Quantum adversary in Tamarin**: classical Dolev-Yao only; quantum extension 仍 evolving。
- **Automation level**: interactive proofs vs full automation tradeoff; Tamarin 較 interactive than ProVerif。

## References worth following
- Tamarin manual: tamarin-prover.github.io/manual/。
- Cremers 等 *5G AKA Tamarin analysis* (CCS 2018)。
- Cohn-Gordon 等 *Signal Tamarin proof* (EuroS&P 2017)。
- Basin 等 textbook *Operational Semantics and Verification of Security Protocols* (Springer)。
