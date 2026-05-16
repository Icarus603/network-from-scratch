# An Efficient Cryptographic Protocol Verifier Based on Prolog Rules
**Venue / Year**: Computer Security Foundations Workshop (CSFW) 2001
**Authors**: Bruno Blanchet
**Read on**: 2026-05-14 (in lesson 3.15)
**Status**: abstract-only（INRIA mirror Cloudflare 阻擋；引用內容綜合自 ProVerif manual + Blanchet's homepage + 訓練資料）
**One-line**: ProVerif 工具的 origin paper——把 cryptographic protocol 翻譯成 Horn clauses 用 SLD resolution 自動找 attack 或證 secrecy；20+ 年來 IETF spec (TLS 1.3, Noise, MLS) 共同進化的主要 verification tool；Proteus 必用。

## Problem
1990 年代 protocol verification 主流是 model checker (FDR for Lowe's Needham-Schroeder 1995)。但 model checker 對 unbounded sessions / unbounded fresh nonces 處理 poor. Blanchet 想：能不能用 Prolog-style logical inference 處理 unbounded?

## Contribution
1. **Applied pi-calculus → Horn clauses translation**:
   - Protocol described as π-calculus processes。
   - 翻譯為 Horn clauses (Datalog-like rules)。
   - Adversary knowledge K modeled as predicate `att(x)` (attacker has x)。
   - Inference rule: from premises in K, derive new facts in K。
2. **Resolution-based proof search**:
   - 用 SLD resolution check if `att(secret)` is derivable。
   - If yes → attack found。
   - If no (or termination reached) → secrecy proved。
3. **Unbounded session support**: 與 model checker 不同，ProVerif 處理 unbounded sessions 透過 abstraction (over-approximation)。
4. **Performance**: 對大型 protocol (TLS 1.3, Noise IK, Signal X3DH) 仍可在 minutes-hours 內完成證明。
5. **Properties supported**: secrecy, authentication, observational equivalence, reachability。

## Method (high-level)
**Process specification**:
```ocaml
(* 描述 protocol *)
let Alice =
    new x: Z;
    out(c, exp(g, x));
    in(c, gy);
    let K = exp(gy, x) in
    out(c, senc(secret, K)).

(* Query *)
query attacker(secret).
```

**Translation to Horn clauses** (sketch):
```text
att(g).                       (* attacker knows g (public) *)
att(c).                       (* attacker knows channel name *)
∀ x. att(x) → att(senc(_, _)) (* if attacker can compute key, can decrypt anything *)
∀ k, x. att(senc(x, k)) ∧ att(k) → att(x)   (* decrypt rule *)
```

**Resolution**: starting from `att(secret)?`, backward chain through rules. If rules cycle without producing concrete result → unable to prove (over-approximation conservative)。

**Special handling**:
- **Equational theory** (e.g., DH commutativity): user-defined equations。
- **Phase / state**: support stateful protocols via phases。
- **Biprocesses**: 兩 process side-by-side for observational equivalence。

## Results
- **Adopted by IETF spec authors**: TLS 1.3, Noise Framework, MLS RFC 9420 都用 ProVerif 早期 verify。
- **Bhargavan 等 2017** 用 ProVerif + F\* 對 TLS 1.3 全 spec mechanised proof。
- **Bhargavan-Kobeissi-Beurdouche 2019 Noise Explorer** 自動 generate ProVerif models for all Noise patterns。
- **WireGuard 2017 設計時** 與 ProVerif co-evolve。
- **Lipp-Blanchet-Bhargavan 2019 EuroS&P** WireGuard 完整 mechanised proof。
- **5G AKA, EAP-TLS, OPAQUE** 等 modern protocols 皆 verified。

## Limitations / what they don't solve
- **Symbolic only**: 不 capture computational attacks (padding oracle, timing)。
- **Over-approximation**: false positive attack reports possible (but rare in practice)。
- **Termination not guaranteed**: 對複雜 stateful protocols 可能不終止；需 manual hint。
- **Equational theory limit**: 某些 advanced primitive (pairing, BLS aggregation) 較難 model。

## How it informs our protocol design
- **Proteus 必用 ProVerif**: Phase III 11.10 為 Proteus IK variant + PSK + ratchet 寫 ProVerif model。
- **Proteus spec design 與 ProVerif co-evolve**: 若 spec 改變 must rerun verification。
- **Proteus properties to verify**:
  - Secrecy of session keys (各 layer)。
  - Mutual authentication。
  - KCI / UKS resistance。
  - Forward secrecy。
  - Replay resistance。
- **Proteus 教訓**: design 階段就要把 protocol 寫成可形式化 form (Noise pattern 啟發 mechanical translation)。

## Open questions
- **Termination guarantees for complex protocols**: 仍 active research。
- **Computational soundness lifting**: ProVerif symbolic → CryptoVerif computational mapping 仍 manual。
- **Quantum adversary in ProVerif**: 當前 model classical Dolev-Yao；quantum extension active research。

## References worth following
- Blanchet *Modeling and Verifying Security Protocols with the Applied Pi Calculus and ProVerif* (FnTPL 2016) — comprehensive tutorial。
- Abadi-Fournet *Mobile Values, New Names, and Secure Communication* (POPL 2001) — applied pi-calculus origin。
- Bhargavan 等 *miTLS* series — combined ProVerif + F\*。
- ProVerif manual (regularly updated)。
