# The Knowledge Complexity of Interactive Proof Systems
**Venue / Year**: SIAM Journal on Computing, Vol. 18, No. 1, 1989（STOC 1985 preliminary）
**Authors**: Shafi Goldwasser, Silvio Micali, Charles Rackoff
**Read on**: 2026-05-14 (in lesson 3.10)
**Status**: full PDF (`assets/papers/gmr-zk-1989.pdf`)
**One-line**: 提出 zero-knowledge proof 概念——對於 NP statement，prover 可說服 verifier statement 為真**且 verifier 學不到 witness 任何 information**；定義整個 ZK proof field，後續所有 SNARK / STARK 都源自此。

## Problem
1985 年的 cryptographic protocol design 假設「prover 要證明知道某 secret，必須 reveal it」。但 password authentication 等 application 反例：不能 reveal password。Goldwasser-Micali-Rackoff 問：能不能形式化定義「prover 證明知道 secret 但 verifier 學不到 secret」？

## Contribution
1. **Interactive Proof System 定義**:
   - (Prover, Verifier) pair of Turing machines。
   - Completeness: prover 知道 truth → verifier 接受。
   - Soundness: prover 不知 truth → verifier 不接受 (with high probability)。
2. **Knowledge complexity (KC) 階梯**:
   - KC = 0: zero-knowledge — verifier 學不到任何 information。
   - KC = log n: 學 log-many bits。
   - KC = poly(n): 學 poly-many bits。
3. **Zero-Knowledge 形式化**:
   - **Simulator paradigm**: 對任何 cheating verifier V*, 存在 PPT simulator S, simulated transcript ≈ real transcript。
   - 意義: V 看到 transcript 可以自己生成 → 沒有從 P 學新 information。
4. **Perfect / Statistical / Computational ZK 區分**:
   - Perfect ZK: distributions 相同。
   - Statistical ZK: ≤ negligible TV distance。
   - Computational ZK: only PPT distinguisher 不能區分。
5. **First example**: Quadratic Residuosity (QR) ZK proof。Prover 證明「我知 x 的 square root mod N」without revealing root。

## Method (草稿)
**QR ZK proof example**:
```text
Public: y, N (composite).
Statement: y is QR mod N (i.e., ∃ x s.t. y = x² mod N).
Witness: x.

Prover P, Verifier V:
    For i = 1..k (security parameter):
        P: r ← random; t = r² mod N; send t
        V: e ← {0, 1}; send e
        P: if e = 0: send r else: send z = r·x mod N
        V: if e = 0: check r² == t; else: check z² == t·y mod N
    Accept if all rounds passed.
```

**Completeness**: honest P knows x → both checks pass.
**Soundness**: cheating P* without x → for each round, must guess e in advance to prepare a valid response → success ≤ 2^-k after k rounds.
**ZK**: simulator S can construct (t, e, response) tuple by:
- 選 e and response first (e.g., response z; e=1)。
- Compute t = z² / y mod N (or t = r² for e=0)。
- Output (t, e, response) — same distribution as real interaction，因為 honest V's e is random。

### 6. Results
- 開創整個 ZK proof field。
- 1986 GMW *Proofs that Yield Nothing But Their Validity* 將 ZK extend to all NP。
- 2012 Goldwasser, Micali 共獲 Turing Award (引文含此論文)。
- 2010s+ ZK proof 進入 production: Zcash (2016)、StarkNet (2020+)。

## Limitations / what they don't solve
- Interactive (multiple rounds) — 不適合 non-interactive 場景。Fiat-Shamir 1986 補。
- Soundness error 2^-k 需多 round — proof size O(k)。Bulletproofs / SNARK 後續壓縮。
- 不直接給 succinctness — Groth16 SNARK 等補。
- ROM-free perfect ZK in NP 仍 open (general)。

## How it informs our protocol design
- **Proteus 認知到 Ed25519 是 NIZK 的 special case**：Schnorr proof of knowledge of sk + Fiat-Shamir → signature。
- **Proteus 未來 anonymous auth**: Privacy Pass / VRF 等都基於 ZK proof of credential validity。
- **Proteus 教訓**：「knowledge」這個概念可形式化；「我知道 sk」可被 cryptographically verified 而不 reveal sk。為 Proteus anonymous subscription / decoy-indistinguishability 等 future feature 提供 conceptual base。

## Open questions
- ZK with sub-linear verifier time (succinct verifier) 仍 active。
- Quantum ZK: post-quantum 安全的 ZK proof system 是否能 match 經典 efficiency? Open。
- Concurrent / Universally Composable ZK 是否能 match standalone ZK efficiency? Open。

## References worth following
- Goldreich-Micali-Wigderson *Proofs that Yield Nothing But Their Validity* (FOCS 1986 / JACM 1991) — ZK for NP。
- Fiat-Shamir 1986 — interactive → NIZK。
- Bellare-Goldreich 1992 — proof of knowledge formal。
- Canetti 等 *UC Zero-Knowledge* — composition framework。
