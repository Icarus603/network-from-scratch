# Problem Areas for the IP Security Protocols
**Venue / Year**: USENIX Security 1996
**Authors**: Steven M. Bellovin (AT&T Research)
**Read on**: 2026-05-16 (in lesson 6.1)
**Status**: full PDF available publicly; we cite from training + abstract（PDF 未本地化）
**One-line**: IPsec 還沒落地前，Bellovin 就點出十幾個結構性問題——25 年後幾乎全部成立。

## Problem
1996 年 IETF IPsec WG 草案進入後期，但 Bellovin 認為設計尚有多處未經審慎評估。他寫這篇是要「在水泥乾之前」逼 IETF 重新看幾個問題。

## Contribution
1. **Anti-replay 視窗的細節 ambiguity**：規格說 window size 32 是 default，但對 64-bit ESN（後加）的相容沒講清楚。
2. **IP fragmentation 與 IPsec 的互動**：fragment 在 IPsec 之前還是之後做？兩種選擇都有問題。
3. **ICMP 經過 IPsec tunnel 的語義不明**：例如 PMTU "Fragmentation Needed" 應該對 outer IP 還是 inner IP 生效？
4. **Cookie / DoS protection 不足**：early IKE 沒有 stateless cookie，server 容易被 amplification 攻擊。
5. **多 SA 與 traffic selector 的 complexity**：如果一個 host 有多條 SA 規則對應同一個 dst，怎麼選？
6. **AH 對 mutable 欄位的處理**：規格寫了，但實作必定誤判某些欄位的 mutability。
7. **Security context 隨 IP packet 流動的語義**：例如 NAT 把 IP 改了，IPsec 的「same security context」要怎麼維持？

## Method
規格批判 + 對若干實作行為的觀察 + 對若干潛在攻擊的構造（非 full implementation）。

## Results
直接導致 RFC 2401 vs 4301 多處修訂、後續 RFC 3947/3948 NAT-T、RFC 4301 §5 對 fragmentation 的處理。

## Limitations / what they don't solve
- 沒有 formal model，所有問題都是「直覺工程級」批判。
- 沒有量化評估每個問題的可利用性。
- 後續攻擊（Paterson-Yau 2006、Degabriele-Paterson 2007）走得更遠，但思想脈絡都能追到這篇。

## How it informs our protocol design
Proteus 設計時把這篇當「不要這樣做」清單：
- 不要把 fragmentation 留給 protocol layer 處理（forbid IP fragmentation 之上跑 protocol，或用 PLPMTUD）。
- 不要讓 ICMP 自由穿過 tunnel（policy decision，不是 protocol-implicit）。
- 不要 negotiation policy 與 selector 互相耦合。
- stateless cookie + retry 是 day-1 設計，不是補丁。

## Open questions
- 25 年來「規格 vs 實作 ambiguity」這個議題能否被 formal spec language (如 NDN's Packet Format Definitions, or QUIC's 用 augmented BNF) 系統性消除？
- 若把這些問題逐一寫成 ProVerif lemma，能否在 Tamarin 跑通？

## References worth following
- Ferguson & Schneier 2003 *A Cryptographic Evaluation of IPsec*（延伸版批判）
- RFC 4301 / 4302 / 4303 / 7296（後續修訂的回應）
- Donenfeld 2017 WireGuard whitepaper（把這篇當設計檢核表）
