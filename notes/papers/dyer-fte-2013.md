# Protocol Misidentification Made Easy with Format-Transforming Encryption
**Venue / Year**: ACM CCS 2013
**Authors**: Kevin P. Dyer, Scott E. Coull, Thomas Ristenpart, Thomas Shrimpton
**Read on**: 2026-05-16 (in lesson 10.6)
**Status**: full PDF
**One-line**: Format-Transforming Encryption — embed ciphertext into outputs of an arbitrary regex (HTTP, SSH, SIP), defeating regex-based DPI.

## Problem
Censors use protocol-conformance DPI: if wire matches HTTP regex, allow; if doesn't, scrutinize. PTs producing high-entropy random bytes immediately stand out. Can ciphertext be made regex-compliant?

## Contribution
1. Format-Transforming Encryption (FTE): combine AES with a DFA-based encoder that maps ciphertext to strings matching a target regex.
2. Rank-unrank algorithm: bijective mapping between integers in $[0, |L_n(A)|)$ and accepted strings of length $n$.
3. Reference impl `fteproxy`.

## Method
- Define DFA $A$ accepting target language (e.g., HTTP/1.1 GETs).
- For ciphertext $c$: interpret as integer, $|L_n(A)|$ count via DP on $A$'s adjacency matrix.
- Unrank: map integer to unique string in $L_n(A)$.
- Bridge reverses (rank to integer, decrypt).

## Results
- DPI evasion: against regex-based DPI (nDPI early versions, Bro signatures): 100% evasion.
- Bandwidth overhead: depends on regex; ~10–50% for HTTP-shaped.

## Limitations
- Stateful DPI (sequence-aware) can still detect — wire content matches HTTP but the order/timing doesn't.
- "Parrot is dead" (Houmansadr 13) lesson: incomplete mimicry fails.
- Real protocol state machines not modeled.

## How it informs our protocol design
- **G6 doesn't pursue FTE-style mimicry** — tunneling real protocol (HTTP/2 with real Chrome behavior) is structurally superior.
- FTE is useful as fallback in extreme low-bandwidth censorship environments (text-only channel).
- The rank-unrank algorithm has independent interest for protocol obfuscation primitives.

## Open questions
- Modern FTE with stateful DPI bypass?
- FTE + real protocol stack (FTE-encoded payloads inside real HTTP/2 frames)?

## References worth following
- Dyer 15 USENIX Sec (Marionette) — successor with programmable state machine
- Houmansadr 13 (Parrot is Dead) — mimicry critique
- meek (Fifield 15) — tunneling alternative
