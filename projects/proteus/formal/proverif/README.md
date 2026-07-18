# Proteus v1.2 symbolic handshake verification

This directory pins ProVerif 2.05 from the official Inria distribution
and verifies the v1.2 triple-hybrid inner handshake in the symbolic
Dolev–Yao model.

Run:

```bash
./formal/proverif/verify.sh
```

The model checks application-payload secrecy plus injective client and
server agreement on the complete session tuple and final application
key. It runs the honest protocol alongside three hedge challenges that
reveal, one at a time, the per-session ephemeral-X25519, static-X25519,
or ML-KEM shared component before the client authenticates Server
Finished. The attacker can therefore use the exposed component during
an active impersonation attempt, not merely after the handshake. A
failure in any challenge breaks the common secrecy query or agreement
query.

The model mirrors the Rust transcript boundary deliberately: the outer
TLS exporter enters `th_ch_sh` and therefore both Finished keys, while
the final application key uses `th_ch_sf` after Finished authentication.
It does not model implementation bugs, side channels, traffic analysis,
computational reductions, RNG failure, endpoint compromise, or the
post-handshake ratchet. Those remain separate verification obligations;
a green ProVerif run is evidence for the stated symbolic properties,
not an independent security audit.

Raw verifier output is written below `formal/proverif/results/`, which
is ignored because it can be regenerated from the pinned model and
container.
