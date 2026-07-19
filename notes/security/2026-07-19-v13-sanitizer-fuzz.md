# Proteus v1.3 sanitizer and fuzz evidence — 2026-07-19

## Scope and provenance

- Source commit under test: `c9cbc8f` plus the fuzz/CI harness in the
  immediately following worktree change.
- Host: Apple Silicon macOS, target `aarch64-apple-darwin`.
- Compiler: `rustc 1.99.0-nightly (eff8269f7 2026-07-18)`.
- Fuzzer: `cargo-fuzz 0.13.2`, `libfuzzer-sys 0.4.13`.
- All temporary toolchains, corpora, artifacts, and Cargo targets lived under
  `/tmp`; none are production dependencies or repository artifacts.

## Coverage-guided wire fuzz

The `wire_decoders` target drives `AuthExtension`, `InnerHeader`, QUIC varint,
α frame, and v1.3 PCS-control decoders. Inputs of at least 40 bytes also
exercise PCS encode/decode round trips.

The AddressSanitizer-backed libFuzzer run completed 66,710,063 executions in
61 seconds. It reached 75 coverage counters and 79 feature counters, retained
10 minimized corpus inputs totalling 123 bytes, and reported no crash, panic,
timeout, or sanitizer finding.

## AddressSanitizer PCS state machine

Nightly AddressSanitizer with leak detection ran the six
`pcs_session_tests` plus the `pcs_two_party_ratchet` integration test. These
cover simultaneous offers, the offer/commit boundary, blocked-receiver and
half-exchange deadlines, legacy-ratchet rejection, the compile-time benchmark
mode invariant, and three consecutive fresh/fresh generations during one-way
application traffic. All seven tests passed with no sanitizer finding.

## Recurring gate

`.github/workflows/ci.yml` now runs the focused v1.3 AddressSanitizer tests on
Linux x86_64 nightly and runs the wire/PCS fuzz target for 60 seconds. The
fuzz target and its dependency lockfile live under `projects/proteus/fuzz/`.

These results close the implementation-candidate sanitizer/fuzz gate. They do
not replace a computational proof, an independent security audit, long-horizon
fuzzing, or adversarial GFW closed-beta evidence.
