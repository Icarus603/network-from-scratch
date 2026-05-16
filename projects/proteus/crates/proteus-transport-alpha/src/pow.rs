//! Proof-of-work verification for the anti-DoS field of the auth ext.
//!
//! Spec §8.3: the server publishes a `difficulty d ∈ [0, 24]` (in its
//! HTTPS RR Proteus parameter). The client must compute a 7-byte
//! `anti_dos_solution` such that:
//!
//! ```text
//! SHA-256(server_pq_fingerprint || client_nonce || anti_dos_solution)
//! ```
//!
//! has at least `d` leading zero bits. Verification on the server side
//! is a single SHA-256 (~50 ns). Difficulty 0 is a no-op (production
//! default when not under DoS); operators bump it on alert.

use sha2::{Digest, Sha256};

/// Verify a proof-of-work solution. Returns `true` if the hash meets the
/// declared difficulty target.
#[must_use]
pub fn verify(
    server_pq_fingerprint: &[u8; 32],
    client_nonce: &[u8; 16],
    difficulty: u8,
    solution: &[u8; 7],
) -> bool {
    if difficulty == 0 {
        return true;
    }
    let mut hasher = Sha256::new();
    hasher.update(server_pq_fingerprint);
    hasher.update(client_nonce);
    hasher.update(solution);
    let digest = hasher.finalize();
    leading_zero_bits(&digest) >= u32::from(difficulty)
}

/// Count leading zero bits of a digest. Used by [`verify`].
#[must_use]
pub fn leading_zero_bits(digest: &[u8]) -> u32 {
    let mut count = 0u32;
    for &b in digest {
        if b == 0 {
            count += 8;
        } else {
            count += b.leading_zeros();
            break;
        }
    }
    count
}

/// Find a 7-byte solution that satisfies the given difficulty.
///
/// Returns `None` if the search space is exhausted (impossible at
/// reasonable difficulties) **or** if the wall-clock deadline elapses
/// before a solution is found.
///
/// Production clients prefer to receive `difficulty=0` (no work) and
/// only solve a puzzle on retry after an explicit reject from the
/// server. Even so, an unlucky tail at d=24 can take ~30 s of CPU;
/// the deadline parameter lets callers cap UX latency and surface
/// the failure cleanly instead of hanging.
#[must_use]
pub fn solve(
    server_pq_fingerprint: &[u8; 32],
    client_nonce: &[u8; 16],
    difficulty: u8,
) -> Option<[u8; 7]> {
    solve_with_deadline(
        server_pq_fingerprint,
        client_nonce,
        difficulty,
        std::time::Duration::from_secs(60),
    )
}

/// As [`solve`] but with an explicit wall-clock deadline. Returns
/// `None` if the deadline elapses before a solution is found.
#[must_use]
pub fn solve_with_deadline(
    server_pq_fingerprint: &[u8; 32],
    client_nonce: &[u8; 16],
    difficulty: u8,
    deadline: std::time::Duration,
) -> Option<[u8; 7]> {
    if difficulty == 0 {
        return Some([0u8; 7]);
    }
    let start = std::time::Instant::now();
    // Check the clock every CHECK_INTERVAL hashes so we don't pay
    // `Instant::now()` cost on every iteration.
    const CHECK_INTERVAL: u64 = 4096;
    let mut sol = [0u8; 7];
    let mut counter: u64 = 0;
    loop {
        sol.copy_from_slice(&counter.to_be_bytes()[1..8]);
        if verify(server_pq_fingerprint, client_nonce, difficulty, &sol) {
            return Some(sol);
        }
        counter = counter.checked_add(1)?;
        if counter > (1u64 << 56) {
            return None;
        }
        if counter.is_multiple_of(CHECK_INTERVAL) && start.elapsed() > deadline {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn difficulty_zero_always_passes() {
        let fp = [0x42u8; 32];
        let nonce = [0x33u8; 16];
        assert!(verify(&fp, &nonce, 0, &[0u8; 7]));
        assert!(verify(&fp, &nonce, 0, &[0xffu8; 7]));
    }

    #[test]
    fn solve_then_verify_round_trip() {
        let fp = [0x11u8; 32];
        let nonce = [0x22u8; 16];
        for d in [1u8, 4, 8, 12] {
            let sol = solve(&fp, &nonce, d).expect("must find solution");
            assert!(verify(&fp, &nonce, d, &sol), "verify failed at d={d}");
        }
    }

    #[test]
    fn bad_solution_rejected_at_nonzero_difficulty() {
        let fp = [0xaau8; 32];
        let nonce = [0xbbu8; 16];
        // Pick a difficulty where the zero solution is overwhelmingly
        // unlikely to satisfy.
        assert!(!verify(&fp, &nonce, 16, &[0u8; 7]));
    }

    #[test]
    fn changing_nonce_invalidates_solution() {
        let fp = [0x01u8; 32];
        let n1 = [0x02u8; 16];
        let n2 = [0x03u8; 16];
        let sol = solve(&fp, &n1, 4).unwrap();
        assert!(verify(&fp, &n1, 4, &sol));
        // The same solution against a different nonce almost certainly fails.
        assert!(!verify(&fp, &n2, 4, &sol));
    }

    #[test]
    fn solve_with_deadline_caps_runtime_under_impossible_difficulty() {
        // Difficulty 64 (impossibly high — 2^64 expected hashes) MUST
        // return None within the deadline rather than hanging forever.
        let fp = [0u8; 32];
        let nonce = [0u8; 16];
        let start = std::time::Instant::now();
        let result = solve_with_deadline(&fp, &nonce, 64, std::time::Duration::from_millis(200));
        let elapsed = start.elapsed();
        assert!(result.is_none(), "impossible difficulty must surface None");
        assert!(
            elapsed < std::time::Duration::from_millis(800),
            "deadline overshoot: {elapsed:?}"
        );
    }

    #[test]
    fn leading_zero_bits_correct() {
        assert_eq!(leading_zero_bits(&[0xff, 0xff]), 0);
        assert_eq!(leading_zero_bits(&[0x7f, 0xff]), 1);
        assert_eq!(leading_zero_bits(&[0x00, 0xff]), 8);
        assert_eq!(leading_zero_bits(&[0x00, 0x7f]), 9);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x80]), 16);
    }
}
