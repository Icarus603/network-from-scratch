//! Shape-shift PRG and transition schedule (spec §22).
//!
//! Both client and server seed the same PRG with the 32-bit `shape_seed`
//! transferred in the auth extension. From that seed they derive:
//!
//! - The initial `cover_profile_id` (one of 5 baseline shapes).
//! - A monotonically increasing schedule of `(t_ms, next_shape_id)` pairs,
//!   spaced 30 minutes ± 10 minutes of seed-derived jitter (spec §22.1).
//!
//! No wire negotiation is required because both endpoints derive the
//! identical sequence; `SHAPE_PROBE`/`SHAPE_ACK` inner packets only act
//! as a 5-second pre-transition smoothing window (§22.2).

use sha2::{Digest, Sha256};

/// Baseline cover-shape catalogue. spec §22.4.
pub const SHAPES: [u16; 5] = [
    proteus_spec::COVER_PROFILE_STREAMING,
    proteus_spec::COVER_PROFILE_API_POLL,
    proteus_spec::COVER_PROFILE_VIDEO_CALL,
    proteus_spec::COVER_PROFILE_FILE_DL,
    proteus_spec::COVER_PROFILE_WEB_BROWSE,
];

/// Mean interval between shape transitions (30 min, in milliseconds).
pub const SHIFT_INTERVAL_MS: u64 = 30 * 60 * 1000;

/// Maximum jitter window (±10 min, in milliseconds). spec §22.1.
pub const SHIFT_JITTER_MS: u64 = 10 * 60 * 1000;

/// SHA-256-based counter-mode PRG. Avoids pulling in a full RNG crate.
///
/// Output sequence: `H(seed || counter)`, 32 bytes per step, big-endian
/// counter starting at 0.
pub struct ShapePrg {
    seed: u32,
    counter: u64,
    buf: [u8; 32],
    buf_pos: usize,
}

impl ShapePrg {
    /// Create a fresh PRG from the given seed.
    #[must_use]
    pub fn new(seed: u32) -> Self {
        let mut me = Self {
            seed,
            counter: 0,
            buf: [0u8; 32],
            buf_pos: 32,
        };
        me.refill();
        me
    }

    fn refill(&mut self) {
        let mut h = Sha256::new();
        h.update(b"proteus-shape-prg-v1");
        h.update(self.seed.to_be_bytes());
        h.update(self.counter.to_be_bytes());
        let digest = h.finalize();
        self.buf.copy_from_slice(&digest);
        self.buf_pos = 0;
        self.counter += 1;
    }

    fn next_u32(&mut self) -> u32 {
        if self.buf_pos + 4 > 32 {
            self.refill();
        }
        let v = u32::from_be_bytes([
            self.buf[self.buf_pos],
            self.buf[self.buf_pos + 1],
            self.buf[self.buf_pos + 2],
            self.buf[self.buf_pos + 3],
        ]);
        self.buf_pos += 4;
        v
    }
}

/// One entry in the shape-shift schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShiftEvent {
    /// Time of transition, measured in milliseconds from session start.
    pub t_ms: u64,
    /// Cover-profile id to install at `t_ms`.
    pub shape_id: u16,
}

/// Compute the first `n` entries of the shape-shift schedule for a given
/// `shape_seed`. spec §22.1.
///
/// The first entry has `t_ms = 0` and identifies the initial shape (so the
/// caller can install it immediately on handshake completion).
#[must_use]
pub fn schedule(shape_seed: u32, n: usize) -> Vec<ShiftEvent> {
    let mut prg = ShapePrg::new(shape_seed);
    let mut out = Vec::with_capacity(n);
    let mut t_ms: u64 = 0;
    let mut prev_shape: Option<u16> = None;
    for _ in 0..n {
        // Pick a shape distinct from the previous one (avoid no-op transitions).
        let mut shape_id;
        loop {
            let idx = (prg.next_u32() as usize) % SHAPES.len();
            shape_id = SHAPES[idx];
            if prev_shape != Some(shape_id) {
                break;
            }
        }
        out.push(ShiftEvent { t_ms, shape_id });
        prev_shape = Some(shape_id);

        // Next transition: interval ± uniform jitter.
        let jitter_raw = prg.next_u32() as u64;
        let jitter = (jitter_raw % (2 * SHIFT_JITTER_MS)) as i64 - SHIFT_JITTER_MS as i64;
        let next_t = (SHIFT_INTERVAL_MS as i64) + jitter;
        debug_assert!(next_t > 0);
        t_ms += next_t as u64;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn schedule_is_deterministic_for_same_seed() {
        let a = schedule(0xdead_beef, 8);
        let b = schedule(0xdead_beef, 8);
        assert_eq!(a, b);
    }

    #[test]
    fn schedule_diverges_for_different_seeds() {
        let a = schedule(0xaaaa_aaaa, 8);
        let b = schedule(0x5555_5555, 8);
        assert_ne!(a, b);
    }

    #[test]
    fn schedule_starts_at_t_zero() {
        let s = schedule(42, 4);
        assert_eq!(s[0].t_ms, 0);
    }

    #[test]
    fn schedule_intervals_within_bounds() {
        let s = schedule(42, 16);
        for w in s.windows(2) {
            let delta = w[1].t_ms - w[0].t_ms;
            let lower = SHIFT_INTERVAL_MS - SHIFT_JITTER_MS;
            let upper = SHIFT_INTERVAL_MS + SHIFT_JITTER_MS;
            assert!(
                delta >= lower && delta < upper,
                "delta {delta} out of [{lower}, {upper})"
            );
        }
    }

    #[test]
    fn schedule_never_repeats_consecutive_shapes() {
        let s = schedule(99, 32);
        for w in s.windows(2) {
            assert_ne!(
                w[0].shape_id, w[1].shape_id,
                "consecutive shapes must differ"
            );
        }
    }

    #[test]
    fn schedule_uses_all_baseline_shapes_eventually() {
        let s = schedule(1, 64);
        let mut seen = BTreeSet::new();
        for ev in &s {
            seen.insert(ev.shape_id);
        }
        for &expected in &SHAPES {
            assert!(seen.contains(&expected), "shape {expected} never selected");
        }
    }
}
