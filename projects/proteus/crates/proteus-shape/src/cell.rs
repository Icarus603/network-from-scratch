//! Cell padding selection for each transport profile (spec §4.6).
//!
//! Per spec §4.6: each outgoing datagram MUST be padded to a profile-and-
//! shape-specific target size. The selection within a profile's cell set
//! is **per-session deterministic** from the `shape_seed`, not per-packet
//! random — random-per-packet would leak entropy that no real cover has.

use proteus_spec::{CELL_SIZES_ALPHA, CELL_SIZES_BETA, CELL_SIZES_GAMMA};

/// Transport profile selector (mirrors `proteus_wire::ProfileHint`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Profile {
    Alpha,
    Beta,
    Gamma,
}

impl Profile {
    /// Cell-size set for this profile.
    #[must_use]
    pub fn cell_sizes(self) -> &'static [u16] {
        match self {
            Self::Alpha => CELL_SIZES_ALPHA,
            Self::Beta => CELL_SIZES_BETA,
            Self::Gamma => CELL_SIZES_GAMMA,
        }
    }

    /// Choose the cell size for this session, deterministically from
    /// `shape_seed`.
    #[must_use]
    pub fn pick_cell_size(self, shape_seed: u32) -> u16 {
        let sizes = self.cell_sizes();
        sizes[(shape_seed as usize) % sizes.len()]
    }
}

/// Number of padding bytes required to bring `current_len` up to `cell_size`.
///
/// Returns 0 if the packet is already at or above the cell size (in which
/// case the caller MUST NOT split the packet — `current_len > cell_size`
/// means the packet was already too big and shaping does not apply).
#[must_use]
pub fn padding_needed(current_len: u16, cell_size: u16) -> u16 {
    cell_size.saturating_sub(current_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn cell_sizes_match_spec() {
        assert_eq!(Profile::Gamma.cell_sizes(), &[1252, 1280, 1452]);
        assert_eq!(Profile::Beta.cell_sizes(), &[1200, 1252, 1280]);
        assert_eq!(Profile::Alpha.cell_sizes(), &[1372, 1448]);
    }

    #[test]
    fn pick_is_deterministic() {
        for seed in [0u32, 1, 0xdead_beef, 0xffff_ffff] {
            let a = Profile::Gamma.pick_cell_size(seed);
            let b = Profile::Gamma.pick_cell_size(seed);
            assert_eq!(a, b);
        }
    }

    #[test]
    fn pick_covers_full_set() {
        for profile in [Profile::Alpha, Profile::Beta, Profile::Gamma] {
            let mut hits = BTreeSet::new();
            for seed in 0..1024 {
                hits.insert(profile.pick_cell_size(seed));
            }
            for &size in profile.cell_sizes() {
                assert!(
                    hits.contains(&size),
                    "size {size} unreached for {profile:?}"
                );
            }
        }
    }

    #[test]
    fn padding_needed_is_saturating() {
        assert_eq!(padding_needed(100, 1280), 1180);
        assert_eq!(padding_needed(1280, 1280), 0);
        assert_eq!(padding_needed(2000, 1280), 0);
    }
}
