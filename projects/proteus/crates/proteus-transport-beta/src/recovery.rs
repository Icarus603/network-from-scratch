//! Direction-local, matched-probe selection for QUIC loss recovery.
//!
//! A static packet threshold cannot be optimal for both genuine loss and
//! severe reordering. This module keeps the safety decision separate from
//! ordinary application traffic: only equal-sized, explicitly paired probes
//! may influence the selected profile. Each endpoint runs an independent
//! selector for its own send direction.

use std::collections::BTreeMap;
use std::time::Duration;

/// The two recovery profiles compared by a matched probe round.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RecoveryProfile {
    /// RFC-style prompt loss detection.
    Standard,
    /// Delayed loss detection for paths with measured reordering.
    ReorderTolerant,
}

/// Packet- and time-threshold pair applied to one local send direction.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RecoveryThresholds {
    pub packet_threshold: u32,
    pub time_threshold: f32,
}

/// Which direction this selector controls.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RecoveryDirection {
    ClientToServer,
    ServerToClient,
}

/// Loss counters observed while one probe profile was active.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct RecoveryCounters {
    pub sent_packets: u64,
    pub declared_lost_packets: u64,
    pub spurious_lost_packets: u64,
}

/// One half of an equal-sized matched probe round.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RecoveryObservation {
    pub round: u64,
    pub profile: RecoveryProfile,
    pub payload_bytes: u64,
    /// `None` records a failed or timed-out probe.
    pub completion_time: Option<Duration>,
    pub counters: RecoveryCounters,
}

/// Tunable guardrails for profile promotion.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RecoveryPolicy {
    pub standard: RecoveryThresholds,
    pub reorder_tolerant: RecoveryThresholds,
    /// Number of complete A/B rounds required before any promotion.
    pub minimum_matched_rounds: usize,
    /// Fixed history bound; older rounds are forgotten so decisions can
    /// follow a changed path without unbounded process-lifetime state.
    pub maximum_retained_rounds: usize,
    /// Small probes are dominated by scheduling and handshake noise.
    pub minimum_probe_bytes: u64,
    /// Required reduction in median completion time, as a fraction.
    pub minimum_completion_gain: f64,
    /// Minimum standard-profile loss declarations needed to classify
    /// reordering rather than treating a few packets as noise.
    pub minimum_loss_evidence_packets: u64,
    /// Fraction of declared losses later acknowledged that constitutes
    /// reordering evidence.
    pub minimum_spurious_fraction: f64,
    /// A meaningful declared-loss rate with too little spurious evidence
    /// is treated as genuine loss and hard-vetoes the tolerant profile.
    pub minimum_real_loss_rate: f64,
}

impl Default for RecoveryPolicy {
    fn default() -> Self {
        Self {
            standard: RecoveryThresholds {
                packet_threshold: 3,
                time_threshold: 1.125,
            },
            reorder_tolerant: RecoveryThresholds {
                packet_threshold: 10,
                time_threshold: 1.125,
            },
            minimum_matched_rounds: 3,
            maximum_retained_rounds: 9,
            minimum_probe_bytes: 4 * 1024 * 1024,
            minimum_completion_gain: 0.05,
            minimum_loss_evidence_packets: 32,
            // The first matched netem signal audit measured 0.025% on
            // IID loss versus 0.50%--1.36% under zero-drop reordering.
            // Keep this configurable; broader two-host evidence may move it.
            minimum_spurious_fraction: 0.0025,
            minimum_real_loss_rate: 0.01,
        }
    }
}

impl RecoveryPolicy {
    fn validate(self) -> Result<Self, RecoverySelectorError> {
        if self.standard.packet_threshold < 3
            || self.reorder_tolerant.packet_threshold < 3
            || !self.standard.time_threshold.is_finite()
            || !self.reorder_tolerant.time_threshold.is_finite()
            || self.standard.time_threshold < 1.125
            || self.reorder_tolerant.time_threshold < 1.125
            || self.minimum_matched_rounds == 0
            || self.maximum_retained_rounds < self.minimum_matched_rounds
            || self.minimum_probe_bytes == 0
            || !(0.0..1.0).contains(&self.minimum_completion_gain)
            || self.minimum_loss_evidence_packets == 0
            || !(0.0..=1.0).contains(&self.minimum_spurious_fraction)
            || !(0.0..=1.0).contains(&self.minimum_real_loss_rate)
        {
            return Err(RecoverySelectorError::InvalidPolicy);
        }
        Ok(self)
    }

    #[must_use]
    pub fn thresholds(self, profile: RecoveryProfile) -> RecoveryThresholds {
        match profile {
            RecoveryProfile::Standard => self.standard,
            RecoveryProfile::ReorderTolerant => self.reorder_tolerant,
        }
    }
}

/// Why the selector currently keeps or changes its profile.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecoveryDecision {
    Collecting {
        matched_rounds: usize,
        required_rounds: usize,
    },
    StandardInsufficientEvidence,
    StandardRealLossVeto {
        declared_loss_rate: f64,
        spurious_fraction: f64,
    },
    StandardTolerantProbeFailed,
    StandardNoCompletionGain {
        completion_gain: f64,
    },
    ReorderTolerant {
        completion_gain: f64,
        spurious_fraction: f64,
    },
}

impl RecoveryDecision {
    #[must_use]
    pub fn profile(self) -> RecoveryProfile {
        match self {
            Self::ReorderTolerant { .. } => RecoveryProfile::ReorderTolerant,
            _ => RecoveryProfile::Standard,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RecoverySelectorError {
    InvalidPolicy,
    ProbeTooSmall,
    InvalidCompletionTime,
    DuplicateObservation,
    MismatchedPayload,
}

#[derive(Debug, Clone, Copy, Default)]
struct ProbeRound {
    standard: Option<RecoveryObservation>,
    tolerant: Option<RecoveryObservation>,
}

impl ProbeRound {
    fn insert(&mut self, observation: RecoveryObservation) -> Result<(), RecoverySelectorError> {
        match observation.profile {
            RecoveryProfile::Standard => {
                if self.standard.is_some() {
                    return Err(RecoverySelectorError::DuplicateObservation);
                }
                if self
                    .tolerant
                    .is_some_and(|sample| sample.payload_bytes != observation.payload_bytes)
                {
                    return Err(RecoverySelectorError::MismatchedPayload);
                }
                self.standard = Some(observation);
            }
            RecoveryProfile::ReorderTolerant => {
                if self.tolerant.is_some() {
                    return Err(RecoverySelectorError::DuplicateObservation);
                }
                if self
                    .standard
                    .is_some_and(|sample| sample.payload_bytes != observation.payload_bytes)
                {
                    return Err(RecoverySelectorError::MismatchedPayload);
                }
                self.tolerant = Some(observation);
            }
        }
        Ok(())
    }

    fn pair(self) -> Option<(RecoveryObservation, RecoveryObservation)> {
        Some((self.standard?, self.tolerant?))
    }
}

/// Stateful selector for one endpoint's local send direction.
pub struct RecoverySelector {
    direction: RecoveryDirection,
    policy: RecoveryPolicy,
    rounds: BTreeMap<u64, ProbeRound>,
}

impl RecoverySelector {
    pub fn new(
        direction: RecoveryDirection,
        policy: RecoveryPolicy,
    ) -> Result<Self, RecoverySelectorError> {
        Ok(Self {
            direction,
            policy: policy.validate()?,
            rounds: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn direction(&self) -> RecoveryDirection {
        self.direction
    }

    /// Deterministically alternates A/B order to remove a fixed warm-cache
    /// advantage from either profile.
    #[must_use]
    pub fn profile_order(round: u64) -> [RecoveryProfile; 2] {
        if round & 1 == 0 {
            [RecoveryProfile::ReorderTolerant, RecoveryProfile::Standard]
        } else {
            [RecoveryProfile::Standard, RecoveryProfile::ReorderTolerant]
        }
    }

    pub fn observe(
        &mut self,
        observation: RecoveryObservation,
    ) -> Result<RecoveryDecision, RecoverySelectorError> {
        if observation.payload_bytes < self.policy.minimum_probe_bytes {
            return Err(RecoverySelectorError::ProbeTooSmall);
        }
        if observation.completion_time == Some(Duration::ZERO) {
            return Err(RecoverySelectorError::InvalidCompletionTime);
        }
        let round = self.rounds.entry(observation.round).or_default();
        round.insert(observation)?;
        while self.rounds.len() > self.policy.maximum_retained_rounds {
            self.rounds.pop_first();
        }
        Ok(self.evaluate())
    }

    #[must_use]
    pub fn evaluate(&self) -> RecoveryDecision {
        let pairs: Vec<_> = self
            .rounds
            .values()
            .filter_map(|round| round.pair())
            .collect();
        if pairs.len() < self.policy.minimum_matched_rounds {
            return RecoveryDecision::Collecting {
                matched_rounds: pairs.len(),
                required_rounds: self.policy.minimum_matched_rounds,
            };
        }

        let mut standard_times = Vec::with_capacity(pairs.len());
        let mut tolerant_times = Vec::with_capacity(pairs.len());
        let mut standard_counters = RecoveryCounters::default();
        for (standard, tolerant) in pairs {
            let Some(standard_time) = standard.completion_time else {
                return RecoveryDecision::StandardInsufficientEvidence;
            };
            let Some(tolerant_time) = tolerant.completion_time else {
                return RecoveryDecision::StandardTolerantProbeFailed;
            };
            standard_times.push(standard_time);
            tolerant_times.push(tolerant_time);
            add_counters(&mut standard_counters, standard.counters);
        }

        let declared_loss_rate = ratio(
            standard_counters.declared_lost_packets,
            standard_counters.sent_packets,
        );
        let spurious_fraction = ratio(
            standard_counters.spurious_lost_packets,
            standard_counters.declared_lost_packets,
        );
        let enough_loss_evidence =
            standard_counters.declared_lost_packets >= self.policy.minimum_loss_evidence_packets;

        if enough_loss_evidence
            && declared_loss_rate >= self.policy.minimum_real_loss_rate
            && spurious_fraction < self.policy.minimum_spurious_fraction
        {
            return RecoveryDecision::StandardRealLossVeto {
                declared_loss_rate,
                spurious_fraction,
            };
        }
        if !enough_loss_evidence || spurious_fraction < self.policy.minimum_spurious_fraction {
            return RecoveryDecision::StandardInsufficientEvidence;
        }

        let standard_median = median_duration(&mut standard_times);
        let tolerant_median = median_duration(&mut tolerant_times);
        let completion_gain = 1.0 - tolerant_median.as_secs_f64() / standard_median.as_secs_f64();
        if completion_gain < self.policy.minimum_completion_gain {
            return RecoveryDecision::StandardNoCompletionGain { completion_gain };
        }
        RecoveryDecision::ReorderTolerant {
            completion_gain,
            spurious_fraction,
        }
    }

    #[must_use]
    pub fn selected_thresholds(&self) -> RecoveryThresholds {
        self.policy.thresholds(self.evaluate().profile())
    }
}

fn add_counters(total: &mut RecoveryCounters, sample: RecoveryCounters) {
    total.sent_packets = total.sent_packets.saturating_add(sample.sent_packets);
    total.declared_lost_packets = total
        .declared_lost_packets
        .saturating_add(sample.declared_lost_packets);
    total.spurious_lost_packets = total
        .spurious_lost_packets
        .saturating_add(sample.spurious_lost_packets);
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn median_duration(values: &mut [Duration]) -> Duration {
    values.sort_unstable();
    let middle = values.len() / 2;
    if values.len() & 1 == 0 {
        (values[middle - 1] + values[middle]) / 2
    } else {
        values[middle]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROBE_BYTES: u64 = 4 * 1024 * 1024;

    fn observation(
        round: u64,
        profile: RecoveryProfile,
        millis: Option<u64>,
        sent: u64,
        lost: u64,
        spurious: u64,
    ) -> RecoveryObservation {
        RecoveryObservation {
            round,
            profile,
            payload_bytes: PROBE_BYTES,
            completion_time: millis.map(Duration::from_millis),
            counters: RecoveryCounters {
                sent_packets: sent,
                declared_lost_packets: lost,
                spurious_lost_packets: spurious,
            },
        }
    }

    fn feed_round(
        selector: &mut RecoverySelector,
        round: u64,
        standard_ms: Option<u64>,
        tolerant_ms: Option<u64>,
        standard_counters: (u64, u64, u64),
    ) -> RecoveryDecision {
        let (sent, lost, spurious) = standard_counters;
        let order = RecoverySelector::profile_order(round);
        let mut decision = selector.evaluate();
        for profile in order {
            let sample = match profile {
                RecoveryProfile::Standard => {
                    observation(round, profile, standard_ms, sent, lost, spurious)
                }
                RecoveryProfile::ReorderTolerant => {
                    observation(round, profile, tolerant_ms, sent, lost / 2, spurious)
                }
            };
            decision = selector.observe(sample).unwrap();
        }
        decision
    }

    #[test]
    fn profile_order_alternates_without_random_seed() {
        assert_eq!(
            RecoverySelector::profile_order(1),
            [RecoveryProfile::Standard, RecoveryProfile::ReorderTolerant]
        );
        assert_eq!(
            RecoverySelector::profile_order(2),
            [RecoveryProfile::ReorderTolerant, RecoveryProfile::Standard]
        );
    }

    #[test]
    fn promotes_tolerant_only_after_matched_reordering_win() {
        let mut selector =
            RecoverySelector::new(RecoveryDirection::ClientToServer, RecoveryPolicy::default())
                .unwrap();
        for round in 1..=2 {
            assert!(matches!(
                feed_round(
                    &mut selector,
                    round,
                    Some(100),
                    Some(75),
                    (10_000, 5_000, 100)
                ),
                RecoveryDecision::Collecting { .. }
            ));
        }
        assert!(matches!(
            feed_round(
                &mut selector,
                3,
                Some(100),
                Some(75),
                (10_000, 5_000, 100)
            ),
            RecoveryDecision::ReorderTolerant {
                completion_gain,
                spurious_fraction
            } if completion_gain > 0.24 && spurious_fraction == 0.02
        ));
        assert_eq!(
            selector.selected_thresholds(),
            RecoveryPolicy::default().reorder_tolerant
        );
    }

    #[test]
    fn genuine_loss_hard_vetoes_tolerant_even_when_faster() {
        let mut selector =
            RecoverySelector::new(RecoveryDirection::ServerToClient, RecoveryPolicy::default())
                .unwrap();
        for round in 1..=3 {
            let decision = feed_round(&mut selector, round, Some(100), Some(70), (10_000, 500, 0));
            if round == 3 {
                assert!(matches!(
                    decision,
                    RecoveryDecision::StandardRealLossVeto {
                        declared_loss_rate,
                        spurious_fraction: 0.0
                    } if declared_loss_rate == 0.05
                ));
            }
        }
    }

    #[test]
    fn reordering_without_completion_gain_keeps_standard() {
        let mut selector =
            RecoverySelector::new(RecoveryDirection::ClientToServer, RecoveryPolicy::default())
                .unwrap();
        for round in 1..=3 {
            let decision = feed_round(
                &mut selector,
                round,
                Some(100),
                Some(105),
                (10_000, 5_000, 100),
            );
            if round == 3 {
                assert!(matches!(
                    decision,
                    RecoveryDecision::StandardNoCompletionGain { completion_gain }
                        if completion_gain < 0.0
                ));
            }
        }
    }

    #[test]
    fn failed_tolerant_probe_fails_closed() {
        let mut selector =
            RecoverySelector::new(RecoveryDirection::ClientToServer, RecoveryPolicy::default())
                .unwrap();
        for round in 1..=3 {
            let decision = feed_round(&mut selector, round, Some(100), None, (10_000, 5_000, 100));
            if round == 3 {
                assert_eq!(decision, RecoveryDecision::StandardTolerantProbeFailed);
            }
        }
    }

    #[test]
    fn mismatched_payload_cannot_enter_decision_window() {
        let mut selector =
            RecoverySelector::new(RecoveryDirection::ClientToServer, RecoveryPolicy::default())
                .unwrap();
        selector
            .observe(observation(
                1,
                RecoveryProfile::Standard,
                Some(100),
                100,
                10,
                1,
            ))
            .unwrap();
        let mut mismatched = observation(1, RecoveryProfile::ReorderTolerant, Some(80), 100, 10, 1);
        mismatched.payload_bytes += 1;
        assert_eq!(
            selector.observe(mismatched),
            Err(RecoverySelectorError::MismatchedPayload)
        );
        assert_eq!(
            selector.rounds.get(&1).unwrap().tolerant,
            None,
            "a rejected half-round must not poison later evaluation"
        );
    }

    #[test]
    fn history_is_bounded_and_tracks_recent_path_state() {
        let policy = RecoveryPolicy {
            minimum_matched_rounds: 1,
            maximum_retained_rounds: 3,
            ..RecoveryPolicy::default()
        };
        let mut selector =
            RecoverySelector::new(RecoveryDirection::ClientToServer, policy).unwrap();
        for round in 1..=5 {
            feed_round(
                &mut selector,
                round,
                Some(100),
                Some(75),
                (10_000, 5_000, 100),
            );
        }
        assert_eq!(selector.rounds.len(), 3);
        assert_eq!(selector.rounds.first_key_value().unwrap().0, &3);
    }

    #[test]
    fn zero_duration_probe_is_rejected() {
        let mut selector =
            RecoverySelector::new(RecoveryDirection::ClientToServer, RecoveryPolicy::default())
                .unwrap();
        assert_eq!(
            selector.observe(observation(
                1,
                RecoveryProfile::Standard,
                Some(0),
                100,
                10,
                1,
            )),
            Err(RecoverySelectorError::InvalidCompletionTime)
        );
    }
}
