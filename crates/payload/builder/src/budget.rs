//! Budget helpers for deciding when to stop executing pool transactions.
//!
//! The builder can stop transaction execution, but it still has to finish
//! non-interruptible finalization work like state hashing, state root updates,
//! and block assembly. These helpers learn the relation between tx execution
//! cutoff time, total replayable build work, and validation latency feedback.
//!
//! The decision model is:
//! `leader_idle + predicted_builder_work + predicted_validator_work >= budget`.
//! Idle waiting only happens on the proposer. Builder work is projected from the
//! current build, while validator work uses feedback from previously validated
//! blocks when available and otherwise falls back to the builder projection.

use std::time::Duration;

use tempo_payload_types::BUILD_TIME_MULTIPLIER_SCALE;

#[cfg(test)]
const DEFAULT_BUILD_TIME_MULTIPLIER_SCALED: u64 = 1_350_000;
const MAX_BUILD_TIME_MULTIPLIER: u64 = 1_700_000;
/// How quickly the multiplier decays when observed builds get cheaper.
const BUILD_TIME_MULTIPLIER_DECAY: u64 = 8;

/// Initial estimate of total replayable build work divided by work at tx cutoff.
///
/// For example, `1.35` means "when cutoff work is 100 ms, expect the completed
/// replayable build work to be about 135 ms".
pub const DEFAULT_BUILD_TIME_MULTIPLIER: f64 = 1.35;

/// Converts a human-readable build-work multiplier into the fixed-point representation.
pub(crate) fn scaled_build_time_multiplier(multiplier: f64) -> u64 {
    assert!(
        multiplier.is_finite() && multiplier >= 1.0,
        "build time multiplier must be finite and >= 1.0"
    );

    (multiplier * BUILD_TIME_MULTIPLIER_SCALE as f64).round() as u64
}

/// Computes the observed total-work to tx-cutoff-work multiplier.
///
/// `work_at_tx_cutoff` is measured when pool transaction execution stops.
/// `total_work` is measured after finalization finishes. Their ratio captures
/// `builder_finish` without needing a separate fixed reserve.
pub(crate) fn observed_build_time_multiplier(
    total_work: Duration,
    work_at_tx_cutoff: Duration,
) -> Option<u64> {
    if work_at_tx_cutoff == Duration::ZERO {
        return None;
    }

    let multiplier = total_work
        .as_nanos()
        .saturating_mul(u128::from(BUILD_TIME_MULTIPLIER_SCALE))
        / work_at_tx_cutoff.as_nanos();
    Some(multiplier.min(u128::from(MAX_BUILD_TIME_MULTIPLIER)) as u64)
}

/// Updates the multiplier, immediately rising but slowly decaying.
pub(crate) fn decay_build_time_multiplier(current: u64, observed: u64) -> u64 {
    if observed >= current {
        observed
    } else {
        let decay = ((current - observed) / BUILD_TIME_MULTIPLIER_DECAY).max(1);
        current.saturating_sub(decay).max(observed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempo_payload_types::{
        BuildPlan, ValidationLatencyEstimate, ValidationLatencyEstimator, ValidationLatencyWorkload,
    };

    fn validation_latency_estimate(
        workload: ValidationLatencyWorkload,
        elapsed: Duration,
    ) -> Option<ValidationLatencyEstimate> {
        let mut estimator = ValidationLatencyEstimator::default();
        estimator.observe(1, workload, elapsed);
        estimator.estimate()
    }

    #[test]
    fn observed_build_multiplier_tracks_tail_cost() {
        assert_eq!(
            observed_build_time_multiplier(Duration::from_millis(135), Duration::from_millis(100)),
            Some(DEFAULT_BUILD_TIME_MULTIPLIER_SCALED)
        );
        assert_eq!(
            observed_build_time_multiplier(Duration::from_millis(100), Duration::from_millis(100)),
            Some(1_000_000)
        );
        assert_eq!(
            observed_build_time_multiplier(Duration::from_millis(250), Duration::from_millis(100)),
            Some(MAX_BUILD_TIME_MULTIPLIER)
        );
        assert_eq!(decay_build_time_multiplier(1_500_000, 1_300_000), 1_475_000);
    }

    #[test]
    fn payload_budget_accounts_for_leader_idle_once() {
        let decision = BuildPlan::new(Duration::MAX, 1_350_000, None).decision(
            Duration::from_millis(100),
            Duration::ZERO,
            ValidationLatencyWorkload::default(),
        );
        assert_eq!(decision.predicted_builder_work, Duration::from_millis(135));
        assert_eq!(
            decision.predicted_validator_work,
            Duration::from_millis(135)
        );
        assert_eq!(decision.total_reserved, Duration::from_millis(270));

        let decision = BuildPlan::new(Duration::MAX, 1_350_000, None).decision(
            Duration::from_millis(350),
            Duration::from_millis(250),
            ValidationLatencyWorkload::default(),
        );
        assert_eq!(decision.predicted_builder_work, Duration::from_millis(135));
        assert_eq!(
            decision.predicted_validator_work,
            Duration::from_millis(135)
        );
        assert_eq!(decision.total_reserved, Duration::from_millis(520));
    }

    #[test]
    fn payload_budget_uses_validator_feedback_when_available() {
        let workload = ValidationLatencyWorkload::new(100, 0);
        let validation_latency = validation_latency_estimate(workload, Duration::from_millis(80));
        let decision = BuildPlan::new(Duration::MAX, 1_350_000, validation_latency).decision(
            Duration::from_millis(100),
            Duration::ZERO,
            workload,
        );

        assert_eq!(decision.predicted_builder_work, Duration::from_millis(135));
        assert_eq!(decision.predicted_validator_work, Duration::from_millis(80));
        assert_eq!(decision.total_reserved, Duration::from_millis(215));
    }

    #[test]
    fn payload_budget_caps_scaled_validator_feedback_at_builder_projection() {
        let validation_latency = validation_latency_estimate(
            ValidationLatencyWorkload::new(100, 10),
            Duration::from_millis(100),
        );
        let decision = BuildPlan::new(Duration::MAX, 1_350_000, validation_latency).decision(
            Duration::from_millis(100),
            Duration::ZERO,
            ValidationLatencyWorkload::new(200, 10),
        );

        assert_eq!(
            decision.predicted_validator_work,
            Duration::from_millis(135)
        );
        assert_eq!(decision.total_reserved, Duration::from_millis(270));
    }

    #[test]
    fn build_multiplier_scales_decimal_values() {
        assert_eq!(
            scaled_build_time_multiplier(DEFAULT_BUILD_TIME_MULTIPLIER),
            DEFAULT_BUILD_TIME_MULTIPLIER_SCALED
        );
    }
}
