//! Stop decisions for paced payload builds.

use std::time::Duration;

use crate::{ValidationLatencyEstimate, ValidationLatencyWorkload};

/// Fixed-point scale for build time multipliers.
pub const BUILD_TIME_MULTIPLIER_SCALE: u64 = 1_000_000;

/// Point-in-time inputs for one payload build's stop decision.
///
/// The builder snapshots this once per build so the same estimates apply to
/// every decision within that build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuildPlan {
    /// Remaining proposal budget handed to this build.
    pub build_budget: Duration,
    multiplier_scaled: u64,
    validation_latency: Option<ValidationLatencyEstimate>,
}

/// Breakdown of the time a build must still reserve at a given moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayloadBudgetDecision {
    /// Replayable proposer work projected from the work done so far.
    pub predicted_builder_work: Duration,
    /// Validator replay work, from feedback when available.
    pub predicted_validator_work: Duration,
    /// Projected total time of the build and its replay: the idle time so
    /// far plus the projected builder and validator work, including the work
    /// already done.
    pub total_reserved: Duration,
}

impl BuildPlan {
    /// Creates a plan from a fixed-point multiplier and validation feedback.
    pub fn new(
        build_budget: Duration,
        multiplier_scaled: u64,
        validation_latency: Option<ValidationLatencyEstimate>,
    ) -> Self {
        Self {
            build_budget,
            multiplier_scaled,
            validation_latency,
        }
    }

    /// The build time multiplier in use.
    pub fn build_time_multiplier(&self) -> f64 {
        self.multiplier_scaled as f64 / BUILD_TIME_MULTIPLIER_SCALE as f64
    }

    /// Computes what the proposal still has to reserve.
    ///
    /// `elapsed` is wall-clock time spent in the builder so far, `idle_elapsed` the
    /// part of it spent waiting for transactions, which validators do not replay.
    /// Builder work is projected with the multiplier; validator work comes from
    /// feedback, capped at the builder projection.
    pub fn decision(
        &self,
        elapsed: Duration,
        idle_elapsed: Duration,
        current_workload: ValidationLatencyWorkload,
    ) -> PayloadBudgetDecision {
        let work_elapsed = elapsed.saturating_sub(idle_elapsed);
        let predicted_builder_work = scaled_duration(work_elapsed, self.multiplier_scaled);

        let predicted_validator_work = self
            .validation_latency
            .and_then(|estimate| estimate.estimate(current_workload))
            .map(|estimate| estimate.min(predicted_builder_work))
            .unwrap_or(predicted_builder_work);
        let total_reserved = idle_elapsed
            .saturating_add(predicted_builder_work)
            .saturating_add(predicted_validator_work);
        PayloadBudgetDecision {
            predicted_builder_work,
            predicted_validator_work,
            total_reserved,
        }
    }

    /// Whether the build has to stop adding transactions now.
    pub fn exhausted(&self, decision: &PayloadBudgetDecision) -> bool {
        decision.total_reserved >= self.build_budget
    }
}

fn scaled_duration(elapsed: Duration, multiplier: u64) -> Duration {
    Duration::from_nanos(
        (elapsed.as_nanos().saturating_mul(u128::from(multiplier))
            / u128::from(BUILD_TIME_MULTIPLIER_SCALE))
        .min(u128::from(u64::MAX)) as u64,
    )
}
