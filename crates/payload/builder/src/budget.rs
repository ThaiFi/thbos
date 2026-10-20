//! Existing build-decision regression tests.

#[cfg(test)]
mod tests {
    use std::time::Duration;
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
}
