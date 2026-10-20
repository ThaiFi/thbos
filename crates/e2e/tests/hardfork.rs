//! The default verification policy follows T14 without restarting validators.

use std::time::{Duration, UNIX_EPOCH};

use alloy_primitives::Sealable as _;
use commonware_macros::test_traced;
use commonware_runtime::{
    Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;
use reth_ethereum::provider::BlockReader as _;
use tempo_e2e::{
    Setup,
    metrics::{MetricsExt as _, wait_for_height, wait_for_metrics},
    setup_validators,
};

#[test_traced]
fn verification_switches_to_deferred_at_t14() {
    let _ = tempo_eyre::install();
    const ACTIVATION: u64 = 5;
    let setup = Setup::default().epoch_length(10).t14_time(ACTIVATION);
    let config = Config::default()
        .with_seed(setup.seed)
        .with_start_time(UNIX_EPOCH)
        .with_timeout(Some(Duration::from_secs(60)));

    Runner::from(config).start(|mut context| async move {
        let (mut validators, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(validators.iter_mut().map(|node| node.start(&context))).await;

        wait_for_metrics(&context, |metrics| {
            validators.iter().all(|node| {
                metrics
                    .for_scope(node)
                    .value::<u64>("immediate_verifications_total")
                    .unwrap()
                    > 0
            })
        })
        .await;
        for node in &validators {
            let metrics = context.to_metrics().for_scope(node);
            assert_eq!(
                metrics.value::<u64>("deferred_verifications_total"),
                Some(0)
            );
            let height = metrics.latest_consensus_height().unwrap();
            let block = node
                .execution_provider()
                .block_by_number(height)
                .unwrap()
                .unwrap();
            assert!(block.header.inner.timestamp < ACTIVATION);
        }

        wait_for_metrics(&context, |metrics| {
            validators.iter().all(|node| {
                metrics
                    .for_scope(node)
                    .value::<u64>("deferred_verifications_total")
                    .unwrap()
                    > 0
            })
        })
        .await;
        let switched = context.to_metrics();
        let target = validators
            .iter()
            .map(|node| switched.for_scope(node).latest_consensus_height().unwrap())
            .max()
            .unwrap()
            + 15;
        join_all(
            validators
                .iter()
                .map(|node| wait_for_height(&context, node, target)),
        )
        .await;

        let mut expected = None;
        for node in &validators {
            let metrics = context.to_metrics().for_scope(node);
            // Pre-fork verification must stop even as the network keeps finalizing.
            assert_eq!(
                metrics.value::<u64>("immediate_verifications_total"),
                switched
                    .for_scope(node)
                    .value::<u64>("immediate_verifications_total"),
            );
            assert!(
                metrics
                    .value::<u64>("deferred_verifications_total")
                    .unwrap()
                    > switched
                        .for_scope(node)
                        .value::<u64>("deferred_verifications_total")
                        .unwrap()
            );
            let block = node
                .execution_provider()
                .block_by_number(target)
                .unwrap()
                .unwrap();
            assert!(block.header.inner.timestamp >= ACTIVATION);
            if let Some(hash) = expected {
                assert_eq!(block.header.hash_slow(), hash);
            } else {
                expected = Some(block.header.hash_slow());
            }
        }
    });
}
