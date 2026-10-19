//! Flat combining for contended AA pool admission.

use crate::{transaction::TempoPooledTransaction, tt_2d_pool::AA2dPool};
use parking_lot::{Mutex, RwLock};
use reth_transaction_pool::{PoolResult, ValidPoolTransaction, pool::AddedTransaction};
use std::sync::{Arc, mpsc};
use tempo_chainspec::hardfork::TempoHardfork;

/// Uncontended requests write directly; contended callers publish work for a combiner.
#[derive(Debug, Default)]
pub(super) struct AdmissionCombiner {
    pending: Mutex<Vec<Request>>,
    combiner: Mutex<()>,
}

impl AdmissionCombiner {
    pub(super) fn add(
        &self,
        pool: &RwLock<AA2dPool>,
        transaction: Arc<ValidPoolTransaction<TempoPooledTransaction>>,
        nonce: u64,
        hardfork: TempoHardfork,
    ) -> PoolResult<AddedTransaction<TempoPooledTransaction>> {
        if let Some(mut pool) = pool.try_write() {
            return pool.add_transaction(transaction, nonce, hardfork);
        }

        let (reply, result) = mpsc::sync_channel(1);
        self.pending.lock().push(Request {
            transaction,
            nonce,
            hardfork,
            reply,
        });

        // A follower may already have its result when the preceding combiner releases this guard.
        let _combiner = self.combiner.lock();
        if let Ok(result) = result.try_recv() {
            return result;
        }
        let requests = std::mem::take(&mut *self.pending.lock());
        {
            let mut pool = pool.write();
            for request in requests {
                let outcome =
                    pool.add_transaction(request.transaction, request.nonce, request.hardfork);
                // Each channel has one reserved slot and receives exactly one response.
                let _ = request.reply.send(outcome);
            }
        }
        result
            .recv()
            .expect("published admission request receives a result")
    }
}

#[derive(Debug)]
struct Request {
    transaction: Arc<ValidPoolTransaction<TempoPooledTransaction>>,
    nonce: u64,
    hardfork: TempoHardfork,
    reply: mpsc::SyncSender<PoolResult<AddedTransaction<TempoPooledTransaction>>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{TxBuilder, wrap_valid_tx};
    use alloy_primitives::{Address, U256};
    use reth_transaction_pool::{TransactionOrigin, error::PoolErrorKind};
    use std::{
        sync::Barrier,
        thread,
        time::{Duration, Instant},
    };

    #[test]
    fn contended_admission_preserves_duplicate_results_and_pool_contents() {
        for duplicate_requests in [false, true] {
            let pool = Arc::new(RwLock::new(AA2dPool::new(Default::default())));
            let combiner = Arc::new(AdmissionCombiner::default());
            let transaction = Arc::new(wrap_valid_tx(
                TxBuilder::aa(Address::repeat_byte(0x42))
                    .nonce_key(U256::ONE)
                    .build(),
                TransactionOrigin::External,
            ));
            let barrier = Arc::new(Barrier::new(9));
            let guard = pool.write();
            let combiner_guard = combiner.combiner.lock();
            let threads = (0..8)
                .map(|index| {
                    let pool = pool.clone();
                    let combiner = combiner.clone();
                    let transaction = if duplicate_requests {
                        transaction.clone()
                    } else {
                        Arc::new(wrap_valid_tx(
                            TxBuilder::aa(Address::repeat_byte(index + 1))
                                .nonce_key(U256::ONE)
                                .build(),
                            TransactionOrigin::External,
                        ))
                    };
                    let barrier = barrier.clone();
                    thread::spawn(move || {
                        barrier.wait();
                        combiner.add(&pool, transaction, 0, TempoHardfork::default())
                    })
                })
                .collect::<Vec<_>>();
            barrier.wait();
            let deadline = Instant::now() + Duration::from_secs(5);
            while combiner.pending.lock().len() < 8 && Instant::now() < deadline {
                thread::yield_now();
            }
            let published = combiner.pending.lock().len();
            drop(guard);
            drop(combiner_guard);
            let mut admitted = 0;
            let mut duplicates = 0;
            for thread in threads {
                match thread.join().unwrap() {
                    Ok(_) => admitted += 1,
                    Err(error) => {
                        assert!(matches!(error.kind, PoolErrorKind::AlreadyImported));
                        duplicates += 1;
                    }
                }
            }
            assert_eq!(
                published, 8,
                "all callers publish while the combiner is occupied"
            );
            let expected = if duplicate_requests { 1 } else { 8 };
            assert_eq!(admitted, expected);
            assert_eq!(duplicates, 8 - expected);
            assert_eq!(pool.read().pending_and_queued_txn_count(), (expected, 0));
            assert!(combiner.pending.lock().is_empty());
        }
    }
}
