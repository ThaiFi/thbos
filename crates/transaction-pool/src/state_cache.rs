//! Tip-scoped concurrent cache of state reads shared across transaction validations.

use alloy_primitives::{Address, B256, U256, map::DefaultHashBuilder};
use moka::{policy::EvictionPolicy, sync::Cache};
use revm::{Database, DatabaseRef, bytecode::Bytecode, state::AccountInfo};

/// Concurrent cache of raw state reads anchored to a specific tip.
///
/// Transaction validation repeatedly reads the same state (system contract configuration,
/// fee token slots, sender accounts) for every transaction. This cache shares those reads
/// across all concurrent validation calls so only the first access hits the underlying
/// state provider.
///
/// The validator replaces the cache whenever a new head block is processed, mirroring the
/// lifecycle of its cached EVM environment.
#[derive(Debug)]
pub(crate) struct StateCache {
    /// Cached basic account info, including non-existent accounts (`None`).
    accounts: Cache<Address, Option<AccountInfo>, DefaultHashBuilder>,
    /// Cached storage values keyed by account and slot.
    storage: Cache<(Address, U256), U256, DefaultHashBuilder>,
    /// Cached bytecode keyed by code hash.
    contracts: Cache<B256, Bytecode, DefaultHashBuilder>,
}

impl StateCache {
    /// Maximum number of cached accounts.
    ///
    /// The caps bound memory if a flood of unique accounts is validated within a single
    /// block interval. TinyLFU admission can retain frequently used reads after reaching a cap.
    const MAX_ACCOUNTS: usize = 1 << 17;
    /// Maximum number of cached storage slots.
    const MAX_STORAGE_SLOTS: usize = 1 << 18;
    /// Maximum number of cached contracts.
    const MAX_CONTRACTS: usize = 1 << 12;
}

impl Default for StateCache {
    fn default() -> Self {
        Self {
            accounts: Cache::builder()
                .max_capacity(Self::MAX_ACCOUNTS as u64)
                .eviction_policy(EvictionPolicy::tiny_lfu())
                .build_with_hasher(Default::default()),
            storage: Cache::builder()
                .max_capacity(Self::MAX_STORAGE_SLOTS as u64)
                .eviction_policy(EvictionPolicy::tiny_lfu())
                .build_with_hasher(Default::default()),
            contracts: Cache::builder()
                .max_capacity(Self::MAX_CONTRACTS as u64)
                .eviction_policy(EvictionPolicy::tiny_lfu())
                .build_with_hasher(Default::default()),
        }
    }
}

/// A [`DatabaseRef`] adapter that serves reads from a shared [`StateCache`], falling back
/// to the wrapped database and populating the cache on miss.
#[derive(Debug)]
#[expect(unnameable_types)]
pub struct StateCacheDb<'a, DB> {
    /// The shared read cache.
    cache: &'a StateCache,
    /// The underlying database.
    db: DB,
}

impl<'a, DB> StateCacheDb<'a, DB> {
    pub(crate) const fn new(cache: &'a StateCache, db: DB) -> Self {
        Self { cache, db }
    }
}

impl<DB: DatabaseRef> DatabaseRef for StateCacheDb<'_, DB> {
    type Error = DB::Error;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if let Some(account) = self.cache.accounts.get(&address) {
            return Ok(account);
        }
        let account = self.db.basic_ref(address)?;
        self.cache.accounts.insert(address, account.clone());
        Ok(account)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if let Some(code) = self.cache.contracts.get(&code_hash) {
            return Ok(code);
        }
        let code = self.db.code_by_hash_ref(code_hash)?;
        self.cache.contracts.insert(code_hash, code.clone());
        Ok(code)
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        if let Some(value) = self.cache.storage.get(&(address, index)) {
            return Ok(value);
        }
        let value = self.db.storage_ref(address, index)?;
        self.cache.storage.insert((address, index), value);
        Ok(value)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.db.block_hash_ref(number)
    }
}

impl<DB: DatabaseRef> Database for StateCacheDb<'_, DB> {
    type Error = DB::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.basic_ref(address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.code_by_hash_ref(code_hash)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.storage_ref(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.block_hash_ref(number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct CountingDb {
        reads: AtomicUsize,
    }

    impl DatabaseRef for CountingDb {
        type Error = core::convert::Infallible;

        fn basic_ref(&self, _address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok(Some(AccountInfo {
                balance: U256::ONE,
                ..Default::default()
            }))
        }

        fn code_by_hash_ref(&self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok(Bytecode::default())
        }

        fn storage_ref(&self, _address: Address, _index: U256) -> Result<U256, Self::Error> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok(U256::from(42))
        }

        fn block_hash_ref(&self, _number: u64) -> Result<B256, Self::Error> {
            Ok(B256::ZERO)
        }
    }

    #[test]
    fn caches_reads_across_instances() {
        let cache = StateCache::default();
        let inner = CountingDb::default();
        let address = Address::with_last_byte(1);
        let slot = U256::from(7);

        {
            let db = StateCacheDb::new(&cache, &inner);
            assert_eq!(db.storage_ref(address, slot).unwrap(), U256::from(42));
            assert!(db.basic_ref(address).unwrap().is_some());
        }
        assert_eq!(inner.reads.load(Ordering::Relaxed), 2);

        // A new adapter over the same cache serves all reads from memory.
        let db = StateCacheDb::new(&cache, &inner);
        assert_eq!(db.storage_ref(address, slot).unwrap(), U256::from(42));
        assert!(db.basic_ref(address).unwrap().is_some());
        assert_eq!(inner.reads.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn eviction_preserves_database_results_and_tip_isolation() {
        let cache = StateCache {
            storage: Cache::builder()
                .max_capacity(2)
                .eviction_policy(EvictionPolicy::tiny_lfu())
                .build_with_hasher(Default::default()),
            ..Default::default()
        };
        let inner = CountingDb::default();
        let address = Address::with_last_byte(1);
        let db = StateCacheDb::new(&cache, &inner);
        for _ in 0..3 {
            for slot in 0..32 {
                assert_eq!(
                    db.storage_ref(address, U256::from(slot)).unwrap(),
                    U256::from(42)
                );
                cache.storage.run_pending_tasks();
            }
        }
        assert!(cache.storage.entry_count() <= 2);
        assert!(inner.reads.load(Ordering::Relaxed) > 2);

        let new_tip = StateCache::default();
        let before = inner.reads.load(Ordering::Relaxed);
        let db = StateCacheDb::new(&new_tip, &inner);
        assert_eq!(db.storage_ref(address, U256::ZERO).unwrap(), U256::from(42));
        assert_eq!(inner.reads.load(Ordering::Relaxed), before + 1);
    }
}
