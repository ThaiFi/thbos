//! The pre-state blocks execute on, and how the state they leave is reported.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, Ordering},
    },
};

use alloy_primitives::{Address, B256, Bytes, U256};
use reth_trie_common::{
    TrieAccount,
    root::{state_root_unhashed, storage_root_unhashed},
};
use revm::{
    DatabaseRef,
    bytecode::Bytecode,
    database::{Cache, CacheDB, DBErrorMarker, DbAccount, EmptyDB},
    state::{AccountInfo, EvmState},
};
use tempo_fuzz_types::{
    AccountDiff, AccountInput, ErrorClass, PreState, StateInput, StorageChangeOutput, TxStateDiff,
};

/// The in-memory state blocks execute on.
pub(crate) type Db = CacheDB<PreStateDb>;

/// What execution reads when the seeded state does not hold a key. For a
/// genesis pre-state that is empty state. For an exact pre-state it is an
/// error, also recorded in a flag that clones share, so the input is known to
/// be incomplete even when the error was swallowed on its way up.
#[derive(Clone, Debug)]
pub(crate) struct PreStateDb {
    exact: bool,
    missed: Arc<AtomicBool>,
}

impl PreStateDb {
    fn new(exact: bool) -> Self {
        Self {
            exact,
            missed: Arc::default(),
        }
    }

    /// Whether a read missed an exact pre-state.
    pub(crate) fn missed(&self) -> bool {
        self.missed.load(Ordering::Relaxed)
    }

    /// Sets the miss flag, e.g. back to a value saved before reads that are
    /// not part of execution.
    pub(crate) fn restore_missed(&self, missed: bool) {
        self.missed.store(missed, Ordering::Relaxed);
    }

    fn miss(&self, key: Missing) -> Result<(), MissingPreState> {
        if !self.exact {
            return Ok(());
        }
        self.missed.store(true, Ordering::Relaxed);
        Err(MissingPreState(key))
    }
}

#[derive(Debug)]
enum Missing {
    Account(Address),
    Storage(Address, U256),
    Code(B256),
    BlockHash(u64),
}

/// A read of a key an exact pre-state does not hold.
#[derive(Debug)]
pub(crate) struct MissingPreState(Missing);

impl fmt::Display for MissingPreState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the exact pre-state does not hold ")?;
        match &self.0 {
            Missing::Account(address) => write!(f, "account {address}"),
            Missing::Storage(address, slot) => write!(f, "slot {slot} of {address}"),
            Missing::Code(hash) => write!(f, "code {hash}"),
            Missing::BlockHash(number) => write!(f, "the hash of block {number}"),
        }
    }
}

impl core::error::Error for MissingPreState {}

impl DBErrorMarker for MissingPreState {}

/// Answers misses on a genesis pre-state the way revm's `EmptyDB` does, which
/// fuzz inputs rely on.
impl DatabaseRef for PreStateDb {
    type Error = MissingPreState;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.miss(Missing::Account(address))?;
        let Ok(info) = EmptyDB::new().basic_ref(address);
        Ok(info)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.miss(Missing::Code(code_hash))?;
        let Ok(code) = EmptyDB::new().code_by_hash_ref(code_hash);
        Ok(code)
    }

    fn storage_ref(&self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.miss(Missing::Storage(address, slot))?;
        let Ok(value) = EmptyDB::new().storage_ref(address, slot);
        Ok(value)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.miss(Missing::BlockHash(number))?;
        let Ok(hash) = EmptyDB::new().block_hash_ref(number);
        Ok(hash)
    }
}

/// The dev genesis allocation, seeded once per process: seeding analyses and
/// hashes every genesis contract, which costs more than executing a transfer.
static GENESIS: LazyLock<Cache> = LazyLock::new(|| {
    let mut db = CacheDB::new(PreStateDb::new(false));
    for (address, account) in &tempo_chainspec::spec::DEV.inner.genesis.alloc {
        let info = account_info(
            account.balance,
            account.nonce.unwrap_or_default(),
            account.code.clone().unwrap_or_default(),
        );
        let storage = account
            .storage
            .iter()
            .flatten()
            .map(|(slot, value)| ((*slot).into(), (*value).into()));
        insert(&mut db, *address, info, storage);
    }
    db.cache
});

/// `pre_state` as a database. `InvalidInput` if a genesis pre-state overrides
/// a genesis account.
pub(crate) fn seed(pre_state: &PreState) -> Result<Db, ErrorClass> {
    match pre_state {
        PreState::Genesis(state) => {
            if state
                .accounts
                .keys()
                .any(|address| GENESIS.accounts.contains_key(address))
            {
                return Err(ErrorClass::InvalidInput);
            }
            let mut db = CacheDB {
                cache: GENESIS.clone(),
                db: PreStateDb::new(false),
            };
            for (address, account) in &state.accounts {
                insert_input(&mut db, *address, account);
            }
            Ok(db)
        }
        PreState::Exact {
            state,
            block_hashes,
        } => {
            let mut db = CacheDB::new(PreStateDb::new(true));
            for (address, account) in &state.accounts {
                if is_empty(account) {
                    db.cache
                        .accounts
                        .insert(*address, DbAccount::new_not_existing());
                } else {
                    insert_input(&mut db, *address, account);
                }
            }
            db.cache.block_hashes.extend(
                block_hashes
                    .iter()
                    .map(|(number, hash)| (U256::from(*number), *hash)),
            );
            Ok(db)
        }
    }
}

fn is_empty(account: &AccountInput) -> bool {
    account.balance.is_zero()
        && account.nonce == 0
        && account.code.is_empty()
        && account.storage.is_empty()
}

fn account_info(balance: U256, nonce: u64, code: Bytes) -> AccountInfo {
    AccountInfo::from_balance(balance)
        .with_nonce(nonce)
        .with_code(Bytecode::new_raw(code))
}

fn insert_input(db: &mut Db, address: Address, account: &AccountInput) {
    let info = account_info(account.balance, account.nonce, account.code.clone());
    let storage = account.storage.iter().map(|(slot, value)| (*slot, *value));
    insert(db, address, info, storage);
}

/// Inserts an account and the slots the pre-state holds for it.
fn insert(
    db: &mut Db,
    address: Address,
    info: AccountInfo,
    storage: impl Iterator<Item = (U256, U256)>,
) {
    db.insert_account_info(address, info);
    db.cache
        .accounts
        .get_mut(&address)
        .expect("the account was just inserted")
        .storage
        .extend(storage);
}

/// The accounts `db` holds that exist and are not empty, with their non-zero
/// slots, in no particular order.
fn accounts(db: &Db) -> impl Iterator<Item = (Address, AccountInfo, BTreeMap<U256, U256>)> + '_ {
    db.cache.accounts.iter().filter_map(|(address, account)| {
        let info = account.info()?;
        let storage: BTreeMap<_, _> = account
            .storage
            .iter()
            .filter(|(_, value)| !value.is_zero())
            .map(|(slot, value)| (*slot, *value))
            .collect();
        let empty = info.is_empty() && storage.is_empty();
        (!empty).then_some((*address, info, storage))
    })
}

/// The state `db` holds.
pub(crate) fn encode(db: &Db) -> StateInput {
    let accounts = accounts(db)
        .map(|(address, info, storage)| {
            let account = AccountInput {
                balance: info.balance,
                nonce: info.nonce,
                code: code(db, &info),
                storage,
            };
            (address, account)
        })
        .collect();
    StateInput { accounts }
}

fn code(db: &Db, info: &AccountInfo) -> Bytes {
    match &info.code {
        Some(code) => code.original_bytes(),
        None => db
            .cache
            .contracts
            .get(&info.code_hash)
            .map(Bytecode::original_bytes)
            .unwrap_or_default(),
    }
}

/// The state root of `db`, which must hold the whole state.
pub(crate) fn state_root(db: &Db) -> B256 {
    state_root_unhashed(accounts(db).map(|(address, info, storage)| {
        let storage = storage
            .into_iter()
            .map(|(slot, value)| (B256::from(slot), value));
        let account = TrieAccount {
            nonce: info.nonce,
            balance: info.balance,
            storage_root: storage_root_unhashed(storage),
            code_hash: info.code_hash,
        };
        (address, account)
    }))
}

/// How `after` differs from `before`: per account, the balance, nonce and code
/// that changed, and every slot that changed.
pub(crate) fn diff(
    before: &StateInput,
    after: &StateInput,
) -> (Vec<AccountDiff>, Vec<StorageChangeOutput>) {
    let empty = AccountInput::default();
    let addresses: BTreeSet<_> = before
        .accounts
        .keys()
        .chain(after.accounts.keys())
        .collect();
    let mut accounts = Vec::new();
    let mut storage = Vec::new();
    for &address in addresses {
        let old = before.accounts.get(&address).unwrap_or(&empty);
        let new = after.accounts.get(&address).unwrap_or(&empty);
        let code = (old.code != new.code).then(|| new.code.clone());
        accounts.extend(account_diff(
            address,
            (old.balance, new.balance),
            (old.nonce, new.nonce),
            code,
        ));

        let slots: BTreeSet<_> = old.storage.keys().chain(new.storage.keys()).collect();
        for &slot in slots {
            let value =
                |account: &AccountInput| account.storage.get(&slot).copied().unwrap_or_default();
            let (before, after) = (value(old), value(new));
            if before != after {
                storage.push(StorageChangeOutput {
                    address,
                    slot,
                    before,
                    after,
                });
            }
        }
    }
    (accounts, storage)
}

/// What a transaction's `changes` do to `db`, before they are committed.
pub(crate) fn tx_diff(db: &Db, changes: &EvmState, block_index: u64, tx_index: u64) -> TxStateDiff {
    let touched: BTreeMap<_, _> = changes
        .iter()
        .filter(|(_, account)| account.is_touched())
        .collect();
    let mut accounts = Vec::new();
    let mut storage = Vec::new();
    for (&address, account) in touched {
        let before = db
            .cache
            .accounts
            .get(&address)
            .and_then(DbAccount::info)
            .unwrap_or_default();
        let after = if account.is_selfdestructed() {
            AccountInfo::default()
        } else {
            account.info.clone()
        };
        let code = (before.code_hash != after.code_hash).then(|| code(db, &after));
        accounts.extend(account_diff(
            address,
            (before.balance, after.balance),
            (before.nonce, after.nonce),
            code,
        ));

        let changed: BTreeMap<_, _> = account
            .storage
            .iter()
            .filter(|(_, slot)| slot.is_changed())
            .collect();
        storage.extend(
            changed
                .into_iter()
                .map(|(&slot, value)| StorageChangeOutput {
                    address,
                    slot,
                    before: value.original_value(),
                    after: value.present_value(),
                }),
        );
    }
    TxStateDiff {
        block_index,
        tx_index,
        accounts,
        storage,
    }
}

/// An account's change from `(before, after)` balances and nonces and its new
/// code, if it changed; `None` if nothing did.
fn account_diff(
    address: Address,
    (old_balance, balance): (U256, U256),
    (old_nonce, nonce): (u64, u64),
    code: Option<Bytes>,
) -> Option<AccountDiff> {
    let diff = AccountDiff {
        address,
        balance: (old_balance != balance).then_some(balance),
        nonce: (old_nonce != nonce).then_some(nonce),
        code,
    };
    (diff.balance.is_some() || diff.nonce.is_some() || diff.code.is_some()).then_some(diff)
}
