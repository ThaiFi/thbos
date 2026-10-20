use std::{collections::BTreeMap, sync::Arc};

use alloy_consensus::{Signed, TxLegacy};
use alloy_eips::{Decodable2718, Encodable2718};
use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256, address};
use alloy_sol_types::SolCall;
use bincode::Options as _;
use commonware_codec::Encode as _;
use revm::{Database as _, database::BundleState};
use tempo_chainspec::hardfork::{TempoHardfork, TempoHardforks};
use tempo_contracts::precompiles::{CURRENT_COMMITTEE_ADDRESS, ITIP20, PATH_USD_ADDRESS};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus};
use tempo_fuzz_types::{
    AccountDiff, AccountInput, BlockContextInput, BlockHeaderInput, ChainSpecInput, ErrorClass,
    FUZZ_ACCEPT, FUZZ_REJECT, InvariantScope, NonEmpty, PreState, StateChanges, StateInput,
    TempoBlock, TempoBlockchainInput, TempoExecutionOutcome, TempoHarnessCapabilities,
    TempoHarnessInput, TempoHarnessOutcome, TempoTransactionInput, TxOutcome,
};
use tempo_precompiles::tip20::slots::{SUPPLY_CAP, TOTAL_SUPPLY};
use tempo_primitives::TempoTxEnvelope;

use crate::{bincode_options, chain, execute, state};

/// Dev account 0, funded with pathUSD in the dev genesis.
const SENDER: Address = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
const RECIPIENT: Address = address!("00000000000000000000000000000000000000aa");

fn transfer(chain_id: u64, nonce: u64, amount: u64) -> Bytes {
    tip20_transfer(chain_id, nonce, RECIPIENT, U256::from(amount), 1_000_000)
}

/// A pathUSD transfer, signed with a placeholder: tests give its sender.
fn tip20_transfer(chain_id: u64, nonce: u64, to: Address, amount: U256, gas_limit: u64) -> Bytes {
    let input = ITIP20::transferCall { to, amount }.abi_encode();
    call(chain_id, nonce, PATH_USD_ADDRESS, input.into(), gas_limit)
}

/// A call without value, signed with a placeholder: tests give its sender.
fn call(chain_id: u64, nonce: u64, to: Address, input: Bytes, gas_limit: u64) -> Bytes {
    let tx = TempoTxEnvelope::Legacy(Signed::new_unhashed(
        TxLegacy {
            chain_id: Some(chain_id),
            nonce,
            gas_price: 0,
            gas_limit,
            to: TxKind::Call(to),
            value: U256::ZERO,
            input,
        },
        Signature::test_signature(),
    ));
    tx.encoded_2718().into()
}

fn context(hardfork: TempoHardfork, timestamp: u64) -> BlockContextInput {
    BlockContextInput {
        hardfork,
        timestamp,
        ..Default::default()
    }
}

fn block(header: BlockHeaderInput, txs: Vec<Bytes>) -> TempoBlock {
    let senders = vec![SENDER; txs.len()];
    TempoBlock {
        header,
        txs,
        senders,
    }
}

fn transfer_block() -> TempoBlock {
    let chain_id = ChainSpecInput::default().chain_id;
    block(
        BlockHeaderInput::Context(context(TempoHardfork::T4, 0)),
        vec![transfer(chain_id, 0, 7)],
    )
}

fn run(
    chain: ChainSpecInput,
    pre_state: PreState,
    blocks: Vec<TempoBlock>,
) -> TempoExecutionOutcome {
    let input = TempoHarnessInput::Blockchain(TempoBlockchainInput {
        chain_spec: chain,
        pre_state,
        blocks: NonEmpty::new(blocks).expect("tests execute at least one block"),
    });
    let TempoHarnessOutcome::Blockchain(outcome) = execute::run(input) else {
        panic!("a blockchain input has a blockchain outcome");
    };
    outcome
}

fn genesis() -> PreState {
    PreState::Genesis(StateInput::default())
}

fn exact(state: StateInput) -> PreState {
    PreState::Exact {
        state,
        block_hashes: BTreeMap::new(),
    }
}

/// The whole dev genesis state, as an outcome reports it.
fn genesis_state() -> StateInput {
    let db = state::seed(&genesis()).expect("the dev genesis seeds");
    let accounts = state::after(&db.cache, &BundleState::default());
    state::encode(&accounts, &db.cache.contracts)
}

/// The dev genesis as an exact pre-state for `blocks`, listing what they read, as an extractor
/// reading a witness would: every account and slot execution loads, zeros included, with its value
/// before the blocks.
fn exact_genesis(blocks: &[TempoBlock]) -> StateInput {
    let spec = Arc::new(chain::chain_spec(&ChainSpecInput::default()).unwrap());
    let mut db = state::seed(&genesis()).unwrap();
    let blocks: Vec<_> = blocks
        .iter()
        .map(|block| execute::recover_block(&spec, block).unwrap())
        .collect();
    let mut outcome = TempoExecutionOutcome::default();
    let _ = execute::execute_blocks(
        &TempoEvmConfig::new(Arc::clone(&spec)),
        &TempoConsensus::new(spec),
        &mut db,
        &blocks,
        &mut outcome,
    );
    assert_eq!(outcome.error, ErrorClass::None);

    let before = genesis_state();
    let accounts = db
        .cache
        .accounts
        .iter()
        .map(|(address, account)| {
            let mut listed = before.accounts.get(address).cloned().unwrap_or_default();
            for slot in account
                .account
                .iter()
                .flat_map(|account| account.storage.keys())
            {
                listed.storage.entry(*slot).or_insert(U256::ZERO);
            }
            (*address, listed)
        })
        .collect();
    StateInput { accounts }
}

fn path_usd(state: &mut StateInput) -> &mut AccountInput {
    state
        .accounts
        .get_mut(&PATH_USD_ADDRESS)
        .expect("the dev genesis holds pathUSD")
}

/// The state root of `state`, computed independently of the harness.
fn trie_root(state: &StateInput) -> B256 {
    use reth_trie_common::{
        TrieAccount,
        root::{state_root_unhashed, storage_root_unhashed},
    };
    state_root_unhashed(state.accounts.iter().map(|(address, account)| {
        let storage = account
            .storage
            .iter()
            .map(|(slot, value)| (B256::from(*slot), *value));
        let code_hash = if account.code.is_empty() {
            revm::primitives::KECCAK_EMPTY
        } else {
            alloy_primitives::keccak256(&account.code)
        };
        let trie_account = TrieAccount {
            nonce: account.nonce,
            balance: account.balance,
            storage_root: storage_root_unhashed(storage),
            code_hash,
        };
        (*address, trie_account)
    }))
}

#[test]
fn a_transfer_reports_its_receipt_changes_and_state_root() {
    let outcome = run(ChainSpecInput::default(), genesis(), vec![transfer_block()]);

    assert_eq!(outcome.error, ErrorClass::None);
    assert_eq!(outcome.receipts.len(), 1);
    let receipt = &outcome.receipts[0];
    assert_eq!(receipt.outcome, TxOutcome::Success);
    assert!(receipt.gas.tx_gas_used() > 0);
    assert_eq!(receipt.cumulative_gas_used, receipt.gas.tx_gas_used());
    assert_eq!(
        receipt.output,
        Bytes::from(U256::from(1).to_be_bytes::<32>())
    );
    assert_eq!(receipt.logs.len(), 1, "one Transfer event");
    assert!(
        outcome.invariant_failures.is_empty(),
        "{:?}",
        outcome.invariant_failures
    );

    // The transfer moves two pathUSD balances and creates the sender, which
    // the dev genesis funds only with pathUSD; the block's total includes it all.
    assert_eq!(outcome.state_diff.blocks.len(), 1);
    let sender = outcome.state_diff.blocks[0].txs[0]
        .accounts
        .iter()
        .find(|account| account.address == SENDER)
        .expect("the transaction bumps the sender's nonce");
    assert_eq!((sender.exists, sender.nonce), (Some(true), Some(1)));
    assert!(outcome.state_diff.total.accounts.contains(sender));
    let tx_changes = &outcome.state_diff.blocks[0].txs[0].storage;
    let path_usd: Vec<_> = tx_changes
        .iter()
        .filter(|change| change.address == PATH_USD_ADDRESS)
        .collect();
    assert_eq!(path_usd.len(), 2, "{tx_changes:?}");
    for change in path_usd {
        assert!(outcome.state_diff.total.storage.contains(change));
    }

    assert_eq!(outcome.state_root, Some(trie_root(&outcome.final_state)));
    assert_ne!(outcome.final_state, genesis_state());
}

#[test]
fn changes_that_cancel_out_within_a_block_are_not_in_the_total() {
    // The recipient sends the transfer straight back: both balances end where
    // they started, so only the nonces change overall.
    let chain_id = ChainSpecInput::default().chain_id;
    let back = tip20_transfer(chain_id, 0, SENDER, U256::from(7), 1_000_000);
    let block = TempoBlock {
        header: BlockHeaderInput::Context(context(TempoHardfork::T4, 0)),
        txs: vec![transfer(chain_id, 0, 7), back],
        senders: vec![SENDER, RECIPIENT],
    };
    let outcome = run(ChainSpecInput::default(), genesis(), vec![block]);
    assert_eq!(outcome.error, ErrorClass::None);

    let path_usd = |changes: &tempo_fuzz_types::StateChanges| {
        changes
            .storage
            .iter()
            .filter(|change| change.address == PATH_USD_ADDRESS)
            .count()
    };
    let txs = &outcome.state_diff.blocks[0].txs;
    assert_eq!((path_usd(&txs[0]), path_usd(&txs[1])), (2, 2));
    assert_eq!(
        path_usd(&outcome.state_diff.total),
        0,
        "{:?}",
        outcome.state_diff.total
    );
    let nonces = outcome
        .state_diff
        .total
        .accounts
        .iter()
        .filter(|account| account.nonce == Some(1));
    assert_eq!(nonces.count(), 2);
}

#[test]
fn receipts_tell_reverts_and_halts_apart() {
    let chain_id = ChainSpecInput::default().chain_id;
    let outcome = |amount, gas_limit| {
        let tx = tip20_transfer(chain_id, 0, RECIPIENT, amount, gas_limit);
        let block = block(
            BlockHeaderInput::Context(context(TempoHardfork::T4, 0)),
            vec![tx],
        );
        let outcome = run(ChainSpecInput::default(), genesis(), vec![block]);
        assert_eq!(outcome.error, ErrorClass::None);
        outcome.receipts[0].clone()
    };

    // More than the sender holds: the token reverts with its error.
    let reverted = outcome(U256::MAX, 1_000_000);
    assert_eq!(reverted.outcome, TxOutcome::Revert);
    assert!(!reverted.output.is_empty(), "the revert carries its error");

    // One gas short of what the transfer uses: it starts, and runs out.
    let needed = outcome(U256::from(1), 1_000_000).gas.tx_gas_used();
    let halted = outcome(U256::from(1), needed - 1);
    assert!(matches!(halted.outcome, TxOutcome::Halt(_)), "{halted:?}");
    assert_eq!(halted.gas.tx_gas_used(), needed - 1);
}

#[test]
fn system_calls_are_reported_apart_from_transactions() {
    // EIP-2935 stores the parent hash before the transactions run.
    let spec = chain::chain_spec(&ChainSpecInput::default()).unwrap();
    let tx = transfer(ChainSpecInput::default().chain_id, 0, 7);
    let mut header = chain::header(
        &spec,
        &BlockHeaderInput::Context(context(TempoHardfork::T4, 0)),
    )
    .unwrap();
    header.inner.parent_hash = B256::repeat_byte(1);
    header.inner.transactions_root =
        alloy_consensus::proofs::calculate_transaction_root(&[TempoTxEnvelope::decode_2718_exact(
            &tx,
        )
        .unwrap()]);
    let rlp = BlockHeaderInput::Rlp(alloy_rlp::encode(&header).into());
    let outcome = run(
        ChainSpecInput::default(),
        genesis(),
        vec![block(rlp, vec![tx])],
    );
    assert_eq!(outcome.error, ErrorClass::None);

    let history = alloy_eips::eip2935::HISTORY_STORAGE_ADDRESS;
    let parent = |changes: &tempo_fuzz_types::StateChanges| {
        changes
            .storage
            .iter()
            .any(|change| change.address == history && change.after == U256::from_be_bytes([1; 32]))
    };
    let steps = &outcome.state_diff.blocks[0];
    assert!(parent(&steps.pre_block), "{:?}", steps.pre_block);
    assert!(!parent(&steps.txs[0]));
    assert!(parent(&outcome.state_diff.total));
}

#[test]
fn an_exact_pre_state_replays_like_the_genesis_it_lists() {
    let from_genesis = run(ChainSpecInput::default(), genesis(), vec![transfer_block()]);
    let replayed = run(
        ChainSpecInput::default(),
        exact(exact_genesis(&[transfer_block()])),
        vec![transfer_block()],
    );

    assert_eq!(replayed.error, ErrorClass::None);
    assert_eq!(replayed.receipts, from_genesis.receipts);
    assert_eq!(replayed.state_diff, from_genesis.state_diff);
    assert_eq!(replayed.final_state, from_genesis.final_state);
    assert_eq!(replayed.state_root, None);
}

#[test]
fn reading_outside_an_exact_pre_state_is_reported() {
    // The sender's balance slot is one the transfer reads.
    let from_genesis = run(ChainSpecInput::default(), genesis(), vec![transfer_block()]);
    let read = from_genesis.state_diff.blocks[0].txs[0]
        .storage
        .iter()
        .find(|change| change.address == PATH_USD_ADDRESS)
        .expect("the transfer changes pathUSD")
        .slot;

    let mut state = exact_genesis(&[transfer_block()]);
    path_usd(&mut state).storage.remove(&read);
    let outcome = run(
        ChainSpecInput::default(),
        exact(state),
        vec![transfer_block()],
    );
    assert_eq!(outcome.error, ErrorClass::IncompletePreState);
    assert!(outcome.receipts.is_empty());
    let mut unchanged = genesis_state();
    path_usd(&mut unchanged).storage.remove(&read);
    assert_eq!(outcome.final_state, unchanged);

    let missing_account = run(
        ChainSpecInput::default(),
        exact(StateInput::default()),
        vec![transfer_block()],
    );
    assert_eq!(missing_account.error, ErrorClass::IncompletePreState);
}

#[test]
fn an_exact_pre_state_answers_listed_block_hashes_only() {
    let hash = B256::repeat_byte(7);
    let mut db = state::seed(&PreState::Exact {
        state: StateInput::default(),
        block_hashes: BTreeMap::from([(5, hash)]),
    })
    .unwrap();
    assert_eq!(db.block_hash(5).unwrap(), hash);
    assert!(!db.database.0.missed());
    assert!(db.block_hash(6).is_err());
    assert!(db.database.0.missed());
}

#[test]
fn an_empty_account_in_an_exact_pre_state_does_not_exist() {
    // Extractors list the zero slots a block read, even of absent accounts.
    let empty = AccountInput {
        storage: BTreeMap::from([(U256::from(3), U256::ZERO)]),
        ..Default::default()
    };
    let state = StateInput {
        accounts: BTreeMap::from([(RECIPIENT, empty)]),
    };
    let mut db = state::seed(&exact(state)).unwrap();
    assert_eq!(db.basic(RECIPIENT).unwrap(), None);
    assert_eq!(db.storage(RECIPIENT, U256::from(3)).unwrap(), U256::ZERO);
    assert!(!db.database.0.missed());
}

#[test]
fn an_empty_account_a_transaction_touches_is_destroyed() {
    // An account holding only storage is empty, so EIP-161 removes it, storage
    // and all, once a transaction touches it.
    let ghost = address!("00000000000000000000000000000000000000cc");
    let pre_state = StateInput {
        accounts: BTreeMap::from([(
            ghost,
            AccountInput {
                storage: BTreeMap::from([(U256::from(1), U256::from(5))]),
                ..Default::default()
            },
        )]),
    };
    let touch = call(
        ChainSpecInput::default().chain_id,
        0,
        ghost,
        Bytes::new(),
        1_000_000,
    );
    let outcome = run(
        ChainSpecInput::default(),
        PreState::Genesis(pre_state),
        vec![block(
            BlockHeaderInput::Context(context(TempoHardfork::T4, 0)),
            vec![touch],
        )],
    );

    assert_eq!(outcome.error, ErrorClass::None);
    assert!(!outcome.final_state.accounts.contains_key(&ghost));
    let destroyed = AccountDiff {
        address: ghost,
        exists: Some(false),
        balance: None,
        nonce: None,
        code: None,
        storage_cleared: true,
    };
    assert!(
        outcome.state_diff.blocks[0].txs[0]
            .accounts
            .contains(&destroyed)
    );
    assert!(outcome.state_diff.total.accounts.contains(&destroyed));
}

#[test]
fn a_recreated_account_keeps_none_of_its_earlier_slots() {
    use revm::{
        database::{AccountStatus, BundleAccount, CacheState},
        state::AccountInfo,
    };
    let mut pre = CacheState::new();
    let slots = [(U256::from(1), U256::from(5))].into_iter().collect();
    pre.insert_account_with_storage(RECIPIENT, AccountInfo::default(), slots);
    let mut bundle = BundleState::default();
    let recreated = BundleAccount {
        info: Some(AccountInfo::from_balance(U256::from(1))),
        original_info: Some(AccountInfo::default()),
        storage: Default::default(),
        status: AccountStatus::DestroyedChanged,
    };
    bundle.state.insert(RECIPIENT, recreated);

    let after = state::after(&pre, &bundle);
    assert_eq!(after[&RECIPIENT].info.balance, U256::from(1));
    assert!(after[&RECIPIENT].storage.is_empty());
}

#[test]
fn an_epoch_boundary_block_updates_the_committee_after_its_transactions() {
    // From T8 on, the last block of an epoch carries the DKG outcome that the
    // committee is set from.
    let spec = chain::chain_spec(&ChainSpecInput::default()).unwrap();
    let epoch_length = spec.info.epoch_length().expect("the dev chain has epochs");
    let boundary = |extra_data: Bytes| {
        let mut context = context(TempoHardfork::T13, 0);
        context.block_number = epoch_length.get() - 1;
        context.extra_data = extra_data;
        let block = block(BlockHeaderInput::Context(context), Vec::new());
        run(ChainSpecInput::default(), genesis(), vec![block])
    };
    let outcome = boundary(OnchainDkgOutcome::dealt(1, 3).encode().to_vec().into());
    assert_eq!(outcome.error, ErrorClass::None);
    let committee = |changes: &StateChanges| {
        changes
            .storage
            .iter()
            .any(|change| change.address == CURRENT_COMMITTEE_ADDRESS)
    };
    let steps = &outcome.state_diff.blocks[0];
    assert!(committee(&steps.post_block), "{:?}", steps.post_block);
    assert!(!committee(&steps.pre_block));
    assert!(committee(&outcome.state_diff.total));

    assert_eq!(boundary(Bytes::new()).error, ErrorClass::Rejected);
}

#[test]
fn broken_invariants_are_reported_without_stopping_execution() {
    let mut state = exact_genesis(&[transfer_block()]);
    // A supply below what the holders hold, and above the cap.
    let token = path_usd(&mut state);
    token.storage.insert(TOTAL_SUPPLY, U256::from(1));
    token.storage.insert(SUPPLY_CAP, U256::ZERO);
    let outcome = run(
        ChainSpecInput::default(),
        exact(state),
        vec![transfer_block()],
    );

    assert_eq!(outcome.error, ErrorClass::None);
    assert_eq!(outcome.receipts.len(), 1);
    let at = |id: &str, scope: InvariantScope| {
        outcome
            .invariant_failures
            .iter()
            .any(|failure| failure.id == id && failure.scope == scope)
    };
    for id in ["TEMPO-TIP20-SUPPLY-CAP", "TEMPO-TIP20-BALANCE-SUM"] {
        assert!(at(id, InvariantScope::Block { block_index: 0 }), "{id}");
        let tx = InvariantScope::Transaction {
            block_index: 0,
            tx_index: 0,
        };
        assert!(at(id, tx), "{id}");
    }
    assert!(
        outcome
            .invariant_failures
            .iter()
            .all(|failure| failure.message.contains(&PATH_USD_ADDRESS.to_string()))
    );
}

#[test]
fn invariant_views_of_keys_an_exact_pre_state_lacks_are_skipped() {
    // Drop pathUSD's supply slot: the supply views read it, the transfer does
    // not. The next token's cap is broken, and must still be checked.
    let mut state = exact_genesis(&[transfer_block()]);
    path_usd(&mut state).storage.remove(&TOTAL_SUPPLY);
    let next = Address::with_last_byte(1) | PATH_USD_ADDRESS;
    let token = state
        .accounts
        .get_mut(&next)
        .expect("the dev genesis holds a second token");
    token.storage.insert(TOTAL_SUPPLY, U256::from(1));
    token.storage.insert(SUPPLY_CAP, U256::ZERO);
    let outcome = run(
        ChainSpecInput::default(),
        exact(state),
        vec![transfer_block()],
    );

    assert_eq!(outcome.error, ErrorClass::None);
    let failures: Vec<_> = outcome
        .invariant_failures
        .iter()
        .map(|failure| (failure.id.as_str(), &failure.scope))
        .collect();
    let block = InvariantScope::Block { block_index: 0 };
    assert!(
        failures.contains(&("TEMPO-TIP20-SUPPLY-CAP", &block)),
        "{failures:?}"
    );
    assert!(
        outcome
            .invariant_failures
            .iter()
            .all(|failure| failure.message.contains(&next.to_string())),
        "{:?}",
        outcome.invariant_failures
    );
}

#[test]
fn the_chain_id_comes_from_the_input() {
    let chain = ChainSpecInput {
        chain_id: 1337,
        ..Default::default()
    };
    let on = |chain_id| {
        let block = block(
            BlockHeaderInput::Context(context(TempoHardfork::T4, 0)),
            vec![transfer(chain_id, 0, 7)],
        );
        run(chain.clone(), genesis(), vec![block]).error
    };
    assert_eq!(on(1337), ErrorClass::None);
    assert_eq!(on(ChainSpecInput::default().chain_id), ErrorClass::Rejected);
}

#[test]
fn an_rlp_header_executes_exactly_as_given() {
    let spec = chain::chain_spec(&ChainSpecInput::default()).unwrap();
    let tx = transfer(ChainSpecInput::default().chain_id, 0, 7);
    let mut header = chain::header(
        &spec,
        &BlockHeaderInput::Context(context(TempoHardfork::T4, 0)),
    )
    .unwrap();
    let decoded = TempoTxEnvelope::decode_2718_exact(&tx).unwrap();
    header.inner.transactions_root =
        alloy_consensus::proofs::calculate_transaction_root(&[decoded]);
    let rlp = |header: &tempo_primitives::TempoHeader| alloy_rlp::encode(header);

    let from_context = run(ChainSpecInput::default(), genesis(), vec![transfer_block()]);
    let from_rlp = run(
        ChainSpecInput::default(),
        genesis(),
        vec![block(
            BlockHeaderInput::Rlp(rlp(&header).into()),
            vec![tx.clone()],
        )],
    );
    assert_eq!(from_rlp, from_context);

    // The header must commit to the block's transactions.
    header.inner.transactions_root = B256::ZERO;
    let wrong_root = run(
        ChainSpecInput::default(),
        genesis(),
        vec![block(BlockHeaderInput::Rlp(rlp(&header).into()), vec![tx])],
    );
    assert_eq!(wrong_root.error, ErrorClass::Rejected);
    assert!(wrong_root.receipts.is_empty());

    let mut trailing = rlp(&header);
    trailing.push(0);
    let outcome = run(
        ChainSpecInput::default(),
        genesis(),
        vec![block(BlockHeaderInput::Rlp(trailing.into()), Vec::new())],
    );
    assert_eq!(outcome.error, ErrorClass::RlpDecode);
}

#[test]
fn a_failing_block_leaves_the_state_before_it() {
    let chain_id = ChainSpecInput::default().chain_id;
    let first = transfer_block();
    // Nonce 0 again: the second block's transaction is invalid.
    let second = block(
        BlockHeaderInput::Context(context(TempoHardfork::T4, 0)),
        vec![transfer(chain_id, 0, 9)],
    );
    let only_first = run(ChainSpecInput::default(), genesis(), vec![first.clone()]);
    let outcome = run(ChainSpecInput::default(), genesis(), vec![first, second]);

    assert_eq!(outcome.error, ErrorClass::Rejected);
    assert_eq!(outcome.receipts, only_first.receipts);
    assert_eq!(outcome.state_diff, only_first.state_diff);
    assert_eq!(outcome.final_state, only_first.final_state);
    assert_eq!(outcome.state_root, only_first.state_root);
}

#[test]
fn malformed_inputs_are_classified_rather_than_executed() {
    let default = ChainSpecInput::default;
    let error = |chain, pre_state, blocks| run(chain, pre_state, blocks).error;

    // Blocks going back in time.
    let late = block(
        BlockHeaderInput::Context(context(TempoHardfork::T5, 0)),
        Vec::new(),
    );
    let early = block(
        BlockHeaderInput::Context(context(TempoHardfork::T4, 0)),
        Vec::new(),
    );
    assert_eq!(
        error(default(), genesis(), vec![late, early]),
        ErrorClass::InvalidInput
    );

    // A schedule activating T3 after T4.
    let mut chain = default();
    chain.hardforks.insert(TempoHardfork::T3, u64::MAX);
    assert_eq!(
        error(chain, genesis(), vec![transfer_block()]),
        ErrorClass::InvalidInput
    );

    // A genesis pre-state overriding a genesis account.
    let mut overriding = StateInput::default();
    let token = path_usd(&mut genesis_state()).clone();
    overriding.accounts.insert(PATH_USD_ADDRESS, token);
    assert_eq!(
        error(
            default(),
            PreState::Genesis(overriding),
            vec![transfer_block()]
        ),
        ErrorClass::InvalidInput
    );

    // Senders that do not match the transactions, and transactions that do not decode.
    let mut mismatched = transfer_block();
    mismatched.senders.push(SENDER);
    assert_eq!(
        error(default(), genesis(), vec![mismatched]),
        ErrorClass::InvalidInput
    );
    let mut undecodable = transfer_block();
    let mut tx = undecodable.txs[0].to_vec();
    tx.push(0);
    undecodable.txs[0] = tx.into();
    assert_eq!(
        error(default(), genesis(), vec![undecodable]),
        ErrorClass::RlpDecode
    );
}

#[test]
fn the_schedule_defaults_unlisted_hardforks() {
    let chain = ChainSpecInput {
        chain_id: 1337,
        hardforks: BTreeMap::from([(TempoHardfork::T3, 100)]),
    };
    let spec = chain::chain_spec(&chain).unwrap();
    // Unlisted hardforks activate at their variant index...
    assert_eq!(spec.tempo_hardfork_at(0), TempoHardfork::Genesis);
    assert_eq!(spec.tempo_hardfork_at(1), TempoHardfork::T0);
    assert_eq!(spec.tempo_hardfork_at(3), TempoHardfork::T1A);
    assert_eq!(spec.tempo_hardfork_at(99), TempoHardfork::T2);
    // ...or with the hardfork before them, if that is later.
    assert_eq!(spec.tempo_hardfork_at(100), TempoHardfork::latest());

    // The default is Moderato's schedule.
    let spec = chain::chain_spec(&ChainSpecInput::default()).unwrap();
    let t4 = TempoHardfork::T4.moderato_activation_timestamp().unwrap();
    assert_eq!(spec.tempo_hardfork_at(t4 - 1), TempoHardfork::T3);
    assert_eq!(spec.tempo_hardfork_at(t4), TempoHardfork::T4);
}

#[test]
fn a_context_header_lands_where_its_hardfork_is_active() {
    let spec = chain::chain_spec(&ChainSpecInput::default()).unwrap();
    let at = |hardfork, timestamp| {
        let context = BlockHeaderInput::Context(context(hardfork, timestamp));
        chain::header(&spec, &context).unwrap().inner.timestamp
    };
    let t3 = TempoHardfork::T3.moderato_activation_timestamp().unwrap();
    let t4 = TempoHardfork::T4.moderato_activation_timestamp().unwrap();
    assert_eq!(at(TempoHardfork::T3, 0), t3);
    assert_eq!(at(TempoHardfork::T3, t3 + 5), t3 + 5);
    assert_eq!(at(TempoHardfork::T3, u64::MAX), t4 - 1);
    assert_eq!(
        spec.tempo_hardfork_at(at(TempoHardfork::T3, u64::MAX)),
        TempoHardfork::T3
    );
    // The latest hardfork has no end.
    assert_eq!(at(TempoHardfork::latest(), u64::MAX), u64::MAX);
}

#[test]
fn transaction_inputs_decode_and_recover_without_executing() {
    let outcome = |tx: Bytes, sender: Option<Address>| {
        let input = TempoHarnessInput::Transaction(TempoTransactionInput { tx, sender });
        let TempoHarnessOutcome::Transaction(outcome) = execute::run(input) else {
            panic!("a transaction input has a transaction outcome");
        };
        outcome
    };
    let tx = transfer(ChainSpecInput::default().chain_id, 0, 1);

    let given = outcome(tx.clone(), Some(SENDER));
    assert_eq!(given.error, ErrorClass::None);
    assert_eq!(given.sender, Some(SENDER));
    assert_eq!(given.tx_type, Some(0));

    let mut undecodable = tx.to_vec();
    undecodable.push(0);
    assert_eq!(
        outcome(undecodable.into(), None).error,
        ErrorClass::RlpDecode
    );
}

#[test]
fn the_c_abi_round_trips_and_rejects_what_does_not_decode() {
    let input = TempoHarnessInput::Blockchain(TempoBlockchainInput {
        chain_spec: ChainSpecInput::default(),
        pre_state: genesis(),
        blocks: NonEmpty::new(vec![transfer_block()]).unwrap(),
    });
    let bytes = bincode_options().serialize(&input).unwrap();
    let call = |input: &[u8], out: &mut Vec<u8>| {
        let mut written = 0;
        let status = unsafe {
            crate::tempo_fuzz_execute_with_result_v1(
                out.as_mut_ptr(),
                out.len(),
                &mut written,
                input.as_ptr(),
                input.len(),
            )
        };
        (status, written)
    };

    let (status, needed) = call(&bytes, &mut Vec::new());
    assert_eq!(status, FUZZ_REJECT);
    let mut out = vec![0; needed];
    assert_eq!(call(&bytes, &mut out), (FUZZ_ACCEPT, needed));
    let outcome: TempoHarnessOutcome = bincode_options().deserialize(&out).unwrap();
    assert_eq!(outcome, execute::run(input));

    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(call(&trailing, &mut out).0, FUZZ_REJECT);

    let mut out = vec![0; 1024];
    let mut written = 0;
    let status =
        unsafe { crate::tempo_fuzz_capabilities_v1(out.as_mut_ptr(), out.len(), &mut written) };
    assert_eq!(status, FUZZ_ACCEPT);
    let capabilities: TempoHarnessCapabilities =
        bincode_options().deserialize(&out[..written]).unwrap();
    assert_eq!(capabilities.schema_version, 3);
    assert_eq!(
        capabilities.supported_hardforks.as_slice(),
        TempoHardfork::VARIANTS
    );
}
