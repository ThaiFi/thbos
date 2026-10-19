use std::{collections::BTreeMap, sync::Arc};

use alloy_consensus::{Signed, TxLegacy, proofs::calculate_transaction_root};
use alloy_eips::{Decodable2718, Encodable2718};
use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256, address};
use alloy_rlp::Encodable;
use alloy_sol_types::SolCall;
use bincode::Options as _;
use tempo_chainspec::hardfork::{TempoHardfork, TempoHardforks};
use tempo_contracts::precompiles::{ITIP20, PATH_USD_ADDRESS};
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus};
use tempo_fuzz_types::{
    AccountInput, BlockContextInput, BlockHeaderInput, ChainSpecInput, ErrorClass, FUZZ_ACCEPT,
    FUZZ_REJECT, InvariantScope, NonEmpty, PreState, StateInput, TempoBlock, TempoBlockchainInput,
    TempoExecutionOutcome, TempoHarnessCapabilities, TempoHarnessInput, TempoHarnessOutcome,
    TempoTransactionInput,
};
use tempo_precompiles::tip20::slots::{SUPPLY_CAP, TOTAL_SUPPLY};
use tempo_primitives::{TempoHeader, TempoTxEnvelope};

use crate::{bincode_options, chain, execute, state};

/// Dev account 0, funded with pathUSD in the dev genesis.
const SENDER: Address = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
const RECIPIENT: Address = address!("00000000000000000000000000000000000000aa");
/// The dev genesis token after pathUSD.
const NEXT_TOKEN: Address = address!("20c0000000000000000000000000000000000001");

fn transfer(chain_id: u64, nonce: u64, amount: u64) -> Bytes {
    let input = ITIP20::transferCall {
        to: RECIPIENT,
        amount: U256::from(amount),
    }
    .abi_encode();
    let tx = TempoTxEnvelope::Legacy(Signed::new_unhashed(
        TxLegacy {
            chain_id: Some(chain_id),
            nonce,
            gas_price: 0,
            gas_limit: 1_000_000,
            to: TxKind::Call(PATH_USD_ADDRESS),
            value: U256::ZERO,
            input: input.into(),
        },
        Signature::test_signature(),
    ));
    tx.encoded_2718().into()
}

fn context(hardfork: TempoHardfork, timestamp: u64) -> BlockHeaderInput {
    BlockHeaderInput::Context(BlockContextInput {
        hardfork,
        timestamp,
        ..Default::default()
    })
}

fn block(header: BlockHeaderInput, txs: Vec<Bytes>) -> TempoBlock {
    let senders = vec![SENDER; txs.len()];
    TempoBlock {
        header,
        txs,
        senders,
    }
}

fn chain_id() -> u64 {
    ChainSpecInput::default().chain_id
}

fn transfer_block() -> TempoBlock {
    block(
        context(TempoHardfork::T4, 0),
        vec![transfer(chain_id(), 0, 7)],
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

/// The whole dev genesis state.
fn genesis_state() -> StateInput {
    state::encode(&state::seed(&genesis()).expect("the dev genesis seeds"))
}

/// The dev genesis as an exact pre-state for `blocks`, listing what they
/// read, as an extractor reading a witness would: every account and slot
/// execution caches, zeros included, with its value before the blocks.
fn exact_genesis(blocks: &[TempoBlock]) -> StateInput {
    let spec = Arc::new(chain::chain_spec(&ChainSpecInput::default()).unwrap());
    let db = state::seed(&genesis()).unwrap();
    let before = state::encode(&db);
    let blocks: Vec<_> = blocks
        .iter()
        .map(|block| execute::recover_block(&spec, block).unwrap())
        .collect();
    let mut outcome = TempoExecutionOutcome::default();
    let after = execute::execute_blocks(
        &TempoEvmConfig::new(Arc::clone(&spec)),
        &TempoConsensus::new(spec),
        db,
        &blocks,
        &mut outcome,
    );
    assert_eq!(outcome.error, ErrorClass::None);
    let after = after.expect("the blocks apply");

    let accounts = after
        .cache
        .accounts
        .iter()
        .map(|(address, account)| {
            let mut listed = before.accounts.get(address).cloned().unwrap_or_default();
            for slot in account.storage.keys() {
                listed.storage.entry(*slot).or_default();
            }
            (*address, listed)
        })
        .collect();
    StateInput { accounts }
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

fn exact(state: StateInput) -> PreState {
    PreState::Exact {
        state,
        block_hashes: BTreeMap::new(),
    }
}

fn token(state: &mut StateInput, address: Address) -> &mut AccountInput {
    state
        .accounts
        .get_mut(&address)
        .expect("the dev genesis holds the token")
}

#[test]
fn a_transfer_reports_its_receipt_changes_and_state_root() {
    let outcome = run(ChainSpecInput::default(), genesis(), vec![transfer_block()]);

    assert_eq!(outcome.error, ErrorClass::None);
    assert_eq!(outcome.receipts.len(), 1);
    let receipt = &outcome.receipts[0];
    assert!(receipt.success);
    assert!(receipt.gas_used > 0);
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

    // The transfer moves two pathUSD balances, and its diff is part of the block's.
    assert_eq!(outcome.state_diff.txs.len(), 1);
    let tx_changes = &outcome.state_diff.txs[0].storage;
    let path_usd: Vec<_> = tx_changes
        .iter()
        .filter(|change| change.address == PATH_USD_ADDRESS)
        .collect();
    assert_eq!(path_usd.len(), 2, "{tx_changes:?}");
    for change in path_usd {
        assert!(outcome.state_diff.storage.contains(change));
    }

    assert_eq!(outcome.state_root, Some(trie_root(&outcome.final_state)));
    assert_ne!(outcome.final_state, genesis_state());
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
    let read = from_genesis.state_diff.txs[0]
        .storage
        .iter()
        .find(|change| change.address == PATH_USD_ADDRESS)
        .expect("the transfer changes pathUSD")
        .slot;

    let mut state = genesis_state();
    token(&mut state, PATH_USD_ADDRESS).storage.remove(&read);
    let outcome = run(
        ChainSpecInput::default(),
        exact(state.clone()),
        vec![transfer_block()],
    );
    assert_eq!(outcome.error, ErrorClass::IncompletePreState);
    assert!(outcome.receipts.is_empty());
    assert_eq!(outcome.final_state, state);

    let missing_account = run(
        ChainSpecInput::default(),
        exact(StateInput::default()),
        vec![transfer_block()],
    );
    assert_eq!(missing_account.error, ErrorClass::IncompletePreState);
}

#[test]
fn an_exact_pre_state_answers_listed_block_hashes_only() {
    use revm::Database as _;
    let hash = B256::repeat_byte(7);
    let mut db = state::seed(&PreState::Exact {
        state: StateInput::default(),
        block_hashes: BTreeMap::from([(5, hash)]),
    })
    .unwrap();
    assert_eq!(db.block_hash(5).unwrap(), hash);
    assert!(!db.db.missed());
    assert!(db.block_hash(6).is_err());
    assert!(db.db.missed());
}

#[test]
fn an_empty_account_in_an_exact_pre_state_does_not_exist() {
    use revm::Database as _;
    let mut db = state::seed(&exact(StateInput {
        accounts: BTreeMap::from([(RECIPIENT, AccountInput::default())]),
    }))
    .unwrap();
    assert_eq!(db.basic(RECIPIENT).unwrap(), None);
    assert_eq!(db.storage(RECIPIENT, U256::from(3)).unwrap(), U256::ZERO);
    assert!(!db.db.missed());
}

#[test]
fn broken_invariants_are_reported_without_stopping_execution() {
    let mut state = exact_genesis(&[transfer_block()]);
    // A supply below what the holders hold, and above the cap.
    let path_usd = token(&mut state, PATH_USD_ADDRESS);
    path_usd.storage.insert(TOTAL_SUPPLY, U256::from(1));
    path_usd.storage.insert(SUPPLY_CAP, U256::ZERO);
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
    let after_tx = InvariantScope::Transaction {
        block_index: 0,
        tx_index: 0,
    };
    for id in ["TEMPO-TIP20-SUPPLY-CAP", "TEMPO-TIP20-BALANCE-SUM"] {
        assert!(at(id, InvariantScope::Block { block_index: 0 }), "{id}");
        assert!(at(id, after_tx.clone()), "{id}");
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
    token(&mut state, PATH_USD_ADDRESS)
        .storage
        .remove(&TOTAL_SUPPLY);
    let next = token(&mut state, NEXT_TOKEN);
    next.storage.insert(TOTAL_SUPPLY, U256::from(1));
    next.storage.insert(SUPPLY_CAP, U256::ZERO);
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
    assert!(
        failures.contains(&(
            "TEMPO-TIP20-SUPPLY-CAP",
            &InvariantScope::Block { block_index: 0 }
        )),
        "{failures:?}"
    );
    assert!(
        outcome
            .invariant_failures
            .iter()
            .all(|failure| failure.message.contains(&NEXT_TOKEN.to_string())),
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
            context(TempoHardfork::T4, 0),
            vec![transfer(chain_id, 0, 7)],
        );
        run(chain.clone(), genesis(), vec![block]).error
    };
    assert_eq!(on(1337), ErrorClass::None);
    assert_eq!(on(chain_id()), ErrorClass::Rejected);
}

#[test]
fn an_rlp_header_executes_exactly_as_given() {
    let spec = chain::chain_spec(&ChainSpecInput::default()).unwrap();
    let tx = transfer(chain_id(), 0, 7);
    let mut header = chain::header(&spec, &context(TempoHardfork::T4, 0)).unwrap();
    header.inner.transactions_root =
        calculate_transaction_root(&[TempoTxEnvelope::decode_2718_exact(&tx).unwrap()]);
    let rlp = |header: &TempoHeader| {
        let mut buf = Vec::new();
        header.encode(&mut buf);
        buf
    };

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
    let first = transfer_block();
    // Nonce 0 again: the second block's transaction is invalid.
    let second = block(
        context(TempoHardfork::T4, 0),
        vec![transfer(chain_id(), 0, 9)],
    );
    let only_first = run(ChainSpecInput::default(), genesis(), vec![first.clone()]);
    let outcome = run(ChainSpecInput::default(), genesis(), vec![first, second]);

    assert_eq!(outcome.error, ErrorClass::Rejected);
    assert_eq!(outcome.receipts, only_first.receipts);
    assert_eq!(outcome.state_diff, only_first.state_diff);
    assert_eq!(outcome.final_state, only_first.final_state);
}

#[test]
fn malformed_inputs_are_classified_rather_than_executed() {
    let default = ChainSpecInput::default;
    let error = |chain, pre_state, blocks| run(chain, pre_state, blocks).error;

    // Blocks going back in time.
    let late = block(context(TempoHardfork::T5, 0), Vec::new());
    let early = block(context(TempoHardfork::T4, 0), Vec::new());
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
    let mut genesis_state = genesis_state();
    let path_usd = token(&mut genesis_state, PATH_USD_ADDRESS).clone();
    let overriding = StateInput {
        accounts: BTreeMap::from([(PATH_USD_ADDRESS, path_usd)]),
    };
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
    // Only T3 is listed: the hardforks before it activate at their variant
    // index, and those after it with it.
    let chain = ChainSpecInput {
        chain_id: chain_id(),
        hardforks: BTreeMap::from([(TempoHardfork::T3, 1000)]),
    };
    let spec = chain::chain_spec(&chain).unwrap();
    assert_eq!(spec.tempo_hardfork_at(0), TempoHardfork::Genesis);
    assert_eq!(spec.tempo_hardfork_at(1), TempoHardfork::T0);
    assert_eq!(spec.tempo_hardfork_at(3), TempoHardfork::T1A);
    assert_eq!(spec.tempo_hardfork_at(999), TempoHardfork::T2);
    assert_eq!(spec.tempo_hardfork_at(1000), TempoHardfork::latest());
}

#[test]
fn a_context_header_lands_where_its_hardfork_is_active() {
    let spec = chain::chain_spec(&ChainSpecInput::default()).unwrap();
    let at = |hardfork, timestamp| {
        chain::header(&spec, &context(hardfork, timestamp))
            .unwrap()
            .inner
            .timestamp
    };
    let t3 = TempoHardfork::T3.moderato_activation_timestamp().unwrap();
    let t4 = TempoHardfork::T4.moderato_activation_timestamp().unwrap();
    assert_eq!(at(TempoHardfork::T3, 0), t3);
    assert_eq!(at(TempoHardfork::T3, t3 + 5), t3 + 5);
    assert_eq!(at(TempoHardfork::T3, u64::MAX), t4 - 1);
    // The latest hardfork has no end.
    assert_eq!(at(TempoHardfork::latest(), u64::MAX), u64::MAX);
    // Every hardfork Moderato separates can be selected.
    for &fork in TempoHardfork::VARIANTS {
        let active = spec.tempo_hardfork_at(at(fork, 0));
        let shares_activation =
            spec.tempo_fork_activation(fork) == spec.tempo_fork_activation(active);
        assert!(
            active == fork || shares_activation,
            "{fork:?} lands on {active:?}"
        );
    }
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
    let tx = transfer(chain_id(), 0, 1);

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
