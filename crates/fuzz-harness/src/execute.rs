//! Executing a harness input.

use std::sync::Arc;

use alloy_consensus::{
    BlockHeader as _, proofs::calculate_transaction_root, transaction::Transaction as _,
};
use alloy_eips::Decodable2718 as _;
use alloy_evm::{
    Evm as _, EvmEnv,
    block::{BlockExecutionError, BlockExecutor, BlockExecutorFactory, TxResult as _},
};
use alloy_primitives::{Address, Bytes};
use reth_consensus::Consensus as _;
use reth_evm::ConfigureEvm;
use reth_primitives_traits::{RecoveredBlock, transaction::signed::SignedTransaction as _};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus, evm::TempoEvm};
use tempo_fuzz_types::{
    BlockHeaderInput, ChainSpecInput, ErrorClass, InvariantFailure, InvariantScope, PreState,
    TempoBlock, TempoExecutionOutcome, TempoHarnessInput, TempoHarnessOutcome,
    TempoTransactionInput, TransactionOutcome, TxReceiptOutput, TxStateDiff,
};
use tempo_primitives::{Block, BlockBody, TempoBlockEnv, TempoReceipt, TempoTxEnvelope};

use crate::{
    chain, invariants,
    state::{self, Db},
};

type ExecutionBlock = RecoveredBlock<Block>;

/// Executes `input`.
pub(crate) fn run(input: TempoHarnessInput) -> TempoHarnessOutcome {
    match input {
        TempoHarnessInput::Transaction(input) => {
            TempoHarnessOutcome::Transaction(transaction(&input))
        }
        TempoHarnessInput::State(input) => {
            let block = TempoBlock {
                header: BlockHeaderInput::Context(input.block_context),
                txs: vec![input.tx],
                senders: input.sender.into_iter().collect(),
            };
            TempoHarnessOutcome::State(execute(
                &input.chain_spec,
                &PreState::Genesis(input.pre_state),
                std::slice::from_ref(&block),
            ))
        }
        TempoHarnessInput::Blockchain(input) => TempoHarnessOutcome::Blockchain(execute(
            &input.chain_spec,
            &input.pre_state,
            input.blocks.as_slice(),
        )),
    }
}

/// Decodes a transaction and finds its sender, without executing it.
fn transaction(input: &TempoTransactionInput) -> TransactionOutcome {
    let tx = match decode_tx(&input.tx) {
        Ok(tx) => tx,
        Err(error) => {
            return TransactionOutcome {
                error,
                ..Default::default()
            };
        }
    };
    let sender = input.sender.or_else(|| tx.try_recover().ok());
    TransactionOutcome {
        error: if sender.is_some() {
            ErrorClass::None
        } else {
            ErrorClass::Rejected
        },
        sender,
        tx_type: Some(tx.tx_type() as u8),
    }
}

fn decode_tx(bytes: &[u8]) -> Result<TempoTxEnvelope, ErrorClass> {
    TempoTxEnvelope::decode_2718_exact(bytes).map_err(|_| ErrorClass::RlpDecode)
}

/// Executes `blocks` in order on `pre_state`, stopping at the first block that
/// fails. An input that is not executable at all leaves an empty outcome with
/// only its error set.
fn execute(
    chain: &ChainSpecInput,
    pre_state: &PreState,
    blocks: &[TempoBlock],
) -> TempoExecutionOutcome {
    let prepared = chain::chain_spec(chain).and_then(|spec| {
        let blocks = blocks
            .iter()
            .map(|block| recover_block(&spec, block))
            .collect::<Result<Vec<_>, _>>()?;
        if !blocks.is_sorted_by_key(|block| block.header().timestamp()) {
            return Err(ErrorClass::InvalidInput);
        }
        let db = state::seed(pre_state)?;
        Ok((Arc::new(spec), blocks, db))
    });
    let (spec, blocks, db) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            return TempoExecutionOutcome {
                error,
                ..Default::default()
            };
        }
    };

    let initial = db.clone();
    let evm_config = TempoEvmConfig::new(Arc::clone(&spec));
    let consensus = TempoConsensus::new(spec);
    let mut outcome = TempoExecutionOutcome::default();
    let after = execute_blocks(&evm_config, &consensus, db, &blocks, &mut outcome);
    let after = after.as_ref().unwrap_or(&initial);

    let final_state = state::encode(after);
    let (accounts, storage) = state::diff(&state::encode(&initial), &final_state);
    outcome.state_diff.accounts = accounts;
    outcome.state_diff.storage = storage;
    outcome.state_root =
        matches!(pre_state, PreState::Genesis(_)).then(|| state::state_root(after));
    outcome.final_state = final_state;
    outcome
}

/// `block` with its header resolved, its transactions decoded and their
/// senders known.
pub(crate) fn recover_block(
    spec: &tempo_chainspec::TempoChainSpec,
    block: &TempoBlock,
) -> Result<ExecutionBlock, ErrorClass> {
    let mut header = chain::header(spec, &block.header)?;
    let txs = block
        .txs
        .iter()
        .map(|tx| decode_tx(tx))
        .collect::<Result<Vec<_>, _>>()?;
    let senders = if block.senders.is_empty() {
        txs.iter()
            .map(|tx| tx.try_recover().map_err(|_| ErrorClass::Rejected))
            .collect::<Result<Vec<_>, _>>()?
    } else if block.senders.len() == txs.len() {
        block.senders.clone()
    } else {
        return Err(ErrorClass::InvalidInput);
    };
    if matches!(block.header, BlockHeaderInput::Context(_)) {
        header.inner.transactions_root = calculate_transaction_root(&txs);
    }
    let body = BlockBody {
        transactions: txs,
        ommers: Vec::new(),
        // `TempoPayloadAttributes` gives every block an empty withdrawals list.
        withdrawals: Some(Default::default()),
    };
    Ok(RecoveredBlock::new_unhashed(
        Block::new(header, body),
        senders,
    ))
}

/// Executes `blocks` on `db`, appending each applied block's outputs to
/// `outcome` and setting its error at the first block that fails. Returns the
/// state after the last block that applied; `None` if none did.
pub(crate) fn execute_blocks(
    evm_config: &TempoEvmConfig,
    consensus: &TempoConsensus,
    mut db: Db,
    blocks: &[ExecutionBlock],
    outcome: &mut TempoExecutionOutcome,
) -> Option<Db> {
    let pre_state = db.db.clone();
    for (index, block) in blocks.iter().enumerate() {
        let before = (index > 0).then(|| db.clone());
        let executed = execute_block(evm_config, consensus, db, block, index as u64);
        // A read the pre-state could not answer makes the result meaningless,
        // even when the error was swallowed on its way up.
        let executed = match executed {
            _ if pre_state.missed() => Err(ErrorClass::IncompletePreState),
            executed => executed,
        };
        match executed {
            Ok((next, outputs)) => {
                outputs.append_to(outcome);
                db = next;
            }
            Err(error) => {
                outcome.error = error;
                return before;
            }
        }
    }
    Some(db)
}

/// What one block produced.
#[derive(Default)]
struct BlockOutputs {
    receipts: Vec<TxReceiptOutput>,
    tx_diffs: Vec<TxStateDiff>,
    invariant_failures: Vec<InvariantFailure>,
}

impl BlockOutputs {
    fn append_to(self, outcome: &mut TempoExecutionOutcome) {
        outcome.receipts.extend(self.receipts);
        outcome.state_diff.txs.extend(self.tx_diffs);
        outcome.invariant_failures.extend(self.invariant_failures);
    }
}

/// What a transaction returned, beyond its receipt.
struct TxOutput {
    output: Bytes,
    gas_used: u64,
    effective_gas_price: u128,
}

fn execute_block(
    evm_config: &TempoEvmConfig,
    consensus: &TempoConsensus,
    db: Db,
    block: &ExecutionBlock,
    block_index: u64,
) -> Result<(Db, BlockOutputs), ErrorClass> {
    consensus
        .validate_block_pre_execution(block.sealed_block())
        .map_err(|_| ErrorClass::Rejected)?;
    let env = evm_config
        .evm_env(block.header())
        .map_err(|_| ErrorClass::Rejected)?;
    let ctx = evm_config
        .context_for_block(block.sealed_block())
        .map_err(|_| ErrorClass::Rejected)?;
    let evm = TempoEvm::new(db, env.clone());
    let mut executor =
        BlockExecutorFactory::create_executor(evm_config.block_executor_factory(), evm, ctx);

    let mut outputs = BlockOutputs::default();
    let txs = execute_txs(&mut executor, block, block_index, &env, &mut outputs)
        .map_err(|err| class(&err))?;
    let (evm, result) = executor.finish().map_err(|err| class(&err))?;
    outputs.receipts = result
        .receipts
        .iter()
        .zip(txs)
        .enumerate()
        .map(|(tx_index, (receipt, tx))| receipt_output(block_index, tx_index as u64, receipt, tx))
        .collect();
    let (db, _) = evm.finish();
    Ok((db, outputs))
}

/// Applies the block's pre-execution changes and its transactions, checking
/// invariants after each.
fn execute_txs<E>(
    executor: &mut E,
    block: &ExecutionBlock,
    block_index: u64,
    env: &EvmEnv<TempoHardfork, TempoBlockEnv>,
    outputs: &mut BlockOutputs,
) -> Result<Vec<TxOutput>, BlockExecutionError>
where
    E: BlockExecutor<Transaction = TempoTxEnvelope, Receipt = TempoReceipt, Evm = TempoEvm<Db>>,
{
    executor.apply_pre_execution_changes()?;
    invariants::check(
        executor_db(executor),
        env,
        &InvariantScope::Block { block_index },
        None,
        &mut outputs.invariant_failures,
    );

    let basefee = block.header().base_fee_per_gas();
    let mut txs = Vec::with_capacity(block.body().transactions.len());
    for (tx_index, tx) in block.transactions_recovered().enumerate() {
        let tx_index = tx_index as u64;
        let effective_gas_price = tx.effective_gas_price(basefee);
        let result = executor.execute_transaction_without_commit(tx)?;
        let evm_result = result.result();
        let diff = state::tx_diff(
            executor_db(executor),
            &evm_result.state,
            block_index,
            tx_index,
        );
        let mut changed: Vec<Address> = diff
            .accounts
            .iter()
            .map(|account| account.address)
            .chain(diff.storage.iter().map(|slot| slot.address))
            .collect();
        changed.sort_unstable();
        changed.dedup();
        outputs.tx_diffs.push(diff);
        let output = evm_result.result.output().cloned().unwrap_or_default();
        let gas = executor.commit_transaction(result);
        txs.push(TxOutput {
            output,
            gas_used: gas.tx_gas_used(),
            effective_gas_price,
        });
        invariants::check(
            executor_db(executor),
            env,
            &InvariantScope::Transaction {
                block_index,
                tx_index,
            },
            Some(&changed),
            &mut outputs.invariant_failures,
        );
    }
    Ok(txs)
}

/// A block the node would reject is `Rejected`; anything else went wrong in
/// the executor.
fn class(err: &BlockExecutionError) -> ErrorClass {
    match err {
        BlockExecutionError::Validation(_) => ErrorClass::Rejected,
        BlockExecutionError::Internal(_) => ErrorClass::Internal,
    }
}

fn receipt_output(
    block_index: u64,
    tx_index: u64,
    receipt: &TempoReceipt,
    tx: TxOutput,
) -> TxReceiptOutput {
    TxReceiptOutput {
        block_index,
        tx_index,
        success: receipt.success,
        cumulative_gas_used: receipt.cumulative_gas_used,
        gas_used: tx.gas_used,
        effective_gas_price: tx.effective_gas_price,
        output: tx.output,
        logs: receipt.logs.clone(),
    }
}

fn executor_db<E: BlockExecutor<Evm = TempoEvm<Db>>>(executor: &E) -> &Db {
    executor.evm().components().0
}
