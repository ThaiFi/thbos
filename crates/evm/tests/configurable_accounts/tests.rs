use super::*;
use alloy_consensus::{Header, SignableTransaction, TxEip1559, TxEip2930, TxEip7702, TxLegacy};
use alloy_eips::{
    eip2930::{AccessList, AccessListItem},
    eip7702::{Authorization, SignedAuthorization},
};
use alloy_evm::{FromRecoveredTx, block::BlockExecutor};
use alloy_primitives::{
    Bytes, KECCAK256_EMPTY, LogData, Signature, aliases::U96, bytes, keccak256,
};
use alloy_sol_types::{SolError, SolEvent, SolValue};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
use reth_chainspec::EthChainSpec;
use reth_ethereum_primitives::Block as EthereumBlock;
use reth_evm::ConfigureEvm;
use reth_execution_types::ExecutionOutcome;
use reth_primitives_traits::{Block as _, SignedTransaction};
use reth_provider::{
    BlockExecutionWriter, BlockWriter, OriginalValuesKnown, StateWriter, TrieWriter,
    providers::BlockchainProvider, test_utils::create_test_provider_factory,
};
use reth_stages::{MerkleCheckpoint, StorageRootMerkleCheckpoint, stages::MerkleStage};
use reth_storage_api::{
    AccountReader, ChangeSetReader, DBProvider, HistoryWriter, StateProviderFactory,
    StateRootProvider, StateWriteConfig, StorageSettingsCache,
};
use reth_trie::{HashedPostState, KeccakKeyHasher, StateRoot, StateRootProgress, StoredSubNode};
use reth_trie_db::{
    DatabaseHashedCursorFactory, DatabaseStateRoot, DatabaseTrieCursorFactory, with_adapter,
};
use revm::{
    context::result::{EVMError, ExecutionResult, InvalidTransaction},
    state::EvmStorageSlot,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tempo_chainspec::{
    TempoChainSpec,
    spec::{DEV, MODERATO},
};
use tempo_contracts::precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, AccountKeychainError, ISignatureVerifier, ITIP20ChannelReserve,
    PATH_USD_ADDRESS, SIGNATURE_VERIFIER_ADDRESS, TIP20_CHANNEL_RESERVE_ADDRESS,
    account_keychain::IAccountKeychain, nonce::INonce, tip20::ITIP20,
};
use tempo_evm::{
    StorageActionReplay, StorageActionReplayError, TempoEvmConfig, supports_storage_action_replay,
};
use tempo_precompiles::{
    error::TempoPrecompileError,
    native_multisig::keccak_cost,
    nonce::NonceManager,
    tip20::{PERMIT_TYPEHASH, TIP20Token},
    tip20_channel_reserve::TIP20ChannelReserve,
};
use tempo_primitives::{
    Block as TempoBlock, SignatureType, TempoHeader, TempoTxEnvelope,
    account::encode_config_commitment,
    transaction::{
        AccountSignature, CallScope, KeyAuthorization, KeychainSignature, MULTISIG_CONFIG_DOMAIN,
        SignedKeyAuthorization, TempoSignedAuthorization, TokenLimit, calc_gas_balance_spending,
        derive_p256_address,
        tt_signature::{P256SignatureWithPreHash, WebAuthnSignature, normalize_p256_s},
    },
};
use tempo_revm::{
    ExecutionContext, TempoInvalidTransaction, TempoTxEnv, error::RootKeyRole,
    native_multisig::NativeMultisigError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GrantOutcome {
    Success,
    RevertAndRetry,
    ScopeRejectionAndRetry,
}

#[test]
fn native_factory_activation_preserves_state() {
    let factory = Address::repeat_byte(0x71);
    let config = activation_config();
    for nonce in [0, 7] {
        for code in [bytes!(""), bytes!("600000")] {
            let mut db = State::builder().with_bundle_update().build();
            let bytecode = Bytecode::new_legacy(code.clone());
            db.insert_account_with_storage(
                factory,
                AccountInfo::new(U256::from(42), nonce, bytecode.hash_slow(), bytecode),
                std::iter::once((U256::from(3), U256::from(9))).collect(),
            );
            for (number, timestamp) in [(1, 9), (2, 10), (3, 11)] {
                let block = TempoBlock::uncle(TempoHeader {
                    inner: Header {
                        number,
                        timestamp,
                        gas_limit: 30_000_000,
                        base_fee_per_gas: Some(0),
                        parent_beacon_block_root: Some(B256::ZERO),
                        ..Default::default()
                    },
                    general_gas_limit: 30_000_000,
                    ..Default::default()
                })
                .seal_slow();
                let mut executor = config.executor_for_block(&mut db, &block).unwrap();
                assert_eq!(
                    executor.evm().cfg_env().spec,
                    if timestamp < 10 {
                        TempoHardfork::T13
                    } else {
                        TempoHardfork::T14
                    }
                );
                executor.apply_pre_execution_changes().unwrap();
                executor.finish().unwrap();
                let info = db.basic(factory).unwrap().unwrap();
                assert_eq!(
                    info.nonce,
                    if timestamp < 10 { nonce } else { nonce.max(1) }
                );
                assert_eq!(info.balance, U256::from(42));
                assert_eq!(
                    info.code.unwrap().original_bytes(),
                    if timestamp < 10 {
                        code.clone()
                    } else {
                        bytes!("ef")
                    }
                );
                assert_eq!(db.storage(factory, U256::from(3)).unwrap(), U256::from(9));
                let marker = db
                    .basic(NATIVE_MULTISIG_ADDRESS)
                    .unwrap()
                    .unwrap_or_default();
                assert_eq!(marker.is_empty_code_hash(), timestamp < 10);
                db.merge_transitions(BundleRetention::Reverts);
            }
        }
    }
}

#[test]
fn native_commitment_only_account_evm_semantics() {
    let target = Address::repeat_byte(0x44);
    let commitment = B256::repeat_byte(0x99);
    // EXTCODEHASH, zero/value CALL, and SELFDESTRUCT must treat the leaf as existing.
    for operation in [0x3f, 0xf1, 0xff] {
        for value in [0u8, 1] {
            let mut gas = Vec::new();
            for (nonce, extension) in [(1, B256::ZERO), (0, commitment), (0, B256::ZERO)] {
                let mut f = Fixture::new();
                f.evm.db_mut().insert_account(
                    target,
                    AccountInfo {
                        nonce,
                        ..Default::default()
                    }
                    .with_extension(encode_config_commitment(extension)),
                );
                let mut code = if operation == 0xf1 {
                    vec![0x5f, 0x5f, 0x5f, 0x5f, 0x60, value, 0x73]
                } else {
                    vec![0x73]
                };
                code.extend_from_slice(target.as_slice());
                match operation {
                    0x3f => code.extend_from_slice(&[0x3f, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]),
                    0xf1 => code.extend_from_slice(&[0x5a, 0xf1, 0x00]),
                    0xff => code.push(0xff),
                    _ => unreachable!(),
                }
                let contract = Address::repeat_byte(0x55);
                let call = f.install_contract(contract, code);
                f.evm
                    .db_mut()
                    .load_cache_account(contract)
                    .unwrap()
                    .account
                    .as_mut()
                    .unwrap()
                    .info
                    .set_balance(U256::from(value));
                let tx = f.signed(3, vec![call]);
                let output = f
                    .evm
                    .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
                    .unwrap();
                assert!(output.result.is_success(), "{:?}", output.result);
                if operation == 0x3f {
                    let expected = if nonce != 0 || !extension.is_zero() {
                        KECCAK256_EMPTY
                    } else {
                        B256::ZERO
                    };
                    assert_eq!(output.result.output().unwrap(), expected.as_slice());
                }
                gas.push(output.result.tx_gas_used());
                f.evm.db_mut().commit(output.state);
                if !extension.is_zero() {
                    let info = f
                        .evm
                        .db_mut()
                        .basic(target)
                        .unwrap()
                        .expect("config-only leaf must survive state clearing");
                    assert_eq!(
                        decode_config_commitment(&info.extension, true).unwrap(),
                        commitment
                    );
                    assert_eq!(info.nonce, 0);
                }
            }
            assert_eq!(gas[0], gas[1], "operation={operation:x}, value={value}");
            if operation != 0x3f && value != 0 {
                assert!(gas[2] > gas[1], "only an empty target pays new-account gas");
            }
        }
    }
}

#[test]
fn native_rotation_rejects_access_keys_and_callbacks() {
    for (access_key, admin) in [(true, false), (true, true), (false, false)] {
        let mut f = Fixture::new();
        let next = MultisigConfig {
            version: 1,
            ..f.config.clone()
        };
        let rotation = Fixture::rotation(&f.config, &next);
        let tx = if access_key {
            let delegate = PrivateKeySigner::from_bytes(&B256::repeat_byte(2)).unwrap();
            let mut authorization =
                KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, delegate.address());
            if admin {
                authorization = authorization.into_admin(f.account);
            }
            let approval = MultisigSignature::try_new(
                f.account,
                f.config.clone(),
                vec![PrimitiveSignature::Secp256k1(
                    f.owner
                        .sign_hash_sync(&multisig_digest(
                            authorization.signature_hash(),
                            f.account,
                            0,
                        ))
                        .unwrap(),
                )],
            )
            .unwrap();
            let tx = TempoTransaction {
                chain_id: 1,
                nonce: 3,
                gas_limit: 1_000_000,
                calls: vec![rotation],
                key_authorization: Some(authorization.into_signed(approval)),
                ..Default::default()
            };
            let signature = delegate
                .sign_hash_sync(&KeychainSignature::signing_hash(
                    tx.signature_hash(),
                    f.account,
                ))
                .unwrap();
            tx.into_signed(TempoSignature::Keychain(KeychainSignature::new(
                f.account,
                PrimitiveSignature::Secp256k1(signature),
            )))
        } else {
            // Forward calldata to the precompile and bubble its revert data.
            let code = [
                bytes!("365f5f375f5f365f5f73").as_ref(),
                NATIVE_MULTISIG_ADDRESS.as_slice(),
                bytes!("5af1503d5f5f3e3d5ffd").as_ref(),
            ]
            .concat();
            let mut call = f.install_contract(Address::repeat_byte(0x55), code);
            call.input = rotation.input;
            f.signed(3, vec![call])
        };
        let output = f
            .evm
            .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
            .unwrap();
        assert!(
            matches!(output.result, ExecutionResult::Revert { .. }),
            "{:?}",
            output.result
        );
        assert_eq!(
            output.result.output().unwrap().as_ref(),
            INativeMultisig::UnauthorizedMultisigCaller {}.abi_encode()
        );
        assert!(
            output
                .result
                .logs()
                .iter()
                .all(|log| log.address != NATIVE_MULTISIG_ADDRESS)
        );
        f.evm.db_mut().commit(output.state);
        assert_eq!(f.commitment(), f.config.commitment().unwrap());
    }
}

#[test]
fn native_commitment_activation_database_lifecycle() {
    let factory = create_test_provider_factory();
    let mut fixture = Fixture::new();
    let config = activation_config();
    let mut roots = Vec::new();
    let mut parent_hash = B256::ZERO;
    for block in 0..=2 {
        if block != 0 {
            let tx = fixture.signed(block + 2, vec![fixture.getter()]);
            let block_env = TempoBlock::uncle(TempoHeader {
                inner: Header {
                    number: block,
                    timestamp: 9 + block,
                    gas_limit: 30_000_000,
                    base_fee_per_gas: Some(0),
                    blob_gas_used: Some(0),
                    excess_blob_gas: Some(0),
                    parent_beacon_block_root: Some(B256::ZERO),
                    ..Default::default()
                },
                general_gas_limit: 30_000_000,
                ..Default::default()
            })
            .seal_slow();
            let mut executor = config
                .executor_for_block(fixture.evm.db_mut(), &block_env)
                .unwrap();
            assert_eq!(executor.evm().cfg_env().spec, TempoHardfork::T14);
            executor.apply_pre_execution_changes().unwrap();
            let recovered = TempoTxEnvelope::AA(tx).with_signer(fixture.account);
            executor.execute_transaction(&recovered).unwrap();
            let (_, result) = executor.finish().unwrap();
            assert!(result.receipts[0].success);
            fixture
                .evm
                .db_mut()
                .merge_transitions(BundleRetention::Reverts);
        }
        let bundle = fixture.evm.db_mut().take_bundle();
        assert!(
            bundle.state().contains_key(&fixture.account),
            "account missing from executed bundle at {block}"
        );
        let hashed = HashedPostState::from_bundle_state::<KeccakKeyHasher>(bundle.state());
        let (root, updates) = factory
            .latest()
            .unwrap()
            .state_root_with_updates(hashed.clone())
            .unwrap();
        let mut header = Header {
            number: block,
            timestamp: 9 + block,
            state_root: root,
            ..Default::default()
        };
        header.parent_hash = parent_hash;
        let chain_block = EthereumBlock::uncle(header).try_into_recovered().unwrap();
        parent_hash = chain_block.hash();
        let provider = factory.provider_rw().unwrap();
        provider.insert_block(&chain_block).unwrap();
        let outcome = ExecutionOutcome::new(bundle, vec![vec![]], block, vec![]);
        provider
            .write_state(
                &outcome,
                OriginalValuesKnown::Yes,
                StateWriteConfig::default(),
            )
            .unwrap();
        provider.write_hashed_state(&hashed.into_sorted()).unwrap();
        provider.write_trie_updates(updates).unwrap();
        provider.update_history_indices(block..=block).unwrap();
        provider.commit().unwrap();
        let latest = factory.latest().unwrap();
        let account = latest
            .basic_account(&fixture.account)
            .unwrap()
            .unwrap_or_else(|| panic!("persisted account missing at {block}"));
        let expected = if block == 0 {
            B256::ZERO
        } else {
            fixture.config.commitment().unwrap()
        };
        assert_eq!(
            decode_config_commitment(&account.extension, true).unwrap(),
            expected
        );
        assert_eq!(latest.state_root(Default::default()).unwrap(), root);
        roots.push(root);
    }
    assert_ne!(roots[0], roots[1]);
    {
        let blockchain = BlockchainProvider::new(factory.clone()).unwrap();
        for block in [0, 1] {
            let historical = blockchain.history_by_block_number(block).unwrap();
            let account = historical.basic_account(&fixture.account).unwrap().unwrap();
            let expected = if block == 0 {
                B256::ZERO
            } else {
                fixture.config.commitment().unwrap()
            };
            assert_eq!(
                decode_config_commitment(&account.extension, true).unwrap(),
                expected
            );
        }
    }
    let before_second = factory
        .provider()
        .unwrap()
        .get_account_before_block(2, fixture.account)
        .unwrap()
        .unwrap();
    assert_eq!(
        decode_config_commitment(&before_second.info.unwrap().extension, true).unwrap(),
        fixture.config.commitment().unwrap()
    );
    for block in [1, 0] {
        let provider = factory.unwind_provider_rw().unwrap();
        provider.remove_block_and_execution_above(block).unwrap();
        provider.commit().unwrap();
        let latest = factory.latest().unwrap();
        let account = latest.basic_account(&fixture.account).unwrap().unwrap();
        let expected = if block == 0 {
            B256::ZERO
        } else {
            fixture.config.commitment().unwrap()
        };
        assert_eq!(
            decode_config_commitment(&account.extension, true).unwrap(),
            expected
        );
        assert_eq!(
            latest.state_root(Default::default()).unwrap(),
            roots[usize::try_from(block).unwrap()]
        );
    }
}

/// Exercises the stage's persisted checkpoint codec with real partial storage-trie work.
/// Reopens database transactions, not a process or a full `Stage::execute` pipeline.
#[test]
fn native_commitment_persisted_storage_trie_resume_and_proof() {
    let factory = create_test_provider_factory();
    let mut fixture = Fixture::new();
    let commitment = fixture.config.commitment().unwrap();
    let mut info = fixture
        .evm
        .db_mut()
        .basic(fixture.account)
        .unwrap()
        .unwrap();
    info.extension = encode_config_commitment(commitment).into();
    let mut account = Account::from(info);
    for slot in 0..128u64 {
        account.storage.insert(
            U256::from(slot),
            EvmStorageSlot::new_changed(U256::ZERO, U256::from(slot + 1), TransactionId::ZERO),
        );
    }
    account.mark_touch();
    fixture
        .evm
        .db_mut()
        .commit(std::iter::once((fixture.account, account)).collect());
    fixture
        .evm
        .db_mut()
        .merge_transitions(BundleRetention::Reverts);
    let bundle = fixture.evm.db_mut().take_bundle();
    let hashed = HashedPostState::from_bundle_state::<KeccakKeyHasher>(bundle.state());
    let expected_root = factory
        .latest()
        .unwrap()
        .state_root(hashed.clone())
        .unwrap();
    {
        let provider = factory.provider_rw().unwrap();
        provider
            .insert_block(
                &EthereumBlock::uncle(Header {
                    state_root: expected_root,
                    ..Default::default()
                })
                .try_into_recovered()
                .unwrap(),
            )
            .unwrap();
        provider
            .write_state(
                &ExecutionOutcome::new(bundle, vec![vec![]], 0, vec![]),
                OriginalValuesKnown::Yes,
                StateWriteConfig::default(),
            )
            .unwrap();
        provider.write_hashed_state(&hashed.into_sorted()).unwrap();
        provider.commit().unwrap();
    }

    let stage = MerkleStage::default_execution();
    let mut storage_resumptions = 0;
    let mut completed_root = None;
    for _ in 0..512 {
        // Drop/commit the previous RW transaction before reading its persisted checkpoint.
        let provider = factory.provider_rw().unwrap();
        let checkpoint = stage.get_execution_checkpoint(&*provider).unwrap();
        if let Some(storage) = checkpoint
            .as_ref()
            .filter(|checkpoint| checkpoint.last_account_key == keccak256(fixture.account))
            .and_then(|checkpoint| checkpoint.storage_root_checkpoint.as_ref())
        {
            storage_resumptions += 1;
            assert_eq!(
                decode_config_commitment(&storage.account_extension, true).unwrap(),
                commitment
            );
        }
        let progress = with_adapter!(&provider, |A| {
            StateRoot::<DatabaseTrieCursorFactory<_, A>, DatabaseHashedCursorFactory<_>>::from_tx(
                provider.tx_ref(),
            )
            .with_intermediate_state(checkpoint.map(Into::into))
            .with_threshold(4)
            .root_with_progress()
        })
        .unwrap();
        match progress {
            StateRootProgress::Progress(state, _, updates) => {
                provider.write_trie_updates(updates).unwrap();
                let mut checkpoint = MerkleCheckpoint::new(
                    0,
                    state.account_root_state.last_hashed_key,
                    state
                        .account_root_state
                        .walker_stack
                        .into_iter()
                        .map(StoredSubNode::from)
                        .collect(),
                    state.account_root_state.hash_builder.into(),
                );
                checkpoint.storage_root_checkpoint = state.storage_root_state.map(|storage| {
                    StorageRootMerkleCheckpoint::new(
                        storage.state.last_hashed_key,
                        storage
                            .state
                            .walker_stack
                            .into_iter()
                            .map(StoredSubNode::from)
                            .collect(),
                        storage.state.hash_builder.into(),
                        storage.account,
                    )
                });
                stage
                    .save_execution_checkpoint(&*provider, Some(checkpoint))
                    .unwrap();
            }
            StateRootProgress::Complete(root, _, updates) => {
                provider.write_trie_updates(updates).unwrap();
                stage.save_execution_checkpoint(&*provider, None).unwrap();
                completed_root = Some(root);
            }
        }
        provider.commit().unwrap();
        if completed_root.is_some() {
            break;
        }
    }
    assert!(
        storage_resumptions > 0,
        "must resume inside an account's nonempty storage trie"
    );
    assert_eq!(completed_root, Some(expected_root));
    let latest = factory.latest().unwrap();
    let proof = latest
        .proof(
            Default::default(),
            fixture.account,
            &[B256::ZERO, B256::with_last_byte(127)],
        )
        .unwrap();
    assert_eq!(
        decode_config_commitment(&proof.info.as_ref().unwrap().extension, true).unwrap(),
        commitment
    );
    assert_eq!(proof.storage_proofs.len(), 2);
    for (key, value) in [
        (B256::ZERO, U256::ONE),
        (B256::with_last_byte(127), U256::from(128)),
    ] {
        assert_eq!(
            proof
                .storage_proofs
                .iter()
                .find(|proof| proof.key == key)
                .unwrap()
                .value,
            value
        );
    }
    proof.verify(expected_root).unwrap();
    // Verification must bind the fifth account field, not merely the ordinary account fields.
    let mut wrong_commitment = proof;
    wrong_commitment.info.as_mut().unwrap().extension =
        encode_config_commitment(B256::repeat_byte(0x99)).into();
    assert!(wrong_commitment.verify(expected_root).is_err());
}

#[test]
fn native_first_call_registration_and_retry() {
    let mut f = Fixture::new();
    let revert = f.install_contract(Address::repeat_byte(0x55), bytes!("60006000fd").to_vec());
    let failed = f.signed(3, vec![f.getter(), revert]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&failed, f.account))
        .unwrap();
    assert!(!output.result.is_success());
    assert_eq!(
        decode_config_commitment(&output.state[&f.account].info.extension, true).unwrap(),
        f.config.commitment().unwrap()
    );
    f.evm.db_mut().commit(output.state);
    let tx = f.signed(4, vec![f.getter()]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    assert_eq!(
        decode_config_commitment(&output.state[&f.account].info.extension, true).unwrap(),
        f.config.commitment().unwrap()
    );
    assert_eq!(
        INativeMultisig::getConfigCommitmentCall::abi_decode_returns(
            output.result.output().unwrap()
        )
        .unwrap(),
        f.config.commitment().unwrap()
    );
}

#[test]
fn native_replay_rejects_account_authorization() {
    let mut f = Fixture::new();
    let signed = f.signed(3, vec![f.getter()]);
    let native: TempoTxEnvelope = signed.clone().into();
    assert!(!supports_storage_action_replay(&native, TempoHardfork::T14));
    let primitive = TempoSignature::from(Signature::test_signature());
    let mut ordinary_tx = signed.tx().clone();
    ordinary_tx.calls[0].to = TxKind::Call(PATH_USD_ADDRESS);
    let ordinary: TempoTxEnvelope = ordinary_tx.clone().into_signed(primitive.clone()).into();
    assert!(supports_storage_action_replay(
        &ordinary,
        TempoHardfork::T14
    ));
    let mut rejected = vec![native];
    for target in [ACCOUNT_KEYCHAIN_ADDRESS, NATIVE_MULTISIG_ADDRESS] {
        for index in 0..2 {
            let mut tx = ordinary_tx.clone();
            tx.calls.push(tx.calls[0].clone());
            tx.calls[index].to = TxKind::Call(target);
            let envelope = tx.into_signed(primitive.clone()).into();
            assert!(!supports_storage_action_replay(
                &envelope,
                TempoHardfork::T14
            ));
            rejected.push(envelope);
        }
    }
    let mut verifier_tx = ordinary_tx.clone();
    verifier_tx.calls[0].to = TxKind::Call(SIGNATURE_VERIFIER_ADDRESS);
    verifier_tx.calls[0].input = ISignatureVerifier::verifyMultisigCall {
        account: f.account,
        hash: signed.tx().signature_hash(),
        signature: signed.signature().to_bytes(),
    }
    .abi_encode()
    .into();
    let verifier: TempoTxEnvelope = verifier_tx.into_signed(primitive.clone()).into();
    assert!(!supports_storage_action_replay(
        &verifier,
        TempoHardfork::T14
    ));
    rejected.push(verifier);
    let mut pure_verifier = ordinary_tx.clone();
    pure_verifier.calls[0].to = TxKind::Call(SIGNATURE_VERIFIER_ADDRESS);
    pure_verifier.calls[0].input = ISignatureVerifier::verifyCall {
        signer: f.account,
        hash: B256::ZERO,
        signature: Default::default(),
    }
    .abi_encode()
    .into();
    assert!(supports_storage_action_replay(
        &pure_verifier.into_signed(primitive.clone()).into(),
        TempoHardfork::T14
    ));
    let mut tx = ordinary_tx;
    tx.key_authorization = Some(
        KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::repeat_byte(2))
            .into_signed(signed.signature().as_multisig().unwrap().clone()),
    );
    assert!(!supports_storage_action_replay(
        &tx.clone().into_signed(primitive.clone()).into(),
        TempoHardfork::T14
    ));
    // Even a primitive-signed primitive grant reads parent metadata at T14.
    tx.key_authorization.as_mut().unwrap().signature =
        AccountSignature::try_from(primitive.clone()).unwrap();
    assert!(!supports_storage_action_replay(
        &tx.into_signed(primitive).into(),
        TempoHardfork::T14
    ));
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&signed, f.account))
        .unwrap();
    let config = TempoEvmConfig::new(MODERATO.clone());
    let block = TempoBlock::default().seal_slow();
    let mut db = State::builder().with_bundle_update().build();
    let mut executor = config.executor_for_block(&mut db, &block).unwrap();
    for envelope in rejected {
        let recovered = envelope.with_signer(f.account);
        let error = executor
            .execute_transaction_with_actions(
                &recovered,
                StorageActionReplay {
                    result: output.result.clone(),
                    actions: vec![],
                    expiring_nonce: None,
                    validator_fee: U256::ZERO,
                },
                |_| panic!("unsupported replay must not commit"),
            )
            .unwrap_err();
        assert_eq!(
            StorageActionReplayError::from_block_execution_error(&error),
            Some(StorageActionReplayError::UnsupportedAuthorization)
        );
    }
}

#[test]
fn native_grant_recipient_code_change_rejects_stale_replay() {
    let mut f = Fixture::with_parent(false);
    f.evm = f.evm.with_actions();
    let recipient = Address::repeat_byte(0x22);
    let grant = KeyAuthorization::unrestricted(1, SignatureType::Multisig, recipient);
    let approval = f.owner.sign_hash_sync(&grant.signature_hash()).unwrap();
    let tx = TempoTransaction {
        chain_id: 1,
        nonce: 3,
        gas_limit: 1_000_000,
        calls: vec![f.getter()],
        key_authorization: Some(grant.into_signed(approval)),
        ..Default::default()
    };
    let signature = f.owner.sign_hash_sync(&tx.signature_hash()).unwrap();
    let signed = tx.into_signed(signature.into());
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&signed, f.account))
        .unwrap();
    assert!(output.result.is_success());
    let actions = f.evm.take_actions().unwrap();
    assert!(
        !actions.is_empty(),
        "the precomputed grant must have real recorded writes"
    );

    // The precomputed result is not committed. Only its separate recipient gains code.
    let mut account = Account::from(AccountInfo {
        code_hash: keccak256([0x00]),
        code: Some(Bytecode::new_raw(vec![0x00].into())),
        ..Default::default()
    });
    account.mark_touch();
    f.evm
        .db_mut()
        .commit(std::iter::once((recipient, account)).collect());
    assert!(
        f.evm
            .transact(TempoTxEnv::from_recovered_tx(&signed, f.account))
            .is_err(),
        "ordinary execution must reject the now-ineligible grant recipient"
    );

    let config = TempoEvmConfig::new(MODERATO.clone());
    let block = TempoBlock::default().seal_slow();
    let mut executor = config.executor_for_block(f.evm.db_mut(), &block).unwrap();
    let recovered = TempoTxEnvelope::AA(signed).with_signer(f.account);
    let error = executor
        .execute_transaction_with_actions(
            &recovered,
            StorageActionReplay {
                result: output.result,
                actions,
                expiring_nonce: None,
                validator_fee: U256::ZERO,
            },
            |_| panic!("stale grant replay must not commit"),
        )
        .unwrap_err();
    assert_eq!(
        StorageActionReplayError::from_block_execution_error(&error),
        Some(StorageActionReplayError::UnsupportedAuthorization)
    );
}

fn activation_config() -> TempoEvmConfig {
    let factory = Address::repeat_byte(0x71);
    let mut genesis = DEV.genesis().clone();
    genesis.config.chain_id = 1;
    for (field, value) in [("t12Time", 0), ("t13Time", 0), ("t14Time", 10)] {
        genesis
            .config
            .extra_fields
            .insert(field.into(), json!(value));
    }
    genesis
        .config
        .extra_fields
        .insert("multisigRecoveryFactory".into(), json!(factory));
    TempoEvmConfig::new(Arc::new(TempoChainSpec::from_genesis(genesis)))
}

#[test]
fn native_signed_parent_delegate_combinations() {
    native_signed_parent_delegate_case(GrantOutcome::Success, 0);
}

#[test]
fn native_signed_parent_delegate_revert_and_retry() {
    native_signed_parent_delegate_case(GrantOutcome::RevertAndRetry, 0);
}

#[test]
fn native_signed_parent_delegate_scope_rejection_and_retry() {
    native_signed_parent_delegate_case(GrantOutcome::ScopeRejectionAndRetry, 0);
}

#[test]
fn native_signed_parent_delegate_revert_preserves_fees() {
    native_signed_parent_delegate_case(GrantOutcome::RevertAndRetry, 1_000_000_000_000);
}

#[test]
fn native_signed_parent_delegate_scope_rejection_preserves_fees() {
    native_signed_parent_delegate_case(GrantOutcome::ScopeRejectionAndRetry, 1_000_000_000_000);
}

fn native_signed_parent_delegate_case(outcome: GrantOutcome, gas_price: u128) {
    for parent_native in [false, true] {
        for delegate_native in [false, true] {
            let mut f = Fixture::with_parent(parent_native);
            let signer = PrivateKeySigner::from_bytes(&B256::repeat_byte(2)).unwrap();
            let config = MultisigConfig {
                salt: B256::repeat_byte(2),
                version: 0,
                threshold: 1,
                owners: vec![MultisigOwner {
                    owner: signer.address(),
                    weight: 1,
                }],
            };
            let delegate = if delegate_native {
                config.derive_account(Address::repeat_byte(0x71)).unwrap()
            } else {
                signer.address()
            };
            let parent = f.account;
            // One microdollar per gas in fee cases; fund all three executions up front.
            let fee_budget = if gas_price == 0 { 0 } else { 50_000_000 };
            let initial_balance = 1000 + fee_budget;
            let initial_limit = 100 + fee_budget;
            let reverter = Address::repeat_byte(0x55);
            let revert = f.install_contract(reverter, bytes!("60006000fd").to_vec());
            StorageCtx::enter_ctx(f.evm.ctx_mut(), StorageActions::disabled(), || {
                TIP20Setup::path_usd(f.owner.address())
                    .with_issuer(f.owner.address())
                    .with_mint(parent, U256::from(initial_balance))
                    .apply()
            })
            .unwrap();
            let state = f.evm.ctx_mut().journaled_state.finalize();
            f.evm.db_mut().commit(state);
            let mut targets = vec![NATIVE_MULTISIG_ADDRESS, PATH_USD_ADDRESS];
            if outcome != GrantOutcome::ScopeRejectionAndRetry {
                targets.push(reverter);
            }
            let authorization = KeyAuthorization::unrestricted(
                1,
                if delegate_native {
                    SignatureType::Multisig
                } else {
                    SignatureType::Secp256k1
                },
                delegate,
            )
            .with_expiry(1000)
            .with_limits(vec![TokenLimit {
                token: PATH_USD_ADDRESS,
                limit: U256::from(initial_limit),
                period: 0,
            }])
            .with_allowed_calls(
                targets
                    .iter()
                    .map(|&target| CallScope {
                        target,
                        selector_rules: vec![],
                    })
                    .collect(),
            );
            let grant_signature = if parent_native {
                AccountSignature::Multisig(
                    MultisigSignature::try_new(
                        f.account,
                        f.config.clone(),
                        vec![PrimitiveSignature::Secp256k1(
                            f.owner
                                .sign_hash_sync(&multisig_digest(
                                    authorization.signature_hash(),
                                    f.account,
                                    0,
                                ))
                                .unwrap(),
                        )],
                    )
                    .unwrap(),
                )
            } else {
                AccountSignature::from(
                    f.owner
                        .sign_hash_sync(&authorization.signature_hash())
                        .unwrap(),
                )
            };
            let transfer = Call {
                to: TxKind::Call(PATH_USD_ADDRESS),
                value: U256::ZERO,
                input: ITIP20::transferCall {
                    to: Address::repeat_byte(0x66),
                    amount: U256::from(10),
                }
                .abi_encode()
                .into(),
            };
            let mut tx = TempoTransaction {
                chain_id: 1,
                nonce: 3,
                gas_limit: 5_000_000,
                max_fee_per_gas: gas_price,
                max_priority_fee_per_gas: gas_price,
                calls: if outcome == GrantOutcome::Success {
                    vec![f.getter()]
                } else {
                    vec![transfer.clone(), revert]
                },
                key_authorization: Some(authorization.into_signed(grant_signature)),
                ..Default::default()
            };
            let sign = |tx: &TempoTransaction| {
                let digest = KeychainSignature::signing_hash(tx.signature_hash(), parent);
                let signature = if delegate_native {
                    AccountSignature::Multisig(
                        MultisigSignature::try_new(
                            delegate,
                            config.clone(),
                            vec![PrimitiveSignature::Secp256k1(
                                signer
                                    .sign_hash_sync(&multisig_digest(digest, delegate, 0))
                                    .unwrap(),
                            )],
                        )
                        .unwrap(),
                    )
                } else {
                    AccountSignature::from(signer.sign_hash_sync(&digest).unwrap())
                };
                tx.clone()
                    .into_signed(TempoSignature::Keychain(KeychainSignature::new(
                        parent, signature,
                    )))
            };
            let signed = sign(&tx);
            assert!(!supports_storage_action_replay(
                &signed.clone().into(),
                TempoHardfork::T14
            ));
            let output = f
                .evm
                .transact(TempoTxEnv::from_recovered_tx(&signed, parent))
                .unwrap();
            assert_eq!(
                output.result.is_success(),
                outcome == GrantOutcome::Success,
                "{outcome:?}, parent={parent_native} delegate={delegate_native}: {:?}",
                output.result
            );
            let charged_fee = |gas_used| {
                let fee = calc_gas_balance_spending(gas_used, gas_price).to::<u64>();
                if gas_price != 0 {
                    assert!(fee > 0, "unused gas must be refunded");
                    assert!(fee < tx.gas_limit, "unused gas must be refunded");
                }
                fee
            };
            let mut total_fees = charged_fee(output.result.tx_gas_used());
            if outcome != GrantOutcome::Success {
                let ExecutionResult::Revert { output, .. } = &output.result else {
                    panic!("expected included revert, got {:?}", output.result);
                };
                let expected = if outcome == GrantOutcome::ScopeRejectionAndRetry {
                    IAccountKeychain::CallNotAllowed {}.abi_encode()
                } else {
                    vec![]
                };
                assert_eq!(output, expected.as_slice());
            }
            for (account, expected) in [
                (
                    f.account,
                    if parent_native {
                        f.config.commitment().unwrap()
                    } else {
                        B256::ZERO
                    },
                ),
                (
                    delegate,
                    if delegate_native {
                        config.commitment().unwrap()
                    } else {
                        B256::ZERO
                    },
                ),
            ] {
                let commitment = output
                    .state
                    .get(&account)
                    .map(|account| decode_config_commitment(&account.info.extension, true).unwrap())
                    .unwrap_or_default();
                assert_eq!(commitment, expected);
            }
            f.evm.db_mut().commit(output.state);
            let assert_grant = |f: &mut Fixture, fees: u64, transferred: u64, nonce: u64| {
                let (key, limit, scopes, balance, recipient_balance) =
                    StorageCtx::enter_ctx(f.evm.ctx_mut(), StorageActions::disabled(), || {
                        let keychain = AccountKeychain::new();
                        Ok::<_, TempoPrecompileError>((
                            keychain.get_key(IAccountKeychain::getKeyCall {
                                account: parent,
                                keyId: delegate,
                            })?,
                            keychain.get_remaining_limit(
                                IAccountKeychain::getRemainingLimitCall {
                                    account: parent,
                                    keyId: delegate,
                                    token: PATH_USD_ADDRESS,
                                },
                            )?,
                            keychain.get_allowed_calls(IAccountKeychain::getAllowedCallsCall {
                                account: parent,
                                keyId: delegate,
                            })?,
                            TIP20Token::from_address(PATH_USD_ADDRESS)?
                                .balance_of(ITIP20::balanceOfCall { account: parent })?,
                            TIP20Token::from_address(PATH_USD_ADDRESS)?.balance_of(
                                ITIP20::balanceOfCall {
                                    account: Address::repeat_byte(0x66),
                                },
                            )?,
                        ))
                    })
                    .unwrap();
                assert_eq!(key.keyId, delegate);
                assert_eq!(key.expiry, 1000);
                assert!(key.enforceLimits);
                assert!(!key.isRevoked);
                assert_eq!(key.signatureType as u8, if delegate_native { 3 } else { 0 });
                assert_eq!(limit, U256::from(initial_limit - fees - transferred));
                assert_eq!(balance, U256::from(initial_balance - fees - transferred));
                assert_eq!(recipient_balance, U256::from(transferred));
                assert!(scopes.isScoped);
                assert_eq!(scopes.scopes.len(), targets.len());
                for scope in scopes.scopes {
                    assert!(targets.contains(&scope.target));
                    assert_eq!(scope.selectorRules, Vec::new());
                }
                f.evm.ctx_mut().journaled_state.finalize();
                assert_eq!(f.evm.db_mut().basic(parent).unwrap().unwrap().nonce, nonce);
            };
            // Calls roll back, but the grant, actual fees and transaction nonce survive.
            assert_grant(&mut f, total_fees, 0, 4);
            if outcome == GrantOutcome::Success {
                continue;
            }
            let accepted_grant = tx.key_authorization.take();
            tx.calls = vec![transfer];
            // Re-sign without the immutable grant. Two uses prove counters do not reset.
            for (nonce, transferred) in [(4, 10), (5, 20)] {
                tx.nonce = nonce;
                let output = f
                    .evm
                    .transact(TempoTxEnv::from_recovered_tx(&sign(&tx), parent))
                    .unwrap();
                assert!(output.result.is_success(), "{:?}", output.result);
                total_fees += charged_fee(output.result.tx_gas_used());
                f.evm.db_mut().commit(output.state);
                assert_grant(&mut f, total_fees, transferred, nonce + 1);
                assert_eq!(
                    f.commitment(),
                    if parent_native {
                        f.config.commitment().unwrap()
                    } else {
                        B256::ZERO
                    }
                );
                let delegate_info = f.evm.db_mut().basic(delegate).unwrap().unwrap_or_default();
                assert_eq!(
                    decode_config_commitment(&delegate_info.extension, true).unwrap(),
                    if delegate_native {
                        config.commitment().unwrap()
                    } else {
                        B256::ZERO
                    },
                );
            }
            tx.nonce = 6;
            tx.key_authorization = accepted_grant;
            let error = f
                .evm
                .transact(TempoTxEnv::from_recovered_tx(&sign(&tx), parent))
                .unwrap_err();
            let EVMError::Transaction(TempoInvalidTransaction::KeychainPrecompileError { reason }) =
                error
            else {
                panic!("expected duplicate-grant validation error, got {error}");
            };
            assert_eq!(
                reason,
                TempoPrecompileError::from(AccountKeychainError::key_already_exists()).to_string()
            );
        }
    }
}

#[test]
fn native_first_registration_preserves_existing_storage() {
    let mut f = Fixture::new();
    let info = f.evm.db_mut().basic(f.account).unwrap().unwrap();
    let slot = U256::from(7);
    let value = U256::from(91);
    f.evm.db_mut().insert_account_with_storage(
        f.account,
        info.clone(),
        std::iter::once((slot, value)).collect(),
    );
    let tx = f.signed(3, vec![f.getter()]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    assert_eq!(output.result.logs(), []);
    f.evm.db_mut().commit(output.state);
    assert_eq!(f.commitment(), f.config.commitment().unwrap());
    assert_eq!(f.evm.db_mut().storage(f.account, slot).unwrap(), value);
    let after = f.evm.db_mut().basic(f.account).unwrap().unwrap();
    assert_eq!(after.balance, info.balance);
    assert_eq!(after.nonce, info.nonce + 1);
}

#[test]
fn native_registration_survives_caught_reverting_subcall() {
    let mut f = Fixture::new();
    let reverter = Address::repeat_byte(0x55);
    // The child writes slot zero, then reverts. Its parent catches the failed CALL.
    f.install_contract(reverter, bytes!("600160005560006000fd").to_vec());
    let catcher = Address::repeat_byte(0x56);
    // GAS CALL ISZERO; persist the caught failure in the parent's slot zero.
    let code = [
        bytes!("6000600060006000600073").as_ref(),
        reverter.as_slice(),
        bytes!("5af11560005500").as_ref(),
    ]
    .concat();
    let call = f.install_contract(catcher, code);
    let tx = f.signed(3, vec![call]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    assert_eq!(output.result.logs(), []);
    f.evm.db_mut().commit(output.state);
    assert_eq!(f.commitment(), f.config.commitment().unwrap());
    assert_eq!(
        f.evm.db_mut().storage(reverter, U256::ZERO).unwrap(),
        U256::ZERO
    );
    assert_eq!(
        f.evm.db_mut().storage(catcher, U256::ZERO).unwrap(),
        U256::ONE
    );
}

#[test]
fn native_first_transaction_can_rotate_configuration() {
    let mut f = Fixture::new();
    let next = MultisigConfig {
        version: 1,
        ..f.config.clone()
    };
    let tx = f.signed(3, vec![Fixture::rotation(&f.config, &next), f.getter()]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    assert_eq!(output.result.logs().len(), 1);
    assert_eq!(
        INativeMultisig::getConfigCommitmentCall::abi_decode_returns(
            output.result.output().unwrap()
        )
        .unwrap(),
        next.commitment().unwrap()
    );
    f.evm.db_mut().commit(output.state);
    assert_eq!(f.commitment(), next.commitment().unwrap());
}

#[test]
fn native_rotation_authorizes_next_transaction_in_same_block() {
    let mut f = Fixture::new();
    let block = f.evm.ctx_mut().block.clone();
    let next_owner = PrivateKeySigner::from_bytes(&B256::repeat_byte(2)).unwrap();
    let next = MultisigConfig {
        version: 1,
        owners: vec![MultisigOwner {
            owner: next_owner.address(),
            weight: 1,
        }],
        ..f.config.clone()
    };
    let rotate = f.signed(3, vec![Fixture::rotation(&f.config, &next)]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&rotate, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    f.evm.db_mut().commit(output.state);
    let stale = f.signed(4, vec![f.getter()]);
    let error = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&stale, f.account))
        .unwrap_err();
    assert!(
        matches!(
            error,
            EVMError::Transaction(TempoInvalidTransaction::NativeMultisig(
                NativeMultisigError::ConfigurationCommitmentMismatch { .. }
            ))
        ),
        "{error}"
    );
    f.config = next;
    f.owner = next_owner;
    let tx = f.signed(4, vec![f.getter()]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    f.evm.db_mut().commit(output.state);
    assert_eq!(f.commitment(), f.config.commitment().unwrap());
    assert_eq!(f.evm.ctx_mut().block.number, block.number);
    assert_eq!(f.evm.ctx_mut().block.timestamp, block.timestamp);
}

#[test]
fn native_batch_rotation_writes_and_events_revert_together() {
    native_batch_rotation_failure(true, false);
}

#[test]
fn native_batch_rotation_writes_and_events_halt_together() {
    native_batch_rotation_failure(true, true);
}

#[test]
fn native_first_rotation_revert_preserves_registration() {
    native_batch_rotation_failure(false, false);
}

#[test]
fn native_first_rotation_halt_preserves_registration() {
    native_batch_rotation_failure(false, true);
}

fn native_batch_rotation_failure(registered: bool, halt: bool) {
    let mut f = Fixture::new();
    let mut nonce = 3;
    if registered {
        let register = f.signed(nonce, vec![f.getter()]);
        let output = f
            .evm
            .transact(TempoTxEnv::from_recovered_tx(&register, f.account))
            .unwrap();
        assert!(output.result.is_success());
        f.evm.db_mut().commit(output.state);
        nonce += 1;
    }
    let v1 = MultisigConfig {
        version: 1,
        owners: vec![MultisigOwner {
            owner: PrivateKeySigner::from_bytes(&B256::repeat_byte(2))
                .unwrap()
                .address(),
            weight: 1,
        }],
        ..f.config.clone()
    };
    let v2 = MultisigConfig {
        version: 2,
        owners: vec![MultisigOwner {
            owner: PrivateKeySigner::from_bytes(&B256::repeat_byte(3))
                .unwrap()
                .address(),
            weight: 1,
        }],
        ..f.config.clone()
    };
    let revert = f.install_contract(
        Address::repeat_byte(0x55),
        if halt {
            bytes!("fe").to_vec()
        } else {
            bytes!("60006000fd").to_vec()
        },
    );
    let rotations = vec![
        Fixture::rotation(&f.config, &v1),
        Fixture::rotation(&v1, &v2),
    ];
    let mut calls = rotations.clone();
    calls.push(revert);
    let tx = f.signed(nonce, calls);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert_eq!(output.result.is_halt(), halt);
    assert_eq!(
        matches!(&output.result, ExecutionResult::Revert { .. }),
        !halt
    );
    assert_eq!(output.result.logs(), []);
    f.evm.db_mut().commit(output.state);
    assert_eq!(f.commitment(), f.config.commitment().unwrap());
    nonce += 1;
    assert_eq!(
        f.evm.db_mut().basic(f.account).unwrap().unwrap().nonce,
        nonce
    );
    // The original witness remains valid. Each successful update must read the
    // previous call's journaled commitment, not the transaction-start leaf.
    let retry = f.signed(nonce, rotations);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&retry, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    assert_eq!(output.result.logs().len(), 2);
    f.evm.db_mut().commit(output.state);
    assert_eq!(f.commitment(), v2.commitment().unwrap());
}

#[derive(Clone, Copy, Debug)]
enum RootTx {
    Legacy,
    Eip2930,
    Eip1559,
    Aa,
}

fn signer(seed: u8) -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&B256::repeat_byte(seed)).unwrap()
}

/// Weight-one owners in the ascending order a configuration requires.
fn owner_set(mut addresses: Vec<Address>) -> Vec<MultisigOwner> {
    addresses.sort();
    addresses
        .into_iter()
        .map(|owner| MultisigOwner { owner, weight: 1 })
        .collect()
}

/// Mints path USD, which pays transaction fees by default.
fn fund(f: &mut Fixture, account: Address, amount: u64) {
    StorageCtx::enter_ctx(f.evm.ctx_mut(), StorageActions::disabled(), || {
        TIP20Setup::path_usd(f.owner.address())
            .with_issuer(f.owner.address())
            .with_mint(account, U256::from(amount))
            .apply()
    })
    .unwrap();
    let state = f.evm.ctx_mut().journaled_state.finalize();
    f.evm.db_mut().commit(state);
}

fn balance(f: &mut Fixture, account: Address) -> U256 {
    StorageCtx::enter_ctx(f.evm.ctx_mut(), StorageActions::disabled(), || {
        TIP20Token::from_address(PATH_USD_ADDRESS)?.balance_of(ITIP20::balanceOfCall { account })
    })
    .unwrap()
}

/// A transaction of `kind` signed by the account's secp256k1 root whose only call is `call`.
fn root_tx(f: &Fixture, kind: RootTx, nonce: u64, call: Call) -> TempoTxEnvelope {
    let Call { to, value, input } = call;
    let sign = |hash: B256| f.owner.sign_hash_sync(&hash).unwrap();
    match kind {
        RootTx::Legacy => {
            let tx = TxLegacy {
                chain_id: Some(1),
                nonce,
                gas_price: 0,
                gas_limit: 1_000_000,
                to,
                value,
                input,
            };
            let signature = sign(tx.signature_hash());
            TempoTxEnvelope::Legacy(tx.into_signed(signature))
        }
        RootTx::Eip2930 => {
            let tx = TxEip2930 {
                chain_id: 1,
                nonce,
                gas_price: 0,
                gas_limit: 1_000_000,
                to,
                value,
                access_list: AccessList(Vec::new()),
                input,
            };
            let signature = sign(tx.signature_hash());
            TempoTxEnvelope::Eip2930(tx.into_signed(signature))
        }
        RootTx::Eip1559 => {
            let tx = TxEip1559 {
                chain_id: 1,
                nonce,
                gas_limit: 1_000_000,
                max_fee_per_gas: 0,
                max_priority_fee_per_gas: 0,
                to,
                value,
                access_list: AccessList(Vec::new()),
                input,
            };
            let signature = sign(tx.signature_hash());
            TempoTxEnvelope::Eip1559(tx.into_signed(signature))
        }
        RootTx::Aa => TempoTxEnvelope::AA(f.primitive(nonce, vec![Call { to, value, input }])),
    }
}

fn authorization(signer: &PrivateKeySigner, target: Address, nonce: u64) -> SignedAuthorization {
    let authorization = Authorization {
        chain_id: U256::from(1),
        address: target,
        nonce,
    };
    let signature = signer
        .sign_hash_sync(&authorization.signature_hash())
        .unwrap();
    authorization.into_signed(signature)
}

/// A root-signed EIP-7702 transaction carrying `authorizations`.
fn type4(
    f: &Fixture,
    nonce: u64,
    to: Address,
    input: Bytes,
    authorizations: Vec<SignedAuthorization>,
) -> TempoTxEnvelope {
    let tx = TxEip7702 {
        chain_id: 1,
        nonce,
        gas_limit: 1_000_000,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        to,
        value: U256::ZERO,
        access_list: AccessList(Vec::new()),
        authorization_list: authorizations,
        input,
    };
    let signature = f.owner.sign_hash_sync(&tx.signature_hash()).unwrap();
    TempoTxEnvelope::Eip7702(tx.into_signed(signature))
}

/// Delegates the account to `target` (the zero address clears the delegation) with a real
/// type-4 transaction at `nonce`; the authorization consumes the next nonce.
fn set_delegation(f: &mut Fixture, nonce: u64, target: Address) {
    let tx = type4(
        f,
        nonce,
        Address::repeat_byte(0x73),
        Bytes::new(),
        vec![authorization(&f.owner, target, nonce + 1)],
    );
    let result = f.run(&tx);
    assert!(result.is_success(), "{result:?}");
}

/// Authorizes `key` for the account with a root-signed grant at `nonce`.
fn grant_key(f: &mut Fixture, nonce: u64, key: &PrivateKeySigner, admin: bool, expiry: u64) {
    let mut grant = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key.address());
    if admin {
        grant = grant.into_admin(f.account);
    }
    if expiry != 0 {
        grant = grant.with_expiry(expiry);
    }
    let approval = f.owner.sign_hash_sync(&grant.signature_hash()).unwrap();
    let tx = f.sign_primitive(TempoTransaction {
        key_authorization: Some(grant.into_signed(approval)),
        ..aa_tx(nonce, vec![f.getter()])
    });
    let result = f.run(&tx);
    assert!(result.is_success(), "{result:?}");
}

/// A transaction signed by the access key `key` on behalf of the account.
fn keychain_tx(f: &Fixture, key: &PrivateKeySigner, nonce: u64, calls: Vec<Call>) -> AASigned {
    let tx = aa_tx(nonce, calls);
    let signature = key
        .sign_hash_sync(&KeychainSignature::signing_hash(
            tx.signature_hash(),
            f.account,
        ))
        .unwrap();
    tx.into_signed(TempoSignature::Keychain(KeychainSignature::new(
        f.account,
        PrimitiveSignature::Secp256k1(signature),
    )))
}

/// A contract that forwards its calldata to the multisig precompile and reverts with the result.
fn forwarder(f: &mut Fixture) -> Call {
    let code = [
        bytes!("365f5f375f5f365f5f73").as_ref(),
        NATIVE_MULTISIG_ADDRESS.as_slice(),
        bytes!("5af1503d5f5f3e3d5ffd").as_ref(),
    ]
    .concat();
    f.install_contract(Address::repeat_byte(0x55), code)
}

/// The data of the multisig precompile's logs; fee transfers and key grants log too.
fn multisig_logs(result: &ExecutionResult<HaltReason>) -> Vec<LogData> {
    result
        .logs()
        .iter()
        .filter(|log| log.address == NATIVE_MULTISIG_ADDRESS)
        .map(|log| log.data.clone())
        .collect()
}

fn assert_upgraded(f: &mut Fixture, result: &ExecutionResult<HaltReason>, config: &MultisigConfig) {
    let commitment = config.commitment().unwrap();
    assert!(result.is_success(), "{result:?}");
    assert_eq!(
        INativeMultisig::upgradeAccountCall::abi_decode_returns(result.output().unwrap()).unwrap(),
        commitment
    );
    let event = INativeMultisig::AccountUpgraded {
        account: f.account,
        commitment,
        salt: config.salt,
        threshold: config.threshold,
        owners: abi_owners(config),
    };
    assert_eq!(multisig_logs(result), [event.encode_log_data()]);
    assert_eq!(f.commitment(), commitment);
}

/// Runs the transaction `tx` builds on `f` and asserts it reverts with exactly `error`.
fn expect_revert(
    mut f: Fixture,
    label: &str,
    tx: impl FnOnce(&mut Fixture) -> TempoTxEnvelope,
    error: &[u8],
) {
    let tx = tx(&mut f);
    let result = f.run(&tx);
    assert!(
        matches!(result, ExecutionResult::Revert { .. }),
        "{label}: {result:?}"
    );
    assert_eq!(result.output().unwrap().as_ref(), error, "{label}");
    assert!(multisig_logs(&result).is_empty(), "{label}");
}

#[test]
fn eoa_migration_commits_configuration() {
    assert_eq!(MULTISIG_UPGRADE_DOMAIN, b"tempo:multisig:upgrade");
    let others = [signer(2).address(), signer(3).address()];
    for kind in [RootTx::Legacy, RootTx::Eip2930, RootTx::Eip1559, RootTx::Aa] {
        for root_listed in [false, true] {
            let mut f = Fixture::with_parent(false);
            let mut members = others.to_vec();
            if root_listed {
                members.push(f.owner.address());
            }
            let config = f.upgraded(2, owner_set(members));
            let tx = root_tx(&f, kind, 3, Fixture::upgrade(&config));
            let result = f.run(&tx);
            assert_upgraded(&mut f, &result, &config);
            assert_eq!(
                config.salt,
                keccak256([b"tempo:multisig:upgrade".as_slice(), f.account.as_slice()].concat()),
                "{kind:?}"
            );
            assert_eq!(f.evm.db_mut().basic(f.account).unwrap().unwrap().nonce, 4);
        }
    }

    // A nonce-zero account with no balance migrates under a fee payer, which pays.
    let mut f = Fixture::with_parent(false);
    f.evm.db_mut().insert_account(
        f.account,
        AccountInfo::new(U256::ZERO, 0, KECCAK256_EMPTY, Bytecode::new()),
    );
    let sponsor = signer(9);
    fund(&mut f, sponsor.address(), 50_000_000);
    let config = f.upgraded(1, owner_set(others.to_vec()));
    let mut tx = TempoTransaction {
        max_fee_per_gas: 1,
        max_priority_fee_per_gas: 1,
        fee_token: Some(PATH_USD_ADDRESS),
        ..aa_tx(0, vec![Fixture::upgrade(&config)])
    };
    tx.fee_payer_signature = Some(
        sponsor
            .sign_hash_sync(&tx.fee_payer_signature_hash(f.account))
            .unwrap(),
    );
    let tx = f.sign_primitive(tx);
    let result = f.run(&tx);
    assert_upgraded(&mut f, &result, &config);
    let fee = calc_gas_balance_spending(result.tx_gas_used(), 1);
    assert!(fee > U256::ZERO);
    assert_eq!(
        balance(&mut f, sponsor.address()),
        U256::from(50_000_000) - fee
    );
    let account = f.account;
    assert_eq!(balance(&mut f, account), U256::ZERO);
    assert_eq!(f.evm.db_mut().basic(account).unwrap().unwrap().nonce, 1);
}

#[test]
fn eoa_migration_error_order() {
    let only_call = INativeMultisig::UpgradeMustBeOnlyCall {}.abi_encode();
    let root_required = INativeMultisig::PrimitiveRootRequired {}.abi_encode();
    let has_code = INativeMultisig::AccountHasCode {}.abi_encode();
    let invalid_config = INativeMultisig::InvalidConfig {}.abi_encode();
    let member = signer(2).address();
    let base = Fixture::with_parent(false).upgraded(1, owner_set(vec![member]));
    let upgrade = Fixture::upgrade(&base);
    let zero_threshold = MultisigConfig {
        threshold: 0,
        ..base.clone()
    };
    let delegate = Address::repeat_byte(0x74);

    // 1: the call must be the transaction's only call, however the account signs.
    expect_revert(
        Fixture::with_parent(false),
        "upgrade then call",
        |f| f.primitive(3, vec![upgrade.clone(), f.getter()]).into(),
        &only_call,
    );
    expect_revert(
        Fixture::with_parent(false),
        "call then upgrade",
        |f| f.primitive(3, vec![f.getter(), upgrade.clone()]).into(),
        &only_call,
    );
    expect_revert(
        Fixture::with_parent(false),
        "nested call",
        |f| {
            let mut call = forwarder(f);
            call.input = upgrade.input.clone();
            f.primitive(3, vec![call]).into()
        },
        &only_call,
    );
    expect_revert(
        Fixture::with_parent(false),
        "type-4 authorization list",
        |f| {
            let authorizations = vec![authorization(&signer(5), Address::ZERO, 0)];
            type4(
                f,
                3,
                NATIVE_MULTISIG_ADDRESS,
                upgrade.input.clone(),
                authorizations,
            )
        },
        &only_call,
    );
    expect_revert(
        Fixture::with_parent(false),
        "AA authorization list",
        |f| {
            let authorization = Authorization {
                chain_id: U256::from(1),
                address: Address::ZERO,
                nonce: 0,
            };
            let signature = signer(5)
                .sign_hash_sync(&authorization.signature_hash())
                .unwrap();
            f.sign_primitive(TempoTransaction {
                tempo_authorization_list: vec![TempoSignedAuthorization::new_unchecked(
                    authorization,
                    signature.into(),
                )],
                ..aa_tx(3, vec![upgrade.clone()])
            })
            .into()
        },
        &only_call,
    );
    expect_revert(
        Fixture::with_parent(false),
        "key authorization",
        |f| {
            let grant =
                KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, signer(6).address());
            let approval = f.owner.sign_hash_sync(&grant.signature_hash()).unwrap();
            f.sign_primitive(TempoTransaction {
                key_authorization: Some(grant.into_signed(approval)),
                ..aa_tx(3, vec![upgrade.clone()])
            })
            .into()
        },
        &only_call,
    );
    // 1 before 2: a batch is rejected before the signer is.
    expect_revert(
        Fixture::with_parent(false),
        "access key batch",
        |f| {
            let key = signer(6);
            grant_key(f, 3, &key, false, 0);
            keychain_tx(f, &key, 4, vec![upgrade.clone(), f.getter()]).into()
        },
        &only_call,
    );
    expect_revert(
        Fixture::new(),
        "native account batch",
        |f| f.signed(3, vec![upgrade.clone(), f.getter()]).into(),
        &only_call,
    );

    // 2: only a primitive root signature may migrate.
    for admin in [false, true] {
        expect_revert(
            Fixture::with_parent(false),
            if admin { "admin key" } else { "access key" },
            |f| {
                let key = signer(6);
                grant_key(f, 3, &key, admin, 0);
                keychain_tx(f, &key, 4, vec![upgrade.clone()]).into()
            },
            &root_required,
        );
    }
    // 2 before 5: the native account's invalid configuration is not reached.
    expect_revert(
        Fixture::new(),
        "native account",
        |f| f.signed(3, vec![Fixture::upgrade(&zero_threshold)]).into(),
        &root_required,
    );
    expect_revert(
        Fixture::with_parent(false),
        "migrated account",
        |f| {
            let config = f.upgraded(1, owner_set(vec![f.owner.address()]));
            let tx = f.primitive(3, vec![Fixture::upgrade(&config)]);
            let result = f.run(&tx);
            assert!(result.is_success(), "{result:?}");
            f.config = config;
            f.signed(4, vec![upgrade.clone()]).into()
        },
        &root_required,
    );
    // 2 before 3: a delegated account with an access key.
    expect_revert(
        Fixture::with_parent(false),
        "delegated access key",
        |f| {
            set_delegation(f, 3, delegate);
            let key = signer(6);
            grant_key(f, 5, &key, false, 0);
            keychain_tx(f, &key, 6, vec![upgrade.clone()]).into()
        },
        &root_required,
    );

    // 3: an account with code, here a 7702 delegation.
    expect_revert(
        Fixture::with_parent(false),
        "delegated account",
        |f| {
            set_delegation(f, 3, delegate);
            f.primitive(5, vec![upgrade.clone()]).into()
        },
        &has_code,
    );
    // 3 before 5: the invalid configuration is not reached.
    expect_revert(
        Fixture::with_parent(false),
        "delegated account, invalid configuration",
        |f| {
            set_delegation(f, 3, delegate);
            f.primitive(5, vec![Fixture::upgrade(&zero_threshold)])
                .into()
        },
        &has_code,
    );

    // 5: every invalid configuration is the same error, not the fine-grained ones.
    let heavy = (1..=49).map(Address::with_last_byte).collect::<Vec<_>>();
    let sorted = owner_set(vec![member, signer(3).address()]);
    let invalid = [
        ("zero threshold", zero_threshold),
        (
            "threshold above total weight",
            MultisigConfig {
                threshold: 2,
                ..base.clone()
            },
        ),
        (
            "no owners",
            MultisigConfig {
                owners: vec![],
                ..base.clone()
            },
        ),
        (
            "too many owners",
            MultisigConfig {
                owners: owner_set(heavy),
                ..base.clone()
            },
        ),
        (
            "zero weight",
            MultisigConfig {
                owners: vec![MultisigOwner {
                    owner: member,
                    weight: 0,
                }],
                ..base.clone()
            },
        ),
        (
            "zero owner",
            MultisigConfig {
                owners: vec![MultisigOwner {
                    owner: Address::ZERO,
                    weight: 1,
                }],
                ..base.clone()
            },
        ),
        (
            "duplicate owner",
            MultisigConfig {
                owners: vec![sorted[0].clone(), sorted[0].clone()],
                ..base.clone()
            },
        ),
        (
            "unsorted owners",
            MultisigConfig {
                owners: vec![sorted[1].clone(), sorted[0].clone()],
                ..base.clone()
            },
        ),
        (
            "total weight above 255",
            MultisigConfig {
                owners: vec![
                    MultisigOwner {
                        weight: 200,
                        ..sorted[0].clone()
                    },
                    MultisigOwner {
                        weight: 100,
                        ..sorted[1].clone()
                    },
                ],
                ..base
            },
        ),
    ];
    for (label, config) in &invalid {
        expect_revert(
            Fixture::with_parent(false),
            label,
            |f| f.primitive(3, vec![Fixture::upgrade(config)]).into(),
            &invalid_config,
        );
    }
    // Without a recovery factory the migrated account could never sign again.
    let mut f = Fixture::with_parent(false);
    f.evm.ctx_mut().block.multisig_recovery_factory = None;
    expect_revert(
        f,
        "no recovery factory",
        |f| f.primitive(3, vec![upgrade.clone()]).into(),
        &invalid_config,
    );
}

#[test]
fn eoa_migration_after_delegation_cleared() {
    let mut f = Fixture::with_parent(false);
    let config = f.upgraded(1, owner_set(vec![signer(2).address()]));
    let tx = f.primitive(5, vec![Fixture::upgrade(&config)]);
    set_delegation(&mut f, 3, Address::repeat_byte(0x74));
    let result = f.run(&tx);
    assert_eq!(
        result.output().unwrap().as_ref(),
        INativeMultisig::AccountHasCode {}.abi_encode()
    );
    assert_eq!(f.commitment(), B256::ZERO);

    // An earlier transaction clearing the delegation makes the account eligible again.
    set_delegation(&mut f, 6, Address::ZERO);
    let info = f.evm.db_mut().basic(f.account).unwrap().unwrap();
    assert_eq!(info.code_hash, KECCAK256_EMPTY);
    assert_eq!(info.nonce, 8);
    let tx = f.primitive(8, vec![Fixture::upgrade(&config)]);
    let result = f.run(&tx);
    assert_upgraded(&mut f, &result, &config);
}

#[test]
fn eoa_migration_failure_keeps_fee_and_nonce() {
    let member = signer(2).address();
    let base = Fixture::with_parent(false).upgraded(1, owner_set(vec![member]));
    let zero_threshold = MultisigConfig {
        threshold: 0,
        ..base.clone()
    };
    for (label, batch, error) in [
        (
            "invalid configuration",
            false,
            INativeMultisig::InvalidConfig {}.abi_encode(),
        ),
        (
            "batch",
            true,
            INativeMultisig::UpgradeMustBeOnlyCall {}.abi_encode(),
        ),
    ] {
        let mut f = Fixture::with_parent(false);
        let account = f.account;
        fund(&mut f, account, 50_000_000);
        let config = if batch { &base } else { &zero_threshold };
        let mut calls = vec![Fixture::upgrade(config)];
        if batch {
            calls.push(f.getter());
        }
        let tx = f.sign_primitive(TempoTransaction {
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            fee_token: Some(PATH_USD_ADDRESS),
            ..aa_tx(3, calls)
        });
        let result = f.run(&tx);
        assert!(
            matches!(result, ExecutionResult::Revert { .. }),
            "{label}: {result:?}"
        );
        assert_eq!(result.output().unwrap().as_ref(), error, "{label}");
        assert!(multisig_logs(&result).is_empty(), "{label}");
        let fee = calc_gas_balance_spending(result.tx_gas_used(), 1);
        assert!(fee > U256::ZERO, "{label}");
        assert_eq!(
            balance(&mut f, account),
            U256::from(50_000_000) - fee,
            "{label}"
        );
        assert_eq!(f.commitment(), B256::ZERO, "{label}");
        assert_eq!(
            f.evm.db_mut().basic(account).unwrap().unwrap().nonce,
            4,
            "{label}"
        );
    }
}

#[test]
fn eoa_migration_gas_schedule() {
    let members = owner_set(vec![
        signer(2).address(),
        signer(3).address(),
        signer(4).address(),
    ]);
    let params = tempo_gas_params(TempoHardfork::T14);
    // Pinned totals: (owners, gas_used). Legacy and AA primitive transactions cost the same.
    let pins = [(1, 45_498), (3, 47_664)];
    for (count, expected) in pins {
        for kind in [RootTx::Legacy, RootTx::Aa] {
            let mut f = Fixture::with_parent(false);
            let config = f.upgraded(1, members[..count].to_vec());
            let call = Fixture::upgrade(&config);
            let tx = root_tx(&f, kind, 3, call.clone());
            let result = f.run(&tx);
            assert!(result.is_success(), "{result:?}");

            // Intrinsic: 21000 plus 4 per zero and 16 per non-zero calldata byte.
            let intrinsic = 21_000
                + call
                    .input
                    .iter()
                    .map(|b| if *b == 0 { 4 } else { 16 })
                    .sum::<u64>();
            // The precompile charges, in order: ABI input, the eligibility TLOAD, the account
            // access for X, the 42-byte salt preimage hash, the commitment preimage hash, the zero
            // to non-zero commitment write, and LOG3 with the ABI-encoded data (salt, threshold,
            // owners).
            let input = 30 * (call.input.len() as u64).div_ceil(32);
            let salt = keccak_cost(MULTISIG_UPGRADE_DOMAIN.len() + 20);
            let commitment = keccak_cost(MULTISIG_CONFIG_DOMAIN.len() + 32 + 8 + 2 + count * 21);
            let warm_read = params.warm_storage_read_cost();
            let tload = warm_read;
            let account_access = warm_read;
            let write = 20_000;
            let log_data = (4 + count as u64 * 2) * 32;
            let log = 375 + 3 * 375 + 8 * log_data;
            let components =
                intrinsic + input + salt + commitment + tload + account_access + write + log;
            assert_eq!(
                components, expected,
                "{count} owners, {kind:?}: component sum"
            );
            assert_eq!(result.tx_gas_used(), expected, "{count} owners, {kind:?}");
        }
    }
}

#[test]
fn eoa_migration_preserves_account_state() {
    let mut f = Fixture::with_parent(false);
    let account = f.account;
    let spender = signer(7).address();
    let keys = [signer(11), signer(12), signer(13), signer(14)];
    fund(&mut f, account, 50_000_000);

    // Allowance, then an ordinary, an admin, a revoked and an expiring access key.
    let approve = Call {
        to: TxKind::Call(PATH_USD_ADDRESS),
        value: U256::ZERO,
        input: ITIP20::approveCall {
            spender,
            amount: U256::from(77),
        }
        .abi_encode()
        .into(),
    };
    let tx = f.primitive(3, vec![approve]);
    assert!(f.run(&tx).is_success());
    grant_key(&mut f, 4, &keys[0], false, 0);
    grant_key(&mut f, 5, &keys[1], true, 0);
    grant_key(&mut f, 6, &keys[2], false, 0);
    let revoke = Call {
        to: TxKind::Call(ACCOUNT_KEYCHAIN_ADDRESS),
        value: U256::ZERO,
        input: IAccountKeychain::revokeKeyCall {
            keyId: keys[2].address(),
        }
        .abi_encode()
        .into(),
    };
    let tx = f.primitive(7, vec![revoke]);
    assert!(f.run(&tx).is_success());
    grant_key(&mut f, 8, &keys[3], false, 1000);
    f.evm.ctx_mut().block.timestamp = U256::from(2000);
    // A used 2D nonce lane; the nonce manager needs its precompile account to persist.
    StorageCtx::enter_ctx(f.evm.ctx_mut(), StorageActions::disabled(), || {
        NonceManager::new().initialize()
    })
    .unwrap();
    let state = f.evm.ctx_mut().journaled_state.finalize();
    f.evm.db_mut().commit(state);
    let lane = U256::from(5);
    let tx = f.sign_primitive(TempoTransaction {
        nonce_key: lane,
        ..aa_tx(0, vec![f.getter()])
    });
    assert!(f.run(&tx).is_success());

    let snapshot = |f: &mut Fixture| {
        StorageCtx::enter_ctx(f.evm.ctx_mut(), StorageActions::disabled(), || {
            let token = TIP20Token::from_address(PATH_USD_ADDRESS)?;
            let keychain = AccountKeychain::new();
            Ok::<_, TempoPrecompileError>((
                token.balance_of(ITIP20::balanceOfCall { account })?,
                token.allowance(ITIP20::allowanceCall {
                    owner: account,
                    spender,
                })?,
                keys.iter()
                    .map(|key| {
                        keychain.get_key(IAccountKeychain::getKeyCall {
                            account,
                            keyId: key.address(),
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                NonceManager::new().get_nonce(INonce::getNonceCall {
                    account,
                    nonceKey: lane,
                })?,
            ))
        })
        .unwrap()
    };
    let before = snapshot(&mut f);
    assert_eq!(before.1, U256::from(77));
    assert_eq!(before.3, 1);

    let config = f.upgraded(1, owner_set(vec![signer(2).address()]));
    let tx = f.primitive(9, vec![Fixture::upgrade(&config)]);
    let result = f.run(&tx);
    assert_upgraded(&mut f, &result, &config);
    assert_eq!(snapshot(&mut f), before);
    assert_eq!(f.evm.db_mut().basic(account).unwrap().unwrap().nonce, 10);

    // The admin key still cannot rotate the migrated account or migrate it again.
    let next = MultisigConfig {
        version: 2,
        ..config.clone()
    };
    for (nonce, call, error) in [
        (
            10,
            Fixture::rotation(&config, &next),
            INativeMultisig::UnauthorizedMultisigCaller {}.abi_encode(),
        ),
        (
            11,
            Fixture::upgrade(&config),
            INativeMultisig::PrimitiveRootRequired {}.abi_encode(),
        ),
    ] {
        let tx = keychain_tx(&f, &keys[1], nonce, vec![call]);
        let result = f.run(&tx);
        assert_eq!(result.output().unwrap().as_ref(), error);
    }
    assert_eq!(f.commitment(), config.commitment().unwrap());
}

#[test]
fn eoa_migration_then_multisig_and_rotation() {
    let mut f = Fixture::with_parent(false);
    let config = f.upgraded(1, owner_set(vec![f.owner.address()]));
    let tx = f.primitive(3, vec![Fixture::upgrade(&config)]);
    let result = f.run(&tx);
    assert_upgraded(&mut f, &result, &config);

    // The next transaction's witness uses the event's salt at version 1.
    f.config = config.clone();
    let tx = f.signed(4, vec![f.getter()]);
    let result = f.run(&tx);
    assert_eq!(
        INativeMultisig::getConfigCommitmentCall::abi_decode_returns(result.output().unwrap())
            .unwrap(),
        config.commitment().unwrap()
    );

    // Version 1 rotates to version 2 with a new owner.
    let next_owner = signer(2);
    let next = MultisigConfig {
        version: 2,
        owners: owner_set(vec![next_owner.address()]),
        ..config.clone()
    };
    let tx = f.signed(5, vec![Fixture::rotation(&config, &next), f.getter()]);
    let result = f.run(&tx);
    assert!(result.is_success(), "{result:?}");
    assert_eq!(result.logs().len(), 1);
    assert_eq!(f.commitment(), next.commitment().unwrap());

    let stale = f.signed(6, vec![f.getter()]);
    let error = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&stale, f.account))
        .unwrap_err();
    assert!(
        matches!(
            error,
            EVMError::Transaction(TempoInvalidTransaction::NativeMultisig(
                NativeMultisigError::ConfigurationCommitmentMismatch { .. }
            ))
        ),
        "{error}"
    );
    f.config = next;
    f.owner = next_owner;
    let tx = f.signed(6, vec![f.getter()]);
    assert!(f.run(&tx).is_success());
}

#[test]
fn eoa_migration_inactive_before_t14() {
    let mut f = Fixture::with_spec(false, TempoHardfork::T13);
    let config = f.upgraded(1, owner_set(vec![signer(2).address()]));
    for (nonce, kind) in [(3, RootTx::Legacy), (4, RootTx::Aa)] {
        // The call reaches an empty account: it succeeds without state or logs.
        let tx = root_tx(&f, kind, nonce, Fixture::upgrade(&config));
        let result = f.run(&tx);
        assert!(result.is_success(), "{kind:?}: {result:?}");
        assert!(result.output().unwrap().is_empty(), "{kind:?}");
        assert!(result.logs().is_empty(), "{kind:?}");
        assert_eq!(f.commitment(), B256::ZERO, "{kind:?}");
        assert_eq!(
            f.evm.db_mut().basic(f.account).unwrap().unwrap().nonce,
            nonce + 1
        );
    }
}

/// Commits a nonzero configuration commitment for `account`, as a migration or a native
/// registration would, keeping its other fields.
fn retire(f: &mut Fixture, account: Address) {
    let info = f
        .evm
        .db_mut()
        .basic(account)
        .unwrap()
        .unwrap_or_else(|| AccountInfo::from_balance(U256::ZERO));
    f.evm.db_mut().insert_account(
        account,
        info.with_extension(encode_config_commitment(B256::repeat_byte(0x77))),
    );
}

/// Migrates the fixture's account for real, to a configuration owned by `owner`.
fn migrate(f: &mut Fixture, nonce: u64, owner: Address) -> MultisigConfig {
    let config = f.upgraded(1, owner_set(vec![owner]));
    let tx = f.primitive(nonce, vec![Fixture::upgrade(&config)]);
    let result = f.run(&tx);
    assert_upgraded(f, &result, &config);
    config
}

/// The environment of `tx` sent by `sender`, optionally as a plain RPC simulation request.
fn env_of<T>(tx: &T, sender: Address, simulation: bool) -> TempoTxEnv
where
    TempoTxEnv: FromRecoveredTx<T>,
{
    let mut env = TempoTxEnv::from_recovered_tx(tx, sender);
    if simulation {
        env.execution_context = ExecutionContext::Simulation;
    }
    env
}

/// The validation error `tx` fails with when sent by `sender`.
fn rejection<T>(f: &mut Fixture, tx: &T, sender: Address) -> TempoInvalidTransaction
where
    TempoTxEnv: FromRecoveredTx<T>,
{
    match f.evm.transact(env_of(tx, sender, false)) {
        Err(EVMError::Transaction(error)) => error,
        other => panic!("expected a validation error, got {other:?}"),
    }
}

fn retired(account: Address, role: RootKeyRole) -> TempoInvalidTransaction {
    TempoInvalidTransaction::RootKeyRetired { account, role }
}

/// Signs `tx` as the account's native multisig, with the fixture's current configuration.
fn multisig_signed(f: &Fixture, tx: TempoTransaction) -> AASigned {
    let digest = multisig_digest(tx.signature_hash(), f.account, f.config.version);
    let signature = MultisigSignature::try_new(
        f.account,
        f.config.clone(),
        vec![PrimitiveSignature::Secp256k1(
            f.owner.sign_hash_sync(&digest).unwrap(),
        )],
    )
    .unwrap();
    tx.into_signed(TempoSignature::Multisig(signature))
}

/// `tx` with `payer` as its fee payer, for sender `sender`.
fn sponsored(
    mut tx: TempoTransaction,
    payer: &PrivateKeySigner,
    sender: Address,
) -> TempoTransaction {
    tx.fee_payer_signature = Some(
        payer
            .sign_hash_sync(&tx.fee_payer_signature_hash(sender))
            .unwrap(),
    );
    tx
}

/// `tx` signed by the access key `key` on behalf of `parent`.
fn keychain_signed(tx: TempoTransaction, key: &PrivateKeySigner, parent: Address) -> AASigned {
    let signature = key
        .sign_hash_sync(&KeychainSignature::signing_hash(
            tx.signature_hash(),
            parent,
        ))
        .unwrap();
    tx.into_signed(TempoSignature::Keychain(KeychainSignature::new(
        parent,
        PrimitiveSignature::Secp256k1(signature),
    )))
}

/// A grant of `key` for the account, signed by `signer` (a primitive root or admin key).
fn grant_by(signer: &PrivateKeySigner, key: Address) -> SignedKeyAuthorization {
    let grant = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key);
    let signature = signer.sign_hash_sync(&grant.signature_hash()).unwrap();
    grant.into_signed(signature)
}

#[test]
fn retired_root_rejects_sender_signatures() {
    let other = signer(2).address();
    // A P256 and a WebAuthn signature are primitive too; only their type reaches validation.
    let p256 = PrimitiveSignature::from_bytes(&[&[0x01u8][..], &[0x11; 129][..]].concat()).unwrap();
    let webauthn =
        PrimitiveSignature::from_bytes(&[&[0x02u8][..], &[0x22; 37 + 20 + 128][..]].concat())
            .unwrap();
    for kind in [RootTx::Legacy, RootTx::Eip2930, RootTx::Eip1559, RootTx::Aa] {
        let mut f = Fixture::with_parent(false);
        // Before the migration the same signatures are accepted.
        let tx = root_tx(&f, kind, 3, f.getter());
        let result = f.run(&tx);
        assert!(result.is_success(), "{kind:?}: {result:?}");
        migrate(&mut f, 4, other);
        let account = f.account;

        let tx = root_tx(&f, kind, 5, f.getter());
        let error = rejection(&mut f, &tx, account);
        assert_eq!(error, retired(account, RootKeyRole::Sender), "{kind:?}");
        assert!(!error.is_bad_transaction(), "{kind:?}");
        // A repeated migration is a root-signed transaction like any other.
        let again = f.upgraded(1, owner_set(vec![signer(3).address()]));
        let tx = root_tx(&f, kind, 5, Fixture::upgrade(&again));
        assert_eq!(
            rejection(&mut f, &tx, account),
            retired(account, RootKeyRole::Sender),
            "{kind:?}"
        );
        assert_eq!(
            f.commitment(),
            f.upgraded(1, owner_set(vec![other])).commitment().unwrap()
        );
        assert_eq!(f.evm.db_mut().basic(account).unwrap().unwrap().nonce, 5);
    }

    let mut f = Fixture::with_parent(false);
    migrate(&mut f, 3, other);
    let account = f.account;
    let expected = retired(account, RootKeyRole::Sender);
    // EIP-7702, a 2D nonce lane, and the other primitive signature types.
    let tx = type4(
        &f,
        4,
        other,
        Bytes::new(),
        vec![authorization(&f.owner, other, 5)],
    );
    assert_eq!(rejection(&mut f, &tx, account), expected);
    let lane = TempoTransaction {
        nonce_key: U256::ONE,
        ..aa_tx(0, vec![f.getter()])
    };
    let tx = f.sign_primitive(lane);
    assert_eq!(rejection(&mut f, &tx, account), expected);
    for signature in [p256, webauthn] {
        let tx = aa_tx(4, vec![f.getter()]).into_signed(TempoSignature::Primitive(signature));
        assert_eq!(rejection(&mut f, &tx, account), expected);
    }

    // A plain RPC simulation does not check the sender.
    let tx = f.primitive(4, vec![f.getter()]);
    let output = f.evm.transact(env_of(&tx, account, true)).unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    // A request of unspecified origin is not a simulation: the sender is checked.
    let mut env = env_of(&tx, account, false);
    env.execution_context = ExecutionContext::Unspecified;
    let error = f.evm.transact(env).unwrap_err();
    assert!(
        matches!(error, EVMError::Transaction(ref error) if *error == expected),
        "{error:?}"
    );

    // The retirement starts at T14: the same state is accepted before it.
    let mut before = Fixture::with_spec(false, TempoHardfork::T13);
    let account = before.account;
    retire(&mut before, account);
    let tx = before.primitive(3, vec![before.getter()]);
    let result = before.run(&tx);
    assert!(result.is_success(), "{result:?}");
}

#[test]
fn retired_root_rejects_delegated_roles() {
    let new_key = signer(7);
    let other = signer(2).address();

    // G22 (a): the bootstrap flow, a root-signed grant used by the new key in the same
    // transaction, is accepted before the migration and rejected after it.
    for migrated in [false, true] {
        let mut f = Fixture::with_parent(false);
        if migrated {
            migrate(&mut f, 3, other);
        }
        let nonce = if migrated { 4 } else { 3 };
        let account = f.account;
        let tx = TempoTransaction {
            key_authorization: Some(grant_by(&f.owner, new_key.address())),
            ..aa_tx(nonce, vec![f.getter()])
        };
        let tx = keychain_signed(tx, &new_key, account);
        if migrated {
            assert_eq!(
                rejection(&mut f, &tx, account),
                retired(account, RootKeyRole::KeyAuthorizationSigner)
            );
        } else {
            let result = f.run(&tx);
            assert!(result.is_success(), "{result:?}");
        }
    }

    // G22 (b): a native transaction of the migrated account may not carry a grant signed by its
    // retired root; the multisig-signed grant is accepted (see the guard test).
    let mut f = Fixture::with_parent(false);
    let root = f.owner.address();
    f.config = migrate(&mut f, 3, root);
    let account = f.account;
    let tx = TempoTransaction {
        key_authorization: Some(grant_by(&f.owner, new_key.address())),
        ..aa_tx(4, vec![f.getter()])
    };
    let tx = multisig_signed(&f, tx);
    assert_eq!(
        rejection(&mut f, &tx, account),
        retired(account, RootKeyRole::KeyAuthorizationSigner)
    );

    // G22 (c) and G21: an admin access key that migrated can neither sign a grant nor sign
    // transactions; its parent is not affected.
    let mut f = Fixture::with_parent(false);
    let admin = signer(4);
    grant_key(&mut f, 3, &admin, true, 0);
    let account = f.account;
    let admin_grant = |f: &Fixture| {
        let grant = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, new_key.address())
            .with_account(f.account);
        let signature = admin.sign_hash_sync(&grant.signature_hash()).unwrap();
        grant.into_signed(signature)
    };
    let tx = TempoTransaction {
        key_authorization: Some(admin_grant(&f)),
        ..aa_tx(4, vec![f.getter()])
    };
    let tx = keychain_signed(tx, &admin, account);
    // Control: the admin key still works while it has no commitment.
    let output = f.evm.transact(env_of(&tx, account, false)).unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    retire(&mut f, admin.address());
    assert_eq!(
        rejection(&mut f, &tx, account),
        retired(admin.address(), RootKeyRole::KeyAuthorizationSigner)
    );
    let tx = keychain_signed(aa_tx(4, vec![f.getter()]), &admin, account);
    assert_eq!(
        rejection(&mut f, &tx, account),
        retired(admin.address(), RootKeyRole::AccessKey)
    );

    // G20: a sponsor that migrates after signing can no longer pay, even for a transaction
    // it signed earlier.
    let mut f = Fixture::with_parent(false);
    let sponsor = signer(5);
    let account = f.account;
    let tx = sponsored(aa_tx(3, vec![f.getter()]), &sponsor, account);
    let tx = f.sign_primitive(tx);
    let output = f.evm.transact(env_of(&tx, account, false)).unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    retire(&mut f, sponsor.address());
    assert_eq!(
        rejection(&mut f, &tx, account),
        retired(sponsor.address(), RootKeyRole::FeePayer)
    );
    // Simulation checks every role but the sender.
    let error = f.evm.transact(env_of(&tx, account, true)).unwrap_err();
    assert!(
        matches!(
            error,
            EVMError::Transaction(ref error)
                if *error == retired(sponsor.address(), RootKeyRole::FeePayer)
        ),
        "{error:?}"
    );

    // G21, G47 and G49: the treasury granted the primitive key B, then B migrates.
    let mut f = Fixture::with_parent(false);
    let key = signer(6);
    grant_key(&mut f, 3, &key, false, 0);
    let account = f.account;
    let tx = keychain_tx(&f, &key, 4, vec![f.getter()]);
    let output = f.evm.transact(env_of(&tx, account, false)).unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    retire(&mut f, key.address());
    let expected = retired(key.address(), RootKeyRole::AccessKey);
    assert_eq!(rejection(&mut f, &tx, account), expected);
    // Simulation replaces the recovered key ID with the request's override.
    let mut env = env_of(&tx, account, true);
    env.tempo_tx_env.as_mut().unwrap().override_key_id = Some(key.address());
    let error = f.evm.transact(env).unwrap_err();
    assert!(
        matches!(error, EVMError::Transaction(ref error) if *error == expected),
        "{error:?}"
    );
    // The override also names the key when another key signed the request.
    let placeholder = keychain_tx(&f, &signer(7), 4, vec![f.getter()]);
    let mut env = env_of(&placeholder, account, true);
    env.tempo_tx_env.as_mut().unwrap().override_key_id = Some(key.address());
    let error = f.evm.transact(env).unwrap_err();
    assert!(
        matches!(error, EVMError::Transaction(ref error) if *error == expected),
        "{error:?}"
    );
    // The treasury cannot register the retired key ID again: the grant is rejected as a reuse.
    let regrant = f.sign_primitive(TempoTransaction {
        key_authorization: Some(grant_by(&f.owner, key.address())),
        ..aa_tx(4, vec![f.getter()])
    });
    assert_eq!(
        rejection(&mut f, &regrant, account),
        TempoInvalidTransaction::KeychainPrecompileError {
            reason: TempoPrecompileError::from(AccountKeychainError::key_already_exists())
                .to_string()
        }
    );
}

#[test]
fn retired_root_keeps_owner_parent_and_sender_authority() {
    // G23: what stays valid for a migrated account X.
    let mut f = Fixture::with_parent(false);
    let old_key = signer(2);
    grant_key(&mut f, 3, &old_key, false, 0);
    // X lists its retired root as the owner of its new configuration (G24).
    let root = f.owner.address();
    f.config = migrate(&mut f, 4, root);
    let account = f.account;
    fund(&mut f, account, 50_000_000);
    let transfer = Call {
        to: TxKind::Call(PATH_USD_ADDRESS),
        value: U256::ZERO,
        input: ITIP20::transferCall {
            to: Address::repeat_byte(0x66),
            amount: U256::from(10),
        }
        .abi_encode()
        .into(),
    };
    let revoke = Call {
        to: TxKind::Call(ACCOUNT_KEYCHAIN_ADDRESS),
        value: U256::ZERO,
        input: IAccountKeychain::revokeKeyCall {
            keyId: old_key.address(),
        }
        .abi_encode()
        .into(),
    };

    // X's old uncommitted access key still signs for X.
    let tx = keychain_tx(&f, &old_key, 5, vec![f.getter()]);
    let result = f.run(&tx);
    assert!(result.is_success(), "{result:?}");

    // X pays its own fees in a multisig transaction, and its calls authenticate as X.
    let before = balance(&mut f, account);
    let tx = multisig_signed(
        &f,
        TempoTransaction {
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            fee_token: Some(PATH_USD_ADDRESS),
            ..aa_tx(6, vec![transfer])
        },
    );
    let result = f.run(&tx);
    assert!(result.is_success(), "{result:?}");
    let fee = calc_gas_balance_spending(result.tx_gas_used(), 1);
    assert!(fee > U256::ZERO);
    assert_eq!(
        balance(&mut f, account),
        before - fee - U256::from(10),
        "the transfer and the fee both come from X"
    );
    // Root-level keychain administration (no access key) is still X's to use.
    let tx = multisig_signed(&f, aa_tx(7, vec![revoke]));
    let result = f.run(&tx);
    assert!(result.is_success(), "{result:?}");
    let tx = keychain_tx(&f, &old_key, 8, vec![f.getter()]);
    // The revocation took effect: the keychain, not the retirement, now rejects the key.
    assert!(matches!(
        rejection(&mut f, &tx, account),
        TempoInvalidTransaction::KeychainValidationFailed { .. }
    ));

    // A multisig-signed grant is accepted: the grant's signature is not a primitive root.
    let grant = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, signer(8).address());
    let grant_signature = AccountSignature::Multisig(
        MultisigSignature::try_new(
            account,
            f.config.clone(),
            vec![PrimitiveSignature::Secp256k1(
                f.owner
                    .sign_hash_sync(&multisig_digest(
                        grant.signature_hash(),
                        account,
                        f.config.version,
                    ))
                    .unwrap(),
            )],
        )
        .unwrap(),
    );
    let tx = multisig_signed(
        &f,
        TempoTransaction {
            key_authorization: Some(grant.into_signed(grant_signature)),
            ..aa_tx(8, vec![f.getter()])
        },
    );
    let result = f.run(&tx);
    assert!(result.is_success(), "{result:?}");

    // G24: another multisig M that lists the retired X accepts X's approval.
    let mut m = Fixture::new();
    let owner = m.owner.address();
    retire(&mut m, owner);
    let tx = m.signed(3, vec![m.getter()]);
    let result = m.run(&tx);
    assert!(result.is_success(), "{result:?}");
}

/// Gas used by `tx` at `spec` on a fresh unmigrated fixture with the access key `key` granted.
fn gas_at(
    spec: TempoHardfork,
    key: &PrivateKeySigner,
    tx: impl FnOnce(&Fixture) -> AASigned,
) -> u64 {
    let mut f = Fixture::with_spec(false, spec);
    grant_key(&mut f, 3, key, false, 0);
    let tx = tx(&f);
    let result = f.run(&tx);
    assert!(result.is_success(), "{spec:?}: {result:?}");
    // Before the minimum-gas floor, which hides small differences.
    result.gas().total_gas_spent()
}

#[test]
fn retired_root_error_order_and_access_gas() {
    let (signer_s, payer, key) = (signer(4), signer(5), signer(6));
    let mut f = Fixture::with_parent(false);
    let account = f.account;
    // Every role names a retired account: the sender, the grant signer, the fee payer, and the
    // access key.
    for address in [account, signer_s.address(), payer.address(), key.address()] {
        retire(&mut f, address);
    }
    let target = signer(7).address();
    // A root-signed grant for a root-signed transaction; an admin-signed grant must travel with
    // its own admin key.
    let root_grant = grant_by(&f.owner, target);
    let admin_grant = {
        let grant = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, target)
            .with_account(account);
        let signature = signer_s.sign_hash_sync(&grant.signature_hash()).unwrap();
        grant.into_signed(signature)
    };
    let sponsor = |tx: TempoTransaction| sponsored(tx, &payer, account);

    // Sender, then key authorization signer, then fee payer, then access key.
    let tx = f.sign_primitive(sponsor(TempoTransaction {
        key_authorization: Some(root_grant.clone()),
        ..aa_tx(3, vec![f.getter()])
    }));
    assert_eq!(
        rejection(&mut f, &tx, account),
        retired(account, RootKeyRole::Sender)
    );
    let tx = keychain_signed(
        sponsor(TempoTransaction {
            key_authorization: Some(admin_grant),
            ..aa_tx(3, vec![f.getter()])
        }),
        &signer_s,
        account,
    );
    assert_eq!(
        rejection(&mut f, &tx, account),
        retired(signer_s.address(), RootKeyRole::KeyAuthorizationSigner)
    );
    let tx = keychain_signed(sponsor(aa_tx(3, vec![f.getter()])), &key, account);
    assert_eq!(
        rejection(&mut f, &tx, account),
        retired(payer.address(), RootKeyRole::FeePayer)
    );
    let tx = keychain_signed(aa_tx(3, vec![f.getter()]), &key, account);
    assert_eq!(
        rejection(&mut f, &tx, account),
        retired(key.address(), RootKeyRole::AccessKey)
    );

    // Request validation comes first: the sponsor may not be the sender.
    let tx = f.sign_primitive(sponsored(aa_tx(3, vec![f.getter()]), &f.owner, account));
    assert_eq!(
        rejection(&mut f, &tx, account),
        TempoInvalidTransaction::SelfSponsoredFeePayer
    );
    // Native role errors come next: the stored commitment is not the witness's configuration.
    let witness_owner = signer(2);
    let witness_config = f.upgraded(1, owner_set(vec![witness_owner.address()]));
    let native_tx = TempoTransaction {
        key_authorization: Some(root_grant),
        ..aa_tx(3, vec![f.getter()])
    };
    let digest = multisig_digest(native_tx.signature_hash(), account, witness_config.version);
    let witness = MultisigSignature::try_new(
        account,
        witness_config,
        vec![PrimitiveSignature::Secp256k1(
            witness_owner.sign_hash_sync(&digest).unwrap(),
        )],
    )
    .unwrap();
    let tx = native_tx.into_signed(TempoSignature::Multisig(witness));
    assert!(matches!(
        rejection(&mut f, &tx, account),
        TempoInvalidTransaction::NativeMultisig(
            NativeMultisigError::ConfigurationCommitmentMismatch { .. }
        )
    ));
    // Nonce, intrinsic gas and balance errors come after, with or without a commitment.
    let mut fresh = Fixture::with_parent(false);
    let mut fresh_rejection = |label: &str, edit: fn(&mut TempoTransaction)| {
        let mut tx = aa_tx(3, vec![f.getter()]);
        edit(&mut tx);
        let signed = f.sign_primitive(tx);
        assert_eq!(
            rejection(&mut f, &signed, account),
            retired(account, RootKeyRole::Sender),
            "{label}"
        );
        rejection(&mut fresh, &signed, account)
    };
    assert_eq!(
        fresh_rejection("nonce", |tx| tx.nonce = 99),
        TempoInvalidTransaction::EthInvalidTransaction(InvalidTransaction::NonceTooHigh {
            tx: 99,
            state: 3
        })
    );
    let error = fresh_rejection("intrinsic gas", |tx| tx.gas_limit = 1);
    assert!(
        matches!(
            error,
            TempoInvalidTransaction::EthInvalidTransaction(
                InvalidTransaction::CallGasCostMoreThanGasLimit { gas_limit: 1, .. }
            )
        ),
        "{error:?}"
    );
    assert_eq!(
        fresh_rejection("balance", |tx| {
            tx.max_fee_per_gas = 1_000_000_000_000;
            tx.fee_token = Some(PATH_USD_ADDRESS);
        }),
        TempoInvalidTransaction::EthInvalidTransaction(InvalidTransaction::LackOfFundForMaxFee {
            fee: Box::new(calc_gas_balance_spending(1_000_000, 1_000_000_000_000)),
            balance: Box::new(U256::ZERO),
        })
    );

    // Gas: each distinct non-caller role account is charged one account access from T14.
    let params = tempo_gas_params(TempoHardfork::T14);
    let warm = params.warm_storage_read_cost();
    let cold = warm + params.cold_account_additional_cost();
    let other = signer(8);
    let delta = |tx: &dyn Fn(&Fixture) -> AASigned| {
        gas_at(TempoHardfork::T14, &key, tx) - gas_at(TempoHardfork::T13, &key, tx)
    };
    let listed = AccessList(vec![AccessListItem {
        address: payer.address(),
        storage_keys: Vec::new(),
    }]);
    // T14 prices every transaction a little differently, with or without role checks; the
    // role charges are measured on top of a plain transaction.
    let base = delta(&|f| f.primitive(4, vec![f.getter()]));
    // The caller is free, even as the grant signer.
    let grant_tx = |f: &Fixture| {
        let grant = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, other.address());
        let signature = f.owner.sign_hash_sync(&grant.signature_hash()).unwrap();
        f.sign_primitive(TempoTransaction {
            key_authorization: Some(grant.into_signed(signature)),
            ..aa_tx(4, vec![f.getter()])
        })
    };
    assert_eq!(delta(&grant_tx), base);
    // A cold fee payer costs a cold access, an access-listed one a warm access.
    let paid = |f: &Fixture, payer: &PrivateKeySigner, list: &AccessList| {
        f.sign_primitive(sponsored(
            TempoTransaction {
                access_list: list.clone(),
                ..aa_tx(4, vec![f.getter()])
            },
            payer,
            f.account,
        ))
    };
    assert_eq!(
        delta(&|f| paid(f, &payer, &AccessList(Vec::new()))),
        base + cold
    );
    assert_eq!(delta(&|f| paid(f, &payer, &listed)), base + warm);
    // The access key and the fee payer are one account here: one access, not two.
    let keyed = |f: &Fixture, payer: &PrivateKeySigner| {
        keychain_signed(
            sponsored(aa_tx(4, vec![f.getter()]), payer, f.account),
            &key,
            f.account,
        )
    };
    assert_eq!(delta(&|f| keyed(f, &key)), base + cold);
    assert_eq!(delta(&|f| keyed(f, &payer)), base + 2 * cold);
    // An access-listed access key costs a warm access.
    let key_listed = AccessList(vec![AccessListItem {
        address: key.address(),
        storage_keys: Vec::new(),
    }]);
    assert_eq!(
        delta(&|f| keychain_signed(
            TempoTransaction {
                access_list: key_listed.clone(),
                ..aa_tx(4, vec![f.getter()])
            },
            &key,
            f.account
        )),
        base + warm
    );
    // A multisig grant to the fee payer adds nothing to the fee payer's access; one to another
    // account adds a cold access. The delegate charge exists only at T14, so the two transactions
    // are compared at T14.
    let delegated = |delegate: Address| {
        gas_at(TempoHardfork::T14, &key, |f| {
            let grant = KeyAuthorization::unrestricted(1, SignatureType::Multisig, delegate);
            let signature = f.owner.sign_hash_sync(&grant.signature_hash()).unwrap();
            f.sign_primitive(sponsored(
                TempoTransaction {
                    key_authorization: Some(grant.into_signed(signature)),
                    ..aa_tx(4, vec![f.getter()])
                },
                &payer,
                f.account,
            ))
        })
    };
    assert_eq!(
        delegated(other.address()) - delegated(payer.address()),
        cold
    );
}

#[derive(Clone, Copy, Debug)]
enum SigKind {
    Secp256k1,
    P256,
    WebAuthn,
    /// The secp256k1 key signing as an access key of its own address, which it names as the
    /// authority.
    Keychain,
}

/// One authorization-list entry: the authority is derived from `kind` and `seed`.
#[derive(Clone, Copy, Debug)]
struct Entry {
    kind: SigKind,
    seed: u8,
    chain_id: u64,
    target: Address,
    nonce: u64,
}

impl Entry {
    fn new(kind: SigKind, seed: u8, target: Address, nonce: u64) -> Self {
        Self {
            kind,
            seed,
            chain_id: 1,
            target,
            nonce,
        }
    }

    fn authorization(&self) -> Authorization {
        Authorization {
            chain_id: U256::from(self.chain_id),
            address: self.target,
            nonce: self.nonce,
        }
    }

    fn address(&self) -> Address {
        self.sign().0
    }

    /// The authority and the entry signed by it with its own key type.
    fn sign(&self) -> (Address, TempoSignedAuthorization) {
        let authorization = self.authorization();
        let hash = authorization.signature_hash();
        let (address, signature) = match self.kind {
            SigKind::Secp256k1 => {
                let key = signer(self.seed);
                let signature = key.sign_hash_sync(&hash).unwrap();
                (key.address(), TempoSignature::from(signature))
            }
            SigKind::Keychain => {
                let key = signer(self.seed);
                let signature = key
                    .sign_hash_sync(&KeychainSignature::signing_hash(hash, key.address()))
                    .unwrap();
                (
                    key.address(),
                    TempoSignature::Keychain(KeychainSignature::new(
                        key.address(),
                        PrimitiveSignature::Secp256k1(signature),
                    )),
                )
            }
            SigKind::P256 | SigKind::WebAuthn => {
                let key = SigningKey::from_slice(&[self.seed; 32]).unwrap();
                let point = key.verifying_key().to_encoded_point(false);
                let pub_key_x = B256::from_slice(point.x().unwrap());
                let pub_key_y = B256::from_slice(point.y().unwrap());
                let primitive = if matches!(self.kind, SigKind::P256) {
                    let signature: p256::ecdsa::Signature =
                        key.sign_prehash(&Sha256::digest(hash)).unwrap();
                    let bytes = signature.to_bytes();
                    PrimitiveSignature::P256(P256SignatureWithPreHash {
                        r: B256::from_slice(&bytes[..32]),
                        s: normalize_p256_s(&bytes[32..]).unwrap(),
                        pub_key_x,
                        pub_key_y,
                        pre_hash: true,
                    })
                } else {
                    let mut authenticator_data = vec![0u8; 37];
                    authenticator_data[..32].copy_from_slice(&[0xAA; 32]);
                    authenticator_data[32] = 0x01;
                    let client_data = format!(
                        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://tempo.xyz","crossOrigin":false}}"#,
                        URL_SAFE_NO_PAD.encode(hash)
                    );
                    let mut message = Sha256::new();
                    message.update(&authenticator_data);
                    message.update(Sha256::digest(client_data.as_bytes()));
                    let signature: p256::ecdsa::Signature =
                        key.sign_prehash(&message.finalize()).unwrap();
                    let bytes = signature.to_bytes();
                    authenticator_data.extend_from_slice(client_data.as_bytes());
                    PrimitiveSignature::WebAuthn(WebAuthnSignature {
                        webauthn_data: authenticator_data.into(),
                        r: B256::from_slice(&bytes[..32]),
                        s: normalize_p256_s(&bytes[32..]).unwrap(),
                        pub_key_x,
                        pub_key_y,
                    })
                };
                (
                    derive_p256_address(&pub_key_x, &pub_key_y),
                    TempoSignature::Primitive(primitive),
                )
            }
        };
        (
            address,
            TempoSignedAuthorization::new_unchecked(authorization, signature),
        )
    }

    /// The entry as an EIP-7702 authorization, which only a secp256k1 authority can sign.
    fn legacy(&self) -> SignedAuthorization {
        assert!(matches!(self.kind, SigKind::Secp256k1), "{self:?}");
        let authorization = self.authorization();
        let signature = signer(self.seed)
            .sign_hash_sync(&authorization.signature_hash())
            .unwrap();
        authorization.into_signed(signature)
    }
}

/// A transaction sent by `sender` (nonce 0) that calls `to` and carries `entries`, as an
/// EIP-7702 transaction or as an AA transaction's `tempo_authorization_list`.
fn listed_tx(
    sender: &PrivateKeySigner,
    aa: bool,
    to: Address,
    entries: &[Entry],
) -> TempoTxEnvelope {
    if aa {
        let tx = TempoTransaction {
            tempo_authorization_list: entries.iter().map(|entry| entry.sign().1).collect(),
            ..aa_tx(
                0,
                vec![Call {
                    to: TxKind::Call(to),
                    value: U256::ZERO,
                    input: Bytes::new(),
                }],
            )
        };
        let signature = sender.sign_hash_sync(&tx.signature_hash()).unwrap();
        TempoTxEnvelope::AA(tx.into_signed(signature.into()))
    } else {
        let tx = TxEip7702 {
            chain_id: 1,
            nonce: 0,
            gas_limit: 1_000_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            to,
            value: U256::ZERO,
            access_list: AccessList(Vec::new()),
            authorization_list: entries.iter().map(Entry::legacy).collect(),
            input: Bytes::new(),
        };
        let signature = sender.sign_hash_sync(&tx.signature_hash()).unwrap();
        TempoTxEnvelope::Eip7702(tx.into_signed(signature))
    }
}

/// Seeds `address` as an existing account without code at `nonce`.
fn seed_eoa(f: &mut Fixture, address: Address, nonce: u64) {
    f.evm.db_mut().insert_account(
        address,
        AccountInfo {
            nonce,
            ..AccountInfo::from_balance(U256::from(1))
        },
    );
}

/// The nonce, the 7702 delegation target (`None` without code) and whether the account's
/// configuration commitment is set.
fn account_state(f: &mut Fixture, address: Address) -> (u64, Option<Address>, bool) {
    let info = f
        .evm
        .db_mut()
        .basic(address)
        .unwrap()
        .unwrap_or_else(|| AccountInfo::from_balance(U256::ZERO));
    let delegation = (info.code_hash != KECCAK256_EMPTY).then(|| {
        let code = info
            .code
            .clone()
            .unwrap_or_else(|| f.evm.db_mut().code_by_hash(info.code_hash).unwrap());
        let bytes = code.original_bytes();
        assert_eq!(bytes[..3], [0xef, 0x01, 0x00], "{bytes:?}");
        Address::from_slice(&bytes[3..])
    });
    let retired = !decode_config_commitment(&info.extension, true)
        .unwrap()
        .is_zero();
    (info.nonce, delegation, retired)
}

/// A call target that touches `account`'s code size: its gas shows whether the account is warm.
const PROBE: Address = Address::repeat_byte(0x99);

fn probe(f: &mut Fixture, account: Address) {
    f.install_contract(
        PROBE,
        [&[0x73u8][..], account.as_slice(), &[0x3b, 0x50, 0x00]].concat(),
    );
}

#[test]
fn retired_root_authorization_list_entries_skipped() {
    let target = Address::repeat_byte(0x55);
    let sender = signer(2);
    let existing = Entry::new(SigKind::Secp256k1, 7, target, 2);
    let fresh = Entry::new(SigKind::Secp256k1, 6, target, 0);

    for (aa, kind) in [
        (false, SigKind::Secp256k1),
        (true, SigKind::Secp256k1),
        (true, SigKind::P256),
        (true, SigKind::WebAuthn),
    ] {
        let label = format!("aa {aa}, {kind:?}");
        let x = Entry::new(kind, 9, target, 5);
        let mismatched = Entry { nonce: 6, ..x };
        // Runs the transaction with `entry` for the authority at nonce 5, retired or not.
        let run = |entry: Entry, retire_x: bool| {
            let mut f = Fixture::with_parent(false);
            seed_eoa(&mut f, x.address(), 5);
            seed_eoa(&mut f, existing.address(), 2);
            if retire_x {
                retire(&mut f, x.address());
            }
            probe(&mut f, x.address());
            let tx = listed_tx(&sender, aa, PROBE, &[entry, existing, fresh]);
            let result = f.run_as(sender.address(), &tx);
            assert!(result.is_success(), "{label}: {result:?}");
            (f, result.tx_gas_used())
        };

        let (mut f, skipped_gas) = run(x, true);
        // The retired authority is untouched, the other entries applied.
        assert_eq!(
            account_state(&mut f, x.address()),
            (5, None, true),
            "{label}"
        );
        assert_eq!(
            account_state(&mut f, existing.address()),
            (3, Some(target), false),
            "{label}"
        );
        assert_eq!(
            account_state(&mut f, fresh.address()),
            (1, Some(target), false),
            "{label}"
        );

        // Same gas, warming and refunds as an entry revm itself skips for its nonce.
        let (mut control, mismatched_gas) = run(mismatched, false);
        assert_eq!(
            account_state(&mut control, x.address()),
            (5, None, false),
            "{label}"
        );
        assert_eq!(skipped_gas, mismatched_gas, "{label}");

        // Without the retirement the entry applies. Its gas is the same too: the authorization
        // refund is disabled since T1, so only the warming above is observable.
        let (mut applied, applied_gas) = run(x, false);
        assert_eq!(
            account_state(&mut applied, x.address()),
            (6, Some(target), false),
            "{label}"
        );
        assert_eq!(applied_gas, skipped_gas, "{label}");
    }
}

#[test]
fn retired_root_authorization_list_entries_skipped_after_a_same_block_migration() {
    // TIP-1112: an entry the root key signed before migrating, relayed by a later transaction
    // of the same block, is skipped.
    let target = Address::repeat_byte(0x55);
    let sender = signer(2);
    let fresh = Entry::new(SigKind::Secp256k1, 6, target, 0);
    for aa in [false, true] {
        let mut f = Fixture::with_parent(false);
        let account = f.account;
        // Signed by the fixture's root key for the nonce its migration leaves.
        let entry = Entry::new(SigKind::Secp256k1, 1, target, 4);
        assert_eq!(entry.address(), account);
        let tx = listed_tx(&sender, aa, Address::repeat_byte(0x73), &[entry, fresh]);
        migrate(&mut f, 3, signer(3).address());

        let result = f.run_as(sender.address(), &tx);
        assert!(result.is_success(), "aa {aa}: {result:?}");
        assert_eq!(account_state(&mut f, account), (4, None, true), "aa {aa}");
        assert_eq!(
            account_state(&mut f, fresh.address()),
            (1, Some(target), false),
            "aa {aa}"
        );
    }
}

#[test]
fn retired_root_authorization_list_variants() {
    let target = Address::repeat_byte(0x55);
    let old_target = Address::repeat_byte(0x44);
    let sender = signer(2);
    let fresh = Entry::new(SigKind::Secp256k1, 6, target, 0);
    let x = Entry::new(SigKind::Secp256k1, 9, target, 5);
    let address = x.address();

    // (name, the account's seeded nonce and delegation, the entries before `fresh`).
    let rows: Vec<(&str, u64, Option<Address>, Vec<Entry>)> = vec![
        // A wildcard chain id is loaded by revm like a matching one.
        ("chain id 0", 5, None, vec![Entry { chain_id: 0, ..x }]),
        // An EOA migrated on a 2D nonce lane keeps protocol nonce 0, where its entry would apply.
        ("nonce 0", 0, None, vec![Entry { nonce: 0, ..x }]),
        // Neither an authorization to clear nor one to replace removes the delegation.
        (
            "clear delegation",
            5,
            Some(old_target),
            vec![Entry {
                target: Address::ZERO,
                ..x
            }],
        ),
        (
            "replace delegation",
            5,
            Some(old_target),
            vec![Entry { target, ..x }],
        ),
        // Every entry of the authority is skipped, whatever its nonce.
        (
            "repeated",
            5,
            None,
            vec![x, Entry { nonce: 6, ..x }, Entry { nonce: 5, ..x }],
        ),
    ];
    for aa in [false, true] {
        for (name, nonce, delegation, entries) in &rows {
            let label = format!("aa {aa}, {name}");
            let mut f = Fixture::with_parent(false);
            let mut info = AccountInfo {
                nonce: *nonce,
                ..AccountInfo::from_balance(U256::from(1))
            };
            if let Some(old) = delegation {
                info = info.with_code(Bytecode::new_eip7702(*old));
            }
            f.evm.db_mut().insert_account(address, info);
            retire(&mut f, address);
            let mut entries = entries.clone();
            entries.push(fresh);
            let tx = listed_tx(&sender, aa, Address::repeat_byte(0x73), &entries);
            let result = f.run_as(sender.address(), &tx);
            assert!(result.is_success(), "{label}: {result:?}");
            assert_eq!(
                account_state(&mut f, address),
                (*nonce, *delegation, true),
                "{label}"
            );
            assert_eq!(
                account_state(&mut f, fresh.address()),
                (1, Some(target), false),
                "{label}"
            );
        }
    }
}

#[test]
fn retired_root_address_remains_a_delegation_target() {
    // G30: only the retired authority is skipped; another EOA may delegate to its address.
    let sender = signer(2);
    let x = Entry::new(SigKind::Secp256k1, 9, Address::ZERO, 5).address();
    let other = Entry::new(SigKind::Secp256k1, 6, x, 0);
    for aa in [false, true] {
        let mut f = Fixture::with_parent(false);
        seed_eoa(&mut f, x, 5);
        retire(&mut f, x);
        let tx = listed_tx(&sender, aa, other.address(), &[other]);
        let result = f.run_as(sender.address(), &tx);
        assert!(result.is_success(), "aa {aa}: {result:?}");
        assert_eq!(
            account_state(&mut f, other.address()),
            (1, Some(x), false),
            "aa {aa}"
        );
        assert_eq!(account_state(&mut f, x), (5, None, true), "aa {aa}");
    }
}

#[test]
fn retired_root_authorization_list_entries_apply_before_t14() {
    let target = Address::repeat_byte(0x55);
    let sender = signer(2);
    let x = Entry::new(SigKind::Secp256k1, 9, target, 5);
    for aa in [false, true] {
        let mut f = Fixture::with_spec(false, TempoHardfork::T13);
        seed_eoa(&mut f, x.address(), 5);
        retire(&mut f, x.address());
        let tx = listed_tx(&sender, aa, Address::repeat_byte(0x73), &[x]);
        let result = f.run_as(sender.address(), &tx);
        assert!(result.is_success(), "aa {aa}: {result:?}");
        assert_eq!(
            account_state(&mut f, x.address()),
            (6, Some(target), true),
            "aa {aa}"
        );
    }
}

#[test]
fn authorization_list_gas_is_unchanged_by_the_retired_root_skip() {
    // The skip may only read the authorities revm itself loads: whatever the list holds, T14
    // warms the same accounts and charges the same gas as T13, where nothing is skipped.
    let target = Address::repeat_byte(0x55);
    let sender = signer(2);
    let x = Entry::new(SigKind::Secp256k1, 9, target, 5);
    let rows = [
        ("matching", x),
        ("chain id 0", Entry { chain_id: 0, ..x }),
        ("other chain id", Entry { chain_id: 2, ..x }),
        ("nonce mismatch", Entry { nonce: 6, ..x }),
        (
            "nonce max",
            Entry {
                nonce: u64::MAX,
                ..x
            },
        ),
    ];
    for aa in [false, true] {
        for (name, entry) in rows {
            for retired in [false, true] {
                let label = format!("aa {aa}, {name}, retired {retired}");
                let run = |spec: TempoHardfork| {
                    let mut f = Fixture::with_spec(false, spec);
                    seed_eoa(&mut f, x.address(), 5);
                    if retired {
                        retire(&mut f, x.address());
                    }
                    probe(&mut f, x.address());
                    let tx = listed_tx(&sender, aa, PROBE, &[entry]);
                    let result = f.run_as(sender.address(), &tx);
                    assert!(result.is_success(), "{label}: {result:?}");
                    result.tx_gas_used()
                };
                assert_eq!(run(TempoHardfork::T14), run(TempoHardfork::T13), "{label}");
            }
        }
    }
}

#[test]
fn keychain_authorization_list_entries_stay_skipped() {
    // The T0 filter drops a keychain-signed entry before the retired-root check reads its
    // authority: retired or not, the named account is neither delegated nor warmed, as at T13.
    let sender = signer(2);
    let x = Entry::new(SigKind::Keychain, 9, Address::repeat_byte(0x55), 5);
    for retired in [false, true] {
        let run = |spec: TempoHardfork| {
            let label = format!("{spec:?}, retired {retired}");
            let mut f = Fixture::with_spec(false, spec);
            seed_eoa(&mut f, x.address(), 5);
            if retired {
                retire(&mut f, x.address());
            }
            probe(&mut f, x.address());
            let tx = listed_tx(&sender, true, PROBE, &[x]);
            let result = f.run_as(sender.address(), &tx);
            assert!(result.is_success(), "{label}: {result:?}");
            assert_eq!(
                account_state(&mut f, x.address()),
                (5, None, retired),
                "{label}"
            );
            result.tx_gas_used()
        };
        assert_eq!(
            run(TempoHardfork::T14),
            run(TempoHardfork::T13),
            "retired {retired}"
        );
    }
}

/// Executes `calls` as one AA transaction that `sender` sends at its current nonce.
fn send(f: &mut Fixture, sender: Address, calls: Vec<Call>) -> ExecutionResult<HaltReason> {
    send_listed(f, sender, calls, AccessList(Vec::new()))
}

fn send_listed(
    f: &mut Fixture,
    sender: Address,
    calls: Vec<Call>,
    access_list: AccessList,
) -> ExecutionResult<HaltReason> {
    let nonce = f
        .evm
        .db_mut()
        .basic(sender)
        .unwrap()
        .map_or(0, |info| info.nonce);
    let tx = f.sign_primitive(TempoTransaction {
        access_list,
        ..aa_tx(nonce, calls)
    });
    f.run_as(sender, &tx)
}

/// Asserts that `result` reverted with exactly `error` and logged nothing.
fn assert_reverts_with(result: &ExecutionResult<HaltReason>, error: impl SolError, label: &str) {
    assert!(
        matches!(result, ExecutionResult::Revert { .. }),
        "{label}: {result:?}"
    );
    assert_eq!(
        result.output().unwrap().as_ref(),
        error.abi_encode().as_slice(),
        "{label}"
    );
    assert!(result.logs().is_empty(), "{label}");
}

fn permit_retired(account: Address) -> ITIP20::RootKeyRetired {
    ITIP20::RootKeyRetired { account }
}

fn voucher_retired(account: Address) -> ITIP20ChannelReserve::RootKeyRetired {
    ITIP20ChannelReserve::RootKeyRetired { account }
}

/// A path USD `permit` of `owner` to `spender`, signed by `key` over the token's current nonce.
fn permit_signed(
    f: &mut Fixture,
    owner: Address,
    key: &PrivateKeySigner,
    spender: Address,
    deadline: u64,
) -> Call {
    let (nonce, separator) =
        StorageCtx::enter_ctx(f.evm.ctx_mut(), StorageActions::disabled(), || {
            let token = TIP20Token::from_address(PATH_USD_ADDRESS)?;
            Ok::<_, TempoPrecompileError>((
                token.nonces(ITIP20::noncesCall { owner })?,
                token.domain_separator()?,
            ))
        })
        .unwrap();
    let (value, deadline) = (U256::from(100), U256::from(deadline));
    let struct_hash =
        keccak256((PERMIT_TYPEHASH, owner, spender, value, nonce, deadline).abi_encode());
    let digest = keccak256(
        [
            &[0x19, 0x01][..],
            separator.as_slice(),
            struct_hash.as_slice(),
        ]
        .concat(),
    );
    let signature = key.sign_hash_sync(&digest).unwrap();
    Call {
        to: TxKind::Call(PATH_USD_ADDRESS),
        value: U256::ZERO,
        input: ITIP20::permitCall {
            owner,
            spender,
            value,
            deadline,
            v: 27 + u8::from(signature.v()),
            r: signature.r().into(),
            s: signature.s().into(),
        }
        .abi_encode()
        .into(),
    }
}

/// The permit nonce of `owner` and its path USD allowance for `spender`.
fn permit_state(f: &mut Fixture, owner: Address, spender: Address) -> (U256, U256) {
    StorageCtx::enter_ctx(f.evm.ctx_mut(), StorageActions::disabled(), || {
        let token = TIP20Token::from_address(PATH_USD_ADDRESS)?;
        Ok::<_, TempoPrecompileError>((
            token.nonces(ITIP20::noncesCall { owner })?,
            token.allowance(ITIP20::allowanceCall { owner, spender })?,
        ))
    })
    .unwrap()
}

#[test]
fn retired_root_permit_reverts() {
    let (spender, relayer) = (signer(8).address(), signer(9).address());
    let mut f = Fixture::with_parent(false);
    let x = f.account;
    let old_key = f.owner.clone();

    // Signed while X's root key still works, relayed after it migrated: the attack path.
    let early = permit_signed(&mut f, x, &old_key, spender, 1_000);
    let early_for_x = permit_signed(&mut f, x, &old_key, signer(7).address(), 1_000);
    let config = migrate(&mut f, 3, x);
    assert_eq!(f.commitment(), config.commitment().unwrap());
    let result = send(&mut f, relayer, vec![early]);
    assert_reverts_with(&result, permit_retired(x), "relayed after migration");
    assert_eq!(permit_state(&mut f, x, spender), (U256::ZERO, U256::ZERO));

    // Signed after the migration with the old root key.
    let late = permit_signed(&mut f, x, &old_key, spender, 1_000);
    let result = send(&mut f, relayer, vec![late]);
    assert_reverts_with(&result, permit_retired(x), "signed after migration");
    assert_eq!(permit_state(&mut f, x, spender), (U256::ZERO, U256::ZERO));

    // X relays its own old permit through its native multisig.
    f.config = config;
    let tx = f.signed(4, vec![early_for_x]);
    let result = f.run(&tx);
    assert_reverts_with(&result, permit_retired(x), "relayed by X");
    assert_eq!(
        permit_state(&mut f, x, signer(7).address()),
        (U256::ZERO, U256::ZERO)
    );
}

#[test]
fn retired_root_permit_error_order() {
    let (owner, spender, relayer) = (signer(4), signer(8).address(), signer(9).address());
    let x = owner.address();
    let mut f = Fixture::with_parent(false);
    retire(&mut f, x);
    f.evm.ctx_mut().block.timestamp = U256::from(2000);

    // The control side of each order: a valid, unexpired signature by the committed owner.
    let valid = permit_signed(&mut f, x, &owner, spender, 3_000);
    let result = send(&mut f, relayer, vec![valid]);
    assert_reverts_with(&result, permit_retired(x), "valid permit");

    // A signature by another key is an invalid signature, not a retired root.
    let forged = permit_signed(&mut f, x, &signer(5), spender, 3_000);
    let result = send(&mut f, relayer, vec![forged]);
    assert_reverts_with(&result, ITIP20::InvalidSignature {}, "forged permit");
    // An uncommitted owner gets the same error.
    let other = signer(6);
    let forged = permit_signed(&mut f, other.address(), &signer(5), spender, 3_000);
    let result = send(&mut f, relayer, vec![forged]);
    assert_reverts_with(&result, ITIP20::InvalidSignature {}, "forged, uncommitted");

    // An expired deadline keeps its own error for the committed owner.
    let expired = permit_signed(&mut f, x, &owner, spender, 1_000);
    let result = send(&mut f, relayer, vec![expired]);
    assert_reverts_with(&result, ITIP20::PermitExpired {}, "expired permit");
    assert_eq!(permit_state(&mut f, x, spender), (U256::ZERO, U256::ZERO));
}

#[test]
fn retired_root_permit_stays_allowed() {
    let (owner, spender, relayer) = (signer(4), signer(8).address(), signer(9).address());
    let mut f = Fixture::with_parent(false);
    // Only the owner's root key is at stake: a committed spender is no authority here.
    retire(&mut f, spender);
    let permit = permit_signed(&mut f, owner.address(), &owner, spender, 1_000);
    let result = send(&mut f, relayer, vec![permit]);
    assert!(result.is_success(), "{result:?}");
    assert_eq!(
        permit_state(&mut f, owner.address(), spender),
        (U256::ONE, U256::from(100))
    );
    assert_eq!(result.logs().len(), 1);
}

#[test]
fn retired_root_permit_inactive_before_t14() {
    let (owner, spender, relayer) = (signer(4), signer(8).address(), signer(9).address());
    let mut f = Fixture::with_spec(false, TempoHardfork::T13);
    retire(&mut f, owner.address());
    let permit = permit_signed(&mut f, owner.address(), &owner, spender, 1_000);
    let result = send(&mut f, relayer, vec![permit]);
    assert!(result.is_success(), "{result:?}");
    assert_eq!(
        permit_state(&mut f, owner.address(), spender),
        (U256::ONE, U256::from(100))
    );
}

fn nonce_of(f: &mut Fixture, account: Address) -> u64 {
    f.evm
        .db_mut()
        .basic(account)
        .unwrap()
        .map_or(0, |info| info.nonce)
}

/// An open path USD channel and its identity.
struct Opened {
    id: B256,
    descriptor: ITIP20ChannelReserve::ChannelDescriptor,
}

#[derive(Clone, Copy, Debug)]
enum Redeem {
    Settle,
    Close,
}

impl Redeem {
    /// The payee's call redeeming `amount` of the channel with `signature`.
    fn call(self, channel: &Opened, amount: u64, signature: Bytes) -> Call {
        let descriptor = channel.descriptor.clone();
        let cumulative_amount = U96::from(amount);
        let input = match self {
            Self::Settle => ITIP20ChannelReserve::settleCall {
                descriptor,
                cumulativeAmount: cumulative_amount,
                signature,
            }
            .abi_encode(),
            Self::Close => ITIP20ChannelReserve::closeCall {
                descriptor,
                cumulativeAmount: cumulative_amount,
                captureAmount: cumulative_amount,
                signature,
            }
            .abi_encode(),
        };
        Call {
            to: TxKind::Call(TIP20_CHANNEL_RESERVE_ADDRESS),
            value: U256::ZERO,
            input: input.into(),
        }
    }
}

/// Funds `payer` with `deposit` and opens a channel to `payee` with the given voucher signer.
fn open_channel(
    f: &mut Fixture,
    payer: Address,
    payee: Address,
    authorized_signer: Address,
    deposit: u64,
) -> Opened {
    // Genesis initializes the precompile; the fixture does not.
    if f.evm
        .db_mut()
        .basic(TIP20_CHANNEL_RESERVE_ADDRESS)
        .unwrap()
        .is_none()
    {
        StorageCtx::enter_ctx(f.evm.ctx_mut(), StorageActions::disabled(), || {
            TIP20ChannelReserve::new().initialize()
        })
        .unwrap();
        let state = f.evm.ctx_mut().journaled_state.finalize();
        f.evm.db_mut().commit(state);
    }
    fund(f, payer, deposit);
    let call = Call {
        to: TxKind::Call(TIP20_CHANNEL_RESERVE_ADDRESS),
        value: U256::ZERO,
        input: ITIP20ChannelReserve::openCall {
            payee,
            operator: Address::ZERO,
            token: PATH_USD_ADDRESS,
            deposit: U96::from(deposit),
            salt: B256::repeat_byte(0x5a),
            authorizedSigner: authorized_signer,
        }
        .abi_encode()
        .into(),
    };
    let result = send(f, payer, vec![call]);
    assert!(result.is_success(), "{result:?}");
    let opened = result
        .logs()
        .iter()
        .find_map(|log| ITIP20ChannelReserve::ChannelOpened::decode_log(log).ok())
        .expect("channel opened")
        .data;
    Opened {
        id: opened.channelId,
        descriptor: ITIP20ChannelReserve::ChannelDescriptor {
            payer,
            payee,
            operator: Address::ZERO,
            token: PATH_USD_ADDRESS,
            salt: opened.salt,
            authorizedSigner: authorized_signer,
            expiringNonceHash: opened.expiringNonceHash,
        },
    }
}

/// A voucher of `key` for `amount` cumulative units of the channel.
fn voucher(f: &mut Fixture, channel: &Opened, key: &PrivateKeySigner, amount: u64) -> Bytes {
    let digest = StorageCtx::enter_ctx(f.evm.ctx_mut(), StorageActions::disabled(), || {
        TIP20ChannelReserve::new().get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
            channelId: channel.id,
            cumulativeAmount: U96::from(amount),
        })
    })
    .unwrap();
    Bytes::from(key.sign_hash_sync(&digest).unwrap().as_bytes())
}

/// Settled amount, deposit and close request of the channel, with the balances of its payee and
/// payer and of the precompile that holds the deposit.
type ChannelSnapshot = (U96, U96, u32, U256, U256, U256);

fn channel_snapshot(f: &mut Fixture, channel: &Opened) -> ChannelSnapshot {
    let state = StorageCtx::enter_ctx(f.evm.ctx_mut(), StorageActions::disabled(), || {
        TIP20ChannelReserve::new().get_channel_state(ITIP20ChannelReserve::getChannelStateCall {
            channelId: channel.id,
        })
    })
    .unwrap();
    (
        state.settled,
        state.deposit,
        state.closeRequestedAt,
        balance(f, channel.descriptor.payee),
        balance(f, channel.descriptor.payer),
        balance(f, TIP20_CHANNEL_RESERVE_ADDRESS),
    )
}

/// A channel from `payer` to a fresh payee, one voucher of `payer`'s key for 60 units, and the
/// voucher signer's configuration still uncommitted.
fn voucher_setup(
    f: &mut Fixture,
    payer: &PrivateKeySigner,
    authorized_signer: &PrivateKeySigner,
) -> (Opened, Bytes) {
    let authorized = if authorized_signer.address() == payer.address() {
        Address::ZERO
    } else {
        authorized_signer.address()
    };
    let channel = open_channel(f, payer.address(), signer(5).address(), authorized, 100);
    let signature = voucher(f, &channel, authorized_signer, 60);
    (channel, signature)
}

#[test]
fn retired_root_channel_voucher_reverts() {
    let payee = signer(5).address();
    for redeem in [Redeem::Settle, Redeem::Close] {
        // The payer is committed and signs for itself.
        let payer = signer(4);
        let mut f = Fixture::with_parent(false);
        let (channel, signature) = voucher_setup(&mut f, &payer, &payer);
        retire(&mut f, payer.address());
        let before = channel_snapshot(&mut f, &channel);
        let call = redeem.call(&channel, 60, signature);
        let result = send(&mut f, payee, vec![call]);
        assert_reverts_with(&result, voucher_retired(payer.address()), "payer signs");
        assert_eq!(channel_snapshot(&mut f, &channel), before, "{redeem:?}");

        // The authorized signer is committed, the payer is not: the signer's root key signed.
        let (payer, delegate) = (signer(4), signer(6));
        let mut f = Fixture::with_parent(false);
        let (channel, signature) = voucher_setup(&mut f, &payer, &delegate);
        retire(&mut f, delegate.address());
        let before = channel_snapshot(&mut f, &channel);
        let call = redeem.call(&channel, 60, signature);
        let result = send(&mut f, payee, vec![call]);
        assert_reverts_with(&result, voucher_retired(delegate.address()), "signer");
        assert_eq!(channel_snapshot(&mut f, &channel), before, "{redeem:?}");

        // The same through a real migration of the payer, in a block after the voucher was signed
        // (this harness has one block environment; the node test uses real blocks).
        let mut f = Fixture::with_parent(false);
        let (account, owner) = (f.account, f.owner.clone());
        let channel = open_channel(&mut f, account, payee, Address::ZERO, 100);
        let signature = voucher(&mut f, &channel, &owner, 60);
        let nonce = nonce_of(&mut f, account);
        migrate(&mut f, nonce, signer(2).address());
        let before = channel_snapshot(&mut f, &channel);
        let call = redeem.call(&channel, 60, signature);
        let result = send(&mut f, payee, vec![call]);
        assert_reverts_with(&result, voucher_retired(account), "migrated payer");
        assert_eq!(channel_snapshot(&mut f, &channel), before, "{redeem:?}");
    }
}

#[test]
fn retired_root_channel_voucher_stays_allowed() {
    let (payer, delegate, payee) = (signer(4), signer(6), signer(5).address());
    for redeem in [Redeem::Settle, Redeem::Close] {
        // The payer is committed but its authorized signer is not: only the signer's root key
        // signed, so the voucher is good.
        let mut f = Fixture::with_parent(false);
        let (channel, signature) = voucher_setup(&mut f, &payer, &delegate);
        retire(&mut f, payer.address());
        let before = channel_snapshot(&mut f, &channel);
        let call = redeem.call(&channel, 60, signature);
        let result = send(&mut f, payee, vec![call]);
        assert!(result.is_success(), "{redeem:?}: {result:?}");
        let after = channel_snapshot(&mut f, &channel);
        assert_eq!(after.3, before.3 + U256::from(60), "{redeem:?}: payee");
        assert_ne!(after, before, "{redeem:?}");
    }
}

#[test]
fn retired_root_channel_close_without_capture_stays_allowed() {
    // Closing without capturing anything verifies no voucher, so a retired payer still gets its
    // refund through the payee's close.
    let (payer, payee) = (signer(4), signer(5).address());
    let mut f = Fixture::with_parent(false);
    let (channel, signature) = voucher_setup(&mut f, &payer, &payer);
    retire(&mut f, payer.address());
    let before = channel_snapshot(&mut f, &channel);
    let call = Call {
        to: TxKind::Call(TIP20_CHANNEL_RESERVE_ADDRESS),
        value: U256::ZERO,
        input: ITIP20ChannelReserve::closeCall {
            descriptor: channel.descriptor.clone(),
            cumulativeAmount: U96::from(60),
            captureAmount: U96::ZERO,
            signature,
        }
        .abi_encode()
        .into(),
    };
    let result = send(&mut f, payee, vec![call]);
    assert!(result.is_success(), "{result:?}");
    let after = channel_snapshot(&mut f, &channel);
    assert_eq!(after.3, before.3, "payee");
    assert_eq!(after.4, before.4 + U256::from(100), "payer refund");
}

#[test]
fn retired_root_channel_voucher_error_order() {
    let (payer, payee) = (signer(4), signer(5).address());
    for redeem in [Redeem::Settle, Redeem::Close] {
        let mut f = Fixture::with_parent(false);
        let (channel, valid) = voucher_setup(&mut f, &payer, &payer);
        retire(&mut f, payer.address());
        // Another key's voucher, and garbage, keep the existing signature error for a committed
        // signer; only a voucher the committed signer really signed is a retired root key.
        let forged = voucher(&mut f, &channel, &signer(7), 60);
        for (label, signature) in [("forged", forged), ("garbage", Bytes::from(vec![0x42; 65]))] {
            let call = redeem.call(&channel, 60, signature);
            let result = send(&mut f, payee, vec![call]);
            assert_reverts_with(
                &result,
                ITIP20ChannelReserve::InvalidSignature {},
                &format!("{redeem:?} {label}"),
            );
        }
        let call = redeem.call(&channel, 60, valid);
        let result = send(&mut f, payee, vec![call]);
        assert_reverts_with(&result, voucher_retired(payer.address()), "valid");
    }
}

#[test]
fn retired_root_channel_voucher_inactive_before_t14() {
    let (payer, payee) = (signer(4), signer(5).address());
    for redeem in [Redeem::Settle, Redeem::Close] {
        let mut f = Fixture::with_spec(false, TempoHardfork::T13);
        let (channel, signature) = voucher_setup(&mut f, &payer, &payer);
        retire(&mut f, payer.address());
        let before = channel_snapshot(&mut f, &channel);
        let call = redeem.call(&channel, 60, signature);
        let result = send(&mut f, payee, vec![call]);
        assert!(result.is_success(), "{redeem:?}: {result:?}");
        assert_eq!(
            channel_snapshot(&mut f, &channel).3,
            before.3 + U256::from(60)
        );
    }
}

#[test]
fn channel_settle_and_close_replay_only_from_t14() {
    let (payer, payee) = (signer(4), signer(5).address());
    let mut f = Fixture::with_parent(false);
    let (channel, signature) = voucher_setup(&mut f, &payer, &payer);
    let primitive = TempoSignature::from(Signature::test_signature());
    let envelope = |calls: Vec<Call>| -> TempoTxEnvelope {
        aa_tx(0, calls).into_signed(primitive.clone()).into()
    };
    let transfer = Call {
        to: TxKind::Call(PATH_USD_ADDRESS),
        value: U256::ZERO,
        input: ITIP20::transferCall {
            to: payee,
            amount: U256::ONE,
        }
        .abi_encode()
        .into(),
    };
    assert!(supports_storage_action_replay(
        &envelope(vec![transfer.clone()]),
        TempoHardfork::T13
    ));
    for redeem in [Redeem::Settle, Redeem::Close] {
        let call = redeem.call(&channel, 60, signature.clone());
        // Settle and close verify a signature the replay cannot gate, so they run sequentially.
        for calls in [
            vec![call.clone()],
            vec![transfer.clone(), call.clone()],
            vec![call, transfer.clone()],
        ] {
            let tx = envelope(calls);
            assert!(
                supports_storage_action_replay(&tx, TempoHardfork::T13),
                "{redeem:?} before T14"
            );
            assert!(
                !supports_storage_action_replay(&tx, TempoHardfork::T14),
                "{redeem:?} from T14"
            );
        }
    }
    // The other channel calls verify no voucher.
    let top_up = Call {
        to: TxKind::Call(TIP20_CHANNEL_RESERVE_ADDRESS),
        value: U256::ZERO,
        input: ITIP20ChannelReserve::topUpCall {
            descriptor: channel.descriptor,
            additionalDeposit: U96::ONE,
        }
        .abi_encode()
        .into(),
    };
    assert!(supports_storage_action_replay(
        &envelope(vec![top_up]),
        TempoHardfork::T14
    ));
}

#[derive(Clone, Copy, Debug)]
enum SignedAction {
    Permit,
    Redeem(Redeem),
}

/// Gas of one `action` verifying the signature of an uncommitted key, with that key's account
/// listed in the access list (warm) or not (cold).
fn signature_gas(spec: TempoHardfork, action: SignedAction, warm: bool) -> u64 {
    let (key, payee, relayer) = (signer(4), signer(5).address(), signer(9).address());
    let mut f = Fixture::with_spec(false, spec);
    let (sender, call) = match action {
        SignedAction::Permit => (
            relayer,
            permit_signed(&mut f, key.address(), &key, signer(8).address(), 1_000),
        ),
        SignedAction::Redeem(redeem) => {
            let (channel, signature) = voucher_setup(&mut f, &key, &key);
            (payee, redeem.call(&channel, 60, signature))
        }
    };
    let access_list = if warm {
        AccessList(vec![AccessListItem {
            address: key.address(),
            storage_keys: Vec::new(),
        }])
    } else {
        AccessList(Vec::new())
    };
    let result = send_listed(&mut f, sender, vec![call], access_list);
    assert!(result.is_success(), "{action:?} at {spec:?}: {result:?}");
    result.tx_gas_used()
}

#[test]
fn retired_root_signature_checks_cost_the_commitment_read() {
    for action in [
        SignedAction::Permit,
        SignedAction::Redeem(Redeem::Settle),
        SignedAction::Redeem(Redeem::Close),
    ] {
        for warm in [false, true] {
            let before = signature_gas(TempoHardfork::T13, action, warm);
            let after = signature_gas(TempoHardfork::T14, action, warm);
            // Reads follow the normal account-access schedule: a cold account load, or a warm
            // one when the key's account is in the access list. An already loaded commitment adds
            // nothing on top.
            let read = if warm { 100 } else { 2600 };
            assert_eq!(after - before, read, "{action:?}, warm: {warm}");
        }
    }
}
