//! Signed transaction integration fixtures for the T14 account-leaf protocol.
use alloy_eips::eip2930::AccessList;
use alloy_evm::{Evm, EvmEnv, FromRecoveredTx};
use alloy_primitives::{Address, B256, TxKind, U256, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use revm::{
    Database, DatabaseCommit,
    context::{
        CfgEnv, JournalTr,
        result::{ExecutionResult, HaltReason},
    },
    database::{EmptyDB, State, states::bundle_state::BundleRetention},
    state::{Account, AccountInfo, Bytecode, TransactionId},
};
use tempo_chainspec::TempoHardfork;
use tempo_contracts::precompiles::{NATIVE_MULTISIG_ADDRESS, native_multisig::INativeMultisig};
use tempo_evm::evm::TempoEvm;
use tempo_precompiles::{
    account_keychain::AccountKeychain,
    storage::{StorageActions, StorageCtx},
    test_util::TIP20Setup,
    tip403_registry::TIP403Registry,
};
use tempo_primitives::{
    AASigned, TempoBlockEnv, TempoSignature, TempoTransaction,
    account::decode_config_commitment,
    transaction::{
        Call, MULTISIG_UPGRADE_DOMAIN, MultisigConfig, MultisigOwner, MultisigSignature,
        PrimitiveSignature, multisig_digest,
    },
};
use tempo_revm::{TempoTxEnv, gas_params::tempo_gas_params};

struct Fixture {
    evm: TempoEvm<State<EmptyDB>>,
    owner: PrivateKeySigner,
    config: MultisigConfig,
    account: Address,
}

impl Fixture {
    fn new() -> Self {
        Self::with_parent(true)
    }

    fn with_parent(configurable: bool) -> Self {
        Self::with_spec(configurable, TempoHardfork::T14)
    }

    fn with_spec(configurable: bool, spec: TempoHardfork) -> Self {
        let owner = signer(1);
        let factory = Address::repeat_byte(0x71);
        let config = MultisigConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: vec![MultisigOwner {
                owner: owner.address(),
                weight: 1,
            }],
        };
        let account = if configurable {
            config.derive_account(factory).unwrap()
        } else {
            owner.address()
        };
        let mut db = State::builder().with_bundle_update().build();
        let mut seed = Account::new_not_existing(TransactionId::ZERO);
        seed.info.set_nonce(3).set_balance(U256::from(42));
        seed.mark_touch();
        db.commit(std::iter::once((account, seed)).collect());
        let cfg = CfgEnv::new_with_spec_and_gas_params(spec, tempo_gas_params(spec));
        let mut evm = TempoEvm::new(
            db,
            EvmEnv::new(
                cfg,
                TempoBlockEnv {
                    multisig_recovery_factory: Some(factory),
                    ..Default::default()
                },
            ),
        );
        StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
            TIP403Registry::new().initialize()?;
            AccountKeychain::new().initialize()?;
            TIP20Setup::path_usd(owner.address()).apply()
        })
        .unwrap();
        let state = evm.ctx_mut().journaled_state.finalize();
        evm.db_mut().commit(state);
        evm.db_mut().merge_transitions(BundleRetention::Reverts);
        Self {
            evm,
            owner,
            config,
            account,
        }
    }

    fn signed(&self, nonce: u64, calls: Vec<Call>) -> AASigned {
        multisig_signed(self, aa_tx(nonce, calls))
    }

    fn getter(&self) -> Call {
        Call {
            to: TxKind::Call(NATIVE_MULTISIG_ADDRESS),
            value: U256::ZERO,
            input: INativeMultisig::getConfigCommitmentCall {
                account: self.account,
            }
            .abi_encode()
            .into(),
        }
    }

    fn rotation(current: &MultisigConfig, next: &MultisigConfig) -> Call {
        Call {
            to: TxKind::Call(NATIVE_MULTISIG_ADDRESS),
            value: U256::ZERO,
            input: INativeMultisig::updateConfigCall {
                current: INativeMultisig::MultisigConfig {
                    salt: current.salt,
                    version: current.version,
                    threshold: current.threshold,
                    owners: abi_owners(current),
                },
                threshold: next.threshold,
                owners: abi_owners(next),
            }
            .abi_encode()
            .into(),
        }
    }

    /// The configuration `upgradeAccount` commits for this account: the upgrade salt at version 1.
    fn upgraded(&self, threshold: u8, owners: Vec<MultisigOwner>) -> MultisigConfig {
        MultisigConfig {
            salt: keccak256([MULTISIG_UPGRADE_DOMAIN, self.account.as_slice()].concat()),
            version: 1,
            threshold,
            owners,
        }
    }

    /// An `upgradeAccount` call that migrates the sender to `config`.
    fn upgrade(config: &MultisigConfig) -> Call {
        Call {
            to: TxKind::Call(NATIVE_MULTISIG_ADDRESS),
            value: U256::ZERO,
            input: INativeMultisig::upgradeAccountCall {
                threshold: config.threshold,
                owners: abi_owners(config),
            }
            .abi_encode()
            .into(),
        }
    }

    /// An AA transaction signed by the account's root key (a primitive signature).
    fn primitive(&self, nonce: u64, calls: Vec<Call>) -> AASigned {
        self.sign_primitive(aa_tx(nonce, calls))
    }

    fn sign_primitive(&self, tx: TempoTransaction) -> AASigned {
        let signature = self.owner.sign_hash_sync(&tx.signature_hash()).unwrap();
        tx.into_signed(signature.into())
    }

    /// Executes `tx` for the account and commits its state, whether or not it reverts.
    fn run<T>(&mut self, tx: &T) -> ExecutionResult<HaltReason>
    where
        TempoTxEnv: FromRecoveredTx<T>,
    {
        self.run_as(self.account, tx)
    }

    /// Executes `tx` sent by `sender` and commits its state, whether or not it reverts.
    fn run_as<T>(&mut self, sender: Address, tx: &T) -> ExecutionResult<HaltReason>
    where
        TempoTxEnv: FromRecoveredTx<T>,
    {
        let output = self
            .evm
            .transact(TempoTxEnv::from_recovered_tx(tx, sender))
            .unwrap();
        self.evm.db_mut().commit(output.state);
        output.result
    }

    fn commitment(&mut self) -> B256 {
        decode_config_commitment(
            &self
                .evm
                .db_mut()
                .basic(self.account)
                .unwrap()
                .unwrap()
                .extension,
            true,
        )
        .unwrap()
    }

    fn install_contract(&mut self, address: Address, code: Vec<u8>) -> Call {
        self.evm.db_mut().insert_account(
            address,
            AccountInfo::default().with_code(Bytecode::new_legacy(code.into())),
        );
        Call {
            to: TxKind::Call(address),
            value: U256::ZERO,
            input: Default::default(),
        }
    }
}

/// An unsigned AA transaction on the protocol nonce lane, with no fee, sponsor, validity window
/// or authorizations.
fn aa_tx(nonce: u64, calls: Vec<Call>) -> TempoTransaction {
    TempoTransaction {
        chain_id: 1,
        fee_token: None,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_limit: 1_000_000,
        calls,
        access_list: AccessList(Vec::new()),
        nonce_key: U256::ZERO,
        nonce,
        fee_payer_signature: None,
        valid_before: None,
        valid_after: None,
        key_authorization: None,
        tempo_authorization_list: Vec::new(),
    }
}

/// The deterministic test key whose private key is `seed` repeated.
fn signer(seed: u8) -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&B256::repeat_byte(seed)).unwrap()
}

/// Signs `tx` as the account's native multisig, with the fixture's current configuration.
fn multisig_signed(f: &Fixture, tx: TempoTransaction) -> AASigned {
    let signature = multisig_approval(f.account, &f.config, &f.owner, tx.signature_hash());
    tx.into_signed(TempoSignature::Multisig(signature))
}

/// `owner`'s approval of `inner_digest` as the multisig `account` with `config`.
fn multisig_approval(
    account: Address,
    config: &MultisigConfig,
    owner: &PrivateKeySigner,
    inner_digest: B256,
) -> MultisigSignature {
    let digest = multisig_digest(inner_digest, account, config.version);
    let approval = PrimitiveSignature::Secp256k1(owner.sign_hash_sync(&digest).unwrap());
    MultisigSignature::try_new(account, config.clone(), vec![approval]).unwrap()
}

fn abi_owners(config: &MultisigConfig) -> Vec<INativeMultisig::MultisigOwner> {
    config
        .owners
        .iter()
        .map(|owner| INativeMultisig::MultisigOwner {
            owner: owner.owner,
            weight: owner.weight,
        })
        .collect()
}

mod tests;
