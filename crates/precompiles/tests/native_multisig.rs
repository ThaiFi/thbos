//! Native multisig precompile calls through its ABI.

use alloy::{
    primitives::{Address, B256, Bytes, address, keccak256},
    sol_types::{SolCall, SolEvent, SolInterface},
};
use alloy_evm::EvmEnv;
use revm::{
    context::CfgEnv,
    database::InMemoryDB,
    interpreter::gas::{KECCAK256, KECCAK256WORD},
    precompile::{PrecompileOutput, PrecompileStatus},
    state::Bytecode,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{INativeMultisig, NATIVE_MULTISIG_ADDRESS, NativeMultisigError};
use tempo_evm::{TempoBlockEnv, evm::TempoEvm};
use tempo_precompiles::{
    Precompile, input_cost,
    native_multisig::{
        NativeMultisig, UpgradeEligibility, initial_account_proof_gas, valid_account,
    },
    storage::{
        ConfigCommitmentWriteGas, StorageActions, StorageCtx, hashmap::HashMapStorageProvider,
    },
};
use tempo_primitives::{
    MasterId, TempoAddressExt, UserTag,
    transaction::{
        MultisigConfig, MultisigOwner,
        multisig::{MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN, MULTISIG_UPGRADE_DOMAIN},
    },
};

const FACTORY: Address = Address::repeat_byte(0x71);
const OWNER: Address = Address::repeat_byte(0x22);
const EOA: Address = Address::repeat_byte(0x33);

fn t14_storage() -> HashMapStorageProvider {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
    storage.set_multisig_recovery_factory(FACTORY);
    storage
}

fn weighted_owners(entries: &[(Address, u8)]) -> Vec<INativeMultisig::MultisigOwner> {
    entries
        .iter()
        .map(|&(owner, weight)| INativeMultisig::MultisigOwner { owner, weight })
        .collect()
}

fn config(
    salt: B256,
    version: u64,
    threshold: u8,
    owners: &[INativeMultisig::MultisigOwner],
) -> MultisigConfig {
    MultisigConfig {
        salt,
        version,
        threshold,
        owners: owners
            .iter()
            .map(|owner| MultisigOwner {
                owner: owner.owner,
                weight: owner.weight,
            })
            .collect(),
    }
}

fn call(sender: Address, call: impl SolCall) -> PrecompileOutput {
    NativeMultisig::new()
        .call(&call.abi_encode(), sender)
        .expect("native multisig calls never fail the frame")
}

fn returns<C: SolCall>(output: PrecompileOutput) -> C::Return {
    assert_eq!(output.status, PrecompileStatus::Success, "{output:?}");
    C::abi_decode_returns(&output.bytes).unwrap()
}

#[track_caller]
fn assert_reverts(output: PrecompileOutput, expected: NativeMultisigError) {
    assert_eq!(output.status, PrecompileStatus::Revert, "{expected:?}");
    assert_eq!(
        output.bytes,
        Bytes::from(expected.abi_encode()),
        "{expected:?}"
    );
}

fn derive(salt: B256, threshold: u8, owners: &[INativeMultisig::MultisigOwner]) -> Address {
    returns::<INativeMultisig::deriveAccountCall>(call(
        Address::ZERO,
        INativeMultisig::deriveAccountCall {
            salt,
            threshold,
            owners: owners.to_vec(),
        },
    ))
}

fn commitment_of(account: Address) -> B256 {
    returns::<INativeMultisig::getConfigCommitmentCall>(call(
        Address::ZERO,
        INativeMultisig::getConfigCommitmentCall { account },
    ))
}

fn update(
    sender: Address,
    current: &INativeMultisig::MultisigConfig,
    threshold: u8,
    owners: &[INativeMultisig::MultisigOwner],
) -> PrecompileOutput {
    call(
        sender,
        INativeMultisig::updateConfigCall {
            current: current.clone(),
            threshold,
            owners: owners.to_vec(),
        },
    )
}

fn upgrade(
    sender: Address,
    threshold: u8,
    owners: &[INativeMultisig::MultisigOwner],
) -> PrecompileOutput {
    call(
        sender,
        INativeMultisig::upgradeAccountCall {
            threshold,
            owners: owners.to_vec(),
        },
    )
}

fn seed_authority(origin: Address, directly_authorized: Address, eligibility: UpgradeEligibility) {
    NativeMultisig::new()
        .set_authority(origin, directly_authorized, eligibility)
        .unwrap();
}

fn seed_commitment(account: Address, commitment: B256) {
    StorageCtx
        .set_config_commitment(account, commitment, ConfigCommitmentWriteGas::Intrinsic)
        .unwrap();
}

#[test]
fn account_namespace_excludes_reserved_addresses() {
    for spec in [TempoHardfork::T12, TempoHardfork::T13, TempoHardfork::T14] {
        for (account, expected) in [
            (Address::ZERO, false),
            (Address::with_last_byte(1), false),
            (address!("0000000000000000000000000000000000000100"), false),
            (address!("20c0000000000000000000000000000000000001"), false),
            (Address::new_virtual(MasterId::ZERO, UserTag::ZERO), false),
            (address!("5ad0000000000000000000000000000000000001"), false),
            (Address::repeat_byte(0x71), true),
        ] {
            assert_eq!(
                valid_account(account, spec),
                expected,
                "{account} at {spec:?}"
            );
        }
    }
}

#[test]
fn derive_account_matches_the_config_derivation() {
    let mut storage = t14_storage();
    StorageCtx::enter(&mut storage, || {
        let salt = B256::repeat_byte(5);
        let owners = weighted_owners(&[(Address::repeat_byte(0x11), 1), (OWNER, 2)]);
        assert_eq!(
            derive(salt, 2, &owners),
            config(salt, 0, 2, &owners).derive_account(FACTORY).unwrap()
        );
        assert_ne!(derive(salt, 2, &owners), derive(salt, 1, &owners));
    });
}

#[test]
fn derive_account_charges_input_and_proof_hashing_gas() {
    let mut cfg = CfgEnv::<TempoHardfork>::default();
    cfg.set_spec_and_mainnet_gas_params(TempoHardfork::T14);
    let block_env = TempoBlockEnv {
        multisig_recovery_factory: Some(FACTORY),
        ..Default::default()
    };
    let mut evm = TempoEvm::new(
        InMemoryDB::default(),
        EvmEnv {
            cfg_env: cfg,
            block_env,
        },
    );
    StorageCtx::enter_ctx(evm.ctx_mut(), StorageActions::disabled(), || {
        let keccak = |len: usize| KECCAK256 + KECCAK256WORD * len.div_ceil(32) as u64;
        for owners in [
            weighted_owners(&[(OWNER, 1)]),
            weighted_owners(&[(Address::repeat_byte(0x11), 1), (OWNER, 1)]),
        ] {
            let config = config(B256::ZERO, 0, 1, &owners);
            let proof_gas = keccak(config.account_salt_preimage_len())
                + keccak(MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN);
            assert_eq!(initial_account_proof_gas(&config), proof_gas);

            let calldata = INativeMultisig::deriveAccountCall {
                salt: B256::ZERO,
                threshold: 1,
                owners,
            }
            .abi_encode();
            let before = StorageCtx.gas_used();
            let output = NativeMultisig::new()
                .call(&calldata, Address::ZERO)
                .unwrap();
            assert_eq!(
                INativeMultisig::deriveAccountCall::abi_decode_returns(&output.bytes).unwrap(),
                config.derive_account(FACTORY).unwrap()
            );
            assert_eq!(
                StorageCtx.gas_used() - before,
                input_cost(TempoHardfork::T14, calldata.len()).unwrap() + proof_gas
            );
        }

        // An invalid configuration is rejected before the hashing charge.
        let calldata = INativeMultisig::deriveAccountCall {
            salt: B256::ZERO,
            threshold: 0,
            owners: weighted_owners(&[(OWNER, 1)]),
        }
        .abi_encode();
        let before = StorageCtx.gas_used();
        let output = NativeMultisig::new()
            .call(&calldata, Address::ZERO)
            .unwrap();
        assert_reverts(output, NativeMultisigError::invalid_threshold());
        assert_eq!(
            StorageCtx.gas_used() - before,
            input_cost(TempoHardfork::T14, calldata.len()).unwrap()
        );
    });
}

#[test]
fn native_rotation_requires_registered_current_leaf_and_direct_authority() {
    let mut storage = t14_storage();
    let (account, owners) = StorageCtx::enter(&mut storage, || {
        let owners = weighted_owners(&[(OWNER, 1)]);
        let account = derive(B256::ZERO, 1, &owners);
        let mut current = INativeMultisig::MultisigConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: owners.clone(),
        };
        assert_eq!(commitment_of(account), B256::ZERO);
        assert_reverts(
            update(account, &current, 1, &owners),
            NativeMultisigError::unauthorized_multisig_caller(),
        );
        seed_authority(account, account, UpgradeEligibility::NotSoleCall);
        assert_reverts(
            update(account, &current, 1, &owners),
            NativeMultisigError::invalid_config(),
        );
        seed_commitment(
            account,
            config(B256::ZERO, 0, 1, &owners).commitment().unwrap(),
        );
        returns::<INativeMultisig::updateConfigCall>(update(account, &current, 1, &owners));
        assert_reverts(
            update(account, &current, 1, &owners),
            NativeMultisigError::invalid_config(),
        );
        current.version = 1;
        returns::<INativeMultisig::updateConfigCall>(update(account, &current, 1, &owners));
        assert_eq!(
            commitment_of(account),
            config(B256::ZERO, 2, 1, &owners).commitment().unwrap()
        );
        (account, owners)
    });

    let events: Vec<_> = (1..=2)
        .map(|version| {
            INativeMultisig::MultisigConfigUpdated {
                account,
                salt: B256::ZERO,
                version,
                threshold: 1,
                owners: owners.clone(),
            }
            .encode_log_data()
        })
        .collect();
    assert_eq!(storage.get_events(NATIVE_MULTISIG_ADDRESS), &events);
}

#[test]
fn update_config_requires_the_sender_as_origin_and_direct_authority() {
    let mut storage = t14_storage();
    StorageCtx::enter(&mut storage, || {
        let owners = weighted_owners(&[(OWNER, 1)]);
        let account = derive(B256::ZERO, 1, &owners);
        let current = INativeMultisig::MultisigConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: owners.clone(),
        };
        seed_commitment(
            account,
            config(B256::ZERO, 0, 1, &owners).commitment().unwrap(),
        );
        for (sender, origin, directly_authorized) in [
            (Address::ZERO, Address::ZERO, Address::ZERO),
            (account, EOA, account),
            (account, account, EOA),
        ] {
            seed_authority(
                origin,
                directly_authorized,
                UpgradeEligibility::PrimitiveRoot,
            );
            assert_reverts(
                update(sender, &current, 1, &owners),
                NativeMultisigError::unauthorized_multisig_caller(),
            );
        }
        seed_authority(account, account, UpgradeEligibility::NotSoleCall);
        returns::<INativeMultisig::updateConfigCall>(update(account, &current, 1, &owners));
    });
}

#[test]
fn update_config_rejects_invalid_current_and_next_configs() {
    let mut storage = t14_storage();
    StorageCtx::enter(&mut storage, || {
        let owners = weighted_owners(&[(OWNER, 1)]);
        let account = derive(B256::ZERO, 1, &owners);
        seed_authority(account, account, UpgradeEligibility::NotSoleCall);
        let initial = config(B256::ZERO, 0, 1, &owners).commitment().unwrap();
        seed_commitment(account, initial);

        // A current configuration that fails validation is stale, so it gets `InvalidConfig`.
        let self_owned = weighted_owners(&[(account, 1)]);
        let current = INativeMultisig::MultisigConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: self_owned,
        };
        assert_reverts(
            update(account, &current, 1, &owners),
            NativeMultisigError::invalid_config(),
        );

        let current = INativeMultisig::MultisigConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: owners.clone(),
        };
        assert_reverts(
            update(account, &current, 0, &owners),
            NativeMultisigError::invalid_threshold(),
        );
        assert_reverts(
            update(account, &current, 1, &[]),
            NativeMultisigError::invalid_multisig_owner(),
        );
        assert_eq!(commitment_of(account), initial);

        let last = INativeMultisig::MultisigConfig {
            salt: B256::ZERO,
            version: u64::MAX,
            threshold: 1,
            owners: owners.clone(),
        };
        StorageCtx
            .set_config_commitment(
                account,
                config(B256::ZERO, u64::MAX, 1, &owners)
                    .commitment()
                    .unwrap(),
                ConfigCommitmentWriteGas::Precompile,
            )
            .unwrap();
        assert_reverts(
            update(account, &last, 1, &owners),
            NativeMultisigError::invalid_config(),
        );
    });
}

#[test]
fn native_config_error_precedence_through_abi() {
    let mut storage = t14_storage();
    StorageCtx::enter(&mut storage, || {
        struct Case {
            name: &'static str,
            threshold: u8,
            owners: Vec<(u8, u8)>,
            expected: NativeMultisigError,
        }
        for Case {
            name: case,
            threshold,
            owners,
            expected,
        } in [
            Case {
                name: "empty before threshold",
                threshold: 0,
                owners: vec![],
                expected: NativeMultisigError::invalid_multisig_owner(),
            },
            Case {
                name: "count before threshold",
                threshold: 0,
                owners: vec![(0, 0); 49],
                expected: NativeMultisigError::too_many_owners(),
            },
            Case {
                name: "threshold before address",
                threshold: 0,
                owners: vec![(0, 0)],
                expected: NativeMultisigError::invalid_threshold(),
            },
            Case {
                name: "address before weight",
                threshold: 1,
                owners: vec![(0x11, 0), (0, 1)],
                expected: NativeMultisigError::invalid_multisig_owner(),
            },
            Case {
                name: "weight before duplicate",
                threshold: 1,
                owners: vec![(0x11, 1), (0x11, 1), (0x22, 0)],
                expected: NativeMultisigError::invalid_weight(),
            },
            Case {
                name: "nonadjacent duplicate before order",
                threshold: 1,
                owners: vec![(0x22, 1), (0x11, 1), (0x22, 1)],
                expected: NativeMultisigError::duplicate_owner(),
            },
            Case {
                name: "order before total weight",
                threshold: 1,
                owners: vec![(0x22, 128), (0x11, 128)],
                expected: NativeMultisigError::invalid_owner_order(),
            },
        ] {
            let call = INativeMultisig::deriveAccountCall {
                salt: B256::ZERO,
                threshold,
                owners: owners
                    .into_iter()
                    .map(|(owner, weight)| INativeMultisig::MultisigOwner {
                        owner: Address::repeat_byte(owner),
                        weight,
                    })
                    .collect(),
            };
            let result = NativeMultisig::new()
                .call(&call.abi_encode(), Address::ZERO)
                .unwrap();
            assert_eq!(result.status, PrecompileStatus::Revert, "{case}");
            assert_eq!(result.bytes, expected.abi_encode(), "{case}");
        }
    });
}

#[test]
fn native_factory_is_required_but_getter_remains_available() {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
    StorageCtx::enter(&mut storage, || {
        let owners = weighted_owners(&[(OWNER, 1)]);
        assert_eq!(commitment_of(Address::repeat_byte(0x11)), B256::ZERO);
        assert_reverts(
            call(
                Address::ZERO,
                INativeMultisig::deriveAccountCall {
                    salt: B256::ZERO,
                    threshold: 1,
                    owners: owners.clone(),
                },
            ),
            NativeMultisigError::invalid_config(),
        );

        let account = config(B256::ZERO, 0, 1, &owners)
            .derive_account(FACTORY)
            .unwrap();
        seed_commitment(
            account,
            config(B256::ZERO, 0, 1, &owners).commitment().unwrap(),
        );
        seed_authority(account, account, UpgradeEligibility::NotSoleCall);
        let current = INativeMultisig::MultisigConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: owners.clone(),
        };
        assert_reverts(
            update(account, &current, 1, &owners),
            NativeMultisigError::invalid_config(),
        );

        seed_authority(EOA, EOA, UpgradeEligibility::PrimitiveRoot);
        assert_reverts(
            upgrade(EOA, 1, &owners),
            NativeMultisigError::invalid_config(),
        );
        assert_eq!(commitment_of(EOA), B256::ZERO);
    });
}

#[test]
fn mutating_calls_reject_static_context() {
    let mut storage = t14_storage();
    storage.set_is_static(true);
    StorageCtx::enter(&mut storage, || {
        let owners = weighted_owners(&[(OWNER, 1)]);
        let account = derive(B256::ZERO, 1, &owners);
        assert_eq!(commitment_of(account), B256::ZERO);
        let current = INativeMultisig::MultisigConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: owners.clone(),
        };
        for output in [
            update(account, &current, 1, &owners),
            upgrade(EOA, 1, &owners),
        ] {
            assert!(
                matches!(output.status, PrecompileStatus::Halt(_)),
                "{output:?}"
            );
            assert!(output.bytes.is_empty());
        }
    });
}

#[test]
fn upgrade_account_checks_eligibility_code_and_commitment_in_order() {
    let mut storage = t14_storage();
    StorageCtx::enter(&mut storage, || {
        let owners = weighted_owners(&[(OWNER, 1)]);
        let with_code = Address::repeat_byte(0x44);
        StorageCtx
            .set_code(with_code, Bytecode::new_raw(Bytes::from_static(&[0x00])))
            .unwrap();
        seed_commitment(with_code, B256::repeat_byte(9));
        let configured = Address::repeat_byte(0x55);
        seed_commitment(configured, B256::repeat_byte(9));

        // An unseeded context rejects every migration.
        assert_reverts(
            upgrade(EOA, 1, &owners),
            NativeMultisigError::upgrade_must_be_only_call(),
        );
        for (sender, eligibility, expected) in [
            (
                with_code,
                UpgradeEligibility::NotSoleCall,
                NativeMultisigError::upgrade_must_be_only_call(),
            ),
            (
                with_code,
                UpgradeEligibility::NotPrimitiveRoot,
                NativeMultisigError::primitive_root_required(),
            ),
            (
                with_code,
                UpgradeEligibility::PrimitiveRoot,
                NativeMultisigError::account_has_code(),
            ),
            (
                configured,
                UpgradeEligibility::PrimitiveRoot,
                NativeMultisigError::account_already_configurable(),
            ),
        ] {
            seed_authority(sender, sender, eligibility);
            assert_reverts(upgrade(sender, 1, &owners), expected);
        }

        // Configuration errors are all reported as an invalid config.
        seed_authority(EOA, EOA, UpgradeEligibility::PrimitiveRoot);
        for (threshold, owners) in [
            (0, owners.clone()),
            (1, vec![]),
            (2, owners),
            (
                1,
                weighted_owners(&[(OWNER, 1), (Address::repeat_byte(0x11), 1)]),
            ),
        ] {
            assert_reverts(
                upgrade(EOA, threshold, &owners),
                NativeMultisigError::invalid_config(),
            );
        }
        assert_eq!(commitment_of(EOA), B256::ZERO);
    });
}

#[test]
fn upgrade_account_installs_a_version_one_commitment() {
    let mut storage = t14_storage();
    // The root key may also be listed as an owner.
    let owners = weighted_owners(&[(OWNER, 1), (EOA, 1)]);
    let salt = keccak256([MULTISIG_UPGRADE_DOMAIN, EOA.as_slice()].concat());
    let expected = config(salt, 1, 2, &owners).commitment().unwrap();
    StorageCtx::enter(&mut storage, || {
        seed_authority(EOA, EOA, UpgradeEligibility::PrimitiveRoot);
        assert_eq!(
            returns::<INativeMultisig::upgradeAccountCall>(upgrade(EOA, 2, &owners)),
            expected
        );
        assert_eq!(commitment_of(EOA), expected);
        assert_reverts(
            upgrade(EOA, 2, &owners),
            NativeMultisigError::account_already_configurable(),
        );

        // The upgraded account rotates like any registered one.
        let current = INativeMultisig::MultisigConfig {
            salt,
            version: 1,
            threshold: 2,
            owners: owners.clone(),
        };
        returns::<INativeMultisig::updateConfigCall>(update(EOA, &current, 1, &owners));
        assert_eq!(
            commitment_of(EOA),
            config(salt, 2, 1, &owners).commitment().unwrap()
        );
    });

    let upgraded = INativeMultisig::AccountUpgraded {
        account: EOA,
        commitment: expected,
        salt,
        threshold: 2,
        owners: owners.clone(),
    }
    .encode_log_data();
    let updated = INativeMultisig::MultisigConfigUpdated {
        account: EOA,
        salt,
        version: 2,
        threshold: 1,
        owners,
    }
    .encode_log_data();
    assert_eq!(
        storage.get_events(NATIVE_MULTISIG_ADDRESS),
        &[upgraded, updated]
    );
}
