use super::*;
use crate::{
    Precompile,
    storage::{StorageCtx, hashmap::HashMapStorageProvider},
};
use alloy::{
    primitives::address,
    sol_types::{SolCall, SolInterface},
};
use revm::precompile::PrecompileStatus;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::TempoAddressExt;

#[test]
fn account_namespace_excludes_reserved_addresses() {
    for spec in [TempoHardfork::T12, TempoHardfork::T13, TempoHardfork::T14] {
        for (account, expected) in [
            (Address::ZERO, false),
            (Address::with_last_byte(1), false),
            (address!("0000000000000000000000000000000000000100"), false),
            (NATIVE_MULTISIG_ADDRESS, !spec.is_t14()),
            (address!("20c0000000000000000000000000000000000001"), false),
            (
                Address::new_virtual(Default::default(), Default::default()),
                false,
            ),
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
fn native_rotation_requires_registered_current_leaf_and_direct_authority() {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14)
        .with_multisig_recovery_factory(Address::repeat_byte(0x71));
    StorageCtx::enter(&mut storage, || {
        let owners = vec![INativeMultisig::MultisigOwner {
            owner: Address::repeat_byte(0x22),
            weight: 1,
        }];
        let mut native = NativeMultisig::new();
        let account = native.derive_account(B256::ZERO, 1, &owners).unwrap();
        let mut current = INativeMultisig::MultisigConfig {
            salt: B256::ZERO,
            version: 0,
            threshold: 1,
            owners: owners.clone(),
        };
        assert_eq!(native.get_config_commitment(account).unwrap(), B256::ZERO);
        assert_eq!(
            native.update_config(account, &current, 1, owners.clone()),
            Err(NativeMultisigError::unauthorized_multisig_caller().into())
        );
        native
            .set_authority(account, account, UpgradeEligibility::NotSoleCall)
            .unwrap();
        assert_eq!(
            native.update_config(account, &current, 1, owners.clone()),
            Err(NativeMultisigError::invalid_config().into())
        );
        let initial = config(B256::ZERO, 0, 1, &owners).commitment().unwrap();
        StorageCtx
            .set_config_commitment(account, initial, ConfigCommitmentWriteGas::Intrinsic)
            .unwrap();
        native
            .update_config(account, &current, 1, owners.clone())
            .unwrap();
        assert_eq!(
            native.update_config(account, &current, 1, owners.clone()),
            Err(NativeMultisigError::invalid_config().into())
        );
        current.version = 1;
        native
            .update_config(account, &current, 1, owners.clone())
            .unwrap();
        assert_eq!(
            native.get_config_commitment(account).unwrap(),
            config(B256::ZERO, 2, 1, &owners).commitment().unwrap()
        );
    });
}

#[test]
fn native_config_error_precedence_through_abi() {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14)
        .with_multisig_recovery_factory(Address::repeat_byte(0x71));
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
        let native = NativeMultisig::new();
        assert_eq!(
            native
                .get_config_commitment(Address::repeat_byte(0x11))
                .unwrap(),
            B256::ZERO
        );
        assert!(
            native
                .derive_account(
                    B256::ZERO,
                    1,
                    &[INativeMultisig::MultisigOwner {
                        owner: Address::repeat_byte(0x22),
                        weight: 1
                    }]
                )
                .is_err()
        );
    });
}
