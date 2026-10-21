//! Signature verifier precompile selectors for configurable accounts.

use alloy::{
    primitives::{Address, B256, keccak256},
    sol_types::{SolCall, SolError, SolValue},
};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use evm2::precompiles::{PrecompileError, PrecompileResult};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{ISignatureVerifier, UnknownFunctionSelector};
use tempo_precompiles::{
    Precompile,
    signature_verifier::SignatureVerifier,
    storage::{StorageCtx, hashmap::HashMapStorageProvider},
};
use tempo_primitives::transaction::{
    ConfigurableAccountConfig, ConfigurableAccountOwner, ConfigurableAccountSignature,
    PrimitiveSignature, TempoSignature, configurable_account_digest,
};

const FACTORY: Address = Address::repeat_byte(0x71);

fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature)[..4].try_into().unwrap()
}

/// Calls the verifier with the selector of `signature` and the arguments of a
/// `(address,bytes32,bytes)` verification over a single-owner configurable account.
fn call_with_selector(selector_signature: &str) -> PrecompileResult {
    let signer = PrivateKeySigner::random();
    let config = ConfigurableAccountConfig {
        salt: B256::ZERO,
        version: 0,
        threshold: 1,
        owners: vec![ConfigurableAccountOwner {
            owner: signer.address(),
            weight: 1,
        }],
    };
    let account = config.derive_account(FACTORY).unwrap();
    let hash = B256::repeat_byte(0x42);
    let approval = signer
        .sign_hash_sync(&configurable_account_digest(hash, account, config.version))
        .unwrap();
    let signature = TempoSignature::ConfigurableAccount(
        ConfigurableAccountSignature::try_new(
            account,
            config,
            vec![PrimitiveSignature::Secp256k1(approval)],
        )
        .unwrap(),
    )
    .to_bytes();

    let mut calldata = selector(selector_signature).to_vec();
    ISignatureVerifier::verifyConfigurableAccountCall {
        account,
        hash,
        signature,
    }
    .abi_encode_raw(&mut calldata);

    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
    storage.set_configurable_account_recovery_factory(FACTORY);
    StorageCtx::enter(&mut storage, || {
        SignatureVerifier::new().call(&calldata, Address::ZERO)
    })
}

#[test]
fn verify_configurable_account_selector_is_dispatched_at_t14() {
    let output = call_with_selector("verifyConfigurableAccount(address,bytes32,bytes)")
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert!(bool::abi_decode(output.bytes()).unwrap());
}

#[test]
fn verify_multisig_selector_is_unknown_at_t14() {
    match call_with_selector("verifyMultisig(address,bytes32,bytes)") {
        Err(PrecompileError::Revert(bytes)) => {
            assert!(UnknownFunctionSelector::abi_decode(&bytes).is_ok())
        }
        other => panic!("expected unknown selector revert, got {other:?}"),
    }
}
