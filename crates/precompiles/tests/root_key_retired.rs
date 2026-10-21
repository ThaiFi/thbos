//! Permits and channel vouchers signed by a root key whose account has a configuration commitment.

use alloy::{
    primitives::{Address, B256, Bytes, U256, aliases::U96, keccak256},
    sol_types::SolValue,
};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use tempo_chainspec::hardfork::TempoHardfork::{self, T13, T14};
use tempo_contracts::precompiles::{
    ITIP20, ITIP20ChannelReserve, TIP20ChannelReserveError, TIP20Error,
};
use tempo_precompiles::{
    error::TempoPrecompileError,
    storage::{
        ConfigCommitmentWriteGas, ContractStorage, StorageCtx, hashmap::HashMapStorageProvider,
    },
    test_util::TIP20Setup,
    tip20::PERMIT_TYPEHASH,
    tip20_channel_reserve::TIP20ChannelReserve,
};

use Party::{Delegate, Payer};

const COMMITMENT: B256 = B256::repeat_byte(0x11);

/// The payer of a channel, or the separate signer it authorizes to sign vouchers.
#[derive(Clone, Copy)]
enum Party {
    Payer,
    Delegate,
}

/// Storage at T14, with a commitment on each of `committed`, running at `spec`.
fn storage_at(spec: TempoHardfork, committed: &[Address]) -> HashMapStorageProvider {
    let mut storage = HashMapStorageProvider::new_with_spec(1, T14);
    StorageCtx::enter(&mut storage, || {
        for account in committed {
            StorageCtx
                .set_config_commitment(*account, COMMITMENT, ConfigCommitmentWriteGas::Intrinsic)
                .unwrap();
        }
    });
    storage.set_spec(spec);
    storage
}

/// Submits a permit signed by a fresh owner, with a commitment on the owner when `committed`.
/// Returns the owner, the permit result and the owner's nonce afterwards.
fn permit(
    spec: TempoHardfork,
    committed: bool,
) -> (Address, Result<(), TempoPrecompileError>, U256) {
    let signer = PrivateKeySigner::random();
    let owner = signer.address();
    let spender = Address::repeat_byte(0x22);
    let committed: &[Address] = if committed { &[owner] } else { &[] };
    let mut storage = storage_at(spec, committed);
    StorageCtx::enter(&mut storage, || {
        let admin = Address::repeat_byte(0x33);
        let mut token = TIP20Setup::create("Test", "TST", admin).apply().unwrap();
        let (value, nonce, deadline) = (U256::from(1_000), U256::ZERO, U256::MAX);
        let struct_hash =
            keccak256((PERMIT_TYPEHASH, owner, spender, value, nonce, deadline).abi_encode());
        let digest = keccak256(
            [
                &[0x19, 0x01],
                token.domain_separator().unwrap().as_slice(),
                struct_hash.as_slice(),
            ]
            .concat(),
        );
        let signature = signer.sign_hash_sync(&digest).unwrap();
        let result = token.permit(ITIP20::permitCall {
            owner,
            spender,
            value,
            deadline,
            v: signature.v_byte(),
            r: signature.r().into(),
            s: signature.s().into(),
        });
        let nonce = token.nonces(ITIP20::noncesCall { owner }).unwrap();
        (owner, result, nonce)
    })
}

#[test]
fn permit_by_a_root_with_a_commitment_is_rejected_from_t14() {
    for (name, spec, committed, rejected) in [
        ("committed root", T14, true, true),
        ("uncommitted root", T14, false, false),
        ("committed root before T14", T13, true, false),
    ] {
        let (owner, result, nonce) = permit(spec, committed);
        if rejected {
            assert_eq!(
                result.expect_err(name),
                TIP20Error::root_key_retired(owner).into(),
                "{name}"
            );
            // The rejected permit consumes no nonce.
            assert_eq!(nonce, U256::ZERO, "{name}");
        } else {
            result.expect(name);
            assert_eq!(nonce, U256::ONE, "{name}");
        }
    }
}

/// Opens a channel from a fresh payer, authorizing a separate signer when `signer` is the
/// delegate, and settles a voucher signed by `signer`, with a commitment on `committed`.
/// Returns the signer's address and the settle result.
fn settle(
    spec: TempoHardfork,
    signer: Party,
    committed: Party,
) -> (Address, Result<(), TempoPrecompileError>) {
    let payer_signer = PrivateKeySigner::random();
    let payer = payer_signer.address();
    let delegate = PrivateKeySigner::random();
    let delegate_address = delegate.address();
    let committed = match committed {
        Payer => payer,
        Delegate => delegate_address,
    };
    let (authorized_signer, voucher_signer) = match signer {
        Payer => (Address::ZERO, payer_signer),
        Delegate => (delegate_address, delegate),
    };
    let payee = Address::repeat_byte(0x44);
    let mut storage = storage_at(spec, &[committed]);
    let result = StorageCtx::enter(&mut storage, || {
        let token = TIP20Setup::path_usd(payer)
            .with_issuer(payer)
            .with_mint(payer, U256::from(200))
            .apply()
            .unwrap();
        let mut reserve = TIP20ChannelReserve::new();
        reserve.initialize().unwrap();
        let salt = B256::repeat_byte(0x55);
        let expiring_nonce_hash = B256::repeat_byte(0x66);
        reserve
            .set_channel_open_context_hash(expiring_nonce_hash)
            .unwrap();
        let channel_id = reserve
            .open(
                payer,
                ITIP20ChannelReserve::openCall {
                    payee,
                    operator: Address::ZERO,
                    token: token.address(),
                    deposit: U96::from(100),
                    salt,
                    authorizedSigner: authorized_signer,
                },
            )
            .unwrap();
        let cumulative_amount = U96::from(40);
        let digest = reserve
            .get_voucher_digest(ITIP20ChannelReserve::getVoucherDigestCall {
                channelId: channel_id,
                cumulativeAmount: cumulative_amount,
            })
            .unwrap();
        let signature = Bytes::from(voucher_signer.sign_hash_sync(&digest).unwrap().as_bytes());
        reserve.settle(
            payee,
            ITIP20ChannelReserve::settleCall {
                descriptor: ITIP20ChannelReserve::ChannelDescriptor {
                    payer,
                    payee,
                    operator: Address::ZERO,
                    token: token.address(),
                    salt,
                    authorizedSigner: authorized_signer,
                    expiringNonceHash: expiring_nonce_hash,
                },
                cumulativeAmount: cumulative_amount,
                signature,
            },
        )
    });
    (voucher_signer.address(), result)
}

#[test]
fn voucher_by_a_signer_with_a_commitment_is_rejected_from_t14() {
    for (name, spec, signer, committed, rejected) in [
        ("committed payer", T14, Payer, Payer, true),
        ("committed delegate", T14, Delegate, Delegate, true),
        // Only the channel's expected signer is checked.
        ("committed payer, delegated", T14, Delegate, Payer, false),
        ("committed payer before T14", T13, Payer, Payer, false),
    ] {
        let (signer, result) = settle(spec, signer, committed);
        if rejected {
            assert_eq!(
                result.expect_err(name),
                TIP20ChannelReserveError::root_key_retired(signer).into(),
                "{name}"
            );
        } else {
            result.expect(name);
        }
    }
}
