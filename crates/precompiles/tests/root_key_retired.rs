//! Permits and channel vouchers signed by a root key whose account has a configuration commitment.

use alloy::{
    primitives::{Address, B256, Bytes, U256, aliases::U96, keccak256},
    sol_types::SolValue,
};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use tempo_chainspec::hardfork::TempoHardfork;
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

const COMMITMENT: B256 = B256::repeat_byte(0x11);

/// Storage at T14, with a commitment on each of `committed`, running at `spec`.
fn storage_at(spec: TempoHardfork, committed: &[Address]) -> HashMapStorageProvider {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
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
            v: u8::from(signature.v()) + 27,
            r: signature.r().into(),
            s: signature.s().into(),
        });
        let nonce = token.nonces(ITIP20::noncesCall { owner }).unwrap();
        (owner, result, nonce)
    })
}

#[test]
fn permit_by_retired_root_is_rejected_at_t14() {
    let (owner, result, nonce) = permit(TempoHardfork::T14, true);
    assert_eq!(
        result.unwrap_err(),
        TIP20Error::root_key_retired(owner).into()
    );
    // The rejected permit consumes no nonce.
    assert_eq!(nonce, U256::ZERO);
}

#[test]
fn permit_without_commitment_is_accepted_at_t14() {
    let (_, result, nonce) = permit(TempoHardfork::T14, false);
    result.unwrap();
    assert_eq!(nonce, U256::ONE);
}

#[test]
fn permit_ignores_commitment_before_t14() {
    let (_, result, nonce) = permit(TempoHardfork::T13, true);
    result.unwrap();
    assert_eq!(nonce, U256::ONE);
}

/// Which account of a channel has a configuration commitment.
#[derive(Clone, Copy)]
enum Committed {
    Payer,
    AuthorizedSigner,
}

/// Opens a channel from a fresh payer, with a separate authorized signer when `delegated`, and
/// settles a voucher signed by the channel's expected signer. Returns that signer and the settle
/// result.
fn settle(
    spec: TempoHardfork,
    delegated: bool,
    committed: Committed,
) -> (Address, Result<(), TempoPrecompileError>) {
    let payer_signer = PrivateKeySigner::random();
    let payer = payer_signer.address();
    let delegate = PrivateKeySigner::random();
    let (authorized_signer, voucher_signer) = if delegated {
        (delegate.address(), delegate)
    } else {
        (Address::ZERO, payer_signer)
    };
    let committed = match committed {
        Committed::Payer => payer,
        Committed::AuthorizedSigner => authorized_signer,
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
fn voucher_by_retired_payer_is_rejected_at_t14() {
    let (signer, result) = settle(TempoHardfork::T14, false, Committed::Payer);
    assert_eq!(
        result.unwrap_err(),
        TIP20ChannelReserveError::root_key_retired(signer).into()
    );
}

#[test]
fn voucher_by_retired_authorized_signer_is_rejected_at_t14() {
    let (signer, result) = settle(TempoHardfork::T14, true, Committed::AuthorizedSigner);
    assert_eq!(
        result.unwrap_err(),
        TIP20ChannelReserveError::root_key_retired(signer).into()
    );
}

#[test]
fn voucher_checks_only_the_expected_signer_at_t14() {
    // The payer is committed, but the voucher is signed by its uncommitted authorized signer.
    let (_, result) = settle(TempoHardfork::T14, true, Committed::Payer);
    result.unwrap();
}

#[test]
fn voucher_ignores_commitment_before_t14() {
    let (_, result) = settle(TempoHardfork::T13, false, Committed::Payer);
    result.unwrap();
}
