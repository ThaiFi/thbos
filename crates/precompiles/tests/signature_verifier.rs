//! Keychain signature verification against retired roots and stored key types.

use alloy::primitives::{Address, B256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::IAccountKeychain::{KeyRestrictions, SignatureType};
use tempo_precompiles::{
    account_keychain::AccountKeychain,
    signature_verifier::SignatureVerifier,
    storage::{ConfigCommitmentWriteGas, StorageCtx, hashmap::HashMapStorageProvider},
};
use tempo_primitives::transaction::tt_signature::{
    KeychainSignature, P256SignatureWithPreHash, PrimitiveSignature, TempoSignature,
    derive_p256_address, normalize_p256_s,
};

const HASH: B256 = B256::repeat_byte(0x42);
const COMMITMENT: B256 = B256::repeat_byte(0x11);

/// A signing key of one of the primitive signature types.
enum Key {
    Secp256k1(PrivateKeySigner),
    P256(SigningKey),
}

impl Key {
    fn random(signature_type: SignatureType) -> Self {
        match signature_type {
            SignatureType::Secp256k1 => Self::Secp256k1(PrivateKeySigner::random()),
            SignatureType::P256 => Self::P256(SigningKey::random(&mut OsRng)),
            other => panic!("unsupported test key type {other:?}"),
        }
    }

    fn p256_coordinates(key: &SigningKey) -> (B256, B256) {
        let point = key.verifying_key().to_encoded_point(false);
        (
            B256::from_slice(point.x().unwrap()),
            B256::from_slice(point.y().unwrap()),
        )
    }

    /// The address a signature by this key recovers to.
    fn address(&self) -> Address {
        match self {
            Self::Secp256k1(signer) => signer.address(),
            Self::P256(key) => {
                let (x, y) = Self::p256_coordinates(key);
                derive_p256_address(&x, &y)
            }
        }
    }

    fn sign(&self, digest: B256) -> PrimitiveSignature {
        match self {
            Self::Secp256k1(signer) => {
                PrimitiveSignature::Secp256k1(signer.sign_hash_sync(&digest).unwrap())
            }
            Self::P256(key) => {
                let (pub_key_x, pub_key_y) = Self::p256_coordinates(key);
                let (signature, _) = key.sign_prehash_recoverable(digest.as_slice()).unwrap();
                PrimitiveSignature::P256(P256SignatureWithPreHash {
                    r: B256::from_slice(&signature.r().to_bytes()),
                    s: normalize_p256_s(&signature.s().to_bytes()).unwrap(),
                    pub_key_x,
                    pub_key_y,
                    pre_hash: false,
                })
            }
        }
    }
}

/// An access-key grant from the account to the signing key.
#[derive(Clone, Copy)]
struct Grant {
    stored_type: SignatureType,
    admin: bool,
}

/// Results of verifying one keychain signature both ways.
#[derive(Debug, PartialEq, Eq)]
struct Verdict {
    keychain: bool,
    keychain_admin: bool,
}

const fn verdict(keychain: bool, keychain_admin: bool) -> Verdict {
    Verdict {
        keychain,
        keychain_admin,
    }
}

/// Storage at T14 with `grant` registered and a commitment on each of `committed`, switched to
/// `spec` afterwards so that earlier forks can see state that only T14 can write.
fn storage_at(
    spec: TempoHardfork,
    account: Address,
    key_id: Address,
    grant: Option<Grant>,
    committed: &[Address],
) -> HashMapStorageProvider {
    let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
    StorageCtx::enter(&mut storage, || {
        let mut keychain = AccountKeychain::new();
        keychain.initialize().unwrap();
        keychain.set_tx_origin(account).unwrap();
        match grant {
            Some(Grant {
                stored_type,
                admin: true,
            }) => keychain
                .authorize_admin_key(account, key_id, stored_type, None)
                .unwrap(),
            Some(Grant {
                stored_type,
                admin: false,
            }) => keychain
                .authorize_key(
                    account,
                    key_id,
                    stored_type,
                    KeyRestrictions {
                        expiry: u64::MAX,
                        enforceLimits: false,
                        limits: Vec::new(),
                        allowAnyCalls: true,
                        allowedCalls: Vec::new(),
                    },
                    None,
                )
                .unwrap(),
            None => {}
        }
        for address in committed {
            StorageCtx
                .set_config_commitment(*address, COMMITMENT, ConfigCommitmentWriteGas::Intrinsic)
                .unwrap();
        }
    });
    storage.set_spec(spec);
    storage
}

/// Verifies a keychain signature over [`HASH`] that `signer` made for `account`.
fn verify(
    spec: TempoHardfork,
    account: Address,
    signer: &Key,
    grant: Option<Grant>,
    committed: &[Address],
) -> Verdict {
    let mut storage = storage_at(spec, account, signer.address(), grant, committed);
    let signature = TempoSignature::Keychain(KeychainSignature::new(
        account,
        signer.sign(KeychainSignature::signing_hash(HASH, account)),
    ))
    .to_bytes();
    StorageCtx::enter(&mut storage, || {
        let verifier = SignatureVerifier::new();
        verdict(
            verifier
                .verify_keychain(account, HASH, signature.clone())
                .unwrap(),
            verifier
                .verify_keychain_admin(account, HASH, signature)
                .unwrap(),
        )
    })
}

fn root() -> Key {
    Key::random(SignatureType::Secp256k1)
}

#[test]
fn root_admin_signature_is_rejected_once_the_root_is_retired() {
    let root = root();
    let account = root.address();
    // The root is implicitly admin, but is not an access key.
    for (spec, committed, admin) in [
        (TempoHardfork::T14, vec![], true),
        (TempoHardfork::T14, vec![account], false),
        (TempoHardfork::T13, vec![account], true),
    ] {
        assert_eq!(
            verify(spec, account, &root, None, &committed),
            verdict(false, admin),
            "{spec:?}, committed: {committed:?}"
        );
    }
}

#[test]
fn access_key_signature_is_rejected_when_the_key_is_a_retired_root() {
    for admin in [false, true] {
        let key = root();
        let account = Address::repeat_byte(0x01);
        let grant = Grant {
            stored_type: SignatureType::Secp256k1,
            admin,
        };
        for (spec, committed, accepted) in [
            (TempoHardfork::T14, vec![], true),
            (TempoHardfork::T14, vec![key.address()], false),
            // A commitment on the granting account does not retire the grantee.
            (TempoHardfork::T14, vec![account], true),
            (TempoHardfork::T13, vec![key.address()], true),
        ] {
            assert_eq!(
                verify(spec, account, &key, Some(grant), &committed),
                verdict(accepted, accepted && admin),
                "admin grant: {admin}, {spec:?}, committed: {committed:?}"
            );
        }
    }
}

#[test]
fn signature_type_must_match_the_stored_key_type_from_t14() {
    let key = Key::random(SignatureType::P256);
    let account = Address::repeat_byte(0x01);
    for (spec, stored_type, accepted) in [
        (TempoHardfork::T14, SignatureType::P256, true),
        (TempoHardfork::T14, SignatureType::Secp256k1, false),
        // Before T14 the stored type was not compared.
        (TempoHardfork::T13, SignatureType::P256, true),
        (TempoHardfork::T13, SignatureType::Secp256k1, true),
    ] {
        let grant = Grant {
            stored_type,
            admin: false,
        };
        assert_eq!(
            verify(spec, account, &key, Some(grant), &[]),
            verdict(accepted, false),
            "{spec:?}, stored: {stored_type:?}"
        );
    }
}

#[test]
fn keychain_signature_must_embed_the_verified_account() {
    let key = root();
    let account = Address::repeat_byte(0x01);
    let grant = Grant {
        stored_type: SignatureType::Secp256k1,
        admin: true,
    };
    let mut storage = storage_at(TempoHardfork::T14, account, key.address(), Some(grant), &[]);
    let signature = TempoSignature::Keychain(KeychainSignature::new(
        account,
        key.sign(KeychainSignature::signing_hash(HASH, account)),
    ))
    .to_bytes();
    StorageCtx::enter(&mut storage, || {
        let verifier = SignatureVerifier::new();
        let other = Address::repeat_byte(0x02);
        assert!(
            !verifier
                .verify_keychain(other, HASH, signature.clone())
                .unwrap()
        );
        assert!(
            !verifier
                .verify_keychain_admin(other, HASH, signature)
                .unwrap()
        );
    });
}

#[test]
fn implicit_root_admin_status_ends_with_the_commitment_from_t14() {
    let account = Address::repeat_byte(0x01);
    for (spec, committed, admin) in [
        (TempoHardfork::T14, vec![], true),
        (TempoHardfork::T14, vec![account], false),
        (TempoHardfork::T13, vec![account], true),
    ] {
        let mut storage = storage_at(spec, account, Address::repeat_byte(0x03), None, &committed);
        StorageCtx::enter(&mut storage, || {
            assert_eq!(
                AccountKeychain::new()
                    .is_admin_key(account, account)
                    .unwrap(),
                admin,
                "{spec:?}, committed: {committed:?}"
            );
        });
    }
}
