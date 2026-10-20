//! Native multisig types of published `tempo-primitives`, exercised through their public API.

use alloy_primitives::{Address, B256, Bytes, U256, address, b256, keccak256};
use alloy_rlp::{Decodable, Encodable, Error as RlpError, Header, decode_exact};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use proptest::prelude::*;
use tempo_primitives::transaction::{
    ACCOUNT_PROXY_INIT_CODE_HASH, KeychainSignature, MAX_MULTISIG_OWNER_SIGNATURE_BYTES,
    MAX_MULTISIG_OWNERS, MAX_MULTISIG_SIGNATURES, MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN,
    MULTISIG_ACCOUNT_DOMAIN, MULTISIG_CONFIG_DOMAIN, MULTISIG_SIGNATURE_DOMAIN, MultisigConfig,
    MultisigConfigError, MultisigOwner, MultisigQuorumError, MultisigSignature,
    MultisigSignatureError, MultisigWeightAccumulator, PrimitiveSignature, SIGNATURE_TYPE_MULTISIG,
    TempoSignature, multisig_digest, tt_signature::WebAuthnSignature,
};

// Deliberately non-production factory fixture: TIP-1110 has not selected its public address.
const TEST_FACTORY: Address = Address::repeat_byte(0x99);

fn current_config(owner: Address) -> MultisigConfig {
    MultisigConfig {
        salt: B256::ZERO,
        version: 1,
        threshold: 1,
        owners: vec![MultisigOwner { owner, weight: 1 }],
    }
}

fn sign_hash(signer: &PrivateKeySigner, digest: &B256) -> PrimitiveSignature {
    PrimitiveSignature::Secp256k1(signer.sign_hash_sync(digest).expect("signing failed"))
}

fn sorted_secp_config(owners: &[(Address, u8)], threshold: u8) -> MultisigConfig {
    let mut owners = owners
        .iter()
        .map(|(owner, weight)| MultisigOwner {
            owner: *owner,
            weight: *weight,
        })
        .collect::<Vec<_>>();
    owners.sort_by_key(|owner| owner.owner);
    MultisigConfig {
        salt: B256::ZERO,
        version: 0,
        threshold,
        owners,
    }
}

fn indexed_owner(index: u16) -> Address {
    Address::left_padding_from(&index.to_be_bytes())
}

fn valid_owner_signature_bytes() -> Bytes {
    valid_owner_signature().to_bytes()
}

fn valid_owner_signature() -> PrimitiveSignature {
    PrimitiveSignature::default()
}

fn initial_multisig_signature() -> MultisigSignature {
    let config = sorted_secp_config(&[(indexed_owner(2), 1)], 1);
    MultisigSignature::try_new(
        config.derive_account(TEST_FACTORY).unwrap(),
        config,
        vec![PrimitiveSignature::default()],
    )
    .unwrap()
}

fn encoded_multisig(
    account: Address,
    config: &MultisigConfig,
    signatures: Vec<Vec<u8>>,
) -> Vec<u8> {
    let signatures = signatures.into_iter().map(Bytes::from).collect::<Vec<_>>();
    let payload_length = account.length() + config.length() + signatures.length();
    let mut encoded = Vec::new();
    Header {
        list: true,
        payload_length,
    }
    .encode(&mut encoded);
    account.encode(&mut encoded);
    config.encode(&mut encoded);
    signatures.encode(&mut encoded);
    encoded
}

/// Builds `levels` of nested current-configuration multisig signatures, where the innermost
/// approval is primitive and each outer level has a single nested multisig owner.
fn nested_multisig_encoding(levels: usize) -> Vec<u8> {
    let mut current = encoded_multisig(
        indexed_owner(100),
        &current_config(indexed_owner(200)),
        vec![valid_owner_signature_bytes().to_vec()],
    );
    for level in 1..u16::try_from(levels).unwrap() {
        let mut owner_approval = vec![SIGNATURE_TYPE_MULTISIG];
        owner_approval.extend_from_slice(&current);
        current = encoded_multisig(
            indexed_owner(100 + level),
            &current_config(indexed_owner(200 + level)),
            vec![owner_approval],
        );
    }
    current
}

fn assert_multisig_decode_rejected(encoded: &[u8]) {
    let mut input = encoded;
    assert!(MultisigSignature::decode(&mut input).is_err());
}

#[cfg(feature = "arbitrary")]
#[test]
fn arbitrary_bounded_approvals() {
    use arbitrary::{Arbitrary, Unstructured};

    let mut primitive_types = [false; 3];
    let mut approval_counts = [false; MAX_MULTISIG_SIGNATURES];
    let mut saw_max_webauthn = false;
    // 0xab repeated 10,000 times previously produced an oversized WebAuthn approval.
    for size in [0, 1, 256, 10_000] {
        for byte in 0..=u8::MAX {
            let input = vec![byte; size];
            let signature = MultisigSignature::arbitrary(&mut Unstructured::new(&input)).unwrap();
            approval_counts[signature.signatures().len() - 1] = true;
            for approval in signature.signatures() {
                assert!(approval.encoded_length() <= MAX_MULTISIG_OWNER_SIGNATURE_BYTES);
                match approval {
                    PrimitiveSignature::Secp256k1(_) => primitive_types[0] = true,
                    PrimitiveSignature::P256(_) => primitive_types[1] = true,
                    PrimitiveSignature::WebAuthn(_) => {
                        primitive_types[2] = true;
                        saw_max_webauthn |=
                            approval.encoded_length() == MAX_MULTISIG_OWNER_SIGNATURE_BYTES;
                    }
                }
            }
            let bytes = alloy_rlp::encode(&signature);
            assert_eq!(
                MultisigSignature::decode(&mut bytes.as_slice()).unwrap(),
                signature
            );
        }
    }
    assert!(primitive_types.into_iter().all(|seen| seen));
    assert!(approval_counts.into_iter().all(|seen| seen));
    assert!(saw_max_webauthn);
}

#[test]
fn validates_owner_order() {
    let owner_a = Address::repeat_byte(0x11);
    let owner_b = Address::repeat_byte(0x22);
    let config = sorted_secp_config(&[(owner_b, 2), (owner_a, 1)], 2);

    config.validate().expect("config is valid");

    let unsorted = MultisigConfig {
        salt: B256::ZERO,
        version: 0,
        threshold: 1,
        owners: vec![
            MultisigOwner {
                owner: owner_b,
                weight: 1,
            },
            MultisigOwner {
                owner: owner_a,
                weight: 1,
            },
        ],
    };
    assert!(unsorted.validate().is_err());
}

#[test]
fn rejects_nested_and_keychain_owner_encodings() {
    for depth in [2, 3, 4096] {
        assert_multisig_decode_rejected(&nested_multisig_encoding(depth));
    }
    for keychain in [
        KeychainSignature::new(indexed_owner(2), PrimitiveSignature::default()),
        KeychainSignature::new_v1(indexed_owner(2), PrimitiveSignature::default()),
    ] {
        let encoded = encoded_multisig(
            indexed_owner(1),
            &current_config(indexed_owner(2)),
            vec![TempoSignature::Keychain(keychain).to_bytes().to_vec()],
        );
        assert_multisig_decode_rejected(&encoded);
    }
}

#[test]
fn positive_versions_allow_primitive_self_ownership() {
    let account = indexed_owner(1);
    for version in [0, 1, u64::MAX] {
        let mut config = current_config(account);
        config.version = version;
        assert_eq!(config.validate_for_account(account).is_ok(), version > 0);
    }
}

#[test]
fn quorum_rejects_approvals_after_threshold() {
    let mut accumulator = MultisigWeightAccumulator::new(1).unwrap();
    accumulator.record_owner(indexed_owner(1), 1).unwrap();
    assert_eq!(
        accumulator.record_owner(indexed_owner(2), 1),
        Err(MultisigQuorumError::ExcessSignatures)
    );
}

#[test]
fn access_key_digest_binds_parent_before_multisig_domain() {
    let signature = initial_multisig_signature();
    let inner = B256::repeat_byte(0x42);
    let digest_a = signature.digest(KeychainSignature::signing_hash(inner, indexed_owner(3)));
    let digest_b = signature.digest(KeychainSignature::signing_hash(inner, indexed_owner(4)));
    assert_ne!(digest_a, digest_b);
}

#[test]
fn sixty_five_byte_owners_remain_untyped() {
    for first in [0x03, 0x04, 0x05] {
        let mut primitive = valid_owner_signature_bytes().to_vec();
        primitive[0] = first;
        let encoded = encoded_multisig(
            indexed_owner(1),
            &current_config(indexed_owner(2)),
            vec![primitive],
        );
        let decoded = MultisigSignature::decode(&mut encoded.as_slice()).unwrap();
        assert!(matches!(
            decoded.signatures()[0],
            PrimitiveSignature::Secp256k1(_)
        ));
    }
}

#[test]
fn account_derivation_includes_salt() {
    let owner = Address::repeat_byte(0x11);
    let zero_salt = sorted_secp_config(&[(owner, 1)], 1);
    let mut nonzero_salt = zero_salt.clone();
    nonzero_salt.salt = B256::repeat_byte(0x42);

    assert_ne!(
        zero_salt.derive_account(TEST_FACTORY).unwrap(),
        nonzero_salt.derive_account(TEST_FACTORY).unwrap()
    );
    zero_salt.validate().expect("zero salt is valid");
}

#[test]
fn multisig_domains_match_spec_vectors() {
    let mut config = sorted_secp_config(&[(Address::repeat_byte(0x11), 1)], 1);
    let account_salt = keccak256(config.account_salt_preimage().unwrap());
    let digest_account = address!("91847576f406d0842ad7c1a0c97c22a122e64278");

    assert_eq!(
        account_salt,
        b256!("7162e370e58784e6b33d61878820d1497eeaf4f68e00b2cfc00a2f3b1dbb00da")
    );
    // Independently reproduced with raw CREATE2 hashing over the placeholder account proxy hash.
    let expected = address!("d62b59cb4e41a0dd9000c71c6663df05e2bb910d");
    assert_eq!(
        TEST_FACTORY.create2(account_salt, ACCOUNT_PROXY_INIT_CODE_HASH),
        expected
    );
    assert_eq!(config.derive_account(TEST_FACTORY).unwrap(), expected);
    assert_eq!(
        multisig_digest(B256::repeat_byte(0x42), digest_account, 0),
        b256!("7a62ef46efdf76a6a0ab6c38c5fdeda2169d6a0de3643bb9912a4fbce881a870")
    );

    assert_eq!(
        config.commitment().unwrap(),
        b256!("a9e7d1e2ad25e227a4de5f38f3bba31d854ffc8efec46aaa8649097a516bb4ee")
    );
    config.version = 1;
    assert_eq!(
        config.commitment().unwrap(),
        b256!("6237ca5930f2265d4fb70a0305dd6ceea4df227053b4a62c304489ede946a2f8")
    );
    assert_eq!(
        multisig_digest(B256::repeat_byte(0x42), digest_account, 1),
        b256!("cceb022fd342beddcf6583e680c18a34936212276a680f026e52728b5ebb722b")
    );
}

#[test]
fn multisig_preimages_follow_documented_layout() {
    let owners = [(indexed_owner(1), 2), (indexed_owner(2), 3)];
    let mut config = sorted_secp_config(&owners, 4);
    config.salt = B256::repeat_byte(0x07);
    config.version = 9;

    let mut owner_set = vec![4, 2];
    for (owner, weight) in owners {
        owner_set.extend_from_slice(owner.as_slice());
        owner_set.push(weight);
    }

    let salt_preimage = [
        MULTISIG_ACCOUNT_DOMAIN,
        config.salt.as_slice(),
        owner_set.as_slice(),
    ]
    .concat();
    assert_eq!(config.account_salt_preimage().unwrap(), salt_preimage);
    assert_eq!(config.account_salt_preimage_len(), salt_preimage.len());

    let commitment_preimage = [
        MULTISIG_CONFIG_DOMAIN,
        config.salt.as_slice(),
        &config.version.to_be_bytes(),
        owner_set.as_slice(),
    ]
    .concat();
    assert_eq!(config.commitment_preimage().unwrap(), commitment_preimage);
    assert_eq!(config.commitment_preimage_len(), commitment_preimage.len());
    assert_eq!(
        config.commitment().unwrap(),
        keccak256(&commitment_preimage)
    );

    let create2_preimage = [
        &[0xff][..],
        TEST_FACTORY.as_slice(),
        keccak256(&salt_preimage).as_slice(),
        ACCOUNT_PROXY_INIT_CODE_HASH.as_slice(),
    ]
    .concat();
    assert_eq!(
        create2_preimage.len(),
        MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN
    );
    assert_eq!(
        config.derive_account(TEST_FACTORY).unwrap(),
        Address::from_word(keccak256(&create2_preimage))
    );

    let inner_digest = B256::repeat_byte(0x42);
    let account = Address::repeat_byte(0x11);
    let digest_preimage = [
        MULTISIG_SIGNATURE_DOMAIN,
        inner_digest.as_slice(),
        account.as_slice(),
        &config.version.to_be_bytes(),
    ]
    .concat();
    assert_eq!(
        multisig_digest(inner_digest, account, config.version),
        keccak256(digest_preimage)
    );
}

#[test]
fn multisig_signature_accessors_expose_committed_parts() {
    let config = sorted_secp_config(&[(indexed_owner(2), 1)], 1);
    let account = config.derive_account(TEST_FACTORY).unwrap();
    let signature =
        MultisigSignature::try_new(account, config.clone(), vec![PrimitiveSignature::default()])
            .unwrap();

    assert_eq!(signature.account(), account);
    assert_eq!(signature.config(), &config);
    assert_eq!(signature.config_commitment(), config.commitment().unwrap());
    assert_eq!(
        signature.digest(B256::ZERO),
        multisig_digest(B256::ZERO, account, config.version)
    );
}

#[test]
fn config_accepts_max_owners() {
    let owners = (1..=u16::try_from(MAX_MULTISIG_OWNERS).unwrap())
        .map(|index| (indexed_owner(index), 1))
        .collect::<Vec<_>>();
    let config = sorted_secp_config(&owners, u8::try_from(MAX_MULTISIG_SIGNATURES).unwrap());

    assert_eq!(
        config.validate(),
        Ok(u8::try_from(MAX_MULTISIG_OWNERS).unwrap())
    );
    assert!(config.derive_account(TEST_FACTORY).is_ok());
}

#[test]
fn config_rejects_more_than_max_owners() {
    let owners = (1..=u16::try_from(MAX_MULTISIG_OWNERS).unwrap() + 1)
        .map(|index| (indexed_owner(index), 1))
        .collect::<Vec<_>>();
    let config = sorted_secp_config(&owners, 1);

    assert_eq!(config.validate(), Err(MultisigConfigError::TooManyOwners));
}

#[test]
fn config_total_weight_is_capped_at_u8_max() {
    let owner_a = Address::repeat_byte(0x11);
    let owner_b = Address::repeat_byte(0x22);
    let config = sorted_secp_config(&[(owner_a, 128), (owner_b, 128)], 1);

    assert_eq!(
        config.validate(),
        Err(MultisigConfigError::TotalWeightExceedsMax)
    );
}

#[test]
fn config_accepts_max_threshold() {
    let owner = Address::repeat_byte(0x11);
    let threshold = u8::MAX;
    let config = sorted_secp_config(&[(owner, threshold)], threshold);

    assert_eq!(config.validate(), Ok(threshold));
}

#[test]
fn config_rejects_threshold_requiring_too_many_approvals() {
    let owners = (1..=u16::try_from(MAX_MULTISIG_SIGNATURES).unwrap() + 1)
        .map(|index| (indexed_owner(index), if index == 1 { 1 } else { 30 }))
        .collect::<Vec<_>>();
    let config = sorted_secp_config(&owners, 240);
    assert_eq!(config.validate(), Ok(241));

    let config = sorted_secp_config(&owners, 241);
    assert_eq!(
        config.validate(),
        Err(MultisigConfigError::ThresholdExceedsWeight)
    );
}

#[test]
fn config_rejects_own_account_as_owner() {
    let account = indexed_owner(1);
    let config = sorted_secp_config(&[(account, 1)], 1);

    assert_eq!(
        config.validate_for_account(account),
        Err(MultisigConfigError::AccountIsOwner)
    );

    let config = sorted_secp_config(&[(account, 0)], 1);
    assert_eq!(
        config.validate_for_account(account),
        Err(MultisigConfigError::AccountIsOwner)
    );
}

#[test]
fn shared_quorum_helpers_verify_order_and_threshold() {
    let owner_a = indexed_owner(1);
    let owner_b = indexed_owner(2);
    let owner_c = indexed_owner(3);
    let config = sorted_secp_config(&[(owner_a, 1), (owner_b, 3), (owner_c, 2)], 4);

    // Reproduce the weight-accounting the native multisig verifier performs: look up each
    // recovered owner's configured weight and feed it to the shared accumulator in order.
    let ordered_weights = |owners: &[Address]| -> Result<(), MultisigQuorumError> {
        let mut accumulator = MultisigWeightAccumulator::new(config.threshold)?;
        for &owner in owners {
            let weight = config
                .owner_weight(owner)
                .ok_or(MultisigQuorumError::SignerNotOwner)?;
            accumulator.record_owner(owner, weight)?;
        }
        accumulator.finish()
    };

    assert_eq!(ordered_weights(&[owner_a, owner_b]), Ok(()));
    assert_eq!(
        ordered_weights(&[owner_b]),
        Err(MultisigQuorumError::WeightBelowThreshold)
    );
    assert_eq!(
        ordered_weights(&[owner_b, owner_a]),
        Err(MultisigQuorumError::SignersNotAscending)
    );
    assert_eq!(
        ordered_weights(&[indexed_owner(4)]),
        Err(MultisigQuorumError::SignerNotOwner)
    );

    assert_eq!(
        MultisigWeightAccumulator::new(0).err(),
        Some(MultisigQuorumError::ZeroThreshold)
    );
}

#[test]
fn owner_signature_cannot_replay_across_accounts_with_same_owners() {
    let signer = PrivateKeySigner::random();
    let owner = signer.address();
    let mut config_a = sorted_secp_config(&[(owner, 1)], 1);
    config_a.salt = B256::repeat_byte(0x11);
    let mut config_b = sorted_secp_config(&[(owner, 1)], 1);
    config_b.salt = B256::repeat_byte(0x22);

    let account_a = config_a.derive_account(TEST_FACTORY).unwrap();
    let account_b = config_b.derive_account(TEST_FACTORY).unwrap();
    assert_ne!(account_a, account_b);

    let inner_digest = B256::repeat_byte(0x42);
    let digest_a = multisig_digest(inner_digest, account_a, 0);
    let digest_b = multisig_digest(inner_digest, account_b, 0);
    assert_ne!(digest_a, digest_b, "digest is domain-separated by account");

    // An owner approval recovers the owner only against the account it was signed for; replaying
    // it against another account's digest recovers a different address that is not an owner.
    let signature = sign_hash(&signer, &digest_a);
    assert_eq!(signature.recover_signer(&digest_a).unwrap(), owner);
    assert_ne!(signature.recover_signer(&digest_b).unwrap(), owner);
}

#[test]
fn owner_signature_cannot_replay_across_config_versions() {
    let signer = PrivateKeySigner::random();
    let owner = signer.address();
    let config = sorted_secp_config(&[(owner, 1)], 1);
    let account = config.derive_account(TEST_FACTORY).unwrap();
    let inner_digest = B256::repeat_byte(0x42);
    let initial_digest = multisig_digest(inner_digest, account, 0);
    let rotated_digest = multisig_digest(inner_digest, account, 1);

    assert_ne!(initial_digest, rotated_digest);
    let signature = sign_hash(&signer, &initial_digest);
    assert_eq!(signature.recover_signer(&initial_digest).unwrap(), owner);
    assert_ne!(signature.recover_signer(&rotated_digest).unwrap(), owner);
}

#[test]
fn verifies_weighted_owner_signatures_in_sorted_order() {
    let signer_a = PrivateKeySigner::random();
    let owner_a = signer_a.address();
    let signer_b = PrivateKeySigner::random();
    let owner_b = signer_b.address();
    let config = sorted_secp_config(&[(owner_a, 1), (owner_b, 1)], 2);
    let account = config.derive_account(TEST_FACTORY).unwrap();
    let digest = multisig_digest(B256::repeat_byte(0x42), account, 0);

    let mut signed = [
        (owner_a, sign_hash(&signer_a, &digest)),
        (owner_b, sign_hash(&signer_b, &digest)),
    ];
    signed.sort_by_key(|(owner, _)| *owner);

    // Feed the recovered owners through the shared accumulator, as the verifier does.
    let quorum_weight = |approvals: &[&PrimitiveSignature]| -> Result<(), MultisigQuorumError> {
        let mut accumulator = MultisigWeightAccumulator::new(config.threshold)?;
        for approval in approvals {
            let owner = approval.recover_signer(&digest).unwrap();
            let weight = config
                .owner_weight(owner)
                .ok_or(MultisigQuorumError::SignerNotOwner)?;
            accumulator.record_owner(owner, weight)?;
        }
        accumulator.finish()
    };

    let both = [&signed[0].1, &signed[1].1];
    assert_eq!(quorum_weight(&both), Ok(()));

    // A single owner falls short of the threshold of 2.
    assert!(quorum_weight(&[&signed[0].1]).is_err());
}

#[test]
fn multisig_signature_encodes_complete_config() {
    let config = current_config(indexed_owner(2));
    let account = Address::repeat_byte(0x11);
    let signatures = [valid_owner_signature_bytes()];
    let signature =
        MultisigSignature::try_new(account, config.clone(), vec![valid_owner_signature()]).unwrap();

    let encoded = alloy_rlp::encode(&signature);
    assert_eq!(
        encoded,
        encoded_multisig(
            account,
            &config,
            signatures
                .iter()
                .map(|signature| signature.to_vec())
                .collect(),
        )
    );

    let decoded = decode_exact::<MultisigSignature>(encoded.as_slice()).unwrap();
    assert_eq!(decoded, signature);
}

#[test]
fn multisig_signature_decode_rejects_invalid_config() {
    let invalid_config = MultisigConfig {
        salt: B256::ZERO,
        version: 0,
        threshold: 0,
        owners: Vec::new(),
    };
    let encoded = encoded_multisig(
        Address::repeat_byte(0x11),
        &invalid_config,
        vec![valid_owner_signature_bytes().to_vec()],
    );

    assert_multisig_decode_rejected(&encoded);
}

#[test]
fn multisig_config_validates_owner_count_after_decoding() {
    let config = MultisigConfig {
        salt: B256::ZERO,
        version: 0,
        threshold: u8::try_from(MAX_MULTISIG_SIGNATURES).unwrap(),
        owners: (1..=u16::try_from(MAX_MULTISIG_OWNERS).unwrap() + 1)
            .map(|index| MultisigOwner {
                owner: Address::from_word(B256::from(U256::from(index))),
                weight: 1,
            })
            .collect(),
    };
    let decoded = decode_exact::<MultisigConfig>(&alloy_rlp::encode(&config)).unwrap();
    assert_eq!(decoded, config);
    assert_eq!(decoded.validate(), Err(MultisigConfigError::TooManyOwners));

    let encoded = encoded_multisig(
        Address::repeat_byte(0x11),
        &decoded,
        vec![valid_owner_signature_bytes().to_vec()],
    );
    assert_multisig_decode_rejected(&encoded);
}

#[test]
fn multisig_signature_decode_rejects_excess_approvals() {
    let encoded = encoded_multisig(
        Address::repeat_byte(0x11),
        &current_config(indexed_owner(2)),
        vec![valid_owner_signature_bytes().to_vec(); MAX_MULTISIG_SIGNATURES + 1],
    );

    let mut input = encoded.as_slice();
    assert!(matches!(
        MultisigSignature::decode(&mut input),
        Err(RlpError::Custom("too many multisig signatures"))
    ));
}

#[test]
fn multisig_signature_shape_rejects_oversized_owner_signature() {
    // A WebAuthn envelope one byte over the 2049-byte owner cap, not an unknown tag.
    let owner_signature = PrimitiveSignature::WebAuthn(WebAuthnSignature {
        webauthn_data: Bytes::from(vec![0; MAX_MULTISIG_OWNER_SIGNATURE_BYTES - 128]),
        r: B256::ZERO,
        s: B256::ZERO,
        pub_key_x: B256::ZERO,
        pub_key_y: B256::ZERO,
    });
    let bytes = owner_signature.to_bytes();
    assert_eq!(bytes.len(), MAX_MULTISIG_OWNER_SIGNATURE_BYTES + 1);
    assert_eq!(
        MultisigSignature::try_new(
            Address::repeat_byte(0x11),
            current_config(indexed_owner(2)),
            vec![owner_signature],
        ),
        Err(MultisigSignatureError::OwnerSignatureTooLarge)
    );
    let encoded = encoded_multisig(
        Address::repeat_byte(0x11),
        &current_config(indexed_owner(2)),
        vec![bytes.to_vec()],
    );
    assert_eq!(
        MultisigSignature::decode(&mut encoded.as_slice()),
        Err(RlpError::Custom("Invalid WebAuthn signature length")),
    );
}

#[cfg(feature = "serde")]
mod serde_json_and_binary {
    use super::{
        MAX_MULTISIG_SIGNATURES, MultisigSignature, PrimitiveSignature, TEST_FACTORY,
        current_config, encoded_multisig, indexed_owner, multisig_digest, nested_multisig_encoding,
        sign_hash, sorted_secp_config, valid_owner_signature_bytes,
    };
    use alloy_primitives::{Address, B256, Bytes};
    use alloy_signer_local::PrivateKeySigner;
    use serde::{
        Deserialize as _,
        de::value::{BorrowedBytesDeserializer, Error as DeError},
    };
    use serde_json::{from_value, json, to_value};

    fn decode_binary_multisig(bytes: &[u8]) -> Result<MultisigSignature, DeError> {
        MultisigSignature::deserialize(BorrowedBytesDeserializer::new(bytes))
    }

    fn malformed_multisig_encodings() -> [Vec<u8>; 2] {
        [
            encoded_multisig(
                indexed_owner(1),
                &current_config(indexed_owner(2)),
                vec![valid_owner_signature_bytes().to_vec(); MAX_MULTISIG_SIGNATURES + 1],
            ),
            nested_multisig_encoding(4_096),
        ]
    }

    #[test]
    fn multisig_signature_serde_roundtrips_rlp_bytes() {
        let signer = PrivateKeySigner::random();
        let owner = signer.address();
        let config = sorted_secp_config(&[(owner, 1)], 1);
        let account = config.derive_account(TEST_FACTORY).unwrap();
        let digest = multisig_digest(B256::ZERO, account, 0);
        let owner_signature = sign_hash(&signer, &digest);
        let signatures = vec![owner_signature];

        let signature = MultisigSignature::try_new(account, config, signatures).unwrap();
        let mut encoded = alloy_rlp::encode(&signature);
        let json = to_value(&signature).unwrap();
        assert_eq!(json, to_value(Bytes::from(encoded.clone())).unwrap());
        assert_eq!(from_value::<MultisigSignature>(json).unwrap(), signature);
        encoded.push(0x80);
        let json = to_value(Bytes::from(encoded)).unwrap();
        assert!(from_value::<MultisigSignature>(json).is_err());
    }

    #[test]
    fn multisig_signature_json_bytes_reject_malformed_shapes() {
        for encoded in malformed_multisig_encodings() {
            let json = to_value(Bytes::from(encoded)).unwrap();
            assert!(from_value::<MultisigSignature>(json).is_err());
        }
    }

    #[test]
    fn multisig_signature_json_rejects_structured_form() {
        let json = json!({
            "account": Address::repeat_byte(0x11),
            "signatures": [],
        });
        assert!(from_value::<MultisigSignature>(json).is_err());
    }

    #[test]
    fn binary_multisig_deserializer_roundtrips_bytes() {
        let signature = MultisigSignature::try_new(
            indexed_owner(2),
            current_config(indexed_owner(3)),
            vec![PrimitiveSignature::default()],
        )
        .unwrap();

        let encoded = alloy_rlp::encode(&signature);
        let decoded = decode_binary_multisig(&encoded).unwrap();

        assert_eq!(decoded, signature);
    }

    #[test]
    fn binary_multisig_deserializer_bounds_shape_before_typed_recursion() {
        for encoded in malformed_multisig_encodings() {
            assert!(decode_binary_multisig(&encoded).is_err());
        }
    }
}

proptest! {
    #[test]
    fn proptest_multisig_signature_decode_encode_canonicalizes_accepted_raw_bytes(
        raw in prop_oneof![
            prop::collection::vec(any::<u8>(), 0..256),
            (
                any::<Address>(),
                prop::collection::vec(prop::collection::vec(any::<u8>(), 0..128), 0..=MAX_MULTISIG_SIGNATURES),
            ).prop_map(|(account, signatures)| {
                encoded_multisig(account, &current_config(indexed_owner(2)), signatures)
            }),
        ],
    ) {
        let first = decode_exact::<MultisigSignature>(raw.as_slice());
        match first {
            Ok(decoded) => {
                let reencoded = alloy_rlp::encode(&decoded);

                let canonical_decoded =
                    decode_exact::<MultisigSignature>(reencoded.as_slice()).unwrap();
                prop_assert_eq!(&canonical_decoded, &decoded);

                let canonical_reencoded = alloy_rlp::encode(&canonical_decoded);
                prop_assert_eq!(canonical_reencoded, reencoded);
            }
            Err(error) => {
                let second = decode_exact::<MultisigSignature>(raw.as_slice());
                prop_assert_eq!(second, Err(error));
            }
        }
    }
}
