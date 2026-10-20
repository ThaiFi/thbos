//! Native multisig types of published `tempo-primitives`, exercised through their public API.

use alloy_primitives::{Address, B256, Bytes, Signature, U256, address, b256, keccak256};
use alloy_rlp::{Decodable, Encodable, Error as RlpError, Header, decode_exact};
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

/// A zero-salt config holding the `(owner, weight)` entries in the order given.
fn multisig_config(version: u64, threshold: u8, owners: &[(Address, u8)]) -> MultisigConfig {
    MultisigConfig {
        salt: B256::ZERO,
        version,
        threshold,
        owners: owners
            .iter()
            .map(|&(owner, weight)| MultisigOwner { owner, weight })
            .collect(),
    }
}

fn current_config(owner: Address) -> MultisigConfig {
    multisig_config(1, 1, &[(owner, 1)])
}

fn indexed_owner(index: u16) -> Address {
    Address::left_padding_from(&index.to_be_bytes())
}

/// `count` ascending owners of equal weight.
fn indexed_owners(count: usize, weight: u8) -> Vec<(Address, u8)> {
    (1..=u16::try_from(count).unwrap())
        .map(|index| (indexed_owner(index), weight))
        .collect()
}

/// A secp256k1 owner approval with fixed scalars: decoding checks its shape, not its signer.
fn owner_approval() -> PrimitiveSignature {
    PrimitiveSignature::Secp256k1(Signature::new(U256::from(1), U256::from(2), false))
}

/// A WebAuthn owner approval whose encoding is `encoded_len` bytes: the type byte, the
/// authenticator data and four 32-byte fields.
fn webauthn_approval(encoded_len: usize) -> PrimitiveSignature {
    PrimitiveSignature::WebAuthn(WebAuthnSignature {
        webauthn_data: Bytes::from(vec![0; encoded_len - 1 - 4 * 32]),
        r: B256::ZERO,
        s: B256::ZERO,
        pub_key_x: B256::ZERO,
        pub_key_y: B256::ZERO,
    })
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
        vec![owner_approval().to_bytes().to_vec()],
    );
    for level in 1..u16::try_from(levels).unwrap() {
        let mut nested_approval = vec![SIGNATURE_TYPE_MULTISIG];
        nested_approval.extend_from_slice(&current);
        current = encoded_multisig(
            indexed_owner(100 + level),
            &current_config(indexed_owner(200 + level)),
            vec![nested_approval],
        );
    }
    current
}

/// Encodings that multisig signature decoding rejects, each with the message of its error.
fn malformed_multisig_encodings() -> Vec<(&'static str, Vec<u8>, String)> {
    let account = indexed_owner(1);
    let config = current_config(indexed_owner(2));
    let approval = owner_approval().to_bytes().to_vec();
    // A nested multisig or keychain approval carries a type byte no primitive signature has.
    let unknown_type = RlpError::Custom("Unknown signature type identifier").to_string();
    let keychain_owner = |keychain: KeychainSignature| {
        encoded_multisig(
            account,
            &config,
            vec![TempoSignature::Keychain(keychain).to_bytes().to_vec()],
        )
    };
    vec![
        (
            "a nested multisig owner",
            nested_multisig_encoding(2),
            unknown_type.clone(),
        ),
        (
            "two levels of nested multisig owners",
            nested_multisig_encoding(3),
            unknown_type.clone(),
        ),
        (
            "4096 levels of nested multisig owners",
            nested_multisig_encoding(4096),
            unknown_type.clone(),
        ),
        (
            "a keychain owner",
            keychain_owner(KeychainSignature::new(indexed_owner(2), owner_approval())),
            unknown_type.clone(),
        ),
        (
            "a v1 keychain owner",
            keychain_owner(KeychainSignature::new_v1(
                indexed_owner(2),
                owner_approval(),
            )),
            unknown_type,
        ),
        (
            "an invalid config",
            encoded_multisig(account, &multisig_config(0, 0, &[]), vec![approval.clone()]),
            MultisigSignatureError::InvalidConfig(MultisigConfigError::EmptyOwners).to_string(),
        ),
        (
            "more owners than the cap",
            encoded_multisig(
                account,
                &multisig_config(0, 8, &indexed_owners(MAX_MULTISIG_OWNERS + 1, 1)),
                vec![approval.clone()],
            ),
            MultisigSignatureError::InvalidConfig(MultisigConfigError::TooManyOwners).to_string(),
        ),
        (
            "more approvals than the cap",
            encoded_multisig(
                account,
                &config,
                vec![approval; MAX_MULTISIG_SIGNATURES + 1],
            ),
            MultisigSignatureError::TooManySignatures.to_string(),
        ),
        // The primitive decoder bounds a WebAuthn approval before the owner size cap applies.
        (
            "an approval over the size cap",
            encoded_multisig(
                account,
                &config,
                vec![
                    webauthn_approval(MAX_MULTISIG_OWNER_SIGNATURE_BYTES + 1)
                        .to_bytes()
                        .to_vec(),
                ],
            ),
            RlpError::Custom("Invalid WebAuthn signature length").to_string(),
        ),
    ]
}

/// Owner-approval bytes of every primitive shape, accepted ones (with the non-canonical
/// secp256k1 parity bytes and P256 pre-hash flags that decoding normalizes) and arbitrary ones.
fn owner_approval_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        (
            prop::collection::vec(any::<u8>(), 64),
            prop::sample::select(vec![0u8, 1, 27, 28]),
        )
            .prop_map(|(scalars, parity)| [scalars, vec![parity]].concat()),
        prop::collection::vec(any::<u8>(), 129).prop_map(|fields| [vec![0x01], fields].concat()),
        prop::collection::vec(any::<u8>(), 128..=192)
            .prop_map(|fields| [vec![0x02], fields].concat()),
        prop::collection::vec(any::<u8>(), 0..=192),
    ]
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
fn config_validation_reports_the_first_broken_rule() {
    let [low, high] = [1, 2].map(indexed_owner);
    let account = indexed_owner(0x10);
    // Nine owners of weight 30 but one of weight 1: the eight heaviest reach 240, of 241.
    let one_light_owner = |index: usize| {
        let mut owners = indexed_owners(MAX_MULTISIG_SIGNATURES + 1, 30);
        owners[index].1 = 1;
        owners
    };

    for (case, config, for_account, expected) in [
        (
            "no owners, before the threshold",
            multisig_config(0, 0, &[]),
            None,
            Err(MultisigConfigError::EmptyOwners),
        ),
        (
            "more owners than the cap, before the threshold",
            multisig_config(0, 0, &indexed_owners(MAX_MULTISIG_OWNERS + 1, 1)),
            None,
            Err(MultisigConfigError::TooManyOwners),
        ),
        (
            "as many owners as the cap",
            multisig_config(0, 8, &indexed_owners(MAX_MULTISIG_OWNERS, 1)),
            None,
            Ok(48),
        ),
        (
            "a zero threshold, before every owner entry",
            multisig_config(0, 0, &[(Address::ZERO, 0)]),
            None,
            Err(MultisigConfigError::ZeroThreshold),
        ),
        (
            "a zero owner anywhere, before an earlier zero weight",
            multisig_config(0, 1, &[(low, 0), (Address::ZERO, 1)]),
            None,
            Err(MultisigConfigError::ZeroOwner),
        ),
        (
            "a zero weight",
            multisig_config(0, 1, &[(low, 1), (high, 0)]),
            None,
            Err(MultisigConfigError::ZeroWeight),
        ),
        (
            "a zero weight, before ordering",
            multisig_config(0, 1, &[(high, 1), (low, 0)]),
            None,
            Err(MultisigConfigError::ZeroWeight),
        ),
        (
            "an adjacent duplicate",
            multisig_config(0, 1, &[(low, 1), (low, 1)]),
            None,
            Err(MultisigConfigError::DuplicateOwner),
        ),
        (
            "a nonadjacent duplicate",
            multisig_config(0, 1, &[(low, 1), (high, 1), (low, 1)]),
            None,
            Err(MultisigConfigError::DuplicateOwner),
        ),
        (
            "descending owners, before the weight total",
            multisig_config(0, 1, &[(high, 128), (low, 128)]),
            None,
            Err(MultisigConfigError::OwnersNotAscending),
        ),
        (
            "ascending owners",
            multisig_config(0, 2, &[(low, 1), (high, 2)]),
            None,
            Ok(3),
        ),
        (
            "the largest threshold and total weight",
            multisig_config(0, u8::MAX, &[(low, u8::MAX)]),
            None,
            Ok(u8::MAX),
        ),
        // The eight heaviest of nine owners of weight 29 cannot reach the threshold either.
        (
            "a weight total past u8::MAX, before reachability",
            multisig_config(0, u8::MAX, &indexed_owners(MAX_MULTISIG_SIGNATURES + 1, 29)),
            None,
            Err(MultisigConfigError::TotalWeightExceedsMax),
        ),
        (
            "the eight heaviest owners reach the threshold, light owner first",
            multisig_config(0, 240, &one_light_owner(0)),
            None,
            Ok(241),
        ),
        (
            "a threshold past the eight heaviest owners",
            multisig_config(0, 241, &one_light_owner(0)),
            None,
            Err(MultisigConfigError::ThresholdExceedsWeight),
        ),
        (
            "an initial config owning its account",
            multisig_config(0, 1, &[(account, 1)]),
            Some(account),
            Err(MultisigConfigError::AccountIsOwner),
        ),
        (
            "self-ownership, before its own zero weight",
            multisig_config(0, 1, &[(account, 0)]),
            Some(account),
            Err(MultisigConfigError::AccountIsOwner),
        ),
        (
            "self-ownership anywhere, before an earlier zero weight",
            multisig_config(0, 1, &[(high, 0), (account, 1)]),
            Some(account),
            Err(MultisigConfigError::AccountIsOwner),
        ),
        (
            "a later version owning its account",
            multisig_config(1, 1, &[(account, 1)]),
            Some(account),
            Ok(1),
        ),
        (
            "the last version owning its account",
            multisig_config(u64::MAX, 1, &[(account, 1)]),
            Some(account),
            Ok(1),
        ),
    ] {
        match for_account {
            Some(account) => {
                assert_eq!(config.validate_for_account(account), expected, "{case}");
            }
            None => {
                assert_eq!(config.validate(), expected, "{case}");
            }
        }
    }
}

#[test]
fn multisig_signature_construction_reports_the_first_broken_rule() {
    let account = Address::repeat_byte(0x11);
    let config = current_config(indexed_owner(2));
    let empty_config = multisig_config(0, 0, &[]);
    let largest = webauthn_approval(MAX_MULTISIG_OWNER_SIGNATURE_BYTES);
    let oversized = webauthn_approval(MAX_MULTISIG_OWNER_SIGNATURE_BYTES + 1);
    assert_eq!(largest.encoded_length(), MAX_MULTISIG_OWNER_SIGNATURE_BYTES);
    assert_eq!(
        oversized.encoded_length(),
        MAX_MULTISIG_OWNER_SIGNATURE_BYTES + 1
    );

    for (case, account, config, approvals, expected) in [
        (
            "a zero account, before the config and the approvals",
            Address::ZERO,
            empty_config.clone(),
            Vec::new(),
            Err(MultisigSignatureError::ZeroAccount),
        ),
        (
            "an invalid config, before the approvals",
            account,
            empty_config,
            Vec::new(),
            Err(MultisigSignatureError::InvalidConfig(
                MultisigConfigError::EmptyOwners,
            )),
        ),
        (
            "initial self-ownership of the named account",
            account,
            multisig_config(0, 1, &[(account, 1)]),
            vec![owner_approval()],
            Err(MultisigSignatureError::InvalidConfig(
                MultisigConfigError::AccountIsOwner,
            )),
        ),
        (
            "no approvals",
            account,
            config.clone(),
            Vec::new(),
            Err(MultisigSignatureError::EmptySignatures),
        ),
        (
            "more approvals than the cap, before their sizes",
            account,
            config.clone(),
            vec![oversized.clone(); MAX_MULTISIG_SIGNATURES + 1],
            Err(MultisigSignatureError::TooManySignatures),
        ),
        (
            "an approval over the size cap after one within it",
            account,
            config.clone(),
            vec![owner_approval(), oversized],
            Err(MultisigSignatureError::OwnerSignatureTooLarge),
        ),
        (
            "as many approvals of the largest size as the caps allow",
            account,
            config,
            vec![largest; MAX_MULTISIG_SIGNATURES],
            Ok(()),
        ),
    ] {
        assert_eq!(
            MultisigSignature::try_new(account, config, approvals.clone())
                .map(|signature| signature.signatures().to_vec()),
            expected.map(|()| approvals),
            "{case}"
        );
    }
}

#[test]
fn multisig_signature_rlp_roundtrips_and_rejects_malformed_encodings() {
    let account = Address::repeat_byte(0x11);
    let config = current_config(indexed_owner(2));
    let approvals = vec![
        owner_approval(),
        webauthn_approval(MAX_MULTISIG_OWNER_SIGNATURE_BYTES),
    ];
    let signature = MultisigSignature::try_new(account, config.clone(), approvals.clone()).unwrap();

    // The wire form is the account, the complete config and each approval's bytes, in order.
    let encoded = alloy_rlp::encode(&signature);
    assert_eq!(
        encoded,
        encoded_multisig(
            account,
            &config,
            approvals
                .iter()
                .map(|approval| approval.to_bytes().to_vec())
                .collect(),
        )
    );
    assert_eq!(decode_exact::<MultisigSignature>(&encoded), Ok(signature));

    for (case, encoded, expected) in malformed_multisig_encodings() {
        assert_eq!(
            MultisigSignature::decode(&mut encoded.as_slice()).map_err(|error| error.to_string()),
            Err(expected),
            "{case}"
        );
    }
}

#[test]
fn sixty_five_byte_owners_remain_untyped() {
    for first in [0x03, 0x04, 0x05] {
        let mut primitive = owner_approval().to_bytes().to_vec();
        primitive[0] = first;
        let expected =
            PrimitiveSignature::Secp256k1(Signature::try_from(primitive.as_slice()).unwrap());
        let encoded = encoded_multisig(
            indexed_owner(1),
            &current_config(indexed_owner(2)),
            vec![primitive],
        );
        let decoded = MultisigSignature::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded.signatures(), [expected]);
    }
}

#[test]
fn multisig_hashes_follow_vectors_and_documented_layout() {
    let inner_digest = B256::repeat_byte(0x42);

    // Vectors over one owner of weight 1 at threshold 1, independently reproduced with raw
    // keccak and CREATE2 hashing over the placeholder account proxy hash.
    let owner = Address::repeat_byte(0x11);
    let initial = multisig_config(0, 1, &[(owner, 1)]);
    assert_eq!(
        initial.account_salt_preimage().map(keccak256),
        Ok(b256!(
            "7162e370e58784e6b33d61878820d1497eeaf4f68e00b2cfc00a2f3b1dbb00da"
        ))
    );
    assert_eq!(
        initial.derive_account(TEST_FACTORY),
        Ok(address!("d62b59cb4e41a0dd9000c71c6663df05e2bb910d"))
    );
    assert_eq!(
        initial.commitment(),
        Ok(b256!(
            "a9e7d1e2ad25e227a4de5f38f3bba31d854ffc8efec46aaa8649097a516bb4ee"
        ))
    );
    let digest_account = address!("91847576f406d0842ad7c1a0c97c22a122e64278");
    assert_eq!(
        multisig_digest(inner_digest, digest_account, 0),
        b256!("7a62ef46efdf76a6a0ab6c38c5fdeda2169d6a0de3643bb9912a4fbce881a870")
    );
    let current = MultisigSignature::try_new(
        digest_account,
        current_config(owner),
        vec![owner_approval()],
    )
    .unwrap();
    assert_eq!(
        current.digest(inner_digest),
        b256!("cceb022fd342beddcf6583e680c18a34936212276a680f026e52728b5ebb722b")
    );
    assert_eq!(
        current.config_commitment(),
        b256!("6237ca5930f2265d4fb70a0305dd6ceea4df227053b4a62c304489ede946a2f8")
    );
    // The most owners, each of weight 1, at threshold 8, reproduced the same way.
    assert_eq!(
        multisig_config(0, 8, &indexed_owners(MAX_MULTISIG_OWNERS, 1)).derive_account(TEST_FACTORY),
        Ok(address!("213bb3642432619a5327c0c6c60bda3ca2bbe59c"))
    );

    // The documented preimage layouts, built by hand.
    let owners = [(indexed_owner(1), 2), (indexed_owner(2), 3)];
    let mut config = multisig_config(9, 4, &owners);
    config.salt = B256::repeat_byte(0x07);
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
    assert_eq!(config.account_salt_preimage(), Ok(salt_preimage.clone()));
    assert_eq!(config.account_salt_preimage_len(), salt_preimage.len());

    let commitment_preimage = [
        MULTISIG_CONFIG_DOMAIN,
        config.salt.as_slice(),
        &config.version.to_be_bytes(),
        owner_set.as_slice(),
    ]
    .concat();
    assert_eq!(
        config.commitment_preimage(),
        Ok(commitment_preimage.clone())
    );
    assert_eq!(config.commitment_preimage_len(), commitment_preimage.len());
    assert_eq!(config.commitment(), Ok(keccak256(&commitment_preimage)));

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
    let account = Address::from_word(keccak256(&create2_preimage));
    assert_eq!(config.derive_account(TEST_FACTORY), Ok(account));

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

    // An owner approval cannot replay across accounts that share owners, or across versions.
    let mut resalted = config.clone();
    resalted.salt = B256::repeat_byte(0x08);
    let resalted_account = resalted.derive_account(TEST_FACTORY).unwrap();
    assert_ne!(resalted_account, account, "the salt sets the account");
    assert_ne!(
        multisig_digest(inner_digest, resalted_account, config.version),
        multisig_digest(inner_digest, account, config.version),
        "the account sets the digest"
    );
    assert_ne!(
        multisig_digest(inner_digest, account, config.version + 1),
        multisig_digest(inner_digest, account, config.version),
        "the version sets the digest"
    );
}

#[test]
fn multisig_quorum_reports_the_first_broken_rule() {
    let [first, second, third] = [1, 2, 3].map(indexed_owner);
    let config = multisig_config(0, 4, &[(first, 1), (second, 3), (third, 2)]);
    assert_eq!(
        [first, second, third, indexed_owner(4)].map(|owner| config.owner_weight(owner)),
        [Some(1), Some(3), Some(2), None]
    );

    // Records each recovered owner with its configured weight, in order.
    let quorum =
        |threshold: u8, approvals: Vec<(Address, u8)>| -> Result<(), MultisigQuorumError> {
            let mut accumulator = MultisigWeightAccumulator::new(threshold)?;
            for (owner, weight) in approvals {
                accumulator.record_owner(owner, weight)?;
            }
            accumulator.finish()
        };
    let light = (first, 1);
    let heavy = (second, 3);

    for (case, threshold, approvals, expected) in [
        (
            "a zero threshold",
            0,
            Vec::new(),
            Err(MultisigQuorumError::ZeroThreshold),
        ),
        (
            "no approvals",
            1,
            Vec::new(),
            Err(MultisigQuorumError::EmptySignatures),
        ),
        (
            "a signer of zero weight, read as outside the owner set",
            2,
            vec![(first, 0)],
            Err(MultisigQuorumError::SignerNotOwner),
        ),
        (
            "a repeated owner",
            2,
            vec![light, light],
            Err(MultisigQuorumError::SignersNotAscending),
        ),
        (
            "descending owners",
            4,
            vec![heavy, light],
            Err(MultisigQuorumError::SignersNotAscending),
        ),
        (
            "more approvals than the cap below quorum, before ordering",
            u8::MAX,
            [indexed_owners(MAX_MULTISIG_SIGNATURES, 1), vec![light]].concat(),
            Err(MultisigQuorumError::TooManySignatures),
        ),
        (
            "an approval after quorum",
            1,
            vec![light, heavy],
            Err(MultisigQuorumError::ExcessSignatures),
        ),
        (
            "an approval after quorum, before its entry is checked",
            1,
            vec![light, (Address::ZERO, 0)],
            Err(MultisigQuorumError::ExcessSignatures),
        ),
        (
            "weight below the threshold",
            4,
            vec![heavy],
            Err(MultisigQuorumError::WeightBelowThreshold),
        ),
        ("weight at the threshold", 4, vec![light, heavy], Ok(())),
    ] {
        assert_eq!(quorum(threshold, approvals), expected, "{case}");
    }
}

#[cfg(feature = "serde")]
mod serde_json_and_binary {
    use super::{
        MultisigSignature, RlpError, current_config, indexed_owner, malformed_multisig_encodings,
        owner_approval,
    };
    use alloy_primitives::{Address, Bytes};
    use serde::{
        Deserialize as _,
        de::{
            Error as _,
            value::{BorrowedBytesDeserializer, Error as DeError},
        },
    };
    use serde_json::{from_value, to_value};

    fn decode_binary_multisig(bytes: &[u8]) -> Result<MultisigSignature, DeError> {
        MultisigSignature::deserialize(BorrowedBytesDeserializer::new(bytes))
    }

    #[test]
    fn multisig_signature_serde_roundtrips_rlp_bytes() {
        let signature = MultisigSignature::try_new(
            Address::repeat_byte(0x11),
            current_config(indexed_owner(2)),
            vec![owner_approval()],
        )
        .unwrap();
        let encoded = alloy_rlp::encode(&signature);

        let json = to_value(&signature).unwrap();
        assert_eq!(json, to_value(Bytes::from(encoded.clone())).unwrap());
        assert_eq!(from_value::<MultisigSignature>(json).unwrap(), signature);
        assert_eq!(decode_binary_multisig(&encoded), Ok(signature));
        // The bytes hold exactly one signature.
        let trailing = [encoded, vec![0x80]].concat();
        assert_eq!(
            decode_binary_multisig(&trailing),
            Err(DeError::custom(RlpError::UnexpectedLength))
        );
    }

    #[test]
    fn multisig_signature_serde_rejects_malformed_encodings() {
        for (case, encoded, expected) in malformed_multisig_encodings() {
            assert_eq!(
                decode_binary_multisig(&encoded),
                Err(DeError::custom(&expected)),
                "{case}"
            );
            let json = to_value(Bytes::from(encoded)).unwrap();
            assert_eq!(
                from_value::<MultisigSignature>(json)
                    .unwrap_err()
                    .to_string(),
                expected,
                "{case}"
            );
        }
    }
}

proptest! {
    #[test]
    fn proptest_multisig_signature_decode_follows_owner_approval_decoding(
        account in any::<Address>().prop_filter("multisig accounts are nonzero", |account| !account.is_zero()),
        approvals in prop::collection::vec(owner_approval_bytes(), 1..=MAX_MULTISIG_SIGNATURES),
    ) {
        let config = current_config(indexed_owner(2));
        let decoded =
            decode_exact::<MultisigSignature>(encoded_multisig(account, &config, approvals.clone()));
        match approvals
            .iter()
            .map(|approval| decode_exact::<PrimitiveSignature>(alloy_rlp::encode(approval.as_slice())))
            .collect::<Result<Vec<_>, _>>()
        {
            // Accepted approvals decode in order and re-encode canonically.
            Ok(signatures) => {
                let decoded = decoded.unwrap();
                prop_assert_eq!(decoded.account(), account);
                prop_assert_eq!(decoded.config(), &config);
                prop_assert_eq!(decoded.signatures(), signatures.as_slice());

                let reencoded = alloy_rlp::encode(&decoded);
                let canonical_approvals = signatures
                    .iter()
                    .map(|signature| signature.to_bytes().to_vec())
                    .collect();
                prop_assert_eq!(
                    &reencoded,
                    &encoded_multisig(account, &config, canonical_approvals)
                );
                prop_assert_eq!(decode_exact::<MultisigSignature>(reencoded), Ok(decoded));
            }
            // The first rejected approval's error is the signature's.
            Err(error) => prop_assert_eq!(decoded, Err(error)),
        }
    }
}
