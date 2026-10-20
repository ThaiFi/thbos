//! Revert errors reported for native multisig config validation failures, exercised through
//! the public precompile error API.

use alloy::primitives::{Bytes, FixedBytes, keccak256};
use tempo_precompiles::error::{TempoPrecompileError, decode_error};
use tempo_primitives::transaction::MultisigConfigError;

/// A config validation error and the signature of the precompile error it reverts with.
struct ErrorMapping {
    config_error: MultisigConfigError,
    error_signature: &'static str,
}

const ERROR_MAPPINGS: [ErrorMapping; 11] = [
    ErrorMapping {
        config_error: MultisigConfigError::EmptyOwners,
        error_signature: "InvalidMultisigOwner()",
    },
    ErrorMapping {
        config_error: MultisigConfigError::TooManyOwners,
        error_signature: "TooManyOwners()",
    },
    ErrorMapping {
        config_error: MultisigConfigError::ZeroThreshold,
        error_signature: "InvalidThreshold()",
    },
    ErrorMapping {
        config_error: MultisigConfigError::ZeroOwner,
        error_signature: "InvalidMultisigOwner()",
    },
    ErrorMapping {
        config_error: MultisigConfigError::ZeroWeight,
        error_signature: "InvalidWeight()",
    },
    ErrorMapping {
        config_error: MultisigConfigError::DuplicateOwner,
        error_signature: "DuplicateOwner()",
    },
    ErrorMapping {
        config_error: MultisigConfigError::OwnersNotAscending,
        error_signature: "InvalidOwnerOrder()",
    },
    ErrorMapping {
        config_error: MultisigConfigError::TotalWeightExceedsMax,
        error_signature: "InvalidWeight()",
    },
    ErrorMapping {
        config_error: MultisigConfigError::ThresholdExceedsWeight,
        error_signature: "InvalidThreshold()",
    },
    ErrorMapping {
        config_error: MultisigConfigError::DerivedAccountZero,
        error_signature: "InvalidAccount()",
    },
    ErrorMapping {
        config_error: MultisigConfigError::AccountIsOwner,
        error_signature: "InvalidMultisigOwner()",
    },
];

/// The position of `error`'s row in [`ERROR_MAPPINGS`]. The match has no wildcard arm, so a new
/// [`MultisigConfigError`] variant fails to compile here until it gets a row.
const fn mapping_index(error: MultisigConfigError) -> usize {
    match error {
        MultisigConfigError::EmptyOwners => 0,
        MultisigConfigError::TooManyOwners => 1,
        MultisigConfigError::ZeroThreshold => 2,
        MultisigConfigError::ZeroOwner => 3,
        MultisigConfigError::ZeroWeight => 4,
        MultisigConfigError::DuplicateOwner => 5,
        MultisigConfigError::OwnersNotAscending => 6,
        MultisigConfigError::TotalWeightExceedsMax => 7,
        MultisigConfigError::ThresholdExceedsWeight => 8,
        MultisigConfigError::DerivedAccountZero => 9,
        MultisigConfigError::AccountIsOwner => 10,
    }
}

#[test]
fn every_config_error_has_one_row() {
    for (index, mapping) in ERROR_MAPPINGS.iter().enumerate() {
        assert_eq!(
            mapping_index(mapping.config_error),
            index,
            "{:?} is in the wrong row",
            mapping.config_error
        );
    }
}

#[test]
fn config_error_reverts_with_the_mapped_precompile_error() {
    for mapping in &ERROR_MAPPINGS {
        let case = format!("{:?}", mapping.config_error);
        let selector = FixedBytes::<4>::from_slice(&keccak256(mapping.error_signature)[..4]);

        let error = TempoPrecompileError::from(mapping.config_error);
        assert_eq!(error.selector(), selector, "{case}: selector");

        let output = error
            .into_precompile_result(0, 0)
            .unwrap_or_else(|e| panic!("{case}: revert is not a halt: {e:?}"));
        assert!(output.status.is_revert(), "{case}: status");
        assert_eq!(
            output.bytes,
            Bytes::copy_from_slice(selector.as_slice()),
            "{case}: revert bytes"
        );

        let decoded = decode_error(&output.bytes)
            .unwrap_or_else(|| panic!("{case}: revert bytes are not decodable"));
        assert_eq!(
            decoded.error.selector(),
            selector,
            "{case}: decoded selector"
        );
    }
}
