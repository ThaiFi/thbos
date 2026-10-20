//! Journaled native account configuration updates.

pub mod dispatch;

use crate::{
    error::Result,
    storage::{ConfigCommitmentWriteGas, Handler},
};
use alloy::primitives::{Address, B256};
use revm::interpreter::gas::{KECCAK256, KECCAK256WORD};
pub use tempo_chainspec::is_valid_native_account as valid_account;
use tempo_contracts::precompiles::{
    INativeMultisig, NATIVE_MULTISIG_ADDRESS, NativeMultisigError, NativeMultisigEvent,
};
use tempo_precompiles_macros::{Storable, contract};
use tempo_primitives::{
    TempoBlockEnv,
    transaction::{
        MultisigConfig, MultisigOwner,
        multisig::{MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN, MULTISIG_UPGRADE_DOMAIN},
    },
};

#[contract(addr = NATIVE_MULTISIG_ADDRESS)]
pub struct NativeMultisig {
    tx_origin: Address,
    directly_authorized_account: Address,
    upgrade_eligibility: UpgradeEligibility,
}

impl NativeMultisig {
    /// Seeds only the direct outer owner-quorum authority, never a delegate or sponsor, and
    /// whether the transaction may migrate its sender.
    pub fn set_authority(
        &mut self,
        origin: Address,
        directly_authorized: Address,
        upgrade_eligibility: UpgradeEligibility,
    ) -> Result<()> {
        self.tx_origin.t_write(origin)?;
        self.directly_authorized_account
            .t_write(directly_authorized)?;
        self.upgrade_eligibility.t_write(upgrade_eligibility)
    }

    fn derive_account(
        &self,
        salt: B256,
        threshold: u8,
        owners: &[INativeMultisig::MultisigOwner],
    ) -> Result<Address> {
        let factory = self.factory()?;
        let config = config(salt, 0, threshold, owners);
        config.validate()?;
        self.storage
            .deduct_gas(initial_account_proof_gas(&config))?;
        let account = config.derive_account(factory)?;
        if !valid_account(account, self.storage.spec()) {
            return Err(NativeMultisigError::invalid_account().into());
        }
        Ok(account)
    }

    fn get_config_commitment(&self, account: Address) -> Result<B256> {
        self.storage.config_commitment(account)
    }

    fn update_config(
        &mut self,
        sender: Address,
        current: &INativeMultisig::MultisigConfig,
        threshold: u8,
        owners: Vec<INativeMultisig::MultisigOwner>,
    ) -> Result<()> {
        // The wrapper rejects delegatecall; a validated native origin cannot have code.
        // Together these conditions restrict authority to protocol-created batch calls.
        if sender.is_zero()
            || self.tx_origin.t_read()? != sender
            || self.directly_authorized_account.t_read()? != sender
        {
            return Err(NativeMultisigError::unauthorized_multisig_caller().into());
        }
        let current = config(
            current.salt,
            current.version,
            current.threshold,
            &current.owners,
        );
        let stored = self.get_config_commitment(sender)?;
        let hash = self.storage.keccak256(
            &current
                .commitment_preimage()
                .map_err(|_| NativeMultisigError::invalid_config())?,
        )?;
        if stored.is_zero() || stored != hash {
            return Err(NativeMultisigError::invalid_config().into());
        }
        let version = current
            .version
            .checked_add(1)
            .ok_or_else(NativeMultisigError::invalid_config)?;
        let next = config(current.salt, version, threshold, &owners);
        next.validate_for_account(sender)?;
        let hash = self.storage.keccak256(&next.commitment_preimage()?)?;
        if hash.is_zero() {
            return Err(NativeMultisigError::invalid_config().into());
        }
        self.storage
            .set_config_commitment(sender, hash, ConfigCommitmentWriteGas::Precompile)?;
        self.emit_event(NativeMultisigEvent::multisig_config_updated(
            sender, next.salt, version, threshold, owners,
        ))
    }

    /// Installs a version-one configuration for `sender`, an EOA that signed with its root key.
    ///
    /// Checks fail in TIP-1113's order, so the first failing condition decides the error. The
    /// root key may also be listed as an owner.
    fn upgrade_account(
        &mut self,
        sender: Address,
        threshold: u8,
        owners: Vec<INativeMultisig::MultisigOwner>,
    ) -> Result<B256> {
        // A sole call means `sender` is the tx caller; whoever seeds the eligibility enforces it.
        let eligibility = self.upgrade_eligibility.t_read()?;
        if eligibility == UpgradeEligibility::NotSoleCall {
            return Err(NativeMultisigError::upgrade_must_be_only_call().into());
        }
        if eligibility == UpgradeEligibility::NotPrimitiveRoot {
            return Err(NativeMultisigError::primitive_root_required().into());
        }
        let has_code = self
            .storage
            .with_account_info(sender, |info| Ok(!info.is_empty_code_hash()))?;
        let commitment = self.storage.config_commitment(sender)?;
        if has_code {
            return Err(NativeMultisigError::account_has_code().into());
        }
        if !commitment.is_zero() {
            return Err(NativeMultisigError::account_already_configurable().into());
        }
        let salt = self
            .storage
            .keccak256(&[MULTISIG_UPGRADE_DOMAIN, sender.as_slice()].concat())?;
        let upgraded = config(salt, 1, threshold, &owners);
        upgraded
            .validate_for_account(sender)
            .map_err(|_| NativeMultisigError::invalid_config())?;
        let hash = self.storage.keccak256(
            &upgraded
                .commitment_preimage()
                .map_err(|_| NativeMultisigError::invalid_config())?,
        )?;
        if hash.is_zero() {
            return Err(NativeMultisigError::invalid_config().into());
        }
        self.storage
            .set_config_commitment(sender, hash, ConfigCommitmentWriteGas::Precompile)?;
        self.emit_event(NativeMultisigEvent::account_upgraded(
            sender, hash, salt, threshold, owners,
        ))?;
        Ok(hash)
    }

    fn factory(&self) -> Result<Address> {
        self.storage
            .with_block_env(TempoBlockEnv::configured_multisig_recovery_factory)
            .ok_or_else(|| NativeMultisigError::invalid_config().into())
    }
}

/// What the transaction allows `upgradeAccount` to do, as decided by the handler before execution.
///
/// Variants are ordered from the most to the least restrictive, so the zero value of an unseeded
/// context rejects every migration.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
pub enum UpgradeEligibility {
    /// The transaction is not a lone, direct call to this precompile without authorizations.
    NotSoleCall,
    /// The transaction is a sole call, but its outer signature is not a primitive root signature.
    NotPrimitiveRoot,
    /// The transaction is a sole call signed by a primitive root key.
    PrimitiveRoot,
}

/// Gas for one `KECCAK256` over `bytes` bytes of input.
pub const fn keccak_cost(bytes: usize) -> u64 {
    KECCAK256 + KECCAK256WORD * bytes.div_ceil(32) as u64
}

/// Hashing cost of deriving an unregistered account from its initial configuration.
pub const fn initial_account_proof_gas(config: &MultisigConfig) -> u64 {
    keccak_cost(config.account_salt_preimage_len())
        + keccak_cost(MULTISIG_ACCOUNT_CREATE2_PREIMAGE_LEN)
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
