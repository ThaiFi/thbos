#![cfg(feature = "evm")]

use alloy_primitives::Address;
use tempo_primitives::TempoBlockEnv;

#[test]
fn configured_configurable_account_recovery_factory_treats_zero_as_unset() {
    let factory = Address::repeat_byte(0x11);
    let with = |configurable_account_recovery_factory| TempoBlockEnv {
        configurable_account_recovery_factory,
        ..Default::default()
    };

    assert_eq!(
        with(None).configured_configurable_account_recovery_factory(),
        None
    );
    assert_eq!(
        with(Some(Address::ZERO)).configured_configurable_account_recovery_factory(),
        None
    );
    assert_eq!(
        with(Some(factory)).configured_configurable_account_recovery_factory(),
        Some(factory)
    );
}
