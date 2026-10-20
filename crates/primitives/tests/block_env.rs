#![cfg(feature = "evm")]

use alloy_primitives::Address;
use tempo_primitives::TempoBlockEnv;

#[test]
fn configured_recovery_factory_treats_zero_as_unset() {
    let factory = Address::repeat_byte(0x11);
    let with = |recovery_factory| TempoBlockEnv {
        recovery_factory,
        ..Default::default()
    };

    assert_eq!(with(None).configured_recovery_factory(), None);
    assert_eq!(
        with(Some(Address::ZERO)).configured_recovery_factory(),
        None
    );
    assert_eq!(
        with(Some(factory)).configured_recovery_factory(),
        Some(factory)
    );
}
