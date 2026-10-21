//! Startup handling of the trusted custom genesis directory.

use std::{fs, path::Path, process::Command};

use alloy_genesis::Genesis;
use alloy_primitives::Address;

#[test]
fn invalid_custom_genesis_fails_startup_without_panicking() {
    let directory = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("invalid-custom-genesis-{}", std::process::id()));
    fs::create_dir_all(&directory).unwrap();
    let mut genesis = Genesis::default();
    genesis.config.chain_id = 31_318;
    genesis.config.extra_fields.insert(
        "configurableAccountRecoveryFactory".into(),
        serde_json::json!(Address::ZERO),
    );
    fs::write(
        directory.join("custom.json"),
        serde_json::to_vec(&genesis).unwrap(),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_tempo-zone-prover-enclave"))
        .arg("--tempo-genesis")
        .arg(&directory)
        .arg("--use-tcp")
        .output()
        .unwrap();
    fs::remove_dir_all(&directory).unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr
            .contains("configurableAccountRecoveryFactory must be a nonzero, non-reserved address"),
        "{stderr}"
    );
}
