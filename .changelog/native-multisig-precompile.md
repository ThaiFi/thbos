---
tempo-precompiles: minor
---

Added the native multisig precompile (`native_multisig::NativeMultisig`: `deriveAccount`, `getConfigCommitment`, `updateConfig`, `upgradeAccount`), its transaction-authority seed `set_authority` with `UpgradeEligibility`, and the test-utils fixture setter `HashMapStorageProvider::set_multisig_recovery_factory`. Nothing registers or calls the precompile yet.
