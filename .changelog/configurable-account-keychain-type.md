---
tempo-contracts: minor
tempo-precompiles: minor
---

Add the `ConfigurableAccount` account keychain signature type (value 3). From T14, `authorizeKey`, `authorizeKeyWithWitness` and `authorizeAdminKey` accept it for a code-free delegate other than the granting account, and a stored key of this type is only usable from T14. Earlier forks keep reverting exactly as for an unknown signature type.
