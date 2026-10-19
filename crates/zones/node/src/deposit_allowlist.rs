//! Sequencer-local allowlist of L1 depositors.
//!
//! When a Zone portal runs with access mode disabled, anyone can deposit on L1. The leader then
//! bounces deposits whose L1 `sender` is not on this list by supplying zeroed decryption data,
//! which the inbox treats as a failed decryption and refunds through the ordinary deposit
//! bounce-back path. The check runs only where blocks are built, so it needs no hardfork.

use std::{
    collections::BTreeSet,
    fs::File,
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use alloy_primitives::{Address, B256};
use eyre::{WrapErr as _, ensure};
use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::ErrorObjectOwned};
use parking_lot::RwLock;
use tracing::info;
use zone_l1::abi::{ChaumPedersenProof, DecryptionData};

/// File name of the persisted allowlist inside the node data directory.
pub const DEPOSIT_ALLOWLIST_FILE_NAME: &str = "deposit-allowlist.json";

/// Allowlist configuration attached to a sequencer.
#[derive(Debug, Clone)]
pub struct DepositAllowlistConfig {
    /// The loaded allowlist shared by the engine and the admin server.
    pub allowlist: DepositAllowlist,
    /// Listen address of the `zoneAdmin` JSON-RPC server. `None` disables the server, leaving
    /// the persisted list fixed for the lifetime of the process.
    pub admin_addr: Option<SocketAddr>,
}

/// Addresses whose L1 deposits the leader credits, persisted as a sorted JSON array.
///
/// Cloning shares the same list.
#[derive(Debug, Clone)]
pub struct DepositAllowlist {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// Persisted list location, rewritten atomically on every update.
    path: PathBuf,
    /// Current list. Writers hold the lock while persisting so updates apply in order.
    addresses: RwLock<BTreeSet<Address>>,
}

impl DepositAllowlist {
    /// Load the persisted list from `path`.
    ///
    /// When `path` does not exist, the list is read from `seed` and persisted to `path`; the seed
    /// is ignored once a persisted list exists. Fails when neither file exists, so a misconfigured
    /// node cannot silently bounce every deposit.
    pub fn load(path: PathBuf, seed: Option<&Path>) -> eyre::Result<Self> {
        let addresses = if path.exists() {
            read_addresses(&path)?
        } else {
            let seed = seed.ok_or_else(|| {
                eyre::eyre!(
                    "deposit allowlist {} does not exist and no seed file was provided",
                    path.display()
                )
            })?;
            let addresses = read_addresses(seed)?;
            persist(&path, &addresses)?;
            info!(
                target: "zone::allowlist",
                seed = %seed.display(),
                path = %path.display(),
                count = addresses.len(),
                "Seeded deposit allowlist"
            );
            addresses
        };
        Ok(Self {
            inner: Arc::new(Inner {
                path,
                addresses: RwLock::new(addresses),
            }),
        })
    }

    /// Returns whether deposits from `sender` are credited.
    pub fn contains(&self, sender: &Address) -> bool {
        self.inner.addresses.read().contains(sender)
    }

    /// Returns the current list in ascending order.
    pub fn addresses(&self) -> Vec<Address> {
        self.inner.addresses.read().iter().copied().collect()
    }

    /// Add or remove `addresses`, persisting the result before it takes effect.
    pub fn set(&self, addresses: &[Address], allowed: bool) -> eyre::Result<()> {
        self.update(|current| {
            let mut next = current.clone();
            for address in addresses {
                if allowed {
                    next.insert(*address);
                } else {
                    next.remove(address);
                }
            }
            next
        })
    }

    /// Replace the whole list, persisting it before it takes effect.
    pub fn replace(&self, addresses: Vec<Address>) -> eyre::Result<()> {
        self.update(|_| addresses.into_iter().collect())
    }

    /// Replace the decryption data of every deposit whose sender is not allowed.
    ///
    /// `senders` holds the L1 sender of each user deposit in queue order; `prepare_many` emits
    /// exactly one entry in `decryptions` per user deposit in the same order. Returns the number
    /// of rejected deposits.
    pub fn reject_unlisted(
        &self,
        senders: &[Address],
        decryptions: &mut [DecryptionData],
    ) -> eyre::Result<usize> {
        ensure!(
            senders.len() == decryptions.len(),
            "{} deposit senders but {} decryptions",
            senders.len(),
            decryptions.len()
        );
        let addresses = self.inner.addresses.read();
        let mut rejected = 0;
        for (sender, decryption) in senders.iter().zip(decryptions) {
            if !addresses.contains(sender) {
                *decryption = rejected_decryption();
                rejected += 1;
            }
        }
        Ok(rejected)
    }

    fn update(
        &self,
        apply: impl FnOnce(&BTreeSet<Address>) -> BTreeSet<Address>,
    ) -> eyre::Result<()> {
        let mut addresses = self.inner.addresses.write();
        let next = apply(&addresses);
        persist(&self.inner.path, &next)?;
        *addresses = next;
        Ok(())
    }
}

/// `zoneAdmin` methods for managing the deposit allowlist.
#[rpc(server, namespace = "zoneAdmin")]
pub(crate) trait DepositAllowlistApi {
    /// Add (`allowed = true`) or remove (`allowed = false`) depositor addresses.
    #[method(name = "setDepositAllowed", blocking)]
    fn set_deposit_allowed(&self, addresses: Vec<Address>, allowed: bool) -> RpcResult<()>;

    /// Replace the whole allowlist.
    #[method(name = "replaceDepositAllowlist", blocking)]
    fn replace_deposit_allowlist(&self, addresses: Vec<Address>) -> RpcResult<()>;

    /// Returns the allowlist in ascending order.
    #[method(name = "getDepositAllowlist")]
    fn get_deposit_allowlist(&self) -> RpcResult<Vec<Address>>;
}

impl DepositAllowlistApiServer for DepositAllowlist {
    fn set_deposit_allowed(&self, addresses: Vec<Address>, allowed: bool) -> RpcResult<()> {
        self.set(&addresses, allowed).map_err(internal_error)?;
        info!(target: "zone::allowlist", count = addresses.len(), allowed, "Updated deposit allowlist");
        Ok(())
    }

    fn replace_deposit_allowlist(&self, addresses: Vec<Address>) -> RpcResult<()> {
        let count = addresses.len();
        self.replace(addresses).map_err(internal_error)?;
        info!(target: "zone::allowlist", count, "Replaced deposit allowlist");
        Ok(())
    }

    fn get_deposit_allowlist(&self) -> RpcResult<Vec<Address>> {
        Ok(self.addresses())
    }
}

fn internal_error(error: eyre::Report) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        jsonrpsee::types::error::INTERNAL_ERROR_CODE,
        format!("{error:#}"),
        None::<()>,
    )
}

/// Decryption data whose shared secret is not a curve point, so the inbox's Chaum-Pedersen check
/// fails and the deposit is bounced back to its Tempo refund recipient.
fn rejected_decryption() -> DecryptionData {
    DecryptionData {
        sharedSecret: B256::ZERO,
        sharedSecretYParity: 0x02,
        cpProof: ChaumPedersenProof {
            s: B256::ZERO,
            c: B256::ZERO,
        },
    }
}

fn read_addresses(path: &Path) -> eyre::Result<BTreeSet<Address>> {
    let file = File::open(path)
        .wrap_err_with(|| format!("failed to open deposit allowlist {}", path.display()))?;
    let addresses: Vec<Address> = serde_json::from_reader(std::io::BufReader::new(file))
        .wrap_err_with(|| format!("failed to parse deposit allowlist {}", path.display()))?;
    Ok(addresses.into_iter().collect())
}

/// Atomically replace `path` with `addresses`: write a sibling temp file, fsync it, rename it
/// over `path`, then fsync the directory so the rename survives a crash.
fn persist(path: &Path, addresses: &BTreeSet<Address>) -> eyre::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| eyre::eyre!("deposit allowlist {} has no parent", path.display()))?;
    std::fs::create_dir_all(dir).wrap_err_with(|| format!("failed to create {}", dir.display()))?;
    let mut file = tempfile::NamedTempFile::new_in(dir)
        .wrap_err_with(|| format!("failed to create temp file in {}", dir.display()))?;
    serde_json::to_writer_pretty(&mut file, addresses)
        .wrap_err("failed to serialize deposit allowlist")?;
    file.write_all(b"\n")
        .and_then(|()| file.as_file().sync_all())
        .wrap_err("failed to write deposit allowlist")?;
    file.persist(path)
        .wrap_err_with(|| format!("failed to replace {}", path.display()))?;
    File::open(dir)
        .and_then(|dir| dir.sync_all())
        .wrap_err_with(|| format!("failed to sync {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    const ALICE: Address = address!("0x00000000000000000000000000000000000a11ce");
    const BOB: Address = address!("0x0000000000000000000000000000000000000b0b");

    fn write_seed(dir: &Path, addresses: &[Address]) -> PathBuf {
        let seed = dir.join("seed.json");
        std::fs::write(&seed, serde_json::to_vec(addresses).unwrap()).unwrap();
        seed
    }

    #[test]
    fn load_requires_persisted_list_or_seed() {
        let dir = tempfile::tempdir().unwrap();
        let err =
            DepositAllowlist::load(dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME), None).unwrap_err();
        assert!(
            err.to_string().contains("no seed file was provided"),
            "{err}"
        );
    }

    #[test]
    fn seed_is_persisted_and_ignored_once_a_list_exists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data").join(DEPOSIT_ALLOWLIST_FILE_NAME);
        let seed = write_seed(dir.path(), &[ALICE]);

        let allowlist = DepositAllowlist::load(path.clone(), Some(&seed)).unwrap();
        assert_eq!(allowlist.addresses(), vec![ALICE]);
        assert_eq!(read_addresses(&path).unwrap(), BTreeSet::from([ALICE]));

        allowlist.set(&[BOB], true).unwrap();
        allowlist.set(&[ALICE], false).unwrap();

        let reloaded = DepositAllowlist::load(path, Some(&seed)).unwrap();
        assert_eq!(reloaded.addresses(), vec![BOB]);
    }

    #[test]
    fn replace_overwrites_the_persisted_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME);
        let seed = write_seed(dir.path(), &[ALICE]);
        let allowlist = DepositAllowlist::load(path.clone(), Some(&seed)).unwrap();

        allowlist.replace(vec![BOB]).unwrap();

        assert!(!allowlist.contains(&ALICE));
        assert!(allowlist.contains(&BOB));
        assert_eq!(read_addresses(&path).unwrap(), BTreeSet::from([BOB]));
    }

    #[test]
    fn failed_persist_leaves_the_list_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME);
        let seed = write_seed(dir.path(), &[ALICE]);
        let allowlist = DepositAllowlist::load(path.clone(), Some(&seed)).unwrap();

        // A directory at the target path makes the rename fail.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();

        let err = allowlist.set(&[BOB], true).unwrap_err();
        assert!(err.to_string().contains("failed to replace"), "{err}");
        assert_eq!(allowlist.addresses(), vec![ALICE]);
    }

    #[test]
    fn reject_unlisted_zeroes_only_unlisted_senders() {
        let dir = tempfile::tempdir().unwrap();
        let seed = write_seed(dir.path(), &[ALICE]);
        let allowlist =
            DepositAllowlist::load(dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME), Some(&seed))
                .unwrap();
        let valid = DecryptionData {
            sharedSecret: B256::repeat_byte(1),
            sharedSecretYParity: 0x03,
            cpProof: ChaumPedersenProof {
                s: B256::repeat_byte(2),
                c: B256::repeat_byte(3),
            },
        };
        let mut decryptions = vec![valid.clone(), valid.clone(), valid.clone()];

        let rejected = allowlist
            .reject_unlisted(&[ALICE, BOB, ALICE], &mut decryptions)
            .unwrap();

        assert_eq!(rejected, 1);
        assert_eq!(decryptions[0], valid);
        assert_eq!(decryptions[1], rejected_decryption());
        assert_eq!(decryptions[2], valid);
    }

    #[test]
    fn reject_unlisted_requires_one_decryption_per_sender() {
        let dir = tempfile::tempdir().unwrap();
        let seed = write_seed(dir.path(), &[ALICE]);
        let allowlist =
            DepositAllowlist::load(dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME), Some(&seed))
                .unwrap();

        let err = allowlist.reject_unlisted(&[ALICE], &mut []).unwrap_err();
        assert_eq!(err.to_string(), "1 deposit senders but 0 decryptions");
    }
}
