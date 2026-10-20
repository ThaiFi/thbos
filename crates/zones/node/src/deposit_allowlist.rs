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
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_primitives::{Address, B256, Bytes, Signature};
use alloy_sol_types::{Eip712Domain, SolStruct as _, eip712_domain, sol};
use eyre::{WrapErr as _, ensure};
use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::ErrorObjectOwned};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tracing::info;
use zone_l1::abi::{ChaumPedersenProof, DecryptionData};

mod relay;
pub(crate) use relay::{AllowlistRelay, apply_relayed_updates};

/// File name of the persisted allowlist inside the node data directory.
pub(crate) const DEPOSIT_ALLOWLIST_FILE_NAME: &str = "deposit-allowlist.json";

/// Longest time a signed write stays valid, bounding how long a captured signature can be
/// replayed.
pub(crate) const MAX_SIGNED_WRITE_VALIDITY: Duration = Duration::from_secs(10 * 60);

/// Most addresses the list may hold, so a full list read through an RPC-only node fits in one
/// P2P allowlist frame.
pub(crate) const MAX_DEPOSIT_ALLOWLIST_LEN: usize = 80_000;

sol! {
    /// EIP-712 message authorizing the admin to add (`allowed`) or remove depositors.
    struct SetDepositAllowed {
        address[] addresses;
        bool allowed;
        uint64 deadline;
    }

    /// EIP-712 message authorizing the admin to replace the whole allowlist.
    struct ReplaceDepositAllowlist {
        address[] addresses;
        uint64 deadline;
    }
}

/// The address whose EIP-712 signatures authorize allowlist writes, and the zone those
/// signatures are bound to.
#[derive(Debug, Clone, Copy)]
pub struct DepositAllowlistAdmin {
    /// Signer that every write must recover to.
    pub address: Address,
    /// Chain ID of this zone, used as the EIP-712 domain chain ID.
    pub zone_chain_id: u64,
}

impl DepositAllowlistAdmin {
    fn domain(&self) -> Eip712Domain {
        eip712_domain! {
            name: "TempoZoneDepositAllowlist",
            version: "1",
            chain_id: self.zone_chain_id,
        }
    }
}

/// An allowlist change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum Write {
    Set {
        addresses: Vec<Address>,
        allowed: bool,
    },
    Replace {
        addresses: Vec<Address>,
    },
}

/// An allowlist change with the admin signature that authorizes it until `deadline`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SignedWrite {
    pub(crate) write: Write,
    /// Unix timestamp in seconds after which the signature is rejected.
    pub(crate) deadline: u64,
    pub(crate) signature: Bytes,
}

impl SignedWrite {
    fn signing_hash(&self, domain: &Eip712Domain) -> B256 {
        match &self.write {
            Write::Set { addresses, allowed } => SetDepositAllowed {
                addresses: addresses.clone(),
                allowed: *allowed,
                deadline: self.deadline,
            }
            .eip712_signing_hash(domain),
            Write::Replace { addresses } => ReplaceDepositAllowlist {
                addresses: addresses.clone(),
                deadline: self.deadline,
            }
            .eip712_signing_hash(domain),
        }
    }
}

/// Why an allowlist request was rejected. Serializable so a sequencer can return it to the
/// RPC-only node that relayed the request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum DepositAllowlistError {
    #[error("signed write expired at {deadline}")]
    Expired { deadline: u64 },
    #[error(
        "signed write deadline {deadline} is more than {}s in the future",
        MAX_SIGNED_WRITE_VALIDITY.as_secs()
    )]
    DeadlineTooFar { deadline: u64 },
    #[error("malformed signature")]
    MalformedSignature,
    #[error("write is signed by {signer}, not the allowlist admin")]
    Unauthorized { signer: Address },
    #[error("allowlist would hold {len} addresses; the limit is {MAX_DEPOSIT_ALLOWLIST_LEN}")]
    TooLarge { len: usize },
    #[error("failed to persist the allowlist: {0}")]
    Persist(String),
    #[error("deposit allowlist is not enabled on this sequencer")]
    Disabled,
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<DepositAllowlistError> for ErrorObjectOwned {
    fn from(error: DepositAllowlistError) -> Self {
        let code = match error {
            DepositAllowlistError::Persist(_)
            | DepositAllowlistError::Disabled
            | DepositAllowlistError::Internal(_) => jsonrpsee::types::error::INTERNAL_ERROR_CODE,
            _ => jsonrpsee::types::error::INVALID_PARAMS_CODE,
        };
        Self::owned(code, error.to_string(), None::<()>)
    }
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
    /// Authorizes writes received over RPC.
    admin: DepositAllowlistAdmin,
    /// Current list, read by the engine on every block build.
    addresses: RwLock<BTreeSet<Address>>,
    /// Serializes writers so updates persist and apply in order without holding `addresses`
    /// across disk I/O.
    write_lock: Mutex<()>,
}

impl DepositAllowlist {
    /// Load the persisted list from `path`.
    ///
    /// When `path` does not exist, the list is read from `seed` and persisted to `path`; the seed
    /// is ignored once a persisted list exists. Fails when neither file exists, so a misconfigured
    /// node cannot silently bounce every deposit, or when the list exceeds
    /// [`MAX_DEPOSIT_ALLOWLIST_LEN`].
    pub fn load(
        path: PathBuf,
        seed: Option<&Path>,
        admin: DepositAllowlistAdmin,
    ) -> eyre::Result<Self> {
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
                admin,
                addresses: RwLock::new(addresses),
                write_lock: Mutex::new(()),
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
    pub fn set(&self, addresses: &[Address], allowed: bool) -> Result<(), DepositAllowlistError> {
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
    pub fn replace(&self, addresses: Vec<Address>) -> Result<(), DepositAllowlistError> {
        self.update(|_| addresses.into_iter().collect())
    }

    /// Apply `write` if the admin signed it and its deadline has not passed.
    pub(crate) fn apply_signed(&self, write: SignedWrite) -> Result<(), DepositAllowlistError> {
        self.authorize(&write)?;
        match write.write {
            Write::Set { addresses, allowed } => self.set(&addresses, allowed),
            Write::Replace { addresses } => self.replace(addresses),
        }
    }

    fn authorize(&self, write: &SignedWrite) -> Result<(), DepositAllowlistError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| DepositAllowlistError::Internal(err.to_string()))?
            .as_secs();
        if write.deadline < now {
            return Err(DepositAllowlistError::Expired {
                deadline: write.deadline,
            });
        }
        if write.deadline > now.saturating_add(MAX_SIGNED_WRITE_VALIDITY.as_secs()) {
            return Err(DepositAllowlistError::DeadlineTooFar {
                deadline: write.deadline,
            });
        }
        let admin = self.inner.admin;
        let signer = Signature::try_from(write.signature.as_ref())
            .and_then(|signature| {
                signature.recover_address_from_prehash(&write.signing_hash(&admin.domain()))
            })
            .map_err(|_| DepositAllowlistError::MalformedSignature)?;
        if signer != admin.address {
            return Err(DepositAllowlistError::Unauthorized { signer });
        }
        Ok(())
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
    ) -> Result<(), DepositAllowlistError> {
        let _writer = self.inner.write_lock.lock();
        // Only writers change `addresses`, so this snapshot stays current until the swap below.
        let next = apply(&self.inner.addresses.read());
        if next.len() > MAX_DEPOSIT_ALLOWLIST_LEN {
            return Err(DepositAllowlistError::TooLarge { len: next.len() });
        }
        persist(&self.inner.path, &next)
            .map_err(|err| DepositAllowlistError::Persist(format!("{err:#}")))?;
        *self.inner.addresses.write() = next;
        Ok(())
    }
}

/// `zoneAdmin` methods for managing the deposit allowlist.
///
/// Served by a sequencer for its own list, or by an RPC-only node that relays each request to
/// every sequencer. Writes carry an EIP-712 signature from the configured admin over
/// [`SetDepositAllowed`] or [`ReplaceDepositAllowlist`], valid until `deadline` (Unix seconds, at
/// most [`MAX_SIGNED_WRITE_VALIDITY`] ahead). Callers must wait for each write to return before
/// sending the next one: concurrent writes may be applied in different orders on different
/// sequencers.
#[rpc(server, namespace = "zoneAdmin")]
pub(crate) trait DepositAllowlistApi {
    /// Add (`allowed = true`) or remove (`allowed = false`) depositor addresses.
    #[method(name = "setDepositAllowed")]
    async fn set_deposit_allowed(
        &self,
        addresses: Vec<Address>,
        allowed: bool,
        deadline: u64,
        signature: Bytes,
    ) -> RpcResult<()>;

    /// Replace the whole allowlist.
    #[method(name = "replaceDepositAllowlist")]
    async fn replace_deposit_allowlist(
        &self,
        addresses: Vec<Address>,
        deadline: u64,
        signature: Bytes,
    ) -> RpcResult<()>;

    /// Returns the allowlist in ascending order. Through an RPC-only node, fails unless every
    /// sequencer holds the same list.
    #[method(name = "getDepositAllowlist")]
    async fn get_deposit_allowlist(&self) -> RpcResult<Vec<Address>>;
}

impl DepositAllowlist {
    async fn apply_signed_blocking(&self, write: SignedWrite) -> Result<(), DepositAllowlistError> {
        let allowlist = self.clone();
        tokio::task::spawn_blocking(move || allowlist.apply_signed(write))
            .await
            .map_err(|err| DepositAllowlistError::Internal(err.to_string()))?
    }
}

#[jsonrpsee::core::async_trait]
impl DepositAllowlistApiServer for DepositAllowlist {
    async fn set_deposit_allowed(
        &self,
        addresses: Vec<Address>,
        allowed: bool,
        deadline: u64,
        signature: Bytes,
    ) -> RpcResult<()> {
        let count = addresses.len();
        self.apply_signed_blocking(SignedWrite {
            write: Write::Set { addresses, allowed },
            deadline,
            signature,
        })
        .await?;
        info!(target: "zone::allowlist", count, allowed, "Updated deposit allowlist");
        Ok(())
    }

    async fn replace_deposit_allowlist(
        &self,
        addresses: Vec<Address>,
        deadline: u64,
        signature: Bytes,
    ) -> RpcResult<()> {
        let count = addresses.len();
        self.apply_signed_blocking(SignedWrite {
            write: Write::Replace { addresses },
            deadline,
            signature,
        })
        .await?;
        info!(target: "zone::allowlist", count, "Replaced deposit allowlist");
        Ok(())
    }

    async fn get_deposit_allowlist(&self) -> RpcResult<Vec<Address>> {
        Ok(self.addresses())
    }
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
    let addresses: BTreeSet<Address> = serde_json::from_reader(std::io::BufReader::new(file))
        .wrap_err_with(|| format!("failed to parse deposit allowlist {}", path.display()))?;
    ensure!(
        addresses.len() <= MAX_DEPOSIT_ALLOWLIST_LEN,
        "deposit allowlist {} holds {} addresses; the limit is {MAX_DEPOSIT_ALLOWLIST_LEN}",
        path.display(),
        addresses.len()
    );
    Ok(addresses)
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
    use alloy_signer::SignerSync as _;
    use alloy_signer_local::PrivateKeySigner;

    const ALICE: Address = address!("0x00000000000000000000000000000000000a11ce");
    const BOB: Address = address!("0x0000000000000000000000000000000000000b0b");
    const ZONE_CHAIN_ID: u64 = 421_700_003;

    fn admin_signer() -> PrivateKeySigner {
        PrivateKeySigner::from_bytes(&B256::repeat_byte(0xad)).unwrap()
    }

    fn admin() -> DepositAllowlistAdmin {
        DepositAllowlistAdmin {
            address: admin_signer().address(),
            zone_chain_id: ZONE_CHAIN_ID,
        }
    }

    fn load(path: PathBuf, seed: Option<&Path>) -> eyre::Result<DepositAllowlist> {
        DepositAllowlist::load(path, seed, admin())
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn sign(
        signer: &PrivateKeySigner,
        zone_chain_id: u64,
        write: Write,
        deadline: u64,
    ) -> SignedWrite {
        let mut signed = SignedWrite {
            write,
            deadline,
            signature: Bytes::new(),
        };
        let domain = DepositAllowlistAdmin {
            address: signer.address(),
            zone_chain_id,
        }
        .domain();
        let signature = signer
            .sign_hash_sync(&signed.signing_hash(&domain))
            .unwrap();
        signed.signature = Bytes::copy_from_slice(&signature.as_bytes());
        signed
    }

    fn add_bob() -> Write {
        Write::Set {
            addresses: vec![BOB],
            allowed: true,
        }
    }

    fn write_seed(dir: &Path, addresses: &[Address]) -> PathBuf {
        let seed = dir.join("seed.json");
        std::fs::write(&seed, serde_json::to_vec(addresses).unwrap()).unwrap();
        seed
    }

    #[test]
    fn load_requires_persisted_list_or_seed() {
        let dir = tempfile::tempdir().unwrap();
        let err = load(dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME), None).unwrap_err();
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

        let allowlist = load(path.clone(), Some(&seed)).unwrap();
        assert_eq!(allowlist.addresses(), vec![ALICE]);
        assert_eq!(read_addresses(&path).unwrap(), BTreeSet::from([ALICE]));

        allowlist.set(&[BOB], true).unwrap();
        allowlist.set(&[ALICE], false).unwrap();

        let reloaded = load(path, Some(&seed)).unwrap();
        assert_eq!(reloaded.addresses(), vec![BOB]);
    }

    #[test]
    fn replace_overwrites_the_persisted_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME);
        let seed = write_seed(dir.path(), &[ALICE]);
        let allowlist = load(path.clone(), Some(&seed)).unwrap();

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
        let allowlist = load(path.clone(), Some(&seed)).unwrap();

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
        let allowlist = load(dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME), Some(&seed)).unwrap();
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
        let allowlist = load(dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME), Some(&seed)).unwrap();

        let err = allowlist.reject_unlisted(&[ALICE], &mut []).unwrap_err();
        assert_eq!(err.to_string(), "1 deposit senders but 0 decryptions");
    }

    #[test]
    fn applies_only_writes_the_admin_signed_for_this_zone() {
        let dir = tempfile::tempdir().unwrap();
        let seed = write_seed(dir.path(), &[ALICE]);
        let allowlist = load(dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME), Some(&seed)).unwrap();
        let deadline = now() + 60;

        let stranger = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x5e)).unwrap();
        assert_eq!(
            allowlist.apply_signed(sign(&stranger, ZONE_CHAIN_ID, add_bob(), deadline)),
            Err(DepositAllowlistError::Unauthorized {
                signer: stranger.address()
            })
        );
        // The admin's signature for another zone recovers to a different address here.
        assert!(matches!(
            allowlist.apply_signed(sign(&admin_signer(), ZONE_CHAIN_ID + 1, add_bob(), deadline)),
            Err(DepositAllowlistError::Unauthorized { signer }) if signer != admin().address
        ));
        // A signature does not carry over to a different write.
        let mut tampered = sign(&admin_signer(), ZONE_CHAIN_ID, add_bob(), deadline);
        tampered.write = Write::Set {
            addresses: vec![ALICE],
            allowed: false,
        };
        assert!(matches!(
            allowlist.apply_signed(tampered),
            Err(DepositAllowlistError::Unauthorized { .. })
        ));
        let mut malformed = sign(&admin_signer(), ZONE_CHAIN_ID, add_bob(), deadline);
        malformed.signature = Bytes::from_static(&[1, 2, 3]);
        assert_eq!(
            allowlist.apply_signed(malformed),
            Err(DepositAllowlistError::MalformedSignature)
        );
        assert_eq!(allowlist.addresses(), vec![ALICE]);

        allowlist
            .apply_signed(sign(&admin_signer(), ZONE_CHAIN_ID, add_bob(), deadline))
            .unwrap();
        allowlist
            .apply_signed(sign(
                &admin_signer(),
                ZONE_CHAIN_ID,
                Write::Replace {
                    addresses: vec![BOB],
                },
                deadline,
            ))
            .unwrap();
        assert_eq!(allowlist.addresses(), vec![BOB]);
    }

    #[test]
    fn rejects_writes_outside_the_signature_window() {
        let dir = tempfile::tempdir().unwrap();
        let seed = write_seed(dir.path(), &[ALICE]);
        let allowlist = load(dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME), Some(&seed)).unwrap();
        let max = MAX_SIGNED_WRITE_VALIDITY.as_secs();

        let expired = now() - 1;
        assert_eq!(
            allowlist.apply_signed(sign(&admin_signer(), ZONE_CHAIN_ID, add_bob(), expired)),
            Err(DepositAllowlistError::Expired { deadline: expired })
        );
        let too_far = now() + max + 60;
        assert_eq!(
            allowlist.apply_signed(sign(&admin_signer(), ZONE_CHAIN_ID, add_bob(), too_far)),
            Err(DepositAllowlistError::DeadlineTooFar { deadline: too_far })
        );
        assert_eq!(allowlist.addresses(), vec![ALICE]);

        allowlist
            .apply_signed(sign(
                &admin_signer(),
                ZONE_CHAIN_ID,
                add_bob(),
                now() + max - 60,
            ))
            .unwrap();
        assert_eq!(allowlist.addresses(), vec![BOB, ALICE]);
    }

    #[test]
    fn rejects_writes_that_exceed_the_list_limit() {
        let dir = tempfile::tempdir().unwrap();
        let seed = write_seed(dir.path(), &[]);
        let allowlist = load(dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME), Some(&seed)).unwrap();
        let addresses = (0..=MAX_DEPOSIT_ALLOWLIST_LEN)
            .map(|index| Address::left_padding_from(&u32::try_from(index).unwrap().to_be_bytes()))
            .collect::<Vec<_>>();

        assert_eq!(
            allowlist.replace(addresses.clone()),
            Err(DepositAllowlistError::TooLarge {
                len: MAX_DEPOSIT_ALLOWLIST_LEN + 1
            })
        );
        allowlist
            .replace(addresses[..MAX_DEPOSIT_ALLOWLIST_LEN].to_vec())
            .unwrap();
        assert_eq!(
            allowlist.set(&addresses[MAX_DEPOSIT_ALLOWLIST_LEN..], true),
            Err(DepositAllowlistError::TooLarge {
                len: MAX_DEPOSIT_ALLOWLIST_LEN + 1
            })
        );
        assert_eq!(allowlist.addresses().len(), MAX_DEPOSIT_ALLOWLIST_LEN);
    }
}
