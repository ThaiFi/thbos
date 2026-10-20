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

use alloy_primitives::{Address, B256, Bytes, Signature, keccak256};
use alloy_sol_types::{Eip712Domain, SolStruct as _, eip712_domain, sol};
use eyre::{WrapErr as _, ensure};
use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::ErrorObjectOwned};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tracing::info;
use zone_l1::{abi::DecryptionData, failed_decryption};

mod relay;
pub(crate) use relay::{AllowlistRelay, apply_relayed_updates};

/// File name of the persisted allowlist inside the node data directory.
pub(crate) const DEPOSIT_ALLOWLIST_FILE_NAME: &str = "deposit-allowlist.json";

/// Longest time a signed write stays valid, bounding how long it can wait before it is applied.
pub(crate) const MAX_SIGNED_WRITE_VALIDITY: Duration = Duration::from_secs(10 * 60);

/// Most addresses the list may hold, so a full list read through an RPC-only node fits in one
/// P2P allowlist frame.
pub(crate) const MAX_DEPOSIT_ALLOWLIST_LEN: usize = 80_000;

sol! {
    /// EIP-712 message authorizing the admin to add (`allowed`) or remove depositors.
    struct SetDepositAllowed {
        address[] addresses;
        bool allowed;
        uint64 nonce;
        uint64 deadline;
    }

    /// EIP-712 message authorizing the admin to replace the whole allowlist.
    struct ReplaceDepositAllowlist {
        address[] addresses;
        uint64 nonce;
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

    /// Check that the admin signed `write` and that its deadline is within the validity window,
    /// returning its EIP-712 signing hash.
    pub(crate) fn authorize(&self, write: &SignedWrite) -> Result<B256, DepositAllowlistError> {
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
        let hash = write.signing_hash(&self.domain());
        let signer = Signature::try_from(write.signature.as_ref())
            .and_then(|signature| signature.recover_address_from_prehash(&hash))
            .map_err(|_| DepositAllowlistError::MalformedSignature)?;
        if signer != self.address {
            return Err(DepositAllowlistError::Unauthorized { signer });
        }
        Ok(hash)
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

/// An allowlist change with the admin signature that authorizes it once, until `deadline`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SignedWrite {
    pub(crate) write: Write,
    /// Must exceed the nonce of the last write the sequencer applied.
    pub(crate) nonce: u64,
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
                nonce: self.nonce,
                deadline: self.deadline,
            }
            .eip712_signing_hash(domain),
            Write::Replace { addresses } => ReplaceDepositAllowlist {
                addresses: addresses.clone(),
                nonce: self.nonce,
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
    #[error("nonce {nonce} does not exceed the last applied nonce {applied}")]
    StaleNonce { nonce: u64, applied: u64 },
    #[error("allowlist would hold {len} addresses; the limit is {MAX_DEPOSIT_ALLOWLIST_LEN}")]
    TooLarge { len: usize },
    #[error("failed to persist the allowlist: {0}")]
    Persist(String),
    #[error("deposit allowlist is not enabled on this sequencer")]
    Disabled,
    #[error("too many allowlist requests in flight; retry later")]
    Busy,
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<DepositAllowlistError> for ErrorObjectOwned {
    fn from(error: DepositAllowlistError) -> Self {
        let code = match error {
            DepositAllowlistError::Persist(_)
            | DepositAllowlistError::Disabled
            | DepositAllowlistError::Busy
            | DepositAllowlistError::Internal(_) => jsonrpsee::types::error::INTERNAL_ERROR_CODE,
            _ => jsonrpsee::types::error::INVALID_PARAMS_CODE,
        };
        Self::owned(code, error.to_string(), None::<()>)
    }
}

/// Persisted allowlist and the last signed write applied to it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct State {
    /// Nonce of the last applied signed write.
    nonce: u64,
    /// EIP-712 signing hash of the last applied signed write, so a retry of that write succeeds
    /// without being applied again.
    last_write: B256,
    addresses: BTreeSet<Address>,
}

impl State {
    /// Commitment to the list, logged so operators can compare sequencers.
    fn list_hash(&self) -> B256 {
        keccak256(
            self.addresses
                .iter()
                .flat_map(|address| address.0.0)
                .collect::<Vec<_>>(),
        )
    }

    fn log(&self, message: &'static str) {
        metrics::gauge!("zone_deposit_allowlist_addresses").set(self.addresses.len() as f64);
        info!(
            target: "zone::allowlist",
            nonce = self.nonce,
            count = self.addresses.len(),
            list_hash = %self.list_hash(),
            "{message}"
        );
    }
}

/// Addresses whose L1 deposits the leader credits, persisted as JSON.
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
    /// Current state; the engine reads its list on every block build.
    state: RwLock<State>,
    /// Serializes writers so updates persist and apply in order without holding `state` across
    /// disk I/O.
    write_lock: Mutex<()>,
}

impl DepositAllowlist {
    /// Load the persisted list from `path`, starting empty when it does not exist yet.
    pub fn load(path: PathBuf, admin: DepositAllowlistAdmin) -> eyre::Result<Self> {
        let state = if path.exists() {
            read_state(&path)?
        } else {
            State::default()
        };
        state.log("Loaded deposit allowlist");
        Ok(Self {
            inner: Arc::new(Inner {
                path,
                admin,
                state: RwLock::new(state),
                write_lock: Mutex::new(()),
            }),
        })
    }

    /// Returns whether deposits from `sender` are credited.
    pub fn contains(&self, sender: &Address) -> bool {
        self.inner.state.read().addresses.contains(sender)
    }

    /// Returns the current list in ascending order.
    pub fn addresses(&self) -> Vec<Address> {
        self.inner.state.read().addresses.iter().copied().collect()
    }

    /// Add or remove `addresses`, persisting the result before it takes effect.
    pub fn set(&self, addresses: &[Address], allowed: bool) -> Result<(), DepositAllowlistError> {
        self.update(|state| {
            let mut next = state.clone();
            apply_set(&mut next.addresses, addresses, allowed);
            Ok(Some(next))
        })
    }

    /// Replace the whole list, persisting it before it takes effect.
    pub fn replace(&self, addresses: Vec<Address>) -> Result<(), DepositAllowlistError> {
        self.update(|state| {
            Ok(Some(State {
                addresses: addresses.into_iter().collect(),
                ..state.clone()
            }))
        })
    }

    /// Apply `write` if the admin signed it, its deadline has not passed, and its nonce exceeds
    /// the last applied one. A retry of the last applied write succeeds without reapplying it.
    pub(crate) fn apply_signed(&self, write: SignedWrite) -> Result<(), DepositAllowlistError> {
        let hash = self.inner.admin.authorize(&write)?;
        self.update(|state| {
            if write.nonce == state.nonce && hash == state.last_write {
                return Ok(None);
            }
            if write.nonce <= state.nonce {
                return Err(DepositAllowlistError::StaleNonce {
                    nonce: write.nonce,
                    applied: state.nonce,
                });
            }
            let mut next = State {
                nonce: write.nonce,
                last_write: hash,
                addresses: state.addresses.clone(),
            };
            match &write.write {
                Write::Set { addresses, allowed } => {
                    apply_set(&mut next.addresses, addresses, *allowed);
                }
                Write::Replace { addresses } => {
                    next.addresses = addresses.iter().copied().collect()
                }
            }
            Ok(Some(next))
        })
    }

    async fn apply_signed_blocking(&self, write: SignedWrite) -> Result<(), DepositAllowlistError> {
        let allowlist = self.clone();
        tokio::task::spawn_blocking(move || allowlist.apply_signed(write))
            .await
            .map_err(|err| DepositAllowlistError::Internal(err.to_string()))?
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
        let state = self.inner.state.read();
        let mut rejected = 0;
        for (sender, decryption) in senders.iter().zip(decryptions) {
            if !state.addresses.contains(sender) {
                *decryption = failed_decryption();
                rejected += 1;
            }
        }
        Ok(rejected)
    }

    /// Persist and install the state `next` derives from the current one. `None` leaves the
    /// state unchanged.
    fn update(
        &self,
        next: impl FnOnce(&State) -> Result<Option<State>, DepositAllowlistError>,
    ) -> Result<(), DepositAllowlistError> {
        let _writer = self.inner.write_lock.lock();
        // Only writers change `state`, so this snapshot stays current until the swap below.
        let Some(next) = next(&self.inner.state.read())? else {
            return Ok(());
        };
        if next.addresses.len() > MAX_DEPOSIT_ALLOWLIST_LEN {
            return Err(DepositAllowlistError::TooLarge {
                len: next.addresses.len(),
            });
        }
        persist(&self.inner.path, &next)
            .map_err(|err| DepositAllowlistError::Persist(format!("{err:#}")))?;
        next.log("Updated deposit allowlist");
        *self.inner.state.write() = next;
        Ok(())
    }
}

fn apply_set(list: &mut BTreeSet<Address>, addresses: &[Address], allowed: bool) {
    for address in addresses {
        if allowed {
            list.insert(*address);
        } else {
            list.remove(address);
        }
    }
}

/// `zoneAdmin` methods for managing the deposit allowlist.
///
/// Served by a sequencer for its own list, or by an RPC-only node that relays each request to
/// every sequencer. Writes carry an EIP-712 signature from the configured admin over
/// [`SetDepositAllowed`] or [`ReplaceDepositAllowlist`]. Each write's `nonce` must exceed the
/// last applied one (Unix milliseconds work), and its `deadline` (Unix seconds) must be at most
/// [`MAX_SIGNED_WRITE_VALIDITY`] ahead. Callers must wait for each write to return before sending
/// the next one, and retry a failed write unchanged.
#[rpc(server, namespace = "zoneAdmin")]
pub(crate) trait DepositAllowlistApi {
    /// Add (`allowed = true`) or remove (`allowed = false`) depositor addresses.
    #[method(name = "setDepositAllowed")]
    async fn set_deposit_allowed(
        &self,
        addresses: Vec<Address>,
        allowed: bool,
        nonce: u64,
        deadline: u64,
        signature: Bytes,
    ) -> RpcResult<()>;

    /// Replace the whole allowlist.
    #[method(name = "replaceDepositAllowlist")]
    async fn replace_deposit_allowlist(
        &self,
        addresses: Vec<Address>,
        nonce: u64,
        deadline: u64,
        signature: Bytes,
    ) -> RpcResult<()>;

    /// Returns the allowlist in ascending order. Through an RPC-only node, fails unless every
    /// sequencer holds the same list.
    #[method(name = "getDepositAllowlist")]
    async fn get_deposit_allowlist(&self) -> RpcResult<Vec<Address>>;
}

#[jsonrpsee::core::async_trait]
impl DepositAllowlistApiServer for DepositAllowlist {
    async fn set_deposit_allowed(
        &self,
        addresses: Vec<Address>,
        allowed: bool,
        nonce: u64,
        deadline: u64,
        signature: Bytes,
    ) -> RpcResult<()> {
        Ok(self
            .apply_signed_blocking(SignedWrite {
                write: Write::Set { addresses, allowed },
                nonce,
                deadline,
                signature,
            })
            .await?)
    }

    async fn replace_deposit_allowlist(
        &self,
        addresses: Vec<Address>,
        nonce: u64,
        deadline: u64,
        signature: Bytes,
    ) -> RpcResult<()> {
        Ok(self
            .apply_signed_blocking(SignedWrite {
                write: Write::Replace { addresses },
                nonce,
                deadline,
                signature,
            })
            .await?)
    }

    async fn get_deposit_allowlist(&self) -> RpcResult<Vec<Address>> {
        Ok(self.addresses())
    }
}

fn read_state(path: &Path) -> eyre::Result<State> {
    let file = File::open(path)
        .wrap_err_with(|| format!("failed to open deposit allowlist {}", path.display()))?;
    let state: State = serde_json::from_reader(std::io::BufReader::new(file))
        .wrap_err_with(|| format!("failed to parse deposit allowlist {}", path.display()))?;
    ensure!(
        state.addresses.len() <= MAX_DEPOSIT_ALLOWLIST_LEN,
        "deposit allowlist {} holds {} addresses; the limit is {MAX_DEPOSIT_ALLOWLIST_LEN}",
        path.display(),
        state.addresses.len()
    );
    Ok(state)
}

/// Atomically replace `path` with `state`: write a sibling temp file, fsync it, rename it over
/// `path`, then fsync the directory so the rename survives a crash.
fn persist(path: &Path, state: &State) -> eyre::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| eyre::eyre!("deposit allowlist {} has no parent", path.display()))?;
    std::fs::create_dir_all(dir).wrap_err_with(|| format!("failed to create {}", dir.display()))?;
    let mut file = tempfile::NamedTempFile::new_in(dir)
        .wrap_err_with(|| format!("failed to create temp file in {}", dir.display()))?;
    serde_json::to_writer_pretty(&mut file, state)
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
    use zone_l1::abi::ChaumPedersenProof;

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

    fn load(path: PathBuf) -> DepositAllowlist {
        DepositAllowlist::load(path, admin()).unwrap()
    }

    /// An allowlist holding only ALICE.
    fn alice_only(dir: &Path) -> DepositAllowlist {
        let allowlist = load(dir.join(DEPOSIT_ALLOWLIST_FILE_NAME));
        allowlist.replace(vec![ALICE]).unwrap();
        allowlist
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn sign_for(
        signer: &PrivateKeySigner,
        zone_chain_id: u64,
        write: Write,
        nonce: u64,
        deadline: u64,
    ) -> SignedWrite {
        let mut signed = SignedWrite {
            write,
            nonce,
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

    /// A write the admin signed for this zone, valid for a minute.
    fn sign(write: Write, nonce: u64) -> SignedWrite {
        sign_for(&admin_signer(), ZONE_CHAIN_ID, write, nonce, now() + 60)
    }

    fn set(addresses: &[Address], allowed: bool) -> Write {
        Write::Set {
            addresses: addresses.to_vec(),
            allowed,
        }
    }

    #[test]
    fn starts_empty_and_persists_updates_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data").join(DEPOSIT_ALLOWLIST_FILE_NAME);

        let allowlist = load(path.clone());
        assert!(allowlist.addresses().is_empty());
        assert!(!path.exists(), "loading must not create the file");

        allowlist.set(&[ALICE, BOB], true).unwrap();
        allowlist
            .apply_signed(sign(set(&[ALICE], false), 7))
            .unwrap();

        let reloaded = load(path);
        assert_eq!(reloaded.addresses(), vec![BOB]);
        // The nonce survives the restart, so the applied write cannot be replayed afterwards.
        assert_eq!(
            reloaded.apply_signed(sign(set(&[ALICE], true), 7)),
            Err(DepositAllowlistError::StaleNonce {
                nonce: 7,
                applied: 7
            })
        );
    }

    #[test]
    fn replace_overwrites_the_persisted_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME);
        let allowlist = alice_only(dir.path());

        allowlist.replace(vec![BOB]).unwrap();

        assert!(!allowlist.contains(&ALICE));
        assert!(allowlist.contains(&BOB));
        assert_eq!(read_state(&path).unwrap().addresses, BTreeSet::from([BOB]));
    }

    #[test]
    fn failed_persist_leaves_the_list_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME);
        let allowlist = alice_only(dir.path());

        // A directory at the target path makes the rename fail.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();

        let err = allowlist.set(&[BOB], true).unwrap_err();
        assert!(err.to_string().contains("failed to replace"), "{err}");
        assert_eq!(allowlist.addresses(), vec![ALICE]);
    }

    #[test]
    fn applies_only_writes_the_admin_signed_for_this_zone() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = alice_only(dir.path());
        let deadline = now() + 60;

        let stranger = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x5e)).unwrap();
        assert_eq!(
            allowlist.apply_signed(sign_for(
                &stranger,
                ZONE_CHAIN_ID,
                set(&[BOB], true),
                1,
                deadline
            )),
            Err(DepositAllowlistError::Unauthorized {
                signer: stranger.address()
            })
        );
        // The admin's signature for another zone recovers to a different address here.
        assert!(matches!(
            allowlist.apply_signed(sign_for(
                &admin_signer(),
                ZONE_CHAIN_ID + 1,
                set(&[BOB], true),
                1,
                deadline
            )),
            Err(DepositAllowlistError::Unauthorized { signer }) if signer != admin().address
        ));
        // A signature does not carry over to a different write or nonce.
        let mut tampered = sign(set(&[BOB], true), 1);
        tampered.write = set(&[ALICE], false);
        assert!(matches!(
            allowlist.apply_signed(tampered),
            Err(DepositAllowlistError::Unauthorized { .. })
        ));
        let mut renonced = sign(set(&[BOB], true), 1);
        renonced.nonce = 2;
        assert!(matches!(
            allowlist.apply_signed(renonced),
            Err(DepositAllowlistError::Unauthorized { .. })
        ));
        let mut malformed = sign(set(&[BOB], true), 1);
        malformed.signature = Bytes::from_static(&[1, 2, 3]);
        assert_eq!(
            allowlist.apply_signed(malformed),
            Err(DepositAllowlistError::MalformedSignature)
        );
        assert_eq!(allowlist.addresses(), vec![ALICE]);

        allowlist.apply_signed(sign(set(&[BOB], true), 1)).unwrap();
        allowlist
            .apply_signed(sign(
                Write::Replace {
                    addresses: vec![BOB],
                },
                2,
            ))
            .unwrap();
        assert_eq!(allowlist.addresses(), vec![BOB]);
    }

    #[test]
    fn rejects_replayed_writes_but_accepts_a_retry_of_the_last_one() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = alice_only(dir.path());
        let add_bob = sign(set(&[BOB], true), 10);
        let remove_bob = sign(set(&[BOB], false), 20);

        allowlist.apply_signed(add_bob.clone()).unwrap();
        allowlist.apply_signed(remove_bob.clone()).unwrap();
        // Retrying the last write succeeds and changes nothing.
        allowlist.apply_signed(remove_bob).unwrap();
        assert_eq!(allowlist.addresses(), vec![ALICE]);

        // Replaying the earlier add cannot undo the removal.
        assert_eq!(
            allowlist.apply_signed(add_bob),
            Err(DepositAllowlistError::StaleNonce {
                nonce: 10,
                applied: 20
            })
        );
        // A different write reusing the last nonce is rejected too.
        assert_eq!(
            allowlist.apply_signed(sign(set(&[BOB], true), 20)),
            Err(DepositAllowlistError::StaleNonce {
                nonce: 20,
                applied: 20
            })
        );
        assert_eq!(allowlist.addresses(), vec![ALICE]);
    }

    #[test]
    fn rejects_writes_outside_the_signature_window() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = alice_only(dir.path());
        let max = MAX_SIGNED_WRITE_VALIDITY.as_secs();
        let sign_until = |deadline| {
            sign_for(
                &admin_signer(),
                ZONE_CHAIN_ID,
                set(&[BOB], true),
                1,
                deadline,
            )
        };

        let expired = now() - 1;
        assert_eq!(
            allowlist.apply_signed(sign_until(expired)),
            Err(DepositAllowlistError::Expired { deadline: expired })
        );
        let too_far = now() + max + 60;
        assert_eq!(
            allowlist.apply_signed(sign_until(too_far)),
            Err(DepositAllowlistError::DeadlineTooFar { deadline: too_far })
        );
        assert_eq!(allowlist.addresses(), vec![ALICE]);

        allowlist
            .apply_signed(sign_until(now() + max - 60))
            .unwrap();
        assert_eq!(allowlist.addresses(), vec![BOB, ALICE]);
    }

    #[test]
    fn rejects_writes_that_exceed_the_list_limit() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = load(dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME));
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

    #[test]
    fn reject_unlisted_zeroes_only_unlisted_senders() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = alice_only(dir.path());
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
        assert_eq!(decryptions[1], failed_decryption());
        assert_eq!(decryptions[2], valid);
    }

    #[test]
    fn reject_unlisted_requires_one_decryption_per_sender() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = alice_only(dir.path());

        let err = allowlist.reject_unlisted(&[ALICE], &mut []).unwrap_err();
        assert_eq!(err.to_string(), "1 deposit senders but 0 decryptions");
    }
}
