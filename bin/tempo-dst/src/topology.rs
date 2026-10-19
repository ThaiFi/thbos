// SPDX-License-Identifier: GPL-2.0

//! The declarative node topology: a single internal model of the nodes a run
//! brings up, so deploy, warmup, finalize and the nemesis read one source of
//! truth instead of each branching on `cluster`/`reference`/`validators` and
//! hardcoding container names, binaries and ports.
//!
//! Step 1 encodes today's exact behavior, no more:
//!
//! - the single dev node (`tempo`), optionally with its reference (`tempo-ref`,
//!   `reference=true`);
//! - zones: a certified `tempo` follower and four independent upstream validators;
//! - the four-validator cluster (`validators=4`): `v1..v4`, consensus on 8000,
//!   from the generated genesis at `/net/genesis.json` (see [`crate::cluster`]),
//!   optionally with a certified L1 follower (`tempo`) appended (`follower=true`).
//!
//! The container names, binaries and RPC endpoints are read from the existing
//! constants ([`crate::common::NODE_CONTAINER`],
//! [`crate::common::REFERENCE_CONTAINER`], [`crate::cluster::ValidatorId`]), so
//! the model is a view over today's wiring rather than a second copy of it.
//! Later steps grow it (compose templating, new nodes, workload args).
//!
//! Nodes are a `Vec` in a fixed order (primary, then reference, or `v1..v4`):
//! callers iterate it directly, so nothing feeds host-ordered state (e.g. a
//! `HashMap`) into a verdict.
//!
//! This is the shared model for a multi-step generalization: some of the
//! selectors, roles (`Zone`/`Prover`), ports and `ImageRef` metadata are the
//! declared API that later steps (compose templating, new nodes) consume, so
//! they are present but not all exercised yet — hence the module-wide
//! `dead_code` allowance.
#![allow(dead_code)]

use crate::{
    cluster::{StorageLayer, ValidatorId},
    common::{Config, NODE_CONTAINER, REFERENCE_CONTAINER},
};

/// The Tempo node binary every node runs today (the reth-based `tempo`).
pub const TEMPO_BIN: &str = "/usr/local/bin/tempo";
/// The dev node's and reference's image (compose `tempo`/`tempo-ref`).
pub const LOCALNET_IMAGE: &str = "bedrock/tempo-localnet:pinned";
/// The cluster validators' image (compose `v1..v4`).
pub const VALIDATORS_IMAGE: &str = "bedrock/tempo-validators:pinned";
/// The dev node's and reference's data directory (`--datadir`).
const DATADIR: &str = "/data";
/// The chain the cluster validators run (the generated genesis in the image).
const CLUSTER_CHAIN: &str = "/net/genesis.json";
/// The chain the dev node and reference run unless `TEMPO_DST_CHAIN` overrides
/// it (finalize reads the same env var).
const DEV_CHAIN_ENV: &str = "TEMPO_DST_CHAIN";
const DEV_CHAIN: &str = "dev";

/// What a node is for. Drives its oracle labels and how finalize treats it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The node under test (the dev node, or the load's target).
    Primary,
    /// A second node that follows the primary and is diffed against it (E7).
    Reference,
    /// A consensus validator in the `validators=4` cluster.
    Validator,
    /// A zones sequencer (reserved for a later step; not emitted yet).
    Zone,
    /// A zones prover (reserved for a later step; not emitted yet).
    Prover,
    /// Consensus validators feeding the zones L1 follower.
    Upstream,
    /// A certified L1 consensus follower attached to the validator cluster
    /// (`follower=true`): an extra node that follows certified consensus
    /// without validating, driven behind to exercise the tempo#8263 catch-up
    /// class. (Zones instead run their follower as the `Primary`.)
    Follower,
}

/// A node's image. A thin newtype today (the compose image name); kept distinct
/// so a later step can grow it (digest, build args) without touching callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef(pub String);

impl ImageRef {
    fn new(name: &str) -> ImageRef {
        ImageRef(name.to_string())
    }

    /// The compose image name.
    pub fn name(&self) -> &str {
        &self.0
    }
}

/// A node's listening ports; `None` where the node does not expose one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ports {
    /// JSON-RPC (`--http.port`).
    pub rpc: Option<u16>,
    /// Engine API, if exposed separately (the dev node runs it in-process).
    pub engine: Option<u16>,
    /// Execution-layer p2p.
    pub p2p: Option<u16>,
    /// Consensus p2p (the cluster's commonware mesh).
    pub consensus: Option<u16>,
}

/// One node of the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSpec {
    /// Container name (and the key [`Topology::by_name`] looks up).
    pub name: String,
    /// The image it runs.
    pub image: ImageRef,
    /// The binary its entrypoint execs (`node`, `re-execute`, `db …`).
    pub binary: String,
    /// What the node is for.
    pub role: Role,
    /// Its listening ports.
    pub ports: Ports,
    /// Its data directory (`--datadir`).
    pub datadir: String,
    /// The chain spec it runs (`--chain`, or `dev`).
    pub chain: String,
    /// The layer under its datadir that can lose un-synced writes, if any.
    pub storage: Option<StorageLayer>,
}

impl NodeSpec {
    /// The cluster validator this node is, if it is one (so cluster oracle code
    /// keyed on [`ValidatorId`] can be fed from the topology).
    pub fn validator_id(&self) -> Option<ValidatorId> {
        ValidatorId::of_container(&self.name)
    }
}

/// The nodes a run brings up, in a stable order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Topology {
    pub nodes: Vec<NodeSpec>,
}

impl Topology {
    /// Every node, in order.
    pub fn iter(&self) -> std::slice::Iter<'_, NodeSpec> {
        self.nodes.iter()
    }

    /// The run's primary node: the dedicated dev node, or — in the cluster,
    /// which has no dev node — its first validator (`v1`), which the load and
    /// deploys target. Always present (a topology is never empty).
    pub fn primary(&self) -> &NodeSpec {
        self.by_role(Role::Primary)
            .next()
            .or_else(|| self.nodes.first())
            .expect("a topology always has at least one node")
    }

    /// The reference node, if the run has one.
    pub fn reference(&self) -> Option<&NodeSpec> {
        self.by_role(Role::Reference).next()
    }

    /// The cluster validators, in order (empty outside the cluster).
    pub fn validators(&self) -> impl Iterator<Item = &NodeSpec> {
        self.by_role(Role::Validator)
    }

    /// The certified L1 follower, if the run has one: the zones primary (with
    /// its upstreams), or the generic cluster's extra `tempo` follower (with its
    /// validators). Always the `tempo` container; `None` for a lone dev node.
    pub fn follower(&self) -> Option<&NodeSpec> {
        let has_consensus = self.by_role(Role::Validator).next().is_some()
            || self.by_role(Role::Upstream).next().is_some();
        has_consensus
            .then(|| self.by_name(NODE_CONTAINER))
            .flatten()
    }

    /// The node named `name`, if any.
    pub fn by_name(&self, name: &str) -> Option<&NodeSpec> {
        self.nodes.iter().find(|n| n.name == name)
    }

    /// Every node with `role`, in order.
    pub fn by_role(&self, role: Role) -> impl Iterator<Item = &NodeSpec> {
        self.nodes.iter().filter(move |n| n.role == role)
    }
}

/// The dev node's and reference's chain (`TEMPO_DST_CHAIN`, else `dev`).
fn dev_chain() -> String {
    std::env::var(DEV_CHAIN_ENV).unwrap_or_else(|_| DEV_CHAIN.into())
}

/// The dev node (`tempo`).
fn primary_node() -> NodeSpec {
    NodeSpec {
        name: NODE_CONTAINER.to_string(),
        image: ImageRef::new(LOCALNET_IMAGE),
        binary: TEMPO_BIN.to_string(),
        role: Role::Primary,
        ports: Ports {
            rpc: Some(8545),
            ..Ports::default()
        },
        datadir: DATADIR.to_string(),
        chain: dev_chain(),
        storage: None,
    }
}

/// The reference node (`tempo-ref`).
fn reference_node() -> NodeSpec {
    NodeSpec {
        name: REFERENCE_CONTAINER.to_string(),
        image: ImageRef::new(LOCALNET_IMAGE),
        binary: TEMPO_BIN.to_string(),
        role: Role::Reference,
        ports: Ports {
            rpc: Some(8547),
            ..Ports::default()
        },
        datadir: DATADIR.to_string(),
        chain: dev_chain(),
        storage: None,
    }
}

/// A cluster validator (`v1..v4`), with `storage` under its datadir if any.
fn validator_node(v: ValidatorId, storage: Option<StorageLayer>) -> NodeSpec {
    NodeSpec {
        name: v.container().to_string(),
        image: ImageRef::new(VALIDATORS_IMAGE),
        binary: TEMPO_BIN.to_string(),
        role: Role::Validator,
        ports: Ports {
            rpc: Some(8545),
            engine: None,
            // Execution-layer p2p is 8001, consensus p2p is 8000 (cluster.rs).
            p2p: Some(8001),
            consensus: Some(crate::cluster::CONSENSUS_PORT),
        },
        datadir: DATADIR.to_string(),
        chain: CLUSTER_CHAIN.to_string(),
        storage,
    }
}

/// A certified L1 follower (`tempo`) attached to the validator cluster: it runs
/// the validators' generated chain and follows certified consensus without
/// validating. Same container as the dev node, so the follower's snapshot,
/// nemesis and catch-up oracle key on [`NODE_CONTAINER`].
fn follower_node() -> NodeSpec {
    NodeSpec {
        name: NODE_CONTAINER.to_string(),
        image: ImageRef::new(VALIDATORS_IMAGE),
        binary: TEMPO_BIN.to_string(),
        role: Role::Follower,
        ports: Ports {
            rpc: Some(8545),
            ..Ports::default()
        },
        datadir: DATADIR.to_string(),
        chain: CLUSTER_CHAIN.to_string(),
        storage: None,
    }
}

/// Builds the topology from its shaping inputs: whether the four-validator
/// cluster runs (with its storage layer), whether the reference node does, and
/// whether a certified L1 follower is attached to the cluster. The one place
/// that knows what nodes a run has.
fn build(cluster: Option<Option<StorageLayer>>, reference: bool, follower: bool) -> Topology {
    let nodes = match cluster {
        // The cluster replaces the dev node (README "Validators"), optionally
        // with a certified follower appended after the validators.
        Some(storage) => {
            let mut nodes: Vec<NodeSpec> = ValidatorId::all()
                .map(|v| validator_node(v, storage))
                .collect();
            if follower {
                nodes.push(follower_node());
            }
            nodes
        }
        None => {
            let mut nodes = vec![primary_node()];
            if reference {
                nodes.push(reference_node());
            }
            nodes
        }
    };
    Topology { nodes }
}

/// The topology the guest config (`config.json`) describes.
pub fn topology(cfg: &Config) -> Topology {
    if cfg.zones {
        zones_topology()
    } else {
        build(
            cfg.cluster.as_ref().map(|c| c.storage),
            cfg.reference,
            cfg.follower,
        )
    }
}

impl Topology {
    /// The topology from the guest config (finalize, nemesis).
    pub fn from_config(cfg: &Config) -> Topology {
        topology(cfg)
    }

    /// The topology from the planner's workload args (warmup, which runs
    /// before `config.json` exists). Produces the same nodes as
    /// [`Topology::from_config`] for the matching config.
    pub fn from_args(args: &crate::planner::TempoArgs) -> Topology {
        if args.load == crate::campaign::Load::Zones {
            return zones_topology();
        }
        let cluster = args.cluster().then_some(args.storage);
        build(cluster, args.reference, args.follower)
    }
}

/// Zones use the generated consensus chain for both upstreams and the follower.
fn zones_topology() -> Topology {
    let mut follower = primary_node();
    follower.chain = CLUSTER_CHAIN.into();
    follower.image = ImageRef::new(VALIDATORS_IMAGE);
    let mut nodes = vec![follower];
    nodes.extend(ValidatorId::all().map(|v| {
        let mut upstream = validator_node(v, None);
        upstream.role = Role::Upstream;
        upstream
    }));
    Topology { nodes }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::ClusterConfig;

    fn cfg_single(reference: bool) -> Config {
        Config {
            reference,
            ..Config::default()
        }
    }

    fn cfg_cluster(storage: Option<StorageLayer>) -> Config {
        Config {
            cluster: Some(ClusterConfig {
                cooldown: Default::default(),
                timeouts: Default::default(),
                faults: Vec::new(),
                storage,
                engine_profiles: Vec::new(),
                first_load_target: ValidatorId::new(1).unwrap(),
            }),
            ..Config::default()
        }
    }

    #[test]
    fn single_node_is_just_the_primary() {
        let t = topology(&cfg_single(false));
        assert_eq!(t.nodes.len(), 1);
        let p = t.primary();
        assert_eq!(p.name, "tempo");
        assert_eq!(p.binary, TEMPO_BIN);
        assert_eq!(p.image.name(), LOCALNET_IMAGE);
        assert_eq!(p.role, Role::Primary);
        assert_eq!(p.ports.rpc, Some(8545));
        assert_eq!(p.chain, "dev");
        assert!(t.reference().is_none());
        assert_eq!(t.validators().count(), 0);
        assert!(p.validator_id().is_none());
    }

    #[test]
    fn reference_is_appended_after_the_primary() {
        let t = topology(&cfg_single(true));
        assert_eq!(t.nodes.len(), 2);
        // Stable order: primary first, reference second.
        assert_eq!(t.nodes[0].name, "tempo");
        assert_eq!(t.nodes[1].name, "tempo-ref");
        let r = t.reference().expect("reference");
        assert_eq!(r.role, Role::Reference);
        assert_eq!(r.binary, TEMPO_BIN);
        assert_eq!(r.image.name(), LOCALNET_IMAGE);
        assert_eq!(r.ports.rpc, Some(8547));
        assert_eq!(r.chain, "dev");
    }

    #[test]
    fn cluster_is_v1_through_v4_on_the_genesis() {
        let t = topology(&cfg_cluster(None));
        let names: Vec<&str> = t.validators().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["v1", "v2", "v3", "v4"]);
        for (i, n) in t.validators().enumerate() {
            assert_eq!(n.role, Role::Validator);
            assert_eq!(n.binary, TEMPO_BIN);
            assert_eq!(n.image.name(), VALIDATORS_IMAGE);
            assert_eq!(n.chain, "/net/genesis.json");
            assert_eq!(n.ports.consensus, Some(8000));
            assert_eq!(n.ports.rpc, Some(8545));
            assert_eq!(n.storage, None);
            // The cluster replaces the dev node: the primary is a validator.
            assert_eq!(n.validator_id(), ValidatorId::new((i + 1) as u8));
        }
        // No separate dev node or reference when the cluster runs.
        assert_eq!(t.primary().name, "v1");
        assert!(t.reference().is_none());
    }

    #[test]
    fn cluster_storage_layer_reaches_every_validator() {
        let t = topology(&cfg_cluster(Some(StorageLayer::Lazyfs)));
        assert!(t
            .validators()
            .all(|n| n.storage == Some(StorageLayer::Lazyfs)));
    }

    #[test]
    fn by_name_and_by_role_select_nodes() {
        let t = topology(&cfg_single(true));
        assert_eq!(
            t.by_name("tempo-ref").map(|n| n.role),
            Some(Role::Reference)
        );
        assert!(t.by_name("v1").is_none());
        assert_eq!(t.by_role(Role::Primary).count(), 1);
        assert_eq!(t.iter().count(), 2);
    }

    #[test]
    fn from_args_matches_from_config() {
        use crate::planner::TempoArgs;
        // Single node, no reference.
        let a = TempoArgs::default();
        assert_eq!(Topology::from_args(&a), topology(&cfg_single(false)));
        // Reference.
        let a = TempoArgs {
            reference: true,
            ..TempoArgs::default()
        };
        assert_eq!(Topology::from_args(&a), topology(&cfg_single(true)));
        // Cluster, with a storage layer.
        let a = TempoArgs {
            validators: 4,
            storage: Some(StorageLayer::Lazyfs),
            ..TempoArgs::default()
        };
        assert_eq!(
            Topology::from_args(&a),
            topology(&cfg_cluster(Some(StorageLayer::Lazyfs)))
        );
    }
    #[test]
    fn zones_primary_is_a_certified_chain_follower_with_independent_upstreams() {
        let cfg = Config {
            zones: true,
            ..Config::default()
        };
        let topo = topology(&cfg);
        assert_eq!(topo.primary().name, NODE_CONTAINER);
        assert_eq!(topo.primary().chain, CLUSTER_CHAIN);
        assert_eq!(topo.primary().image.name(), VALIDATORS_IMAGE);
        assert_eq!(topo.by_role(Role::Upstream).count(), 4);
        assert_eq!(topo.validators().count(), 0);
        assert!(topo.reference().is_none());
        let args = crate::planner::TempoArgs {
            load: crate::campaign::Load::Zones,
            ..Default::default()
        };
        assert_eq!(Topology::from_args(&args), topo);
    }

    #[test]
    fn a_generic_follower_is_appended_to_the_validator_cluster() {
        let cfg = Config {
            follower: true,
            ..cfg_cluster(None)
        };
        let t = topology(&cfg);
        // v1..v4 then the certified follower (tempo).
        let names: Vec<&str> = t.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["v1", "v2", "v3", "v4", "tempo"]);
        let follower = t.follower().expect("follower");
        assert_eq!(follower.name, NODE_CONTAINER);
        assert_eq!(follower.role, Role::Follower);
        assert_eq!(follower.chain, CLUSTER_CHAIN);
        assert_eq!(follower.image.name(), VALIDATORS_IMAGE);
        // The load still targets a validator, not the follower.
        assert_eq!(t.primary().name, "v1");
        assert_eq!(t.validators().count(), 4);
        // Off: a plain cluster has no follower; a lone dev node has none either.
        assert!(topology(&cfg_cluster(None)).follower().is_none());
        assert!(topology(&cfg_single(false)).follower().is_none());
        let args = crate::planner::TempoArgs {
            validators: 4,
            consensus: true,
            follower: true,
            ..Default::default()
        };
        assert_eq!(Topology::from_args(&args), t);
    }
}
