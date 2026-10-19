"""Render the selected Tempo DST topology, shared by the runner and tests."""
import json, re, sys
from pathlib import Path
variant, node_image, run_dir, validators, cluster_mode, config = sys.argv[1:7]
validators = int(validators)
cluster_mode = cluster_mode == "1"
run_dir = Path(run_dir)
build_info = dict(line.split('=', 1) for line in (run_dir / 'build-info.env').read_text().splitlines())
revisions = build_info['tempo_revs'].split(',')
args = json.load(open(config)) if config else {}
for kv in sys.argv[7:]:
    k, _, v = kv.partition("=")
    args[k] = v
def arg(key, default):
    return str(args.get(key, default)).lower()
reference = arg("reference", False) == "true"
if arg("load", "") == "zones":
    if validators != 4 or not cluster_mode or reference:
        sys.exit("zones requires four upstream validators and a certified follower")
flags = {
    "default": [],
    "no-prewarm": ["--builder.disable-prewarming"],
    "parallel": ["--builder.parallel"],
    # Persist every 3 blocks with the state-trie frontier 1 block behind the
    # persisted tip: trie reverts and historical overlays run constantly.
    "masking": [
        "--engine.persistence-threshold", "3",
        "--engine.num-state-masking-blocks", "1",
        "--engine.memory-block-buffer-target", "0",
    ],
}[variant]
# Validator variants (bin/tempo-dst/src/cluster.rs Cooldown, Timeouts).
validator_flags = {
    "1s": ["--consensus.connection-per-peer-min-period", "1s"],
    "default": [],
}[arg("cooldown", "1s")] + {
    # Relaxed for Bedrock's instruction-count clock; leader skip stays at
    # Tempo's default.
    "tuned": [
        "--consensus.target-block-time", "1s",
        "--consensus.wait-for-proposal", "3s",
        "--consensus.wait-for-notarizations", "5s",
        "--consensus.worker-threads", "1",
    ],
    "prod": [],
}[arg("timeouts", "tuned")]
# Per-validator engine profiles (validator_engine_diff). Keep in sync with
# bin/tempo-dst/src/cluster.rs: EngineProfile::flags, engine_profiles() and
# the planner's ENGINE_SALT. The assignment draws from the campaign-fixed
# workload_seed (the validators boot once, before the shared warm checkpoint),
# so it matches the planner's config.json and a replay exactly.
engine_diff = arg("validator_engine_diff", False) == "true" and cluster_mode and validators >= 2
MASK = (1 << 64) - 1
def splitmix64(x):
    x = (x + 0x9E3779B97F4A7C15) & MASK
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & MASK
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & MASK
    return x ^ (x >> 31)
ENGINE_SALT = 0x656E67696E656431  # "engined1"
ENGINE_FLAGS = {
    "optimized": ["--engine.state-root-task-compare-updates"],
    "simple": ["--engine.state-root-fallback", "--engine.disable-prewarming",
               "--engine.disable-precompile-cache", "--engine.disable-state-cache",
               "--engine.num-state-masking-blocks", "0"],
    "compare": ["--engine.state-root-task-compare-updates", "--engine.disable-state-cache"],
    "race": ["--engine.state-root-task-timeout", "1ms"],
    "noprune": ["--engine.disable-sparse-trie-cache-pruning"],
}
ENGINE_ALL = ["optimized", "simple", "compare", "race", "noprune"]
def engine_profile_names(seed, count):
    names, state = [], splitmix64((seed ^ ENGINE_SALT) & MASK)
    for i in range(count):
        if i == 0:
            names.append("optimized")
        elif i == 1:
            names.append("simple")
        else:
            state = splitmix64(state)
            names.append(ENGINE_ALL[state % len(ENGINE_ALL)])
    return names
if engine_diff:
    workload_seed = int(arg("workload_seed", 99))
    engine_names = engine_profile_names(workload_seed, validators)
    print("validator_engine_diff: " + " ".join(f"v{i+1}={n}" for i, n in enumerate(engine_names)),
          file=sys.stderr)
def drop(s, block):
    return re.sub(rf"(?m)^ *# >>> {block}\n(.*\n)*? *# <<< {block}\n", "", s)
root = Path("contrib/bedrock-dst")
s = (root / "compose.yaml").read_text()
if not reference:
    s = drop(s, "reference")
zones = arg("load", "") == "zones"
# A certified L1 follower (`tempo`) is attached to the validator cluster for
# zones (always) or with `follower=true` on `validators=N consensus=true`: the
# generic tempo#8263 catch-up detector.
follower = zones or arg("follower", False) == "true"
if follower and not cluster_mode:
    sys.exit("follower=true needs the consensus cluster (validators>=1 consensus=true)")
s = drop(s, "single" if cluster_mode else "validators")
if not follower:
    s = drop(s, "zones-follower")
if cluster_mode:
    template = re.search(r"(?s)(  v1:\n.*?)(?=  # <<< validators\n)", s).group(1)
    peers = (run_dir / 'validator-peers').read_text().strip()
    images = [f"bedrock/tempo-validators:{validators}-rev-{rev[:12]}" for rev in revisions]
    engine_marker = "      # validator engine flags\n"
    def engine_lines(i):
        if engine_diff:
            # The profile's engine flags, then the node variant flags (handled
            # per-node here, so the global anchor replace below is skipped).
            prof = ENGINE_FLAGS[engine_names[i - 1]]
            return "".join(f"      - {f}\n" for f in prof + flags)
        # Off: today's default flag; the global anchor replace adds the variant.
        return "      - --engine.state-root-task-compare-updates\n"
    nodes = []
    for i in range(1, validators + 1):
        node = template.replace('v1', f'v{i}').replace('10.89.77.11', f'10.89.77.{10+i}')
        node = node.replace('bedrock/tempo-validators:pinned', images[(i-1) % len(images)])
        node = node.replace(engine_marker, engine_lines(i))
        if validators == 1:
            node = re.sub(r'(?m)^      - --trusted-peers\n      - enode://[^\n]+\n', '', node)
        else:
            node = re.sub(r'(?m)^      - enode://[^\n]+$', f'      - {peers}', node)
        nodes.append(node)
    s = s.replace(template, ''.join(nodes), 1)
    s = s.replace('  v1-data:\n', ''.join(f'  v{i}-data:\n' for i in range(1, validators + 1)), 1)
    if follower:
        # The follower runs the built validators image and trusts v1's p2p so it
        # catches up through execution-layer sync, not just the follow stream.
        s = s.replace('bedrock/tempo-validators:pinned', images[0])
        s = s.replace('      # follower trusted peers\n', f'      - --trusted-peers\n      - {peers}\n')
zones = arg("load", "") == "zones"
multi = zones and int(arg("zone_sequencers", 1)) == 3
if not zones:
    s = drop(s, "zones")
else:
    window = '      - --rpc.eth-proof-window\n      - "256"\n'
    assert window in s
    s = s.replace(window, window.replace('"256"', '"4096"'), 1)
# One zone flavour: the single sequencer, or the multi-sequencer cluster.
keep, gone = ("zones-multi", "zones-single") if multi else ("zones-single", "zones-multi")
s = drop(s, gone)
# The kept flavour's markers go too, so single-sequencer files are unchanged.
s = re.sub(rf"(?m)^ *# (>>>|<<<) {keep}\n", "", s)
anchor = "      - --engine.state-root-task-compare-updates\n"
# With validator_engine_diff the variant flags are already applied per-validator
# (engine_lines), so skip the global append for the validators to avoid doubling
# it; the single dev node (no cluster) still goes through here.
if not engine_diff:
    s = s.replace(anchor, anchor + "".join(f"      - {f}\n" for f in flags))
s = s.replace("      # validator variant flags\n", "".join(f"      - \"{f}\"\n" for f in validator_flags))
s = s.replace("image: bedrock/tempo-runtime:latest", f"image: {node_image}")
if not cluster_mode and not multi:
    s = s.replace("networks:\n\nvolumes:", "volumes:")
# The validators run the node image with the cluster's /net baked in
# (validators/build.sh).
(run_dir / "compose-run.yaml").write_text(s)
