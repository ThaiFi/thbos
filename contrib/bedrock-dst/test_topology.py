"""Semantic checks for the generated zones and ordinary DST configurations.

Run: uv run --with pyyaml python -m unittest discover -s contrib/bedrock-dst -p test_topology.py
"""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


class UniqueKeys(yaml.SafeLoader):
    pass


def mapping(loader, node):
    result = {}
    for key, value in node.value:
        key = loader.construct_object(key)
        if key in result:
            raise AssertionError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value)
    return result


UniqueKeys.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def engine_flag(command, flag):
    return int(command[command.index(flag) + 1])


class TopologyTests(unittest.TestCase):
    def assert_follower_engine_boots(self, command):
        # reth refuses to start unless num-state-masking-blocks +
        # memory-block-buffer-target < persistence-threshold. The follower must
        # set all three (the reth defaults 10 + 3 violate this), while keeping
        # masking small enough that catch-up still crosses the persistence
        # frontier.
        masking = engine_flag(command, "--engine.num-state-masking-blocks")
        buffer = engine_flag(command, "--engine.memory-block-buffer-target")
        threshold = engine_flag(command, "--engine.persistence-threshold")
        self.assertLess(masking + buffer, threshold)
        self.assertGreaterEqual(masking, 1)  # still exercises the catch-up path

    def render(self, args, validators, cluster):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            (run / "build-info.env").write_text("tempo_revs=" + "a" * 40 + "\n")
            (run / "validator-peers").write_text("enode://" + "1" * 128 + "@10.89.77.11:8001\n")
            subprocess.run([sys.executable, str(ROOT / "contrib/bedrock-dst/render-compose.py"),
                            "default", "bedrock/tempo-runtime:test", str(run),
                            str(validators), str(int(cluster)), "", *args], cwd=ROOT, check=True)
            return yaml.load((run / "compose-run.yaml").read_text(), Loader=UniqueKeys)

    def test_zones_is_always_certified_and_has_four_upstreams(self):
        for count in (1, 3):
            with self.subTest(sequencers=count):
                config = self.render(["load=zones", f"zone_sequencers={count}"], 4, True)
                services = config["services"]
                self.assertEqual([name for name in services if name.startswith("v")], ["v1", "v2", "v3", "v4"])
                follower = services["tempo"]
                command = follower["command"]
                self.assertNotIn("--dev", command)
                self.assertNotIn("--follow.nocertify", command)
                self.assertEqual(command[command.index("--follow") + 1], "ws://10.89.77.11:8546")
                self.assertEqual(command[command.index("--chain") + 1], "/net/genesis.json")
                self.assertEqual(command[command.index("--rpc.eth-proof-window") + 1], "4096")
                self.assert_follower_engine_boots(command)
                self.assertEqual(follower["volumes"], ["tempo-data:/data"])
                self.assertNotIn("tempo-ref", services)
                for i in range(1, 5):
                    validator = services[f"v{i}"]
                    self.assertNotIn("--follow", validator["command"])
                    self.assertIn("--consensus.signing-share", validator["command"])
                    self.assertIn("--ws", validator["command"])
                    self.assertEqual(validator["image"], follower["image"])
                    self.assertEqual(validator["volumes"], [f"v{i}-data:/data"])
                    self.assertIn(f"v{i}-data", config["volumes"])
                self.assertIn("validators", config["networks"])
                if count == 3:
                    self.assertIn("zseq", config["networks"])
                    self.assertIn("zone-0", services)
                    self.assertNotIn("zone", services)
                else:
                    self.assertNotIn("zseq", config["networks"])
                    self.assertIn("zone", services)

    def test_ordinary_dev_reference_and_validator_topologies_still_render(self):
        dev = self.render([], 1, False)
        self.assertIn("--dev", dev["services"]["tempo"]["command"])
        self.assertNotIn("networks", dev)
        reference = self.render(["reference=true"], 1, False)
        self.assertIn("--follow.nocertify", reference["services"]["tempo-ref"]["command"])
        for count in (1, 4):
            cluster = self.render([f"validators={count}", "consensus=true"], count, True)
            self.assertNotIn("tempo", cluster["services"])
            self.assertEqual(len([n for n in cluster["services"] if n.startswith("v")]), count)
            self.assertEqual(set(cluster["networks"]), {"validators"})

    def test_a_generic_follower_attaches_to_the_cluster_under_any_load(self):
        # follower=true on the consensus cluster adds one certified follower
        # (tempo) alongside the validators, under an ordinary load (not zones).
        config = self.render(["load=trie", "validators=4", "consensus=true", "follower=true"], 4, True)
        services = config["services"]
        self.assertEqual([n for n in services if n.startswith("v")], ["v1", "v2", "v3", "v4"])
        follower = services["tempo"]
        command = follower["command"]
        self.assertNotIn("--dev", command)
        # It follows v1's certified consensus and trusts v1's execution p2p.
        self.assertEqual(command[command.index("--follow") + 1], "ws://10.89.77.11:8546")
        self.assertEqual(command[command.index("--chain") + 1], "/net/genesis.json")
        self.assertIn("--trusted-peers", command)
        self.assert_follower_engine_boots(command)
        self.assertEqual(follower["volumes"], ["tempo-data:/data"])
        # No zone services under a non-zones load.
        self.assertNotIn("zone", services)
        self.assertNotIn("zseq", config.get("networks", {}))

    def test_zones_genesis_override_preserves_consensus_and_all_other_allocations(self):
        spec = importlib.util.spec_from_file_location("zones_genesis", ROOT / "contrib/bedrock-dst/validators/zones-genesis.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        factory = "0x5AF2000000000000000000000000000000000000"
        slot = "0x" + "0" * 64
        genesis = {"extraData": "0x1234", "config": {"chainId": 1337}, "alloc": {
            factory: {"code": "0xef", "storage": {slot: "0x" + "0" * 63 + "1", "0x01": "0x42"}},
            "0xabc": {"balance": "0x100"}}}
        before = copy.deepcopy(genesis)
        actual = module.configure(genesis)
        value = int(actual["alloc"][factory]["storage"][slot], 16)
        self.assertEqual(value >> 32, int("f39fd6e51aad88f6f4ce6ab8827279cfffb92266", 16))
        self.assertEqual(value & 0xffffffff, 1)
        actual["alloc"][factory]["storage"][slot] = before["alloc"][factory]["storage"][slot]
        self.assertEqual(actual, before)


if __name__ == "__main__":
    unittest.main()
