"""Give the zones fixture's dev account ownership of the native factory.

Matches Tempo's zones L1TestNode::install_native_zone_factory owner packing;
leave generated consensus keys, DKG extraData, runtimes and funding intact.
"""
import json
import sys
from pathlib import Path


def configure(genesis):
    factory = "5af2000000000000000000000000000000000000"
    owner = int("f39fd6e51aad88f6f4ce6ab8827279cfffb92266", 16)
    account = next(v for k, v in genesis["alloc"].items() if k.lower().removeprefix("0x") == factory)
    storage = account["storage"]
    slot = next(k for k in storage if int(k, 16) == 0)
    assert int(storage[slot], 16) & 0xffffffff == 1, "factory must be fresh"
    storage[slot] = f"0x{(owner << 32) | 1:064x}"
    return genesis


if __name__ == "__main__":
    path = Path(sys.argv[1])
    path.write_text(json.dumps(configure(json.loads(path.read_text())), indent=2) + "\n")
