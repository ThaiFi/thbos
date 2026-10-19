// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Writes exactly the requested slot and nothing else, so its storage trie is
/// shaped only by the workload. Raw slots (not mapping keys): the trie path is
/// keccak256(bytes32(slot)).
contract RawStorage {
    function set(uint256 slot, uint256 value) external {
        assembly {
            sstore(slot, value)
        }
    }
}
