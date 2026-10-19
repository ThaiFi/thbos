// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Append-only hash chain (Antithesis "chain of blocks"). Each append links
/// the payload to the stored head, so every included append is valid whatever
/// the writer lost with the node's transaction pool, and `head` after n
/// appends commits to the whole history.
///
/// Storage: slot 0 `length`, slot 1 `head`, `links[i]` at
/// keccak256(abi.encode(i, 2)). Each append emits `Appended`, so the history
/// can also be rebuilt from receipts, independently of state.
contract ChainOfBlocks {
    uint256 public length;
    bytes32 public head;
    mapping(uint256 => bytes32) public links;

    event Appended(uint256 index, bytes32 payload, bytes32 link);

    function append(bytes32 payload) external {
        uint256 index = length;
        bytes32 link = keccak256(abi.encode(head, payload, index));
        links[index] = link;
        head = link;
        length = index + 1;
        emit Appended(index, payload, link);
    }
}
