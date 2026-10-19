// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// A minimal child contract whose creation and destruction stress the account
/// trie. Its init code takes no constructor arguments, so a CREATE2 address is
/// a pure function of the salt and can be reused after a destroy. It stores one
/// non-zero word so the created account is non-empty and persists (EIP-161).
contract Child {
    constructor() {
        assembly {
            sstore(0, 1)
        }
    }

    /// SELFDESTRUCT, sending any balance back to the caller (the Mutator).
    function die() external {
        selfdestruct(payable(msg.sender));
    }
}

/// One contract whose calldata selects a state mutation, so a single deployed
/// contract exercises every tx-level state-mutation path. Every effect is a
/// deterministic function of the arguments: no block number, timestamp or
/// balance is read, so a run replays identically.
contract Mutator {
    /// Applies mutation `op` with parameters `key` and `val`:
    ///
    /// - 0 SET          raw `sstore(key, val)` (set, update, clear-to-zero,
    ///                  max/edge values, bulk-write-then-clear ranges);
    /// - 1 CREATE       deploy a Child via CREATE, record it at slot `key`;
    /// - 2 CREATE2      deploy a Child via CREATE2 with salt `key` (a reused
    ///                  address after a destroy), record it at slot `key`;
    /// - 3 DESTROY      selfdestruct the child recorded at slot `key`, clear it;
    /// - 4 CREATE_DIE   create a Child and selfdestruct it in the same tx;
    /// - 5 EMPTY_TOUCH  call an empty account (EIP-161 create-then-prune);
    /// - 6 TRANSFER     forward `msg.value` to a derived address (plain
    ///                  value transfer touching the account trie).
    function exec(uint256 op, uint256 key, uint256 val) external payable {
        if (op == 0) {
            assembly {
                sstore(key, val)
            }
        } else if (op == 1) {
            Child c = new Child();
            assembly {
                sstore(key, c)
            }
        } else if (op == 2) {
            Child c = new Child{salt: bytes32(key)}();
            assembly {
                sstore(key, c)
            }
        } else if (op == 3) {
            address a;
            assembly {
                a := sload(key)
            }
            if (a != address(0)) {
                Child(a).die();
            }
            assembly {
                sstore(key, 0)
            }
        } else if (op == 4) {
            Child c = new Child();
            c.die();
        } else if (op == 5) {
            address a = address(uint160(key));
            assembly {
                pop(call(gas(), a, 0, 0, 0, 0, 0))
            }
        } else if (op == 6) {
            address a = address(uint160(key));
            assembly {
                pop(call(gas(), a, val, 0, 0, 0, 0))
            }
        }
    }
}
