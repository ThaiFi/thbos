// SPDX-License-Identifier: GPL-2.0

//! Shared oracle results and node-log classification vocabulary.

/// Signatures for log lines that indicate a bug on their own. Message strings
/// are taken from reth at Tempo's pinned rev (42fa3c5); see the README table.
pub(crate) const LOG_PATTERNS: &[(&str, &str)] = &[
    ("E1/panic", "panicked at"),
    ("E1/state-root-mismatch", "mismatched block state root"),
    ("E1/receipt-root-mismatch", "receipt root mismatch"),
    ("E1/gas-used-mismatch", "block gas used mismatch"),
    ("E1/tx-root-mismatch", "mismatched block transaction root"),
    ("E1/bloom-mismatch", "header bloom filter mismatch"),
    ("E1/trie-diff-account", "Difference in account trie updates"),
    ("E1/trie-diff-storage", "Difference in storage trie updates"),
    (
        "E1/trie-diff-removed-account",
        "Difference in removed account trie nodes",
    ),
    (
        "E1/trie-diff-removed-storage",
        "Difference in removed storage trie nodes",
    ),
    ("E1/engine-fatal", "Fatal error in consensus engine"),
    ("E1/insert-fatal", "insert block fatal error"),
    ("E1/connect-fatal", "fatal error occurred while"),
    ("E1/persistence-failed", "Persistence service failed"),
    (
        "E1/persistence-advance-failed",
        "Advancing persistence failed",
    ),
    ("E1/persistence-poll-failed", "Polling persistence failed"),
    (
        "E1/persistence-complete-failed",
        "Persistence complete handling failed",
    ),
    (
        "E1/insert-executed-failed",
        "Failed to insert already executed block",
    ),
    ("E1/tree-state-missing", "block not found in TreeState"),
    ("E1/bad-block", "Bad block"),
    ("E1/invalid-payload", "Invalid payload"),
    ("E1/unwind-failed", "failed to run unwind"),
];

/// An oracle signature and the evidence describing its outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub signature: String,
    pub detail: String,
}

/// Strips ANSI escape sequences reth may emit.
pub(crate) fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Outputs of one oracle step, written as assertions by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// An Always assertion with the given outcome.
    Always(bool, Finding),
    /// A Sometimes assertion (coverage signal) with the given outcome.
    Sometimes(bool, Finding),
}

pub(crate) fn finding(signature: &str, detail: String) -> Finding {
    Finding {
        signature: signature.into(),
        detail,
    }
}
