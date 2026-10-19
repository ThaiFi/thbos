// SPDX-License-Identifier: GPL-2.0

//! Assertion primitives for bedrock.
//!
//! An [`Assertion`] checks a [`Condition`] about guest execution; each
//! serde-serializable record carries its operands, result, message and
//! [`Location`]. Build them with the `always_*` / `sometimes_*` macros.
//! Userspace only (not used in the kernel module).

#[macro_use]
mod macros;
mod assertion;
mod condition;
pub mod files;

pub use assertion::{Assertion, AssertionData, Location};
pub use condition::Condition;
