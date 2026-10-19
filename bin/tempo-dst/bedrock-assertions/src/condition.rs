// SPDX-License-Identifier: GPL-2.0

//! The [`Condition`] type: the thing an [`Assertion`](crate::Assertion) checks.

use serde::{Deserialize, Serialize};

/// A condition evaluated by an assertion. Comparisons keep their operands so a
/// record is self-describing; `i128` holds the full `u64` and `i64` ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Condition {
    Bool(bool),
    /// `x < y`.
    Lt {
        x: i128,
        y: i128,
    },
    /// `x > y`.
    Gt {
        x: i128,
        y: i128,
    },
    /// `x <= y`.
    Lte {
        x: i128,
        y: i128,
    },
    /// `x >= y`.
    Gte {
        x: i128,
        y: i128,
    },
    /// `x == y`.
    Eq {
        x: i128,
        y: i128,
    },
}

impl Condition {
    pub fn evaluate(&self) -> bool {
        match self {
            Condition::Bool(b) => *b,
            Condition::Lt { x, y } => x < y,
            Condition::Gt { x, y } => x > y,
            Condition::Lte { x, y } => x <= y,
            Condition::Gte { x, y } => x >= y,
            Condition::Eq { x, y } => x == y,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bool_evaluates_to_itself() {
        assert!(Condition::Bool(true).evaluate());
        assert!(!Condition::Bool(false).evaluate());
    }

    #[test]
    fn lt_compares_operands() {
        assert!(Condition::Lt { x: 1, y: 2 }.evaluate());
        assert!(!Condition::Lt { x: 2, y: 2 }.evaluate());
        assert!(!Condition::Lt { x: 3, y: 2 }.evaluate());
    }

    #[test]
    fn gt_compares_operands() {
        assert!(Condition::Gt { x: 3, y: 2 }.evaluate());
        assert!(!Condition::Gt { x: 2, y: 2 }.evaluate());
        assert!(!Condition::Gt { x: 1, y: 2 }.evaluate());
    }

    #[test]
    fn lte_compares_operands() {
        assert!(Condition::Lte { x: 1, y: 2 }.evaluate());
        assert!(Condition::Lte { x: 2, y: 2 }.evaluate());
        assert!(!Condition::Lte { x: 3, y: 2 }.evaluate());
    }

    #[test]
    fn gte_compares_operands() {
        assert!(Condition::Gte { x: 3, y: 2 }.evaluate());
        assert!(Condition::Gte { x: 2, y: 2 }.evaluate());
        assert!(!Condition::Gte { x: 1, y: 2 }.evaluate());
    }

    #[test]
    fn eq_compares_operands() {
        assert!(Condition::Eq { x: 2, y: 2 }.evaluate());
        assert!(!Condition::Eq { x: 1, y: 2 }.evaluate());
        assert!(!Condition::Eq { x: 3, y: 2 }.evaluate());
    }

    #[test]
    fn full_u64_range_is_representable() {
        // u64::MAX must widen into i128 without loss.
        let max = i128::from(u64::MAX);
        assert!(!Condition::Lt { x: max, y: max }.evaluate());
        assert!(Condition::Lt { x: max - 1, y: max }.evaluate());
        assert!(Condition::Gt { x: max, y: max - 1 }.evaluate());
        assert!(Condition::Eq { x: max, y: max }.evaluate());
    }

    #[test]
    fn operands_survive_serde_round_trip() {
        let c = Condition::Lt { x: -5, y: 7 };
        let json = serde_json::to_string(&c).unwrap();
        let back: Condition = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}
