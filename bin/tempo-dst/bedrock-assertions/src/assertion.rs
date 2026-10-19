// SPDX-License-Identifier: GPL-2.0

//! The [`Assertion`] type, its [`AssertionData`] payload, and source
//! [`Location`].

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::Condition;

/// Call-site location of an assertion macro.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub file: String,
    /// 1-based.
    pub line: u32,
    /// 1-based.
    pub column: u32,
}

impl Location {
    pub fn new(file: impl Into<String>, line: u32, column: u32) -> Self {
        Location {
            file: file.into(),
            line,
            column,
        }
    }
}

/// The payload common to both [`Assertion`] variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertionData {
    pub condition: Condition,
    /// Evaluated once at construction.
    pub result: bool,
    /// Describes the asserted property.
    pub message: String,
    pub location: Location,
    /// Wall-clock time at construction, in nanoseconds since the Unix epoch.
    #[serde(default)]
    pub timestamp_unix_nano: u64,
}

impl AssertionData {
    fn new(condition: Condition, message: impl Into<String>, location: Location) -> Self {
        AssertionData {
            result: condition.evaluate(),
            condition,
            message: message.into(),
            location,
            timestamp_unix_nano: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
        }
    }
}

/// A property checked about guest execution. The variant says how a collector
/// aggregates many records; each record only carries its own
/// [`result`](AssertionData::result).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Assertion {
    /// The condition must hold every time the assertion is evaluated.
    Always(AssertionData),
    /// The condition must hold at least once across all evaluations.
    Sometimes(AssertionData),
}

impl Assertion {
    pub fn always(condition: Condition, message: impl Into<String>, location: Location) -> Self {
        Assertion::Always(AssertionData::new(condition, message, location))
    }

    pub fn sometimes(condition: Condition, message: impl Into<String>, location: Location) -> Self {
        Assertion::Sometimes(AssertionData::new(condition, message, location))
    }

    pub fn data(&self) -> &AssertionData {
        match self {
            Assertion::Always(data) | Assertion::Sometimes(data) => data,
        }
    }

    pub fn condition(&self) -> Condition {
        self.data().condition
    }

    /// The stored [`result`](AssertionData::result).
    pub fn holds(&self) -> bool {
        self.data().result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc() -> Location {
        Location::new("test.rs", 1, 1)
    }

    #[test]
    fn always_holds_when_condition_true() {
        assert!(Assertion::always(Condition::Bool(true), "m", loc()).holds());
        assert!(Assertion::always(Condition::Lt { x: 1, y: 2 }, "m", loc()).holds());
    }

    #[test]
    fn always_violated_when_condition_false() {
        assert!(!Assertion::always(Condition::Bool(false), "m", loc()).holds());
        assert!(!Assertion::always(Condition::Gt { x: 1, y: 2 }, "m", loc()).holds());
    }

    #[test]
    fn records_result_message_and_location() {
        let a = Assertion::always(
            Condition::Gt { x: 5, y: 2 },
            "five beats two",
            Location::new("f.rs", 10, 4),
        );
        let d = a.data();
        assert!(d.result);
        assert_eq!(d.message, "five beats two");
        assert_eq!(d.condition, Condition::Gt { x: 5, y: 2 });
        assert_eq!(d.location, Location::new("f.rs", 10, 4));
    }

    #[test]
    fn result_reflects_false_condition() {
        assert!(
            !Assertion::always(Condition::Lt { x: 9, y: 2 }, "m", loc())
                .data()
                .result
        );
    }

    #[test]
    fn sometimes_holds_evaluates_condition() {
        assert!(Assertion::sometimes(Condition::Bool(true), "m", loc()).holds());
        assert!(!Assertion::sometimes(Condition::Bool(false), "m", loc()).holds());
    }

    #[test]
    fn round_trips_through_serde() {
        let a = Assertion::always(
            Condition::Gt { x: 9, y: 2 },
            "nine gt two",
            Location::new("m.rs", 3, 7),
        );
        let json = serde_json::to_string(&a).unwrap();
        let back: Assertion = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }
}
