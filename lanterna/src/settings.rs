//! The bounds that ride on every request.
//!
//! [`Settings`] is the ONE place the per-request ClickHouse settings are
//! chosen and rendered. Every request the transport sends carries all of
//! them as URL parameters, because the client builds the request from
//! [`Settings::query_pairs`] and has no other constructor:
//!
//! * `readonly=1` — the server itself refuses any statement that is not a
//!   read, and refuses any change to a setting. Observe-only is therefore
//!   enforced twice: lanterna has no mutating statement, and the server
//!   would reject one.
//! * `max_execution_time` — wall-clock seconds on the server.
//! * `max_result_rows` / `max_result_bytes` with
//!   `result_overflow_mode=break` — the server stops the result instead of
//!   failing the query.
//! * `wait_end_of_query=1` — buffer the result so a mid-stream failure is a
//!   real HTTP status rather than text appended to a 200.
//! * `default_format=JSONCompact` — the one response shape the client reads.

use crate::config::LanternaConfig;

/// The settings one request carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// `max_execution_time`, in seconds.
    pub max_execution_seconds: u64,
    /// `max_result_rows`: the result cap plus the one probe row.
    pub max_result_rows: u64,
    /// `max_result_bytes`.
    pub max_result_bytes: u64,
}

impl Settings {
    /// The settings a deployment's bounds imply. The row bound is the cap
    /// plus one, so the probe row a question asks for is never cut off.
    #[must_use]
    pub fn of(config: &LanternaConfig) -> Self {
        Self {
            max_execution_seconds: config.max_execution_seconds,
            max_result_rows: u64::from(config.max_results) + 1,
            max_result_bytes: config.max_result_bytes,
        }
    }

    /// The URL parameters, in one fixed order.
    #[must_use]
    pub fn query_pairs(&self) -> Vec<(String, String)> {
        vec![
            pair("readonly", 1),
            pair("max_execution_time", self.max_execution_seconds),
            pair("max_result_rows", self.max_result_rows),
            pair("max_result_bytes", self.max_result_bytes),
            ("result_overflow_mode".to_owned(), "break".to_owned()),
            pair("wait_end_of_query", 1),
            ("default_format".to_owned(), "JSONCompact".to_owned()),
        ]
    }
}

fn pair(key: &str, value: u64) -> (String, String) {
    (key.to_owned(), value.to_string())
}

/// The setting names every request must carry, for tests and docs.
pub const REQUIRED_SETTINGS: [&str; 6] = [
    "readonly",
    "max_execution_time",
    "max_result_rows",
    "max_result_bytes",
    "result_overflow_mode",
    "wait_end_of_query",
];

#[cfg(test)]
mod tests {
    use super::*;
    use shikumi::TieredConfig as _;

    #[test]
    fn every_required_setting_is_rendered_and_readonly_is_one() {
        let pairs = Settings::of(&LanternaConfig::prescribed_default()).query_pairs();
        for name in REQUIRED_SETTINGS {
            assert!(pairs.iter().any(|(k, _)| k == name), "{name} missing");
        }
        assert!(pairs.contains(&("readonly".to_owned(), "1".to_owned())));
        assert!(pairs.contains(&("result_overflow_mode".to_owned(), "break".to_owned())));
    }

    #[test]
    fn the_row_bound_leaves_room_for_the_probe_row() {
        let config = LanternaConfig::prescribed_default();
        assert_eq!(
            Settings::of(&config).max_result_rows,
            u64::from(config.max_results) + 1
        );
    }
}
