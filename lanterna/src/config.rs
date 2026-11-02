//! `LanternaConfig`: the ONE typed bounds surface, carrying both faces.
//!
//! shikumi's tiers (`bare` / `prescribed` / a YAML overlay) and the
//! tatara-lisp `(deflanterna …)` form are two faces of one struct, on the
//! holofote precedent. Every field is a **bound** the server enforces
//! against one ClickHouse host; nothing here identifies a host, a tenant,
//! or a credential. Those are argv, and they are per host.
//!
//! The YAML face carries `deny_unknown_fields`, so an operator's typo is a
//! loud failure. A **partial** overlay is legal and folds onto the
//! prescribed tier: `#[serde(default)]` routes every omitted key through
//! `Default`, which delegates to `prescribed_default()`.

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tatara_lisp::DeriveTataraDomain;

/// The canonical authored form that ships with the crate.
pub const CANONICAL_LANTERNA_LISP: &str = include_str!("../specs/lanterna.lisp");

/// The bounds lanterna enforces against one ClickHouse host.
#[derive(DeriveTataraDomain, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[tatara(keyword = "deflanterna")]
pub struct LanternaConfig {
    /// The hard cap on any question's `limit`. A request above it is
    /// refused, never clamped. The server-side `max_result_rows` is this
    /// plus one probe row.
    ///
    /// Lisp face: `:max-results 500`.
    pub max_results: u32,

    /// The longest time window any question may name, in seconds.
    ///
    /// Lisp face: `:max-window-seconds 604800`.
    pub max_window_seconds: u64,

    /// Sent as `max_execution_time`: the server-side wall-clock bound.
    ///
    /// Lisp face: `:max-execution-seconds 30`.
    pub max_execution_seconds: u64,

    /// Sent as `max_result_bytes`.
    ///
    /// Lisp face: `:max-result-bytes 10485760`.
    pub max_result_bytes: u64,

    /// TCP connect + TLS handshake budget, in milliseconds.
    ///
    /// Lisp face: `:connect-timeout-ms 5000`.
    pub connect_timeout_ms: u64,

    /// Whole-request budget for one call, in milliseconds.
    ///
    /// Lisp face: `:request-timeout-ms 45000`.
    pub request_timeout_ms: u64,

    /// How many filters one `select` may carry.
    ///
    /// Lisp face: `:max-filters 16`.
    pub max_filters: u32,

    /// How many columns one `select` may name.
    ///
    /// Lisp face: `:max-columns 32`.
    pub max_columns: u32,

    /// How many bytes one filter value may carry, so a value is never a
    /// payload.
    ///
    /// Lisp face: `:max-value-bytes 1024`.
    pub max_value_bytes: u32,

    /// The tables `select` may read: `database.table`, or `database.*` for
    /// every table of a database. Empty means `select` is refused for every
    /// table.
    ///
    /// Lisp face: `:select-allow ("system.*")`.
    pub select_allow: Vec<String>,
}

/// Why a config was refused.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The overlay file could not be read.
    #[error("config overlay {path} could not be read: {source}")]
    Unreadable {
        /// The path given.
        path: std::path::PathBuf,
        /// The OS's reason.
        #[source]
        source: std::io::Error,
    },
    /// The overlay file did not parse, including an unknown key.
    #[error("config overlay {path} is not a valid LanternaConfig: {source}")]
    Malformed {
        /// The path given.
        path: std::path::PathBuf,
        /// `serde_yaml`'s reason, which names the offending key.
        #[source]
        source: serde_yaml::Error,
    },
    /// A bound that would make every request illegal or every call hang.
    #[error("config field {field} must be at least 1 (got 0)")]
    ZeroBound {
        /// The camelCase field name.
        field: &'static str,
    },
    /// An allowlist entry outside `database.table` / `database.*`.
    #[error("config field selectAllow entry {entry:?} is not database.table or database.*")]
    BadAllowEntry {
        /// The entry as written.
        entry: String,
    },
}

impl LanternaConfig {
    /// Refuse bounds that would make the server useless, and an allowlist
    /// entry that names no table.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let checks: [(&'static str, u64); 8] = [
            ("maxResults", u64::from(self.max_results)),
            ("maxWindowSeconds", self.max_window_seconds),
            ("maxExecutionSeconds", self.max_execution_seconds),
            ("maxResultBytes", self.max_result_bytes),
            ("connectTimeoutMs", self.connect_timeout_ms),
            ("requestTimeoutMs", self.request_timeout_ms),
            ("maxFilters", u64::from(self.max_filters)),
            ("maxColumns", u64::from(self.max_columns)),
        ];
        if let Some((field, _)) = checks.iter().find(|(_, v)| *v == 0) {
            return Err(ConfigError::ZeroBound { field });
        }
        if self.max_value_bytes == 0 {
            return Err(ConfigError::ZeroBound {
                field: "maxValueBytes",
            });
        }
        for entry in &self.select_allow {
            if crate::sql::AllowEntry::parse(entry).is_none() {
                return Err(ConfigError::BadAllowEntry {
                    entry: entry.clone(),
                });
            }
        }
        Ok(())
    }

    /// Read a YAML overlay **strictly** and fold it onto the prescribed tier.
    ///
    /// Strict where `shikumi::TieredConfig::resolve_tier` is lenient: a
    /// bounds file that cannot be honoured stops the server instead of
    /// silently becoming the defaults.
    pub fn from_overlay_file(path: &Path) -> Result<Self, ConfigError> {
        use shikumi::TieredConfig as _;
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Unreadable {
            path: path.to_path_buf(),
            source,
        })?;
        let overlay: Self =
            serde_yaml::from_str(&text).map_err(|source| ConfigError::Malformed {
                path: path.to_path_buf(),
                source,
            })?;
        let folded = overlay.extend(&Self::prescribed_default());
        folded.validate()?;
        Ok(folded)
    }

    /// Compile a `(deflanterna …)` form, the Lisp authoring face.
    pub fn from_lisp(src: &str) -> Result<Self, tatara_lisp::LispError> {
        use tatara_lisp::domain::TataraDomain as _;
        let forms = tatara_lisp::read(src)?;
        let first = forms
            .first()
            .ok_or_else(|| tatara_lisp::LispError::Compile {
                form: "deflanterna".into(),
                message: "empty config: expected one top-level (deflanterna …) form".into(),
            })?;
        Self::compile_from_sexp(first)
    }

    /// The transport deadlines.
    #[must_use]
    pub const fn timeouts(&self) -> crate::transport::Timeouts {
        crate::transport::Timeouts {
            connect: Duration::from_millis(self.connect_timeout_ms),
            request: Duration::from_millis(self.request_timeout_ms),
        }
    }

    /// The bounds one question is validated against.
    #[must_use]
    pub fn bounds(&self) -> crate::sql::Bounds {
        crate::sql::Bounds {
            max_results: self.max_results,
            max_window_seconds: self.max_window_seconds,
            max_filters: self.max_filters,
            max_columns: self.max_columns,
            max_value_bytes: self.max_value_bytes,
            select_allow: self.select_allow.clone(),
        }
    }
}

impl shikumi::TieredConfig for LanternaConfig {
    /// Tier 0: the tightest bounds under which one question can still
    /// complete.
    fn bare() -> Self {
        Self {
            max_results: 1,
            max_window_seconds: 60,
            max_execution_seconds: 5,
            max_result_bytes: 65_536,
            connect_timeout_ms: 1_000,
            request_timeout_ms: 10_000,
            max_filters: 1,
            max_columns: 1,
            max_value_bytes: 64,
            select_allow: Vec::new(),
        }
    }

    /// Tier 2: what the server boots with. Mirrors `specs/lanterna.lisp`;
    /// `prescribed_mirrors_the_authored_lisp` pins the two together.
    fn prescribed_default() -> Self {
        Self {
            max_results: 500,
            max_window_seconds: 604_800,
            max_execution_seconds: 30,
            max_result_bytes: 10_485_760,
            connect_timeout_ms: 5_000,
            request_timeout_ms: 45_000,
            max_filters: 16,
            max_columns: 32,
            max_value_bytes: 1_024,
            select_allow: vec!["system.*".to_owned()],
        }
    }
}

impl Default for LanternaConfig {
    fn default() -> Self {
        <Self as shikumi::TieredConfig>::prescribed_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shikumi::TieredConfig as _;
    use std::io::Write as _;

    fn overlay(text: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(text.as_bytes()).expect("write");
        f
    }

    #[test]
    fn bare_is_below_prescribed_on_every_numeric_bound() {
        let bare = LanternaConfig::bare();
        let p = LanternaConfig::prescribed_default();
        assert!(bare.max_results < p.max_results);
        assert!(bare.max_window_seconds < p.max_window_seconds);
        assert!(bare.max_execution_seconds < p.max_execution_seconds);
        assert!(bare.max_result_bytes < p.max_result_bytes);
        assert!(bare.max_filters < p.max_filters);
        assert!(bare.max_columns < p.max_columns);
        assert!(bare.max_value_bytes < p.max_value_bytes);
        assert_eq!(bare.select_allow.len(), 0);
    }

    #[test]
    fn an_unknown_yaml_key_is_rejected_by_name() {
        let f = overlay("maxResultz: 3\n");
        let err = LanternaConfig::from_overlay_file(f.path()).expect_err("refused");
        assert!(matches!(err, ConfigError::Malformed { .. }));
        assert!(err.to_string().contains("maxResultz"), "{err}");
    }

    #[test]
    fn a_partial_overlay_folds_onto_prescribed() {
        let f = overlay("maxResults: 10\nselectAllow: [\"analytics.events\"]\n");
        let c = LanternaConfig::from_overlay_file(f.path()).expect("folds");
        assert_eq!(c.max_results, 10);
        assert_eq!(c.select_allow, ["analytics.events"]);
        assert_eq!(
            c.max_window_seconds,
            LanternaConfig::prescribed_default().max_window_seconds
        );
    }

    #[test]
    fn the_strict_loader_refuses_what_shikumi_would_paper_over() {
        let missing = Path::new("/definitely/not/here/lanterna.yaml");
        assert!(matches!(
            LanternaConfig::from_overlay_file(missing),
            Err(ConfigError::Unreadable { .. })
        ));
    }

    #[test]
    fn a_zero_bound_is_refused_by_field_name() {
        for (key, field) in [
            ("maxResults", "maxResults"),
            ("maxWindowSeconds", "maxWindowSeconds"),
            ("maxExecutionSeconds", "maxExecutionSeconds"),
            ("maxResultBytes", "maxResultBytes"),
            ("connectTimeoutMs", "connectTimeoutMs"),
            ("requestTimeoutMs", "requestTimeoutMs"),
            ("maxFilters", "maxFilters"),
            ("maxColumns", "maxColumns"),
            ("maxValueBytes", "maxValueBytes"),
        ] {
            let f = overlay(&format!("{key}: 0\n"));
            let err = LanternaConfig::from_overlay_file(f.path()).expect_err("refused");
            assert!(
                matches!(err, ConfigError::ZeroBound { field: got } if got == field),
                "{key}: {err}"
            );
        }
    }

    #[test]
    fn an_allow_entry_that_names_no_table_is_refused() {
        for bad in ["events", "a.b.c", ".x", "x.", "a b.c", "a.*b"] {
            let f = overlay(&format!("selectAllow: [\"{bad}\"]\n"));
            let err = LanternaConfig::from_overlay_file(f.path()).expect_err(bad);
            assert!(matches!(err, ConfigError::BadAllowEntry { .. }), "{bad}");
        }
    }

    #[test]
    fn yaml_round_trips_in_camel_case() {
        let c = LanternaConfig::prescribed_default();
        let text = serde_yaml::to_string(&c).expect("serializes");
        assert!(text.contains("maxResults") && text.contains("selectAllow"));
        let back: LanternaConfig = serde_yaml::from_str(&text).expect("parses");
        assert_eq!(back, c);
    }

    #[test]
    fn prescribed_mirrors_the_authored_lisp() {
        let from_lisp = LanternaConfig::from_lisp(CANONICAL_LANTERNA_LISP).expect("compiles");
        assert_eq!(from_lisp, LanternaConfig::prescribed_default());
        assert!(from_lisp.validate().is_ok());
    }

    #[test]
    fn the_lisp_face_refuses_an_empty_source() {
        assert!(LanternaConfig::from_lisp("").is_err());
    }

    #[test]
    fn derived_views_follow_the_fields() {
        let c = LanternaConfig::prescribed_default();
        assert_eq!(c.timeouts().connect, Duration::from_millis(5_000));
        assert_eq!(c.timeouts().request, Duration::from_secs(45));
        assert_eq!(c.bounds().max_results, 500);
        assert_eq!(c.bounds().select_allow, ["system.*"]);
    }
}
