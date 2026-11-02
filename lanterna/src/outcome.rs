//! The four things a call can conclude, as the library's own sum, and the
//! typed reasons behind the two that are not about the world.
//!
//! [`Outcome`] is the crate's vocabulary; it converts into `kotae::Answer`
//! at the border (`From`), so the MCP server never chooses a discriminant by
//! hand. [`Blindness`] and [`Refusal`] are the typed causes: every message an
//! agent will read is a `thiserror` `Display`, so the words are written once
//! and the typed-emission rule holds without a `format!`.

use serde::Serialize;

use crate::auth::{CredentialError, LEGAL_CREDENTIAL_FORMS};
use crate::sql::SqlError;
use crate::transport::TransportError;

/// The observe-only questions a refusal can name as legal.
pub const LEGAL_QUESTIONS: [&str; 12] = [
    "whoami",
    "databases",
    "tables",
    "columns",
    "table_sizes",
    "health",
    "processes",
    "slow_queries",
    "row_policies",
    "grants",
    "metrics",
    "select",
];

/// What a call concluded. Generic over the found payload so each client
/// method returns its own shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome<P> {
    /// Answered; here it is.
    Found(P),
    /// Answered; there is nothing. `of` names what was looked for.
    Empty {
        /// What was looked for.
        of: String,
    },
    /// The host answered and rejected the question, or the question failed
    /// validation before it was put. `legal` names what would be accepted.
    Refused {
        /// Why.
        because: String,
        /// What would have been accepted. Empty when not enumerable.
        legal: Vec<String>,
    },
    /// The question could not be put at all. Says nothing about the subject.
    Blind {
        /// What stopped it.
        because: String,
    },
}

impl<P> Outcome<P> {
    /// The discriminant, matching kotae's vocabulary.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Found(_) => "found",
            Self::Empty { .. } => "empty",
            Self::Refused { .. } => "refused",
            Self::Blind { .. } => "blind",
        }
    }

    /// `true` only for `Found` and `Empty`: the two that say something about
    /// the subject rather than about the attempt.
    #[must_use]
    pub const fn is_about_the_world(&self) -> bool {
        matches!(self, Self::Found(_) | Self::Empty { .. })
    }

    /// Map the found payload, leaving the other three arms untouched.
    pub fn map<Q>(self, f: impl FnOnce(P) -> Q) -> Outcome<Q> {
        match self {
            Self::Found(p) => Outcome::Found(f(p)),
            Self::Empty { of } => Outcome::Empty { of },
            Self::Refused { because, legal } => Outcome::Refused { because, legal },
            Self::Blind { because } => Outcome::Blind { because },
        }
    }
}

impl<P: Serialize> From<Outcome<P>> for kotae::Answer {
    fn from(o: Outcome<P>) -> Self {
        match o {
            Outcome::Found(p) => Self::found(&p),
            Outcome::Empty { of } => Self::empty(of),
            Outcome::Refused { because, legal } if legal.is_empty() => {
                Self::refused_flatly(because)
            }
            Outcome::Refused { because, legal } => Self::refused(because, legal),
            Outcome::Blind { because } => Self::blind(because),
        }
    }
}

/// Why the question could not be put. Each arm names its remedy.
#[derive(Debug, thiserror::Error)]
pub enum Blindness {
    /// The host could not be reached at all: refused, unroutable,
    /// unresolvable, or the connect timed out.
    #[error(
        "{source}. The usual cause is that the network path to this host is not up (a VPN not connected, a name that does not resolve, or an allowlist that excludes this client); fix the path and retry"
    )]
    Unreachable {
        /// The transport's own account.
        #[source]
        source: TransportError,
    },
    /// The host WAS reached and then outran the request timeout.
    #[error(
        "{source}. The host is reachable; this call outran requestTimeoutMs: retry, ask a narrower question, or raise requestTimeoutMs"
    )]
    RequestTimeout {
        /// The transport's own account.
        #[source]
        source: TransportError,
    },
    /// The TLS handshake failed under the configured posture.
    #[error(
        "{source} under `--tls {posture}`. Use `--tls ca:<PEM>` with the private root, or `--tls accept-any` (degraded)"
    )]
    Tls {
        /// The transport's own account.
        #[source]
        source: TransportError,
        /// The posture in force.
        posture: String,
    },
    /// Some other transport failure.
    #[error(transparent)]
    Transport(TransportError),
    /// The host answered with a status that says "not now" or "I broke".
    #[error("{host} answered HTTP {status} ({verdict}); {advice}")]
    Upstream {
        /// The host as configured.
        host: String,
        /// The status.
        status: u16,
        /// handan's reading of it.
        verdict: handan::Verdict,
        /// Retry advice, rendered.
        advice: String,
    },
    /// The server stopped the statement at `max_execution_time`.
    #[error(
        "{host} stopped the question at its {seconds}s execution limit; the answer is unknown, not empty. Narrow the window or lower the limit, or raise maxExecutionSeconds"
    )]
    QueryTimeout {
        /// The host as configured.
        host: String,
        /// The bound that was sent.
        seconds: u64,
    },
    /// A `404` with no ClickHouse exception: the URL does not reach the
    /// HTTP interface.
    #[error(
        "{host} answered HTTP 404 with no ClickHouse exception; the URL may not point at the HTTP interface (8443 with TLS on Cloud, 8123 without), or a proxy in front of it drops the path"
    )]
    NotClickHouseHttp {
        /// The host as configured.
        host: String,
    },
    /// No credential, or its file could not be read.
    #[error(transparent)]
    Credential(#[from] CredentialError),
    /// The body did not have the shape ClickHouse documents.
    #[error("{host} answered with a body lanterna could not read: {detail}")]
    Unreadable {
        /// The host as configured.
        host: String,
        /// serde's reason.
        detail: String,
    },
}

/// The kind of thing a server said does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    /// A table.
    Table,
    /// A database.
    Database,
    /// A column.
    Column,
}

impl std::fmt::Display for Missing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Table => "table",
            Self::Database => "database",
            Self::Column => "column",
        })
    }
}

/// Why the question was refused. Each arm knows its legal set.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    /// The host rejected the credential (HTTP 401, or an authentication
    /// exception).
    #[error(
        "{host} rejected the credential (HTTP {status}); retrying cannot help: the user or password is not valid for this host"
    )]
    Unauthorized {
        /// The host as configured.
        host: String,
        /// The status.
        status: u16,
    },
    /// The credential is valid and the user lacks the privilege (HTTP 403,
    /// or an access-denied exception).
    #[error("{host} denied the user access (HTTP {status}): {message}")]
    AccessDenied {
        /// The host as configured.
        host: String,
        /// The status.
        status: u16,
        /// The server's first line.
        message: String,
    },
    /// The server refused because the request is `readonly`.
    #[error(
        "{host} refused in readonly mode: {message}. lanterna is observe-only and sends every request with readonly=1"
    )]
    Readonly {
        /// The host as configured.
        host: String,
        /// The server's first line.
        message: String,
    },
    /// The statement named something the server does not have.
    #[error("{host} has no such {what}: {message}")]
    Unknown {
        /// The host as configured.
        host: String,
        /// Which kind of thing.
        what: Missing,
        /// The server's first line.
        message: String,
    },
    /// The server rejected the statement for another reason.
    #[error("{host} rejected the question (HTTP {status}): {message}")]
    Rejected {
        /// The host as configured.
        host: String,
        /// The status.
        status: u16,
        /// The server's first line.
        message: String,
    },
    /// The request failed validation before it was sent.
    #[error(transparent)]
    Invalid(#[from] SqlError),
    /// A `target` that names no configured host.
    #[error("no target named {got:?}; this server serves: {}", known.join(", "))]
    UnknownTarget {
        /// What was asked for.
        got: String,
        /// Every configured label.
        known: Vec<String>,
    },
    /// No `target` named while several are served.
    #[error("this server serves several targets and the call named none; pass `target`, one of: {}", known.join(", "))]
    TargetRequired {
        /// Every configured label.
        known: Vec<String>,
    },
}

impl Refusal {
    /// What would have been accepted.
    #[must_use]
    pub fn legal(&self) -> Vec<String> {
        match self {
            Self::Unauthorized { .. } => LEGAL_CREDENTIAL_FORMS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            Self::AccessDenied { .. } => vec![
                "a user with SELECT on the table, or on the system table the question reads"
                    .to_owned(),
                "the clickhouse_grants question lists what this user may do".to_owned(),
            ],
            Self::Readonly { .. } => LEGAL_QUESTIONS.iter().map(|s| (*s).to_owned()).collect(),
            Self::Unknown { what, .. } => match what {
                Missing::Database => vec!["list databases with the databases question".to_owned()],
                Missing::Table => vec![
                    "list databases with the databases question".to_owned(),
                    "list tables with the tables question".to_owned(),
                ],
                Missing::Column => vec!["list columns with the columns question".to_owned()],
            },
            Self::Rejected { .. } => vec![crate::sql::IDENT_GRAMMAR.to_owned()],
            Self::Invalid(e) => e.legal(),
            Self::UnknownTarget { known, .. } | Self::TargetRequired { known } => known.clone(),
        }
    }
}

/// The two ways a call ends without an answer about the world.
#[derive(Debug, thiserror::Error)]
pub enum Failure {
    /// See [`Blindness`].
    #[error(transparent)]
    Blind(#[from] Blindness),
    /// See [`Refusal`].
    #[error(transparent)]
    Refused(#[from] Refusal),
}

impl From<CredentialError> for Failure {
    fn from(e: CredentialError) -> Self {
        Self::Blind(Blindness::Credential(e))
    }
}

impl From<SqlError> for Failure {
    fn from(e: SqlError) -> Self {
        Self::Refused(Refusal::Invalid(e))
    }
}

impl<P> From<Failure> for Outcome<P> {
    fn from(f: Failure) -> Self {
        match f {
            Failure::Blind(b) => Self::Blind {
                because: b.to_string(),
            },
            Failure::Refused(r) => Self::Refused {
                because: r.to_string(),
                legal: r.legal(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn render<P: Serialize>(o: Outcome<P>) -> Value {
        let answer: kotae::Answer = o.into();
        serde_json::from_str(&answer.render()).expect("valid JSON")
    }

    #[test]
    fn the_four_outcomes_render_four_distinct_discriminants() {
        let outcomes: [Outcome<Value>; 4] = [
            Outcome::Found(json!({"rows": []})),
            Outcome::Empty { of: "rows".into() },
            Outcome::Refused {
                because: "bad".into(),
                legal: vec!["good".into()],
            },
            Outcome::Blind {
                because: "down".into(),
            },
        ];
        let mut seen = std::collections::HashSet::new();
        for o in outcomes {
            let kind = o.kind();
            let about_world = o.is_about_the_world();
            let v = render(o);
            assert_eq!(v["outcome"], kind);
            assert!(seen.insert(kind), "{kind} rendered twice");
            assert_eq!(about_world, matches!(kind, "found" | "empty"));
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn an_empty_legal_set_becomes_the_flat_refusal() {
        let v = render(Outcome::<()>::Refused {
            because: "x".into(),
            legal: vec![],
        });
        assert_eq!(v["outcome"], "refused");
        assert!(v["legal"].is_null());
        let w = render(Outcome::<()>::Refused {
            because: "x".into(),
            legal: vec!["a".into()],
        });
        assert_eq!(w["legal"], json!(["a"]));
    }

    #[test]
    fn failures_convert_to_the_matching_arm_with_their_legal_set() {
        let unauthorized: Outcome<()> = Failure::from(Refusal::Unauthorized {
            host: HOST.into(),
            status: 401,
        })
        .into();
        match &unauthorized {
            Outcome::Refused { because, legal } => {
                assert!(
                    because.contains("401") && because.contains("retrying cannot help"),
                    "{because}"
                );
                assert_eq!(legal.len(), LEGAL_CREDENTIAL_FORMS.len());
            }
            other => panic!("expected refused, got {}", other.kind()),
        }

        let readonly: Outcome<()> = Failure::from(Refusal::Readonly {
            host: HOST.into(),
            message: "Code: 164".into(),
        })
        .into();
        match &readonly {
            Outcome::Refused { legal, .. } => assert_eq!(legal.len(), LEGAL_QUESTIONS.len()),
            other => panic!("expected refused, got {}", other.kind()),
        }

        let blind: Outcome<()> = Failure::from(Blindness::Unreachable {
            source: TransportError::Connect {
                host: HOST.into(),
                detail: "connection refused".into(),
                evidence: crate::transport::ConnectEvidence::Unprobed,
            },
        })
        .into();
        match &blind {
            Outcome::Blind { because } => assert!(because.contains("network path"), "{because}"),
            other => panic!("expected blind, got {}", other.kind()),
        }

        let invalid: Outcome<()> =
            Failure::from(SqlError::IllegalTable { got: "a b".into() }).into();
        match &invalid {
            Outcome::Refused { legal, .. } => {
                assert_eq!(legal, &vec![crate::sql::IDENT_GRAMMAR.to_owned()]);
            }
            other => panic!("expected refused, got {}", other.kind()),
        }
    }

    const HOST: &str = "https://clickhouse-a.example.com:8443";

    #[test]
    fn map_touches_only_the_found_arm() {
        assert_eq!(Outcome::Found(2).map(|n| n * 2), Outcome::Found(4));
        assert_eq!(
            Outcome::<i32>::Empty { of: "x".into() }.map(|n| n * 2),
            Outcome::Empty { of: "x".into() }
        );
    }
}
