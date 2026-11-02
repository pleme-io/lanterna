//! `ClickHouseClient<T: Transport>`: one host, one credential, and a single
//! way to ask a question.
//!
//! The client owns the three decisions the border cares about. It validates
//! a [`QuestionRequest`] into a [`Question`] before anything is sent. It
//! builds every request from [`Settings`], so `readonly=1` and the result
//! bounds ride on all of them. And it turns every response, and every
//! failure to get one, into exactly one of kotae's four outcomes, judging
//! each HTTP status with [`handan::judge`] and each ClickHouse exception by
//! its numeric code.

use std::fmt;

use handan::{RetryAdvice, Verdict};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::{AuthHeaders, Credential, CredentialError};
use crate::config::LanternaConfig;
use crate::exception::{Exception, Known};
use crate::outcome::{Blindness, Failure, Missing, Outcome, Refusal};
use crate::route::Route;
use crate::settings::Settings;
use crate::sql::{Question, QuestionRequest};
use crate::tls::TlsPosture;
use crate::transport::{HttpRequest, HttpResponse, Transport, TransportError};

/// Who this client is, for answers and logs. Never carries userinfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The label every answer carries, a tenant name and never a hostname.
    pub label: String,
    /// The host as `scheme://host[:port]`.
    pub host: String,
    /// The posture in force.
    pub tls_posture: TlsPosture,
}

/// One result column.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Column {
    /// The column name.
    pub name: String,
    /// The ClickHouse type.
    #[serde(rename = "type")]
    pub kind: String,
}

/// The rows of one answer.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Rows {
    /// The target label.
    pub target: String,
    /// The columns, in order.
    pub columns: Vec<Column>,
    /// The rows, each in column order.
    pub rows: Vec<Vec<Value>>,
    /// How many rows came back (after the probe row is dropped).
    pub returned: usize,
    /// More rows matched than `limit`: the probe row came back. A fact the
    /// wire carries, never a guess.
    pub truncated: bool,
    /// The row cap the question was asked with; absent for the identity
    /// question.
    pub limit: Option<u32>,
}

/// The bounds in force, echoed so an agent can see what it was held to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BoundsInForce {
    /// Every request carries `readonly=1`.
    pub readonly: bool,
    /// The row cap.
    pub max_results: u32,
    /// The longest window, in seconds.
    pub max_window_seconds: u64,
    /// The server-side execution bound, in seconds.
    pub max_execution_seconds: u64,
    /// The server-side result-size bound, in bytes.
    pub max_result_bytes: u64,
}

/// The answer to the identity question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WhoAmI {
    /// The target label.
    pub target: String,
    /// The host as configured.
    pub host: String,
    /// The TLS posture in force.
    pub tls_posture: String,
    /// The user the credential authenticates as.
    pub user: String,
    /// The server version.
    pub version: String,
    /// Seconds since the server started.
    pub uptime_seconds: u64,
    /// The bounds this client holds every request to.
    pub bounds: BoundsInForce,
}

#[derive(Deserialize)]
struct Body {
    meta: Vec<Column>,
    data: Vec<Vec<Value>>,
}

struct Advice(Option<RetryAdvice>);

impl fmt::Display for Advice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(RetryAdvice::After(d)) => write!(f, "retry after {}s", d.as_secs()),
            Some(RetryAdvice::At { unix_secs }) => write!(f, "retry at unix time {unix_secs}"),
            Some(other) => write!(f, "retry after {}s", other.delay_now().as_secs()),
            None => f.write_str("no retry advice was given; the same request may succeed later"),
        }
    }
}

/// An observe-only client for one ClickHouse host.
pub struct ClickHouseClient<T: Transport> {
    transport: T,
    credential: Credential,
    config: LanternaConfig,
    identity: Identity,
}

impl<T: Transport> ClickHouseClient<T> {
    /// Build a client. `config` should already have passed
    /// [`LanternaConfig::validate`].
    #[must_use]
    pub const fn new(
        transport: T,
        credential: Credential,
        config: LanternaConfig,
        identity: Identity,
    ) -> Self {
        Self {
            transport,
            credential,
            config,
            identity,
        }
    }

    /// Who this client is.
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The bounds this client enforces.
    #[must_use]
    pub const fn config(&self) -> &LanternaConfig {
        &self.config
    }

    /// Ask one question. Validation failures are `refused` and nothing is
    /// sent; every other path ends in `found`, `empty`, `refused` or `blind`.
    pub async fn ask(&self, request: &QuestionRequest) -> Outcome<Rows> {
        let question = match Question::build(request, &self.config.bounds()) {
            Ok(q) => q,
            Err(e) => return Failure::from(e).into(),
        };
        match self.execute(&question).await {
            Ok(rows) if rows.rows.is_empty() => Outcome::Empty {
                of: question.subject().to_owned(),
            },
            Ok(rows) => Outcome::Found(rows),
            Err(Failure::Refused(Refusal::Unknown {
                what: Missing::Table | Missing::Database,
                ..
            })) if question.source_may_be_absent() => Outcome::Empty {
                of: question.subject().to_owned(),
            },
            Err(f) => f.into(),
        }
    }

    /// The identity question, with the bounds in force.
    pub async fn whoami(&self) -> Outcome<WhoAmI> {
        let rows = match self.execute(&Question::WhoAmI).await {
            Ok(rows) => rows,
            Err(f) => return f.into(),
        };
        match self.identity_of(&rows) {
            Some(who) => Outcome::Found(who),
            None => Failure::from(Blindness::Unreadable {
                host: self.identity.host.clone(),
                detail: "the identity row lacked user, version or uptime_seconds".to_owned(),
            })
            .into(),
        }
    }

    fn identity_of(&self, rows: &Rows) -> Option<WhoAmI> {
        let row = rows.rows.first()?;
        let cell = |name: &str| {
            let at = rows.columns.iter().position(|c| c.name == name)?;
            row.get(at)
        };
        let uptime = match cell("uptime_seconds")? {
            Value::Number(n) => n.as_u64()?,
            Value::String(s) => s.parse().ok()?,
            _ => return None,
        };
        let c = &self.config;
        Some(WhoAmI {
            target: self.identity.label.clone(),
            host: self.identity.host.clone(),
            tls_posture: self.identity.tls_posture.to_string(),
            user: cell("user")?.as_str()?.to_owned(),
            version: cell("version")?.as_str()?.to_owned(),
            uptime_seconds: uptime,
            bounds: BoundsInForce {
                readonly: true,
                max_results: c.max_results,
                max_window_seconds: c.max_window_seconds,
                max_execution_seconds: c.max_execution_seconds,
                max_result_bytes: c.max_result_bytes,
            },
        })
    }

    fn authorization(&self) -> Result<AuthHeaders, CredentialError> {
        match &self.credential {
            Credential::None => Err(CredentialError::Absent),
            Credential::Password {
                user_file,
                password_file,
            } => AuthHeaders::read(user_file, password_file),
        }
    }

    async fn execute(&self, question: &Question) -> Result<Rows, Failure> {
        let credentials = self.authorization()?;
        let request = HttpRequest::new(Route::Query)
            .queries(Settings::of(&self.config).query_pairs())
            .statement(question.to_string())
            .authorized(credentials);
        let resp = self
            .transport
            .send(request)
            .await
            .map_err(|e| self.blind(e))?;
        let judgment = handan::judge(resp.status, resp.retry_after.as_deref());
        if judgment.verdict() != Verdict::Success {
            return Err(self.failure_for(&resp, judgment));
        }
        let body: Body = serde_json::from_slice(&resp.body).map_err(|e| {
            Failure::from(Blindness::Unreadable {
                host: self.identity.host.clone(),
                detail: e.to_string(),
            })
        })?;
        let mut rows = body.data;
        let limit = question.limit().map(|l| l.get());
        let cap = limit.map(|l| usize::try_from(l).unwrap_or(usize::MAX));
        let truncated = cap.is_some_and(|c| rows.len() > c);
        if let Some(c) = cap {
            rows.truncate(c);
        }
        Ok(Rows {
            target: self.identity.label.clone(),
            columns: body.meta,
            returned: rows.len(),
            rows,
            truncated,
            limit,
        })
    }

    fn blind(&self, e: TransportError) -> Failure {
        match e {
            TransportError::Connect { .. } => Blindness::Unreachable { source: e }.into(),
            TransportError::Timeout { .. } => Blindness::RequestTimeout { source: e }.into(),
            TransportError::Tls { .. } => Blindness::Tls {
                source: e,
                posture: self.identity.tls_posture.to_string(),
            }
            .into(),
            other => Blindness::Transport(other).into(),
        }
    }

    fn failure_for(&self, resp: &HttpResponse, judgment: handan::Judgment) -> Failure {
        let host = self.identity.host.clone();
        let status = resp.status;
        let ex = Exception::of(resp);
        let message = ex.message.clone();
        match ex.known {
            Known::AuthenticationFailed => return Refusal::Unauthorized { host, status }.into(),
            Known::AccessDenied => {
                return Refusal::AccessDenied {
                    host,
                    status,
                    message,
                }
                .into();
            }
            Known::Readonly => return Refusal::Readonly { host, message }.into(),
            Known::UnknownTable => {
                return Refusal::Unknown {
                    host,
                    what: Missing::Table,
                    message,
                }
                .into();
            }
            Known::UnknownDatabase => {
                return Refusal::Unknown {
                    host,
                    what: Missing::Database,
                    message,
                }
                .into();
            }
            Known::UnknownColumn => {
                return Refusal::Unknown {
                    host,
                    what: Missing::Column,
                    message,
                }
                .into();
            }
            Known::TimeoutExceeded => {
                return Blindness::QueryTimeout {
                    host,
                    seconds: self.config.max_execution_seconds,
                }
                .into();
            }
            Known::Other => {}
        }
        match judgment.verdict() {
            Verdict::Unauthorized if status == 403 => Refusal::AccessDenied {
                host,
                status,
                message,
            }
            .into(),
            Verdict::Unauthorized => Refusal::Unauthorized { host, status }.into(),
            Verdict::Absent => Blindness::NotClickHouseHttp { host }.into(),
            Verdict::Throttled | Verdict::ServerError => Blindness::Upstream {
                host,
                status,
                verdict: judgment.verdict(),
                advice: Advice(judgment.advice()).to_string(),
            }
            .into(),
            _ if (400..500).contains(&status) => Refusal::Rejected {
                host,
                status,
                message,
            }
            .into(),
            verdict => Blindness::Upstream {
                host,
                status,
                verdict,
                advice: Advice(judgment.advice()).to_string(),
            }
            .into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::REQUIRED_SETTINGS;
    use crate::transport::{ConnectEvidence, MockTransport, Scripted};
    use serde_json::json;
    use shikumi::TieredConfig as _;
    use std::io::Write as _;
    use std::path::PathBuf;

    const HOST: &str = "https://clickhouse-a.example.com:8443";
    const SENTINEL: &str = "sentinel-value-not-a-real-one";

    struct Files {
        user: tempfile::NamedTempFile,
        keyfile: tempfile::NamedTempFile,
    }

    impl Files {
        fn new() -> Self {
            let write = |text: &str| {
                let mut f = tempfile::NamedTempFile::new().expect("tempfile");
                f.write_all(text.as_bytes()).expect("write");
                f
            };
            Self {
                user: write("observer\n"),
                keyfile: write(&(SENTINEL.to_owned() + "\n")),
            }
        }

        fn credential(&self) -> Credential {
            Credential::Password {
                user_file: self.user.path().to_path_buf(),
                password_file: self.keyfile.path().to_path_buf(),
            }
        }
    }

    fn shared_credential() -> Credential {
        static SHARED: std::sync::OnceLock<Files> = std::sync::OnceLock::new();
        SHARED.get_or_init(Files::new).credential()
    }

    fn client(mock: MockTransport, credential: Credential) -> ClickHouseClient<MockTransport> {
        ClickHouseClient::new(
            mock,
            credential,
            LanternaConfig::prescribed_default(),
            Identity {
                label: "alpha".into(),
                host: HOST.into(),
                tls_posture: TlsPosture::System,
            },
        )
    }

    fn rows_body(names: &[&str], data: &[Value]) -> Value {
        let meta: Vec<Value> = names
            .iter()
            .map(|n| json!({"name": n, "type": "String"}))
            .collect();
        json!({"meta": meta, "data": data, "rows": data.len()})
    }

    fn databases(limit: Option<u32>) -> QuestionRequest {
        QuestionRequest::Databases { limit }
    }

    fn found(o: Outcome<Rows>) -> Rows {
        match o {
            Outcome::Found(r) => r,
            other => panic!("expected found, got {}", other.kind()),
        }
    }

    fn because<P>(o: &Outcome<P>) -> (&'static str, String) {
        match o {
            Outcome::Refused { because, .. } | Outcome::Blind { because } => {
                (o.kind(), because.clone())
            }
            other => (other.kind(), String::new()),
        }
    }

    #[tokio::test]
    async fn rows_are_found_and_every_request_carries_the_readonly_bounds() {
        let files = Files::new();
        let mock = MockTransport::new().reply_json(
            200,
            &rows_body(&["name", "engine"], &[json!(["default", "Atomic"])]),
        );
        let c = client(mock, files.credential());
        let rows = found(c.ask(&databases(Some(5))).await);
        assert_eq!(rows.returned, 1);
        assert!(!rows.truncated);
        assert_eq!(rows.target, "alpha");
        assert_eq!(rows.columns[0].name, "name");

        let calls = c.transport.calls();
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.route, "/");
        for name in REQUIRED_SETTINGS {
            assert!(call.setting(name).is_some(), "{name} missing: {call:?}");
        }
        assert_eq!(call.setting("readonly"), Some("1"));
        assert_eq!(call.setting("result_overflow_mode"), Some("break"));
        assert_eq!(call.setting("max_result_rows"), Some("501"));
        assert_eq!(call.setting("max_execution_time"), Some("30"));
        assert_eq!(call.setting("max_result_bytes"), Some("10485760"));
        assert!(call.body.starts_with("SELECT "), "{}", call.body);
        assert!(call.body.ends_with("LIMIT 6"), "{}", call.body);
    }

    #[tokio::test]
    async fn the_credential_is_read_on_every_call_and_never_echoed() {
        let files = Files::new();
        let mock = MockTransport::new().reply_json(200, &rows_body(&["name"], &[json!(["a"])]));
        let c = client(mock, files.credential());
        let first = c.ask(&databases(Some(1))).await;
        std::fs::write(files.keyfile.path(), "rotated\n").expect("rotate");
        let second = c.ask(&databases(Some(1))).await;
        let calls = c.transport.calls();
        assert_eq!(calls[0].user.as_deref(), Some("observer"));
        assert_eq!(calls[0].key.as_deref(), Some(SENTINEL));
        assert_eq!(calls[1].key.as_deref(), Some("rotated"));
        for outcome in [first, second] {
            let text = kotae::Answer::from(outcome).render();
            assert!(
                !text.contains(SENTINEL) && !text.contains("rotated") && !text.contains("observer"),
                "{text}"
            );
        }
    }

    #[tokio::test]
    async fn zero_rows_is_empty_and_names_what_was_looked_for() {
        let mock = MockTransport::new().reply_json(200, &rows_body(&["name"], &[]));
        let c = client(mock, shared_credential());
        match c.ask(&databases(Some(5))).await {
            Outcome::Empty { of } => assert_eq!(of, "databases visible to this user"),
            other => panic!("expected empty, got {}", other.kind()),
        }
    }

    #[tokio::test]
    async fn the_probe_row_makes_truncation_a_fact_the_wire_carries() {
        let three = [json!(["a"]), json!(["b"]), json!(["c"])];
        let over = MockTransport::new().reply_json(200, &rows_body(&["name"], &three));
        let c = client(over, shared_credential());
        let rows = found(c.ask(&databases(Some(2))).await);
        assert!(rows.truncated, "limit+1 rows came back");
        assert_eq!(rows.returned, 2);
        assert_eq!(rows.rows, vec![vec![json!("a")], vec![json!("b")]]);
        assert_eq!(rows.limit, Some(2));
        assert!(c.transport.calls()[0].body.ends_with("LIMIT 3"));

        let exact = MockTransport::new().reply_json(200, &rows_body(&["name"], &three[..2]));
        let c = client(exact, shared_credential());
        let rows = found(c.ask(&databases(Some(2))).await);
        assert!(!rows.truncated, "exactly limit rows is not truncated");
        assert_eq!(rows.returned, 2);
    }

    #[tokio::test]
    async fn a_missing_limit_or_window_is_refused_before_anything_is_sent() {
        let c = client(MockTransport::new(), shared_credential());
        for request in [
            databases(None),
            QuestionRequest::SlowQueries {
                window: None,
                limit: Some(5),
            },
            QuestionRequest::SlowQueries {
                window: Some("1h".into()),
                limit: None,
            },
            databases(Some(0)),
            databases(Some(501)),
        ] {
            let outcome = c.ask(&request).await;
            assert_eq!(outcome.kind(), "refused", "{request:?}");
            match outcome {
                Outcome::Refused { legal, .. } => assert_ne!(legal.len(), 0),
                _ => unreachable!(),
            }
        }
        assert!(c.transport.calls().is_empty(), "nothing may reach the wire");
    }

    #[tokio::test]
    async fn rejected_credentials_and_privileges_are_refused_naming_what_is_legal() {
        for (resp, needle) in [
            (
                HttpResponse::exception(401, 516, "Code: 516. DB::Exception: auth"),
                "rejected the credential",
            ),
            (
                HttpResponse::exception(403, 497, "Code: 497. DB::Exception: no grant"),
                "denied the user access",
            ),
            (
                HttpResponse::exception(403, 164, "Code: 164. DB::Exception: readonly"),
                "readonly",
            ),
            (
                HttpResponse::exception(
                    500,
                    164,
                    "Code: 164. DB::Exception: Cannot execute query in readonly mode",
                ),
                "readonly",
            ),
            (
                HttpResponse::json(401, &json!({})),
                "rejected the credential",
            ),
            (
                HttpResponse::json(403, &json!({})),
                "denied the user access",
            ),
        ] {
            let mock = MockTransport::new().on_any(vec![Scripted::Reply(resp)]);
            let c = client(mock, shared_credential());
            let outcome = c.ask(&databases(Some(1))).await;
            match &outcome {
                Outcome::Refused { because, legal } => {
                    assert!(because.contains(needle), "{needle}: {because}");
                    assert_ne!(legal.len(), 0);
                }
                other => panic!("expected refused for {needle}, got {}", other.kind()),
            }
        }
    }

    #[tokio::test]
    async fn an_unknown_table_database_or_column_is_refused_even_though_the_server_says_404() {
        for (status, code, what) in [
            (404, 60, "table"),
            (404, 81, "database"),
            (500, 47, "column"),
        ] {
            let text = "Code: 0. DB::Exception: nope";
            let mock = MockTransport::new().on_any(vec![Scripted::Reply(HttpResponse::exception(
                status, code, text,
            ))]);
            let c = client(mock, shared_credential());
            let outcome = c
                .ask(&QuestionRequest::Columns {
                    database: "alpha".into(),
                    table: "gone".into(),
                    limit: Some(5),
                })
                .await;
            let (kind, why) = because(&outcome);
            assert_eq!(kind, "refused", "{code}");
            assert!(why.contains(&("no such ".to_owned() + what)), "{why}");
        }
    }

    #[tokio::test]
    async fn replication_on_a_server_without_replicas_is_empty_and_other_sources_are_not_excused() {
        let absent = HttpResponse::exception(404, 60, "Code: 60. DB::Exception: system.replicas");
        let mock = MockTransport::new().on_any(vec![Scripted::Reply(absent.clone())]);
        let c = client(mock, shared_credential());
        match c
            .ask(&QuestionRequest::Replication { limit: Some(5) })
            .await
        {
            Outcome::Empty { of } => assert!(of.contains("system.replicas"), "{of}"),
            other => panic!("expected empty, got {}", other.kind()),
        }

        let none = MockTransport::new().reply_json(200, &rows_body(&["table"], &[]));
        let c = client(none, shared_credential());
        assert_eq!(
            c.ask(&QuestionRequest::Replication { limit: Some(5) })
                .await
                .kind(),
            "empty"
        );

        let mock = MockTransport::new().on_any(vec![Scripted::Reply(absent)]);
        let c = client(mock, shared_credential());
        assert_eq!(
            c.ask(&QuestionRequest::Merges { limit: Some(5) })
                .await
                .kind(),
            "refused",
            "an absent source is excused for replication only"
        );
    }

    #[tokio::test]
    async fn an_unreachable_host_is_blind_and_never_empty() {
        let connect = TransportError::Connect {
            host: "clickhouse-a.example.com".into(),
            detail: "dns error: failed to lookup address information".into(),
            evidence: ConnectEvidence::TcpClosed {
                host: "clickhouse-a.example.com".into(),
                port: 8443,
            },
        };
        let mock = MockTransport::new().on_any(vec![Scripted::Fail(connect)]);
        let c = client(mock, shared_credential());
        let outcome = c.ask(&databases(Some(5))).await;
        let (kind, why) = because(&outcome);
        assert_eq!(kind, "blind");
        assert!(
            why.contains("network path") && why.contains("also fails"),
            "{why}"
        );
    }

    #[tokio::test]
    async fn a_real_transport_against_a_closed_loopback_port_is_blind_with_evidence() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let transport = crate::transport::ReqwestTransport::new(
            url::Url::parse(&format!("https://127.0.0.1:{port}")).expect("url"),
            &TlsPosture::System,
            crate::transport::Timeouts {
                connect: std::time::Duration::from_secs(2),
                request: std::time::Duration::from_secs(2),
            },
        )
        .expect("builds");
        let files = Files::new();
        let c = ClickHouseClient::new(
            transport,
            files.credential(),
            LanternaConfig::prescribed_default(),
            Identity {
                label: "alpha".into(),
                host: HOST.into(),
                tls_posture: TlsPosture::System,
            },
        );
        let outcome = c.ask(&databases(Some(5))).await;
        let (kind, why) = because(&outcome);
        assert_eq!(kind, "blind", "{why}");
        assert!(
            why.contains("also fails within the connect timeout"),
            "{why}"
        );
    }

    #[tokio::test]
    async fn timeouts_tls_and_upstream_failures_are_each_blind_with_their_own_remedy() {
        let cases: Vec<(Scripted, &str)> = vec![
            (
                Scripted::Fail(TransportError::Timeout {
                    host: "h".into(),
                    detail: "slow".into(),
                }),
                "requestTimeoutMs",
            ),
            (
                Scripted::Fail(TransportError::Tls {
                    host: "h".into(),
                    detail: "bad cert".into(),
                    evidence: ConnectEvidence::Unprobed,
                }),
                "--tls system",
            ),
            (
                Scripted::Fail(TransportError::Other {
                    host: "h".into(),
                    detail: "weird".into(),
                    evidence: ConnectEvidence::Unprobed,
                }),
                "weird",
            ),
            (
                Scripted::Reply(HttpResponse::json(503, &json!({})).retry_after("7")),
                "retry after 7s",
            ),
            (
                Scripted::Reply(HttpResponse::json(429, &json!({}))),
                "no retry advice",
            ),
            (
                Scripted::Reply(HttpResponse::exception(
                    500,
                    159,
                    "Code: 159. DB::Exception: Timeout exceeded",
                )),
                "execution limit",
            ),
            (
                Scripted::Reply(HttpResponse::json(404, &json!({}))),
                "HTTP interface",
            ),
            (
                Scripted::Reply(HttpResponse::json(200, &json!({"oops": true}))),
                "could not read",
            ),
        ];
        for (script, needle) in cases {
            let mock = MockTransport::new().on_any(vec![script]);
            let c = client(mock, shared_credential());
            let outcome = c.ask(&databases(Some(5))).await;
            let (kind, why) = because(&outcome);
            assert_eq!(kind, "blind", "{needle}: {why}");
            assert!(why.contains(needle), "{needle}: {why}");
        }
    }

    #[tokio::test]
    async fn a_missing_credential_is_blind_naming_the_legal_form_and_nothing_is_sent() {
        let c = client(MockTransport::new(), Credential::None);
        let (kind, why) = because(&c.ask(&databases(Some(1))).await);
        assert_eq!(kind, "blind");
        assert!(why.contains("--user-file"), "{why}");

        let missing = Credential::Password {
            user_file: PathBuf::from("/definitely/not/here/user"),
            password_file: PathBuf::from("/definitely/not/here/password"),
        };
        let c = client(MockTransport::new(), missing);
        let (kind, why) = because(&c.ask(&databases(Some(1))).await);
        assert_eq!(kind, "blind");
        assert!(why.contains("/definitely/not/here/user"), "{why}");
        assert_eq!(c.transport.calls().len(), 0);
    }

    #[tokio::test]
    async fn whoami_reports_identity_and_the_bounds_in_force() {
        let body = json!({
            "meta": [
                {"name": "user", "type": "String"},
                {"name": "version", "type": "String"},
                {"name": "uptime_seconds", "type": "UInt32"}
            ],
            "data": [["observer", "24.8.1.1", 3600]],
            "rows": 1
        });
        let c = client(
            MockTransport::new().reply_json(200, &body),
            shared_credential(),
        );
        match c.whoami().await {
            Outcome::Found(who) => {
                assert_eq!(who.user, "observer");
                assert_eq!(who.version, "24.8.1.1");
                assert_eq!(who.uptime_seconds, 3600);
                assert_eq!(who.target, "alpha");
                assert!(who.bounds.readonly);
                assert_eq!(who.bounds.max_results, 500);
            }
            other => panic!("expected found, got {}", other.kind()),
        }
        let c = client(
            MockTransport::new().reply_json(200, &rows_body(&["user"], &[json!(["x"])])),
            shared_credential(),
        );
        assert_eq!(c.whoami().await.kind(), "blind");
    }

    #[tokio::test]
    async fn a_hostile_value_reaches_the_wire_only_as_an_escaped_literal() {
        let mock = MockTransport::new().reply_json(200, &rows_body(&["query"], &[json!(["q"])]));
        let c = client(mock, shared_credential());
        let request = QuestionRequest::Select(crate::sql::SelectRequest {
            database: "system".into(),
            table: "query_log".into(),
            columns: vec!["query".into()],
            filters: vec![crate::sql::FilterRequest {
                column: "query".into(),
                op: None,
                value: "x' OR 1=1; --".into(),
            }],
            time_column: Some("event_time".into()),
            window: Some("1h".into()),
            limit: Some(3),
        });
        assert_eq!(c.ask(&request).await.kind(), "found");
        let body = &c.transport.calls()[0].body;
        assert!(body.contains("`query` = 'x\\' OR 1=1; --'"), "{body}");
        assert_eq!(body.matches("SELECT").count(), 1);
    }
}
