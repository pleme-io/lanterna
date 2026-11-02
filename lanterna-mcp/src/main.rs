//! lanterna-mcp: the observe-only ClickHouse MCP server, on stdio.
//!
//! Twelve `clickhouse_*` tools over one target or several (each its own
//! host, TLS posture and credential, addressed by label), and every answer
//! is one of kotae's four outcomes. This binary owns the **wire** and
//! nothing else: argv, the transport, the runtime, the MCP framing. Every
//! decision about what a ClickHouse answer *means* lives in the `lanterna`
//! library, where it is tested against a scripted transport with no network.
//!
//! ## What is deliberately absent
//!
//! There is no tool that writes and no tool that takes SQL. The library's
//! route enum has no arm for a write and its question enum has no variant
//! that carries a statement, so neither could be built here even by accident.
//!
//! ## Where secrets go
//!
//! Credentials are file paths on argv; the files are read on every call into
//! zeroizing memory and never logged. A `--host` URL carrying userinfo is
//! refused at startup, and the host as it appears in answers and logs is
//! rendered from scheme, host and port only. `tracing` goes to stderr only:
//! stdout is the MCP transport, and a log line on stdout would corrupt it.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;

use clap::Parser;
use lanterna::outcome::{Failure, Refusal};
use lanterna::tls::TlsPostureError;
use lanterna::transport::{ReqwestTransport, Transport};
use lanterna::{
    ClickHouseClient, Credential, FilterRequest, HealthCheck, Identity, LanternaConfig, Outcome,
    QuestionRequest, Rows, SelectRequest, Targets, TargetsError, TlsPosture, WhoAmI,
};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use serde::Deserialize;
use serde_json::Value;

const INSTRUCTIONS: &str = "lanterna: an observe-only ClickHouse client. Twelve tools: `clickhouse_whoami` (the cheap \
reachability + credential probe: user, version, uptime, TLS posture, the bounds in force), \
`clickhouse_databases`, `clickhouse_tables`, `clickhouse_columns`, `clickhouse_table_sizes`, \
`clickhouse_health` (parts, merges, mutations or replication), `clickhouse_processes`, \
`clickhouse_slow_queries`, `clickhouse_row_policies`, `clickhouse_grants`, `clickhouse_metrics`, \
and `clickhouse_select` (one bounded read of an allowlisted table). There is no tool that writes \
and none that takes SQL: every request is sent readonly with execution, row and byte bounds. \
Every question that returns rows REQUIRES `limit`; every question over an event time REQUIRES \
`window` (`15m`, `24h`, `7d`). `truncated: true` means more rows matched than `limit`. Every \
answer carries an `outcome` discriminant and it is one of exactly four: `found` (here it is), \
`empty` (the host answered and there is nothing, a FINDING), `refused` (the question was not \
accepted: a missing or oversized bound, an illegal name, an unknown table, a rejected credential, \
or a privilege the user lacks; `legal` names what would be accepted, so retry differently), and \
`blind` (the question could not be put at all: conclude NOTHING about the subject). `blind` \
usually means the network path to the host is down (a VPN, an unresolvable name); it is also a TLS \
posture mismatch (`--tls`), a server timeout, a 5xx/429 with retry advice, or a missing \
credential file, and the message names which. Never read `blind` or `refused` as `empty`.";

const NAMED_TARGETS_PREAMBLE: &str = " This server serves several ClickHouse targets, each with its own host, TLS \
posture and credential. Every tool takes a REQUIRED `target`, one of: ";

const NAMED_TARGETS_CODA: &str = ". A missing or unknown `target` is `refused` naming these; one target \
answering `blind` says nothing about another.";

const TARGET_DESCRIPTION: &str =
    "Which configured ClickHouse target to ask: one of the labels the server instructions list.";

const LIMIT_DESCRIPTION: &str = "REQUIRED row cap, 1..=maxResults. The server asks for one probe row beyond it; `truncated` reports whether it came back.";

const WINDOW_DESCRIPTION: &str = "REQUIRED time window ending now: `<n>s`, `<n>m`, `<n>h` or `<n>d`, for example `15m`, `24h`, `7d`.";

const TARGET_KEYS: [&str; 5] = ["label", "host", "tls", "user-file", "password-file"];

const TOOL_REQUIRED: [(&str, &[&str]); 12] = [
    ("clickhouse_whoami", &[]),
    ("clickhouse_databases", &["limit"]),
    ("clickhouse_tables", &["database", "limit"]),
    ("clickhouse_columns", &["database", "table", "limit"]),
    ("clickhouse_table_sizes", &["database", "limit"]),
    ("clickhouse_health", &["check", "limit"]),
    ("clickhouse_processes", &["limit"]),
    ("clickhouse_slow_queries", &["window", "limit"]),
    ("clickhouse_row_policies", &["limit"]),
    ("clickhouse_grants", &["limit"]),
    ("clickhouse_metrics", &["limit"]),
    (
        "clickhouse_select",
        &[
            "database",
            "table",
            "columns",
            "time_column",
            "window",
            "limit",
        ],
    ),
];

/// The CLI contract. The Nix side emits exactly these flags.
#[derive(Debug, Parser)]
#[command(
    name = "lanterna-mcp",
    version,
    about = "observe-only ClickHouse MCP server (stdio)"
)]
struct Cli {
    /// Full HTTP(S) interface URL including scheme and port, e.g.
    /// `https://clickhouse-a.example.com:8443`.
    #[arg(
        long,
        value_name = "URL",
        required_unless_present = "targets",
        conflicts_with = "targets"
    )]
    host: Option<url::Url>,

    /// Display label used in every answer: a tenant name, never a hostname.
    #[arg(
        long,
        value_name = "STRING",
        required_unless_present = "targets",
        conflicts_with = "targets"
    )]
    label: Option<String>,

    /// File holding the ClickHouse user name. Requires `--password-file`.
    #[arg(
        long,
        value_name = "PATH",
        requires = "password_file",
        conflicts_with = "targets"
    )]
    user_file: Option<PathBuf>,

    /// File holding the password. Requires `--user-file`.
    #[arg(
        long,
        value_name = "PATH",
        requires = "user_file",
        conflicts_with = "targets"
    )]
    password_file: Option<PathBuf>,

    /// TLS posture: `system` (public roots), `accept-any` (degraded), or
    /// `ca:<PEM_PATH>` (a private root).
    #[arg(
        long,
        value_name = "system|accept-any|ca:<PEM_PATH>",
        default_value = "system",
        conflicts_with = "targets"
    )]
    tls: TlsPosture,

    #[arg(
        long = "target",
        value_name = "JSON",
        help = "One ClickHouse target as a JSON object with keys label, host, tls, user-file, password-file. Repeat it to serve several targets from one server; every tool then takes a required `target`. Conflicts with --host/--label/--tls and the credential flags"
    )]
    targets: Vec<Endpoint>,

    /// Optional shikumi YAML overlay for the bounds (`LanternaConfig`); an
    /// unknown key is refused, a partial file folds onto the prescribed tier.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
}

/// Why the server could not start. Each arm is one argv-level fact.
#[derive(Debug, thiserror::Error)]
enum StartError {
    /// `--host` must be `http(s)://<host>[:port]`.
    #[error(
        "host {label} must be an http or https URL naming a host, e.g. https://clickhouse-a.example.com:8443"
    )]
    Host {
        /// What was passed, as [`HostLabel`] renders it: never the raw URL,
        /// which may carry userinfo.
        label: String,
    },
    /// The bounds overlay was refused.
    #[error(transparent)]
    Config(#[from] lanterna::ConfigError),
    /// The HTTP client could not be built.
    #[error(transparent)]
    Transport(#[from] lanterna::transport::TransportBuildError),
    /// The target set was empty or repeated a label.
    #[error(transparent)]
    Targets(#[from] TargetsError),
}

impl Cli {
    fn credential(&self) -> Credential {
        credential_from(self.user_file.clone(), self.password_file.clone())
            .unwrap_or(Credential::None)
    }

    fn addressing(&self) -> Addressing {
        if self.targets.is_empty() {
            Addressing::Implicit
        } else {
            Addressing::Named
        }
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        match (&self.host, &self.label) {
            (Some(host), Some(label)) => vec![Endpoint {
                label: label.clone(),
                host: host.clone(),
                tls: self.tls.clone(),
                credential: self.credential(),
            }],
            _ => self.targets.clone(),
        }
    }

    fn config(&self) -> Result<LanternaConfig, StartError> {
        use shikumi::TieredConfig as _;
        Ok(match &self.config {
            Some(path) => LanternaConfig::from_overlay_file(path)?,
            None => LanternaConfig::prescribed_default(),
        })
    }

    fn server(&self) -> Result<LanternaMcp, StartError> {
        let config = self.config()?;
        let clients = self
            .endpoints()
            .iter()
            .map(|endpoint| endpoint.client(&config))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(LanternaMcp::new(Targets::new(clients)?, self.addressing()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Addressing {
    Implicit,
    Named,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Endpoint {
    label: String,
    host: url::Url,
    tls: TlsPosture,
    credential: Credential,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct TargetArg {
    label: String,
    host: String,
    #[serde(default)]
    tls: Option<String>,
    #[serde(default)]
    user_file: Option<PathBuf>,
    #[serde(default)]
    password_file: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
enum TargetArgError {
    #[error("--target must be one JSON object with keys {}: {source}", TARGET_KEYS.join(", "))]
    Json {
        #[source]
        source: serde_json::Error,
    },
    #[error("--target {label}: host is not a URL: {source}")]
    Url {
        label: String,
        #[source]
        source: url::ParseError,
    },
    #[error("--target {label}: {source}")]
    Tls {
        label: String,
        #[source]
        source: TlsPostureError,
    },
    #[error("--target {label}: {shape}")]
    Credential {
        label: String,
        shape: CredentialShapeError,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum CredentialShapeError {
    #[error("user-file and password-file must appear together; both are needed")]
    HalfPair,
}

fn credential_from(
    user_file: Option<PathBuf>,
    password_file: Option<PathBuf>,
) -> Result<Credential, CredentialShapeError> {
    match (user_file, password_file) {
        (Some(user_file), Some(password_file)) => Ok(Credential::Password {
            user_file,
            password_file,
        }),
        (None, None) => Ok(Credential::None),
        (Some(_), None) | (None, Some(_)) => Err(CredentialShapeError::HalfPair),
    }
}

impl FromStr for Endpoint {
    type Err = TargetArgError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let arg: TargetArg =
            serde_json::from_str(s).map_err(|source| TargetArgError::Json { source })?;
        let host = url::Url::parse(&arg.host).map_err(|source| TargetArgError::Url {
            label: arg.label.clone(),
            source,
        })?;
        let tls = match &arg.tls {
            Some(posture) => posture.parse().map_err(|source| TargetArgError::Tls {
                label: arg.label.clone(),
                source,
            })?,
            None => TlsPosture::System,
        };
        let credential = credential_from(arg.user_file, arg.password_file).map_err(|shape| {
            TargetArgError::Credential {
                label: arg.label.clone(),
                shape,
            }
        })?;
        Ok(Self {
            label: arg.label,
            host,
            tls,
            credential,
        })
    }
}

impl Endpoint {
    fn host_label(&self) -> String {
        HostLabel(&self.host).to_string()
    }

    fn validate_host(&self) -> Result<(), StartError> {
        let scheme_ok = matches!(self.host.scheme(), "http" | "https");
        if scheme_ok && self.host.host_str().is_some() {
            Ok(())
        } else {
            Err(StartError::Host {
                label: self.host_label(),
            })
        }
    }

    fn identity(&self) -> Identity {
        Identity {
            label: self.label.clone(),
            host: self.host_label(),
            tls_posture: self.tls.clone(),
        }
    }

    fn client(
        &self,
        config: &LanternaConfig,
    ) -> Result<ClickHouseClient<Arc<dyn Transport>>, StartError> {
        self.validate_host()?;
        let transport = ReqwestTransport::new(self.host.clone(), &self.tls, config.timeouts())?;
        let transport: Arc<dyn Transport> = Arc::new(transport);
        Ok(ClickHouseClient::new(
            transport,
            self.credential.clone(),
            config.clone(),
            self.identity(),
        ))
    }

    fn announce(&self) {
        let host = self.host_label();
        if self.tls.is_degraded() {
            tracing::warn!(
                target_label = %self.label,
                host = %host,
                posture = %self.tls,
                "TLS posture is DEGRADED: certificates and hostnames are not verified for this host"
            );
        }
        match self.credential {
            Credential::None => {
                tracing::warn!(
                    target_label = %self.label,
                    host = %host,
                    "no credential configured; every tool will answer `blind` naming the legal form"
                );
            }
            Credential::Password { .. } => {
                tracing::info!(target_label = %self.label, host = %host, "starting");
            }
        }
    }
}

/// `scheme://host[:port]`: the one rendering of `--host` that reaches an
/// answer or a log line. Built from the URL's parts, never from its text, so
/// userinfo, a path, a query or a trailing slash cannot ride along.
struct HostLabel<'a>(&'a url::Url);

impl fmt::Display for HostLabel<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}://{}",
            self.0.scheme(),
            self.0.host_str().unwrap_or_default()
        )?;
        if let Some(port) = self.0.port() {
            write!(f, ":{port}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WhoAmIInput {
    #[serde(default)]
    #[schemars(description = TARGET_DESCRIPTION)]
    target: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct LimitInput {
    #[serde(default)]
    #[schemars(description = TARGET_DESCRIPTION)]
    target: Option<String>,
    #[serde(default)]
    #[schemars(description = LIMIT_DESCRIPTION)]
    limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DatabaseInput {
    #[serde(default)]
    #[schemars(description = TARGET_DESCRIPTION)]
    target: Option<String>,
    /// The database name (`[A-Za-z_][A-Za-z0-9_]*`).
    database: String,
    #[serde(default)]
    #[schemars(description = LIMIT_DESCRIPTION)]
    limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ColumnsInput {
    #[serde(default)]
    #[schemars(description = TARGET_DESCRIPTION)]
    target: Option<String>,
    /// The database name.
    database: String,
    /// The table name.
    table: String,
    #[serde(default)]
    #[schemars(description = LIMIT_DESCRIPTION)]
    limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct HealthInput {
    #[serde(default)]
    #[schemars(description = TARGET_DESCRIPTION)]
    target: Option<String>,
    /// One of `parts`, `merges`, `mutations`, `replication`. `parts` and
    /// `mutations` also REQUIRE `window`.
    check: String,
    /// `parts` only: restrict to one database.
    #[serde(default)]
    database: Option<String>,
    /// REQUIRED for `parts` and `mutations`: `<n>s|m|h|d`.
    #[serde(default)]
    window: Option<String>,
    #[serde(default)]
    #[schemars(description = LIMIT_DESCRIPTION)]
    limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SlowQueriesInput {
    #[serde(default)]
    #[schemars(description = TARGET_DESCRIPTION)]
    target: Option<String>,
    #[serde(default)]
    #[schemars(description = WINDOW_DESCRIPTION)]
    window: Option<String>,
    #[serde(default)]
    #[schemars(description = LIMIT_DESCRIPTION)]
    limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct MetricsInput {
    #[serde(default)]
    #[schemars(description = TARGET_DESCRIPTION)]
    target: Option<String>,
    /// One of `metrics` (gauges), `asynchronous` (sampled), `events`
    /// (cumulative). Defaults to `metrics`.
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    #[schemars(description = LIMIT_DESCRIPTION)]
    limit: Option<u32>,
}

/// One filter. The value is always rendered as a quoted literal.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct FilterInput {
    /// Column name (`[A-Za-z_][A-Za-z0-9_]*`).
    column: String,
    /// One of `eq` `ne` `gt` `lt` `ge` `le` `like`. Defaults to `eq`.
    #[serde(default)]
    op: Option<String>,
    /// The value to compare against.
    value: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SelectInput {
    #[serde(default)]
    #[schemars(description = TARGET_DESCRIPTION)]
    target: Option<String>,
    /// The database; it must be in the deployment's select allowlist.
    database: String,
    /// The table; it must be in the deployment's select allowlist.
    table: String,
    /// The columns to read: at least one, no wildcard.
    columns: Vec<String>,
    /// Filters, all of which must hold.
    #[serde(default)]
    filters: Vec<FilterInput>,
    /// REQUIRED: the column the window applies to; also the sort key (newest first).
    #[serde(default)]
    time_column: Option<String>,
    #[serde(default)]
    #[schemars(description = WINDOW_DESCRIPTION)]
    window: Option<String>,
    #[serde(default)]
    #[schemars(description = LIMIT_DESCRIPTION)]
    limit: Option<u32>,
}

impl From<SelectInput> for SelectRequest {
    fn from(s: SelectInput) -> Self {
        Self {
            database: s.database,
            table: s.table,
            columns: s.columns,
            filters: s
                .filters
                .into_iter()
                .map(|f| FilterRequest {
                    column: f.column,
                    op: f.op,
                    value: f.value,
                })
                .collect(),
            time_column: s.time_column,
            window: s.window,
            limit: s.limit,
        }
    }
}

#[derive(Clone)]
struct LanternaMcp {
    targets: Arc<Targets<Arc<dyn Transport>>>,
    tool_router: ToolRouter<Self>,
    instructions: Arc<str>,
}

/// The one place an [`Outcome`] becomes an MCP result. `is_error` is derived
/// from the discriminant: `found` and `empty` are answers about the world;
/// `refused` and `blind` are about the attempt.
fn answer<P: serde::Serialize>(outcome: Outcome<P>) -> CallToolResult {
    let a: kotae::Answer = outcome.into();
    let content = vec![Content::text(a.render())];
    if a.is_about_the_world() {
        CallToolResult::success(content)
    } else {
        CallToolResult::error(content)
    }
}

fn refused(refusal: Refusal) -> CallToolResult {
    answer::<()>(Failure::from(refusal).into())
}

fn required_for(tool: &str) -> &'static [&'static str] {
    TOOL_REQUIRED
        .iter()
        .find(|(name, _)| *name == tool)
        .map_or(&[], |(_, fields)| fields)
}

fn shape_schemas(router: &mut ToolRouter<LanternaMcp>, addressing: Addressing) {
    for route in router.map.values_mut() {
        let tool = route.attr.name.to_string();
        let schema = Arc::make_mut(&mut route.attr.input_schema);
        let required = schema
            .entry("required")
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Value::Array(names) = required {
            let mut wanted: Vec<&str> = required_for(&tool).to_vec();
            if addressing == Addressing::Named {
                wanted.push("target");
            }
            for field in wanted {
                if !names.iter().any(|n| n == field) {
                    names.push(Value::from(field));
                }
            }
        }
        if addressing == Addressing::Implicit
            && let Some(Value::Object(properties)) = schema.get_mut("properties")
        {
            properties.remove("target");
        }
        if schema
            .get("required")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        {
            schema.remove("required");
        }
    }
}

fn instructions_for(targets: &Targets<Arc<dyn Transport>>, addressing: Addressing) -> String {
    let mut text = INSTRUCTIONS.to_owned();
    if addressing == Addressing::Named {
        text.push_str(NAMED_TARGETS_PREAMBLE);
        text.push_str(&targets.labels().collect::<Vec<_>>().join(", "));
        text.push_str(NAMED_TARGETS_CODA);
    }
    text
}

impl LanternaMcp {
    fn new(targets: Targets<Arc<dyn Transport>>, addressing: Addressing) -> Self {
        let mut tool_router = Self::tool_router();
        shape_schemas(&mut tool_router, addressing);
        let instructions = instructions_for(&targets, addressing).into();
        Self {
            targets: Arc::new(targets),
            tool_router,
            instructions,
        }
    }

    fn pick(
        &self,
        target: Option<&str>,
    ) -> Result<&ClickHouseClient<Arc<dyn Transport>>, CallToolResult> {
        self.targets.resolve(target).map_err(refused)
    }

    async fn ask(&self, target: Option<&str>, request: QuestionRequest) -> CallToolResult {
        match self.pick(target) {
            Ok(client) => answer::<Rows>(client.ask(&request).await),
            Err(refusal) => refusal,
        }
    }
}

#[tool_router]
impl LanternaMcp {
    #[tool(
        description = "Reachability + credential probe for the configured ClickHouse host: label, host, the user the credential authenticates as, server version, uptime, the TLS posture in force, and the bounds every request is held to (readonly, maxResults, window, execution and result-size limits). `blind` here usually means the network path is down."
    )]
    async fn clickhouse_whoami(
        &self,
        Parameters(input): Parameters<WhoAmIInput>,
    ) -> CallToolResult {
        match self.pick(input.target.as_deref()) {
            Ok(client) => answer::<WhoAmI>(client.whoami().await),
            Err(refusal) => refusal,
        }
    }

    #[tool(
        description = "List the databases this user can see. `limit` is REQUIRED (1..=maxResults). `empty` means the host answered and this user sees no database."
    )]
    async fn clickhouse_databases(
        &self,
        Parameters(input): Parameters<LimitInput>,
    ) -> CallToolResult {
        self.ask(
            input.target.as_deref(),
            QuestionRequest::Databases { limit: input.limit },
        )
        .await
    }

    #[tool(
        description = "List the tables of one database, with engine and total rows and bytes where reported. `database` and `limit` are REQUIRED. An unknown database is `refused`."
    )]
    async fn clickhouse_tables(
        &self,
        Parameters(input): Parameters<DatabaseInput>,
    ) -> CallToolResult {
        self.ask(
            input.target.as_deref(),
            QuestionRequest::Tables {
                database: input.database,
                limit: input.limit,
            },
        )
        .await
    }

    #[tool(
        description = "List the columns of one table, with type and key membership. `database`, `table` and `limit` are REQUIRED. A table with no columns visible to this user is `empty`."
    )]
    async fn clickhouse_columns(
        &self,
        Parameters(input): Parameters<ColumnsInput>,
    ) -> CallToolResult {
        self.ask(
            input.target.as_deref(),
            QuestionRequest::Columns {
                database: input.database,
                table: input.table,
                limit: input.limit,
            },
        )
        .await
    }

    #[tool(
        description = "Active-part sizes per table of one database (rows, bytes on disk, compressed and uncompressed bytes, part count), largest first. `database` and `limit` are REQUIRED."
    )]
    async fn clickhouse_table_sizes(
        &self,
        Parameters(input): Parameters<DatabaseInput>,
    ) -> CallToolResult {
        self.ask(
            input.target.as_deref(),
            QuestionRequest::TableSizes {
                database: input.database,
                limit: input.limit,
            },
        )
        .await
    }

    #[tool(
        description = "One health check, chosen by `check`: `parts` (active parts per table modified inside `window`; optional `database`), `merges` (merges running now), `mutations` (created inside `window`, plus every unfinished one), `replication` (replica state; a server with no replicated tables answers `empty`, not an error). `limit` is REQUIRED; `window` is REQUIRED for `parts` and `mutations`."
    )]
    async fn clickhouse_health(
        &self,
        Parameters(input): Parameters<HealthInput>,
    ) -> CallToolResult {
        match HealthCheck::try_from(input.check.as_str()) {
            Ok(check) => {
                self.ask(
                    input.target.as_deref(),
                    check.request(input.database, input.window, input.limit),
                )
                .await
            }
            Err(e) => refused(Refusal::Invalid(e)),
        }
    }

    #[tool(
        description = "Queries running now (excluding this one), longest first, with user, elapsed seconds, rows read, memory and the first 512 characters of the text. `limit` is REQUIRED. `empty` means nothing else is running."
    )]
    async fn clickhouse_processes(
        &self,
        Parameters(input): Parameters<LimitInput>,
    ) -> CallToolResult {
        self.ask(
            input.target.as_deref(),
            QuestionRequest::RunningQueries { limit: input.limit },
        )
        .await
    }

    #[tool(
        description = "The slowest finished top-level queries inside `window`, from system.query_log, with duration, rows and bytes read, memory, exception code and the first 512 characters of the text. `window` and `limit` are REQUIRED."
    )]
    async fn clickhouse_slow_queries(
        &self,
        Parameters(input): Parameters<SlowQueriesInput>,
    ) -> CallToolResult {
        self.ask(
            input.target.as_deref(),
            QuestionRequest::SlowQueries {
                window: input.window,
                limit: input.limit,
            },
        )
        .await
    }

    #[tool(
        description = "Row policies visible to this user (name, database, table, filter, restrictive). `limit` is REQUIRED. `empty` means none are visible."
    )]
    async fn clickhouse_row_policies(
        &self,
        Parameters(input): Parameters<LimitInput>,
    ) -> CallToolResult {
        self.ask(
            input.target.as_deref(),
            QuestionRequest::RowPolicies { limit: input.limit },
        )
        .await
    }

    #[tool(
        description = "Grants visible to this user (user or role, access type, database, table, column). `limit` is REQUIRED."
    )]
    async fn clickhouse_grants(&self, Parameters(input): Parameters<LimitInput>) -> CallToolResult {
        self.ask(
            input.target.as_deref(),
            QuestionRequest::Grants { limit: input.limit },
        )
        .await
    }

    #[tool(
        description = "Server counters from one `source`: `metrics` (current gauges), `asynchronous` (sampled values), `events` (cumulative counters). `limit` is REQUIRED."
    )]
    async fn clickhouse_metrics(
        &self,
        Parameters(input): Parameters<MetricsInput>,
    ) -> CallToolResult {
        self.ask(
            input.target.as_deref(),
            QuestionRequest::Metrics {
                source: input.source,
                limit: input.limit,
            },
        )
        .await
    }

    #[tool(
        description = "One bounded read of an allowlisted table: `SELECT <columns> FROM <database>.<table> WHERE <time_column> >= now() - <window> AND <filters> ORDER BY <time_column> DESC LIMIT <limit>`. `database`, `table`, `columns`, `time_column`, `window` and `limit` are REQUIRED; a table outside the deployment's select allowlist is `refused` and the refusal lists the allowlist. Filter values are always quoted literals."
    )]
    async fn clickhouse_select(
        &self,
        Parameters(input): Parameters<SelectInput>,
    ) -> CallToolResult {
        let target = input.target.clone();
        self.ask(target.as_deref(), QuestionRequest::Select(input.into()))
            .await
    }
}

#[allow(clippy::unused_async_trait_impl)]
#[tool_handler(router = self.tool_router)]
impl ServerHandler for LanternaMcp {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.instructions = Some(self.instructions.to_string());
        info
    }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
}

/// Why serving stopped before a clean close. Three phases, three arms.
#[derive(Debug, thiserror::Error)]
enum ServeError {
    /// The Tokio runtime could not be built.
    #[error("runtime could not be built: {0}")]
    Runtime(#[from] std::io::Error),
    /// The MCP initialize handshake on stdio failed. Boxed: the rmcp error
    /// carries the offending message and is large.
    #[error("MCP initialize handshake failed: {0}")]
    Initialize(#[from] Box<rmcp::service::ServerInitializeError>),
    /// The serving task ended abnormally.
    #[error("serving task ended abnormally: {0}")]
    Task(#[from] tokio::task::JoinError),
}

fn serve(server: LanternaMcp) -> Result<(), ServeError> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        use rmcp::ServiceExt as _;
        let service = server
            .serve(rmcp::transport::stdio())
            .await
            .map_err(Box::new)?;
        let reason = service.waiting().await?;
        tracing::info!(reason = ?reason, "lanterna-mcp closed");
        Ok(())
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing();
    let server = match cli.server() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "lanterna-mcp could not start");
            return ExitCode::from(2);
        }
    };
    for endpoint in cli.endpoints() {
        endpoint.announce();
    }
    match serve(server) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "lanterna-mcp stopped");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;
    use lanterna::transport::{HttpResponse, MockTransport, Scripted};
    use serde_json::json;
    use shikumi::TieredConfig as _;
    use std::io::Write as _;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("lanterna-mcp").chain(args.iter().copied()))
    }

    fn parse_owned(args: &[String]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("lanterna-mcp".to_owned()).chain(args.iter().cloned()))
    }

    const BASE: [&str; 4] = [
        "--host",
        "https://clickhouse-a.example.com:8443",
        "--label",
        "alpha",
    ];

    fn with(extra: &[&str]) -> Vec<&'static str> {
        let mut v: Vec<&'static str> = BASE.to_vec();
        for e in extra {
            v.push(Box::leak((*e).to_owned().into_boxed_str()));
        }
        v
    }

    fn sole(cli: &Cli) -> Endpoint {
        let mut endpoints = cli.endpoints();
        assert_eq!(endpoints.len(), 1);
        endpoints.remove(0)
    }

    fn target_json(label: &str, host: &str, extra: &str) -> String {
        let mut s = String::new();
        s.push_str("{\"label\":\"");
        s.push_str(label);
        s.push_str("\",\"host\":\"");
        s.push_str(host);
        s.push('"');
        s.push_str(extra);
        s.push('}');
        s
    }

    fn two_targets() -> Vec<String> {
        vec![
            "--target".to_owned(),
            target_json(
                "alpha",
                "https://clickhouse-a.example.com:8443",
                ",\"user-file\":\"/u-a\",\"password-file\":\"/p-a\"",
            ),
            "--target".to_owned(),
            target_json(
                "beta",
                "https://clickhouse-b.example.com:8443",
                ",\"tls\":\"accept-any\"",
            ),
        ]
    }

    fn mock_client(
        label: &str,
        host: &str,
        mock: MockTransport,
        credential: Credential,
    ) -> ClickHouseClient<Arc<dyn Transport>> {
        let transport: Arc<dyn Transport> = Arc::new(mock);
        ClickHouseClient::new(
            transport,
            credential,
            LanternaConfig::prescribed_default(),
            Identity {
                label: label.into(),
                host: host.into(),
                tls_posture: TlsPosture::System,
            },
        )
    }

    fn credential_files() -> (tempfile::NamedTempFile, tempfile::NamedTempFile, Credential) {
        let write = |text: &str| {
            let mut f = tempfile::NamedTempFile::new().expect("tempfile");
            f.write_all(text.as_bytes()).expect("write");
            f
        };
        let user = write("observer\n");
        let key = write("not-a-real-value\n");
        let credential = Credential::Password {
            user_file: user.path().to_path_buf(),
            password_file: key.path().to_path_buf(),
        };
        (user, key, credential)
    }

    fn server(mock: MockTransport, credential: Credential) -> LanternaMcp {
        let client = mock_client(
            "alpha",
            "https://clickhouse-a.example.com:8443",
            mock,
            credential,
        );
        LanternaMcp::new(
            Targets::new([client]).expect("one target"),
            Addressing::Implicit,
        )
    }

    fn fleet() -> (LanternaMcp, [tempfile::NamedTempFile; 2]) {
        let (user, key, credential) = credential_files();
        let rows = |name: &str| {
            json!({
                "meta": [{"name": "name", "type": "String"}],
                "data": [[name]],
                "rows": 1
            })
        };
        let a = mock_client(
            "alpha",
            "https://clickhouse-a.example.com:8443",
            MockTransport::new().reply_json(200, &rows("from-alpha")),
            credential.clone(),
        );
        let b = mock_client(
            "beta",
            "https://clickhouse-b.example.com:8443",
            MockTransport::new().reply_json(200, &rows("from-beta")),
            credential,
        );
        (
            LanternaMcp::new(Targets::new([a, b]).expect("two"), Addressing::Named),
            [user, key],
        )
    }

    fn text_of(result: &CallToolResult) -> Value {
        let text = result
            .content
            .first()
            .and_then(|c| c.as_text())
            .expect("one text content")
            .text
            .clone();
        serde_json::from_str(&text).expect("the answer is JSON")
    }

    #[test]
    fn the_cli_contract_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn host_and_label_are_required_and_credentials_default_to_none() {
        assert!(parse(&["--label", "alpha"]).is_err());
        assert!(parse(&["--host", "https://h.example.com:8443"]).is_err());
        let cli = parse(&BASE).expect("parses");
        assert_eq!(cli.credential(), Credential::None);
        assert_eq!(cli.tls, TlsPosture::System);
        assert_eq!(
            sole(&cli).host_label(),
            "https://clickhouse-a.example.com:8443"
        );
        assert!(cli.config.is_none());
    }

    #[test]
    fn the_password_pair_travels_together() {
        assert!(parse(&with(&["--user-file", "/u"])).is_err());
        assert!(parse(&with(&["--password-file", "/p"])).is_err());
        let pw = parse(&with(&["--user-file", "/u", "--password-file", "/p"])).expect("pair");
        assert_eq!(
            pw.credential(),
            Credential::Password {
                user_file: "/u".into(),
                password_file: "/p".into()
            }
        );
        assert!(
            parse(&with(&["--token-file", "/t"])).is_err(),
            "no token form"
        );
    }

    #[test]
    fn the_tls_flag_is_the_typed_posture_and_names_its_legal_set() {
        assert_eq!(
            parse(&with(&["--tls", "accept-any"])).expect("ok").tls,
            TlsPosture::AcceptAny
        );
        let err = parse(&with(&["--tls", "insecure"])).expect_err("refused");
        assert!(err.to_string().contains("ca:<PEM_PATH>"), "{err}");
    }

    #[test]
    fn a_host_carrying_a_credential_is_refused_and_never_echoed() {
        let with_userinfo = format!(
            "https://{}@clickhouse-a.example.com:8443/",
            ["observer", "hunter2"].join(":")
        );
        let cli = parse(&["--host", &with_userinfo, "--label", "alpha"]).expect("url parses");
        assert_eq!(
            sole(&cli).host_label(),
            "https://clickhouse-a.example.com:8443"
        );
        let err = cli.server().err().expect("refused");
        assert!(matches!(err, StartError::Transport(_)), "{err:?}");
        let msg = err.to_string();
        assert!(
            !msg.contains("hunter2") && !msg.contains("observer"),
            "{msg}"
        );
        for form in lanterna::LEGAL_CREDENTIAL_FORMS {
            assert!(msg.contains(form), "{msg}");
        }
        let cli = parse(&["--host", "mailto:ops@example.com", "--label", "alpha"]).expect("parses");
        assert!(matches!(
            sole(&cli).validate_host(),
            Err(StartError::Host { .. })
        ));
    }

    #[test]
    fn a_config_overlay_folds_and_an_unknown_key_refuses_startup() {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(b"maxResults: 25\n").expect("write");
        let path = f.path().to_str().expect("utf8 path").to_owned();
        let cli = parse(&with(&["--config", &path])).expect("ok");
        assert_eq!(cli.config().expect("loads").max_results, 25);

        let mut bad = tempfile::NamedTempFile::new().expect("tempfile");
        bad.write_all(b"maxResultz: 25\n").expect("write");
        let path = bad.path().to_str().expect("utf8 path").to_owned();
        let cli = parse(&with(&["--config", &path])).expect("ok");
        let err = cli.server().err().expect("refused");
        assert!(matches!(err, StartError::Config(_)), "{err:?}");
        assert!(err.to_string().contains("maxResultz"), "{err}");
    }

    #[test]
    fn the_production_client_builds_under_every_posture_without_touching_the_network() {
        for posture in ["system", "accept-any"] {
            parse(&with(&["--tls", posture]))
                .expect("ok")
                .server()
                .expect("builds");
        }
        let cli = parse(&with(&["--tls", "ca:/nope/lanterna-root.pem"])).expect("ok");
        assert!(matches!(cli.server().err(), Some(StartError::Transport(_))));
    }

    #[test]
    fn each_target_keeps_its_own_host_tls_and_credential() {
        let cli = parse_owned(&two_targets()).expect("parses");
        assert_eq!(cli.addressing(), Addressing::Named);
        let endpoints = cli.endpoints();
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].label, "alpha");
        assert_eq!(
            endpoints[0].credential,
            Credential::Password {
                user_file: "/u-a".into(),
                password_file: "/p-a".into()
            }
        );
        assert_eq!(endpoints[0].tls, TlsPosture::System);
        assert_eq!(endpoints[1].tls, TlsPosture::AcceptAny);
        assert_eq!(endpoints[1].credential, Credential::None);
        cli.server().expect("both build");
    }

    #[test]
    fn target_and_the_single_target_flags_are_exclusive() {
        let mut args = two_targets();
        args.extend(["--host".to_owned(), "https://h.example.com:8443".to_owned()]);
        assert!(parse_owned(&args).is_err());
        let mut args = two_targets();
        args.extend(["--tls".to_owned(), "accept-any".to_owned()]);
        assert!(parse_owned(&args).is_err());
        let mut args = two_targets();
        args.extend(["--user-file".to_owned(), "/u".to_owned()]);
        assert!(parse_owned(&args).is_err());
    }

    #[test]
    fn a_malformed_target_is_refused_at_parse_naming_the_fault() {
        let bad = |json: &str| {
            parse_owned(&["--target".to_owned(), json.to_owned()])
                .expect_err("refused")
                .to_string()
        };
        let msg = bad("{\"label\":\"alpha\",\"host\":\"https://h.example.com\",\"bogus\":1}");
        assert!(
            msg.contains("bogus") && msg.contains("label, host, tls"),
            "{msg}"
        );
        assert!(bad("not json").contains("--target must be one JSON object"));
        assert!(bad("{\"label\":\"a\",\"host\":\"no scheme\"}").contains("host is not a URL"));
        assert!(
            bad("{\"label\":\"a\",\"host\":\"https://h.example.com\",\"tls\":\"insecure\"}")
                .contains("accept-any")
        );
        assert!(
            bad("{\"label\":\"a\",\"host\":\"https://h.example.com\",\"user-file\":\"/u\"}")
                .contains("together")
        );
        assert!(
            bad("{\"label\":\"a\",\"host\":\"https://h.example.com\",\"token-file\":\"/t\"}")
                .contains("token-file"),
            "there is no token form"
        );
    }

    #[test]
    fn a_duplicate_target_label_refuses_startup() {
        let t = target_json("alpha", "https://clickhouse-a.example.com:8443", "");
        let cli = parse_owned(&["--target".to_owned(), t.clone(), "--target".to_owned(), t])
            .expect("parses");
        assert!(matches!(
            cli.server().err(),
            Some(StartError::Targets(TargetsError::Duplicate { .. }))
        ));
    }

    #[test]
    fn the_server_advertises_exactly_the_twelve_clickhouse_tools() {
        let router = LanternaMcp::tool_router();
        let mut names: Vec<String> = router
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        names.sort();
        let mut expected: Vec<String> =
            TOOL_REQUIRED.iter().map(|(n, _)| (*n).to_owned()).collect();
        expected.sort();
        assert_eq!(names, expected);
        assert_eq!(names.len(), 12);
        assert!(names.iter().all(|n| n.starts_with("clickhouse_")));
        for write_like in ["insert", "alter", "drop", "query", "sql", "execute", "kill"] {
            assert!(
                names.iter().all(|n| !n.contains(write_like)),
                "no tool may be named like a write: {write_like}"
            );
        }
    }

    #[test]
    fn bounds_are_required_in_every_schema_so_a_client_sees_them_before_it_asks() {
        let (s, _files) = fleet();
        for tool in s.tool_router.list_all() {
            let required: Vec<String> = tool
                .input_schema
                .get("required")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            assert!(required.contains(&"target".to_owned()), "{}", tool.name);
            for field in required_for(&tool.name) {
                assert!(
                    required.contains(&(*field).to_owned()),
                    "{}: {field}",
                    tool.name
                );
            }
            if tool.name != "clickhouse_whoami" {
                assert!(required.contains(&"limit".to_owned()), "{}", tool.name);
            }
        }
        let slow = s
            .tool_router
            .get("clickhouse_slow_queries")
            .expect("registered");
        let required = slow
            .input_schema
            .get("required")
            .expect("required")
            .to_string();
        assert!(
            required.contains("window") && required.contains("limit"),
            "{required}"
        );
    }

    #[test]
    fn a_single_target_server_advertises_no_target() {
        let s = server(MockTransport::new(), Credential::None);
        for tool in s.tool_router.list_all() {
            assert!(
                tool.input_schema
                    .get("properties")
                    .and_then(Value::as_object)
                    .is_none_or(|p| !p.contains_key("target")),
                "{}",
                tool.name
            );
            let required = tool.input_schema.get("required").map(Value::to_string);
            assert!(
                required.is_none_or(|r| !r.contains("target")),
                "{}",
                tool.name
            );
        }
    }

    #[test]
    fn the_instructions_teach_the_four_outcomes_and_name_the_targets_once() {
        let info = server(MockTransport::new(), Credential::None).get_info();
        assert!(info.capabilities.tools.is_some());
        let instr = info.instructions.expect("instructions");
        for word in [
            "found", "empty", "refused", "blind", "readonly", "legal", "limit", "window",
        ] {
            assert!(instr.contains(word), "instructions must mention {word}");
        }
        assert!(!instr.contains("alpha"));
        let (named_server, _files) = fleet();
        let named = named_server.get_info().instructions.expect("instructions");
        assert!(named.contains("alpha, beta"), "{named}");
        assert_eq!(named.matches("alpha").count(), 1);
    }

    #[tokio::test]
    async fn a_named_target_is_answered_by_its_own_host() {
        let (s, _files) = fleet();
        for (label, expect) in [("alpha", "from-alpha"), ("beta", "from-beta")] {
            let r = s
                .clickhouse_databases(Parameters(LimitInput {
                    target: Some(label.into()),
                    limit: Some(5),
                }))
                .await;
            assert_ne!(r.is_error, Some(true));
            let v = text_of(&r);
            assert_eq!(v["outcome"], "found");
            assert_eq!(v["target"], label);
            assert_eq!(v["rows"][0][0], expect);
        }
    }

    #[tokio::test]
    async fn an_unknown_or_missing_target_is_refused_naming_every_legal_label() {
        let (s, _files) = fleet();
        for target in [Some("gamma".to_owned()), None] {
            let r = s
                .clickhouse_databases(Parameters(LimitInput {
                    target,
                    limit: Some(5),
                }))
                .await;
            assert_eq!(r.is_error, Some(true));
            let v = text_of(&r);
            assert_eq!(v["outcome"], "refused");
            assert_eq!(v["legal"], json!(["alpha", "beta"]));
        }
    }

    #[tokio::test]
    async fn a_missing_bound_is_refused_with_is_error_and_the_legal_form() {
        let (_u, _p, credential) = credential_files();
        let s = server(MockTransport::new(), credential);
        let r = s
            .clickhouse_slow_queries(Parameters(SlowQueriesInput {
                target: None,
                window: None,
                limit: Some(5),
            }))
            .await;
        assert_eq!(r.is_error, Some(true));
        let v = text_of(&r);
        assert_eq!(v["outcome"], "refused");
        assert!(
            v["legal"][0].as_str().expect("legal").contains("<n>s"),
            "{v}"
        );

        let r = s
            .clickhouse_databases(Parameters(LimitInput {
                target: None,
                limit: None,
            }))
            .await;
        assert_eq!(text_of(&r)["outcome"], "refused");
    }

    #[tokio::test]
    async fn no_credential_answers_blind_with_is_error_and_the_legal_form() {
        let s = server(MockTransport::new(), Credential::None);
        let r = s
            .clickhouse_whoami(Parameters(WhoAmIInput { target: None }))
            .await;
        assert_eq!(r.is_error, Some(true));
        let v = text_of(&r);
        assert_eq!(v["outcome"], "blind");
        assert!(
            v["because"]
                .as_str()
                .expect("because")
                .contains("--user-file")
        );
    }

    #[tokio::test]
    async fn an_empty_table_is_empty_and_not_an_error_while_a_403_is_refused() {
        let (_u, _p, credential) = credential_files();
        let none = json!({"meta": [{"name": "name", "type": "String"}], "data": [], "rows": 0});
        let s = server(
            MockTransport::new().reply_json(200, &none),
            credential.clone(),
        );
        let r = s
            .clickhouse_databases(Parameters(LimitInput {
                target: None,
                limit: Some(5),
            }))
            .await;
        assert_ne!(r.is_error, Some(true));
        assert_eq!(text_of(&r)["outcome"], "empty");

        let denied = MockTransport::new().on_any(vec![Scripted::Reply(HttpResponse::exception(
            403,
            497,
            "Code: 497. DB::Exception: not enough privileges",
        ))]);
        let s = server(denied, credential);
        let r = s
            .clickhouse_databases(Parameters(LimitInput {
                target: None,
                limit: Some(5),
            }))
            .await;
        assert_eq!(r.is_error, Some(true));
        assert_eq!(text_of(&r)["outcome"], "refused");
    }

    #[tokio::test]
    async fn health_dispatches_each_check_and_refuses_an_unknown_one() {
        let (_u, _p, credential) = credential_files();
        let body = json!({"meta": [{"name": "x", "type": "String"}], "data": [["v"]], "rows": 1});
        let s = server(MockTransport::new().reply_json(200, &body), credential);
        for (check, window) in [
            ("parts", Some("1h")),
            ("merges", None),
            ("mutations", Some("1h")),
            ("replication", None),
        ] {
            let r = s
                .clickhouse_health(Parameters(HealthInput {
                    target: None,
                    check: check.into(),
                    database: None,
                    window: window.map(str::to_owned),
                    limit: Some(3),
                }))
                .await;
            assert_eq!(text_of(&r)["outcome"], "found", "{check}");
        }
        let r = s
            .clickhouse_health(Parameters(HealthInput {
                target: None,
                check: "vacuum".into(),
                database: None,
                window: None,
                limit: Some(3),
            }))
            .await;
        let v = text_of(&r);
        assert_eq!(v["outcome"], "refused");
        assert_eq!(
            v["legal"],
            json!(["parts", "merges", "mutations", "replication"])
        );
    }

    #[tokio::test]
    async fn select_outside_the_allowlist_is_refused_listing_the_allowlist() {
        let (_u, _p, credential) = credential_files();
        let s = server(MockTransport::new(), credential);
        let r = s
            .clickhouse_select(Parameters(SelectInput {
                target: None,
                database: "analytics".into(),
                table: "events".into(),
                columns: vec!["a".into()],
                filters: vec![],
                time_column: Some("t".into()),
                window: Some("1h".into()),
                limit: Some(5),
            }))
            .await;
        assert_eq!(r.is_error, Some(true));
        let v = text_of(&r);
        assert_eq!(v["outcome"], "refused");
        assert_eq!(v["legal"], json!(["system.*"]));
    }
}
