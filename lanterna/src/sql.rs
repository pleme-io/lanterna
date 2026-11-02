//! The closed set of questions lanterna can ask, and the ONE place SQL text
//! is assembled.
//!
//! There is no raw-SQL entry point. A caller builds a [`QuestionRequest`]
//! out of plain strings and numbers; [`Question::build`] validates it
//! against the deployment's [`Bounds`] and either returns a typed
//! [`Question`] or a [`SqlError`] that names what would be accepted, before
//! anything is sent. `impl Display for Question` is the only renderer.
//!
//! Three rules make the rendered text inert:
//!
//! * **One identifier grammar.** A database, table or column name is
//!   [`IDENT_GRAMMAR`] and nothing else, so it can carry no quote, no
//!   backtick, no space and no punctuation. It is rendered inside backticks
//!   anyway.
//! * **Values are always literals.** A caller's value is rendered as a
//!   single-quoted ClickHouse string with `\`, `'` and every ASCII control
//!   character escaped, so a quote, a keyword or a backslash in a value is
//!   bytes in a string and never syntax.
//! * **Every statement is a `SELECT` from a fixed template.** The text
//!   outside identifiers and literals is written once, below.
//!
//! Boundedness is a field, not a convention. Every question that returns
//! rows carries a [`ResultCap`] (`1..=cap`); every question over a source
//! that has an event time carries a [`Window`]. The request type holds both
//! as `Option` so that a missing one is a typed refusal
//! ([`SqlError::Missing`]) rather than a deserialization error.
//!
//! ```compile_fail,E0599
//! let _ = lanterna::Question::Raw(String::from("SELECT 1"));
//! ```

use std::fmt::{self, Write as _};

/// The grammar every database, table and column name must satisfy.
pub const IDENT_GRAMMAR: &str = "[A-Za-z_][A-Za-z0-9_]*";

const IDENT_MAX_LEN: usize = 128;

fn is_ident(candidate: &str) -> bool {
    let mut bytes = candidate.bytes();
    let head_ok = matches!(bytes.next(), Some(b) if b.is_ascii_alphabetic() || b == b'_');
    head_ok
        && candidate.len() <= IDENT_MAX_LEN
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// A single-quoted ClickHouse string literal: the only way a caller's value
/// reaches a statement.
struct Literal<'a>(&'a str);

impl fmt::Display for Literal<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char('\'')?;
        for c in self.0.chars() {
            match c {
                '\\' => f.write_str("\\\\")?,
                '\'' => f.write_str("\\'")?,
                '\n' => f.write_str("\\n")?,
                '\r' => f.write_str("\\r")?,
                '\t' => f.write_str("\\t")?,
                '\0' => f.write_str("\\0")?,
                '\u{8}' => f.write_str("\\b")?,
                '\u{c}' => f.write_str("\\f")?,
                c if c.is_ascii_control() => write!(f, "\\x{:02X}", u32::from(c))?,
                c => f.write_char(c)?,
            }
        }
        f.write_char('\'')
    }
}

/// A validated name inside backticks.
struct Quoted<'a>(&'a str);

impl fmt::Display for Quoted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`{}`", self.0)
    }
}

/// Why a question could not be built. Every arm names what WOULD have been
/// accepted through [`SqlError::legal`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SqlError {
    /// A database name outside [`IDENT_GRAMMAR`].
    #[error("database name {got:?} is not {IDENT_GRAMMAR}")]
    IllegalDatabase {
        /// The rejected name.
        got: String,
    },
    /// A table name outside [`IDENT_GRAMMAR`].
    #[error("table name {got:?} is not {IDENT_GRAMMAR}")]
    IllegalTable {
        /// The rejected name.
        got: String,
    },
    /// A column name outside [`IDENT_GRAMMAR`].
    #[error("column name {got:?} is not {IDENT_GRAMMAR}")]
    IllegalColumn {
        /// The rejected name.
        got: String,
    },
    /// An operator spelling outside [`Op::LEGAL`].
    #[error("operator {got:?} is not one of eq ne gt lt ge le like")]
    IllegalOp {
        /// The rejected spelling.
        got: String,
    },
    /// A metric source outside [`MetricSource::LEGAL`].
    #[error("metric source {got:?} is not one of metrics asynchronous events")]
    IllegalMetricSource {
        /// The rejected spelling.
        got: String,
    },
    /// A health check outside [`HealthCheck::LEGAL`].
    #[error("health check {got:?} is not one of parts merges mutations replication")]
    IllegalHealthCheck {
        /// The rejected spelling.
        got: String,
    },
    /// A field every row-returning question needs, and the caller left out.
    #[error("{field} is required: an unbounded question is refused before it is sent")]
    Missing {
        /// The missing field.
        field: &'static str,
    },
    /// A time window that did not parse or is out of range.
    #[error(transparent)]
    Window(#[from] WindowError),
    /// A result limit outside `1..=cap`.
    #[error(transparent)]
    Limit(#[from] CapError),
    /// A count or a length over one of the deployment's bounds.
    #[error("{got} {bound} exceeds the configured maximum of {max}; legal: at most {max}")]
    OverBound {
        /// Which bound.
        bound: SelectBound,
        /// What was asked for.
        got: usize,
        /// The configured maximum.
        max: u32,
    },
    /// A table the deployment does not allow `select` to read.
    #[error("table {table} is not in the select allowlist")]
    TableNotAllowed {
        /// The table as `database.table`.
        table: String,
        /// The allowlist entries, so the refusal names what is legal.
        allowed: Vec<String>,
    },
}

impl SqlError {
    /// What would have been accepted: the `legal` set of a refusal.
    #[must_use]
    pub fn legal(&self) -> Vec<String> {
        match self {
            Self::IllegalDatabase { .. }
            | Self::IllegalTable { .. }
            | Self::IllegalColumn { .. } => vec![IDENT_GRAMMAR.to_owned()],
            Self::IllegalOp { .. } => Op::LEGAL.iter().map(|s| (*s).to_owned()).collect(),
            Self::IllegalHealthCheck { .. } => {
                HealthCheck::LEGAL.iter().map(|s| (*s).to_owned()).collect()
            }
            Self::IllegalMetricSource { .. } => MetricSource::LEGAL
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            Self::Missing { field } => match *field {
                "limit" => vec!["limit: 1..=maxResults".to_owned()],
                "window" => vec![Window::LEGAL_FORM.to_owned()],
                "columns" => {
                    vec!["columns: at least one name matching the identifier grammar".to_owned()]
                }
                other => vec![other.to_owned()],
            },
            Self::Window(e) => vec![e.legal()],
            Self::Limit(e) => vec![e.legal()],
            Self::OverBound { bound, max, .. } => {
                let mut s = String::new();
                let _ = write!(s, "at most {max} {bound}");
                vec![s]
            }
            Self::TableNotAllowed { allowed, .. } => allowed.clone(),
        }
    }
}

/// The dimensions of a `select` the deployment bounds, besides the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectBound {
    /// `maxFilters`.
    Filters,
    /// `maxColumns`.
    Columns,
    /// `maxValueBytes`.
    ValueBytes,
}

impl fmt::Display for SelectBound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Filters => "filters (maxFilters)",
            Self::Columns => "columns (maxColumns)",
            Self::ValueBytes => "value bytes (maxValueBytes)",
        })
    }
}

/// The deployment bounds one question is validated against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bounds {
    /// The result cap.
    pub max_results: u32,
    /// The longest window, in seconds.
    pub max_window_seconds: u64,
    /// The most filters on a `select`.
    pub max_filters: u32,
    /// The most columns on a `select`.
    pub max_columns: u32,
    /// The longest filter value, in bytes.
    pub max_value_bytes: u32,
    /// The `database.table` / `database.*` entries `select` may read.
    pub select_allow: Vec<String>,
}

impl Bounds {
    fn check(bound: SelectBound, got: usize, max: u32) -> Result<(), SqlError> {
        if got > usize::try_from(max).unwrap_or(usize::MAX) {
            Err(SqlError::OverBound { bound, got, max })
        } else {
            Ok(())
        }
    }
}

macro_rules! ident_newtype {
    ($(#[$doc:meta])* $name:ident, $variant:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            /// The validated name.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = SqlError;

            fn try_from(candidate: &str) -> Result<Self, Self::Error> {
                if is_ident(candidate) {
                    Ok(Self(candidate.to_owned()))
                } else {
                    Err(SqlError::$variant {
                        got: candidate.to_owned(),
                    })
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

ident_newtype! {
    /// A database name, constructible only against [`IDENT_GRAMMAR`].
    DatabaseName, IllegalDatabase
}

ident_newtype! {
    /// A table name, constructible only against [`IDENT_GRAMMAR`].
    TableName, IllegalTable
}

ident_newtype! {
    /// A column name, constructible only against [`IDENT_GRAMMAR`].
    ColumnName, IllegalColumn
}

/// A database and a table, both validated.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TableRef {
    /// The database.
    pub database: DatabaseName,
    /// The table.
    pub table: TableName,
}

impl TableRef {
    /// Validate both names.
    pub fn parse(database: &str, table: &str) -> Result<Self, SqlError> {
        Ok(Self {
            database: DatabaseName::try_from(database)?,
            table: TableName::try_from(table)?,
        })
    }
}

impl fmt::Display for TableRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}",
            Quoted(self.database.as_str()),
            Quoted(self.table.as_str())
        )
    }
}

/// One entry of the `select` allowlist: `database.table` or `database.*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowEntry {
    database: String,
    table: Option<String>,
}

impl AllowEntry {
    /// Parse an entry; `None` when it names no table.
    #[must_use]
    pub fn parse(entry: &str) -> Option<Self> {
        let (database, table) = entry.split_once('.')?;
        if !is_ident(database) {
            return None;
        }
        match table {
            "*" => Some(Self {
                database: database.to_owned(),
                table: None,
            }),
            name if is_ident(name) => Some(Self {
                database: database.to_owned(),
                table: Some(name.to_owned()),
            }),
            _ => None,
        }
    }

    /// Whether this entry permits reading `table`.
    #[must_use]
    pub fn permits(&self, table: &TableRef) -> bool {
        self.database == table.database.as_str()
            && self
                .table
                .as_deref()
                .is_none_or(|t| t == table.table.as_str())
    }
}

/// A result limit in `1..=cap`. `0` has no value here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResultCap {
    value: u32,
    cap: u32,
}

/// Why a limit was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapError {
    /// `0` asked for.
    #[error("limit 0 is not allowed; legal: 1..={cap}")]
    Zero {
        /// The configured maximum.
        cap: u32,
    },
    /// More than the deployment allows.
    #[error("limit {got} exceeds the configured maximum {cap}; legal: 1..={cap}")]
    OverCap {
        /// What was asked for.
        got: u32,
        /// The configured maximum.
        cap: u32,
    },
    /// The deployment itself allows nothing.
    #[error("the configured maximum is 0, so no limit can be legal; raise maxResults")]
    NoRoom,
}

impl CapError {
    fn legal(&self) -> String {
        let cap = match self {
            Self::Zero { cap } | Self::OverCap { cap, .. } => *cap,
            Self::NoRoom => 0,
        };
        let mut s = String::new();
        let _ = write!(s, "1..={cap}");
        s
    }
}

impl ResultCap {
    /// `value` in `1..=cap`.
    pub const fn new(value: u32, cap: u32) -> Result<Self, CapError> {
        if cap == 0 {
            Err(CapError::NoRoom)
        } else if value == 0 {
            Err(CapError::Zero { cap })
        } else if value > cap {
            Err(CapError::OverCap { got: value, cap })
        } else {
            Ok(Self { value, cap })
        }
    }

    /// The limit.
    #[must_use]
    pub const fn get(&self) -> u32 {
        self.value
    }

    /// The maximum it was checked against.
    #[must_use]
    pub const fn cap(&self) -> u32 {
        self.cap
    }

    /// One row beyond the limit: the row the statement asks for that the
    /// caller did not, so `truncated` is a fact the wire carries (the probe
    /// row came back) rather than a guess. The client drops it before
    /// answering.
    #[must_use]
    pub const fn probe(&self) -> u64 {
        self.value as u64 + 1
    }
}

impl fmt::Display for ResultCap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

/// A time window ending now: `<n>s`, `<n>m`, `<n>h` or `<n>d`, at least one
/// second and at most the deployment's `maxWindowSeconds`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Window {
    seconds: u64,
}

/// Why a window was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WindowError {
    /// Not `<n><unit>`.
    #[error("window {got:?} is not <n>s, <n>m, <n>h or <n>d")]
    Malformed {
        /// What was passed.
        got: String,
    },
    /// Zero length.
    #[error("window {got:?} is empty; it must be at least 1s")]
    Zero {
        /// What was passed.
        got: String,
    },
    /// Longer than the deployment allows.
    #[error("window {got:?} is longer than the configured maximum of {max}s")]
    OverMax {
        /// What was passed.
        got: String,
        /// The configured maximum, in seconds.
        max: u64,
    },
}

impl WindowError {
    fn legal(&self) -> String {
        match self {
            Self::OverMax { max, .. } => {
                let mut s = String::new();
                let _ = write!(s, "{} up to {max}s", Window::LEGAL_FORM);
                s
            }
            Self::Malformed { .. } | Self::Zero { .. } => Window::LEGAL_FORM.to_owned(),
        }
    }
}

impl Window {
    /// The legal spellings, for a refusal's `legal` set.
    pub const LEGAL_FORM: &'static str = "<n>s | <n>m | <n>h | <n>d (for example 15m, 24h, 7d)";

    /// Parse `text`, bounded by `max_seconds`.
    pub fn parse(text: &str, max_seconds: u64) -> Result<Self, WindowError> {
        let malformed = || WindowError::Malformed {
            got: text.to_owned(),
        };
        let unit = text.chars().last().ok_or_else(malformed)?;
        let per = match unit {
            's' => 1_u64,
            'm' => 60,
            'h' => 3_600,
            'd' => 86_400,
            _ => return Err(malformed()),
        };
        let digits = &text[..text.len() - 1];
        if digits.is_empty() || digits.len() > 9 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(malformed());
        }
        let n: u64 = digits.parse().map_err(|_| malformed())?;
        let seconds = n.checked_mul(per).ok_or_else(malformed)?;
        if seconds == 0 {
            return Err(WindowError::Zero {
                got: text.to_owned(),
            });
        }
        if seconds > max_seconds {
            return Err(WindowError::OverMax {
                got: text.to_owned(),
                max: max_seconds,
            });
        }
        Ok(Self { seconds })
    }

    /// The length in seconds.
    #[must_use]
    pub const fn seconds(&self) -> u64 {
        self.seconds
    }
}

struct Since<'a>(&'a str, Window);

impl fmt::Display for Since<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} >= now() - INTERVAL {} SECOND",
            self.0, self.1.seconds
        )
    }
}

/// A comparison operator on a filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Op {
    /// `=`
    #[default]
    Eq,
    /// `!=`
    Ne,
    /// `>`
    Gt,
    /// `<`
    Lt,
    /// `>=`
    Ge,
    /// `<=`
    Le,
    /// `LIKE`
    Like,
}

impl Op {
    /// The legal spellings.
    pub const LEGAL: [&'static str; 7] = ["eq", "ne", "gt", "lt", "ge", "le", "like"];

    const fn sql(self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::Ne => "!=",
            Self::Gt => ">",
            Self::Lt => "<",
            Self::Ge => ">=",
            Self::Le => "<=",
            Self::Like => "LIKE",
        }
    }
}

impl TryFrom<&str> for Op {
    type Error = SqlError;

    fn try_from(spelling: &str) -> Result<Self, Self::Error> {
        match spelling {
            "eq" => Ok(Self::Eq),
            "ne" => Ok(Self::Ne),
            "gt" => Ok(Self::Gt),
            "lt" => Ok(Self::Lt),
            "ge" => Ok(Self::Ge),
            "le" => Ok(Self::Le),
            "like" => Ok(Self::Like),
            other => Err(SqlError::IllegalOp {
                got: other.to_owned(),
            }),
        }
    }
}

/// One typed filter: a validated column, an operator, and a value that is
/// always rendered as a literal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    column: ColumnName,
    op: Op,
    value: String,
}

impl Filter {
    /// Build a filter.
    #[must_use]
    pub fn new(column: ColumnName, op: Op, value: impl Into<String>) -> Self {
        Self {
            column,
            op,
            value: value.into(),
        }
    }
}

impl fmt::Display for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            Quoted(self.column.as_str()),
            self.op.sql(),
            Literal(&self.value)
        )
    }
}

/// Which server-side counters a [`Question::Metrics`] reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum MetricSource {
    /// `system.metrics`: current gauges.
    #[default]
    Metrics,
    /// `system.asynchronous_metrics`: periodically sampled values.
    Asynchronous,
    /// `system.events`: cumulative counters.
    Events,
}

impl MetricSource {
    /// The legal spellings.
    pub const LEGAL: [&'static str; 3] = ["metrics", "asynchronous", "events"];
}

impl TryFrom<&str> for MetricSource {
    type Error = SqlError;

    fn try_from(spelling: &str) -> Result<Self, Self::Error> {
        match spelling {
            "metrics" => Ok(Self::Metrics),
            "asynchronous" => Ok(Self::Asynchronous),
            "events" => Ok(Self::Events),
            other => Err(SqlError::IllegalMetricSource {
                got: other.to_owned(),
            }),
        }
    }
}

/// Which health question a `health` call asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HealthCheck {
    /// [`Question::Parts`].
    Parts,
    /// [`Question::Merges`].
    Merges,
    /// [`Question::Mutations`].
    Mutations,
    /// [`Question::Replication`].
    Replication,
}

impl HealthCheck {
    /// The legal spellings.
    pub const LEGAL: [&'static str; 4] = ["parts", "merges", "mutations", "replication"];

    /// The request this check names, from the loose fields a tool carries.
    /// `database` applies to `parts` only; `window` to `parts` and
    /// `mutations`.
    #[must_use]
    pub fn request(
        self,
        database: Option<String>,
        window: Option<String>,
        limit: Option<u32>,
    ) -> QuestionRequest {
        match self {
            Self::Parts => QuestionRequest::Parts {
                database,
                window,
                limit,
            },
            Self::Merges => QuestionRequest::Merges { limit },
            Self::Mutations => QuestionRequest::Mutations { window, limit },
            Self::Replication => QuestionRequest::Replication { limit },
        }
    }
}

impl TryFrom<&str> for HealthCheck {
    type Error = SqlError;

    fn try_from(spelling: &str) -> Result<Self, Self::Error> {
        match spelling {
            "parts" => Ok(Self::Parts),
            "merges" => Ok(Self::Merges),
            "mutations" => Ok(Self::Mutations),
            "replication" => Ok(Self::Replication),
            other => Err(SqlError::IllegalHealthCheck {
                got: other.to_owned(),
            }),
        }
    }
}

/// A validated, bounded read of one allowlisted table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Select {
    table: TableRef,
    columns: Vec<ColumnName>,
    filters: Vec<Filter>,
    time_column: ColumnName,
    window: Window,
    limit: ResultCap,
}

fn write_metrics(
    f: &mut fmt::Formatter<'_>,
    source: MetricSource,
    limit: ResultCap,
) -> fmt::Result {
    let (columns, table, key) = match source {
        MetricSource::Metrics => ("metric, value, description", "metrics", "metric"),
        MetricSource::Asynchronous => ("metric, value", "asynchronous_metrics", "metric"),
        MetricSource::Events => ("event AS metric, value, description", "events", "event"),
    };
    write!(
        f,
        "SELECT {columns} FROM system.{table} ORDER BY {key} LIMIT {}",
        limit.probe()
    )
}

impl fmt::Display for Select {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SELECT ")?;
        for (i, column) in self.columns.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{}", Quoted(column.as_str()))?;
        }
        write!(f, " FROM {} WHERE ", self.table)?;
        let time = Quoted(self.time_column.as_str()).to_string();
        write!(f, "{}", Since(&time, self.window))?;
        for filter in &self.filters {
            write!(f, " AND {filter}")?;
        }
        write!(f, " ORDER BY {time} DESC LIMIT {}", self.limit.probe())
    }
}

/// The closed set of questions. Closed: there is no variant that carries
/// SQL text, and none that writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Question {
    /// Who the credential is, and which server answered.
    WhoAmI,
    /// The databases this user can see.
    Databases {
        /// Row cap.
        limit: ResultCap,
    },
    /// The tables of one database.
    Tables {
        /// Which database.
        database: DatabaseName,
        /// Row cap.
        limit: ResultCap,
    },
    /// The columns of one table.
    Columns {
        /// Which table.
        table: TableRef,
        /// Row cap.
        limit: ResultCap,
    },
    /// Active-part sizes per table of one database.
    TableSizes {
        /// Which database.
        database: DatabaseName,
        /// Row cap.
        limit: ResultCap,
    },
    /// Active-part health per table, for parts modified inside the window.
    Parts {
        /// Restrict to one database.
        database: Option<DatabaseName>,
        /// Parts modified within this window.
        window: Window,
        /// Row cap.
        limit: ResultCap,
    },
    /// Merges running now.
    Merges {
        /// Row cap.
        limit: ResultCap,
    },
    /// Mutations created inside the window, and every unfinished one.
    Mutations {
        /// Mutations created within this window.
        window: Window,
        /// Row cap.
        limit: ResultCap,
    },
    /// Replica state. Guarded: `system.replicas` may hold nothing.
    Replication {
        /// Row cap.
        limit: ResultCap,
    },
    /// Queries running now, excluding this one.
    RunningQueries {
        /// Row cap.
        limit: ResultCap,
    },
    /// The slowest finished queries inside the window.
    SlowQueries {
        /// Queries finished within this window.
        window: Window,
        /// Row cap.
        limit: ResultCap,
    },
    /// Row policies.
    RowPolicies {
        /// Row cap.
        limit: ResultCap,
    },
    /// Grants.
    Grants {
        /// Row cap.
        limit: ResultCap,
    },
    /// Server counters.
    Metrics {
        /// Which counters.
        source: MetricSource,
        /// Row cap.
        limit: ResultCap,
    },
    /// A bounded read of one allowlisted table.
    Select(Select),
}

impl Question {
    /// What an `empty` answer is about.
    #[must_use]
    pub const fn subject(&self) -> &'static str {
        match self {
            Self::WhoAmI => "identity rows",
            Self::Databases { .. } => "databases visible to this user",
            Self::Tables { .. } => "tables in that database",
            Self::Columns { .. } => "columns of that table",
            Self::TableSizes { .. } => "active parts in that database",
            Self::Parts { .. } => "active parts modified in that window",
            Self::Merges { .. } => "merges running now",
            Self::Mutations { .. } => "mutations in that window or unfinished",
            Self::Replication { .. } => {
                "replicated tables (system.replicas holds no rows or is absent on this server)"
            }
            Self::RunningQueries { .. } => "other queries running now",
            Self::SlowQueries { .. } => "finished queries in that window",
            Self::RowPolicies { .. } => "row policies visible to this user",
            Self::Grants { .. } => "grants visible to this user",
            Self::Metrics { .. } => "counters from that source",
            Self::Select(_) => "rows matching the filters in that window",
        }
    }

    /// Whether the source may legitimately be absent on a server, which the
    /// client answers as `empty` instead of refusing.
    #[must_use]
    pub const fn source_may_be_absent(&self) -> bool {
        matches!(self, Self::Replication { .. })
    }

    /// The row cap, `None` for the one-row identity question.
    #[must_use]
    pub const fn limit(&self) -> Option<ResultCap> {
        match self {
            Self::WhoAmI => None,
            Self::Databases { limit }
            | Self::Tables { limit, .. }
            | Self::Columns { limit, .. }
            | Self::TableSizes { limit, .. }
            | Self::Parts { limit, .. }
            | Self::Merges { limit }
            | Self::Mutations { limit, .. }
            | Self::Replication { limit }
            | Self::RunningQueries { limit }
            | Self::SlowQueries { limit, .. }
            | Self::RowPolicies { limit }
            | Self::Grants { limit }
            | Self::Metrics { limit, .. } => Some(*limit),
            Self::Select(s) => Some(s.limit),
        }
    }
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WhoAmI => f.write_str(
                "SELECT currentUser() AS user, version() AS version, uptime() AS uptime_seconds LIMIT 1",
            ),
            Self::Databases { limit } => write!(
                f,
                "SELECT name, engine FROM system.databases ORDER BY name LIMIT {}",
                limit.probe()
            ),
            Self::Tables { database, limit } => write!(
                f,
                "SELECT name, engine, total_rows, total_bytes FROM system.tables WHERE database = {} ORDER BY name LIMIT {}",
                Literal(database.as_str()),
                limit.probe()
            ),
            Self::Columns { table, limit } => write!(
                f,
                "SELECT name, type, default_kind, is_in_primary_key, is_in_sorting_key FROM system.columns WHERE database = {} AND table = {} ORDER BY position LIMIT {}",
                Literal(table.database.as_str()),
                Literal(table.table.as_str()),
                limit.probe()
            ),
            Self::TableSizes { database, limit } => write!(
                f,
                "SELECT table, sum(rows) AS rows, sum(bytes_on_disk) AS bytes_on_disk, sum(data_compressed_bytes) AS compressed_bytes, sum(data_uncompressed_bytes) AS uncompressed_bytes, count() AS parts FROM system.parts WHERE active AND database = {} GROUP BY table ORDER BY bytes_on_disk DESC LIMIT {}",
                Literal(database.as_str()),
                limit.probe()
            ),
            Self::Parts {
                database,
                window,
                limit,
            } => {
                f.write_str(
                    "SELECT database, table, count() AS active_parts, uniqExact(partition) AS partitions, max(modification_time) AS last_modified FROM system.parts WHERE active AND ",
                )?;
                write!(f, "{}", Since("modification_time", *window))?;
                if let Some(database) = database {
                    write!(f, " AND database = {}", Literal(database.as_str()))?;
                }
                write!(
                    f,
                    " GROUP BY database, table ORDER BY active_parts DESC LIMIT {}",
                    limit.probe()
                )
            }
            Self::Merges { limit } => write!(
                f,
                "SELECT database, table, elapsed, progress, num_parts, result_part_name, is_mutation, total_size_bytes_compressed FROM system.merges ORDER BY elapsed DESC LIMIT {}",
                limit.probe()
            ),
            Self::Mutations { window, limit } => write!(
                f,
                "SELECT database, table, mutation_id, command, create_time, parts_to_do, is_done, latest_fail_reason FROM system.mutations WHERE ({} OR is_done = 0) ORDER BY create_time DESC LIMIT {}",
                Since("create_time", *window),
                limit.probe()
            ),
            Self::Replication { limit } => write!(
                f,
                "SELECT database, table, is_leader, is_readonly, is_session_expired, absolute_delay, queue_size, inserts_in_queue, merges_in_queue FROM system.replicas ORDER BY absolute_delay DESC LIMIT {}",
                limit.probe()
            ),
            Self::RunningQueries { limit } => write!(
                f,
                "SELECT query_id, user, elapsed, read_rows, memory_usage, substring(query, 1, 512) AS query FROM system.processes WHERE query_id != queryID() ORDER BY elapsed DESC LIMIT {}",
                limit.probe()
            ),
            Self::SlowQueries { window, limit } => write!(
                f,
                "SELECT event_time, query_duration_ms, user, type, read_rows, read_bytes, memory_usage, exception_code, substring(query, 1, 512) AS query FROM system.query_log WHERE type != 'QueryStart' AND is_initial_query AND {} ORDER BY query_duration_ms DESC LIMIT {}",
                Since("event_time", *window),
                limit.probe()
            ),
            Self::RowPolicies { limit } => write!(
                f,
                "SELECT name, short_name, database, table, select_filter, is_restrictive FROM system.row_policies ORDER BY name LIMIT {}",
                limit.probe()
            ),
            Self::Grants { limit } => write!(
                f,
                "SELECT user_name, role_name, access_type, database, table, column, is_partial_revoke, grant_option FROM system.grants ORDER BY user_name, role_name, access_type LIMIT {}",
                limit.probe()
            ),
            Self::Metrics { source, limit } => write_metrics(f, *source, *limit),
            Self::Select(s) => write!(f, "{s}"),
        }
    }
}

/// A `select` as plain strings, before validation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SelectRequest {
    /// The database.
    pub database: String,
    /// The table.
    pub table: String,
    /// The columns to read.
    pub columns: Vec<String>,
    /// Filters, all of which must hold.
    pub filters: Vec<FilterRequest>,
    /// REQUIRED: the column the window applies to, and the sort key.
    pub time_column: Option<String>,
    /// REQUIRED: the window, `<n>s|m|h|d`.
    pub window: Option<String>,
    /// REQUIRED: the row cap.
    pub limit: Option<u32>,
}

/// A filter as plain strings, before validation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FilterRequest {
    /// The column.
    pub column: String,
    /// One of [`Op::LEGAL`]; `eq` when absent.
    pub op: Option<String>,
    /// The value, rendered as a literal.
    pub value: String,
}

/// A question as plain strings and numbers, before validation. `limit` and
/// `window` are `Option` so that leaving one out is a typed refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuestionRequest {
    /// See [`Question::WhoAmI`].
    WhoAmI,
    /// See [`Question::Databases`].
    Databases {
        /// REQUIRED row cap.
        limit: Option<u32>,
    },
    /// See [`Question::Tables`].
    Tables {
        /// The database.
        database: String,
        /// REQUIRED row cap.
        limit: Option<u32>,
    },
    /// See [`Question::Columns`].
    Columns {
        /// The database.
        database: String,
        /// The table.
        table: String,
        /// REQUIRED row cap.
        limit: Option<u32>,
    },
    /// See [`Question::TableSizes`].
    TableSizes {
        /// The database.
        database: String,
        /// REQUIRED row cap.
        limit: Option<u32>,
    },
    /// See [`Question::Parts`].
    Parts {
        /// Restrict to one database.
        database: Option<String>,
        /// REQUIRED window.
        window: Option<String>,
        /// REQUIRED row cap.
        limit: Option<u32>,
    },
    /// See [`Question::Merges`].
    Merges {
        /// REQUIRED row cap.
        limit: Option<u32>,
    },
    /// See [`Question::Mutations`].
    Mutations {
        /// REQUIRED window.
        window: Option<String>,
        /// REQUIRED row cap.
        limit: Option<u32>,
    },
    /// See [`Question::Replication`].
    Replication {
        /// REQUIRED row cap.
        limit: Option<u32>,
    },
    /// See [`Question::RunningQueries`].
    RunningQueries {
        /// REQUIRED row cap.
        limit: Option<u32>,
    },
    /// See [`Question::SlowQueries`].
    SlowQueries {
        /// REQUIRED window.
        window: Option<String>,
        /// REQUIRED row cap.
        limit: Option<u32>,
    },
    /// See [`Question::RowPolicies`].
    RowPolicies {
        /// REQUIRED row cap.
        limit: Option<u32>,
    },
    /// See [`Question::Grants`].
    Grants {
        /// REQUIRED row cap.
        limit: Option<u32>,
    },
    /// See [`Question::Metrics`].
    Metrics {
        /// One of [`MetricSource::LEGAL`]; `metrics` when absent.
        source: Option<String>,
        /// REQUIRED row cap.
        limit: Option<u32>,
    },
    /// See [`Question::Select`].
    Select(SelectRequest),
}

fn cap(limit: Option<u32>, bounds: &Bounds) -> Result<ResultCap, SqlError> {
    let value = limit.ok_or(SqlError::Missing { field: "limit" })?;
    Ok(ResultCap::new(value, bounds.max_results)?)
}

fn window(text: Option<&str>, bounds: &Bounds) -> Result<Window, SqlError> {
    let text = text.ok_or(SqlError::Missing { field: "window" })?;
    Ok(Window::parse(text, bounds.max_window_seconds)?)
}

impl Select {
    fn build(req: &SelectRequest, bounds: &Bounds) -> Result<Self, SqlError> {
        let table = TableRef::parse(&req.database, &req.table)?;
        let allowed = bounds
            .select_allow
            .iter()
            .filter_map(|entry| AllowEntry::parse(entry))
            .any(|entry| entry.permits(&table));
        if !allowed {
            let mut name = String::new();
            let _ = write!(name, "{}.{}", table.database, table.table);
            return Err(SqlError::TableNotAllowed {
                table: name,
                allowed: bounds.select_allow.clone(),
            });
        }
        if req.columns.is_empty() {
            return Err(SqlError::Missing { field: "columns" });
        }
        Bounds::check(SelectBound::Columns, req.columns.len(), bounds.max_columns)?;
        Bounds::check(SelectBound::Filters, req.filters.len(), bounds.max_filters)?;
        let columns = req
            .columns
            .iter()
            .map(|c| ColumnName::try_from(c.as_str()))
            .collect::<Result<Vec<_>, _>>()?;
        let time_column =
            ColumnName::try_from(req.time_column.as_deref().ok_or(SqlError::Missing {
                field: "time_column",
            })?)?;
        let mut filters = Vec::with_capacity(req.filters.len());
        for filter in &req.filters {
            Bounds::check(
                SelectBound::ValueBytes,
                filter.value.len(),
                bounds.max_value_bytes,
            )?;
            let op = filter
                .op
                .as_deref()
                .map_or(Ok(Op::default()), Op::try_from)?;
            filters.push(Filter::new(
                ColumnName::try_from(filter.column.as_str())?,
                op,
                filter.value.as_str(),
            ));
        }
        Ok(Self {
            table,
            columns,
            filters,
            time_column,
            window: window(req.window.as_deref(), bounds)?,
            limit: cap(req.limit, bounds)?,
        })
    }
}

impl Question {
    /// Validate a request against the deployment's bounds.
    pub fn build(req: &QuestionRequest, bounds: &Bounds) -> Result<Self, SqlError> {
        Ok(match req {
            QuestionRequest::WhoAmI => Self::WhoAmI,
            QuestionRequest::Databases { limit } => Self::Databases {
                limit: cap(*limit, bounds)?,
            },
            QuestionRequest::Tables { database, limit } => Self::Tables {
                database: DatabaseName::try_from(database.as_str())?,
                limit: cap(*limit, bounds)?,
            },
            QuestionRequest::Columns {
                database,
                table,
                limit,
            } => Self::Columns {
                table: TableRef::parse(database, table)?,
                limit: cap(*limit, bounds)?,
            },
            QuestionRequest::TableSizes { database, limit } => Self::TableSizes {
                database: DatabaseName::try_from(database.as_str())?,
                limit: cap(*limit, bounds)?,
            },
            QuestionRequest::Parts {
                database,
                window: w,
                limit,
            } => Self::Parts {
                database: database
                    .as_deref()
                    .map(DatabaseName::try_from)
                    .transpose()?,
                window: window(w.as_deref(), bounds)?,
                limit: cap(*limit, bounds)?,
            },
            QuestionRequest::Merges { limit } => Self::Merges {
                limit: cap(*limit, bounds)?,
            },
            QuestionRequest::Mutations { window: w, limit } => Self::Mutations {
                window: window(w.as_deref(), bounds)?,
                limit: cap(*limit, bounds)?,
            },
            QuestionRequest::Replication { limit } => Self::Replication {
                limit: cap(*limit, bounds)?,
            },
            QuestionRequest::RunningQueries { limit } => Self::RunningQueries {
                limit: cap(*limit, bounds)?,
            },
            QuestionRequest::SlowQueries { window: w, limit } => Self::SlowQueries {
                window: window(w.as_deref(), bounds)?,
                limit: cap(*limit, bounds)?,
            },
            QuestionRequest::RowPolicies { limit } => Self::RowPolicies {
                limit: cap(*limit, bounds)?,
            },
            QuestionRequest::Grants { limit } => Self::Grants {
                limit: cap(*limit, bounds)?,
            },
            QuestionRequest::Metrics { source, limit } => Self::Metrics {
                source: source
                    .as_deref()
                    .map_or(Ok(MetricSource::default()), MetricSource::try_from)?,
                limit: cap(*limit, bounds)?,
            },
            QuestionRequest::Select(s) => Self::Select(Select::build(s, bounds)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shikumi::TieredConfig as _;

    fn bounds() -> Bounds {
        crate::config::LanternaConfig::prescribed_default().bounds()
    }

    fn build(req: &QuestionRequest) -> Result<Question, SqlError> {
        Question::build(req, &bounds())
    }

    fn sql(req: &QuestionRequest) -> String {
        build(req).expect("valid").to_string()
    }

    fn select(value: &str) -> QuestionRequest {
        QuestionRequest::Select(SelectRequest {
            database: "system".into(),
            table: "query_log".into(),
            columns: vec!["query".into(), "event_time".into()],
            filters: vec![FilterRequest {
                column: "query".into(),
                op: Some("like".into()),
                value: value.into(),
            }],
            time_column: Some("event_time".into()),
            window: Some("1h".into()),
            limit: Some(10),
        })
    }

    fn strip_literals(sql: &str) -> String {
        let mut out = String::new();
        let mut chars = sql.chars();
        while let Some(c) = chars.next() {
            if c == '\'' {
                out.push_str("''");
                loop {
                    match chars.next() {
                        Some('\\') => {
                            chars.next();
                        }
                        Some('\'') | None => break,
                        Some(_) => {}
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn a_window_parses_every_unit_and_refuses_everything_else() {
        assert_eq!(Window::parse("90s", 1_000).expect("s").seconds(), 90);
        assert_eq!(Window::parse("15m", 1_000_000).expect("m").seconds(), 900);
        assert_eq!(
            Window::parse("24h", 1_000_000).expect("h").seconds(),
            86_400
        );
        assert_eq!(
            Window::parse("7d", 1_000_000).expect("d").seconds(),
            604_800
        );
        for bad in [
            "",
            "m",
            "15",
            "15x",
            "-5m",
            "1.5h",
            "0 5m",
            "5 m",
            "+5m",
            "1e3s",
            "9999999999d",
        ] {
            assert!(
                matches!(
                    Window::parse(bad, u64::MAX),
                    Err(WindowError::Malformed { .. })
                ),
                "{bad:?}"
            );
        }
        assert!(matches!(
            Window::parse("0m", 100),
            Err(WindowError::Zero { .. })
        ));
        assert!(matches!(
            Window::parse("2m", 100),
            Err(WindowError::OverMax { max: 100, .. })
        ));
    }

    #[test]
    fn a_result_cap_is_one_to_cap_and_asks_for_one_probe_row_more() {
        assert_eq!(ResultCap::new(5, 500).expect("ok").probe(), 6);
        assert_eq!(ResultCap::new(500, 500).expect("ok").probe(), 501);
        assert_eq!(ResultCap::new(0, 500), Err(CapError::Zero { cap: 500 }));
        assert_eq!(
            ResultCap::new(501, 500),
            Err(CapError::OverCap { got: 501, cap: 500 })
        );
        assert_eq!(ResultCap::new(1, 0), Err(CapError::NoRoom));
    }

    #[test]
    fn identifiers_have_one_grammar() {
        for good in ["system", "_t", "a1_b", "Events"] {
            assert!(DatabaseName::try_from(good).is_ok(), "{good}");
        }
        let long = "x".repeat(129);
        for bad in [
            "", "1a", "a b", "a.b", "a`b", "a'b", "a-b", "a;b", "é", &long,
        ] {
            assert!(
                matches!(TableName::try_from(bad), Err(SqlError::IllegalTable { .. })),
                "{bad:?}"
            );
        }
        assert_eq!(
            SqlError::IllegalColumn { got: "x y".into() }.legal(),
            [IDENT_GRAMMAR]
        );
    }

    #[test]
    fn every_row_question_refuses_a_missing_limit_before_anything_is_sent() {
        let none = None;
        let d = || "d".to_owned();
        let one_hour = || Some("1h".to_owned());
        let reqs = [
            QuestionRequest::Databases { limit: none },
            QuestionRequest::Tables {
                database: d(),
                limit: none,
            },
            QuestionRequest::Columns {
                database: d(),
                table: "t".into(),
                limit: none,
            },
            QuestionRequest::TableSizes {
                database: d(),
                limit: none,
            },
            QuestionRequest::Parts {
                database: None,
                window: one_hour(),
                limit: none,
            },
            QuestionRequest::Merges { limit: none },
            QuestionRequest::Mutations {
                window: one_hour(),
                limit: none,
            },
            QuestionRequest::Replication { limit: none },
            QuestionRequest::RunningQueries { limit: none },
            QuestionRequest::SlowQueries {
                window: one_hour(),
                limit: none,
            },
            QuestionRequest::RowPolicies { limit: none },
            QuestionRequest::Grants { limit: none },
            QuestionRequest::Metrics {
                source: None,
                limit: none,
            },
        ];
        for req in &reqs {
            assert_eq!(
                build(req),
                Err(SqlError::Missing { field: "limit" }),
                "{req:?}"
            );
        }
        let mut s = SelectRequest {
            database: "system".into(),
            table: "query_log".into(),
            columns: vec!["query".into()],
            time_column: Some("event_time".into()),
            window: one_hour(),
            ..SelectRequest::default()
        };
        assert_eq!(
            build(&QuestionRequest::Select(s.clone())),
            Err(SqlError::Missing { field: "limit" })
        );
        s.limit = Some(1);
        s.window = None;
        assert_eq!(
            build(&QuestionRequest::Select(s)),
            Err(SqlError::Missing { field: "window" })
        );
    }

    #[test]
    fn every_time_bearing_question_refuses_a_missing_window() {
        let limit = Some(5);
        for req in [
            QuestionRequest::Parts {
                database: None,
                window: None,
                limit,
            },
            QuestionRequest::Mutations {
                window: None,
                limit,
            },
            QuestionRequest::SlowQueries {
                window: None,
                limit,
            },
        ] {
            assert_eq!(
                build(&req),
                Err(SqlError::Missing { field: "window" }),
                "{req:?}"
            );
        }
        let missing = SqlError::Missing { field: "window" };
        assert_eq!(missing.legal(), [Window::LEGAL_FORM]);
        assert_eq!(
            SqlError::Missing { field: "limit" }.legal(),
            ["limit: 1..=maxResults"]
        );
    }

    #[test]
    fn a_limit_or_window_over_the_deployment_bound_is_refused() {
        assert!(matches!(
            build(&QuestionRequest::Databases { limit: Some(501) }),
            Err(SqlError::Limit(CapError::OverCap { got: 501, cap: 500 }))
        ));
        assert!(matches!(
            build(&QuestionRequest::Databases { limit: Some(0) }),
            Err(SqlError::Limit(CapError::Zero { .. }))
        ));
        assert!(matches!(
            build(&QuestionRequest::SlowQueries {
                window: Some("8d".into()),
                limit: Some(1)
            }),
            Err(SqlError::Window(WindowError::OverMax { .. }))
        ));
    }

    #[test]
    fn each_question_renders_its_fixed_template_with_the_probe_row() {
        assert_eq!(
            sql(&QuestionRequest::Databases { limit: Some(3) }),
            "SELECT name, engine FROM system.databases ORDER BY name LIMIT 4"
        );
        assert_eq!(
            sql(&QuestionRequest::Columns {
                database: "alpha".into(),
                table: "events".into(),
                limit: Some(9)
            }),
            "SELECT name, type, default_kind, is_in_primary_key, is_in_sorting_key FROM system.columns WHERE database = 'alpha' AND table = 'events' ORDER BY position LIMIT 10"
        );
        assert_eq!(
            sql(&QuestionRequest::SlowQueries {
                window: Some("15m".into()),
                limit: Some(2)
            }),
            "SELECT event_time, query_duration_ms, user, type, read_rows, read_bytes, memory_usage, exception_code, substring(query, 1, 512) AS query FROM system.query_log WHERE type != 'QueryStart' AND is_initial_query AND event_time >= now() - INTERVAL 900 SECOND ORDER BY query_duration_ms DESC LIMIT 3"
        );
        assert_eq!(
            sql(&QuestionRequest::Parts {
                database: Some("alpha".into()),
                window: Some("1h".into()),
                limit: Some(4)
            }),
            "SELECT database, table, count() AS active_parts, uniqExact(partition) AS partitions, max(modification_time) AS last_modified FROM system.parts WHERE active AND modification_time >= now() - INTERVAL 3600 SECOND AND database = 'alpha' GROUP BY database, table ORDER BY active_parts DESC LIMIT 5"
        );
        assert_eq!(
            sql(&QuestionRequest::Metrics {
                source: Some("events".into()),
                limit: Some(1)
            }),
            "SELECT event AS metric, value, description FROM system.events ORDER BY event LIMIT 2"
        );
        assert_eq!(
            sql(&select("%x%")),
            "SELECT `query`, `event_time` FROM `system`.`query_log` WHERE `event_time` >= now() - INTERVAL 3600 SECOND AND `query` LIKE '%x%' ORDER BY `event_time` DESC LIMIT 11"
        );
    }

    #[test]
    fn every_question_renders_a_single_select_with_a_limit_and_no_terminator() {
        let l = Some(5);
        let w = Some("1h".to_owned());
        let reqs = [
            QuestionRequest::WhoAmI,
            QuestionRequest::Databases { limit: l },
            QuestionRequest::Tables {
                database: "d".into(),
                limit: l,
            },
            QuestionRequest::Columns {
                database: "d".into(),
                table: "t".into(),
                limit: l,
            },
            QuestionRequest::TableSizes {
                database: "d".into(),
                limit: l,
            },
            QuestionRequest::Parts {
                database: None,
                window: w.clone(),
                limit: l,
            },
            QuestionRequest::Merges { limit: l },
            QuestionRequest::Mutations {
                window: w.clone(),
                limit: l,
            },
            QuestionRequest::Replication { limit: l },
            QuestionRequest::RunningQueries { limit: l },
            QuestionRequest::SlowQueries {
                window: w,
                limit: l,
            },
            QuestionRequest::RowPolicies { limit: l },
            QuestionRequest::Grants { limit: l },
            QuestionRequest::Metrics {
                source: None,
                limit: l,
            },
            select("v"),
        ];
        for req in &reqs {
            let text = sql(req);
            assert!(text.starts_with("SELECT "), "{text}");
            assert!(text.contains(" LIMIT "), "{text}");
            assert!(!text.contains(';'), "{text}");
            assert_eq!(text.matches("SELECT").count(), 1, "{text}");
            let outside = strip_literals(&text);
            for verb in [
                "INSERT", "ALTER", "DROP", "CREATE", "DELETE", "TRUNCATE", "SYSTEM ", "GRANT ",
                "KILL", "OPTIMIZE", "ATTACH", "DETACH", "RENAME", "UNION",
            ] {
                assert!(!outside.contains(verb), "{verb} in {text}");
            }
        }
    }

    #[test]
    fn hostile_values_render_as_inert_quoted_literals() {
        let hostile = [
            "'; DROP TABLE t; --",
            "x' UNION SELECT password FROM system.users --",
            "back\\slash\\'",
            "\\",
            "ends with backslash\\",
            "multi\nline\r\ttab\0nul",
            "/* c */ ' OR '1'='1",
            "`; SYSTEM SHUTDOWN; `",
            "\u{7}bell\u{1b}[31m",
            "{param:String} $$ heredoc $$",
        ];
        for value in hostile {
            let text = sql(&select(value));
            let outside = strip_literals(&text);
            assert_eq!(
                outside,
                "SELECT `query`, `event_time` FROM `system`.`query_log` WHERE `event_time` >= now() - INTERVAL 3600 SECOND AND `query` LIKE '' ORDER BY `event_time` DESC LIMIT 11",
                "{value:?} leaked out of its literal: {text}"
            );
            assert!(!text.contains('\n') && !text.contains('\0') && !text.contains('\r'));
        }
        assert_eq!(Literal("a'b\\c").to_string(), "'a\\'b\\\\c'");
        assert_eq!(Literal("a\nb\0c\u{7}").to_string(), "'a\\nb\\0c\\x07'");
        assert_eq!(Literal("é").to_string(), "'é'");
        assert_eq!(
            Literal("'; DROP TABLE t; --").to_string(),
            "'\\'; DROP TABLE t; --'"
        );
    }

    #[test]
    fn a_hostile_identifier_never_reaches_the_renderer() {
        for bad in ["t`; DROP", "t' OR 1=1", "d.t", "t--", "t/*", "t;"] {
            assert!(
                matches!(
                    build(&QuestionRequest::Columns {
                        database: "d".into(),
                        table: bad.into(),
                        limit: Some(1)
                    }),
                    Err(SqlError::IllegalTable { .. })
                ),
                "{bad}"
            );
            assert!(matches!(
                build(&QuestionRequest::Tables {
                    database: bad.into(),
                    limit: Some(1)
                }),
                Err(SqlError::IllegalDatabase { .. })
            ));
        }
        let mut req = SelectRequest {
            database: "system".into(),
            table: "query_log".into(),
            columns: vec!["a; DROP".into()],
            time_column: Some("event_time".into()),
            window: Some("1h".into()),
            limit: Some(1),
            ..SelectRequest::default()
        };
        assert!(matches!(
            build(&QuestionRequest::Select(req.clone())),
            Err(SqlError::IllegalColumn { .. })
        ));
        req.columns = vec!["a".into()];
        req.filters = vec![FilterRequest {
            column: "a`b".into(),
            op: None,
            value: "v".into(),
        }];
        assert!(matches!(
            build(&QuestionRequest::Select(req)),
            Err(SqlError::IllegalColumn { .. })
        ));
    }

    #[test]
    fn select_is_bounded_and_allowlisted() {
        let mut req = SelectRequest {
            database: "analytics".into(),
            table: "events".into(),
            columns: vec!["a".into()],
            time_column: Some("t".into()),
            window: Some("1h".into()),
            limit: Some(1),
            ..SelectRequest::default()
        };
        let err = build(&QuestionRequest::Select(req.clone())).expect_err("not allowed");
        assert_eq!(
            err,
            SqlError::TableNotAllowed {
                table: "analytics.events".into(),
                allowed: vec!["system.*".into()]
            }
        );
        assert_eq!(err.legal(), ["system.*"]);

        let mut b = bounds();
        b.select_allow = vec!["analytics.events".into()];
        assert!(Question::build(&QuestionRequest::Select(req.clone()), &b).is_ok());
        req.table = "other".into();
        assert!(matches!(
            Question::build(&QuestionRequest::Select(req.clone()), &b),
            Err(SqlError::TableNotAllowed { .. })
        ));

        b.select_allow = Vec::new();
        assert!(matches!(
            Question::build(&QuestionRequest::Select(req.clone()), &b),
            Err(SqlError::TableNotAllowed { .. })
        ));

        b.select_allow = vec!["analytics.*".into()];
        req.table = "events".into();
        req.columns = (0..33).map(|i| format!("c{i}")).collect();
        assert!(matches!(
            Question::build(&QuestionRequest::Select(req.clone()), &b),
            Err(SqlError::OverBound {
                bound: SelectBound::Columns,
                got: 33,
                max: 32
            })
        ));
        req.columns = vec!["a".into()];
        req.filters = (0..17)
            .map(|i| FilterRequest {
                column: format!("c{i}"),
                op: None,
                value: "v".into(),
            })
            .collect();
        assert!(matches!(
            Question::build(&QuestionRequest::Select(req.clone()), &b),
            Err(SqlError::OverBound {
                bound: SelectBound::Filters,
                ..
            })
        ));
        req.filters = vec![FilterRequest {
            column: "c".into(),
            op: None,
            value: "x".repeat(1025),
        }];
        assert!(matches!(
            Question::build(&QuestionRequest::Select(req.clone()), &b),
            Err(SqlError::OverBound {
                bound: SelectBound::ValueBytes,
                ..
            })
        ));
        req.filters = Vec::new();
        req.columns = Vec::new();
        assert_eq!(
            Question::build(&QuestionRequest::Select(req), &b),
            Err(SqlError::Missing { field: "columns" })
        );
    }

    #[test]
    fn operators_and_metric_sources_have_closed_spellings() {
        for (text, rendered) in [
            ("eq", "="),
            ("ne", "!="),
            ("gt", ">"),
            ("lt", "<"),
            ("ge", ">="),
            ("le", "<="),
            ("like", "LIKE"),
        ] {
            assert_eq!(Op::try_from(text).expect("legal").sql(), rendered);
        }
        assert_eq!(
            Op::try_from("=; x"),
            Err(SqlError::IllegalOp { got: "=; x".into() })
        );
        assert_eq!(SqlError::IllegalOp { got: "x".into() }.legal().len(), 7);
        assert!(MetricSource::try_from("nope").is_err());
        assert_eq!(MetricSource::try_from("events"), Ok(MetricSource::Events));
    }

    #[test]
    fn the_allowlist_grammar_accepts_exact_and_wildcard_entries() {
        let t = TableRef::parse("system", "parts").expect("valid");
        assert!(
            AllowEntry::parse("system.parts")
                .expect("exact")
                .permits(&t)
        );
        assert!(AllowEntry::parse("system.*").expect("wild").permits(&t));
        assert!(
            !AllowEntry::parse("system.other")
                .expect("exact")
                .permits(&t)
        );
        assert!(!AllowEntry::parse("other.*").expect("wild").permits(&t));
        for bad in ["system", "a.b.c", ".x", "x.", "a b.c", "a.*b", "*.x"] {
            assert!(AllowEntry::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn health_checks_map_to_their_requests() {
        let l = Some(3);
        let w = Some("1h".to_owned());
        assert!(matches!(
            HealthCheck::try_from("parts")
                .expect("legal")
                .request(Some("d".into()), w.clone(), l),
            QuestionRequest::Parts {
                database: Some(_),
                window: Some(_),
                limit: Some(3)
            }
        ));
        assert_eq!(
            HealthCheck::try_from("merges")
                .expect("legal")
                .request(None, None, l),
            QuestionRequest::Merges { limit: l }
        );
        assert_eq!(
            HealthCheck::try_from("mutations")
                .expect("legal")
                .request(None, w.clone(), l),
            QuestionRequest::Mutations {
                window: w,
                limit: l
            }
        );
        assert_eq!(
            HealthCheck::try_from("replication")
                .expect("legal")
                .request(None, None, l),
            QuestionRequest::Replication { limit: l }
        );
        let err = HealthCheck::try_from("vacuum").expect_err("refused");
        assert_eq!(err.legal().len(), 4);
    }

    #[test]
    fn only_the_guarded_question_may_find_its_source_absent() {
        let limit = ResultCap::new(1, 5).expect("cap");
        assert!(Question::Replication { limit }.source_may_be_absent());
        assert!(!Question::Merges { limit }.source_may_be_absent());
        assert_eq!(Question::WhoAmI.limit(), None);
        assert_eq!(Question::Merges { limit }.limit(), Some(limit));
    }
}
