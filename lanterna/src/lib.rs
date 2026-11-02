//! lanterna (*lantern*) — a typed, observe-only ClickHouse client whose every
//! answer says which of four things happened.
//!
//! # What it is
//!
//! A client over ClickHouse's HTTP(S) interface (8443 on ClickHouse Cloud)
//! that can only ask a closed set of read questions: who am I, which
//! databases, tables and columns exist, how big the tables are, whether the
//! parts, merges, mutations and replicas are healthy, what is running and
//! what was slow, which row policies and grants exist, the server's counters,
//! and one bounded `select` over an allowlisted table.
//!
//! # Observe-only, three times over
//!
//! * **There is no write path.** [`route::Route`] has one arm, a `POST /`
//!   whose body is only ever the text rendered from a [`sql::Question`], and
//!   [`sql::Question`] has no variant that carries SQL or writes. A call that
//!   would change ClickHouse state is `E0599`, not a runtime refusal.
//! * **There is no raw-SQL entry point.** `impl Display for Question` is the
//!   only place statement text is assembled; identifiers have one grammar and
//!   values are always escaped literals.
//! * **The server enforces it too.** [`settings::Settings`] puts `readonly=1`
//!   and the execution and result bounds on every request.
//!
//! # The shape
//!
//! | module | owns |
//! |---|---|
//! | [`transport`] | the seam: one trait, the `reqwest` impl, the scripted mock (feature `mock`) |
//! | [`route`] | the closed route enum, its one `Display` |
//! | [`settings`] | the per-request `readonly` / `max_*` bounds, rendered once |
//! | [`auth`] | credential files read at call time into zeroizing memory |
//! | [`sql`] | the closed `Question` enum, the validated types, the ONE renderer |
//! | [`exception`] | what a ClickHouse exception code means |
//! | [`config`] | `LanternaConfig`: shikumi tiers + a `(deflanterna …)` face on one struct |
//! | [`outcome`] | `Outcome` (found / empty / refused / blind) and the typed causes |
//! | [`client`] | `ClickHouseClient<T: Transport>`: validate, send, classify |
//! | [`targets`] | `Targets<T>`: several clients keyed by label |
//!
//! # Four outcomes, never collapsed
//!
//! The reader of these answers is a language model with no peripheral
//! vision. An empty table is `empty` (a finding), a question over a bound is
//! `refused` (retry differently; the legal forms are listed), and a host that
//! does not resolve is `blind` (nobody knows; conclude nothing). Every HTTP
//! status is classified by [`handan::judge`].
//!
//! # Typed emission
//!
//! There is no `format!` macro call outside the test modules of this crate.
//! Every string an agent reads is a `thiserror` message, a `Display` impl, a
//! `tracing` event, or serde output.

#![forbid(unsafe_code)]

pub mod auth;
pub mod client;
pub mod config;
pub mod exception;
pub mod outcome;
pub mod route;
pub mod settings;
pub mod sql;
pub mod targets;
pub mod tls;
pub mod transport;

pub use auth::{Credential, LEGAL_CREDENTIAL_FORMS};
pub use client::{BoundsInForce, ClickHouseClient, Column, Identity, Rows, WhoAmI};
pub use config::{ConfigError, LanternaConfig};
pub use outcome::{LEGAL_QUESTIONS, Outcome};
pub use route::Route;
pub use settings::Settings;
pub use sql::{
    Bounds, FilterRequest, HealthCheck, MetricSource, Question, QuestionRequest, ResultCap,
    SelectRequest, SqlError, Window,
};
pub use targets::{Targets, TargetsError};
pub use tls::TlsPosture;
#[cfg(any(test, feature = "mock"))]
pub use transport::MockTransport;
pub use transport::{ConnectEvidence, ReqwestTransport, Transport};
