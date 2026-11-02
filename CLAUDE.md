# lanterna — typed observe-only ClickHouse client + MCP server

pending-extract: transport-seam shared with holofote

<!-- Non-applicable ★★ directive waivers (lanterna is a stdio binary that READS
     ClickHouse hosts; it has no in-cluster runtime and never writes): -->
skip-urdume: binary-not-a-service
skip-tela: binary-not-web
skip-helm-native: pure-binary-no-cluster-runtime
skip-gitops: pure-binary-no-cluster-runtime
skip-magma: pure-binary-no-cluster-runtime
skip-continuous-convergence: pure-binary-no-cluster-runtime
skip-platform-mediated: pure-binary-no-cluster-runtime

One-sentence purpose: ask a ClickHouse host a closed set of observe-only
questions (who am I, what exists, how big, is it healthy, what is running, what
was slow, one bounded select) and answer each with one of kotae's four
outcomes, so a host behind a down network path is never read as an empty table.
One process can serve several hosts (`--target`, repeated), each addressed by
label. Sibling of holofote; the transport seam is a deliberate copy until the
extraction named above lands.

## Public and generic — no estate identifiers

This repo is PUBLIC (MIT). It contains no company, tenant, host, environment
codename or person name; docs and tests use `example.com` hosts and the labels
`alpha` / `beta`. `lanterna/tests/no_estate_identifiers.rs` walks everything git
ships (`.rs/.md/.toml/.nix/.lisp/.yml/.yaml/.json/.lock` and every
extension-less file, workflows and lock files included) and BLAKE3-compares each
token, and every 4–32-byte window inside it, against holofote's hashed denylist.
The deployment (hosts, labels, credential paths) is argv, emitted by the Nix
side.

## Where to look

| Concern | File |
|---|---|
| the seam: `Transport`, `ReqwestTransport`, `MockTransport` (feature `mock`, matches on statement text); failure classification `ErrorShape` + `ConnectEvidence` → the pure `classify_with` | `lanterna/src/transport.rs` |
| the closed `Route` enum (one arm) and `Method` | `lanterna/src/route.rs` |
| the per-request `readonly` / `max_*` settings, rendered once | `lanterna/src/settings.rs` |
| credentials read at call time into `Zeroizing`; `AuthHeaders` | `lanterna/src/auth.rs` |
| the closed `Question` enum, identifier grammar, `Window`, `ResultCap` + the probe row, `Bounds`, the ONE renderer | `lanterna/src/sql.rs` |
| what a ClickHouse exception code means | `lanterna/src/exception.rs` |
| `Outcome` + the typed `Blindness` / `Refusal` causes | `lanterna/src/outcome.rs` |
| `ClickHouseClient<T: Transport>`: validate, send, classify | `lanterna/src/client.rs` |
| `Targets<T>`: several clients by label; `resolve` → client or a `Refusal` naming every label | `lanterna/src/targets.rs` |
| `LanternaConfig`: shikumi tiers + `(deflanterna …)` on one struct | `lanterna/src/config.rs`, `lanterna/specs/lanterna.lisp` |
| the CLI contract, tool inputs, required-field schemas, the MCP border | `lanterna-mcp/src/main.rs` |

## Invariants, and where each is sealed

- **No write has a code path.** `Route` has one arm (`POST /`) and `Question` has
  no variant that writes or carries SQL, so a write is `E0599`
  (`compile_fail` doctests in `route.rs` and `sql.rs`), not a runtime refusal.
  Do not add an arm or a variant that mutates.
- **Every request is `readonly`.** `Settings::query_pairs` is the only builder of
  request parameters: `readonly=1`, `max_execution_time`, `max_result_rows`
  (cap + 1), `max_result_bytes`, `result_overflow_mode=break`,
  `wait_end_of_query=1`, `default_format=JSONCompact`. The client test asserts all
  of them on the wire.
- **One SQL renderer.** `impl Display for Question` is the only place statement
  text is assembled; there is no raw-SQL entry point. Identifiers are
  `[A-Za-z_][A-Za-z0-9_]*` and rendered in backticks; values are always
  single-quoted literals with `\`, `'` and ASCII controls escaped.
  `hostile_values_render_as_inert_quoted_literals` proves a quote, `UNION`,
  `;`, `--`, a heredoc and a backslash stay inside their literal.
- **`limit` is required on every row-returning question; `window` on every
  question over an event time** (`slow_queries`, `parts`, `mutations`, `select`).
  State questions (`databases`, `tables`, `columns`, `table_sizes`, `merges`,
  `replication`, `processes`, `row_policies`, `grants`, `metrics`) have no event
  time, so `limit` alone bounds them. The request type holds both as `Option` so
  a missing one is a typed `refused` before anything is sent. `ResultCap` is
  `1..=cap`; a window is `<n>s|m|h|d`, at least 1 s, at most `maxWindowSeconds`.
- **`select` reads only allowlisted tables.** `selectAllow` (`database.table` or
  `database.*`, default `system.*`) gates it; outside the list is `refused` with
  the list as `legal`. Columns, filters and value bytes are bounded.
- **`truncated` is a fact the wire carries.** Every statement asks for
  `limit + 1` rows (the probe row); it came back, so more matched than `limit`;
  it is dropped before answering. A byte-bound break (`max_result_bytes`) cuts
  rows without a probe row and is not reported as `truncated`.
- **Every HTTP status is judged by `handan::judge`, after the exception code.**
  ClickHouse reports an unknown table as `404` and a timeout as `500`, so the
  numeric code (`X-ClickHouse-Exception-Code`, else the `Code: n.` body prefix)
  is read first (`exception.rs`): 516/193/192 → `refused` credential; 497 and 403
  → `refused` access denied; 164 → `refused` readonly; 60/81/47 → `refused`
  unknown table/database/column; 159 → `blind` (a timeout, never `empty`).
- **Four outcomes, never collapsed.** Connect failure with plain TCP failing too
  (this includes a name that does not resolve) → `blind`, never `empty`; request
  timeout → `blind` naming `requestTimeoutMs`; TLS → `blind` naming `--tls`,
  recognised by type (a `rustls::Error` in the chain) or by evidence (a
  connect-class failure while plain TCP opens). The decision is the pure
  `transport::classify_with`, table-tested. 5xx/429 → `blind` with retry advice.
  A table with zero rows → `empty`. `Replication` is guarded: an absent
  `system.replicas` is `empty`, not an error. `is_error` on the MCP result is
  derived from the discriminant in exactly one function (`answer`).
- **Secrets never leave zeroizing memory.** The user and password files are read
  on every call into `Zeroizing`, sent as `X-ClickHouse-User` / `X-ClickHouse-Key`
  via `Bytes::from_owner(Zeroizing<_>)` marked sensitive. `--host` userinfo is
  refused without echo; the host label is `scheme://host[:port]`. `Debug` impls
  redact; tracing is stderr only. `MockTransport` / `RecordedCall` copy secrets
  into plain strings by design and compile only under `cfg(test)` or `mock`.
- **Typed emission.** No `format!` macro call, nor `format_args!(` / `fmt::format(`,
  outside `#[cfg(test)] mod` blocks; the ban test walks both members. Use
  `write!` into a `Display`, thiserror, tracing, or serde.
- **A target is addressed by label, and a bad address is `refused`.** With
  `--target`, `Refusal::UnknownTarget` / `TargetRequired` carry every label as
  `legal`; every tool schema marks `target` required and the instructions name
  the labels once. The single-target form (`--host`/`--label`) strips `target`
  from the schemas at construction.
- **Every tool schema marks its bounds required** (`TOOL_REQUIRED` in `main.rs`),
  so a client sees `limit` / `window` before it asks.

## Gates

`cargo fmt && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test --workspace --all-features && gen build .`
All client logic is mock-green with zero network. `Cargo.gen.lock` is committed;
`Cargo.build-spec.json` is ignored. The flake is four lines over
`substrate.rust.workspace`.
