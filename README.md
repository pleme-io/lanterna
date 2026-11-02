# lanterna

**A typed, observe-only ClickHouse client and MCP server.**

*lanterna* is Portuguese for *lantern*: it lights what a ClickHouse host
holds, or several hosts, and never touches it. It is the sibling of holofote
(a typed Splunk client and MCP server) and answers in the same vocabulary.

Two workspace members:

| crate | what it is |
|---|---|
| `lanterna` | the library: a transport seam over the ClickHouse HTTP(S) interface, a closed route enum, a closed `Question` enum with one SQL renderer, `readonly` bounds on every request, shikumi config, and an outcome sum. No rmcp dependency. |
| `lanterna-mcp` | the stdio MCP server (rmcp): twelve `clickhouse_*` tools over one target, or over several targets addressed by label. |

## Observe-only, three times over

1. **No write has a code path.** The route enum has one arm (`POST /`, whose
   body is only ever rendered from a `Question`), and `Question` has no variant
   that writes or carries SQL.
2. **No raw SQL.** Identifiers have one grammar; values are always escaped
   literals; every statement is a `SELECT` from a fixed template.
3. **The server enforces it too.** Every request carries `readonly=1`,
   `max_execution_time`, `max_result_rows`, `max_result_bytes` and
   `result_overflow_mode=break`.

## The four outcomes

Every answer carries an `outcome` from [kotae](https://github.com/pleme-io/kotae):

| outcome | `is_error` | meaning |
|---|---|---|
| `found` | false | here are the rows |
| `empty` | false | **a finding**: the host answered and there is nothing |
| `refused` | true | the question was not accepted; `legal` names what would be |
| `blind` | true | the question could not be put; **conclude nothing** |

An unresolvable or unreachable host is `blind`, never `empty`. Every HTTP
status is read by [handan](https://github.com/pleme-io/handan)'s `judge`.

## Tools

`clickhouse_whoami`, `clickhouse_databases`, `clickhouse_tables`,
`clickhouse_columns`, `clickhouse_table_sizes`, `clickhouse_health`
(`parts` | `merges` | `mutations` | `replication`), `clickhouse_processes`,
`clickhouse_slow_queries`, `clickhouse_row_policies`, `clickhouse_grants`,
`clickhouse_metrics`, `clickhouse_select`.

`limit` is required on every question that returns rows, and `window`
(`15m`, `24h`, `7d`) on every question over an event time. `truncated` is a
fact the wire carries: the statement asks for `limit + 1` rows and the extra
one came back.

## The CLI contract

```
lanterna-mcp --host <URL> --label <STRING>
             [--user-file <PATH> --password-file <PATH>]
             [--tls <system|accept-any|ca:<PEM_PATH>>] [--config <PATH>]

lanterna-mcp --target <JSON> [--target <JSON> ...] [--config <PATH>]
```

A `--target` is a JSON object with the keys `label`, `host`, `tls`,
`user-file` and `password-file`. With `--target`, every tool takes a required
`target`; an unknown one is `refused` and lists the legal labels.

Credentials are file paths, read on every call into zeroizing memory and
never logged.

## License

MIT
