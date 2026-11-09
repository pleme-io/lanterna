;; lanterna: the typed SDLC manifest. One file, one source of truth.
;;
;; Kind rationale: lanterna is a Binario (a stdio MCP server that READS
;; ClickHouse hosts and never writes to them). It carries no in-cluster
;; runtime, which is why CLAUDE.md declares skip-urdume / skip-helm-native /
;; skip-gitops / skip-magma / skip-continuous-convergence /
;; skip-platform-mediated.

(defcaixa
  :nome "lanterna"
  :versao "0.1.0"
  :kind Binario
  :edicao "2026"
  :descricao "lanterna (lantern): a typed, observe-only ClickHouse HTTP client and MCP server. A closed route enum with no mutating arm, a closed Question enum with exactly one SQL renderer, readonly and result bounds on every request, credentials read at call time into zeroizing memory, and every answer one of kotae's four outcomes (found / empty / refused / blind) so an unreachable host is never read as an empty table."
  :repositorio "github:pleme-io/lanterna"
  :licenca "MIT"
  :autores ("pleme-io")
  :etiquetas ("rust"
    "tatara-lisp"
    "clickhouse"
    "sql"
    "mcp"
    "observability"
    "observe-only"
    "kotae"
    "handan"
    "shikumi"
    "caixa-binario")

  :deps ()
  :deps-dev ()

  :exe ("lanterna-mcp")

  :caixotes ("lanterna"))
