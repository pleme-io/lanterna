;; lanterna deployment bounds: the (deflanterna) authoring face.
;;
;; ONE struct, two faces: this form and the shikumi YAML overlay both
;; deserialize into `LanternaConfig`. Every field is a BOUND on what the
;; observe-only server will do against one ClickHouse host; none of them is
;; a credential, a host, or a label. Those are argv, per host.
;;
;; A test (`prescribed_mirrors_the_authored_lisp`) pins this form to
;; `TieredConfig::prescribed_default()`, so the two faces cannot drift.

(deflanterna
  :max-results 500
  :max-window-seconds 604800
  :max-execution-seconds 30
  :max-result-bytes 10485760
  :connect-timeout-ms 5000
  :request-timeout-ms 45000
  :max-filters 16
  :max-columns 32
  :max-value-bytes 1024
  :select-allow ("system.*"))
