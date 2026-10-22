# Canonical decision ledger

`core/decision.lua` normalizes the final owner and semantics of a request
decision. Existing module-specific telemetry remains available; this ledger is
the stable cross-layer view used for fleet comparison.

Current schema: `dschema=1`.

| Log field | Meaning |
|---|---|
| `pver` | Policy build identifier from `core/policy_meta.lua` |
| `dschema` | Decision schema version |
| `dkind` | `security`, `capacity`, `policy`, or `challenge` |
| `dsrc` | Module that owns the final decision |
| `drule` | Stable rule/cause within that module |
| `dmode` | `observe`, `shadow`, `enforce`, or `degraded` |
| `dscope` | Enforcement scope such as request, IP, host, docroot, or principal |
| `dsubject` | Subject identifier for the scope; values are log-token sanitized |
| `dttl` | Effective enforcement TTL in seconds, or `-` when not applicable |
| `dup` | Whether this request actually reached an upstream (`true`/`false`) |

Rules:

- A module records a decision immediately before its terminal return/exit.
- Later terminal stages may replace an earlier provisional record; the log row
  represents the final owner.
- `dup` is finalized in log phase from `upstream_status`, unless the terminal
  module already proved the request was answered locally.
- Adding the ledger must not change thresholds or traffic verdicts.
- Any incompatible field-meaning change increments `decision_schema`.
