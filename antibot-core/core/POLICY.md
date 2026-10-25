# Compiled policy P1.1

The policy lifecycle has two deliberately separate halves:

```text
offline/root: candidate -> validate/compile -> full run.sh -> atomic publish
init_worker:  active.json -> LKG fallback -> compile once into worker RAM
request:      compiled RAM only
```

No request reads a file or Redis. `init_worker` performs bounded `io.open`
reads only; it never writes or promotes policy. A bad `active.json` falls back
to `/etc/antibot/policy/last-good.json`. If both files are missing or invalid,
the worker uses the built-in empty overlay and logs a critical degraded state.

## Candidate and precedence

`core/policy_runtime.lua` remains the source-controlled candidate. Precedence
is fixed:

```text
global -> servers[$hostname] -> tenants[$document_root] -> principals[name]
```

Example (do not deploy these values without measurements):

```lua
return {
    schema = "1",
    version = "example-1",
    global = {
        settings = {
            l7_circuit_breaker = { mode = "shadow" },
        },
    },
    servers = {
        ["node-a"] = {
            settings = {
                l7_admission = { retry_after = 3 },
            },
        },
    },
    tenants = {
        ["/home/demo/domains/example.com/public_html"] = {
            settings = {
                endpoint_guard = { enabled = true },
            },
        },
    },
    principals = {
        ["gptbot"] = {
            settings = {
                automation_concurrency = { mode = "shadow" },
            },
        },
    },
}
```

Only registered sections and keys already present in `core/config.lua` are
accepted. Types must match. Redis, credentials, secret paths and arbitrary new
keys cannot be changed through policy. The registered surface is:

- `automation`, `automation_concurrency`, `principal_churn`
- `l7_admission`, `endpoint_guard`, `dynamic_guard`
- `l7_surge_guard`, `l7_circuit_breaker`
- `expensive_filter`, `ip_tour`

The logged `pver` is `<declared-version>+<deterministic-digest>`. The digest
includes the artifact and all registered defaults in `core/config.lua`, so a
changed artifact/default cannot silently keep the same runtime identity.

## Publish and rollback

Nothing publishes automatically, including `deploy.sh --fleet`. On one canary
node, after the code has been deployed:

```bash
sudo bash /usr/local/openresty/nginx/conf/antibot/waf/scripts/policyctl.sh publish
sudo /usr/local/openresty/nginx/sbin/nginx -t
sudo /usr/local/openresty/nginx/sbin/nginx -s reload
```

`publish` validates the real candidate, runs the complete `run.sh`, writes a
temporary file in `/etc/antibot/policy`, fsyncs it and switches each file with
`os.rename`. It never overwrites `active.json` in place. The previous valid
active artifact becomes `last-good.json`.

When `policyctl.sh` is invoked from the rsynced live tree, it runs `run.sh`
from `/home/xadmin/antibot/antibot-no-upstream/antibot-core`. Tests such as
`postdeploy_test` and `fim_test` require that source-tree context. Before the
test, policyctl byte-compares the policy compiler/config/tooling in source and
live trees; drift aborts promotion. Use `ANTIBOT_POLICY_SOURCE_DIR` only when
the canonical checkout is stored elsewhere.

The publisher sets `RUN_BASE=HEAD`. The code delta was already tested by
`deploy.sh`; policy publication still runs all unconditional policy, pipeline,
WAF and L7 contracts, while expensive conditional FIM/postdeploy suites run
only when their own files are currently dirty. `POLICY_RUN_BASE` can override
this for an intentional historical comparison. Git `safe.directory` is passed
only to the test process and never written to global configuration.

Observe the canary for 5-15 minutes:

```bash
grep -E '\[policy\].*(active version|candidate rejected|CRITICAL)' \
  /usr/local/openresty/nginx/logs/error.log | tail -30
grep -o 'pver=[^ ]*' /var/log/antibot/antibot.log | tail -20
```

Only then repeat publish/reload on the remaining nodes. During a graceful
reload, old and new workers can briefly emit different `pver` values; this is
expected. Rollback is explicit:

```bash
sudo bash /usr/local/openresty/nginx/conf/antibot/waf/scripts/policyctl.sh rollback
sudo /usr/local/openresty/nginx/sbin/nginx -t
sudo /usr/local/openresty/nginx/sbin/nginx -s reload
```

The state directory is root-controlled (`0750`, normally `root:nginx`) and the
two artifacts are `0640`. A different group or state directory may be supplied
with `ANTIBOT_POLICY_GROUP` and `ANTIBOT_POLICY_DIR` when necessary.

## P1.2 unified node health

The read-only health view consumes the same structured request evidence used
for policy decisions. It reads current and rotated logs by `ts=`, so a midnight
rotation cannot silently reset the observation window:

```bash
bash /usr/local/openresty/nginx/conf/antibot/waf/scripts/healthstat.sh
# or compare nodes over one exact interval:
bash /usr/local/openresty/nginx/conf/antibot/waf/scripts/healthstat.sh 1792800000
```

It reports active/LKG artifacts, observed `pver`/`dschema`, mixed-version
workers, local-versus-upstream decisions, degraded modules, challenge repeats,
top automation principals/endpoints/cohorts by measured upstream work, and
first-party/verified rejection guards. Redis and both threat/operator feed
ages are shown from exact health keys. No Redis key or policy is changed.

`logger_error_rows` covers explicit open/timer failures. A graceful reload may
still lose at most the in-memory tail (64 lines per worker); that bound cannot
be reconstructed after worker exit and is therefore printed as an explicit
unobservable limitation rather than reported as zero loss.
