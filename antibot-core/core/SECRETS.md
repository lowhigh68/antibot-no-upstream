# Protected secret contract

The runtime reads secrets from `/etc/antibot/secrets.json` (override only with
`ANTIBOT_SECRETS_FILE`). The file is outside the source/deploy tree and is read
once per OpenResty worker.

Use `secrets.example.json` as the schema. Requirements:

- `schema_version` is `1`.
- `admin.operator` is required; `admin.viewer` is optional and read-only.
- Admin passwords are 16–512 bytes and usernames must be distinct.
- `pow.challenge_secret` is 32–512 random bytes. Rotate the former source-code
  secret because repository history must be treated as exposed.

Recommended ownership is `root:<openresty-worker-group>` with mode `0640`, and
the parent directory should be `0750`. Do not pass secret values on a command
line and do not commit the live JSON file.

Failure behavior is deliberate:

- Admin authentication fails closed.
- New PoW challenges degrade to monitor/allow and log
  `challenge_secret_unavailable`; public traffic is not blocked by an operator
  provisioning error.
- Existing verified cookies and already stored one-time challenge records are
  not invalidated by this loader.
