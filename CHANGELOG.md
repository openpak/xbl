# Changelog

## v0.2.0 - 2026-11-04

- Account erasure (card #120): `DELETE /internal/accounts/{account_id}/data` with `Authorization: Bearer <ACCOUNT_ERASE_KEY>`, served on the
  existing internal listener (`XBL_INTERNAL_ADDR`, default `:23513`, container network only; 503 when the key is unset; other
  internal routes still use `X-Internal-Key`). Removes the account's `xuid_map` rows (Postgres and memory), its cached identity, presence,
  MPSD session memberships (a session left empty ends) and handles, pending device-code grants, and closes its RTA sockets. One
  `account erased` log line; idempotent. Nothing authored by the account is kept; xbl stores no content.

## v0.1.1 - 2026-11-03

- The XUID reverse map moved from `xuids.json` to Postgres (schema `xbl` of the shared `xbox` database). `XBL_DATABASE_URL` is required. New XUIDs are written at once, not only on the periodic flush. `token.key` stays a file under `XBL_STATE_DIR`.
- Tests run against Postgres (`XBL_TEST_DATABASE_URL`) and cover a restart on the same database.
