# Changelog

## v0.1.1 - 2026-11-03

- The XUID reverse map moved from `xuids.json` to Postgres (schema `xbl` of the shared `xbox` database). `XBL_DATABASE_URL` is required. New XUIDs are written at once, not only on the periodic flush. `token.key` stays a file under `XBL_STATE_DIR`.
- Tests run against Postgres (`XBL_TEST_DATABASE_URL`) and cover a restart on the same database.
