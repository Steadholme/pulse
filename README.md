# Pulse — adaptive risk & continuous access engine

Pulse re-scores identity risk from the login telemetry already flowing into **Watchtower**. A
background poller builds per-subject behavioral baselines (known IPs / devices / hours), scores each
new authentication event by how far it deviates, and records continuous-access decisions. It is part
of the Steadholme sovereign-infra estate and follows the same layout as `inkwell` / `relay`.

- **Subdomain:** `risk.w33d.xyz` · **internal port:** `9300` · **db:** `pulse`
- **Surfaces (split at the Sluice gateway):**
  - `GET /` and `GET /user/{sub}` — `auth=sso` server-rendered dashboard (trusts injected
    `X-Auth-Subject` / `X-Auth-Email`; Pulse is internal-only and never logs anyone in itself).
  - `POST /api/score` — `auth=public` at the gateway; Pulse does its OWN bearer auth against
    `PULSE_SERVICE_TOKEN` so Keystone can consult it synchronously at login time.
  - `GET /healthz` — unauthenticated liveness (container HEALTHCHECK).

## How it works

A background poller (`PULSE_POLL_INTERVAL_SECS`, default 30s) GETs
`WATCHTOWER_URL/api/events?limit=N`, keeps the authentication events
(`login.success` / `login.failure` / `webauthn.*` / `forward_auth.*`, `actor` = subject), de-dupes
each by its Watchtower event id (`signals.id = wt_<seq>`), records a signal, and re-scores the
subject. A **high** verdict appends a `revocations` row (deduped per triggering signal), emits a
`pulse.risk.high` Watchtower audit event, and best-effort notifies Klaxon — each exactly once.
Everything is resilient: a down/slow Watchtower simply skips the cycle; the server keeps serving.

### Scoring (pure, deterministic — `src/scoring.rs`)

`assess(baseline, candidate) -> { score 0..=100, level low|medium|high, reasons[] }`. Deviation is
only meaningful relative to an established baseline, so a brand-new subject is never spuriously
flagged. Weighted, additive, bounded signals: new source IP, new device/UA, off-hours activity,
authentication failure, recent failure count, and activity burst. `>= 70` is high, `>= 40` medium.

> v1 **records** the decision (a CAEP-style "session should step-up / be revoked"); it does **not**
> force Keystone to revoke.

## Storage

`async-trait Store` with an in-memory default (`PULSE_STORE=memory`, the zero-config boot) and a
`PgStore` (sqlx 0.8, runtime-tokio-rustls, runtime queries only — no macros, no database needed to
build). Portable standard SQL only (TEXT / BIGINT / DOUBLE PRECISION, `INSERT .. ON CONFLICT`,
`CREATE INDEX`), so the same statements later run unchanged on FusionDB over pgwire. `migrate()`
runs on startup.

```sql
signals(id TEXT PK, sub TEXT, kind TEXT, source_ip TEXT DEFAULT '', ua TEXT DEFAULT '', ts BIGINT);
  INDEX(sub, ts)
risk(sub TEXT PK, score DOUBLE PRECISION, level TEXT, reasons TEXT, updated_at BIGINT)
revocations(id TEXT PK, sub TEXT, reason TEXT, ts BIGINT); INDEX(ts)
```

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `BIND_ADDR` | `0.0.0.0:9300` | Listen address |
| `PULSE_STORE` | `memory` | `memory` or `postgres` |
| `PULSE_DATABASE_URL` / `DATABASE_URL` | — | required when `PULSE_STORE=postgres` |
| `PULSE_SERVICE_TOKEN` | _(empty)_ | Bearer for `POST /api/score`; **empty = endpoint disabled (fail closed)** |
| `WATCHTOWER_URL` | `http://watchtower:8500` | Telemetry feed + audit sink base URL |
| `PULSE_POLL_ENABLED` | `true` | Run the background telemetry poller |
| `PULSE_POLL_INTERVAL_SECS` | `30` | Poll cadence |
| `PULSE_EVENT_LIMIT` | `200` | Events pulled per cycle (`?limit=N`) |
| `AUDIT_ENABLED` | `false` | Emit `pulse.risk.high` to Watchtower |
| `AUDIT_INGEST_TOKEN` | — | Bearer for the Watchtower `/events` ingest |
| `KLAXON_URL` + `KLAXON_TOKEN` | — | Optional step-up notification target |

Boots zero-config (in-memory, no database, poller resilient if Watchtower is unreachable).

## `POST /api/score`

```bash
curl -s https://risk.w33d.xyz/api/score \
  -H 'Authorization: Bearer <PULSE_SERVICE_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{"sub":"u_alice","ip":"203.0.113.9","ua":"Mozilla/5.0","hour":3}'
# -> {"sub":"u_alice","score":40.0,"level":"medium","reasons":["new source IP 203.0.113.9"]}
```

Computes the verdict live against the subject's stored baseline; it does not write state.

## Build & test

```bash
CARGO_BUILD_JOBS=2 cargo check --all-targets   # clean (no database needed)
cargo test                                     # in-memory flow + scoring + store
# Postgres integration (optional, needs an external PG):
TEST_DATABASE_URL=postgres://... cargo test --test pg_store -- --nocapture
```

No OpenSSL anywhere (sqlx `rustls`; the Watchtower/Klaxon hops are dependency-light raw-TCP
HTTP/1.1). Multi-stage Docker build: `rust:1.96-slim` builder → `debian:trixie-slim` runtime,
non-root uid 10001, `pulse healthcheck` HEALTHCHECK.

## Deferred (explicitly out of scope for v1)

- **No enforcement of revocation.** Pulse records the continuous-access decision and surfaces it; it
  does not call Keystone to terminate or step-up a live session. Wiring Keystone to consult
  `revocations` (or a future push) is a follow-up — kept out so Pulse can never accidentally lock
  the estate out.
- **No privileged/kernel/microVM operations.** Pulse is a plain user-space HTTP service; it performs
  no host, network-admin, or kernel actions.
- **No ML.** Scoring is intentionally simple, deterministic, and auditable, not a trained model.
- **IP / UA enrichment is best-effort.** Today's Keystone login events do not carry IP/UA, so those
  signals are usually empty and the score is driven by failure/burst patterns; Pulse captures IP/UA
  when a producer stamps them into the event `detail` (`ip=… ua=…`).
