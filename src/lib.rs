//! Pulse — adaptive risk & continuous access engine for the HOLDFAST stack.
//!
//! Library root: defines [`AppState`], wires the routes via [`app`], and provides
//! [`build_dev_state`] (in-memory store, audit off, no poller) and [`build_state_from_env`]
//! (env-selected store + Watchtower audit). Integration tests consume [`app`] directly via
//! `tower::oneshot`, exactly like the rest of the estate.
//!
//! Pulse serves TWO surfaces on one subdomain (`risk.w33d.xyz`), split at the Sluice gateway:
//!
//! - The SSO DASHBOARD at `/` and `/user/{sub}` is `auth=sso` (gateway-injected `X-Auth-*`): the
//!   per-subject current risk + level + reasons, a recent high-risk timeline, and signal volume.
//!   Pulse is internal-only and trusts the injected operator identity.
//! - `POST /api/score` is `auth=public` at the gateway — a service-to-service caller (Keystone at
//!   login time) cannot speak the browser OIDC/cookie SSO — so Pulse does its OWN bearer auth there
//!   against `PULSE_SERVICE_TOKEN` and computes a verdict LIVE (no write).
//!
//! A background poller (see [`poller`]) consumes the login telemetry already flowing into
//! Watchtower, builds per-subject behavioral baselines, records signals, and re-scores risk — a
//! `high` verdict records a revocation, emits `pulse.risk.high`, and optionally notifies Klaxon.

pub mod audit;
pub mod auth;
pub mod config;
pub mod error;
pub mod handlers;
pub mod httpc;
pub mod notify;
pub mod poller;
pub mod scoring;
pub mod store;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::{get, post};
use axum::Router;

use crate::audit::AuditSink;
use crate::config::{env_nonempty, truthy, Config};
use crate::store::{InMemoryStore, PgStore, Store};

/// Shared application state. Cheap to clone (everything behind `Arc` / cloneable handles).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub audit: AuditSink,
}

/// Build the router wiring all endpoints onto `state`.
///
/// The dashboard routes sit at the service root (Sluice forwards them unmodified); `/api/score` is
/// the public service-token surface (Pulse enforces its own bearer auth there).
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        // --- SSO dashboard ---
        .route("/", get(handlers::dashboard::index))
        .route("/user/{sub}", get(handlers::dashboard::user))
        // --- public service-token scoring surface ---
        .route("/api/score", post(handlers::api::score))
        .with_state(state)
}

/// Construct dev state: dev [`Config`], an empty [`InMemoryStore`], and a disabled audit sink. Used
/// by the integration tests, so they need no database and no network.
pub fn build_dev_state() -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store: Arc::new(InMemoryStore::new()),
        audit: AuditSink::disabled(),
    }
}

/// Build runtime state from the environment.
///
/// [`Config`] comes from [`Config::from_env`]. The store is selected by `PULSE_STORE`:
/// - `memory` (default): empty [`InMemoryStore`] — no database required.
/// - `postgres`: connect `PULSE_DATABASE_URL` (or `DATABASE_URL`), run the idempotent migration,
///   wire [`PgStore`].
///
/// The audit sink is enabled by `AUDIT_ENABLED` + `WATCHTOWER_URL` + `AUDIT_INGEST_TOKEN`. Returns
/// an error string on misconfiguration so `main` can fail loudly.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();

    let store_kind = env_nonempty("PULSE_STORE").unwrap_or_else(|| "memory".to_string());
    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = env_nonempty("PULSE_DATABASE_URL")
                .or_else(|| env_nonempty("DATABASE_URL"))
                .ok_or_else(|| "PULSE_STORE=postgres requires PULSE_DATABASE_URL".to_string())?;
            tracing::info!("PULSE_STORE=postgres — connecting to database");
            let pg = PgStore::connect(&database_url)
                .await
                .map_err(|e| format!("connect postgres: {e}"))?;
            pg.migrate()
                .await
                .map_err(|e| format!("run migration: {e}"))?;
            tracing::info!("postgres store ready (migrated)");
            Arc::new(pg)
        }
        "memory" => Arc::new(InMemoryStore::new()),
        other => return Err(format!("unknown PULSE_STORE={other} (use memory|postgres)")),
    };

    let audit = AuditSink::start(
        truthy(&env_nonempty("AUDIT_ENABLED").unwrap_or_default()),
        &env_nonempty("WATCHTOWER_URL").unwrap_or_else(|| config.watchtower_url.clone()),
        env_nonempty("AUDIT_INGEST_TOKEN").as_deref(),
    );

    if config.service_token.is_empty() {
        tracing::warn!("PULSE_SERVICE_TOKEN unset — POST /api/score will reject every call");
    }

    Ok(AppState {
        config: Arc::new(config),
        store,
        audit,
    })
}

/// Spawn the background Watchtower telemetry poller for this state (resilient; honors
/// `PULSE_POLL_ENABLED`).
pub fn spawn_poller(state: AppState) {
    poller::spawn(state);
}

/// Current wall-clock time in epoch seconds.
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

/// Hour-of-day (0..=23, UTC) for an epoch-SECONDS timestamp. `time` std only — no extra C deps.
pub fn hour_of_day(ts_secs: i64) -> u8 {
    match time::OffsetDateTime::from_unix_timestamp(ts_secs) {
        Ok(dt) => dt.hour(),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hour_of_day_is_utc() {
        // 1970-01-01T13:00:00Z -> hour 13.
        assert_eq!(hour_of_day(13 * 3600), 13);
        assert_eq!(hour_of_day(0), 0);
    }
}
