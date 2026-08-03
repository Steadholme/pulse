//! Risk telemetry storage: `signals`, `risk`, `revocations`.
//!
//! `Store` is a small async trait with an in-memory and a PostgreSQL implementation, mirroring the
//! keystone/inkwell/relay seam: handlers + the poller depend only on the trait, so a FusionDB-backed
//! store can drop in later. The PostgreSQL layer uses ONLY portable standard SQL
//! (TEXT/BIGINT/DOUBLE PRECISION, PK/UNIQUE/NOT NULL/DEFAULT, `INSERT .. ON CONFLICT`, parameterized
//! queries, `CREATE INDEX`) and runtime queries (no compile-time macros), so the build needs NO
//! database and the same statements later run unchanged on FusionDB over pgwire.
//!
//! The methods are `async`: handlers `.await` them directly on the serving runtime and `PgStore`
//! drives sqlx natively — NO `block_in_place`, NO sync-over-async bridge, so a DB round-trip never
//! blocks a worker thread. Writes that must be idempotent (a signal de-duped by event id; a single
//! revocation per triggering signal) lean on the PRIMARY KEY + `ON CONFLICT DO NOTHING`, so no
//! in-process serializer is needed even under a concurrent poller.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::config::{DASHBOARD_LIMIT, USER_SIGNAL_LIMIT};
use crate::hour_of_day;
use crate::scoring::Baseline;

/// Recent-failure window (seconds): failures newer than this feed the brute-force signal.
pub const RECENT_FAILURE_WINDOW_SECS: i64 = 3_600;
/// Burst window (seconds): events newer than this feed the activity-burst signal.
pub const BURST_WINDOW_SECS: i64 = 300;
/// How many of a subject's newest signals the baseline is derived from (bounds the PG scan).
pub const BASELINE_SCAN_LIMIT: usize = 500;

/// One recorded behavioral signal (maps 1:1 to a `signals` row). `ts` is epoch SECONDS.
#[derive(Clone, Debug)]
pub struct Signal {
    pub id: String,
    pub sub: String,
    pub kind: String,
    pub source_ip: String,
    pub ua: String,
    pub ts: i64,
}

/// A subject's current risk verdict (maps 1:1 to a `risk` row). `reasons` is a single human string
/// (reasons joined by ` · `), kept portable in a TEXT column.
#[derive(Clone, Debug)]
pub struct Risk {
    pub sub: String,
    pub score: f64,
    pub level: String,
    pub reasons: String,
    pub updated_at: i64,
}

/// A recorded continuous-access decision (maps 1:1 to a `revocations` row). v1 RECORDS the decision
/// (a CAEP-style "session should step-up/revoke"); it does not force Keystone.
#[derive(Clone, Debug)]
pub struct Revocation {
    pub id: String,
    pub sub: String,
    pub reason: String,
    pub ts: i64,
}

/// One `(kind, count)` row of the signal-volume summary shown on the dashboard.
#[derive(Clone, Debug)]
pub struct KindCount {
    pub kind: String,
    pub count: i64,
}

/// Storage failure surfaced to the caller (mapped to a 500 at the handler layer).
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store error: {0}")]
    Backend(String),
}

/// Pluggable risk store.
#[async_trait]
pub trait Store: Send + Sync {
    /// Record one signal, de-duped by its `id` (the Watchtower event id). Returns `true` when the
    /// row was newly inserted, `false` when it already existed (a duplicate poll).
    async fn record_signal(&self, signal: &Signal) -> Result<bool, StoreError>;

    /// A subject's newest signals (capped), newest-first.
    async fn signals_for_sub(&self, sub: &str, limit: usize) -> Vec<Signal>;

    /// Upsert a subject's current risk verdict (keyed by `sub`).
    async fn upsert_risk(&self, risk: &Risk) -> Result<(), StoreError>;

    /// One subject's current risk verdict.
    async fn get_risk(&self, sub: &str) -> Option<Risk>;

    /// All current risk verdicts, highest score first (capped).
    async fn list_risks(&self, limit: usize) -> Vec<Risk>;

    /// Record a continuous-access decision, de-duped by its `id`. Returns `true` when newly
    /// inserted (so the caller emits the audit/notify exactly once).
    async fn insert_revocation(&self, rev: &Revocation) -> Result<bool, StoreError>;

    /// Recent revocations across all subjects, newest-first (capped).
    async fn list_revocations(&self, limit: usize) -> Vec<Revocation>;

    /// A subject's revocations, newest-first (capped).
    async fn revocations_for_sub(&self, sub: &str, limit: usize) -> Vec<Revocation>;

    /// Total signals recorded.
    async fn signal_count(&self) -> i64;

    /// Signal volume by kind, highest count first.
    async fn signal_volume(&self) -> Vec<KindCount>;
}

/// Derive a [`Baseline`] from a subject's signals.
///
/// Pure (modulo `hour_of_day`): the known IP/UA/hour sets and `history_len` come from the prior
/// history (signals other than `exclude_id`, so a candidate's own fields are not pre-"known"),
/// while `recent_failures` / `recent_events` are counted over ALL signals within their windows
/// (current pressure, candidate included). Shared by both store backends and the live `/api/score`.
pub fn build_baseline(signals: &[Signal], now: i64, exclude_id: Option<&str>) -> Baseline {
    let mut b = Baseline::default();
    for s in signals {
        let is_candidate = exclude_id == Some(s.id.as_str());
        if !is_candidate {
            if !s.source_ip.is_empty() {
                b.known_ips.insert(s.source_ip.clone());
            }
            if !s.ua.is_empty() {
                b.known_uas.insert(s.ua.clone());
            }
            b.active_hours.insert(hour_of_day(s.ts));
            b.history_len += 1;
        }
        if now - s.ts <= RECENT_FAILURE_WINDOW_SECS && is_failure_kind(&s.kind) {
            b.recent_failures += 1;
        }
        if now - s.ts <= BURST_WINDOW_SECS {
            b.recent_events += 1;
        }
    }
    b
}

/// True for any `*.failure` signal kind.
pub fn is_failure_kind(kind: &str) -> bool {
    kind == "login.failure" || kind.ends_with(".failure")
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

#[derive(Default)]
struct Inner {
    signals: Vec<Signal>,
    risk: HashMap<String, Risk>,
    revocations: Vec<Revocation>,
}

#[derive(Default)]
pub struct InMemoryStore {
    inner: Mutex<Inner>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    // The std `Mutex` is fine throughout: each critical section is fully synchronous (no `.await`
    // inside), so a guard is never held across a yield point.
    async fn record_signal(&self, signal: &Signal) -> Result<bool, StoreError> {
        let mut inner = self.inner.lock().expect("inner lock poisoned");
        if inner.signals.iter().any(|s| s.id == signal.id) {
            return Ok(false);
        }
        inner.signals.push(signal.clone());
        Ok(true)
    }

    async fn signals_for_sub(&self, sub: &str, limit: usize) -> Vec<Signal> {
        let inner = self.inner.lock().expect("inner lock poisoned");
        let mut v: Vec<Signal> = inner
            .signals
            .iter()
            .filter(|s| s.sub == sub)
            .cloned()
            .collect();
        v.sort_by(|a, b| b.ts.cmp(&a.ts).then_with(|| b.id.cmp(&a.id)));
        v.truncate(limit);
        v
    }

    async fn upsert_risk(&self, risk: &Risk) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().expect("inner lock poisoned");
        inner.risk.insert(risk.sub.clone(), risk.clone());
        Ok(())
    }

    async fn get_risk(&self, sub: &str) -> Option<Risk> {
        self.inner
            .lock()
            .expect("inner lock poisoned")
            .risk
            .get(sub)
            .cloned()
    }

    async fn list_risks(&self, limit: usize) -> Vec<Risk> {
        let inner = self.inner.lock().expect("inner lock poisoned");
        let mut v: Vec<Risk> = inner.risk.values().cloned().collect();
        v.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.updated_at.cmp(&a.updated_at))
                .then_with(|| a.sub.cmp(&b.sub))
        });
        v.truncate(limit);
        v
    }

    async fn insert_revocation(&self, rev: &Revocation) -> Result<bool, StoreError> {
        let mut inner = self.inner.lock().expect("inner lock poisoned");
        if inner.revocations.iter().any(|r| r.id == rev.id) {
            return Ok(false);
        }
        inner.revocations.push(rev.clone());
        Ok(true)
    }

    async fn list_revocations(&self, limit: usize) -> Vec<Revocation> {
        let inner = self.inner.lock().expect("inner lock poisoned");
        let mut v: Vec<Revocation> = inner.revocations.clone();
        v.sort_by(|a, b| b.ts.cmp(&a.ts).then_with(|| b.id.cmp(&a.id)));
        v.truncate(limit);
        v
    }

    async fn revocations_for_sub(&self, sub: &str, limit: usize) -> Vec<Revocation> {
        let inner = self.inner.lock().expect("inner lock poisoned");
        let mut v: Vec<Revocation> = inner
            .revocations
            .iter()
            .filter(|r| r.sub == sub)
            .cloned()
            .collect();
        v.sort_by(|a, b| b.ts.cmp(&a.ts).then_with(|| b.id.cmp(&a.id)));
        v.truncate(limit);
        v
    }

    async fn signal_count(&self) -> i64 {
        self.inner
            .lock()
            .expect("inner lock poisoned")
            .signals
            .len() as i64
    }

    async fn signal_volume(&self) -> Vec<KindCount> {
        let inner = self.inner.lock().expect("inner lock poisoned");
        let mut counts: HashMap<String, i64> = HashMap::new();
        for s in &inner.signals {
            *counts.entry(s.kind.clone()).or_insert(0) += 1;
        }
        let mut v: Vec<KindCount> = counts
            .into_iter()
            .map(|(kind, count)| KindCount { kind, count })
            .collect();
        v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.kind.cmp(&b.kind)));
        v
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `PULSE_STORE=postgres`. Each method drives sqlx natively and the callers
// `.await` it on the serving runtime — NO `block_in_place`, NO sync-over-async. Idempotent writes
// rely on the PRIMARY KEY + `ON CONFLICT DO NOTHING`; the risk upsert uses `ON CONFLICT (sub) DO
// UPDATE`.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// PostgreSQL-backed [`Store`]. Holds just a `PgPool`.
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    /// Open a pooled connection. Async; call from within a Tokio runtime.
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await?;
        Ok(Self::from_pool(pool))
    }

    /// Construct from an existing pool (used by tests that share a pool).
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Idempotent, portable migration. Standard SQL only — safe to run on every startup.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS signals (\
                 id TEXT PRIMARY KEY, \
                 sub TEXT NOT NULL, \
                 kind TEXT NOT NULL, \
                 source_ip TEXT NOT NULL DEFAULT '', \
                 ua TEXT NOT NULL DEFAULT '', \
                 ts BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_signals_sub_ts ON signals (sub, ts)")
            .execute(&self.pool)
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS risk (\
                 sub TEXT PRIMARY KEY, \
                 score DOUBLE PRECISION NOT NULL DEFAULT 0, \
                 level TEXT NOT NULL DEFAULT 'low', \
                 reasons TEXT NOT NULL DEFAULT '', \
                 updated_at BIGINT NOT NULL DEFAULT 0\
             )",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS revocations (\
                 id TEXT PRIMARY KEY, \
                 sub TEXT NOT NULL, \
                 reason TEXT NOT NULL, \
                 ts BIGINT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_revocations_ts ON revocations (ts)")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    fn signal_from_row(row: &sqlx::postgres::PgRow) -> Result<Signal, sqlx::Error> {
        Ok(Signal {
            id: row.try_get("id")?,
            sub: row.try_get("sub")?,
            kind: row.try_get("kind")?,
            source_ip: row.try_get("source_ip")?,
            ua: row.try_get("ua")?,
            ts: row.try_get("ts")?,
        })
    }

    fn risk_from_row(row: &sqlx::postgres::PgRow) -> Result<Risk, sqlx::Error> {
        Ok(Risk {
            sub: row.try_get("sub")?,
            score: row.try_get("score")?,
            level: row.try_get("level")?,
            reasons: row.try_get("reasons")?,
            updated_at: row.try_get("updated_at")?,
        })
    }

    fn revocation_from_row(row: &sqlx::postgres::PgRow) -> Result<Revocation, sqlx::Error> {
        Ok(Revocation {
            id: row.try_get("id")?,
            sub: row.try_get("sub")?,
            reason: row.try_get("reason")?,
            ts: row.try_get("ts")?,
        })
    }

    async fn record_signal_async(&self, s: &Signal) -> Result<bool, sqlx::Error> {
        let res = sqlx::query(
            "INSERT INTO signals (id, sub, kind, source_ip, ua, ts) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO NOTHING",
        )
        .bind(&s.id)
        .bind(&s.sub)
        .bind(&s.kind)
        .bind(&s.source_ip)
        .bind(&s.ua)
        .bind(s.ts)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn signals_for_sub_async(
        &self,
        sub: &str,
        limit: usize,
    ) -> Result<Vec<Signal>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, sub, kind, source_ip, ua, ts FROM signals \
             WHERE sub = $1 ORDER BY ts DESC, id DESC LIMIT $2",
        )
        .bind(sub)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::signal_from_row).collect()
    }

    async fn upsert_risk_async(&self, r: &Risk) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO risk (sub, score, level, reasons, updated_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (sub) DO UPDATE SET \
                 score = EXCLUDED.score, level = EXCLUDED.level, \
                 reasons = EXCLUDED.reasons, updated_at = EXCLUDED.updated_at",
        )
        .bind(&r.sub)
        .bind(r.score)
        .bind(&r.level)
        .bind(&r.reasons)
        .bind(r.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_risk_async(&self, sub: &str) -> Result<Option<Risk>, sqlx::Error> {
        let row =
            sqlx::query("SELECT sub, score, level, reasons, updated_at FROM risk WHERE sub = $1")
                .bind(sub)
                .fetch_optional(&self.pool)
                .await?;
        match row {
            Some(r) => Ok(Some(Self::risk_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn list_risks_async(&self, limit: usize) -> Result<Vec<Risk>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT sub, score, level, reasons, updated_at FROM risk \
             ORDER BY score DESC, updated_at DESC, sub ASC LIMIT $1",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::risk_from_row).collect()
    }

    async fn insert_revocation_async(&self, rev: &Revocation) -> Result<bool, sqlx::Error> {
        let res = sqlx::query(
            "INSERT INTO revocations (id, sub, reason, ts) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&rev.id)
        .bind(&rev.sub)
        .bind(&rev.reason)
        .bind(rev.ts)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn list_revocations_async(&self, limit: usize) -> Result<Vec<Revocation>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, sub, reason, ts FROM revocations ORDER BY ts DESC, id DESC LIMIT $1",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::revocation_from_row).collect()
    }

    async fn revocations_for_sub_async(
        &self,
        sub: &str,
        limit: usize,
    ) -> Result<Vec<Revocation>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, sub, reason, ts FROM revocations \
             WHERE sub = $1 ORDER BY ts DESC, id DESC LIMIT $2",
        )
        .bind(sub)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::revocation_from_row).collect()
    }

    async fn signal_count_async(&self) -> Result<i64, sqlx::Error> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM signals")
            .fetch_one(&self.pool)
            .await?;
        row.try_get("n")
    }

    async fn signal_volume_async(&self) -> Result<Vec<KindCount>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT kind, COUNT(*) AS n FROM signals GROUP BY kind ORDER BY n DESC, kind ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(KindCount {
                    kind: r.try_get("kind")?,
                    count: r.try_get("n")?,
                })
            })
            .collect()
    }
}

#[async_trait]
impl Store for PgStore {
    async fn record_signal(&self, signal: &Signal) -> Result<bool, StoreError> {
        self.record_signal_async(signal)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn signals_for_sub(&self, sub: &str, limit: usize) -> Vec<Signal> {
        self.signals_for_sub_async(sub, limit)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg signals_for_sub failed");
                Vec::new()
            })
    }

    async fn upsert_risk(&self, risk: &Risk) -> Result<(), StoreError> {
        self.upsert_risk_async(risk)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn get_risk(&self, sub: &str) -> Option<Risk> {
        self.get_risk_async(sub).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_risk failed");
            None
        })
    }

    async fn list_risks(&self, limit: usize) -> Vec<Risk> {
        self.list_risks_async(limit).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_risks failed");
            Vec::new()
        })
    }

    async fn insert_revocation(&self, rev: &Revocation) -> Result<bool, StoreError> {
        self.insert_revocation_async(rev)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_revocations(&self, limit: usize) -> Vec<Revocation> {
        self.list_revocations_async(limit)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg list_revocations failed");
                Vec::new()
            })
    }

    async fn revocations_for_sub(&self, sub: &str, limit: usize) -> Vec<Revocation> {
        self.revocations_for_sub_async(sub, limit)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg revocations_for_sub failed");
                Vec::new()
            })
    }

    async fn signal_count(&self) -> i64 {
        self.signal_count_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg signal_count failed");
            0
        })
    }

    async fn signal_volume(&self) -> Vec<KindCount> {
        self.signal_volume_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg signal_volume failed");
            Vec::new()
        })
    }
}

/// Convenience used by callers that want a subject's baseline directly from the store.
pub async fn baseline_for_sub(
    store: &dyn Store,
    sub: &str,
    now: i64,
    exclude_id: Option<&str>,
) -> Baseline {
    let signals = store.signals_for_sub(sub, BASELINE_SCAN_LIMIT).await;
    build_baseline(&signals, now, exclude_id)
}

// Surfaced for tests / docs.
pub const _DASHBOARD_LIMIT: usize = DASHBOARD_LIMIT;
pub const _USER_SIGNAL_LIMIT: usize = USER_SIGNAL_LIMIT;

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(id: &str, sub: &str, kind: &str, ip: &str, ts: i64) -> Signal {
        Signal {
            id: id.to_string(),
            sub: sub.to_string(),
            kind: kind.to_string(),
            source_ip: ip.to_string(),
            ua: String::new(),
            ts,
        }
    }

    #[tokio::test]
    async fn record_signal_dedupes_by_id() {
        let store = InMemoryStore::new();
        let s = sig("wt_1", "u1", "login.success", "10.0.0.1", 1000);
        assert!(store.record_signal(&s).await.unwrap());
        assert!(
            !store.record_signal(&s).await.unwrap(),
            "second insert is a no-op"
        );
        assert_eq!(store.signal_count().await, 1);
    }

    #[tokio::test]
    async fn revocation_dedupes_by_id() {
        let store = InMemoryStore::new();
        let r = Revocation {
            id: "rev_wt_1".to_string(),
            sub: "u1".to_string(),
            reason: "high risk".to_string(),
            ts: 1000,
        };
        assert!(store.insert_revocation(&r).await.unwrap());
        assert!(!store.insert_revocation(&r).await.unwrap());
        assert_eq!(store.list_revocations(10).await.len(), 1);
    }

    #[tokio::test]
    async fn risk_upsert_replaces() {
        let store = InMemoryStore::new();
        store
            .upsert_risk(&Risk {
                sub: "u1".to_string(),
                score: 10.0,
                level: "low".to_string(),
                reasons: String::new(),
                updated_at: 1,
            })
            .await
            .unwrap();
        store
            .upsert_risk(&Risk {
                sub: "u1".to_string(),
                score: 80.0,
                level: "high".to_string(),
                reasons: "new IP".to_string(),
                updated_at: 2,
            })
            .await
            .unwrap();
        let r = store.get_risk("u1").await.unwrap();
        assert_eq!(r.score, 80.0);
        assert_eq!(r.level, "high");
        assert_eq!(store.list_risks(10).await.len(), 1);
    }

    #[tokio::test]
    async fn build_baseline_excludes_candidate_for_known_sets() {
        let store = InMemoryStore::new();
        // Prior history from one IP.
        store
            .record_signal(&sig("wt_1", "u1", "login.success", "10.0.0.1", 1_000))
            .await
            .unwrap();
        // The candidate from a NEW IP.
        store
            .record_signal(&sig("wt_2", "u1", "login.success", "203.0.113.5", 2_000))
            .await
            .unwrap();
        let signals = store.signals_for_sub("u1", 100).await;
        let b = build_baseline(&signals, 2_000, Some("wt_2"));
        // The candidate's own IP is NOT pre-known.
        assert!(b.known_ips.contains("10.0.0.1"));
        assert!(!b.known_ips.contains("203.0.113.5"));
        assert_eq!(b.history_len, 1);
    }

    #[tokio::test]
    async fn list_risks_orders_by_score_desc() {
        let store = InMemoryStore::new();
        for (sub, score) in [("a", 10.0), ("b", 90.0), ("c", 50.0)] {
            store
                .upsert_risk(&Risk {
                    sub: sub.to_string(),
                    score,
                    level: "x".to_string(),
                    reasons: String::new(),
                    updated_at: 1,
                })
                .await
                .unwrap();
        }
        let ranked = store.list_risks(10).await;
        assert_eq!(ranked[0].sub, "b");
        assert_eq!(ranked[2].sub, "a");
    }
}
