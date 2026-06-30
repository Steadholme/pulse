//! Optional Klaxon step-up notification (best-effort, CAEP-style).
//!
//! When a subject crosses the `high` risk threshold, Pulse RECORDS the decision (a revocation row +
//! a Watchtower audit event) and, if a Klaxon target is configured, fires a best-effort
//! notification so a human sees "this session should step-up / be revoked". v1 does NOT force
//! Keystone to revoke — it surfaces the decision. The POST is fire-and-forget: any failure only
//! warns and never affects the poller.

use std::time::Duration;

use serde_json::json;

use crate::config::Klaxon;
use crate::httpc;

/// Per-POST budget. Klaxon is in-network; keep it short.
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(2);

/// Best-effort notify. No-op when no Klaxon target is configured.
pub async fn step_up(klaxon: Option<&Klaxon>, sub: &str, score: f64, reasons: &str) {
    let Some(k) = klaxon else { return };
    let body = json!({
        "user_sub": sub,
        "source": "pulse",
        "title": format!("Risk elevated to HIGH (score {:.0})", score),
        "body": format!("Continuous-access decision: session should step-up or be revoked. {reasons}"),
    })
    .to_string();
    match httpc::post_json(&k.url, &k.token, &body, NOTIFY_TIMEOUT).await {
        Some(s) if (200..300).contains(&s) => {
            tracing::info!(sub = %sub, "klaxon step-up notification sent")
        }
        Some(s) => tracing::warn!(sub = %sub, status = s, "klaxon rejected notification"),
        None => { /* already warned in httpc */ }
    }
}
