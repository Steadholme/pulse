//! `POST /api/score` — the service-token live-scoring surface.
//!
//! This path is `auth=public` at the Sluice gateway (Keystone calls it synchronously at login time
//! and cannot speak the browser OIDC/cookie SSO), so Pulse authenticates it itself against the
//! fixed `PULSE_SERVICE_TOKEN`. It computes a verdict LIVE against the subject's stored baseline and
//! returns `{score, level, reasons[]}` — it does NOT write a signal or a verdict (only the poller,
//! consuming sealed Watchtower telemetry, mutates state). The caller decides what to do with the
//! verdict (e.g. require step-up).

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Json, Response};
use serde::{Deserialize, Serialize};

use crate::auth;
use crate::error::AppError;
use crate::scoring::{assess, Candidate};
use crate::store::baseline_for_sub;
use crate::{now_secs, AppState};

/// Request body. `ip` / `ua` / `hour` are the proposed login's attributes; all optional so a caller
/// can score with whatever it has. `sub` is required (the identity being evaluated).
#[derive(Debug, Default, Deserialize)]
pub struct ScoreRequest {
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub ua: Option<String>,
    #[serde(default)]
    pub hour: Option<u8>,
}

/// Response body returned to the caller.
#[derive(Debug, Serialize)]
pub struct ScoreResponse {
    pub sub: String,
    pub score: f64,
    pub level: String,
    pub reasons: Vec<String>,
}

/// `POST /api/score` — own-bearer-token, live verdict.
pub async fn score(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    match handle(&state, &headers, &body).await {
        Ok(resp) => Json(resp).into_response(),
        Err(e) => e.into_json(),
    }
}

async fn handle(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<ScoreResponse, AppError> {
    // Own bearer auth FIRST (before touching the body), fail-closed.
    auth::require_service_token(headers, &state.config.service_token)?;

    let req: ScoreRequest = serde_json::from_slice(body)
        .map_err(|e| AppError::InvalidRequest(format!("malformed JSON body: {e}")))?;

    let sub = req.sub.trim();
    if sub.is_empty() {
        return Err(AppError::InvalidRequest("`sub` is required".to_string()));
    }
    if let Some(h) = req.hour {
        if h > 23 {
            return Err(AppError::InvalidRequest(
                "`hour` must be 0..=23".to_string(),
            ));
        }
    }

    let now = now_secs();
    // Live verdict against the subject's stored baseline (no exclusion — the candidate is not a
    // stored signal). Windows are referenced to "now".
    let baseline = baseline_for_sub(state.store.as_ref(), sub, now, None).await;
    let candidate = Candidate {
        // A synchronous login-time check is a login attempt, not a recorded failure.
        kind: "login.attempt".to_string(),
        ip: req.ip.unwrap_or_default().trim().to_string(),
        ua: req.ua.unwrap_or_default().trim().to_string(),
        hour: req.hour,
    };
    let a = assess(&baseline, &candidate);

    Ok(ScoreResponse {
        sub: sub.to_string(),
        score: a.score,
        level: a.level,
        reasons: a.reasons,
    })
}
