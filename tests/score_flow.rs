//! End-to-end HTTP flow over the in-memory store (NO database, NO network).
//!
//! Drives the real `app` router via `tower::oneshot`, exactly like the rest of the estate. Covers:
//! health, the SSO dashboard, the per-user view, the `/api/score` service-token guard (fail-closed
//! with bearer enforcement), live scoring math through the HTTP surface, and the poller's
//! `rescore` path producing a high verdict plus a deduped revocation.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use pulse::config::Config;
use pulse::store::{InMemoryStore, Signal};
use pulse::{app, build_dev_state, AppState};
use tower::ServiceExt;

fn get(path: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .unwrap()
}

fn get_sso(path: &str, sub: &str, email: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header("x-auth-subject", sub)
        .header("x-auth-email", email)
        .body(Body::empty())
        .unwrap()
}

fn post_score(token: Option<&str>, json: &str) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/api/score")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(json.to_string())).unwrap()
}

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 4 * 1_048_576).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// State with a configured service token (so /api/score is enabled).
fn state_with_token(token: &str) -> AppState {
    let mut cfg = Config::dev();
    cfg.service_token = token.to_string();
    cfg.poll_enabled = false;
    AppState {
        config: Arc::new(cfg),
        store: Arc::new(InMemoryStore::new()),
        audit: pulse::audit::AuditSink::disabled(),
    }
}

#[tokio::test]
async fn health_is_unauthenticated_ok() {
    let state = build_dev_state();
    let (status, body) = call(&state, get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn dashboard_renders_empty_then_lists() {
    let state = build_dev_state();
    let (status, body) = call(&state, get_sso("/", "u_admin", "admin@w33d.xyz")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Risk overview"));
    assert!(body.contains("No subjects scored yet"));
    assert!(
        body.contains("admin@w33d.xyz"),
        "operator email shown in topbar"
    );
}

#[tokio::test]
async fn user_view_renders_for_unknown_subject() {
    let state = build_dev_state();
    let (status, body) = call(&state, get_sso("/user/ghost", "u_admin", "a@w33d.xyz")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("ghost"));
    assert!(body.contains("No verdict yet"));
    assert!(body.contains(r#"class="verdict verdict--empty" data-state="unscored""#));
    assert!(!body.contains(r#"class="verdict verdict--empty" data-level="low""#));
}

#[tokio::test]
async fn score_endpoint_fails_closed_without_token_config() {
    // Dev state has an empty service_token -> endpoint disabled, every call rejected.
    let state = build_dev_state();
    let (status, _) = call(&state, post_score(Some("anything"), r#"{"sub":"u1"}"#)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn score_endpoint_enforces_bearer() {
    let state = state_with_token("svc-secret");
    // Missing bearer.
    let (status, _) = call(&state, post_score(None, r#"{"sub":"u1"}"#)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Wrong bearer.
    let (status, _) = call(&state, post_score(Some("nope"), r#"{"sub":"u1"}"#)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Missing sub.
    let (status, _) = call(&state, post_score(Some("svc-secret"), r#"{}"#)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn score_endpoint_computes_live_verdict() {
    let state = state_with_token("svc-secret");

    // Seed a baseline of one known IP for u1 via the store directly.
    state
        .store
        .record_signal(&Signal {
            id: "wt_1".to_string(),
            sub: "u1".to_string(),
            kind: "login.success".to_string(),
            source_ip: "10.0.0.1".to_string(),
            ua: String::new(),
            ts: 1_700_000_000,
        })
        .await
        .unwrap();

    // A login from a KNOWN ip -> low.
    let (status, body) = call(
        &state,
        post_score(Some("svc-secret"), r#"{"sub":"u1","ip":"10.0.0.1"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["level"], "low");
    assert_eq!(v["sub"], "u1");

    // A login from a NEW ip -> medium, with a reason.
    let (status, body) = call(
        &state,
        post_score(Some("svc-secret"), r#"{"sub":"u1","ip":"203.0.113.9"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["level"], "medium");
    assert!(v["score"].as_f64().unwrap() > 0.0);
    assert!(v["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r.as_str().unwrap().contains("new source IP")));
}

#[tokio::test]
async fn rescore_records_high_verdict_and_dedupes_revocation() {
    let state = state_with_token("svc-secret");

    // Establish a baseline (a known IP) so a later new-IP failure deviates.
    state
        .store
        .record_signal(&Signal {
            id: "wt_1".to_string(),
            sub: "u1".to_string(),
            kind: "login.success".to_string(),
            source_ip: "10.0.0.1".to_string(),
            ua: String::new(),
            ts: 1_700_000_000,
        })
        .await
        .unwrap();

    // A sustained burst of failed attempts from a NEW IP -> the verdict climbs (the very first
    // new-IP failure trips high on novelty; once the IP is in the baseline, accumulating failures
    // + burst keep the score high). The estate-realistic shape: a brute-force run.
    let mut last = None;
    for i in 2i64..=7 {
        let ts = 1_700_000_000 + 100 * (i - 1);
        let sig = Signal {
            id: format!("wt_{i}"),
            sub: "u1".to_string(),
            kind: "login.failure".to_string(),
            source_ip: "203.0.113.9".to_string(),
            ua: String::new(),
            ts,
        };
        state.store.record_signal(&sig).await.unwrap();
        pulse::poller::rescore(&state, &sig).await;
        last = Some(sig);
    }

    let risk = state.store.get_risk("u1").await.expect("verdict present");
    assert_eq!(
        risk.level, "high",
        "sustained brute-force stays high; score {}",
        risk.score
    );

    // At least one high-risk decision was recorded; re-running rescore on the same triggering
    // signal does NOT add another (deduped per signal id).
    let before = state.store.list_revocations(100).await.len();
    assert!(before >= 1, "at least one high-risk revocation recorded");
    pulse::poller::rescore(&state, last.as_ref().unwrap()).await;
    let after = state.store.list_revocations(100).await.len();
    assert_eq!(before, after, "revocation is deduped per triggering signal");

    // The dashboard surfaces the high subject (current level) + the decision timeline.
    let (status, body) = call(&state, get_sso("/", "u_admin", "a@w33d.xyz")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("u1"));
    assert!(body.contains("badge-high"));

    // The per-user view shows the signal history + a step-up decision.
    let (status, ubody) = call(&state, get_sso("/user/u1", "u_admin", "a@w33d.xyz")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(ubody.contains("login.failure"));
    assert!(ubody.contains("step-up / revoke"));
}
