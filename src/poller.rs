//! Background Watchtower telemetry poller + the shared re-scoring path.
//!
//! Every `PULSE_POLL_INTERVAL_SECS` the poller GETs `WATCHTOWER_URL/api/events?limit=N`, keeps the
//! authentication events (`login.success` / `login.failure` / `webauthn.*` / `forward_auth.*`),
//! de-dupes each by its Watchtower event id, records a `signals` row, and re-scores the subject.
//! A `high` verdict appends a `revocations` row (de-duped per triggering signal), emits a
//! `pulse.risk.high` Watchtower audit event, and best-effort notifies Klaxon — each exactly once.
//!
//! RESILIENCE IS THE CONTRACT: a down/slow Watchtower (or garbage in the feed) just skips the cycle;
//! the poller never panics and the HTTP server keeps serving. Idempotency lives in the data model
//! (`ON CONFLICT DO NOTHING` on the signal id and the revocation id), so a replayed feed after a
//! restart produces no duplicate signals, revocations, audit events, or notifications.

use std::time::Duration;

use serde::Deserialize;

use crate::scoring::{assess, Candidate};
use crate::store::{baseline_for_sub, Revocation, Risk, Signal};
use crate::{hour_of_day, now_secs, AppState};

/// Per-fetch budget for the events GET.
const FETCH_TIMEOUT: Duration = Duration::from_secs(3);

/// One Watchtower audit event as returned by `GET /api/events` (only the fields we consume; every
/// field defaults so a partial/foreign row is tolerated). `ts` is epoch MILLISECONDS.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct WatchtowerEvent {
    #[serde(default)]
    pub seq: i64,
    #[serde(default)]
    pub ts: i64,
    #[serde(default)]
    pub actor: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub detail: String,
}

/// True for the authentication event kinds Pulse scores.
pub fn is_auth_kind(action: &str) -> bool {
    action == "login.success"
        || action == "login.failure"
        || action.starts_with("webauthn.")
        || action.starts_with("forward_auth.")
}

/// Parse the `/api/events` JSON array. Foreign/invalid JSON yields an empty Vec (resilient).
pub fn parse_events(body: &str) -> Vec<WatchtowerEvent> {
    serde_json::from_str::<Vec<WatchtowerEvent>>(body).unwrap_or_default()
}

/// Pull `ip=<token>` / `ua=<rest>` out of an event's `detail` string, best-effort.
///
/// HONEST SCOPE: today's Keystone login events do not carry IP/UA, so these are usually empty and
/// the score is driven by failure/burst signals. When a producer does stamp `detail` with
/// `ip=1.2.3.4 ua=Mozilla/5.0 ...`, we capture them: `ip` is the contiguous token after `ip=`, and
/// `ua` is everything after `ua=` (user-agents contain spaces) up to the end.
pub fn extract_ip_ua(detail: &str) -> (String, String) {
    let ip = find_token(detail, "ip=");
    let ua = match detail.find("ua=") {
        Some(i) => detail[i + 3..].trim().to_string(),
        None => String::new(),
    };
    (ip, ua)
}

fn find_token(s: &str, key: &str) -> String {
    match s.find(key) {
        Some(i) => s[i + key.len()..]
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string(),
        None => String::new(),
    }
}

impl WatchtowerEvent {
    /// Convert to a [`Signal`] (id de-dupe key = `wt_<seq>`; ts normalised ms -> seconds). Returns
    /// `None` for events without a positive seq (which would not de-dupe).
    pub fn to_signal(&self) -> Option<Signal> {
        if self.seq <= 0 {
            return None;
        }
        let (ip, ua) = extract_ip_ua(&self.detail);
        let ts = if self.ts >= 1_000_000_000_000 {
            self.ts / 1000 // milliseconds -> seconds
        } else {
            self.ts
        };
        Some(Signal {
            id: format!("wt_{}", self.seq),
            sub: self.actor.trim().to_string(),
            kind: self.action.trim().to_string(),
            source_ip: ip,
            ua,
            ts,
        })
    }
}

/// Spawn the poller task. No-op (info log) when polling is disabled in config.
pub fn spawn(state: AppState) {
    if !state.config.poll_enabled {
        tracing::info!("PULSE_POLL_ENABLED=false — telemetry poller not started");
        return;
    }
    let interval = Duration::from_secs(state.config.poll_interval_secs.max(1));
    tracing::info!(
        url = %state.config.watchtower_url,
        secs = state.config.poll_interval_secs,
        "starting Watchtower telemetry poller"
    );
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let n = poll_once(&state).await;
            if n > 0 {
                tracing::info!(new_signals = n, "telemetry poll ingested new signals");
            }
        }
    });
}

/// Run one poll cycle. Returns the number of NEW signals ingested. Never errors.
pub async fn poll_once(state: &AppState) -> usize {
    let url = format!(
        "{}/api/events?limit={}",
        state.config.watchtower_url.trim_end_matches('/'),
        state.config.event_limit
    );
    let Some(body) = crate::httpc::get(&url, FETCH_TIMEOUT).await else {
        return 0;
    };

    // Keep auth events, oldest-first (so each scored event sees the prior ones already recorded).
    let mut events: Vec<WatchtowerEvent> = parse_events(&body)
        .into_iter()
        .filter(|e| is_auth_kind(&e.action))
        .collect();
    events.sort_by_key(|e| e.seq);

    let mut new_count = 0usize;
    for ev in &events {
        let Some(signal) = ev.to_signal() else {
            continue;
        };
        if signal.sub.is_empty() {
            continue;
        }
        match state.store.record_signal(&signal).await {
            Ok(true) => {}
            Ok(false) => continue, // already ingested (de-duped)
            Err(e) => {
                tracing::warn!(error = %e, id = %signal.id, "record_signal failed — skipping");
                continue;
            }
        }
        new_count += 1;
        rescore(state, &signal).await;
    }
    new_count
}

/// Re-score the subject of `signal` and persist the verdict. On a `high` verdict, record the
/// continuous-access decision (revocation), emit the audit event, and notify Klaxon — each exactly
/// once (gated on the revocation being newly inserted). Shared by the poller; the `/api/score`
/// endpoint computes its own verdict live without writing.
pub async fn rescore(state: &AppState, signal: &Signal) {
    // Baseline from prior history (this event excluded), with windows referenced to the event.
    let baseline = baseline_for_sub(
        state.store.as_ref(),
        &signal.sub,
        signal.ts,
        Some(&signal.id),
    )
    .await;
    let candidate = Candidate {
        kind: signal.kind.clone(),
        ip: signal.source_ip.clone(),
        ua: signal.ua.clone(),
        hour: Some(hour_of_day(signal.ts)),
    };
    let assessment = assess(&baseline, &candidate);
    let reasons = join_reasons(&assessment.reasons);

    let risk = Risk {
        sub: signal.sub.clone(),
        score: assessment.score,
        level: assessment.level.clone(),
        reasons: reasons.clone(),
        updated_at: now_secs(),
    };
    if let Err(e) = state.store.upsert_risk(&risk).await {
        tracing::warn!(error = %e, sub = %signal.sub, "upsert_risk failed");
        return;
    }

    if !assessment.is_high() {
        return;
    }

    // A high verdict: record the decision (de-duped per triggering signal).
    let rev = Revocation {
        id: format!("rev_{}", signal.id),
        sub: signal.sub.clone(),
        reason: reasons.clone(),
        ts: now_secs(),
    };
    let newly = match state.store.insert_revocation(&rev).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, sub = %signal.sub, "insert_revocation failed");
            return;
        }
    };
    if !newly {
        return; // already acted on this triggering signal
    }

    tracing::warn!(sub = %signal.sub, score = assessment.score, "risk elevated to HIGH");
    state.audit.emit(crate::audit::AuditEvent::warning(
        "pulse.risk.high",
        &signal.sub,
        "session",
        &format!("score={:.0} level=high", assessment.score),
    ));
    crate::notify::step_up(
        state.config.klaxon.as_ref(),
        &signal.sub,
        assessment.score,
        &reasons,
    )
    .await;
}

/// Join reasons into the single `reasons` TEXT column value (` · `-separated; a stable fallback when
/// empty so a high verdict always carries a human explanation).
pub fn join_reasons(reasons: &[String]) -> String {
    if reasons.is_empty() {
        "no specific deviation".to_string()
    } else {
        reasons.join(" · ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_kind_matches_expected() {
        assert!(is_auth_kind("login.success"));
        assert!(is_auth_kind("login.failure"));
        assert!(is_auth_kind("webauthn.register"));
        assert!(is_auth_kind("forward_auth.allow"));
        assert!(!is_auth_kind("session.logout"));
        assert!(!is_auth_kind("post.created"));
    }

    #[test]
    fn parse_events_resilient() {
        assert!(parse_events("not json").is_empty());
        assert!(parse_events("{}").is_empty());
        let evs = parse_events(
            r#"[{"seq":3,"ts":1700000000000,"actor":"a@b","action":"login.success"}]"#,
        );
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].seq, 3);
        assert_eq!(evs[0].actor, "a@b");
    }

    #[test]
    fn extract_ip_ua_best_effort() {
        let (ip, ua) = extract_ip_ua("ip=203.0.113.7 ua=Mozilla/5.0 (X11; Linux)");
        assert_eq!(ip, "203.0.113.7");
        assert_eq!(ua, "Mozilla/5.0 (X11; Linux)");
        let (ip, ua) = extract_ip_ua("password login");
        assert!(ip.is_empty());
        assert!(ua.is_empty());
    }

    #[test]
    fn to_signal_normalises_ms_and_requires_seq() {
        let ev = WatchtowerEvent {
            seq: 5,
            ts: 1_700_000_000_000,
            actor: "u1".to_string(),
            action: "login.success".to_string(),
            detail: "ip=10.0.0.1".to_string(),
            ..WatchtowerEvent::default()
        };
        let s = ev.to_signal().unwrap();
        assert_eq!(s.id, "wt_5");
        assert_eq!(s.ts, 1_700_000_000); // ms -> s
        assert_eq!(s.source_ip, "10.0.0.1");

        let no_seq = WatchtowerEvent {
            action: "login.success".to_string(),
            ..WatchtowerEvent::default()
        };
        assert!(no_seq.to_signal().is_none());
    }

    #[test]
    fn is_failure_kind_reexport_works() {
        assert!(crate::store::is_failure_kind("login.failure"));
        assert!(!crate::store::is_failure_kind("login.success"));
    }

    #[test]
    fn join_reasons_has_fallback() {
        assert_eq!(join_reasons(&[]), "no specific deviation");
        assert_eq!(
            join_reasons(&["a".to_string(), "b".to_string()]),
            "a · b"
        );
    }
}
