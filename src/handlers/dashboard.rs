//! The SSO risk dashboard (`risk.w33d.xyz/`, `/user/{sub}`).
//!
//! Mounted behind the gateway `auth=sso` route — the operator identity is taken from the injected
//! `X-Auth-*` (Pulse trusts these; it is internal-only). Both views are READ-ONLY: the index shows
//! every monitored subject's current risk + a recent high-risk timeline + signal volume; the
//! per-user view shows one subject's signal history, derived baseline, and live score breakdown.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};

use crate::auth;
use crate::config::{DASHBOARD_LIMIT, USER_SIGNAL_LIMIT};
use crate::handlers::{app_css, esc, fmt_ts, level_badge, topbar};
use crate::poller::join_reasons;
use crate::scoring::{assess, Candidate};
use crate::store::{build_baseline, KindCount, Revocation, Risk, Signal};
use crate::{hour_of_day, now_secs, AppState};

const DASHBOARD_HTML: &str = include_str!("../../templates/dashboard.html");
const USER_HTML: &str = include_str!("../../templates/user.html");

// ===========================================================================
// GET / — risk overview
// ===========================================================================

pub async fn index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let email = auth::display_email(&headers);

    let risks = state.store.list_risks(DASHBOARD_LIMIT).await;
    let revocations = state.store.list_revocations(DASHBOARD_LIMIT).await;
    let volume = state.store.signal_volume().await;
    let total_signals = state.store.signal_count().await;

    let high_count = risks.iter().filter(|r| r.level == "high").count();
    let medium_count = risks.iter().filter(|r| r.level == "medium").count();

    let stats = format!(
        r#"<div class="stat-grid">
  <div class="stat"><div class="stat__value">{subjects}</div><div class="stat__label">Monitored subjects</div></div>
  <div class="stat stat--danger"><div class="stat__value">{high}</div><div class="stat__label">High risk</div></div>
  <div class="stat stat--warn"><div class="stat__value">{medium}</div><div class="stat__label">Medium risk</div></div>
  <div class="stat"><div class="stat__value">{signals}</div><div class="stat__label">Signals recorded</div></div>
</div>"#,
        subjects = risks.len(),
        high = high_count,
        medium = medium_count,
        signals = total_signals,
    );

    let risk_rows = render_risk_rows(&risks);
    let timeline = render_timeline(&revocations);
    let volume_html = render_volume(&volume);

    let body = DASHBOARD_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{TOPBAR}}", &topbar("Risk overview", &email))
        .replace("{{STATS}}", &stats)
        .replace("{{RISK_ROWS}}", &risk_rows)
        .replace("{{TIMELINE}}", &timeline)
        .replace("{{VOLUME}}", &volume_html);
    Html(body).into_response()
}

// ===========================================================================
// GET /user/{sub} — one subject's history, baseline, and breakdown
// ===========================================================================

pub async fn user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(sub): Path<String>,
) -> Response {
    let email = auth::display_email(&headers);

    let risk = state.store.get_risk(&sub).await;
    let signals = state.store.signals_for_sub(&sub, USER_SIGNAL_LIMIT).await;
    let revocations = state.store.revocations_for_sub(&sub, DASHBOARD_LIMIT).await;

    let now = now_secs();
    let baseline = build_baseline(&signals, now, None);

    // Live score breakdown of the subject's most recent signal (its own row excluded from baseline),
    // so the operator sees exactly why the current verdict landed where it did.
    let breakdown = match signals.first() {
        Some(latest) => {
            let b = build_baseline(&signals, latest.ts, Some(&latest.id));
            let a = assess(
                &b,
                &Candidate {
                    kind: latest.kind.clone(),
                    ip: latest.source_ip.clone(),
                    ua: latest.ua.clone(),
                    hour: Some(hour_of_day(latest.ts)),
                },
            );
            join_reasons(&a.reasons)
        }
        None => "no signals recorded yet".to_string(),
    };

    let verdict = render_verdict(&sub, risk.as_ref(), &breakdown);
    let baseline_html = format!(
        r#"<div class="kv-grid">
  <div class="kv"><span class="kv__k">Signals in history</span><span class="kv__v">{hist}</span></div>
  <div class="kv"><span class="kv__k">Known source IPs</span><span class="kv__v">{ips}</span></div>
  <div class="kv"><span class="kv__k">Known devices (UA)</span><span class="kv__v">{uas}</span></div>
  <div class="kv"><span class="kv__k">Active hours (UTC)</span><span class="kv__v">{hours}</span></div>
  <div class="kv"><span class="kv__k">Recent failures (1h)</span><span class="kv__v">{fails}</span></div>
  <div class="kv"><span class="kv__k">Burst (5m)</span><span class="kv__v">{burst}</span></div>
</div>"#,
        hist = baseline.history_len,
        ips = baseline.known_ips.len(),
        uas = baseline.known_uas.len(),
        hours = fmt_hours(&baseline.active_hours),
        fails = baseline.recent_failures,
        burst = baseline.recent_events,
    );

    let signal_rows = render_signal_rows(&signals);
    let rev_rows = render_user_revocations(&revocations);

    let body = USER_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{TOPBAR}}", &topbar("Subject risk", &email))
        .replace("{{SUB}}", &esc(&sub))
        .replace("{{VERDICT}}", &verdict)
        .replace("{{BASELINE}}", &baseline_html)
        .replace("{{REVOCATIONS}}", &rev_rows)
        .replace("{{SIGNAL_ROWS}}", &signal_rows);
    Html(body).into_response()
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

fn render_risk_rows(risks: &[Risk]) -> String {
    if risks.is_empty() {
        return r#"<tr><td colspan="4" class="empty-cell">No subjects scored yet. The poller records signals from Watchtower login telemetry.</td></tr>"#.to_string();
    }
    let mut out = String::new();
    for r in risks {
        out.push_str(&format!(
            r#"<tr>
  <td class="cell-sub"><a href="/user/{sub_enc}">{sub}</a></td>
  <td>{badge}</td>
  <td class="cell-num">{score:.0}</td>
  <td class="cell-reasons">{reasons}</td>
</tr>"#,
            sub_enc = esc(&r.sub),
            sub = esc(&r.sub),
            badge = level_badge(&r.level),
            score = r.score,
            reasons = esc(&r.reasons),
        ));
    }
    out
}

fn render_timeline(revs: &[Revocation]) -> String {
    if revs.is_empty() {
        return r#"<div class="empty-state"><p>No high-risk decisions recorded.</p></div>"#
            .to_string();
    }
    let mut out = String::from(r#"<ul class="timeline">"#);
    for r in revs {
        out.push_str(&format!(
            r#"<li class="timeline__item">
  <div class="timeline__head"><a href="/user/{sub_enc}">{sub}</a><span class="timeline__time">{ts}</span></div>
  <div class="timeline__body">{reason}</div>
</li>"#,
            sub_enc = esc(&r.sub),
            sub = esc(&r.sub),
            ts = esc(&fmt_ts(r.ts)),
            reason = esc(&r.reason),
        ));
    }
    out.push_str("</ul>");
    out
}

fn render_volume(volume: &[KindCount]) -> String {
    if volume.is_empty() {
        return r#"<div class="empty-state"><p>No signals yet.</p></div>"#.to_string();
    }
    let max = volume.iter().map(|k| k.count).max().unwrap_or(1).max(1);
    let mut out = String::from(r#"<div class="bars">"#);
    for k in volume {
        let pct = (k.count as f64 / max as f64 * 100.0).round() as i64;
        out.push_str(&format!(
            r#"<div class="bar-row">
  <span class="bar-row__label">{kind}</span>
  <span class="bar-row__track"><span class="bar-row__fill" style="width:{pct}%"></span></span>
  <span class="bar-row__count">{count}</span>
</div>"#,
            kind = esc(&k.kind),
            pct = pct,
            count = k.count,
        ));
    }
    out.push_str("</div>");
    out
}

fn render_verdict(sub: &str, risk: Option<&Risk>, breakdown: &str) -> String {
    match risk {
        Some(r) => format!(
            r#"<div class="verdict">
  <div class="verdict__score">{score:.0}<span class="verdict__max">/100</span></div>
  <div class="verdict__meta">
    <div class="verdict__level">{badge}</div>
    <div class="verdict__reasons">{reasons}</div>
    <div class="verdict__updated">Last updated {ts}</div>
  </div>
</div>
<div class="breakdown"><span class="breakdown__k">Latest event breakdown</span><span class="breakdown__v">{breakdown}</span></div>"#,
            score = r.score,
            badge = level_badge(&r.level),
            reasons = esc(&r.reasons),
            ts = esc(&fmt_ts(r.updated_at)),
            breakdown = esc(breakdown),
        ),
        None => format!(
            r#"<div class="verdict verdict--empty">
  <div class="verdict__score">—</div>
  <div class="verdict__meta">
    <div class="verdict__level">{badge}</div>
    <div class="verdict__reasons">No verdict yet for <code>{sub}</code>.</div>
  </div>
</div>"#,
            badge = level_badge("low"),
            sub = esc(sub),
        ),
    }
}

fn render_signal_rows(signals: &[Signal]) -> String {
    if signals.is_empty() {
        return r#"<tr><td colspan="4" class="empty-cell">No signals recorded for this subject.</td></tr>"#.to_string();
    }
    let mut out = String::new();
    for s in signals {
        out.push_str(&format!(
            r#"<tr>
  <td>{ts}</td>
  <td class="cell-kind">{kind}</td>
  <td>{ip}</td>
  <td class="cell-ua">{ua}</td>
</tr>"#,
            ts = esc(&fmt_ts(s.ts)),
            kind = esc(&s.kind),
            ip = if s.source_ip.is_empty() { "—".to_string() } else { esc(&s.source_ip) },
            ua = if s.ua.is_empty() { "—".to_string() } else { esc(&s.ua) },
        ));
    }
    out
}

fn render_user_revocations(revs: &[Revocation]) -> String {
    if revs.is_empty() {
        return r#"<div class="empty-state"><p>No continuous-access decisions recorded for this subject.</p></div>"#.to_string();
    }
    let mut out = String::from(r#"<ul class="timeline">"#);
    for r in revs {
        out.push_str(&format!(
            r#"<li class="timeline__item">
  <div class="timeline__head"><span class="timeline__tag">step-up / revoke</span><span class="timeline__time">{ts}</span></div>
  <div class="timeline__body">{reason}</div>
</li>"#,
            ts = esc(&fmt_ts(r.ts)),
            reason = esc(&r.reason),
        ));
    }
    out.push_str("</ul>");
    out
}

/// Render the active-hours set as a compact UTC list, capped for readability.
fn fmt_hours(hours: &std::collections::BTreeSet<u8>) -> String {
    if hours.is_empty() {
        return "—".to_string();
    }
    hours
        .iter()
        .map(|h| format!("{h:02}"))
        .collect::<Vec<_>>()
        .join(", ")
}
