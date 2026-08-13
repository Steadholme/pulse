//! The SSO risk dashboard (`risk.w33d.xyz/`, `/user/{sub}`).
//!
//! Mounted behind the gateway `auth=sso` route. Both views are read-only and render a causal,
//! paper-instrument account of identity risk: the overview features the current worst subject,
//! while the subject view renders a bounded reconstruction from its loaded history slice.
//! Each trace instrument carries a calibration line (evidence depth, observation window,
//! freshness) derived only from the loaded slice — an empty trace reports silence, never an
//! estimate.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};

use crate::auth;
use crate::config::{DASHBOARD_LIMIT, SEISMO_TRACE_LIMIT, USER_SIGNAL_LIMIT};
use crate::handlers::{app_css, esc, fmt_ts, level_badge, topbar};
use crate::poller::join_reasons;
use crate::scoring::{assess, Baseline, Candidate, HIGH_THRESHOLD, MEDIUM_THRESHOLD};
use crate::store::{build_baseline, KindCount, Revocation, Risk, Signal};
use crate::{hour_of_day, now_secs, AppState};

const DASHBOARD_HTML: &str = include_str!("../../templates/dashboard.html");
const USER_HTML: &str = include_str!("../../templates/user.html");

type KindDash = HashMap<String, u8>;

#[derive(Clone, Debug)]
struct TracePoint {
    ts: i64,
    kind: String,
    source_ip: String,
    ua: String,
    score: f64,
    level: String,
    reasons: Vec<String>,
}

// ===========================================================================
// GET / — bounded risk overview
// ===========================================================================

pub async fn index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let email = auth::display_email(&headers);
    let now = now_secs();

    let risks = state.store.list_risks(DASHBOARD_LIMIT).await;
    let revocations = state.store.list_revocations(DASHBOARD_LIMIT).await;
    let volume = state.store.signal_volume().await;
    let total_signals = state.store.signal_count().await;

    // One collection is the single source for every top-eight representation.
    let overview: Vec<&Risk> = risks.iter().take(8).collect();
    let kind_dash = build_kind_dash(volume.iter().map(|item| item.kind.as_str()));
    let trace = match overview.first() {
        Some(worst) => {
            let signals = state
                .store
                .signals_for_sub(&worst.sub, SEISMO_TRACE_LIMIT)
                .await;
            reconstruct_trace(&signals)
        }
        None => Vec::new(),
    };

    let readout = render_readout(&risks, total_signals, now);
    let seismograph = render_seismograph(&trace, &kind_dash, now);
    let roster_rows = render_roster_rows(&overview);
    let roster_cards = render_roster_cards(&overview);
    let endpoint_legend = render_endpoint_legend(&overview);
    let decision_rail = render_decision_rail(&revocations);
    let volume_html = render_volume(&volume, &kind_dash);

    // Legacy and new token names bridge the parallel K3 template change. The scanner only walks
    // original template bytes, so hostile replacement text cannot smuggle a second token.
    // "Risk overview" stays the estate wayfinding name for this view (subject pages link back to
    // it under that label); the H1 carries the instrument identity.
    let page_topbar = topbar("Risk overview", &email);
    let body = fill_template(
        DASHBOARD_HTML,
        &[
            ("CSS", app_css()),
            ("TOPBAR", &page_topbar),
            ("READOUT", &readout),
            ("STATS", &readout),
            ("SEISMOGRAPH", &seismograph),
            ("ROSTER_ROWS", &roster_rows),
            ("RISK_ROWS", &roster_rows),
            ("ROSTER_CARDS", &roster_cards),
            ("ENDPOINT_LEGEND", &endpoint_legend),
            ("DECISION_RAIL", &decision_rail),
            ("TIMELINE", &decision_rail),
            ("VOLUME", &volume_html),
        ],
    );
    Html(body).into_response()
}

// ===========================================================================
// GET /user/{sub} — causal subject trace
// ===========================================================================

pub async fn user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(sub): Path<String>,
) -> Response {
    let email = auth::display_email(&headers);
    let now = now_secs();

    let risk = state.store.get_risk(&sub).await;
    let signals = state.store.signals_for_sub(&sub, USER_SIGNAL_LIMIT).await;
    let revocations = state.store.revocations_for_sub(&sub, DASHBOARD_LIMIT).await;

    let trace = reconstruct_trace(&signals);
    let baseline = build_baseline(&signals, now, None);
    let kind_dash = build_kind_dash(trace.iter().map(|point| point.kind.as_str()));
    let breakdown = trace
        .last()
        .map(|point| join_reasons(&point.reasons))
        .unwrap_or_else(|| "no signals recorded yet".to_string());

    let verdict = render_verdict(&sub, risk.as_ref(), &breakdown);
    let orbit = render_orbit(&trace, &baseline, &kind_dash, now);
    let ledger_rows = render_deviation_ledger_rows(&trace, &kind_dash);
    let signal_rows = render_signal_history_rows(&trace, &kind_dash);
    let access_decisions = render_access_decisions(&revocations);

    let page_topbar = topbar("Subject reconstruction", &email);
    let escaped_sub = esc(&sub);
    let body = fill_template(
        USER_HTML,
        &[
            ("CSS", app_css()),
            ("TOPBAR", &page_topbar),
            ("SUB", &escaped_sub),
            ("VERDICT", &verdict),
            ("ORBIT", &orbit),
            ("BASELINE", &orbit),
            ("DEVIATION_LEDGER", &ledger_rows),
            ("ACCESS_DECISIONS", &access_decisions),
            ("REVOCATIONS", &access_decisions),
            ("SIGNAL_ROWS", &signal_rows),
        ],
    );
    Html(body).into_response()
}

// ---------------------------------------------------------------------------
// Causal model and shared semantic mappings
// ---------------------------------------------------------------------------

fn reconstruct_trace(signals: &[Signal]) -> Vec<TracePoint> {
    let mut chronological = signals.to_vec();
    chronological.sort_by(|a, b| a.ts.cmp(&b.ts).then_with(|| a.id.cmp(&b.id)));

    (0..chronological.len())
        .map(|index| {
            let signal = &chronological[index];
            let baseline = build_baseline(
                &chronological[..=index],
                signal.ts,
                Some(signal.id.as_str()),
            );
            let assessment = assess(
                &baseline,
                &Candidate {
                    kind: signal.kind.clone(),
                    ip: signal.source_ip.clone(),
                    ua: signal.ua.clone(),
                    hour: Some(hour_of_day(signal.ts)),
                },
            );
            TracePoint {
                ts: signal.ts,
                kind: signal.kind.clone(),
                source_ip: signal.source_ip.clone(),
                ua: signal.ua.clone(),
                score: assessment.score,
                level: assessment.level,
                reasons: assessment.reasons,
            }
        })
        .collect()
}

fn build_kind_dash<'a>(kinds: impl IntoIterator<Item = &'a str>) -> KindDash {
    let mut mapping = KindDash::new();
    let mut next = 0usize;
    for kind in kinds {
        if !mapping.contains_key(kind) {
            mapping.insert(kind.to_string(), (next % 4) as u8);
            next += 1;
        }
    }
    mapping
}

fn dash_for(mapping: &KindDash, kind: &str) -> u8 {
    mapping.get(kind).copied().unwrap_or(0)
}

/// Encode exactly one RFC 3986 path segment. URL encoding and HTML escaping remain separate.
fn encode_path_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[(byte >> 4) as usize]));
            encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
    }
    encoded
}

fn user_path(sub: &str) -> String {
    format!("/user/{}", encode_path_segment(sub))
}

fn fill_template(template: &str, slots: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut remaining = template;
    while let Some(start) = remaining.find("{{") {
        out.push_str(&remaining[..start]);
        let token_start = start + 2;
        let Some(relative_end) = remaining[token_start..].find("}}") else {
            out.push_str(&remaining[start..]);
            return out;
        };
        let token_end = token_start + relative_end;
        let name = &remaining[token_start..token_end];
        if let Some((_, replacement)) = slots.iter().find(|(slot, _)| *slot == name) {
            out.push_str(replacement);
        } else {
            out.push_str(&remaining[start..token_end + 2]);
        }
        remaining = &remaining[token_end + 2..];
    }
    out.push_str(remaining);
    out
}

// ---------------------------------------------------------------------------
// Overview fragments
// ---------------------------------------------------------------------------

fn render_readout(risks: &[Risk], total_signals: i64, now: i64) -> String {
    let high = risks.iter().filter(|risk| risk.level == "high").count();
    let medium = risks.iter().filter(|risk| risk.level == "medium").count();
    // The freshest verdict write across the loaded slice; with no verdicts the cell
    // stays a dash rather than inventing a reading.
    let latest_cell = match risks.iter().map(|risk| risk.updated_at).max() {
        Some(ts) => format!(
            r#"<dd data-ts="{ts}">{rel}</dd>"#,
            ts = ts,
            rel = esc(&fmt_relative(now, ts)),
        ),
        None => "<dd>—</dd>".to_string(),
    };
    format!(
        r#"<dl class="seismo-readout" aria-label="Identity risk readout">
  <div class="readout-cell"><dt>Subjects</dt><dd>{subjects}</dd></div>
  <div class="readout-cell" data-level="high"><dt>High</dt><dd>{high}</dd></div>
  <div class="readout-cell" data-level="medium"><dt>Medium</dt><dd>{medium}</dd></div>
  <div class="readout-cell"><dt>Recorded signals</dt><dd>{signals}</dd></div>
  <div class="readout-cell readout-cell--meta"><dt>Latest verdict</dt>{latest_cell}</div>
</dl>"#,
        subjects = risks.len(),
        high = high,
        medium = medium,
        signals = total_signals,
        latest_cell = latest_cell,
    )
}

fn render_roster_rows(risks: &[&Risk]) -> String {
    if risks.is_empty() {
        return r#"<tr class="roster-row roster-row--empty"><td colspan="5" class="empty-cell">No subjects scored yet. The poller records signals from Watchtower login telemetry.</td></tr>"#.to_string();
    }

    let mut out = String::new();
    for risk in risks {
        let path = user_path(&risk.sub);
        let _ = write!(
            out,
            r#"<tr class="roster-row" data-level="{level}">
  <td class="col-subject"><a href="{path}">{sub}</a></td>
  <td class="col-level">{badge}</td>
  <td class="col-score">{score:.0}</td>
  <td class="col-reasons">{reasons}</td>
  <td class="col-updated">{updated}</td>
</tr>"#,
            level = esc(&risk.level),
            path = esc(&path),
            sub = esc(&risk.sub),
            badge = level_badge(&risk.level),
            score = risk.score,
            reasons = esc(&risk.reasons),
            updated = esc(&fmt_ts(risk.updated_at)),
        );
    }
    out
}

fn render_roster_cards(risks: &[&Risk]) -> String {
    if risks.is_empty() {
        return r#"<p class="roster-cards__empty">No subject endpoints to plot.</p>"#.to_string();
    }
    let mut out = String::from(r#"<div class="roster-cards">"#);
    for risk in risks {
        let path = user_path(&risk.sub);
        let _ = write!(
            out,
            r#"<a class="roster-card" data-level="{level}" href="{path}"><span class="roster-card__sub">{sub}</span><span class="roster-card__score">{score:.0}</span><span class="roster-card__level">{level_word}</span></a>"#,
            level = esc(&risk.level),
            path = esc(&path),
            sub = esc(&risk.sub),
            score = risk.score,
            level_word = esc(&risk.level),
        );
    }
    out.push_str("</div>");
    out
}

fn render_endpoint_legend(risks: &[&Risk]) -> String {
    if risks.is_empty() {
        return r#"<p class="endpoint-legend__empty">No endpoints observed.</p>"#.to_string();
    }
    let mut out = String::from(r#"<ol class="endpoint-legend" aria-label="Plotted subjects">"#);
    for risk in risks {
        let path = user_path(&risk.sub);
        let _ = write!(
            out,
            r#"<li data-level="{level}"><a href="{path}"><span class="endpoint-legend__sub">{sub}</span><span class="endpoint-legend__level">{level_word}</span></a></li>"#,
            level = esc(&risk.level),
            path = esc(&path),
            sub = esc(&risk.sub),
            level_word = esc(&risk.level),
        );
    }
    out.push_str("</ol>");
    out
}

fn render_decision_rail(revocations: &[Revocation]) -> String {
    if revocations.is_empty() {
        return r#"<div class="decision-rail decision-rail--empty"><p>No high-risk decisions recorded.</p></div>"#.to_string();
    }
    let mut out = String::from(r#"<ol class="decision-rail">"#);
    for revocation in revocations {
        let path = user_path(&revocation.sub);
        let _ = write!(
            out,
            r#"<li class="decision-mark"><a href="{path}">{sub}</a><time>{time}</time><span>{reason}</span></li>"#,
            path = esc(&path),
            sub = esc(&revocation.sub),
            time = esc(&fmt_ts(revocation.ts)),
            reason = esc(&revocation.reason),
        );
    }
    out.push_str("</ol>");
    out
}

fn render_volume(volume: &[KindCount], mapping: &KindDash) -> String {
    if volume.is_empty() {
        return r#"<div class="signal-volume signal-volume--empty"><p>No signals yet.</p></div>"#
            .to_string();
    }
    let max = volume
        .iter()
        .map(|item| item.count)
        .max()
        .unwrap_or(1)
        .max(1);
    let mut out = String::from(r#"<ol class="signal-volume">"#);
    for item in volume {
        let share = (item.count as f64 / max as f64 * 100.0).round() as i64;
        let _ = write!(
            out,
            r#"<li class="signal-volume__row" data-kind-dash="{dash}" style="--signal-share:{share}%"><span class="signal-volume__kind">{kind}</span><span class="signal-volume__rule" aria-hidden="true"></span><span class="signal-volume__count">{count}</span></li>"#,
            dash = dash_for(mapping, &item.kind),
            share = share,
            kind = esc(&item.kind),
            count = item.count,
        );
    }
    out.push_str("</ol>");
    out
}

// ---------------------------------------------------------------------------
// Shared trace graphics and row-only emitters
// ---------------------------------------------------------------------------

fn render_seismograph(trace: &[TracePoint], mapping: &KindDash, now: i64) -> String {
    let mut out = format!(
        r#"<figure class="seismograph"><svg class="seismograph__plot" viewBox="0 0 720 220" role="img" aria-labelledby="seismograph-title seismograph-desc"><title id="seismograph-title">Causal identity-risk trace</title><desc id="seismograph-desc">A bounded reconstruction of assessments from recorded signals, calculated only from evidence available in the loaded prefix; it is not a live feed.</desc><line class="threshold threshold--medium" data-threshold="medium" x1="36" y1="{medium_y:.1}" x2="684" y2="{medium_y:.1}" stroke="currentColor"/><line class="threshold threshold--high" data-threshold="high" x1="36" y1="{high_y:.1}" x2="684" y2="{high_y:.1}" stroke="currentColor"/>"#,
        medium_y = trace_y(MEDIUM_THRESHOLD),
        high_y = trace_y(HIGH_THRESHOLD),
    );

    if trace.is_empty() {
        out.push_str(r#"<text class="seismograph__empty" x="360" y="112" text-anchor="middle" fill="currentColor">NO TRACE · NO CLAIM</text>"#);
    } else {
        let mut path = String::new();
        for (index, point) in trace.iter().enumerate() {
            let x = trace_x(index, trace.len());
            let y = trace_y(point.score);
            let command = if index == 0 { 'M' } else { 'L' };
            let _ = write!(path, "{command}{x:.1},{y:.1} ");
        }
        let _ = write!(
            out,
            r#"<path class="seismograph__trace" d="{path}" fill="none" stroke="currentColor"/>"#,
            path = path.trim(),
        );
        for (index, point) in trace.iter().enumerate() {
            let x = trace_x(index, trace.len());
            let y = trace_y(point.score);
            let _ = write!(
                out,
                r#"<circle class="seismograph__point" data-trace-index="{index}" data-score="{score:.0}" data-level="{level}" data-kind="{kind}" data-kind-dash="{dash}" cx="{x:.1}" cy="{y:.1}" r="5" fill="currentColor"><title>{kind_word}: {score:.0}, {level_word}</title></circle>"#,
                index = index,
                score = point.score,
                level = esc(&point.level),
                kind = esc(&point.kind),
                dash = dash_for(mapping, &point.kind),
                x = x,
                y = y,
                kind_word = esc(&point.kind),
                level_word = esc(&point.level),
            );
        }
    }
    out.push_str("</svg>");
    out.push_str(&render_kind_key(trace, mapping, "seismograph__key"));
    out.push_str(&render_trace_calibration(trace, SEISMO_TRACE_LIMIT, now));
    out.push_str("</figure>");
    out
}

fn render_orbit(trace: &[TracePoint], baseline: &Baseline, mapping: &KindDash, now: i64) -> String {
    let hours = fmt_hours(&baseline.active_hours);
    let mut out = format!(
        r#"<figure class="identity-orbit"><svg class="identity-orbit__plot" viewBox="0 0 420 300" role="img" aria-labelledby="orbit-title orbit-desc"><title id="orbit-title">Identity behavior orbit</title><desc id="orbit-desc">Recorded events around the learned UTC activity envelope. Points are a historical reconstruction, not live location or session telemetry.</desc><circle class="identity-orbit__envelope" data-active-hours="{hours}" cx="210" cy="145" r="104" fill="none" stroke="currentColor"/>"#,
        hours = esc(&hours),
    );
    if trace.is_empty() {
        out.push_str(r#"<text class="identity-orbit__empty" x="210" y="150" text-anchor="middle" fill="currentColor">NO OBSERVATIONS</text>"#);
    } else {
        for (index, point) in trace.iter().enumerate() {
            let angle = (f64::from(hour_of_day(point.ts)) / 24.0) * std::f64::consts::TAU
                - std::f64::consts::FRAC_PI_2;
            let radius = 70.0 + point.score * 0.32;
            let x = 210.0 + radius * angle.cos();
            let y = 145.0 + radius * angle.sin();
            let _ = write!(
                out,
                r#"<circle class="identity-orbit__point" data-trace-index="{index}" data-score="{score:.0}" data-level="{level}" data-kind="{kind}" data-kind-dash="{dash}" cx="{x:.1}" cy="{y:.1}" r="5" fill="currentColor"><title>{kind_word} at {hour:02}:00 UTC: {score:.0}, {level_word}</title></circle>"#,
                index = index,
                score = point.score,
                level = esc(&point.level),
                kind = esc(&point.kind),
                dash = dash_for(mapping, &point.kind),
                x = x,
                y = y,
                kind_word = esc(&point.kind),
                hour = hour_of_day(point.ts),
                level_word = esc(&point.level),
            );
        }
    }
    out.push_str("</svg>");
    let _ = write!(
        out,
        r#"<dl class="identity-orbit__readout"><div><dt>History</dt><dd>{history}</dd></div><div><dt>Known IPs</dt><dd>{ips}</dd></div><div><dt>Known devices</dt><dd>{devices}</dd></div><div><dt>Active hours UTC</dt><dd>{hours}</dd></div><div><dt>Recent failures</dt><dd>{failures}</dd></div><div><dt>5m burst</dt><dd>{burst}</dd></div></dl>"#,
        history = baseline.history_len,
        ips = baseline.known_ips.len(),
        devices = baseline.known_uas.len(),
        hours = esc(&hours),
        failures = baseline.recent_failures,
        burst = baseline.recent_events,
    );
    out.push_str(&render_kind_key(trace, mapping, "identity-orbit__key"));
    out.push_str(&render_trace_calibration(trace, USER_SIGNAL_LIMIT, now));
    out.push_str("</figure>");
    out
}

/// The instrument's calibration line: how much evidence the reconstruction holds, the
/// window it spans, and how fresh the newest observation is. Claims are limited to the
/// loaded slice — a full window only proves saturation, never that older history is shown,
/// and an empty trace reports silence instead of an estimate.
fn render_trace_calibration(trace: &[TracePoint], limit: usize, now: i64) -> String {
    let (Some(first), Some(last)) = (trace.first(), trace.last()) else {
        return r#"<figcaption class="tape-meta">No observations recorded — the instrument reports nothing rather than estimating.</figcaption>"#
            .to_string();
    };
    let depth = if trace.len() >= limit {
        format!("the {limit} most recent signals (window saturated)")
    } else if trace.len() == 1 {
        "the only recorded signal".to_string()
    } else {
        format!("all {} recorded signals", trace.len())
    };
    let window = if trace.len() == 1 {
        "single observation".to_string()
    } else {
        format!("{} window", fmt_span(last.ts - first.ts))
    };
    format!(
        r#"<figcaption class="tape-meta">Reconstructed from {depth} · {window} · last observation {rel} ({abs} UTC) · bounded history, not a live feed.</figcaption>"#,
        depth = depth,
        window = window,
        rel = esc(&fmt_relative(now, last.ts)),
        abs = esc(&fmt_ts(last.ts)),
    )
}

/// Relative freshness for calibration lines. A timestamp ahead of the page clock is
/// reported as skew instead of being clamped into a fabricated "just now".
fn fmt_relative(now: i64, ts: i64) -> String {
    let delta = now - ts;
    if delta < 0 {
        return "ahead of clock".to_string();
    }
    if delta < 60 {
        format!("{delta}s ago")
    } else if delta < 3_600 {
        format!("{}m ago", delta / 60)
    } else if delta < 86_400 {
        format!("{:.1}h ago", delta as f64 / 3_600.0)
    } else {
        format!("{}d ago", delta / 86_400)
    }
}

/// Compact duration for the observation-window span.
fn fmt_span(secs: i64) -> String {
    let secs = secs.max(0);
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3_600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{:.1}h", secs as f64 / 3_600.0)
    } else {
        format!("{:.1}d", secs as f64 / 86_400.0)
    }
}

fn render_kind_key(trace: &[TracePoint], mapping: &KindDash, class_name: &str) -> String {
    let mut seen: HashMap<&str, ()> = HashMap::new();
    let mut out = format!(r#"<ol class="{}">"#, esc(class_name));
    for point in trace {
        if seen.insert(point.kind.as_str(), ()).is_none() {
            let _ = write!(
                out,
                r#"<li data-kind-dash="{dash}"><span aria-hidden="true">━</span>{kind}</li>"#,
                dash = dash_for(mapping, &point.kind),
                kind = esc(&point.kind),
            );
        }
    }
    out.push_str("</ol>");
    out
}

fn render_deviation_ledger_rows(trace: &[TracePoint], mapping: &KindDash) -> String {
    if trace.is_empty() {
        return r#"<tr class="ledger-row ledger-row--empty"><td colspan="5" class="empty-cell">No deviations can be reconstructed without signals.</td></tr>"#.to_string();
    }
    let mut out = String::new();
    for (index, point) in trace.iter().enumerate().rev() {
        let _ = write!(
            out,
            r#"<tr class="ledger-row" data-trace-index="{index}" data-score="{score:.0}" data-level="{level}">
  <td class="col-when">{when}</td>
  <td class="col-kind"><span data-kind-dash="{dash}">{kind}</span></td>
  <td class="col-score">{score:.0}</td>
  <td class="col-level">{badge}</td>
  <td class="col-deviation">{reasons}</td>
</tr>"#,
            index = index,
            score = point.score,
            level = esc(&point.level),
            when = esc(&fmt_ts(point.ts)),
            dash = dash_for(mapping, &point.kind),
            kind = esc(&point.kind),
            badge = level_badge(&point.level),
            reasons = esc(&join_reasons(&point.reasons)),
        );
    }
    out
}

fn render_signal_history_rows(trace: &[TracePoint], mapping: &KindDash) -> String {
    if trace.is_empty() {
        return r#"<tr class="signal-row signal-row--empty"><td colspan="5" class="empty-cell">No signals recorded for this subject.</td></tr>"#.to_string();
    }
    let mut out = String::new();
    for (index, point) in trace.iter().enumerate().rev() {
        let _ = write!(
            out,
            r#"<tr class="signal-row" data-trace-index="{index}" data-score="{score:.0}" data-level="{level}">
  <td class="col-when">{when}</td>
  <td class="col-kind"><span data-kind-dash="{dash}">{kind}</span></td>
  <td class="col-level">{badge}</td>
  <td class="col-ip">{ip}</td>
  <td class="col-ua">{ua}</td>
</tr>"#,
            index = index,
            score = point.score,
            level = esc(&point.level),
            when = esc(&fmt_ts(point.ts)),
            dash = dash_for(mapping, &point.kind),
            kind = esc(&point.kind),
            badge = level_badge(&point.level),
            ip = visible_or_dash(&point.source_ip),
            ua = visible_or_dash(&point.ua),
        );
    }
    out
}

fn visible_or_dash(value: &str) -> String {
    if value.is_empty() {
        "—".to_string()
    } else {
        esc(value)
    }
}

fn trace_x(index: usize, len: usize) -> f64 {
    if len <= 1 {
        360.0
    } else {
        36.0 + 648.0 * index as f64 / (len - 1) as f64
    }
}

fn trace_y(score: f64) -> f64 {
    206.0 - score.clamp(0.0, 100.0) * 1.5
}

// ---------------------------------------------------------------------------
// Subject verdict and decisions
// ---------------------------------------------------------------------------

fn render_verdict(sub: &str, risk: Option<&Risk>, breakdown: &str) -> String {
    match risk {
        Some(risk) => format!(
            r#"<div class="verdict" data-level="{level}">
  <div class="verdict__score">{score:.0}<span class="verdict__max">/100</span></div>
  <div class="verdict__meta"><div class="verdict__level">{badge}</div><div class="verdict__reasons">{reasons}</div><div class="verdict__updated">Last updated {updated}</div></div>
</div><div class="breakdown"><span class="breakdown__k">Latest reconstructed decision</span><span class="breakdown__v">{breakdown}</span></div>"#,
            level = esc(&risk.level),
            score = risk.score,
            badge = level_badge(&risk.level),
            reasons = esc(&risk.reasons),
            updated = esc(&fmt_ts(risk.updated_at)),
            breakdown = esc(breakdown),
        ),
        None => format!(
            r#"<div class="verdict verdict--empty" data-state="unscored"><div class="verdict__score">—</div><div class="verdict__meta"><div class="verdict__level"><span class="badge">unscored</span></div><div class="verdict__reasons">No verdict yet for <code>{sub}</code>.</div></div></div>"#,
            sub = esc(sub),
        ),
    }
}

fn render_access_decisions(revocations: &[Revocation]) -> String {
    if revocations.is_empty() {
        return r#"<div class="empty-state"><p>No continuous-access decisions recorded for this subject.</p></div>"#.to_string();
    }
    let mut out = String::from(r#"<ol class="access-decisions">"#);
    for revocation in revocations {
        let _ = write!(
            out,
            r#"<li class="access-decision"><span class="access-decision__tag">step-up / revoke</span><time>{time}</time><span>{reason}</span></li>"#,
            time = esc(&fmt_ts(revocation.ts)),
            reason = esc(&revocation.reason),
        );
    }
    out.push_str("</ol>");
    out
}

/// Render the active-hours set as a compact UTC list, capped for readability.
fn fmt_hours(hours: &std::collections::BTreeSet<u8>) -> String {
    if hours.is_empty() {
        return "—".to_string();
    }
    hours
        .iter()
        .map(|hour| format!("{hour:02}"))
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------
// One executable test seam. It invokes the same private emitters as the handlers.
// ---------------------------------------------------------------------------

#[doc(hidden)]
pub fn seismograph_probe(
    risks: &[Risk],
    revocations: &[Revocation],
    volume: &[KindCount],
    worst_signals: &[Signal],
    subject: &str,
    subject_signals: &[Signal],
    now: i64,
) -> BTreeMap<&'static str, String> {
    let overview: Vec<&Risk> = risks.iter().take(8).collect();
    let worst_trace = reconstruct_trace(worst_signals);
    let subject_trace = reconstruct_trace(subject_signals);
    let index_kind_dash = build_kind_dash(volume.iter().map(|item| item.kind.as_str()));
    let user_kind_dash = build_kind_dash(subject_trace.iter().map(|point| point.kind.as_str()));
    let baseline = build_baseline(subject_signals, now, None);

    let roster_rows = render_roster_rows(&overview);
    let roster_cards = render_roster_cards(&overview);
    let endpoint_legend = render_endpoint_legend(&overview);
    let decision_rail = render_decision_rail(revocations);

    let index_kind_dash_text = mapping_text(
        volume.iter().map(|item| item.kind.as_str()),
        &index_kind_dash,
    );
    let user_kind_dash_text = mapping_text(
        subject_trace.iter().map(|point| point.kind.as_str()),
        &user_kind_dash,
    );

    let mut probe = BTreeMap::new();
    probe.insert(
        "readout",
        render_readout(
            risks,
            (worst_signals.len() + subject_signals.len()) as i64,
            now,
        ),
    );
    probe.insert(
        "seismograph_svg",
        render_seismograph(&worst_trace, &index_kind_dash, now),
    );
    probe.insert("roster_rows", roster_rows);
    probe.insert("roster_cards", roster_cards);
    probe.insert("endpoint_legend", endpoint_legend);
    probe.insert("decision_rail", decision_rail);
    probe.insert("volume", render_volume(volume, &index_kind_dash));
    probe.insert(
        "verdict",
        render_verdict(
            subject,
            risks.first(),
            subject_trace
                .last()
                .map(|point| join_reasons(&point.reasons))
                .as_deref()
                .unwrap_or("no signals recorded yet"),
        ),
    );
    probe.insert(
        "orbit_svg",
        render_orbit(&subject_trace, &baseline, &user_kind_dash, now),
    );
    probe.insert(
        "deviation_ledger_rows",
        render_deviation_ledger_rows(&subject_trace, &user_kind_dash),
    );
    probe.insert(
        "signal_history_rows",
        render_signal_history_rows(&subject_trace, &user_kind_dash),
    );
    probe.insert("index_kind_dash", index_kind_dash_text);
    probe.insert("user_kind_dash", user_kind_dash_text);
    probe
}

fn mapping_text<'a>(kinds: impl IntoIterator<Item = &'a str>, mapping: &KindDash) -> String {
    let mut seen = HashMap::<&str, ()>::new();
    kinds
        .into_iter()
        .filter(|kind| seen.insert(*kind, ()).is_none())
        .map(|kind| format!("{kind}:{}", dash_for(mapping, kind)))
        .collect::<Vec<_>>()
        .join("|")
}
