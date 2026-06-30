//! HTTP handlers + shared server-render helpers.
//!
//! `health` is the unauthenticated liveness probe; `dashboard` carries the SSO risk views;
//! `api` is the service-token live-scoring surface.
//!
//! The shared design tokens / CSS are embedded (via `include_str!`) and inlined into every page,
//! matching the HOLDFAST enterprise brand (the Keystone/inkwell look): dark command-center palette,
//! brand gradient, indigo accent, status colors, cards, app-bar.

pub mod api;
pub mod dashboard;
pub mod health;

use axum::http::StatusCode;

/// Embedded design system, inlined into each rendered page's `<style>`.
pub const APP_CSS: &str = include_str!("../../static/app.css");

/// Cross-subdomain gateway logout (Pulse lives at risk.w33d.xyz; the IdP is at id.w33d.xyz).
pub const LOGOUT_URL: &str = "https://id.w33d.xyz/_gw/auth/logout";

/// The HOLDFAST shield glyph (small, for the app-bar brand lockup).
pub const SHIELD_SVG: &str = r##"<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="hf-shield-sm" x1="8" y1="4" x2="40" y2="44" gradientUnits="userSpaceOnUse"><stop stop-color="#818CF8"/><stop offset="1" stop-color="#4F46E5"/></linearGradient></defs><path d="M24 4 8 9.5V22c0 11 7 17.4 16 21.5C33 39.4 40 33 40 22V9.5L24 4Z" fill="url(#hf-shield-sm)"/><rect x="20" y="19" width="8" height="13" rx="1" fill="#fff" fill-opacity="0.92"/><path d="M20 19v-2.5a4 4 0 0 1 8 0V19" stroke="#fff" stroke-width="2" stroke-opacity="0.92" fill="none"/></svg>"##;

/// Minimal HTML escaping for text/attribute interpolation (defense-in-depth on every field).
pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Render the shared app-bar: shield + HOLDFAST wordmark on the left; the page title, an "All apps"
/// link back to the apex portal, the signed-in operator chip (avatar initial + email), and a Logout
/// link to the gateway on the right. The chip is omitted when no identity is known (e.g. the error
/// page), leaving just the All-apps link — matching the estate-wide chrome (see sanctum::userbox).
pub fn topbar(page_title: &str, email: &str) -> String {
    let chip = if email.is_empty() || email == "—" {
        String::new()
    } else {
        let initial = email
            .chars()
            .next()
            .map(|c| c.to_uppercase().to_string())
            .unwrap_or_else(|| "H".to_string());
        format!(
            "<span class=\"userchip\"><span class=\"userchip__avatar\" aria-hidden=\"true\">{}</span><span class=\"user-email\">{}</span></span>",
            esc(&initial),
            esc(email),
        )
    };
    format!(
        r#"<header class="topbar">
  <div class="topbar__inner">
    <a class="brand" href="/" aria-label="HOLDFAST Pulse">
      <span class="brand__glyph" aria-hidden="true">{shield}</span>
      <span class="brand__word">HOLDFAST</span>
    </a>
    <div class="topbar__right">
      <span class="topbar__title">{title}</span>
      <a class="allapps" href="https://w33d.xyz" title="All apps"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>All apps</a>
      {chip}
      <a class="btn btn-ghost btn-sm" href="{logout}">Log out</a>
    </div>
  </div>
</header>"#,
        shield = SHIELD_SVG,
        title = esc(page_title),
        chip = chip,
        logout = LOGOUT_URL,
    )
}

/// A risk-level pill (`low` / `medium` / `high` -> branded badge). Unknown levels render neutral.
pub fn level_badge(level: &str) -> String {
    let class = match level {
        "high" => "badge badge-high",
        "medium" => "badge badge-medium",
        "low" => "badge badge-low",
        _ => "badge",
    };
    format!(
        r#"<span class="{class}">{label}</span>"#,
        class = class,
        label = esc(level)
    )
}

/// Format epoch seconds as a compact UTC stamp `Mon D, YYYY HH:MM` (e.g. `Jun 30, 2026 14:05`).
pub fn fmt_ts(secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!(
            "{} {}, {} {:02}:{:02}",
            month_abbr(dt.month()),
            dt.day(),
            dt.year(),
            dt.hour(),
            dt.minute()
        ),
        Err(_) => secs.to_string(),
    }
}

fn month_abbr(m: time::Month) -> &'static str {
    use time::Month::*;
    match m {
        January => "Jan",
        February => "Feb",
        March => "Mar",
        April => "Apr",
        May => "May",
        June => "Jun",
        July => "Jul",
        August => "Aug",
        September => "Sep",
        October => "Oct",
        November => "Nov",
        December => "Dec",
    }
}

/// A small, branded HTML error page (used by [`crate::error::AppError`]).
pub fn error_page(status: StatusCode, message: &str) -> String {
    let code = status.as_u16();
    let reason = status.canonical_reason().unwrap_or("Error");
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>{code} {reason} · Pulse</title><style>{css}</style></head>
<body class="page-console">
{topbar}
<main class="console">
  <div class="error-card">
    <div class="error-card__code">{code}</div>
    <h1 class="error-card__title">{reason}</h1>
    <p class="error-card__msg">{msg}</p>
    <a class="btn btn-primary" href="/">Back to the dashboard</a>
  </div>
</main>
</body></html>"#,
        css = APP_CSS,
        topbar = topbar("Pulse", "—"),
        code = code,
        reason = esc(reason),
        msg = esc(message),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esc_blocks_html() {
        assert_eq!(esc("<b>&\"'"), "&lt;b&gt;&amp;&quot;&#x27;");
    }

    #[test]
    fn level_badge_classes() {
        assert!(level_badge("high").contains("badge-high"));
        assert!(level_badge("low").contains("badge-low"));
        assert!(level_badge("weird").contains(r#"class="badge""#));
    }
}
