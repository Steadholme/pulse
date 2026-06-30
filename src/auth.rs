//! Two authentication surfaces + double-submit CSRF, split at the Sluice gateway.
//!
//! - The DASHBOARD (`risk.w33d.xyz/`, `/user/{sub}`) is `auth=sso`: the gateway runs the OIDC
//!   browser login against Keystone, STRIPS any inbound `X-Auth-*`, and injects the verified
//!   `X-Auth-Subject` / `X-Auth-Email` / `X-Auth-Scope`. Pulse is internal-only, so it TRUSTS those
//!   headers as the signed-in operator. Pulse never logs anyone in itself.
//!
//! - `POST /api/score` is `auth=public` at the gateway — a service-to-service caller (Keystone at
//!   login time) cannot speak the browser OIDC/cookie SSO — so Pulse does its OWN bearer auth there
//!   against the fixed `PULSE_SERVICE_TOKEN`, compared in constant time. An unset token fails CLOSED
//!   (every call rejected), never open.
//!
//! State-changing dashboard POSTs would carry a double-submit CSRF token (a random `__Host-csrf`
//! cookie that must equal a hidden form field). v1's dashboard is read-only, but the primitives are
//! here and used by the estate-standard pattern, so any future action is protected by construction.

use axum::http::{header, HeaderMap};

use crate::error::AppError;

pub const HEADER_SUBJECT: &str = "x-auth-subject";
pub const HEADER_EMAIL: &str = "x-auth-email";
pub const HEADER_SCOPE: &str = "x-auth-scope";

/// Double-submit CSRF cookie. `__Host-` prefix => Secure + Path=/ + no Domain, so the browser only
/// ever returns it over TLS to this exact host.
pub const CSRF_COOKIE: &str = "__Host-csrf";
/// CSRF cookie lifetime, seconds.
const CSRF_TTL: u64 = 3600;

/// The signed-in operator's subject (stable user id), if the gateway injected one.
pub fn operator_sub(headers: &HeaderMap) -> Option<String> {
    header_value(headers, HEADER_SUBJECT)
}

/// The signed-in operator's email, if the gateway injected one.
pub fn operator_email(headers: &HeaderMap) -> Option<String> {
    header_value(headers, HEADER_EMAIL)
}

/// The operator's email for display, falling back to a neutral label when unauthenticated (e.g. a
/// local `cargo run` with no gateway session).
pub fn display_email(headers: &HeaderMap) -> String {
    operator_email(headers).unwrap_or_else(|| "—".to_string())
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// Service token (/api/score bearer)
// ---------------------------------------------------------------------------

/// Parse the token from `Authorization: Bearer <token>`, if present and non-empty.
pub fn parse_bearer(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?
        .trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// Require a valid `PULSE_SERVICE_TOKEN` bearer on `/api/score`. Fails CLOSED when the configured
/// token is empty (the endpoint is unusable until an operator sets a token) and on any mismatch.
pub fn require_service_token(headers: &HeaderMap, configured: &str) -> Result<(), AppError> {
    if configured.is_empty() {
        return Err(AppError::Unauthorized(
            "scoring endpoint disabled (PULSE_SERVICE_TOKEN unset)".to_string(),
        ));
    }
    let presented = parse_bearer(headers)
        .ok_or_else(|| AppError::Unauthorized("missing bearer service token".to_string()))?;
    if ct_eq(presented.as_bytes(), configured.as_bytes()) {
        Ok(())
    } else {
        Err(AppError::Unauthorized("invalid service token".to_string()))
    }
}

// ---------------------------------------------------------------------------
// Cookies + CSRF (double-submit)
// ---------------------------------------------------------------------------

/// Read a single cookie value from the request's `Cookie` header(s).
pub fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for hv in headers.get_all(header::COOKIE).iter() {
        let Ok(raw) = hv.to_str() else { continue };
        for pair in raw.split(';') {
            let pair = pair.trim();
            if let Some((k, v)) = pair.split_once('=') {
                if k.trim() == name {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

/// `Set-Cookie` value for the (JS-readable) CSRF cookie.
pub fn csrf_cookie(value: &str) -> String {
    format!("{CSRF_COOKIE}={value}; Path=/; Secure; SameSite=Lax; Max-Age={CSRF_TTL}")
}

/// Mint a fresh CSRF token: 32 CSPRNG bytes, hex-encoded.
pub fn new_csrf_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable");
    hex::encode(bytes)
}

/// Resolve the CSRF token for this render's forms. Reuses the existing cookie token when present
/// (stable across pages/tabs); otherwise mints one and returns the matching `Set-Cookie`.
pub fn ensure_csrf(headers: &HeaderMap) -> (String, Option<String>) {
    match get_cookie(headers, CSRF_COOKIE) {
        Some(c) if !c.is_empty() => (c, None),
        _ => {
            let token = new_csrf_token();
            let set = csrf_cookie(&token);
            (token, Some(set))
        }
    }
}

/// Double-submit check: the `submitted` form token must equal the `__Host-csrf` cookie.
pub fn verify_csrf(headers: &HeaderMap, submitted: &str) -> Result<(), AppError> {
    let ok = match get_cookie(headers, CSRF_COOKIE) {
        Some(cookie) if !cookie.is_empty() => ct_eq(cookie.as_bytes(), submitted.as_bytes()),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(AppError::Unauthorized("CSRF token mismatch".to_string()))
    }
}

/// Length-checked constant-time byte comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_token_fails_closed_when_unset() {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Bearer anything".parse().unwrap());
        assert!(require_service_token(&h, "").is_err());
    }

    #[test]
    fn service_token_matches_and_rejects() {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Bearer s3cret".parse().unwrap());
        assert!(require_service_token(&h, "s3cret").is_ok());
        assert!(require_service_token(&h, "other").is_err());
        assert!(require_service_token(&HeaderMap::new(), "s3cret").is_err());
    }

    #[test]
    fn csrf_token_is_random_and_hex() {
        let a = new_csrf_token();
        let b = new_csrf_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn csrf_double_submit_matches_and_rejects() {
        let token = new_csrf_token();
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            format!("{CSRF_COOKIE}={token}").parse().unwrap(),
        );
        assert!(verify_csrf(&headers, &token).is_ok());
        assert!(verify_csrf(&headers, "nope").is_err());
        assert!(verify_csrf(&HeaderMap::new(), &token).is_err());
    }

    #[test]
    fn operator_identity_reads_gateway_headers() {
        let mut h = HeaderMap::new();
        h.insert(HEADER_SUBJECT, "u_admin".parse().unwrap());
        h.insert(HEADER_EMAIL, "a@w33d.xyz".parse().unwrap());
        assert_eq!(operator_sub(&h).as_deref(), Some("u_admin"));
        assert_eq!(display_email(&h), "a@w33d.xyz");
        assert_eq!(display_email(&HeaderMap::new()), "—");
    }
}
