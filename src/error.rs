//! Error type + responses.
//!
//! Dashboard (HTML) failures render a small branded error page; the `/api/score` machine path
//! returns a JSON envelope instead. One enum mirrors the keystone/inkwell/relay error seam.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Json, Response};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    /// Malformed/incomplete request input.
    #[error("invalid_request: {0}")]
    InvalidRequest(String),

    /// No gateway-injected identity, a failed CSRF check, or a bad service token.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// No such subject / resource.
    #[error("not_found: {0}")]
    NotFound(String),

    /// Unexpected internal failure (store I/O).
    #[error("server_error: {0}")]
    Internal(String),
}

impl AppError {
    fn parts(&self) -> (StatusCode, String, bool) {
        match self {
            AppError::InvalidRequest(d) => (StatusCode::BAD_REQUEST, d.clone(), false),
            AppError::Unauthorized(d) => (StatusCode::UNAUTHORIZED, d.clone(), true),
            AppError::NotFound(d) => (StatusCode::NOT_FOUND, d.clone(), false),
            AppError::Internal(d) => (StatusCode::INTERNAL_SERVER_ERROR, d.clone(), false),
        }
    }

    /// Render this error as a JSON envelope (used by `/api/score`).
    pub fn into_json(self) -> Response {
        let (status, description, www_authenticate) = self.parts();
        let mut resp = (
            status,
            Json(json!({ "error": { "message": description, "code": status.as_u16() } })),
        )
            .into_response();
        if www_authenticate {
            resp.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        resp
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, description, www_authenticate) = self.parts();
        let body = crate::handlers::error_page(status, &description);
        let mut response = (status, Html(body)).into_response();
        if www_authenticate {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}

/// Store failures collapse to a 500.
impl From<crate::store::StoreError> for AppError {
    fn from(e: crate::store::StoreError) -> Self {
        match e {
            crate::store::StoreError::Backend(m) => AppError::Internal(m),
        }
    }
}
