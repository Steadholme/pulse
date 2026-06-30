//! Dependency-light outbound HTTP/1.1 over a raw `tokio::net::TcpStream`.
//!
//! Pulse talks to two internal, plaintext services on the `holdfast` Docker network: it GETs the
//! Watchtower audit feed (the poller) and best-effort POSTs a Klaxon step-up notification. Both hops
//! are internal `http://`, so rather than pull in a full HTTP client (and a TLS stack) we keep the
//! estate's dependency-light approach — the same one the audit emitter and portal use.
//!
//! RESILIENCE IS THE CONTRACT: every failure (DNS, connect, timeout, malformed response) collapses
//! to `None`/`Err` that the caller treats as "skip this cycle" — a down backend never panics, hangs,
//! or fails anything but the one best-effort call.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Cap on the buffered response body (the audit feed is small; this only bounds a misbehaving peer).
const MAX_BODY: usize = 4 * 1_048_576; // 4 MiB

/// A parsed `http://host[:port]/path` target. Only plain `http` is accepted (internal hops).
struct Url {
    host: String,
    port: u16,
    authority: String,
    path: String,
}

fn parse_url(url: &str) -> Option<Url> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()?),
        None => (authority.to_string(), 80u16),
    };
    if host.is_empty() {
        return None;
    }
    Some(Url {
        host,
        port,
        authority: authority.to_string(),
        path: if path.is_empty() { "/".to_string() } else { path.to_string() },
    })
}

/// `GET url`, returning the response BODY as a string, or `None` on ANY failure. `timeout` bounds
/// the whole connect + write + read.
pub async fn get(url: &str, timeout: Duration) -> Option<String> {
    match tokio::time::timeout(timeout, get_inner(url)).await {
        Ok(Ok(body)) => Some(body),
        Ok(Err(e)) => {
            tracing::warn!(url = %url, error = %e, "GET failed — skipping");
            None
        }
        Err(_) => {
            tracing::warn!(url = %url, "GET timed out — skipping");
            None
        }
    }
}

async fn get_inner(url: &str) -> std::io::Result<String> {
    let u = parse_url(url).ok_or_else(|| io_err("invalid URL"))?;
    let mut stream = TcpStream::connect((u.host.as_str(), u.port)).await?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: pulse/0.1\r\n\
         Accept: application/json\r\nConnection: close\r\n\r\n",
        path = u.path,
        authority = u.authority,
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;
    let raw = read_to_cap(&mut stream).await?;
    split_body(&raw)
}

/// `POST url` with a JSON body and a bearer token. Best-effort: returns the response status, or
/// `None` on any failure. Bounded by `timeout`.
pub async fn post_json(
    url: &str,
    bearer: &str,
    body: &str,
    timeout: Duration,
) -> Option<u16> {
    match tokio::time::timeout(timeout, post_inner(url, bearer, body)).await {
        Ok(Ok(status)) => Some(status),
        Ok(Err(e)) => {
            tracing::warn!(url = %url, error = %e, "POST failed — skipping");
            None
        }
        Err(_) => {
            tracing::warn!(url = %url, "POST timed out — skipping");
            None
        }
    }
}

async fn post_inner(url: &str, bearer: &str, body: &str) -> std::io::Result<u16> {
    let u = parse_url(url).ok_or_else(|| io_err("invalid URL"))?;
    let mut stream = TcpStream::connect((u.host.as_str(), u.port)).await?;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer {bearer}\r\n\
         Content-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        path = u.path,
        authority = u.authority,
        len = body.len(),
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;
    let raw = read_to_cap(&mut stream).await?;
    parse_status(&raw).ok_or_else(|| io_err("no HTTP status line"))
}

async fn read_to_cap(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut acc: Vec<u8> = Vec::with_capacity(4096);
    let mut buf = [0u8; 8192];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        acc.extend_from_slice(&buf[..n]);
        if acc.len() > MAX_BODY {
            break;
        }
    }
    Ok(acc)
}

/// Split a raw HTTP response into its body (bytes after the first blank line), lossy-UTF8.
fn split_body(raw: &[u8]) -> std::io::Result<String> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io_err("no HTTP header terminator"))?;
    Ok(String::from_utf8_lossy(&raw[sep + 4..]).into_owned())
}

fn parse_status(buf: &[u8]) -> Option<u16> {
    let line_end = buf.iter().position(|&b| b == b'\n').unwrap_or(buf.len());
    let line = std::str::from_utf8(&buf[..line_end]).ok()?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn io_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_variants() {
        let u = parse_url("http://watchtower:8500/api/events?limit=50").unwrap();
        assert_eq!(u.host, "watchtower");
        assert_eq!(u.port, 8500);
        assert_eq!(u.path, "/api/events?limit=50");
        let u = parse_url("http://klaxon").unwrap();
        assert_eq!(u.port, 80);
        assert_eq!(u.path, "/");
        assert!(parse_url("https://x").is_none());
        assert!(parse_url("watchtower:8500").is_none());
    }

    #[test]
    fn split_body_after_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[1,2,3]";
        assert_eq!(split_body(raw).unwrap(), "[1,2,3]");
    }

    #[test]
    fn parse_status_reads_code() {
        assert_eq!(parse_status(b"HTTP/1.1 201 Created\r\n\r\n"), Some(201));
        assert_eq!(parse_status(b"garbage"), None);
    }
}
