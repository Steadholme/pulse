//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so the
//! in-memory dev path boots with NO configuration and NO database — exactly like
//! keystone/inkwell/relay. Production overrides each via the environment. Secrets (the
//! `/api/score` service token, the audit ingest token, the Klaxon token) are resolved here from
//! the environment and held only in this read-only `Config`, never logged.

/// Default listen address (all interfaces, internal-only port 9300).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9300";

/// Default internal Watchtower base URL the poller reads the audit feed from.
pub const DEFAULT_WATCHTOWER_URL: &str = "http://watchtower:8500";

/// Default poll cadence (seconds) for the Watchtower telemetry poller.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 30;

/// Default cap on how many recent events the poller pulls per cycle (`?limit=N`).
pub const DEFAULT_EVENT_LIMIT: usize = 200;

/// Hard cap on rows the dashboard renders (current risk table + recent revocations).
pub const DASHBOARD_LIMIT: usize = 100;
/// Hard cap on signal rows the per-user view renders.
pub const USER_SIGNAL_LIMIT: usize = 200;
/// Hard cap on signals used to reconstruct the featured identity seismograph trace.
pub const SEISMO_TRACE_LIMIT: usize = 120;

/// Optional Klaxon step-up notification target.
#[derive(Clone, Debug)]
pub struct Klaxon {
    /// Full notify endpoint URL (e.g. `http://klaxon:8900/api/notify`).
    pub url: String,
    /// Bearer ingest token Klaxon requires.
    pub token: String,
}

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// Internal Watchtower base URL the poller reads from (`WATCHTOWER_URL`).
    pub watchtower_url: String,
    /// Whether the background poller runs (`PULSE_POLL_ENABLED`, default on).
    pub poll_enabled: bool,
    /// Poll cadence in seconds (`PULSE_POLL_INTERVAL_SECS`).
    pub poll_interval_secs: u64,
    /// Per-cycle event pull cap (`PULSE_EVENT_LIMIT`).
    pub event_limit: usize,
    /// Bearer token guarding `POST /api/score` (`PULSE_SERVICE_TOKEN`). Empty disables the
    /// endpoint (every call is rejected) — fail closed, never open.
    pub service_token: String,
    /// Optional Klaxon step-up notification target (`KLAXON_URL` + `KLAXON_TOKEN`).
    pub klaxon: Option<Klaxon>,
}

impl Config {
    /// Default development configuration (in-memory friendly, no database, no secrets).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            watchtower_url: DEFAULT_WATCHTOWER_URL.to_string(),
            poll_enabled: true,
            poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
            event_limit: DEFAULT_EVENT_LIMIT,
            service_token: String::new(),
            klaxon: None,
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        if let Some(v) = env_nonempty("WATCHTOWER_URL") {
            config.watchtower_url = v.trim_end_matches('/').to_string();
        }
        if let Some(v) = env_nonempty("PULSE_POLL_ENABLED") {
            config.poll_enabled = truthy(&v);
        }
        if let Some(v) =
            env_nonempty("PULSE_POLL_INTERVAL_SECS").and_then(|v| v.parse::<u64>().ok())
        {
            if v > 0 {
                config.poll_interval_secs = v;
            }
        }
        if let Some(v) = env_nonempty("PULSE_EVENT_LIMIT").and_then(|v| v.parse::<usize>().ok()) {
            if v > 0 {
                config.event_limit = v;
            }
        }
        if let Some(v) = env_nonempty("PULSE_SERVICE_TOKEN") {
            config.service_token = v;
        }
        match (env_nonempty("KLAXON_URL"), env_nonempty("KLAXON_TOKEN")) {
            (Some(url), Some(token)) => config.klaxon = Some(Klaxon { url, token }),
            _ => config.klaxon = None,
        }
        config
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::dev()
    }
}

/// Interpret a boolean-ish env value (`on`/`true`/`1`/`yes`, case-insensitive). Unknown -> false.
pub fn truthy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "on" | "true" | "1" | "yes"
    )
}

/// Read an env var, returning `None` when unset OR empty (empty never clobbers a default).
pub fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_defaults_boot_zero_config() {
        let c = Config::dev();
        assert_eq!(c.bind_addr, DEFAULT_BIND_ADDR);
        assert_eq!(c.watchtower_url, DEFAULT_WATCHTOWER_URL);
        assert!(c.poll_enabled);
        assert_eq!(c.event_limit, DEFAULT_EVENT_LIMIT);
        assert!(c.service_token.is_empty());
        assert!(c.klaxon.is_none());
    }

    #[test]
    fn truthy_variants() {
        for v in ["on", "TRUE", "1", "Yes"] {
            assert!(truthy(v));
        }
        for v in ["off", "0", "no", ""] {
            assert!(!truthy(v));
        }
    }
}
