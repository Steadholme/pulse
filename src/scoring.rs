//! Pure, deterministic risk scoring.
//!
//! Scoring is a pure function of two values: a [`Baseline`] (what Pulse has learned about a
//! subject from history) and a [`Candidate`] (the event being scored). It returns a bounded
//! `0..=100` score, a `low`/`medium`/`high` level, and a human list of reasons. No I/O, no clock,
//! no randomness — so the same inputs always yield the same output, and the whole module is
//! trivially unit-testable. The store derives the [`Baseline`] from the `signals` history; the
//! poller and `POST /api/score` both call [`assess`].
//!
//! Philosophy: deviation is only meaningful relative to an established baseline. On a cold start
//! (no prior history, or no prior IPs/UAs/hours observed) a "new" IP/UA/hour is NOT penalised — we
//! cannot deviate from nothing — so a brand-new user is never spuriously flagged high. The signals
//! that DO drive a cold-start score are intrinsic to the event itself (a failed auth) and the
//! recent failure / burst counts the caller passes in.

use std::collections::BTreeSet;

/// Score at/above which a subject is `high` risk (records a revocation + emits an audit event).
pub const HIGH_THRESHOLD: f64 = 70.0;
/// Score at/above which a subject is `medium` risk.
pub const MEDIUM_THRESHOLD: f64 = 40.0;

/// Minimum prior-history length before "off-hours" deviation is considered meaningful.
const MIN_HISTORY_FOR_HOURS: usize = 5;

// Additive weights (points). Tuned so a single strong novelty lands in `medium`, and a novelty
// stacked with active failures/bursts crosses into `high`.
const W_NEW_IP: f64 = 40.0;
const W_NEW_UA: f64 = 20.0;
const W_OFF_HOURS: f64 = 15.0;
const W_FAILURE_KIND: f64 = 25.0;
const W_PER_RECENT_FAILURE: f64 = 8.0;
const CAP_RECENT_FAILURE: f64 = 40.0;
const W_PER_BURST_EVENT: f64 = 6.0;
const CAP_BURST: f64 = 30.0;
/// Burst is only penalised beyond this many events in the burst window (normal logins are fine).
const BURST_FREE: usize = 3;

/// What Pulse has learned about a subject from its `signals` history. Derived by the store; pure
/// input to [`assess`].
#[derive(Clone, Debug, Default)]
pub struct Baseline {
    /// Distinct non-empty source IPs seen historically.
    pub known_ips: BTreeSet<String>,
    /// Distinct non-empty user-agents seen historically.
    pub known_uas: BTreeSet<String>,
    /// Distinct hours-of-day (0..=23, UTC) the subject has been active.
    pub active_hours: BTreeSet<u8>,
    /// Total prior signals recorded for the subject.
    pub history_len: usize,
    /// Failure signals within the recent window (caller-defined; e.g. last hour).
    pub recent_failures: usize,
    /// Total signals within the burst window (caller-defined; e.g. last few minutes).
    pub recent_events: usize,
}

/// The event being scored.
#[derive(Clone, Debug, Default)]
pub struct Candidate {
    /// Event kind (e.g. `login.success`, `login.failure`, `webauthn.assertion`).
    pub kind: String,
    /// Source IP, or empty when telemetry did not carry one.
    pub ip: String,
    /// User-agent, or empty when telemetry did not carry one.
    pub ua: String,
    /// Hour-of-day (0..=23, UTC) of the event, or `None` when unknown.
    pub hour: Option<u8>,
}

/// The computed assessment.
#[derive(Clone, Debug)]
pub struct Assessment {
    /// Bounded `0.0..=100.0`.
    pub score: f64,
    /// `low` | `medium` | `high`.
    pub level: String,
    /// Ordered, human-readable contributing reasons (empty when nothing stood out).
    pub reasons: Vec<String>,
}

impl Assessment {
    /// Convenience: is this a `high` assessment (the revoke/notify trigger)?
    pub fn is_high(&self) -> bool {
        self.level == "high"
    }
}

/// Map a bounded score to its level. Single source of truth for the thresholds.
pub fn level_for(score: f64) -> &'static str {
    if score >= HIGH_THRESHOLD {
        "high"
    } else if score >= MEDIUM_THRESHOLD {
        "medium"
    } else {
        "low"
    }
}

/// Score `candidate` against `baseline`. Pure + deterministic; bounded `0..=100`.
pub fn assess(baseline: &Baseline, candidate: &Candidate) -> Assessment {
    let mut score = 0.0f64;
    let mut reasons: Vec<String> = Vec::new();

    let kind = candidate.kind.trim();
    let is_failure = kind == "login.failure" || kind.ends_with(".failure");

    // 1. A failed auth is intrinsically suspicious, independent of any baseline.
    if is_failure {
        score += W_FAILURE_KIND;
        reasons.push("authentication failure".to_string());
    }

    // 2. New source IP — only meaningful once we have a baseline of known IPs.
    let ip = candidate.ip.trim();
    if !ip.is_empty() && !baseline.known_ips.is_empty() && !baseline.known_ips.contains(ip) {
        score += W_NEW_IP;
        reasons.push(format!("new source IP {ip}"));
    }

    // 3. New user-agent — likewise needs an established UA baseline.
    let ua = candidate.ua.trim();
    if !ua.is_empty() && !baseline.known_uas.is_empty() && !baseline.known_uas.contains(ua) {
        score += W_NEW_UA;
        reasons.push("new device / user-agent".to_string());
    }

    // 4. Off-hours — only once we have enough history to know the subject's normal hours.
    if let Some(h) = candidate.hour {
        if baseline.history_len >= MIN_HISTORY_FOR_HOURS
            && !baseline.active_hours.is_empty()
            && !baseline.active_hours.contains(&h)
        {
            score += W_OFF_HOURS;
            reasons.push(format!("off-hours activity ({h:02}:00 UTC)"));
        }
    }

    // 5. Repeated recent failures (credential stuffing / brute force).
    if baseline.recent_failures > 0 {
        let pts = (baseline.recent_failures as f64 * W_PER_RECENT_FAILURE).min(CAP_RECENT_FAILURE);
        score += pts;
        reasons.push(format!(
            "{} recent failed attempt(s)",
            baseline.recent_failures
        ));
    }

    // 6. Burst: an abnormal number of events in a short window.
    if baseline.recent_events > BURST_FREE {
        let over = baseline.recent_events - BURST_FREE;
        let pts = (over as f64 * W_PER_BURST_EVENT).min(CAP_BURST);
        score += pts;
        reasons.push(format!(
            "elevated activity burst ({} events)",
            baseline.recent_events
        ));
    }

    let score = score.clamp(0.0, 100.0);
    Assessment {
        score,
        level: level_for(score).to_string(),
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline_with_ips(ips: &[&str]) -> Baseline {
        Baseline {
            known_ips: ips.iter().map(|s| s.to_string()).collect(),
            history_len: ips.len(),
            ..Baseline::default()
        }
    }

    #[test]
    fn cold_start_is_low_even_with_novel_fields() {
        // No history at all: a brand-new IP/UA/hour cannot be a "deviation".
        let b = Baseline::default();
        let c = Candidate {
            kind: "login.success".to_string(),
            ip: "203.0.113.9".to_string(),
            ua: "Mozilla/5.0".to_string(),
            hour: Some(3),
        };
        let a = assess(&b, &c);
        assert_eq!(a.score, 0.0);
        assert_eq!(a.level, "low");
        assert!(a.reasons.is_empty());
    }

    #[test]
    fn known_ip_success_is_low() {
        let b = baseline_with_ips(&["10.0.0.1"]);
        let c = Candidate {
            kind: "login.success".to_string(),
            ip: "10.0.0.1".to_string(),
            ..Candidate::default()
        };
        let a = assess(&b, &c);
        assert_eq!(a.score, 0.0);
        assert_eq!(a.level, "low");
    }

    #[test]
    fn new_ip_alone_is_medium() {
        let b = baseline_with_ips(&["10.0.0.1"]);
        let c = Candidate {
            kind: "login.success".to_string(),
            ip: "198.51.100.7".to_string(),
            ..Candidate::default()
        };
        let a = assess(&b, &c);
        assert_eq!(a.score, W_NEW_IP);
        assert_eq!(a.level, "medium");
        assert!(a.reasons.iter().any(|r| r.contains("new source IP")));
    }

    #[test]
    fn new_ip_with_failures_is_high() {
        let mut b = baseline_with_ips(&["10.0.0.1"]);
        b.recent_failures = 3;
        let c = Candidate {
            kind: "login.failure".to_string(),
            ip: "198.51.100.7".to_string(),
            ..Candidate::default()
        };
        let a = assess(&b, &c);
        // failure(25) + new_ip(35) + 3*8=24 -> 84
        assert!(a.score >= HIGH_THRESHOLD, "score was {}", a.score);
        assert_eq!(a.level, "high");
        assert!(a.is_high());
    }

    #[test]
    fn score_is_bounded_to_100() {
        let mut b = baseline_with_ips(&["10.0.0.1"]);
        b.known_uas.insert("known-ua".to_string());
        b.active_hours.insert(9);
        b.history_len = 50;
        b.recent_failures = 100;
        b.recent_events = 100;
        let c = Candidate {
            kind: "login.failure".to_string(),
            ip: "198.51.100.7".to_string(),
            ua: "evil".to_string(),
            hour: Some(3),
        };
        let a = assess(&b, &c);
        assert!(a.score <= 100.0);
        assert_eq!(a.level, "high");
    }

    #[test]
    fn off_hours_needs_enough_history() {
        // Too little history: off-hours is not yet meaningful.
        let mut b = Baseline {
            active_hours: [9u8, 10, 11].into_iter().collect(),
            history_len: 3,
            ..Baseline::default()
        };
        let c = Candidate {
            kind: "login.success".to_string(),
            hour: Some(3),
            ..Candidate::default()
        };
        assert_eq!(assess(&b, &c).score, 0.0);
        // Enough history: now off-hours counts.
        b.history_len = MIN_HISTORY_FOR_HOURS;
        assert_eq!(assess(&b, &c).score, W_OFF_HOURS);
    }

    #[test]
    fn level_thresholds() {
        assert_eq!(level_for(0.0), "low");
        assert_eq!(level_for(39.9), "low");
        assert_eq!(level_for(40.0), "medium");
        assert_eq!(level_for(69.9), "medium");
        assert_eq!(level_for(70.0), "high");
        assert_eq!(level_for(100.0), "high");
    }
}
