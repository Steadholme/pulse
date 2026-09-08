//! Identity Seismograph SSR, authority, bounded-read, and hostile-input contracts.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use pulse::config::{Config, SEISMO_TRACE_LIMIT, USER_SIGNAL_LIMIT};
use pulse::handlers::dashboard::seismograph_probe;
use pulse::store::{InMemoryStore, KindCount, Revocation, Risk, Signal, Store, StoreError};
use pulse::{app, AppState};
use tower::ServiceExt;

const NOW: i64 = 1_800_000_000;

#[derive(Default)]
struct ReadCounts {
    signals_for_sub: AtomicUsize,
    get_risk: AtomicUsize,
    list_risks: AtomicUsize,
    list_revocations: AtomicUsize,
    revocations_for_sub: AtomicUsize,
    signal_count: AtomicUsize,
    signal_volume: AtomicUsize,
    signal_subjects: Mutex<Vec<String>>,
    signal_limits: Mutex<Vec<usize>>,
}

impl ReadCounts {
    fn total(&self) -> usize {
        self.signals_for_sub.load(Ordering::Relaxed)
            + self.get_risk.load(Ordering::Relaxed)
            + self.list_risks.load(Ordering::Relaxed)
            + self.list_revocations.load(Ordering::Relaxed)
            + self.revocations_for_sub.load(Ordering::Relaxed)
            + self.signal_count.load(Ordering::Relaxed)
            + self.signal_volume.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
struct CountingStore {
    inner: InMemoryStore,
    reads: ReadCounts,
}

#[async_trait]
impl Store for CountingStore {
    async fn record_signal(&self, signal: &Signal) -> Result<bool, StoreError> {
        self.inner.record_signal(signal).await
    }

    async fn signals_for_sub(&self, sub: &str, limit: usize) -> Vec<Signal> {
        self.reads.signals_for_sub.fetch_add(1, Ordering::Relaxed);
        self.reads
            .signal_subjects
            .lock()
            .expect("signal-subject lock")
            .push(sub.to_string());
        self.reads
            .signal_limits
            .lock()
            .expect("signal-limit lock")
            .push(limit);
        self.inner.signals_for_sub(sub, limit).await
    }

    async fn upsert_risk(&self, risk: &Risk) -> Result<(), StoreError> {
        self.inner.upsert_risk(risk).await
    }

    async fn get_risk(&self, sub: &str) -> Option<Risk> {
        self.reads.get_risk.fetch_add(1, Ordering::Relaxed);
        self.inner.get_risk(sub).await
    }

    async fn list_risks(&self, limit: usize) -> Vec<Risk> {
        self.reads.list_risks.fetch_add(1, Ordering::Relaxed);
        self.inner.list_risks(limit).await
    }

    async fn insert_revocation(&self, revocation: &Revocation) -> Result<bool, StoreError> {
        self.inner.insert_revocation(revocation).await
    }

    async fn list_revocations(&self, limit: usize) -> Vec<Revocation> {
        self.reads.list_revocations.fetch_add(1, Ordering::Relaxed);
        self.inner.list_revocations(limit).await
    }

    async fn revocations_for_sub(&self, sub: &str, limit: usize) -> Vec<Revocation> {
        self.reads
            .revocations_for_sub
            .fetch_add(1, Ordering::Relaxed);
        self.inner.revocations_for_sub(sub, limit).await
    }

    async fn signal_count(&self) -> i64 {
        self.reads.signal_count.fetch_add(1, Ordering::Relaxed);
        self.inner.signal_count().await
    }

    async fn signal_volume(&self) -> Vec<KindCount> {
        self.reads.signal_volume.fetch_add(1, Ordering::Relaxed);
        self.inner.signal_volume().await
    }
}

fn state_with_store(store: Arc<dyn Store>) -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store,
        audit: pulse::audit::AuditSink::disabled(),
    }
}

fn get_sso(path: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header("x-auth-subject", "operator")
        .header("x-auth-email", "operator@w33d.xyz")
        .body(Body::empty())
        .expect("request")
}

async fn call(state: &AppState, path: &str) -> (StatusCode, String) {
    let response = app(state.clone())
        .oneshot(get_sso(path))
        .await
        .expect("router response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 4 * 1_048_576)
        .await
        .expect("response body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn stylesheet_is_public_immutable_and_linked() {
    let state = state_with_store(Arc::new(InMemoryStore::new()));
    let response = app(state.clone())
        .oneshot(get_sso("/assets/pulse-20260908.css"))
        .await
        .expect("stylesheet response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "public, max-age=31536000, immutable"
    );
    assert_eq!(
        response
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .unwrap(),
        "nosniff"
    );
    let (_, html) = call(&state, "/").await;
    assert!(html.contains("/assets/pulse-20260908.css"));
    assert!(!html.contains("<style>"));
}

fn risk(sub: &str, score: f64, level: &str, updated_at: i64) -> Risk {
    Risk {
        sub: sub.to_string(),
        score,
        level: level.to_string(),
        reasons: format!("sentinel:{sub}"),
        updated_at,
    }
}

fn signal(id: &str, sub: &str, kind: &str, ip: &str, ua: &str, ts: i64) -> Signal {
    Signal {
        id: id.to_string(),
        sub: sub.to_string(),
        kind: kind.to_string(),
        source_ip: ip.to_string(),
        ua: ua.to_string(),
        ts,
    }
}

fn revocation(sub: &str) -> Revocation {
    Revocation {
        id: format!("rev:{sub}"),
        sub: sub.to_string(),
        reason: format!("decision:{sub}"),
        ts: NOW,
    }
}

fn volume(kind: &str, count: i64) -> KindCount {
    KindCount {
        kind: kind.to_string(),
        count,
    }
}

fn probe(
    risks: &[Risk],
    revocations: &[Revocation],
    volumes: &[KindCount],
    worst_signals: &[Signal],
    subject: &str,
    subject_signals: &[Signal],
) -> BTreeMap<&'static str, String> {
    seismograph_probe(
        risks,
        revocations,
        volumes,
        worst_signals,
        subject,
        subject_signals,
        NOW,
    )
}

fn fragment<'a>(probe: &'a BTreeMap<&str, String>, key: &str) -> &'a str {
    probe.get(key).map(String::as_str).expect("probe fragment")
}

fn occurrences(haystack: &str, needle: &str) -> usize {
    haystack.match_indices(needle).count()
}

fn attributes(fragment: &str, name: &str) -> Vec<String> {
    let prefix = format!(r#" {name}=""#);
    let mut values = Vec::new();
    let mut remaining = fragment;
    while let Some(start) = remaining.find(&prefix) {
        remaining = &remaining[start + prefix.len()..];
        let Some(end) = remaining.find('"') else {
            break;
        };
        values.push(remaining[..end].to_string());
        remaining = &remaining[end + 1..];
    }
    values
}

fn hrefs(fragment: &str) -> Vec<String> {
    attributes(fragment, "href")
        .into_iter()
        .filter(|href| href.starts_with("/user/"))
        .collect()
}

#[tokio::test]
async fn dashboard_index_makes_five_reads_and_one_signals_for_sub() {
    let store = Arc::new(CountingStore::default());
    for index in 0..12 {
        store
            .upsert_risk(&risk(
                &format!("subject-{index}"),
                100.0 - index as f64,
                "high",
                NOW - index,
            ))
            .await
            .unwrap();
    }
    store
        .record_signal(&signal(
            "s1",
            "subject-0",
            "login.failure",
            "203.0.113.9",
            "ua",
            NOW,
        ))
        .await
        .unwrap();
    let state = state_with_store(store.clone());

    let (status, _) = call(&state, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(store.reads.total(), 5);
    assert_eq!(store.reads.signals_for_sub.load(Ordering::Relaxed), 1);
    assert_eq!(
        *store.reads.signal_subjects.lock().unwrap(),
        vec!["subject-0".to_string()]
    );
    assert_eq!(
        *store.reads.signal_limits.lock().unwrap(),
        vec![SEISMO_TRACE_LIMIT]
    );
}

#[tokio::test]
async fn empty_index_makes_four_reads_and_zero_signals_for_sub() {
    let store = Arc::new(CountingStore::default());
    let state = state_with_store(store.clone());

    let (status, body) = call(&state, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("No subjects scored yet"));
    assert_eq!(store.reads.total(), 4);
    assert_eq!(store.reads.signals_for_sub.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn user_view_makes_three_reads_and_one_signals_for_sub() {
    let store = Arc::new(CountingStore::default());
    let state = state_with_store(store.clone());

    let (status, _) = call(&state, "/user/subject").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(store.reads.total(), 3);
    assert_eq!(store.reads.get_risk.load(Ordering::Relaxed), 1);
    assert_eq!(store.reads.signals_for_sub.load(Ordering::Relaxed), 1);
    assert_eq!(store.reads.revocations_for_sub.load(Ordering::Relaxed), 1);
    assert_eq!(
        *store.reads.signal_limits.lock().unwrap(),
        vec![USER_SIGNAL_LIMIT]
    );
}

#[test]
fn overview_bounded_to_top_eight() {
    let risks: Vec<Risk> = (0..12)
        .map(|index| {
            risk(
                &format!("subject-{index}"),
                100.0 - index as f64,
                "high",
                NOW,
            )
        })
        .collect();
    let rendered = probe(&risks, &[], &[], &[], "subject-0", &[]);

    assert_eq!(
        occurrences(fragment(&rendered, "roster_rows"), "class=\"roster-row\""),
        8
    );
    assert_eq!(
        occurrences(fragment(&rendered, "roster_cards"), "class=\"roster-card\""),
        8
    );
    assert_eq!(
        fragment(&rendered, "endpoint_legend")
            .matches("<li ")
            .count(),
        8
    );
    for omitted in 8..12 {
        let subject = format!("subject-{omitted}");
        assert!(!fragment(&rendered, "roster_rows").contains(&subject));
        assert!(!fragment(&rendered, "roster_cards").contains(&subject));
        assert!(!fragment(&rendered, "endpoint_legend").contains(&subject));
    }
}

#[test]
fn seismograph_emits_no_table_skeleton() {
    let subject_signal = signal("s1", "sub", "login.success", "10.0.0.1", "ua", NOW);
    let rendered = probe(
        &[risk("sub", 0.0, "low", NOW)],
        &[],
        &[volume("login.success", 1)],
        &[],
        "sub",
        &[subject_signal],
    );
    for key in [
        "roster_rows",
        "deviation_ledger_rows",
        "signal_history_rows",
    ] {
        let rows = fragment(&rendered, key);
        assert!(rows.contains("<tr"), "{key} must emit rows");
        assert!(rows.contains("<td"), "{key} must emit cells");
        for forbidden in ["<table", "<caption", "<thead", "<th", "<tbody"] {
            assert!(!rows.contains(forbidden), "{key} emitted {forbidden}");
        }
    }
}

#[test]
fn user_href_producers_all_percent_encode() {
    let sub = "a/b?x y#é%<tag>";
    let expected = "/user/a%2Fb%3Fx%20y%23%C3%A9%25%3Ctag%3E";
    let rendered = probe(
        &[risk(sub, 80.0, "high", NOW)],
        &[revocation(sub)],
        &[],
        &[],
        sub,
        &[],
    );
    for key in [
        "roster_rows",
        "roster_cards",
        "endpoint_legend",
        "decision_rail",
    ] {
        assert_eq!(hrefs(fragment(&rendered, key)), vec![expected.to_string()]);
    }
}

#[test]
fn hostile_subject_href_encoding_table() {
    for (sub, encoded) in [
        ("a/b", "a%2Fb"),
        ("a?b", "a%3Fb"),
        ("a#b", "a%23b"),
        ("a b", "a%20b"),
        ("a%b", "a%25b"),
        ("<b>", "%3Cb%3E"),
        ("é", "%C3%A9"),
        ("~.", "~."),
        ("~..", "~.."),
        ("~alice", "~alice"),
        ("~~alice", "~~alice"),
    ] {
        let rendered = probe(
            &[risk(sub, 10.0, "low", NOW)],
            &[revocation(sub)],
            &[],
            &[],
            sub,
            &[],
        );
        let expected = format!("/user/{encoded}");
        for key in [
            "roster_rows",
            "roster_cards",
            "endpoint_legend",
            "decision_rail",
        ] {
            assert_eq!(hrefs(fragment(&rendered, key)), vec![expected.clone()]);
        }
    }
}

#[test]
fn visible_text_is_html_escaped_not_url_encoded() {
    let sub = "<b>&\"'";
    let rendered = probe(
        &[risk(sub, 10.0, "low", NOW)],
        &[revocation(sub)],
        &[],
        &[],
        sub,
        &[],
    );
    let rows = fragment(&rendered, "roster_rows");
    assert!(rows.contains("&lt;b&gt;&amp;&quot;&#x27;"));
    assert!(rows.contains("/user/%3Cb%3E%26%22%27"));
    assert!(!rows.contains(">%3Cb%3E%26%22%27</a>"));
}

#[tokio::test]
async fn user_route_round_trips_every_emitted_hostile_subject() {
    let store = Arc::new(InMemoryStore::new());
    let subjects = [
        "a/b", "a?b", "a#b", "a b", "a%b", "<b>", "é", "~.", "~..", "~alice", "~~alice",
    ];
    for (index, sub) in subjects.iter().enumerate() {
        let mut seeded = risk(sub, index as f64, "low", NOW + index as i64);
        seeded.reasons = format!("roundtrip-sentinel-{index}");
        store.upsert_risk(&seeded).await.unwrap();
    }
    let state = state_with_store(store);

    for (index, sub) in subjects.iter().enumerate() {
        let rendered = probe(
            &[risk(sub, 10.0, "low", NOW)],
            &[revocation(sub)],
            &[],
            &[],
            sub,
            &[],
        );
        for key in [
            "roster_rows",
            "roster_cards",
            "endpoint_legend",
            "decision_rail",
        ] {
            let path = hrefs(fragment(&rendered, key)).pop().unwrap();
            let (status, body) = call(&state, &path).await;
            assert_eq!(status, StatusCode::OK, "route failed for {sub} from {key}");
            assert!(
                body.contains(&format!("roundtrip-sentinel-{index}")),
                "store lookup did not receive original subject {sub:?} from {key}"
            );
        }
    }
}

#[tokio::test]
async fn index_has_no_duplicate_ids() {
    let store = Arc::new(InMemoryStore::new());
    for index in 0..3 {
        store
            .upsert_risk(&risk(
                &format!("subject-{index}"),
                90.0 - index as f64,
                "high",
                NOW + index,
            ))
            .await
            .unwrap();
    }
    let state = state_with_store(store);
    let (status, body) = call(&state, "/").await;
    assert_eq!(status, StatusCode::OK);
    let ids = attributes(&body, "id");
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(ids.len(), unique.len(), "duplicate ids: {ids:?}");
}

#[test]
fn kind_dash_is_first_encounter_index_mod_four() {
    let signals: Vec<Signal> = (0..6)
        .map(|index| {
            signal(
                &format!("s{index}"),
                "sub",
                &format!("kind.{index}"),
                "",
                "",
                NOW + index,
            )
        })
        .collect();
    let volumes: Vec<KindCount> = (0..6)
        .map(|index| volume(&format!("kind.{index}"), 6 - index))
        .collect();
    let rendered = probe(&[], &[], &volumes, &signals, "sub", &signals);
    assert_eq!(
        fragment(&rendered, "index_kind_dash"),
        "kind.0:0|kind.1:1|kind.2:2|kind.3:3|kind.4:0|kind.5:1"
    );
    assert_eq!(
        fragment(&rendered, "user_kind_dash"),
        "kind.0:0|kind.1:1|kind.2:2|kind.3:3|kind.4:0|kind.5:1"
    );
}

#[test]
fn one_scoped_kind_dash_is_consumed_by_every_trace_fragment() {
    let index_signals = vec![
        signal("i1", "sub", "index.first", "", "", NOW),
        signal("i2", "sub", "index.second", "", "", NOW + 1),
    ];
    let user_signals = vec![
        signal("u1", "sub", "user.first", "", "", NOW),
        signal("u2", "sub", "user.second", "", "", NOW + 1),
    ];
    let rendered = probe(
        &[],
        &[],
        &[volume("index.first", 7), volume("index.second", 3)],
        &index_signals,
        "sub",
        &user_signals,
    );
    assert_eq!(
        fragment(&rendered, "index_kind_dash"),
        "index.first:0|index.second:1"
    );
    for key in ["seismograph_svg", "volume"] {
        let value = fragment(&rendered, key);
        assert!(value.contains("index.second"), "missing kind in {key}");
        assert!(
            value.contains("data-kind-dash=\"1\""),
            "wrong dash in {key}"
        );
    }
    assert_eq!(
        fragment(&rendered, "user_kind_dash"),
        "user.first:0|user.second:1"
    );
    for key in ["orbit_svg", "deviation_ledger_rows", "signal_history_rows"] {
        let value = fragment(&rendered, key);
        assert!(value.contains("user.second"), "missing kind in {key}");
        assert!(
            value.contains("data-kind-dash=\"1\""),
            "wrong dash in {key}"
        );
    }
}

#[test]
fn unscored_subject_never_fabricates_a_low_verdict() {
    let rendered = probe(&[], &[], &[], &[], "unknown", &[]);
    let verdict = fragment(&rendered, "verdict");
    assert!(verdict.contains("data-state=\"unscored\""));
    assert!(verdict.contains(">unscored</span>"));
    assert!(verdict.contains("No verdict yet"));
    assert!(!verdict.contains("data-level=\"low\""));
    assert!(!verdict.contains("badge-low"));
}

#[test]
fn failure_kind_can_render_low_status() {
    let failed = signal("s1", "sub", "login.failure", "", "", NOW);
    let rendered = probe(
        &[],
        &[],
        &[volume("login.failure", 1)],
        &[],
        "sub",
        &[failed],
    );
    for key in ["deviation_ledger_rows", "signal_history_rows"] {
        let value = fragment(&rendered, key);
        assert!(value.contains("login.failure"));
        assert!(value.contains("data-level=\"low\""));
        assert!(value.contains("badge-low"));
        let kind_cell = value.split("col-kind").nth(1).expect("kind cell");
        assert!(!kind_cell.split("</td>").next().unwrap().contains("badge-"));
    }
}

#[test]
fn reconstructed_trace_is_causal_and_excludes_future() {
    let signals = vec![
        signal("s1", "sub", "login.success", "10.0.0.1", "ua", NOW),
        signal("s2", "sub", "login.success", "203.0.113.9", "ua", NOW + 60),
    ];
    let rendered = probe(&[], &[], &[], &[], "sub", &signals);
    let ledger = fragment(&rendered, "deviation_ledger_rows");
    assert!(ledger.contains("data-trace-index=\"0\" data-score=\"0\""));
    assert!(ledger.contains("data-trace-index=\"1\" data-score=\"40\""));
}

#[test]
fn empty_trace_renders_an_explicit_no_claim_state() {
    let rendered = probe(&[], &[], &[], &[], "sub", &[]);
    assert!(fragment(&rendered, "seismograph_svg").contains("NO TRACE · NO CLAIM"));
    assert!(fragment(&rendered, "orbit_svg").contains("NO OBSERVATIONS"));
    assert!(fragment(&rendered, "deviation_ledger_rows").contains("No deviations"));
}

#[test]
fn flat_trace_renders_without_non_finite_geometry() {
    let signals = vec![
        signal("s1", "sub", "login.success", "10.0.0.1", "ua", NOW),
        signal("s2", "sub", "login.success", "10.0.0.1", "ua", NOW + 10),
    ];
    let rendered = probe(&[], &[], &[], &signals, "sub", &signals);
    for key in ["seismograph_svg", "orbit_svg"] {
        let svg = fragment(&rendered, key);
        assert!(!svg.contains("NaN"));
        assert!(!svg.contains("inf"));
        assert!(svg.contains("data-score=\"0\""));
    }
}

#[test]
fn single_point_trace_has_valid_centered_geometry() {
    let one = signal("s1", "sub", "login.success", "", "", NOW);
    let rendered = probe(
        &[],
        &[],
        &[],
        std::slice::from_ref(&one),
        "sub",
        std::slice::from_ref(&one),
    );
    let svg = fragment(&rendered, "seismograph_svg");
    assert!(svg.contains("cx=\"360.0\""));
    assert!(!svg.contains("NaN"));
}

#[test]
fn trace_svgs_have_truthful_accessible_titles_and_descriptions() {
    let rendered = probe(&[], &[], &[], &[], "sub", &[]);
    let seismograph = fragment(&rendered, "seismograph_svg");
    assert!(seismograph.contains("role=\"img\""));
    assert!(seismograph.contains("<title id=\"seismograph-title\""));
    assert!(seismograph.contains("bounded reconstruction"));
    assert!(seismograph.contains("assessments from recorded signals"));
    assert!(!seismograph.contains("recorded decisions"));
    assert!(seismograph.contains("not a live feed"));
    let orbit = fragment(&rendered, "orbit_svg");
    assert!(orbit.contains("role=\"img\""));
    assert!(orbit.contains("<title id=\"orbit-title\""));
    assert!(orbit.contains("not live location or session telemetry"));
}

#[test]
fn readout_reports_latest_verdict_freshness_truthfully() {
    for (updated_at, expected) in [
        (NOW - 5, "5s ago"),
        (NOW - 90, "1m ago"),
        (NOW - 7_200, "2.0h ago"),
        (NOW - 3 * 86_400, "3d ago"),
    ] {
        let rendered = probe(
            &[risk("sub", 10.0, "low", updated_at)],
            &[],
            &[],
            &[],
            "sub",
            &[],
        );
        let readout = fragment(&rendered, "readout");
        assert!(readout.contains("readout-cell--meta"));
        assert!(readout.contains("Latest verdict"));
        assert!(
            readout.contains(&format!(r#"data-ts="{updated_at}">{expected}<"#)),
            "expected {expected} for delta {}",
            NOW - updated_at
        );
    }

    // The freshest verdict write wins across the loaded slice, not the top-scored row.
    let rendered = probe(
        &[
            risk("a", 90.0, "high", NOW - 600),
            risk("b", 10.0, "low", NOW - 60),
        ],
        &[],
        &[],
        &[],
        "a",
        &[],
    );
    assert!(fragment(&rendered, "readout").contains(&format!(r#"data-ts="{}">1m ago<"#, NOW - 60)));
}

#[test]
fn readout_clock_skew_is_reported_not_clamped() {
    let rendered = probe(
        &[risk("sub", 10.0, "low", NOW + 120)],
        &[],
        &[],
        &[],
        "sub",
        &[],
    );
    let readout = fragment(&rendered, "readout");
    assert!(readout.contains("ahead of clock"));
    assert!(!readout.contains("ago"));
}

#[test]
fn readout_stays_silent_with_no_verdicts() {
    let rendered = probe(&[], &[], &[], &[], "sub", &[]);
    let readout = fragment(&rendered, "readout");
    assert!(readout.contains("Latest verdict"));
    assert!(readout.contains("<dd>—</dd>"));
    assert!(!readout.contains("data-ts"));
    assert!(!readout.contains("ago"));
}

#[test]
fn trace_calibration_reports_depth_window_and_freshness() {
    let signals = vec![
        signal("s1", "sub", "login.success", "10.0.0.1", "ua", NOW - 3_660),
        signal("s2", "sub", "login.success", "10.0.0.1", "ua", NOW - 60),
    ];
    let rendered = probe(&[], &[], &[], &signals, "sub", &signals);
    for key in ["seismograph_svg", "orbit_svg"] {
        let figure = fragment(&rendered, key);
        assert!(figure.contains(r#"<figcaption class="tape-meta">"#));
        assert!(figure.contains("all 2 recorded signals"), "depth in {key}");
        assert!(figure.contains("1.0h window"), "span in {key}");
        assert!(
            figure.contains("last observation 1m ago (Jan 15, 2027 07:59 UTC)"),
            "freshness in {key}"
        );
        assert!(figure.contains("bounded history, not a live feed"));
        assert!(!figure.contains("window saturated"));
    }
}

#[test]
fn saturated_window_is_declared_per_view_limit() {
    let worst: Vec<Signal> = (0..SEISMO_TRACE_LIMIT)
        .map(|index| {
            signal(
                &format!("w{index}"),
                "sub",
                "login.success",
                "",
                "",
                NOW - 10_000 + index as i64,
            )
        })
        .collect();
    let subject: Vec<Signal> = (0..USER_SIGNAL_LIMIT)
        .map(|index| {
            signal(
                &format!("u{index}"),
                "sub",
                "login.success",
                "",
                "",
                NOW - 10_000 + index as i64,
            )
        })
        .collect();
    let rendered = probe(&[], &[], &[], &worst, "sub", &subject);

    let tape = fragment(&rendered, "seismograph_svg");
    assert!(tape.contains(&format!(
        "the {SEISMO_TRACE_LIMIT} most recent signals (window saturated)"
    )));
    assert!(!tape.contains(&format!("all {SEISMO_TRACE_LIMIT} recorded signals")));

    let orbit = fragment(&rendered, "orbit_svg");
    assert!(orbit.contains(&format!(
        "the {USER_SIGNAL_LIMIT} most recent signals (window saturated)"
    )));
    assert!(!orbit.contains(&format!("all {USER_SIGNAL_LIMIT} recorded signals")));
}

#[test]
fn single_observation_calibration_is_exact() {
    let one = signal("s1", "sub", "login.success", "", "", NOW - 30);
    let rendered = probe(
        &[],
        &[],
        &[],
        std::slice::from_ref(&one),
        "sub",
        std::slice::from_ref(&one),
    );
    for key in ["seismograph_svg", "orbit_svg"] {
        let figure = fragment(&rendered, key);
        assert!(
            figure.contains("the only recorded signal"),
            "depth in {key}"
        );
        assert!(figure.contains("single observation"), "window in {key}");
        assert!(figure.contains("30s ago"), "freshness in {key}");
    }
}

#[test]
fn empty_trace_calibration_stays_silent() {
    let rendered = probe(&[], &[], &[], &[], "sub", &[]);
    for key in ["seismograph_svg", "orbit_svg"] {
        let figure = fragment(&rendered, key);
        assert!(
            figure.contains("No observations recorded"),
            "empty state in {key}"
        );
        assert!(!figure.contains("ago"), "no fabricated freshness in {key}");
        assert!(!figure.contains("window"), "no fabricated span in {key}");
    }
}

#[test]
fn volume_is_category_only_and_carries_no_status_tone() {
    let sig = signal("s1", "sub", "login.failure", "", "", NOW);
    let rendered = probe(&[], &[], &[volume("login.failure", 9)], &[sig], "sub", &[]);
    let volume = fragment(&rendered, "volume");
    assert!(volume.contains("login.failure"));
    assert!(volume.contains("data-kind-dash=\"0\""));
    assert!(!volume.contains("badge-"));
    assert!(!volume.contains("data-level"));
}

#[tokio::test]
async fn template_values_cannot_smuggle_later_tokens() {
    let sub = "{{VERDICT}}";
    let store = Arc::new(InMemoryStore::new());
    let mut seeded = risk(sub, 5.0, "low", NOW);
    seeded.reasons = "reason {{SIGNAL_ROWS}} stays text".to_string();
    store.upsert_risk(&seeded).await.unwrap();
    let state = state_with_store(store);
    let rendered = probe(&[seeded], &[revocation(sub)], &[], &[], sub, &[]);
    let path = hrefs(fragment(&rendered, "roster_rows")).pop().unwrap();

    let (status, body) = call(&state, &path).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(occurrences(&body, "{{VERDICT}}"), 1);
    assert!(body.contains("<title>Subject risk · Pulse</title>"));
    assert!(body.contains("<h1>Subject <code>{{VERDICT}}</code></h1>"));
    assert!(body.contains("reason {{SIGNAL_ROWS}} stays text"));
    assert_eq!(occurrences(&body, "class=\"verdict\""), 1);
}

#[tokio::test]
async fn calibrated_instrument_headings_and_meta_render_end_to_end() {
    let store = Arc::new(InMemoryStore::new());
    store
        .upsert_risk(&risk("subject-0", 80.0, "high", NOW))
        .await
        .unwrap();
    store
        .record_signal(&signal(
            "s1",
            "subject-0",
            "login.failure",
            "203.0.113.9",
            "ua",
            NOW,
        ))
        .await
        .unwrap();
    let state = state_with_store(store);

    let (status, body) = call(&state, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<h1>Identity Seismograph</h1>"));
    assert!(body.contains("Instrument readout"));
    assert!(body.contains("Causal trace — highest-risk subject"));
    assert!(
        body.contains("Risk overview"),
        "estate wayfinding name stays on the overview"
    );
    assert!(body.contains(r#"<figcaption class="tape-meta">"#));
    assert!(body.contains("Latest verdict"));

    let (status, body) = call(&state, "/user/subject-0").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Reconstructed verdict"));
    assert!(body.contains("Subject reconstruction"));
    assert!(body.contains(r#"<figcaption class="tape-meta">"#));
}
