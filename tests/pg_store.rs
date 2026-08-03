//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When unset the test
//! prints a note and returns early — it never fails the default `cargo test` run, which stays
//! database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! docker run --rm -d -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=pulse \
//!   -p 127.0.0.1:55470:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55470/pulse \
//!   cargo test --test pg_store -- --nocapture
//! ```
//!
//! The `Store` trait is async: each method `.await`s sqlx natively (no `block_in_place`), so it
//! runs on any Tokio scheduler — this test stays on `multi_thread` for parallel queries.

use sqlx::postgres::PgPoolOptions;

use pulse::store::{build_baseline, PgStore, Revocation, Risk, Signal, Store};

const TEST_SUB: &str = "pg_user";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_store_full_integration() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!(
            "NOTE: TEST_DATABASE_URL not set — skipping Postgres integration test \
             (needs external Postgres). This is expected for the default test run."
        );
        return;
    };

    // --- connect / migrate (idempotent: run twice) -------------------------
    let pg = PgStore::connect(&url)
        .await
        .expect("connect TEST_DATABASE_URL");
    pg.migrate().await.expect("migrate");
    pg.migrate().await.expect("migrate is idempotent");

    // A dedicated pool used only to reset the test rows so the run is repeatable.
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("admin pool");
    for stmt in [
        "DELETE FROM signals WHERE sub = $1",
        "DELETE FROM risk WHERE sub = $1",
        "DELETE FROM revocations WHERE sub = $1",
    ] {
        sqlx::query(stmt)
            .bind(TEST_SUB)
            .execute(&admin)
            .await
            .expect("reset");
    }

    // --- signal de-dup by id ----------------------------------------------
    let s1 = Signal {
        id: "wt_pg_1".to_string(),
        sub: TEST_SUB.to_string(),
        kind: "login.success".to_string(),
        source_ip: "10.1.2.3".to_string(),
        ua: "curl/8".to_string(),
        ts: 1_700_000_000,
    };
    assert!(pg.record_signal(&s1).await.unwrap(), "first insert");
    assert!(
        !pg.record_signal(&s1).await.unwrap(),
        "duplicate is a no-op"
    );

    let s2 = Signal {
        id: "wt_pg_2".to_string(),
        sub: TEST_SUB.to_string(),
        kind: "login.failure".to_string(),
        source_ip: "203.0.113.5".to_string(),
        ua: String::new(),
        ts: 1_700_000_100,
    };
    pg.record_signal(&s2).await.unwrap();

    let signals = pg.signals_for_sub(TEST_SUB, 100).await;
    assert_eq!(signals.len(), 2);
    assert_eq!(signals[0].id, "wt_pg_2", "newest-first");

    // Baseline derived from PG rows behaves like the in-memory path.
    let b = build_baseline(&signals, 1_700_000_100, Some("wt_pg_2"));
    assert!(b.known_ips.contains("10.1.2.3"));
    assert!(!b.known_ips.contains("203.0.113.5"), "candidate excluded");

    // --- risk upsert -------------------------------------------------------
    pg.upsert_risk(&Risk {
        sub: TEST_SUB.to_string(),
        score: 30.0,
        level: "low".to_string(),
        reasons: String::new(),
        updated_at: 1,
    })
    .await
    .unwrap();
    pg.upsert_risk(&Risk {
        sub: TEST_SUB.to_string(),
        score: 85.0,
        level: "high".to_string(),
        reasons: "new source IP · authentication failure".to_string(),
        updated_at: 2,
    })
    .await
    .unwrap();
    let r = pg.get_risk(TEST_SUB).await.expect("risk present");
    assert_eq!(r.score, 85.0);
    assert_eq!(r.level, "high");

    // --- revocation de-dup by id ------------------------------------------
    let rev = Revocation {
        id: "rev_wt_pg_2".to_string(),
        sub: TEST_SUB.to_string(),
        reason: "high risk".to_string(),
        ts: 1_700_000_200,
    };
    assert!(
        pg.insert_revocation(&rev).await.unwrap(),
        "first revocation"
    );
    assert!(
        !pg.insert_revocation(&rev).await.unwrap(),
        "dup revocation no-op"
    );
    assert_eq!(pg.revocations_for_sub(TEST_SUB, 10).await.len(), 1);

    // --- aggregates --------------------------------------------------------
    assert!(pg.signal_count().await >= 2);
    let volume = pg.signal_volume().await;
    assert!(volume.iter().any(|k| k.kind == "login.success"));
    assert!(volume.iter().any(|k| k.kind == "login.failure"));

    // --- clean up so the next run starts fresh ----------------------------
    for stmt in [
        "DELETE FROM signals WHERE sub = $1",
        "DELETE FROM risk WHERE sub = $1",
        "DELETE FROM revocations WHERE sub = $1",
    ] {
        sqlx::query(stmt).bind(TEST_SUB).execute(&admin).await.ok();
    }
}
