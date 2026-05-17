//! End-to-end SIGHUP-driven `server_endpoints` hot-reload test.
//!
//! This test does NOT spawn the full `proteus-client` binary (that
//! would require a real Proteus server + SOCKS5 wiring + signal
//! delivery). Instead it drives the *same* code path the production
//! SIGHUP handler runs:
//!
//!   1. Build a `ClientCtx` with an initial `ReloadablePool`.
//!   2. Drive some dispatcher activity (bump counters on entry 0).
//!   3. Call `reload_from_addrs` with a new endpoint list — the
//!      same primitive the SIGHUP handler in `main.rs` invokes.
//!   4. Verify per-endpoint counter carryover, the pool ordering,
//!      and the reload counter bumps.
//!   5. Capture an admin `/status.json` snapshot via the same
//!      `ClientStatusSnapshot::from_ctx` the production endpoint
//!      uses, and assert the post-reload state is visible to a
//!      Prometheus scraper that hit the /metrics endpoint right
//!      after the SIGHUP fired.
//!
//! The reason this is an integration test (not a unit test) is
//! that it exercises multiple modules together (ClientCtx +
//! ReloadablePool + EndpointPool::new_with_carryover + admin
//! snapshot rendering) — the same end-to-end the SIGHUP handler
//! relies on.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;

use proteus_client::admin::ClientStatusSnapshot;
use proteus_client::carrier_health::CarrierHealth;
use proteus_client::ctx::ClientCtx;
use proteus_client::endpoint_pool::EndpointPool;

/// Helper: ClientCtx wired with a 2-entry pool and β configured.
fn ctx_with_initial_pool(addrs: Vec<&str>) -> Arc<ClientCtx> {
    let pool = Arc::new(EndpointPool::new(addrs.into_iter().map(String::from).collect()).unwrap());
    Arc::new(ClientCtx::new(
        Arc::new(CarrierHealth::new()),
        Some(pool),
        None,
        0,
        true,
    ))
}

#[tokio::test]
async fn sighup_reload_preserves_unchanged_entry_counters_and_swaps_order() {
    let ctx = ctx_with_initial_pool(vec!["primary:8443", "backup:8443"]);

    // Drive primary's counters via the public dispatch API the way
    // the real socks dispatcher would.
    let pool = ctx.pool().expect("initial pool wired");
    let h0 = pool.endpoint_health(0).unwrap();
    for _ in 0..10 {
        h0.record_attempt();
        h0.record_success();
    }
    let h1 = pool.endpoint_health(1).unwrap();
    h1.record_attempt();
    h1.record_failure(Instant::now());
    drop(pool);

    // SIGHUP scenario: operator added a third VPS to the pool AND
    // reordered (new fast backup first, old primary moved to last).
    let (prev, new) = ctx.reloadable_pool.reload_from_addrs(vec![
        "fast-backup:8443".to_string(),
        "backup:8443".to_string(),
        "primary:8443".to_string(),
    ]);
    assert_eq!(prev, vec!["primary:8443", "backup:8443"]);
    assert_eq!(new, vec!["fast-backup:8443", "backup:8443", "primary:8443"]);

    // After reload: pool has 3 entries in the new order.
    let pool = ctx.pool().expect("pool after reload");
    assert_eq!(pool.len(), 3);
    let addrs: Vec<&str> = pool.addresses().collect();
    assert_eq!(
        addrs,
        vec!["fast-backup:8443", "backup:8443", "primary:8443"]
    );

    // Counters: primary's 10 successes survived the reload despite
    // moving from index 0 to index 2.
    let primary_after = pool.endpoint_health(2).unwrap().counters();
    assert_eq!(
        primary_after.attempts, 10,
        "primary's attempts must survive carryover: {primary_after:?}"
    );
    assert_eq!(primary_after.successes, 10);
    assert_eq!(primary_after.failures, 0);

    // backup:8443 stayed (now at index 1): 1 attempt + 1 failure carried.
    let backup_after = pool.endpoint_health(1).unwrap().counters();
    assert_eq!(backup_after.attempts, 1, "{backup_after:?}");
    assert_eq!(backup_after.failures, 1);

    // fast-backup is new (index 0): zero counters.
    let fast_after = pool.endpoint_health(0).unwrap().counters();
    assert_eq!(fast_after.attempts, 0, "{fast_after:?}");

    // Reload counters bumped exactly once.
    assert_eq!(ctx.reloadable_pool.reload_attempts(), 1);
    assert_eq!(ctx.reloadable_pool.reload_succeeded(), 1);
}

#[tokio::test]
async fn sighup_reload_drops_removed_entry_counters() {
    let ctx = ctx_with_initial_pool(vec!["a:1", "b:2", "c:3"]);
    let pool = ctx.pool().unwrap();
    for h in [
        pool.endpoint_health(0),
        pool.endpoint_health(1),
        pool.endpoint_health(2),
    ]
    .into_iter()
    .flatten()
    {
        h.record_attempt();
        h.record_success();
    }
    drop(pool);

    // Operator removes b:2 entirely.
    ctx.reloadable_pool
        .reload_from_addrs(vec!["a:1".into(), "c:3".into()]);
    let pool = ctx.pool().unwrap();
    assert_eq!(pool.len(), 2);
    let addrs: Vec<&str> = pool.addresses().collect();
    assert_eq!(addrs, vec!["a:1", "c:3"]);
    // a:1 and c:3 still have their successes.
    assert_eq!(pool.endpoint_health(0).unwrap().counters().successes, 1);
    assert_eq!(pool.endpoint_health(1).unwrap().counters().successes, 1);
}

#[tokio::test]
async fn sighup_empty_reload_transitions_to_single_endpoint_mode() {
    let ctx = ctx_with_initial_pool(vec!["a:1", "b:2"]);
    assert!(ctx.pool().is_some(), "starts with pool wired");
    // Operator deletes server_endpoints (or sets it to empty list)
    // → SIGHUP → pool clears → dispatcher falls back to single
    // server_endpoint mode.
    ctx.reloadable_pool.reload_from_addrs(vec![]);
    assert!(
        ctx.pool().is_none(),
        "pool should be cleared after empty reload"
    );
    assert_eq!(ctx.reloadable_pool.reload_attempts(), 1);
}

#[tokio::test]
async fn admin_snapshot_reflects_pool_state_immediately_after_sighup() {
    let ctx = ctx_with_initial_pool(vec!["old-vps:8443"]);
    // Before reload: snapshot shows the old pool.
    let alive = Arc::new(AtomicBool::new(true));
    let snap_before = ClientStatusSnapshot::from_ctx(
        alive.load(std::sync::atomic::Ordering::Relaxed),
        &ctx,
        Instant::now(),
    );
    assert_eq!(snap_before.pool.as_ref().unwrap().entries.len(), 1);
    assert_eq!(snap_before.pool_reload.attempts, 0);

    // SIGHUP fires — operator added two backups.
    ctx.reloadable_pool.reload_from_addrs(vec![
        "old-vps:8443".to_string(),
        "backup1:8443".to_string(),
        "backup2:8443".to_string(),
    ]);

    // After reload: NEXT snapshot reflects the new pool AND the
    // reload counters bumped.
    let snap_after = ClientStatusSnapshot::from_ctx(
        alive.load(std::sync::atomic::Ordering::Relaxed),
        &ctx,
        Instant::now(),
    );
    let entries = snap_after.pool.as_ref().unwrap();
    assert_eq!(entries.entries.len(), 3);
    assert_eq!(entries.entries[0].addr, "old-vps:8443");
    assert_eq!(entries.entries[1].addr, "backup1:8443");
    assert_eq!(entries.entries[2].addr, "backup2:8443");
    assert_eq!(snap_after.pool_reload.attempts, 1);
    assert_eq!(snap_after.pool_reload.succeeded, 1);

    // The JSON serializer should round-trip the new state.
    let j = snap_after.to_json();
    assert!(
        j.contains(r#""addr":"backup1:8443""#),
        "missing new entry in JSON: {j}"
    );
    assert!(
        j.contains(r#""pool_reload":{"attempts":1,"succeeded":1}"#),
        "missing reload counters in JSON: {j}"
    );

    // Prometheus output gets the new per-endpoint series + reload
    // counter.
    let p = snap_after.to_prometheus();
    assert!(
        p.contains(r#"proteus_client_endpoint_attempts_total{addr="backup1:8443"} 0"#),
        "missing per-endpoint series for new backup1: {p}"
    );
    assert!(
        p.contains("proteus_client_pool_reload_attempts_total 1"),
        "missing pool_reload counter in Prometheus: {p}"
    );
}
