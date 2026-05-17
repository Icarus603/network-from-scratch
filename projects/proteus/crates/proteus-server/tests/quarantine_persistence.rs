//! Restart-survival smoke test for the user_quarantine persistence
//! path.
//!
//! Full cross-process scenario (different keys, different server
//! instance) is too much glue for an integration test — the
//! library-level path is what matters and is exercised by the
//! unit tests in `user_quarantine.rs` (`persist_writes_jsonl_file_*`,
//! `load_from_disk_restores_*`, `user_id_roundtrip_through_persistence_*`).
//!
//! This test fills the operator-visible gap between those:
//! "If I configure persistence in YAML, will a fresh process
//! restore the prior bans and have them queryable via the list?"
//! The integration boundary is: the file is the source of truth
//! across "process 1" and "process 2", and the loaded list's
//! check() returns the same Some(...) the prior process would
//! have.

use std::sync::Arc;
use std::time::Duration;

use proteus_transport_alpha::user_quarantine::UserQuarantineList;

fn tmp_path(suffix: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "proteus_quarantine_e2e_{}_{}.jsonl",
        std::process::id(),
        suffix
    ));
    let _ = std::fs::remove_file(&p);
    p
}

#[tokio::test]
async fn quarantine_survives_process_restart_via_disk_persistence() {
    let path = tmp_path("survive_restart");

    // ----- "Process 1": insert several users with different
    //                    trigger labels; auto-persist happens.
    {
        let q1 = Arc::new(
            UserQuarantineList::new(Duration::from_secs(600), 4096).with_persistence(path.clone()),
        );
        assert!(q1.insert(*b"alice001", "per_user_bandwidth_rate"));
        assert!(q1.insert(*b"bob00002", "rate_limit"));
        assert!(q1.insert(*b"carol003", "byte_budget"));
        assert!(
            q1.persist_attempts_total() >= 3,
            "must have persisted 3 times"
        );
        assert_eq!(q1.persist_failed_total(), 0);
        assert!(path.exists(), "persistence file must exist after inserts");
        // Drop q1 — process exits.
    }

    // ----- "Process 2": load from disk -----
    let q2 = UserQuarantineList::load_from_disk(path.clone(), Duration::from_secs(600), 4096);
    assert_eq!(q2.loaded_from_disk(), 3, "all three bans must be restored");

    // Every prior ban survives — checked via the same admission-
    // gate API the server uses in production.
    let alice = q2.check(b"alice001").expect("alice ban must survive");
    let bob = q2.check(b"bob00002").expect("bob ban must survive");
    let carol = q2.check(b"carol003").expect("carol ban must survive");
    // TTLs are roughly the original 600 seconds (small slack for
    // the test's wall-clock between persist + load).
    for (who, secs) in [("alice", alice), ("bob", bob), ("carol", carol)] {
        assert!(
            secs > 550 && secs <= 600,
            "{who} remaining ban time out of band: {secs}"
        );
    }

    // The triggered_by labels survive the roundtrip — surfaced in
    // /diagnose so operators see WHY each user was banned.
    let snap = q2.active_snapshot(64);
    let alice = snap.iter().find(|e| e.user_id == "alice001").unwrap();
    let bob = snap.iter().find(|e| e.user_id == "bob00002").unwrap();
    let carol = snap.iter().find(|e| e.user_id == "carol003").unwrap();
    assert_eq!(alice.triggered_by, "per_user_bandwidth_rate");
    assert_eq!(bob.triggered_by, "rate_limit");
    assert_eq!(carol.triggered_by, "byte_budget");

    // A FRESH insert in process 2 should ALSO auto-persist (i.e.
    // persistence is wired by load_from_disk, not just by
    // with_persistence on the explicit builder path).
    assert!(q2.insert(*b"dave0001", "per_user_bandwidth_rate"));
    assert!(q2.persist_attempts_total() >= 1);

    // Read the file again — dave should be there alongside the
    // original three.
    let body = std::fs::read_to_string(&path).expect("file readable");
    assert!(
        body.contains(r#""user_id":"dave0001""#),
        "dave's fresh ban must have auto-persisted: {body}"
    );
    assert!(body.contains(r#""user_id":"alice001""#));

    let _ = std::fs::remove_file(&path);
}
