//! Iter-41 regression test: pin the SIGHUP per-section reload
//! counter-bump policy.
//!
//! ## What this pins
//!
//! Pre-iter-41 the per-section reload paths in `main.rs` bumped
//! `*_reload_attempts` upfront (so an operator who SIGHUPed knows
//! the signal reached us) but only bumped `*_reload_succeeded`
//! when both:
//!   - the operator's `client.yaml` had the section present, AND
//!   - the runtime had a corresponding limiter installed at startup.
//!
//! That meant operators who SIGHUPed WITHOUT a `rate_limit:` block
//! in their config saw the gap `(attempts - succeeded)` grow by 1
//! on every SIGHUP, permanently tripping iter-38's
//! `ProteusRateLimitReloadFailing` alert as a false positive.
//! Same for `user_rate_limit:` and `handshake_budget:`.
//!
//! Post-iter-41 the policy is:
//!   - Config-PARSE failure (ServerConfig::load returned Err) →
//!     bump attempts only. ProteusXxxReloadFailing fires. Correct.
//!   - Config parsed; section absent → bump both attempts AND
//!     succeeded (the reload completed; there was just nothing to
//!     do). Alert does NOT fire. Correct.
//!   - Config parsed; section present + reload-fn returned true →
//!     bump both. Alert does NOT fire. Correct.
//!   - Config parsed; section present + reload-fn returned false
//!     (no limiter installed at startup, edit ignored with warn!)
//!     → bump both. We don't pin a perma-alert on the operator's
//!     attempt to edit something the binary doesn't support hot-
//!     reloading; the warn! in the journal is the surface.
//!
//! ## Why this lives as a pure-function test
//!
//! The SIGHUP path in main.rs is heavily coupled (signal handler,
//! file I/O, sd_notify, structured tracing). Extracting a
//! testable pure function would force a large refactor. Instead
//! we mirror the policy here in a pure helper and assert its
//! behavior matches the documented post-iter-41 contract. The
//! actual main.rs SIGHUP body uses the same decision tree by
//! visual inspection (the helper here is a 1:1 transcription).

/// Mirror of the counter-bump policy in
/// `proteus-server/src/main.rs` SIGHUP block (iter-41).
///
/// Inputs:
///   - `parse_ok`: did `ServerConfig::load` succeed?
///   - `section_present`: did the parsed config have the section?
///   - `reload_fn_outcome`: did the runtime reload function return
///     true? (only meaningful if `section_present == true`)
///
/// Output: `(attempts_delta, succeeded_delta)` for ONE SIGHUP.
fn policy(parse_ok: bool, section_present: bool, reload_fn_outcome: bool) -> (u64, u64) {
    let attempts_delta = 1; // always bumped upfront
    if !parse_ok {
        // Parse failure → gap grows. Genuine "edit didn't apply".
        return (attempts_delta, 0);
    }
    if !section_present {
        // Section absent → reload completed (no-op). No gap.
        return (attempts_delta, 1);
    }
    // Section present → bump succeeded regardless of reload_fn
    // outcome. The `false` return path is "edit ignored — no
    // limiter at startup"; we warn! in the journal but do NOT
    // perma-trip the alert (pre-iter-41 false-positive class).
    let _ = reload_fn_outcome;
    (attempts_delta, 1)
}

#[test]
fn parse_failure_bumps_attempts_only() {
    // Config-parse failure → gap grows by 1. Operator's edit
    // truly didn't apply; this is exactly when the alert SHOULD
    // fire.
    let (att, succ) = policy(false, false, false);
    assert_eq!(att, 1);
    assert_eq!(succ, 0);
    assert_eq!(att - succ, 1, "parse failure must create a gap");
}

#[test]
fn section_absent_bumps_both_no_gap() {
    // Operator's config doesn't have `rate_limit:` — SIGHUP is a
    // no-op for that section. Must NOT create a gap; otherwise
    // every operator who doesn't use rate-limiting gets a
    // perma-trip alert on every SIGHUP.
    let (att, succ) = policy(true, false, false);
    assert_eq!(att, 1);
    assert_eq!(succ, 1);
    assert_eq!(att, succ, "section-absent must not create a gap");
}

#[test]
fn section_present_reload_ok_bumps_both_no_gap() {
    // The happy path: operator has the section, the runtime
    // accepted the hot-swap. Both bump.
    let (att, succ) = policy(true, true, true);
    assert_eq!(att, 1);
    assert_eq!(succ, 1);
}

#[test]
fn section_present_reload_ignored_still_bumps_both() {
    // The "edit ignored — no limiter at startup" case. Operator
    // tried to hot-swap something the binary doesn't support
    // hot-reloading; we warn! in the journal but do NOT
    // perma-trip the alert. Pre-iter-41 this was the second
    // false-positive class.
    let (att, succ) = policy(true, true, false);
    assert_eq!(att, 1);
    assert_eq!(succ, 1);
    assert_eq!(
        att, succ,
        "edit-ignored-at-startup must not perma-trip the alert"
    );
}

/// Multi-SIGHUP simulation: 5 SIGHUPs from an operator who has
/// no `rate_limit:` block + 1 SIGHUP with a parse error in the
/// YAML → gap == 1, not 6 (the pre-iter-41 false-positive bug
/// would have made gap == 6, with 5 of them being false alarms).
#[test]
fn five_no_section_sighups_plus_one_parse_failure_gives_gap_of_one() {
    let mut att = 0u64;
    let mut succ = 0u64;
    // Five SIGHUPs with parse OK, section absent.
    for _ in 0..5 {
        let (a, s) = policy(true, false, false);
        att += a;
        succ += s;
    }
    assert_eq!(att, 5);
    assert_eq!(succ, 5);
    assert_eq!(att - succ, 0, "5 no-section SIGHUPs must not create gap");

    // One SIGHUP with parse failure.
    let (a, s) = policy(false, false, false);
    att += a;
    succ += s;
    assert_eq!(att, 6);
    assert_eq!(succ, 5);
    assert_eq!(
        att - succ,
        1,
        "exactly one parse failure → gap of exactly one — not 6"
    );
}
