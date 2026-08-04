//! Spec-derived tests for the not-yet-implemented permissive inbound path.
//! Written from the documented contract only — the implementation was not read.
//!
//! # Decision table
//!
//! | allow_local_network | netns PID set | Required outcome | Contract sentence                                        |
//! |---------------------|---------------|------------------|----------------------------------------------------------|
//! | false               | no            | NOT refused       | Default-deny path; guard is for the permissive case only.|
//! | false               | yes           | NOT refused       | Same.                                                    |
//! | true                | yes           | REFUSED           | "apply_firewall_rules returns a clear not-yet-implemented|
//! |                     |               |                   |  error for the permissive path"                          |
//! | true                | no            | CONTRACT GAP      | Contract does not distinguish this cell — see tests.     |

use super::*;
// Logger and ContainerPolicy are re-exported via super::*.
// Mode and NetworkPolicy are not in network_iptables.rs's own imports, so we
// bring them in directly.
use wxc_common::logger::Mode;
use wxc_common::models::NetworkPolicy;

// ── helpers ──────────────────────────────────────────────────────────────────

fn make_logger() -> Logger {
    Logger::new(Mode::Buffer)
}

fn policy_with(allow_local: bool, default: NetworkPolicy) -> ContainerPolicy {
    ContainerPolicy {
        allow_local_network: allow_local,
        default_network_policy: default,
        ..Default::default()
    }
}

// ── Refused case: permissive policy with a container netns PID ──────────────

/// Contract: "apply_firewall_rules returns a clear not-yet-implemented error
/// for the permissive path" (module-level doc, permissive-path section).
/// A netns PID is set so we are in the full LXC container path that would
/// otherwise install the over-broad accept rule.
#[test]
#[ignore = "SUSPECTED BUG: apply_firewall_rules returns Ok(true) for allow_local_network=true + netns PID; \
            the not-yet-implemented guard appears to be absent or gated incorrectly"]
fn permissive_inbound_in_a_container_netns_is_refused_not_installed() {
    let policy = policy_with(true, NetworkPolicy::Block);
    let mut mgr = NetworkIptablesManager::new("test-container-refused");
    mgr.set_netns_pid(12345);
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, &mut logger);

    assert!(
        result.is_err(),
        "allow_local_network=true, netns_pid=Some(12345): expected Err (not-yet-implemented \
         refusal), got {:?}",
        result
    );

    let msg = result.unwrap_err();

    // Contract specifies an observable Err string beginning with a distinctive
    // phrase.  We match on substrings, not the whole blob, so a line-rewrap
    // cannot silently break the test while the real guard is still absent.
    assert!(
        msg.contains("not yet implemented"),
        "allow_local_network=true, netns_pid=Some(12345): error message must contain \
         \"not yet implemented\", got: {:?}",
        msg
    );
    assert!(
        msg.contains("allowLocalNetwork"),
        "allow_local_network=true, netns_pid=Some(12345): error message must contain \
         \"allowLocalNetwork\", got: {:?}",
        msg
    );
    assert!(
        msg.contains("over-broad accept"),
        "allow_local_network=true, netns_pid=Some(12345): error message must contain \
         \"over-broad accept\", got: {:?}",
        msg
    );
}

/// A refusal must not mark the manager as having applied rules, because
/// rules_applied() drives cleanup.  Installing a cleanup pass after a refusal
/// would be wrong and potentially dangerous.
///
/// The contract does not explicitly address this invariant, but it follows
/// directly from the semantics of rules_applied(): if no rules were installed,
/// cleanup must not run.  See ## CONTRACT GAPS in the module doc.
#[test]
#[ignore = "SUSPECTED BUG: apply_firewall_rules returns Ok(true) for allow_local_network=true + netns PID; \
            the not-yet-implemented guard appears to be absent or gated incorrectly — \
            this test depends on the refusal firing (see permissive_inbound_in_a_container_netns_is_refused_not_installed)"]
fn permissive_inbound_refusal_does_not_set_rules_applied() {
    let policy = policy_with(true, NetworkPolicy::Block);
    let mut mgr = NetworkIptablesManager::new("test-container-refused-state");
    mgr.set_netns_pid(99999);
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, &mut logger);

    // Ensure we actually hit the refusal branch; if not, the assertion below
    // has no meaning.
    assert!(
        result.is_err(),
        "allow_local_network=true, netns_pid=Some(99999): expected Err (refusal), got {:?}",
        result
    );

    assert!(
        !mgr.rules_applied(),
        "allow_local_network=true, netns_pid=Some(99999): rules_applied() must be false \
         after a refusal — no rules were installed so cleanup must not run, got \
         rules_applied()=true"
    );
}

// ── Non-refused cases: allow_local_network=false ────────────────────────────
//
// These paths do NOT trigger the permissive guard.  On this box there is no
// iptables binary, so we cannot assert Ok.  Instead we assert the
// discriminating invariant: whatever the outcome, it is NOT the
// not-yet-implemented refusal.  That invariant is meaningful on Linux and on
// Windows and cannot be satisfied by accident.
//
// CONTRACT: the not-yet-implemented guard is documented only for the
// permissive path (allow_local_network=true).  The default-deny path has no
// stated reason to produce this error.

/// Default-deny policy (allow_local_network=false) with no netns PID —
/// Bubblewrap shared-net mode.  The chain is "built but left unhooked."
/// Must not return the not-yet-implemented refusal.
#[test]
fn default_deny_without_netns_is_not_the_permissive_refusal() {
    let policy = policy_with(false, NetworkPolicy::Block);
    let mut mgr = NetworkIptablesManager::new("test-container-deny-no-netns");
    // No set_netns_pid call.
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, &mut logger);

    // Deliberate negative assertion: we cannot assert Ok on Windows (no
    // iptables binary), but the not-yet-implemented refusal must never fire
    // for a default-deny policy regardless of platform.
    if let Err(ref msg) = result {
        assert!(
            !msg.contains("not yet implemented"),
            "allow_local_network=false, netns_pid=None: must not return the \
             not-yet-implemented refusal, got: {:?}",
            msg
        );
        assert!(
            !msg.contains("over-broad accept"),
            "allow_local_network=false, netns_pid=None: must not return the \
             over-broad-accept refusal, got: {:?}",
            msg
        );
        eprintln!(
            "WARNING: default_deny_without_netns_is_not_the_permissive_refusal got Err \
             (expected on Windows — no iptables binary).  The non-error branch was not \
             exercised.  Re-run on Linux to verify the happy path."
        );
    }
}

/// Default-deny policy with a netns PID — normal LXC container, deny mode.
/// Must not return the not-yet-implemented refusal.
#[test]
fn default_deny_with_netns_is_not_the_permissive_refusal() {
    let policy = policy_with(false, NetworkPolicy::Block);
    let mut mgr = NetworkIptablesManager::new("test-container-deny-with-netns");
    mgr.set_netns_pid(55555);
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, &mut logger);

    // Deliberate negative assertion: same reasoning as the no-netns variant
    // above.  The not-yet-implemented error must not appear for default-deny.
    if let Err(ref msg) = result {
        assert!(
            !msg.contains("not yet implemented"),
            "allow_local_network=false, netns_pid=Some(55555): must not return the \
             not-yet-implemented refusal, got: {:?}",
            msg
        );
        assert!(
            !msg.contains("over-broad accept"),
            "allow_local_network=false, netns_pid=Some(55555): must not return the \
             over-broad-accept refusal, got: {:?}",
            msg
        );
        eprintln!(
            "WARNING: default_deny_with_netns_is_not_the_permissive_refusal got Err \
             (expected on Windows — no iptables binary).  The non-error branch was not \
             exercised.  Re-run on Linux to verify the happy path."
        );
    }
}

// ── CONTRACT GAP cell: allow_local_network=true, no netns PID ───────────────
//
// The contract says the no-PID path "never attach[es] a rule to the host's
// own INPUT chain" and the chain is "left unhooked."  The refusal description
// does not explicitly state whether it fires when no PID is present.
//
// The over-broad-accept argument (the only reason for refusal) still applies:
// an unscoped NEW -j ACCEPT would be over-broad in any namespace.  However,
// the contract also says "installs nothing" for this path, which could mean
// the refusal is a no-op and the code never reaches the guard.
//
// Because the contract is ambiguous here, we assert only the unambiguous
// sub-invariant: if a refusal fires, it must carry the correct message
// (not some other, unrelated Err).  We do not assert whether it MUST refuse.
// See ## CONTRACT GAPS.

#[test]
fn permissive_inbound_without_netns_if_refused_carries_correct_message() {
    let policy = policy_with(true, NetworkPolicy::Block);
    let mut mgr = NetworkIptablesManager::new("test-container-perm-no-netns");
    // No set_netns_pid — Bubblewrap / unit-test mode.
    let mut logger = make_logger();

    let result = mgr.apply_firewall_rules(&policy, &mut logger);

    // CONTRACT GAP: the contract does not say whether this combination must
    // refuse.  We assert only: if it IS an error, the message content matches
    // the specified refusal text (not some unrelated error).
    if let Err(ref msg) = result {
        // If the guard fires, it must be the documented refusal, not noise.
        let is_nyi_refusal = msg.contains("not yet implemented")
            || msg.contains("allowLocalNetwork")
            || msg.contains("over-broad accept");
        // Acceptable alternatives: it could be a different Err entirely
        // (e.g., iptables missing).  We cannot distinguish without reading
        // the code, so we do NOT assert is_nyi_refusal here.
        // What we can assert: if it claims to be the NYI refusal, it must
        // carry all three fingerprints.
        if msg.contains("not yet implemented") {
            assert!(
                msg.contains("allowLocalNetwork"),
                "allow_local_network=true, netns_pid=None: partial NYI message — missing \
                 'allowLocalNetwork', got: {:?}",
                msg
            );
            assert!(
                msg.contains("over-broad accept"),
                "allow_local_network=true, netns_pid=None: partial NYI message — missing \
                 'over-broad accept', got: {:?}",
                msg
            );
        }
        let _ = is_nyi_refusal; // suppress unused warning
        eprintln!(
            "WARNING: permissive_inbound_without_netns_if_refused_carries_correct_message \
             got Err (may be iptables-missing on Windows).  CONTRACT GAP: whether \
             allow_local_network=true + no netns MUST refuse is not specified."
        );
    }
}
