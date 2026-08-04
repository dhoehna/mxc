//! Spec-derived tests for the `ip6tables` usability classification and the
//! fail-open vs fail-closed decision it guards. Written from the documented
//! contract only.

use super::*;

// ---------------------------------------------------------------------------
// Truth table — all four input combinations are enumerated and pinned.
// ---------------------------------------------------------------------------

#[test]
fn working_probe_with_active_ipv6_reports_available() {
    // "A working probe means the tool is usable regardless of address state."
    let result = NetworkIptablesManager::classify_ip6tables_status(true, true);
    assert_eq!(
        result,
        Ip6tablesStatus::Available,
        "classify_ip6tables_status(probe=true, ipv6_active=true) should be Available; got {result:?}"
    );
}

#[test]
fn working_probe_without_active_ipv6_still_reports_available() {
    // "A working probe means the tool is usable regardless of address state."
    let result = NetworkIptablesManager::classify_ip6tables_status(true, false);
    assert_eq!(
        result,
        Ip6tablesStatus::Available,
        "classify_ip6tables_status(probe=true, ipv6_active=false) should be Available; got {result:?}"
    );
}

#[test]
fn failed_probe_with_no_active_ipv6_reports_kernel_ipv6_disabled() {
    // "if the kernel has no active IPv6 there is nothing to filter and skipping is safe"
    let result = NetworkIptablesManager::classify_ip6tables_status(false, false);
    assert_eq!(
        result,
        Ip6tablesStatus::KernelIpv6Disabled,
        "classify_ip6tables_status(probe=false, ipv6_active=false) should be KernelIpv6Disabled; got {result:?}"
    );
}

#[test]
fn live_ipv6_with_a_broken_tool_must_fail_closed_not_skip() {
    // "if IPv6 is live the tool is genuinely missing or broken and setup must
    // fail closed rather than leave IPv6 egress unfiltered"
    let result = NetworkIptablesManager::classify_ip6tables_status(false, true);
    assert_eq!(
        result,
        Ip6tablesStatus::UnusableButIpv6Active,
        "classify_ip6tables_status(probe=false, ipv6_active=true) should be UnusableButIpv6Active (fail-closed); got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Invariants — properties that must hold across the whole domain.
// ---------------------------------------------------------------------------

/// A working probe always yields Available, regardless of IPv6 address state.
#[test]
fn working_probe_always_yields_available_regardless_of_ipv6_state() {
    for ipv6_active in [false, true] {
        let result = NetworkIptablesManager::classify_ip6tables_status(true, ipv6_active);
        assert_eq!(
            result,
            Ip6tablesStatus::Available,
            "probe_succeeded=true, ipv6_active={ipv6_active}: expected Available, got {result:?}"
        );
    }
}

/// A failed probe must never return Available — it can only be KernelIpv6Disabled
/// or UnusableButIpv6Active.
#[test]
fn failed_probe_never_reports_available() {
    for ipv6_active in [false, true] {
        let result = NetworkIptablesManager::classify_ip6tables_status(false, ipv6_active);
        assert_ne!(
            result,
            Ip6tablesStatus::Available,
            "probe_succeeded=false, ipv6_active={ipv6_active}: Available must not be returned when the probe failed; got {result:?}"
        );
    }
}

/// UnusableButIpv6Active is ONLY reachable when the probe failed AND IPv6 is
/// live.  If a mutation makes the fail-closed branch unreachable (silent
/// fail-open), this test catches it.
#[test]
fn fail_closed_outcome_is_reachable_only_when_probe_failed_and_ipv6_is_live() {
    // The one combination that MUST produce UnusableButIpv6Active.
    let fail_closed = NetworkIptablesManager::classify_ip6tables_status(false, true);
    assert_eq!(
        fail_closed,
        Ip6tablesStatus::UnusableButIpv6Active,
        "classify_ip6tables_status(probe=false, ipv6_active=true) must be UnusableButIpv6Active; got {fail_closed:?}"
    );

    // All other combinations must NOT produce UnusableButIpv6Active.
    let other_pairs = [(true, true), (true, false), (false, false)];
    for (probe, active) in other_pairs {
        let result = NetworkIptablesManager::classify_ip6tables_status(probe, active);
        assert_ne!(
            result,
            Ip6tablesStatus::UnusableButIpv6Active,
            "classify_ip6tables_status(probe={probe}, ipv6_active={active}) must not be UnusableButIpv6Active; got {result:?}"
        );
    }
}

/// KernelIpv6Disabled is ONLY reachable when the probe failed AND IPv6 is
/// inactive.  It must not surface as a safe-skip when IPv6 is actually live.
#[test]
fn safe_skip_outcome_is_reachable_only_when_probe_failed_and_ipv6_is_inactive() {
    // The one combination that MUST produce KernelIpv6Disabled.
    let safe_skip = NetworkIptablesManager::classify_ip6tables_status(false, false);
    assert_eq!(
        safe_skip,
        Ip6tablesStatus::KernelIpv6Disabled,
        "classify_ip6tables_status(probe=false, ipv6_active=false) must be KernelIpv6Disabled; got {safe_skip:?}"
    );

    // All other combinations must NOT produce KernelIpv6Disabled.
    let other_pairs = [(true, true), (true, false), (false, true)];
    for (probe, active) in other_pairs {
        let result = NetworkIptablesManager::classify_ip6tables_status(probe, active);
        assert_ne!(
            result,
            Ip6tablesStatus::KernelIpv6Disabled,
            "classify_ip6tables_status(probe={probe}, ipv6_active={active}) must not be KernelIpv6Disabled; got {result:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Discriminant distinctness — a mutation that collapses two variants must
// be caught before PartialEq-based assertions below would silently accept it.
// ---------------------------------------------------------------------------

#[test]
fn ip6tables_status_variants_are_all_distinct_from_each_other() {
    assert_ne!(
        Ip6tablesStatus::Available,
        Ip6tablesStatus::KernelIpv6Disabled,
        "Available and KernelIpv6Disabled must be distinct variants"
    );
    assert_ne!(
        Ip6tablesStatus::Available,
        Ip6tablesStatus::UnusableButIpv6Active,
        "Available and UnusableButIpv6Active must be distinct variants"
    );
    assert_ne!(
        Ip6tablesStatus::KernelIpv6Disabled,
        Ip6tablesStatus::UnusableButIpv6Active,
        "KernelIpv6Disabled and UnusableButIpv6Active must be distinct variants"
    );
}
