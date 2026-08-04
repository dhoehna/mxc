//! Spec-derived tests for the `/proc/net/if_inet6` content -> host-IPv6-state
//! mapping. Written from the documented contract only: the parse/classify step
//! must distinguish an egress-capable interface from loopback-only `::1`, and
//! must not convert an unreadable file into a confirmed "IPv6 is off".

use super::*;
use std::io::{Error, ErrorKind};

// A real `/proc/net/if_inet6` line: 32-hex-char address, if_index, prefix_len,
// scope, flags, and the device name in the final field. These samples mirror
// the kernel's actual formatting (space-separated fields).
const LOOPBACK_LINE: &str = "00000000000000000000000000000001 01 80 10 80         lo";
const ETH0_GLOBAL_LINE: &str = "2606280002200001024818932c5c1946 03 40 00 80         eth0";
const ETH0_LINKLOCAL_LINE: &str = "fe80000000000000020000fffe000001 03 40 20 80         eth0";

#[test]
fn a_real_interface_address_is_classified_active() {
    // "a line is treated as evidence of active IPv6 only when its device is
    // something other than `lo`" -- a global address on eth0 is egress-capable.
    let contents = format!("{LOOPBACK_LINE}\n{ETH0_GLOBAL_LINE}\n");
    let state = NetworkIptablesManager::classify_host_ipv6_state(Ok(contents));
    assert_eq!(
        state,
        HostIpv6State::Active,
        "a non-loopback interface with an IPv6 address must classify as Active; got {state:?}"
    );
}

#[test]
fn a_link_local_address_on_a_real_interface_is_still_active() {
    // The kernel lists the link-local `fe80::` address on any interface with
    // IPv6 up; its device is not `lo`, so the host has an IPv6 stack to filter.
    let contents = format!("{ETH0_LINKLOCAL_LINE}\n");
    let state = NetworkIptablesManager::classify_host_ipv6_state(Ok(contents));
    assert_eq!(
        state,
        HostIpv6State::Active,
        "a link-local address on eth0 must classify as Active; got {state:?}"
    );
}

#[test]
fn loopback_only_is_not_a_basis_for_claiming_egress_capable_ipv6() {
    // An IPv4-only host commonly still lists `::1` on `lo`. Loopback is not
    // egress-capable, so it must NOT be treated as active IPv6.
    let contents = format!("{LOOPBACK_LINE}\n");
    let state = NetworkIptablesManager::classify_host_ipv6_state(Ok(contents));
    assert_eq!(
        state,
        HostIpv6State::Inactive,
        "loopback-only `::1` on `lo` must classify as Inactive, not Active; got {state:?}"
    );
    assert_ne!(
        state,
        HostIpv6State::Active,
        "loopback-only `::1` must never be reported as egress-capable IPv6"
    );
}

#[test]
fn empty_contents_are_inactive() {
    let state = NetworkIptablesManager::classify_host_ipv6_state(Ok(String::new()));
    assert_eq!(
        state,
        HostIpv6State::Inactive,
        "an empty `/proc/net/if_inet6` means no IPv6 addresses; got {state:?}"
    );
}

#[test]
fn whitespace_only_contents_are_inactive() {
    let state = NetworkIptablesManager::classify_host_ipv6_state(Ok("\n  \n".to_string()));
    assert_eq!(
        state,
        HostIpv6State::Inactive,
        "blank lines carry no interface, so the state is Inactive; got {state:?}"
    );
}

#[test]
fn a_missing_file_is_a_confirmed_negative() {
    // A `NotFound` read means the kernel never created the file (IPv6 disabled
    // at boot), which IS a genuine "IPv6 is off" -> Inactive.
    let state =
        NetworkIptablesManager::classify_host_ipv6_state(Err(Error::from(ErrorKind::NotFound)));
    assert_eq!(
        state,
        HostIpv6State::Inactive,
        "a NotFound read (IPv6 disabled at boot) is a confirmed negative; got {state:?}"
    );
}

#[test]
fn an_unreadable_file_is_unknown_not_a_confirmed_negative() {
    // Any read error other than NotFound (permission denied, I/O error, /proc
    // not mounted) means "we could not determine the state", which must NOT be
    // silently converted into "IPv6 is off". This is the fail-open guard.
    let state = NetworkIptablesManager::classify_host_ipv6_state(Err(Error::from(
        ErrorKind::PermissionDenied,
    )));
    assert_eq!(
        state,
        HostIpv6State::Unknown,
        "a PermissionDenied read must be Unknown, not Inactive; got {state:?}"
    );
    assert_ne!(
        state,
        HostIpv6State::Inactive,
        "an unreadable IPv6 state must never be treated as a confirmed 'IPv6 is off'"
    );
}

#[test]
fn a_generic_io_error_is_unknown_not_a_confirmed_negative() {
    let state =
        NetworkIptablesManager::classify_host_ipv6_state(Err(Error::from(ErrorKind::Other)));
    assert_eq!(
        state,
        HostIpv6State::Unknown,
        "a generic I/O error must be Unknown, not Inactive; got {state:?}"
    );
}

// The three states must be distinct, or the PartialEq-based assertions above
// could silently accept a mutation that collapses two of them.
#[test]
fn host_ipv6_states_are_all_distinct() {
    assert_ne!(HostIpv6State::Active, HostIpv6State::Inactive);
    assert_ne!(HostIpv6State::Active, HostIpv6State::Unknown);
    assert_ne!(HostIpv6State::Inactive, HostIpv6State::Unknown);
}

// ---------------------------------------------------------------------------
// State -> "treat as active" mapping. This is the fail-open guard: Unknown
// must be treated as active so an unreadable IPv6 state fails closed rather
// than leaving IPv6 egress unfiltered.
// ---------------------------------------------------------------------------

#[test]
fn active_state_is_treated_as_active() {
    assert!(
        NetworkIptablesManager::ipv6_state_treated_as_active(HostIpv6State::Active),
        "Active must be treated as active"
    );
}

#[test]
fn inactive_state_is_not_treated_as_active() {
    assert!(
        !NetworkIptablesManager::ipv6_state_treated_as_active(HostIpv6State::Inactive),
        "Inactive must not be treated as active; there is genuinely nothing to filter"
    );
}

#[test]
fn unknown_state_is_treated_as_active_to_fail_closed() {
    // The fail-open guard: "we could not determine IPv6 state" must NOT become
    // "IPv6 is off". Treating Unknown as active means a failed ip6tables probe
    // then fails setup closed instead of leaving IPv6 egress unfiltered.
    assert!(
        NetworkIptablesManager::ipv6_state_treated_as_active(HostIpv6State::Unknown),
        "Unknown must be treated as active so an unreadable IPv6 state fails closed"
    );
}
