//! Spec-derived tests for loopback proxy-host rejection.
//! Written from the documented contract only.
//!
//! Contract source: doc comment on `host_is_loopback`:
//!   "127.0.0.0/8, ::1, or the name "localhost".
//!    Accepts bracketed IPv6 literals (e.g. `[::1]`)."

use super::*;

// ─── 127.0.0.0/8 ─────────────────────────────────────────────────────────────
// Contract: "127.0.0.0/8" — the entire /8 block is loopback, not just .1.

#[test]
fn the_canonical_loopback_address_is_loopback() {
    // Contract: 127.0.0.0/8
    assert!(
        host_is_loopback("127.0.0.1"),
        "input=127.0.0.1 — canonical loopback must be rejected"
    );
}

#[test]
fn a_non_canonical_address_inside_127_slash_8_is_loopback() {
    // Contract: "127.0.0.0/8" — the *whole* block, not only .1.
    // This case distinguishes a correct /8 check from an exact-match on 127.0.0.1.
    assert!(
        host_is_loopback("127.0.0.2"),
        "input=127.0.0.2 — entire 127.0.0.0/8 block must be loopback"
    );
}

#[test]
fn the_upper_bound_of_127_slash_8_is_loopback() {
    // Contract: "127.0.0.0/8" — 127.255.255.254 is the last usable host in the block.
    assert!(
        host_is_loopback("127.255.255.254"),
        "input=127.255.255.254 — top of 127.0.0.0/8 must be loopback"
    );
}

#[test]
fn a_midrange_127_address_is_loopback() {
    // Contract: "127.0.0.0/8"
    assert!(
        host_is_loopback("127.1.2.3"),
        "input=127.1.2.3 — mid-range 127.x.x.x must be loopback"
    );
}

#[test]
fn the_network_address_of_127_slash_8_is_loopback() {
    // Contract: "127.0.0.0/8" — network address itself is inside the block.
    assert!(
        host_is_loopback("127.0.0.0"),
        "input=127.0.0.0 — 127.0.0.0/8 network address must be loopback"
    );
}

// ─── 127.x.x.x near-misses ───────────────────────────────────────────────────

#[test]
fn an_address_just_above_127_slash_8_is_not_loopback() {
    // Contract negation: 128.0.0.1 is outside 127.0.0.0/8.
    assert!(
        !host_is_loopback("128.0.0.1"),
        "input=128.0.0.1 — outside 127.0.0.0/8, must NOT be loopback"
    );
}

#[test]
fn an_address_just_below_127_slash_8_is_not_loopback() {
    // Contract negation: 126.255.255.255 is outside 127.0.0.0/8.
    assert!(
        !host_is_loopback("126.255.255.255"),
        "input=126.255.255.255 — outside 127.0.0.0/8, must NOT be loopback"
    );
}

#[test]
fn a_private_rfc1918_address_is_not_loopback() {
    // Contract negation: only 127.0.0.0/8, ::1, or "localhost" are loopback.
    assert!(
        !host_is_loopback("10.0.3.1"),
        "input=10.0.3.1 — RFC 1918 private address must NOT be loopback"
    );
}

#[test]
fn the_unspecified_address_is_not_loopback() {
    // Contract negation: 0.0.0.0 is not listed as loopback.
    assert!(
        !host_is_loopback("0.0.0.0"),
        "input=0.0.0.0 — unspecified address must NOT be loopback"
    );
}

// ─── ::1 ─────────────────────────────────────────────────────────────────────
// Contract: "::1"

#[test]
fn the_ipv6_loopback_address_is_loopback() {
    // Contract: "::1"
    assert!(
        host_is_loopback("::1"),
        "input=::1 — IPv6 loopback must be rejected"
    );
}

// ─── Bracketed IPv6 ──────────────────────────────────────────────────────────
// Contract: "Accepts bracketed IPv6 literals (e.g. `[::1]`) as stored by the
//            proxy URL parser."

#[test]
fn bracketed_ipv6_loopback_is_loopback() {
    // Contract: explicit bracketed-form acceptance.
    assert!(
        host_is_loopback("[::1]"),
        "input=[::1] — bracketed IPv6 loopback must be rejected"
    );
}

#[test]
fn bracketed_non_loopback_ipv6_is_not_loopback() {
    // Contract: bracket stripping must not make a non-loopback address loopback.
    assert!(
        !host_is_loopback("[2001:db8::1]"),
        "input=[2001:db8::1] — bracketed non-loopback IPv6 must NOT be loopback"
    );
}

// ─── "localhost" ─────────────────────────────────────────────────────────────
// Contract: `or the name "localhost"` (exact name, not a prefix/substring rule).

#[test]
fn the_name_localhost_is_loopback() {
    // Contract: `or the name "localhost"`
    assert!(
        host_is_loopback("localhost"),
        "input=localhost — the name localhost must be loopback"
    );
}

#[test]
fn a_host_merely_prefixed_with_localhost_is_not_loopback() {
    // Contract: "the name" — exact match only.
    // A substring/prefix match would accept localhost.evil.com; the contract forbids it.
    assert!(
        !host_is_loopback("localhost.evil.com"),
        "input=localhost.evil.com — must NOT be loopback; contract requires exact name match"
    );
}

#[test]
fn a_host_that_contains_localhost_as_a_suffix_is_not_loopback() {
    // Contract: exact name match, not substring.
    assert!(
        !host_is_loopback("notlocalhost"),
        "input=notlocalhost — must NOT be loopback; contract requires exact name match"
    );
}

// ─── Documenting tests for contract-silent cases ─────────────────────────────
// These record the *observed* behavior.  They are NOT contract assertions.
// See ## CONTRACT GAPS in the task report for reasoning.

#[test]
#[ignore = "DOCUMENTING — contract is silent on empty string behavior; not a requirement"]
fn documenting_empty_string_behavior_is_not_loopback() {
    // The contract names three families; empty string matches none of them.
    // Expected: false.  If this fails, the implementation treats "" as loopback,
    // which is worth surfacing.
    assert!(
        !host_is_loopback(""),
        "input='' — documenting: empty string should not be loopback"
    );
}
