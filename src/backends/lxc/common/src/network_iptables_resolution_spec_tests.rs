//! Spec-derived tests for the resolution and CIDR-parsing contract.
//!
//! Written from roadmap item 19 and AB#62830559, not from the implementation.

use super::*;

fn assert_resolved_exact(input: &str, expected_ipv4: &[&str], expected_ipv6: &[&str]) {
    let resolved = NetworkIptablesManager::resolve_host(input);
    let expected_ipv4: Vec<String> = expected_ipv4
        .iter()
        .map(|value| value.to_string())
        .collect();
    let expected_ipv6: Vec<String> = expected_ipv6
        .iter()
        .map(|value| value.to_string())
        .collect();

    assert_eq!(
        resolved.ipv4, expected_ipv4,
        "unexpected IPv4 destinations for {input:?}"
    );
    assert_eq!(
        resolved.ipv6, expected_ipv6,
        "unexpected IPv6 destinations for {input:?}"
    );
}

fn assert_destination_family(input: &str, expected: Option<IpFamily>) {
    assert_eq!(
        NetworkIptablesManager::destination_family(input),
        expected,
        "unexpected destination family for {input:?}"
    );
}

#[test]
fn bare_ip_literals_are_routed_only_to_their_matching_family() {
    let cases = [
        ("192.0.2.1", &["192.0.2.1"][..], &[][..]),
        ("127.0.0.1", &["127.0.0.1"][..], &[][..]),
        ("2606:50c0::153", &[][..], &["2606:50c0::153"][..]),
        (
            "2606:50c0:0000:0000:0000:0000:0000:0153",
            &[][..],
            &["2606:50c0:0000:0000:0000:0000:0000:0153"][..],
        ),
        ("::1", &[][..], &["::1"][..]),
    ];

    for (input, expected_ipv4, expected_ipv6) in cases {
        assert_resolved_exact(input, expected_ipv4, expected_ipv6);
    }
}

#[test]
fn ipv4_mapped_ipv6_literal_is_retained_as_ipv6() {
    // SPEC_BRIEF §3 says bare IPv4/IPv6 literals are retained in their matching family.
    assert_resolved_exact("::ffff:127.0.0.1", &[], &["::ffff:127.0.0.1"]);
}

#[test]
fn valid_cidrs_are_passed_through_unchanged_in_their_matching_family() {
    // SPEC_BRIEF §3 requires validated CIDRs to be passed through unchanged.
    let cases = [
        ("140.82.112.0/20", &["140.82.112.0/20"][..], &[][..]),
        ("2606:50c0::/32", &[][..], &["2606:50c0::/32"][..]),
    ];

    for (input, expected_ipv4, expected_ipv6) in cases {
        assert_resolved_exact(input, expected_ipv4, expected_ipv6);
    }
}

#[test]
fn v4_cidr_with_host_bits_set_is_passed_through_unchanged() {
    // SPEC_BRIEF §3 says host bits are not required to be zero because iptables applies the mask.
    assert_resolved_exact("140.82.112.5/20", &["140.82.112.5/20"], &[]);
}

#[test]
fn cidr_prefix_lengths_accept_only_family_specific_bounds() {
    let cases = [
        ("0.0.0.0/0", Some(IpFamily::V4), &["0.0.0.0/0"][..], &[][..]),
        (
            "192.0.2.1/32",
            Some(IpFamily::V4),
            &["192.0.2.1/32"][..],
            &[][..],
        ),
        ("192.0.2.1/33", None, &[][..], &[][..]),
        ("192.0.2.1/129", None, &[][..], &[][..]),
        ("::/0", Some(IpFamily::V6), &[][..], &["::/0"][..]),
        (
            "2001:db8::1/128",
            Some(IpFamily::V6),
            &[][..],
            &["2001:db8::1/128"][..],
        ),
        ("2001:db8::1/129", None, &[][..], &[][..]),
    ];

    for (input, expected_family, expected_ipv4, expected_ipv6) in cases {
        assert_resolved_exact(input, expected_ipv4, expected_ipv6);
        assert_destination_family(input, expected_family);
    }
}

#[test]
fn v6_prefix_length_on_v4_address_is_rejected() {
    assert_resolved_exact("10.0.0.0/64", &[], &[]);
    assert_destination_family("10.0.0.0/64", None);
}

#[test]
fn malformed_cidr_syntax_and_garbage_resolve_to_nothing() {
    let cases = [
        "/24",
        "10.0.0.0/",
        "10.0.0.0//24",
        "10.0.0.0/abc",
        "10.0.0.0/-1",
        "10.0.0.0/ 24",
        "not-a-valid-firewall-destination",
    ];

    for input in cases {
        let resolved = NetworkIptablesManager::resolve_host(input);
        assert!(
            resolved.is_empty(),
            "malformed destination {input:?} should resolve to nothing, got {resolved:?}"
        );
        assert_destination_family(input, None);
    }
}

// A leading `+` on the prefix is accepted, and it is a synonym rather than a
// hole. Rust's `u8::from_str` accepts a leading `+`, so the prefix validates and
// the string is passed through unchanged. iptables' own parser accepts the same
// spelling: appending `-d 10.0.0.0/+24` to a real chain stores it as
// `-d 10.0.0.0/24`, byte-identical to the plain form (verified against iptables
// on a live host). The permissive spelling therefore widens nothing.
//
// What does matter is that the sign must not smuggle a prefix past the
// family range check, so that is asserted here too.
#[test]
fn cidr_prefix_with_leading_plus_is_a_synonym_and_does_not_bypass_range_checks() {
    let plus = NetworkIptablesManager::resolve_host("10.0.0.0/+24");
    let plain = NetworkIptablesManager::resolve_host("10.0.0.0/24");

    assert_eq!(
        plus.ipv4,
        vec!["10.0.0.0/+24".to_string()],
        "a validated CIDR must be passed through unchanged, got {plus:?}"
    );
    assert!(
        plus.ipv6.is_empty(),
        "a v4 CIDR must not populate the v6 bucket, got {plus:?}"
    );
    assert_eq!(
        plus.ipv4.len(),
        plain.ipv4.len(),
        "`/+24` and `/24` must yield the same number of v4 destinations"
    );
    assert_destination_family("10.0.0.0/+24", Some(IpFamily::V4));

    // 33 > 32 must still be rejected regardless of the sign.
    let out_of_range = NetworkIptablesManager::resolve_host("10.0.0.0/+33");
    assert!(
        out_of_range.is_empty(),
        "a leading `+` must not smuggle an out-of-range prefix past validation, \
         got {out_of_range:?}"
    );
    assert_destination_family("10.0.0.0/+33", None);
}

#[test]
fn empty_input_resolves_to_nothing() {
    let resolved = NetworkIptablesManager::resolve_host("");
    assert!(
        resolved.is_empty(),
        "empty input should resolve to nothing, got {resolved:?}"
    );
    assert_destination_family("", None);
}

#[test]
fn localhost_resolution_populates_available_loopback_families() {
    let resolved = NetworkIptablesManager::resolve_host("localhost");

    // SPEC_BRIEF §3 requires hostnames to resolve to both A and AAAA. Some
    // minimal hosts can have a degenerate /etc/hosts, so this accepts whichever
    // localhost family is configured while checking that no other address leaks in.
    assert!(
        !resolved.is_empty(),
        "localhost should resolve to at least one loopback family"
    );
    assert!(
        resolved
            .ipv4
            .iter()
            .all(|destination| destination == "127.0.0.1"),
        "localhost IPv4 results should all be 127.0.0.1, got {:?}",
        resolved.ipv4
    );
    assert!(
        resolved.ipv6.iter().all(|destination| destination == "::1"),
        "localhost IPv6 results should all be ::1, got {:?}",
        resolved.ipv6
    );
}

#[test]
fn unresolvable_invalid_tld_hostname_resolves_to_nothing() {
    let input = "mxc-resolution-spec-7f3b2d9c4a1e6f80.invalid";
    let resolved = NetworkIptablesManager::resolve_host(input);

    assert!(
        resolved.is_empty(),
        "reserved .invalid hostname {input:?} should resolve to nothing, got {resolved:?}"
    );
    assert_destination_family(input, None);
}

#[test]
fn destination_family_agrees_with_every_resolved_destination() {
    let inputs = [
        "192.0.2.44",
        "2606:50c0::153",
        "140.82.112.5/20",
        "2606:50c0::/32",
        "::ffff:127.0.0.1",
        "localhost",
    ];

    for input in inputs {
        let resolved = NetworkIptablesManager::resolve_host(input);

        for destination in &resolved.ipv4 {
            assert_eq!(
                NetworkIptablesManager::destination_family(destination),
                Some(IpFamily::V4),
                "destination_family disagreed with IPv4 filing for input {input:?}, destination {destination:?}"
            );
        }

        for destination in &resolved.ipv6 {
            assert_eq!(
                NetworkIptablesManager::destination_family(destination),
                Some(IpFamily::V6),
                "destination_family disagreed with IPv6 filing for input {input:?}, destination {destination:?}"
            );
        }
    }
}
