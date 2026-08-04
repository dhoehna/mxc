//! Spec-derived tests for `ProxyAddress::rewrite_url_host`.
//! Written from the documented contract and the review that produced the fix.
//!
//! Primary contract source: doc comment on `rewrite_url_host`:
//!   "Replace the host of `raw` with `ip`, preserving scheme, credentials,
//!    port and path. Returns `None` when `raw` is not a parseable URL or the
//!    host cannot be replaced."
//!
//! Additional requirement (sourced from PR #632 review by Soham, NOT from the
//! doc comment):  a URL carrying a query string and/or a fragment must survive
//! the rewrite intact.  The doc comment is silent on query and fragment —
//! that silence is reported under CONTRACT GAPS below.

use super::*;

// ─── Helper ──────────────────────────────────────────────────────────────────

/// Assert that `result` is `Some`, that it contains `new_ip`, that it does NOT
/// contain `old_host`, and that every non-host component in `expected_parts`
/// is still present.  Also compare against the full `expected` string so that
/// failures are legible.
fn assert_rewrite(
    input: &str,
    new_ip: &str,
    old_host: &str,
    expected_parts: &[&str],
    expected: &str,
) {
    let result = ProxyAddress::rewrite_url_host(input, new_ip);
    assert!(
        result.is_some(),
        "input={input:?} new_ip={new_ip:?} — expected Some(..), got None"
    );
    let out = result.unwrap();
    assert_eq!(
        out, expected,
        "input={input:?} new_ip={new_ip:?} — full output mismatch"
    );
    assert!(
        out.contains(new_ip),
        "input={input:?} — output {out:?} does not contain new ip {new_ip:?}"
    );
    assert!(
        !out.contains(old_host),
        "input={input:?} — output {out:?} still contains old host {old_host:?}"
    );
    for part in expected_parts {
        assert!(
            out.contains(part),
            "input={input:?} — output {out:?} is missing component {part:?}"
        );
    }
}

// ─── Plain http://host:port/path ─────────────────────────────────────────────

#[test]
fn a_plain_url_with_port_and_path_rewrites_the_host() {
    // Contract: "preserving scheme, credentials, port and path"
    assert_rewrite(
        "http://original.host:3128/some/path",
        "192.168.1.5",
        "original.host",
        &["http://", ":3128", "/some/path"],
        "http://192.168.1.5:3128/some/path",
    );
}

#[test]
fn a_url_without_a_path_rewrites_the_host() {
    // Contract: path preservation; no path edge case.
    assert_rewrite(
        "http://proxy.example.com:8080",
        "10.0.0.1",
        "proxy.example.com",
        &["http://", ":8080"],
        "http://10.0.0.1:8080",
    );
}

#[test]
fn a_url_without_a_port_rewrites_the_host() {
    // Contract: "preserving … port" — absence of a port must also be preserved.
    assert_rewrite(
        "http://proxy.example.com/path",
        "10.0.0.2",
        "proxy.example.com",
        &["http://", "/path"],
        "http://10.0.0.2/path",
    );
    // Must not insert a spurious port: the only colon in the output is in "http:"
    let out = ProxyAddress::rewrite_url_host("http://proxy.example.com/path", "10.0.0.2").unwrap();
    let after_scheme = out.trim_start_matches("http://");
    assert!(
        !after_scheme.contains(':'),
        "output {out:?} must not contain a port-colon when no port was present in input"
    );
}

// ─── Query string ─────────────────────────────────────────────────────────────
// Requirement sourced from PR #632 review (Soham), NOT from the doc comment.
// The prior pop()-based implementation corrupted query strings.

#[test]
fn a_query_string_survives_the_host_rewrite() {
    // Review requirement: query string must survive intact.
    assert_rewrite(
        "http://proxy.example.com:3128/path?a=1&b=2",
        "192.0.2.1",
        "proxy.example.com",
        &["http://", ":3128", "/path", "?a=1&b=2"],
        "http://192.0.2.1:3128/path?a=1&b=2",
    );
}

#[test]
fn a_query_string_without_a_path_survives_the_host_rewrite() {
    // Review requirement: query string must survive even with no explicit path.
    // Note: URL normalization may insert a "/" before the "?" — the expected
    // string accounts for this; the invariant assertion (query present, old
    // host absent) is the binding requirement.
    let input = "http://proxy.example.com:3128?token=abc";
    let new_ip = "192.0.2.1";
    let result = ProxyAddress::rewrite_url_host(input, new_ip);
    assert!(
        result.is_some(),
        "input={input:?} — expected Some(..), got None"
    );
    let out = result.unwrap();
    assert!(
        out.contains("?token=abc"),
        "input={input:?} — query string must survive; output was {out:?}"
    );
    assert!(
        out.contains(new_ip),
        "input={input:?} — output {out:?} does not contain new ip {new_ip:?}"
    );
    assert!(
        !out.contains("proxy.example.com"),
        "input={input:?} — output {out:?} still contains old host"
    );
    assert!(
        out.contains(":3128"),
        "input={input:?} — port must survive; output was {out:?}"
    );
}

// ─── Fragment ────────────────────────────────────────────────────────────────
// Requirement sourced from PR #632 review (Soham), NOT from the doc comment.

#[test]
fn a_fragment_survives_the_host_rewrite() {
    // Review requirement: fragment must survive intact.
    assert_rewrite(
        "http://proxy.example.com:3128/page#section",
        "192.0.2.2",
        "proxy.example.com",
        &["http://", ":3128", "/page", "#section"],
        "http://192.0.2.2:3128/page#section",
    );
}

#[test]
fn both_a_query_string_and_a_fragment_survive_the_host_rewrite() {
    // Review requirement: both must survive together — the pop()-based bug
    // corrupted whichever appeared last.
    assert_rewrite(
        "http://proxy.example.com:3128/path?q=1#anchor",
        "192.0.2.3",
        "proxy.example.com",
        &["http://", ":3128", "/path", "?q=1", "#anchor"],
        "http://192.0.2.3:3128/path?q=1#anchor",
    );
}

// ─── Credentials ─────────────────────────────────────────────────────────────

#[test]
fn credentials_survive_the_host_rewrite() {
    // Contract: "preserving scheme, credentials, port and path"
    assert_rewrite(
        "http://user:pass@proxy.example.com:3128/",
        "172.16.0.1",
        "proxy.example.com",
        &["http://", "user:pass@", ":3128", "/"],
        "http://user:pass@172.16.0.1:3128/",
    );
}

// ─── None cases ──────────────────────────────────────────────────────────────

#[test]
fn an_unparseable_input_returns_none() {
    // Contract: "Returns `None` when `raw` is not a parseable URL"
    let result = ProxyAddress::rewrite_url_host("not a url at all !!!!", "192.0.2.9");
    assert!(
        result.is_none(),
        "input='not a url at all !!!!' — expected None for unparseable input, got {result:?}"
    );
}

#[test]
#[ignore = "DOCUMENTING — contract is silent on whether an empty-host URL (file:///) is rewriteable; observed: implementation returns Some and fills in the ip. See CONTRACT GAPS."]
fn documenting_empty_host_file_url_behavior() {
    // file:/// has an empty host authority.  Contract says "None when host
    // cannot be replaced" but does not define whether empty-host == cannot-replace.
    // Observed behavior: Some("file://192.0.2.10/etc/passwd").
    // Not asserting a specific value; just documenting the call succeeds.
    let result = ProxyAddress::rewrite_url_host("file:///etc/passwd", "192.0.2.10");
    // Document current behavior without requiring None or Some.
    let _ = result;
}

// ─── Documenting test — IPv6 target ──────────────────────────────────────────
// The contract does not state whether the result should be bracketed when
// the new `ip` is an IPv6 address.  See CONTRACT GAPS.

#[test]
#[ignore = "DOCUMENTING — contract is silent on whether IPv6 ip argument is auto-bracketed in the output; not a requirement"]
fn documenting_ipv6_target_ip_behavior() {
    // We exercise the call and assert the host component appeared somewhere.
    // The bracketing question is unresolved; see CONTRACT GAPS.
    let ip = "::1";
    let result = ProxyAddress::rewrite_url_host("http://proxy.example.com:3128/path", ip);
    assert!(
        result.is_some(),
        "input=http://proxy.example.com:3128/path ip={ip:?} — expected Some(..), got None"
    );
    let out = result.unwrap();
    // Either bare or bracketed form is acceptable until the contract says otherwise.
    assert!(
        out.contains(ip) || out.contains(&format!("[{ip}]")),
        "output {out:?} must contain the IPv6 ip in some form"
    );
}
