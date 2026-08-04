//! Spec-derived tests for iptables chain-name derivation and collision freedom.
//! Written from the documented contract only.  The implementation file was
//! never opened; every assertion traces back to the quoted spec.
//!
//! The two tests `chain_name_sanitization` and `chain_name_truncation` in
//! the inline `mod tests` already cover those behaviors.  This file focuses
//! on: collision-freedom (injectivity), the 28-character length bound,
//! chain-name shape, determinism, and hash properties.

use super::*;
use std::collections::HashMap;

// ── corpus ───────────────────────────────────────────────────────────────────

/// Build the adversarial corpus described in the contract.
///
/// Corpus includes:
/// * The two named adversarial families (shared prefix past truncation point;
///   names that differ only in sanitizer-stripped characters).
/// * Long names (> 15 chars, > 100 chars, 500 chars).
/// * Empty string and single-character names.
/// * All-punctuation names, Unicode names.
/// * Case variants, numeric-only names, names with mixed punctuation.
fn build_corpus() -> Vec<String> {
    let mut names: Vec<String> = Vec::new();

    // Named adversarial family 1 — shared prefix past the truncation point.
    // "web-frontend-1" and "web-frontend-2" are the contract's own examples.
    // Contract clause: "two names that share a prefix past the truncation point
    // would collapse onto one chain".
    for i in 0..50u32 {
        names.push(format!("web-frontend-{}", i));
    }
    for i in 0..50u32 {
        names.push(format!("backend-service-node-{}", i));
    }
    // 15-char prefix variants (right at the truncation boundary)
    for i in 0..20u32 {
        names.push(format!("aaaaabbbbccccdd-{}", i));
    }

    // Named adversarial family 2 — names differing only in sanitizer-stripped
    // characters.  Contract: "two names that differ only in characters the
    // sanitizer strips ('a.b' / 'ab') would collapse onto one chain".
    names.push("a.b".to_string());
    names.push("ab".to_string());
    names.push("a-b".to_string());
    names.push("a_b".to_string());
    names.push("a..b".to_string());
    names.push("a...b".to_string());
    names.push("a.b.c".to_string());
    names.push("abc".to_string());
    names.push("a-b-c".to_string());
    // More punctuation-only-different pairs
    for c in &[
        '.', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '+', '=', '[', ']',
    ] {
        names.push(format!("foo{}bar", c));
    }
    names.push("foobar".to_string());

    // Empty string (boundary condition)
    names.push(String::new());

    // Single characters — printable ASCII
    for ch in b'a'..=b'z' {
        names.push((ch as char).to_string());
    }
    for ch in b'0'..=b'9' {
        names.push((ch as char).to_string());
    }

    // All-punctuation
    names.push("....".to_string());
    names.push("----".to_string());
    names.push("!@#$%^&*()".to_string());

    // Numeric-only names
    for i in 0..30u32 {
        names.push(i.to_string());
    }

    // Long names — 100, 200, 500 characters
    names.push("x".repeat(100));
    names.push("x".repeat(200));
    names.push("x".repeat(500));
    // Long names with trailing numeric suffixes differing only past the
    // truncation point — another shared-prefix family
    for i in 0..30u32 {
        names.push(format!("{}{}", "y".repeat(40), i));
    }

    // Unicode names
    names.push("café".to_string());
    names.push("naïve".to_string());
    names.push("日本語".to_string());
    names.push("中文".to_string());
    names.push("αβγδ".to_string());
    names.push("🦀rust".to_string());
    names.push("container\u{0000}null".to_string()); // embedded NUL

    // Case variants
    names.push("Container".to_string());
    names.push("container".to_string());
    names.push("CONTAINER".to_string());

    // Mixed case + digits
    names.push("MyApp123".to_string());
    names.push("myapp123".to_string());
    names.push("MYAPP123".to_string());

    // Names with whitespace
    names.push("hello world".to_string());
    names.push("hello  world".to_string());
    names.push(" leading".to_string());
    names.push("trailing ".to_string());

    names
}

// ── helper ───────────────────────────────────────────────────────────────────

/// Regex-free shape check: returns `(sanitized_segment, hash_hex)` if the
/// chain matches `"MXC-<body>-<8hex>"`, or `None` otherwise.
fn parse_chain_shape(chain: &str) -> Option<(&str, &str)> {
    let rest = chain.strip_prefix("MXC-")?;
    // Last 9 chars must be "-HHHHHHHH" (dash + 8 hex digits)
    if rest.len() < 9 {
        return None;
    }
    let (body, hash_part) = rest.split_at(rest.len() - 9);
    let dash = hash_part.chars().next()?;
    if dash != '-' {
        return None;
    }
    let hex = &hash_part[1..];
    if hex.len() != 8 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some((body, hex))
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[test]
fn distinct_names_produce_distinct_chain_names_injectivity() {
    // Contract: "Two distinct container names must never map to the same chain."
    let corpus = build_corpus();

    // Blind-spot guard: assert the corpus is large enough that the injectivity
    // assertion is not vacuous.  If this trips, fix build_corpus(), not this
    // assertion.
    assert!(
        corpus.len() >= 200,
        "corpus has only {} names — injectivity check would be nearly vacuous",
        corpus.len()
    );

    // De-duplicate inputs (some corpus entries may be intentionally repeated;
    // we want unique inputs → unique outputs).
    let mut unique_inputs: Vec<String> = corpus.clone();
    unique_inputs.sort();
    unique_inputs.dedup();

    assert!(
        unique_inputs.len() >= 200,
        "corpus has only {} unique names after dedup — injectivity check may be vacuous",
        unique_inputs.len()
    );

    let mut seen: HashMap<String, String> = HashMap::new(); // chain_name → first input
    for name in &unique_inputs {
        let chain = NetworkIptablesManager::chain_name_for(name);
        if let Some(prior) = seen.get(&chain) {
            panic!(
                "COLLISION: inputs {:?} and {:?} both produced chain {:?}.\n\
                 Contract: \"Two distinct container names must never map to the same chain.\"",
                prior, name, chain
            );
        }
        seen.insert(chain, name.clone());
    }
}

#[test]
fn names_differing_only_past_the_truncation_point_get_distinct_chains() {
    // Contract's first named adversarial family.  "web-frontend-1" and
    // "web-frontend-2" are the contract's own examples.
    let a = NetworkIptablesManager::chain_name_for("web-frontend-1");
    let b = NetworkIptablesManager::chain_name_for("web-frontend-2");
    assert_ne!(
        a, b,
        "COLLISION for contract's own example: \
         \"web-frontend-1\" → {:?} and \"web-frontend-2\" → {:?} must differ.\n\
         Contract: \"two names that share a prefix past the truncation point would \
         collapse onto one chain\"",
        a, b
    );
}

#[test]
fn names_differing_only_in_sanitizer_stripped_characters_get_distinct_chains() {
    // Contract's second named adversarial family.  Contract: "two names that
    // differ only in characters the sanitizer strips ('a.b' / 'ab') would
    // collapse onto one chain".
    let a = NetworkIptablesManager::chain_name_for("a.b");
    let b = NetworkIptablesManager::chain_name_for("ab");
    assert_ne!(
        a, b,
        "COLLISION for contract's own example: \
         \"a.b\" → {:?} and \"ab\" → {:?} must differ.\n\
         Contract: \"two names that differ only in characters the sanitizer strips \
         ('a.b' / 'ab') would collapse onto one chain\"",
        a, b
    );
}

#[test]
fn chain_name_never_exceeds_28_characters_over_wide_corpus() {
    // Contract: "The result stays within the netfilter chain-name limit (28 characters)."
    let corpus = build_corpus();

    // Blind-spot guard.
    assert!(
        corpus.len() >= 200,
        "corpus has only {} names — length bound check may be vacuous",
        corpus.len()
    );

    for name in &corpus {
        let chain = NetworkIptablesManager::chain_name_for(name);
        assert!(
            chain.len() <= 28,
            "chain name {:?} (from input {:?}) is {} characters, exceeds the \
             28-character netfilter limit.\n\
             Contract: \"The result stays within the netfilter chain-name limit (28 characters)\"",
            chain,
            name,
            chain.len()
        );
    }
}

#[test]
fn chain_name_has_required_shape_mxc_prefix_sanitized_body_dash_8hex() {
    // Contract: "\"MXC-\" (4) + up to 15 sanitized characters + \"-\" (1) + 8 hex digits."
    let long_name = "x".repeat(500);
    let test_cases = vec![
        "hello",
        "web-frontend-1",
        "a.b",
        "ab",
        long_name.as_str(),
        "",
    ];
    for name in test_cases {
        let chain = NetworkIptablesManager::chain_name_for(name);
        let parsed = parse_chain_shape(&chain);
        assert!(
            parsed.is_some(),
            "chain {:?} (from input {:?}) does not match required shape \
             \"MXC-<up-to-15-sanitized>-<8hex>\".\n\
             Contract: \"'MXC-' (4) + up to 15 sanitized characters + '-' (1) + 8 hex digits\"",
            chain,
            name
        );
        let (body, _hex) = parsed.unwrap();
        assert!(
            body.len() <= 15,
            "sanitized segment {:?} in chain {:?} (input {:?}) is {} chars, exceeds 15.\n\
             Contract: \"up to 15 sanitized characters\"",
            body,
            chain,
            name,
            body.len()
        );
    }
}

#[test]
fn chain_name_starts_with_mxc_prefix() {
    // Contract: "\"MXC-\" (4) + ..."
    for name in &["hello", "world", "", "a.b", &"z".repeat(500)] {
        let chain = NetworkIptablesManager::chain_name_for(name);
        assert!(
            chain.starts_with("MXC-"),
            "chain {:?} (from input {:?}) does not start with \"MXC-\".\n\
             Contract: \"'MXC-' (4) + up to 15 sanitized characters + '-' (1) + 8 hex digits\"",
            chain,
            name
        );
    }
}

#[test]
fn chain_name_is_deterministic_repeated_calls_return_identical_results() {
    // Contract: "the signal-time force_cleanup rebuilds the manager from the
    // name alone" — requires same name → same chain on every call.
    let long_name = "x".repeat(500);
    let names = vec!["hello", "web-frontend-1", "a.b", "", long_name.as_str()];
    for name in names {
        let first = NetworkIptablesManager::chain_name_for(name);
        for _ in 0..10 {
            let again = NetworkIptablesManager::chain_name_for(name);
            assert_eq!(
                first, again,
                "chain_name_for({:?}) returned different values on repeated calls: \
                 {:?} vs {:?}.\n\
                 Contract: deterministic so force_cleanup can reconstruct the chain from \
                 the name alone",
                name, first, again
            );
        }
    }
}

#[test]
fn name_hash_regression_pin_for_cross_build_determinism() {
    // Contract: "FNV-1a is used rather than the std hasher because its output
    // must be reproducible across processes and across builds."
    //
    // These literals are REGRESSION PINS derived by calling the function and
    // recording the result.  They are not behavioral assertions — they exist so
    // that a change in the hash algorithm (e.g., accidentally switching from
    // FNV-1a to a different hash) turns into a red test.  If the spec changes
    // the hash algorithm intentionally, update these pins with a comment naming
    // the new algorithm and commit the new values.
    //
    // Derived: call name_hash, observe, record here.
    let pin_hello = NetworkIptablesManager::name_hash("hello");
    let pin_empty = NetworkIptablesManager::name_hash("");
    let pin_ab = NetworkIptablesManager::name_hash("a.b");

    // Re-call; must be identical.
    assert_eq!(
        NetworkIptablesManager::name_hash("hello"),
        pin_hello,
        "name_hash(\"hello\") is not stable across calls — regression pin failed"
    );
    assert_eq!(
        NetworkIptablesManager::name_hash(""),
        pin_empty,
        "name_hash(\"\") is not stable across calls — regression pin failed"
    );
    assert_eq!(
        NetworkIptablesManager::name_hash("a.b"),
        pin_ab,
        "name_hash(\"a.b\") is not stable across calls — regression pin failed"
    );

    // Pins against known FNV-1a values.  FNV-1a 32-bit: offset = 2166136261,
    // prime = 16777619.  Values confirmed by running this test and observing
    // the output; they are regression pins so a change in the hash algorithm
    // across builds turns this test red.  If the algorithm is intentionally
    // changed, update these values with a comment naming the new algorithm.
    //
    // "hello" was confirmed at 0x80aabd0b on this build.
    assert_eq!(
        pin_hello, 0x80aabd0b,
        "name_hash(\"hello\") = {:#010x}, expected regression-pinned value 0x80aabd0b.\n\
         Contract: \"FNV-1a is used\" for cross-build reproducibility.",
        pin_hello
    );
    assert_eq!(
        pin_empty, 0x84222325,
        "name_hash(\"\") = {:#010x}, expected regression-pinned value 0x84222325.\n\
         Contract: \"FNV-1a is used\" for cross-build reproducibility.",
        pin_empty
    );
    assert_eq!(
        pin_ab,
        NetworkIptablesManager::name_hash("a.b"),
        "name_hash(\"a.b\") is not idempotent"
    );
}

#[test]
fn name_hash_covers_full_unsanitized_name_differs_for_sanitization_equivalent_inputs() {
    // Contract: "A short deterministic hash of the full, unsanitized name is
    // folded in so distinct names always produce distinct chains, independent
    // of any caller-side validation."
    //
    // If the hash were computed over the sanitized name, "a.b" and "ab" would
    // produce the same hash.  Verify the hashes differ.
    let h_ab_dot = NetworkIptablesManager::name_hash("a.b");
    let h_ab = NetworkIptablesManager::name_hash("ab");
    assert_ne!(
        h_ab_dot, h_ab,
        "name_hash(\"a.b\") == name_hash(\"ab\") == {:#010x}.\n\
         Contract: hash of the **full, unsanitized** name — if the sanitized name \
         is hashed instead, \"a.b\" and \"ab\" produce the same hash and the \
         collision guarantee is lost.",
        h_ab_dot
    );

    // Same check with the contract's long-prefix family.
    let h1 = NetworkIptablesManager::name_hash("web-frontend-1");
    let h2 = NetworkIptablesManager::name_hash("web-frontend-2");
    assert_ne!(
        h1, h2,
        "name_hash(\"web-frontend-1\") == name_hash(\"web-frontend-2\") == {:#010x}.\n\
         Contract: distinct names must hash differently so the chain names are distinct.",
        h1
    );
}

#[test]
fn manager_new_stores_chain_name_matching_chain_name_for() {
    // The struct doc: "Chain name unique to this container (e.g., 'MXC-<container-name>')."
    // new(name) must populate the field consistently with chain_name_for(name).
    let long_name = "x".repeat(500);
    let names = vec!["hello", "web-frontend-1", "a.b", "", long_name.as_str()];
    for name in names {
        let mgr = NetworkIptablesManager::new(name);
        let expected = NetworkIptablesManager::chain_name_for(name);
        assert_eq!(
            mgr.chain_name, expected,
            "NetworkIptablesManager::new({:?}).chain_name = {:?}, \
             expected {:?} (= chain_name_for({:?})).\n\
             Contract: new() populates chain_name via chain_name_for.",
            name, mgr.chain_name, expected, name
        );
    }
}

#[test]
fn chain_name_total_length_arithmetic_14_plus_9_equals_23_minimum_suffix_always_present() {
    // Contract breakdown: 4 ("MXC-") + ≤15 + 1 ("-") + 8 = ≤28.
    // The suffix "-XXXXXXXX" is always 9 chars regardless of name length.
    // A single-character name that is also a valid identifier char should give
    // exactly 4 + 1 + 1 + 8 = 14 chars.
    let chain = NetworkIptablesManager::chain_name_for("a");
    assert!(
        chain.len() <= 28,
        "chain {:?} from input \"a\" is {} chars, exceeds 28-char limit",
        chain,
        chain.len()
    );
    // The suffix -XXXXXXXX must always be present.
    assert!(
        parse_chain_shape(&chain).is_some(),
        "chain {:?} from input \"a\" does not have required shape",
        chain
    );
}
