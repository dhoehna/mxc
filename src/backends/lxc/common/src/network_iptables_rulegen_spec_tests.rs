//! Spec-derived tests for the firewall rule-argument generation contract.
//!
//! Written from roadmap item 19 and AB#62830559, not from the implementation.

use super::*;

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

fn joined(rule: &[String]) -> String {
    rule.join(" ")
}

fn assert_rule_contains(rule: &[String], expected: &str, input: &str) {
    assert!(
        rule.iter().any(|arg| arg == expected),
        "rule for {input} should contain {expected:?}; actual: {rule:?}"
    );
}

fn assert_rule_omits(rule: &[String], unexpected: &str, input: &str) {
    assert!(
        !rule.iter().any(|arg| arg == unexpected),
        "rule for {input} should not contain {unexpected:?}; actual: {rule:?}"
    );
}

fn policy_with_hosts(allowed_hosts: &[&str], blocked_hosts: &[&str]) -> ContainerPolicy {
    ContainerPolicy {
        allowed_hosts: strings(allowed_hosts),
        blocked_hosts: strings(blocked_hosts),
        ..Default::default()
    }
}

#[test]
fn allow_and_deny_actions_map_to_exact_iptables_jump_targets() {
    assert_eq!(
        NetworkIptablesManager::rule_action_arg(&RuleAction::Allow),
        "ACCEPT",
        "RuleAction::Allow should map to ACCEPT exactly"
    );
    assert_eq!(
        NetworkIptablesManager::rule_action_arg(&RuleAction::Deny),
        "DROP",
        "RuleAction::Deny should map to DROP exactly"
    );
}

#[test]
fn destination_literals_and_cidrs_land_only_in_their_address_family_bucket() {
    let cases = [
        ("192.0.2.10", "ipv4 bare literal", true),
        ("192.0.2.10/24", "ipv4 CIDR", true),
        ("2001:db8::10", "ipv6 bare literal", false),
        ("2001:db8::10/64", "ipv6 CIDR", false),
    ];

    for (destination, label, is_ipv4) in cases {
        let rules = NetworkIptablesManager::build_host_rule_args(
            "MXC-family-split",
            destination,
            &RuleAction::Allow,
        );

        if is_ipv4 {
            assert_eq!(
                rules.ipv4.len(),
                1,
                "{label} {destination} should produce one IPv4 rule; actual: {rules:?}"
            );
            assert!(
                rules.ipv6.is_empty(),
                "{label} {destination} should leave IPv6 rules empty; actual: {rules:?}"
            );
            assert_rule_contains(&rules.ipv4[0], destination, destination);
        } else {
            assert!(
                rules.ipv4.is_empty(),
                "{label} {destination} must not leak into IPv4 rules; actual: {rules:?}"
            );
            assert_eq!(
                rules.ipv6.len(),
                1,
                "{label} {destination} should produce one IPv6 rule; actual: {rules:?}"
            );
            assert_rule_contains(&rules.ipv6[0], destination, destination);
        }
    }
}

#[test]
fn mixed_family_host_list_produces_matching_rule_count_in_each_bucket() {
    let policy = policy_with_hosts(
        &[
            "192.0.2.10",
            "198.51.100.0/24",
            "2001:db8::10",
            "2001:db8:abcd::/48",
        ],
        &[],
    );
    let rules = NetworkIptablesManager::build_policy_rule_args("MXC-mixed", &policy);

    assert_eq!(
        rules.ipv4.len(),
        2,
        "mixed host list should produce two IPv4 rules; actual: {rules:?}"
    );
    assert_eq!(
        rules.ipv6.len(),
        2,
        "mixed host list should produce two IPv6 rules; actual: {rules:?}"
    );
}

#[test]
fn generated_destination_rules_append_to_chain_match_destination_and_jump_target() {
    let chain_name = "MXC-shape";
    let destination = "203.0.113.0/24";
    let rule =
        NetworkIptablesManager::build_single_rule_args(chain_name, destination, &RuleAction::Deny);

    assert_eq!(
        rule.first().map(String::as_str),
        Some("-A"),
        "rule for {destination} should append with -A; actual: {rule:?}"
    );
    assert_rule_contains(&rule, chain_name, destination);
    assert_rule_contains(&rule, "-d", destination);
    assert_rule_contains(&rule, destination, destination);
    assert_rule_contains(&rule, "-j", destination);
    assert_rule_contains(&rule, "DROP", destination);

    let rendered = joined(&rule);
    assert!(
        rendered.contains("-A MXC-shape"),
        "rule for {destination} should append to the requested chain; actual: {rendered}"
    );
    assert!(
        rendered.contains("-d 203.0.113.0/24"),
        "CIDR destination should be passed through unchanged in rule; actual: {rendered}"
    );
    assert!(
        rendered.contains("-j DROP"),
        "deny rule for {destination} should jump to DROP; actual: {rendered}"
    );
}

#[test]
fn resolved_destinations_are_split_into_ipv4_and_ipv6_rule_args() {
    let destinations = ResolvedDestinations {
        ipv4: strings(&["192.0.2.10", "198.51.100.0/24"]),
        ipv6: strings(&["2001:db8::10", "2001:db8:abcd::/48"]),
    };
    let rules = NetworkIptablesManager::build_resolved_destination_rule_args(
        "MXC-resolved",
        &destinations,
        &RuleAction::Allow,
    );

    assert_eq!(
        rules.ipv4.len(),
        2,
        "resolved destinations should keep both IPv4 rules in IPv4 bucket; actual: {rules:?}"
    );
    assert_eq!(
        rules.ipv6.len(),
        2,
        "resolved destinations should keep both IPv6 rules in IPv6 bucket; actual: {rules:?}"
    );
    for destination in &destinations.ipv4 {
        assert!(
            rules.ipv4.iter().any(|rule| rule.contains(destination)),
            "IPv4 destination {destination} should appear in IPv4 rules; actual: {rules:?}"
        );
        assert!(
            !rules.ipv6.iter().any(|rule| rule.contains(destination)),
            "IPv4 destination {destination} should not appear in IPv6 rules; actual: {rules:?}"
        );
    }
    for destination in &destinations.ipv6 {
        assert!(
            rules.ipv6.iter().any(|rule| rule.contains(destination)),
            "IPv6 destination {destination} should appear in IPv6 rules; actual: {rules:?}"
        );
        assert!(
            !rules.ipv4.iter().any(|rule| rule.contains(destination)),
            "IPv6 destination {destination} must not appear in IPv4 rules; actual: {rules:?}"
        );
    }
}

#[test]
fn allow_list_rules_are_emitted_before_block_list_rules_for_same_ipv4_destination() {
    let destination = "203.0.113.44";
    let policy = policy_with_hosts(&[destination], &[destination]);
    let rules = NetworkIptablesManager::build_policy_rule_args("MXC-order-v4", &policy);
    let rendered: Vec<String> = rules.ipv4.iter().map(|rule| joined(rule)).collect();

    let accept_index = rendered
        .iter()
        .position(|rule| rule.contains(destination) && rule.contains("-j ACCEPT"))
        .expect("IPv4 ACCEPT rule for duplicate destination should exist");
    let drop_index = rendered
        .iter()
        .position(|rule| rule.contains(destination) && rule.contains("-j DROP"))
        .expect("IPv4 DROP rule for duplicate destination should exist");

    // SPEC_BRIEF §3 pins this interim AB#62830341 behavior until deny-precedence lands.
    assert!(
        accept_index < drop_index,
        "IPv4 duplicate {destination} should ACCEPT before DROP; actual order: {rendered:?}"
    );
}

#[test]
fn allow_list_rules_are_emitted_before_block_list_rules_for_same_ipv6_destination() {
    let destination = "2001:db8::44";
    let policy = policy_with_hosts(&[destination], &[destination]);
    let rules = NetworkIptablesManager::build_policy_rule_args("MXC-order-v6", &policy);
    let rendered: Vec<String> = rules.ipv6.iter().map(|rule| joined(rule)).collect();

    let accept_index = rendered
        .iter()
        .position(|rule| rule.contains(destination) && rule.contains("-j ACCEPT"))
        .expect("IPv6 ACCEPT rule for duplicate destination should exist");
    let drop_index = rendered
        .iter()
        .position(|rule| rule.contains(destination) && rule.contains("-j DROP"))
        .expect("IPv6 DROP rule for duplicate destination should exist");

    // SPEC_BRIEF §3 says allow-before-block ordering applies to both iptables buckets.
    assert!(
        accept_index < drop_index,
        "IPv6 duplicate {destination} should ACCEPT before DROP; actual order: {rendered:?}"
    );
}

#[test]
fn base_chain_rules_are_four_family_agnostic_rules_in_documented_order() {
    let chain_name = "MXC-base";
    let rules = NetworkIptablesManager::build_base_chain_rule_args(chain_name);
    let expected = vec![
        strings(&["-A", chain_name, "-i", "lo", "-j", "ACCEPT"]),
        strings(&[
            "-A",
            chain_name,
            "-m",
            "state",
            "--state",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ]),
        strings(&[
            "-A", chain_name, "-p", "udp", "--dport", "53", "-j", "ACCEPT",
        ]),
        strings(&[
            "-A", chain_name, "-p", "tcp", "--dport", "53", "-j", "ACCEPT",
        ]),
    ];

    assert_eq!(
        rules, expected,
        "base chain rules should be the documented four rules in order"
    );
    for (index, rule) in rules.iter().enumerate() {
        assert_rule_omits(rule, "-d", &format!("base rule {index}"));
        assert!(
            !rule.iter().any(|arg| arg == "icmp" || arg == "icmpv6"),
            "base rule {index} must be family-agnostic; -p icmp is invalid for ip6tables and would make the v6 chain fail: {rule:?}"
        );
    }
}

#[test]
fn default_network_policy_maps_to_exact_terminal_rule_vector() {
    let chain_name = "MXC-default";

    assert_eq!(
        NetworkIptablesManager::build_default_policy_rule_arg(chain_name, NetworkPolicy::Block),
        strings(&["-A", chain_name, "-j", "DROP"]),
        "NetworkPolicy::Block should produce the exact DROP terminal rule"
    );
    assert_eq!(
        NetworkIptablesManager::build_default_policy_rule_arg(chain_name, NetworkPolicy::Allow),
        strings(&["-A", chain_name, "-j", "ACCEPT"]),
        "NetworkPolicy::Allow should produce the exact ACCEPT terminal rule"
    );
}

#[test]
fn chain_names_have_mxc_prefix_and_total_length_cap_of_twenty_four() {
    let short_name = "short";
    let short_manager = NetworkIptablesManager::new(short_name);
    assert_eq!(
        short_manager.chain_name, "MXC-short",
        "short container name {short_name} should be preserved after MXC- prefix"
    );

    let long_name = "abcdefghijklmnopqrstuvwxyz";
    let long_manager = NetworkIptablesManager::new(long_name);
    let expected = "MXC-abcdefghijklmnopqrst";
    assert_eq!(
        long_manager.chain_name, expected,
        "long container name should be truncated to 20 chars after MXC- prefix"
    );
    assert_eq!(
        long_manager.chain_name.len(),
        24,
        "chain name length cap should apply to total length including MXC- prefix"
    );
    assert!(
        long_manager.chain_name.starts_with("MXC-"),
        "long chain name should keep MXC- prefix; actual: {}",
        long_manager.chain_name
    );
}

#[test]
fn empty_policy_produces_no_destination_rules_in_either_bucket() {
    let policy = policy_with_hosts(&[], &[]);
    let rules = NetworkIptablesManager::build_policy_rule_args("MXC-empty", &policy);

    assert!(
        rules.ipv4.is_empty(),
        "empty policy should produce no IPv4 destination rules; actual: {rules:?}"
    );
    assert!(
        rules.ipv6.is_empty(),
        "empty policy should produce no IPv6 destination rules; actual: {rules:?}"
    );
}

#[test]
fn unresolvable_invalid_hostname_contributes_no_destination_rules() {
    let host = "definitely-unresolvable-mxc-rulegen-spec.invalid";
    let rules =
        NetworkIptablesManager::build_host_rule_args("MXC-invalid", host, &RuleAction::Allow);

    assert!(
        rules.ipv4.is_empty(),
        "unresolvable host {host} should produce no IPv4 rules; actual: {rules:?}"
    );
    assert!(
        rules.ipv6.is_empty(),
        "unresolvable host {host} should produce no IPv6 rules; actual: {rules:?}"
    );
}
