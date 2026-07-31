//! Spec-derived tests for manager lifecycle state and the enforcement-mode
//! gate. Written from the public API contract only.

use super::*;
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{ContainerPolicy, NetworkEnforcementMode};

#[test]
fn a_new_manager_reports_no_rules_applied() {
    let manager = NetworkIptablesManager::new("fresh");

    assert!(
        !manager.rules_applied(),
        "a newly constructed manager must not report firewall state needing cleanup"
    );
}

#[test]
fn a_non_firewall_policy_is_a_successful_no_op() {
    let mut manager = NetworkIptablesManager::new("skip-noop");
    manager.set_veth_interface("veth-skip");
    let policy = policy_with_enforcement_mode(NetworkEnforcementMode::Capabilities);
    let mut logger = Logger::new(Mode::Buffer);

    let result = manager.apply_firewall_rules(&policy, &mut logger);

    assert_eq!(
        result,
        Ok(true),
        "a policy that does not use firewall enforcement must be reported as a successful no-op"
    );
    assert!(
        !manager.rules_applied(),
        "a no-op firewall skip must leave no rules marked as applied"
    );
}

#[test]
fn every_enforcement_mode_takes_the_contractual_firewall_gate() {
    const SKIP_MESSAGE: &str = "Network enforcement mode does not use firewall, skipping iptables.";

    for (mode, uses_firewall) in enforcement_modes_with_firewall_contract() {
        let mut manager = NetworkIptablesManager::new(&format!("gate-{mode:?}"));
        manager.set_veth_interface("veth-gate");
        let policy = policy_with_enforcement_mode(mode.clone());
        let mut logger = Logger::new(Mode::Buffer);

        let _ = manager.apply_firewall_rules(&policy, &mut logger);
        let log = logger.get_buffer();

        assert_eq!(
            log.contains(SKIP_MESSAGE),
            !uses_firewall,
            "{mode:?} gate mismatch; log was {log:?}"
        );
    }
}

fn policy_with_enforcement_mode(
    network_enforcement_mode: NetworkEnforcementMode,
) -> ContainerPolicy {
    ContainerPolicy {
        network_enforcement_mode,
        ..Default::default()
    }
}

fn enforcement_modes_with_firewall_contract() -> [(NetworkEnforcementMode, bool); 3] {
    use NetworkEnforcementMode::{Both, Capabilities, Firewall};

    [
        (Capabilities, enforcement_mode_uses_firewall(Capabilities)),
        (Firewall, enforcement_mode_uses_firewall(Firewall)),
        (Both, enforcement_mode_uses_firewall(Both)),
    ]
}

fn enforcement_mode_uses_firewall(mode: NetworkEnforcementMode) -> bool {
    use NetworkEnforcementMode::{Both, Capabilities, Firewall};

    match mode {
        Capabilities => false,
        Firewall | Both => true,
    }
}
