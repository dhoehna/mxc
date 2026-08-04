// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Network policy enforcement via iptables rules scoped to the LXC container.
//!
//! Maps the platform-agnostic `ContainerPolicy` network settings to iptables
//! and ip6tables rules applied to the container's virtual ethernet (veth)
//! interface.

use std::net::{IpAddr, ToSocketAddrs};
use std::process::Command;

use wxc_common::logger::Logger;
use wxc_common::models::{ContainerPolicy, NetworkEnforcementMode, NetworkPolicy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    V4,
    V6,
}

/// Whether a host-list entry produces an ACCEPT or a DROP rule. Local to this
/// backend: it distinguishes `allowedHosts` from `blockedHosts` and is not a
/// policy-schema type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleAction {
    Allow,
    Deny,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ResolvedDestinations {
    ipv4: Vec<String>,
    ipv6: Vec<String>,
}

impl ResolvedDestinations {
    fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct FirewallRuleArgs {
    ipv4: Vec<Vec<String>>,
    ipv6: Vec<Vec<String>>,
}

impl FirewallRuleArgs {
    fn extend(&mut self, other: FirewallRuleArgs) {
        self.ipv4.extend(other.ipv4);
        self.ipv6.extend(other.ipv6);
    }
}

/// Records exactly which per-family chains and FORWARD hooks a single apply
/// attempt created, so rollback and teardown remove only what this manager
/// installed. Without this, a partial-failure rollback would tear down chains
/// this attempt never created, and because chain names truncate at 20 chars a
/// torn-down chain can belong to a different container.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct CreatedResources {
    v4_chain: bool,
    v6_chain: bool,
    v4_hook: bool,
    v6_hook: bool,
}

/// Three-way classification of whether `ip6tables` can be used on this host.
///
/// The old boolean probe collapsed two very different situations into "skip
/// IPv6": a kernel with IPv6 disabled (nothing to filter, safe to skip) and an
/// IPv6-capable host whose `ip6tables` userspace tool is missing or broken
/// (IPv6 egress is live but unfiltered, which is a silent fail-open on a
/// security control). They must be handled differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ip6tablesStatus {
    /// `ip6tables` works; program the parallel IPv6 chain.
    Available,
    /// The kernel has no active IPv6, so there is no IPv6 traffic to filter.
    /// Skipping the IPv6 chain is safe.
    KernelIpv6Disabled,
    /// The host has active IPv6 but `ip6tables` is missing or broken. Applying
    /// only the IPv4 policy would leave IPv6 egress unfiltered, so setup must
    /// fail closed instead.
    UnusableButIpv6Active,
}

/// Manages iptables rules for an LXC container's network policy.
pub struct NetworkIptablesManager {
    /// Chain name unique to this container (e.g., "MXC-<container-name>").
    chain_name: String,
    /// Whether rules have been applied.
    rules_applied: bool,
    /// The container's veth interface name on the host.
    veth_interface: Option<String>,
    /// Chains and FORWARD hooks this manager successfully created, so teardown
    /// and rollback remove only resources this attempt actually installed.
    created: CreatedResources,
}

impl NetworkIptablesManager {
    /// Create a new manager for the given container name.
    pub fn new(container_name: &str) -> Self {
        // Sanitize container name for use in iptables chain name
        let sanitized: String = container_name
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
            .take(20)
            .collect();

        Self {
            chain_name: format!("MXC-{}", sanitized),
            rules_applied: false,
            veth_interface: None,
            created: CreatedResources::default(),
        }
    }

    /// Whether rules have been applied and need cleanup.
    pub fn rules_applied(&self) -> bool {
        self.rules_applied
    }

    /// Discover the host-side veth interface name for a running container.
    /// Parses the `Link:` line from `lxc-info -n <name>` output.
    /// Returns the veth interface name (e.g., "vethXXXXXX") if found.
    pub fn discover_veth_interface(container_name: &str) -> Option<String> {
        // Use lxc-info without -i to get the full output including the Link: line.
        // Output format includes: "Link:           vethXXXXXX"
        let output = Command::new("lxc-info")
            .arg("-n")
            .arg(container_name)
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse the "Link:" line from lxc-info output
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(link_name) = trimmed.strip_prefix("Link:") {
                let veth = link_name.trim();
                if veth.starts_with("veth") {
                    return Some(veth.to_string());
                }
            }
        }

        None
    }

    /// Set the veth interface name for the container.
    pub fn set_veth_interface(&mut self, iface: &str) {
        self.veth_interface = Some(iface.to_string());
    }

    /// Resolve a destination string to IPv4 and IPv6 firewall destinations.
    ///
    /// Bare IPv4/IPv6 literals are retained in their matching family. CIDR
    /// strings are accepted after validating that the address parses and the
    /// prefix length is within range for its family; the host bits are not
    /// required to be zero, since `iptables`/`ip6tables` apply the prefix mask
    /// themselves. Validated CIDRs are passed through unchanged. Hostnames are
    /// resolved to both A and AAAA records so IPv4 destinations route to
    /// `iptables` and IPv6 destinations route to `ip6tables`.
    fn resolve_host(host: &str) -> ResolvedDestinations {
        // An empty entry is not a hostname. Without this guard the DNS branch
        // below formats ":0", which Winsock resolves to every local interface
        // address, so an empty policy entry would emit rules for the host's
        // own addresses. glibc rejects ":0", so this only shows up on Windows.
        if host.trim().is_empty() {
            return ResolvedDestinations::default();
        }

        if host.contains('/') {
            return match Self::destination_family(host) {
                Some(IpFamily::V4) => ResolvedDestinations {
                    ipv4: vec![host.to_string()],
                    ipv6: Vec::new(),
                },
                Some(IpFamily::V6) => ResolvedDestinations {
                    ipv4: Vec::new(),
                    ipv6: vec![host.to_string()],
                },
                None => ResolvedDestinations::default(),
            };
        }

        // Try as IP address first.
        if let Ok(addr) = host.parse::<IpAddr>() {
            return match addr {
                IpAddr::V4(_) => ResolvedDestinations {
                    ipv4: vec![host.to_string()],
                    ipv6: Vec::new(),
                },
                IpAddr::V6(_) => ResolvedDestinations {
                    ipv4: Vec::new(),
                    ipv6: vec![host.to_string()],
                },
            };
        }

        // Try DNS resolution.
        let mut resolved = ResolvedDestinations::default();
        if let Ok(addrs) = format!("{}:0", host).to_socket_addrs() {
            for addr in addrs {
                match addr.ip() {
                    IpAddr::V4(ip) => resolved.ipv4.push(ip.to_string()),
                    IpAddr::V6(ip) => resolved.ipv6.push(ip.to_string()),
                }
            }
        }
        resolved
    }

    fn destination_family(destination: &str) -> Option<IpFamily> {
        if let Some((network, prefix)) = destination.split_once('/') {
            // The prefix must be digits only. `u8::from_str` would otherwise
            // accept a leading `+`, so `10.0.0.0/+24` would be forwarded to
            // iptables, which silently canonicalizes it to `10.0.0.0/24`. A
            // typo in a policy file would then be applied instead of being
            // reported by the unresolved-host warning. Also subsumes the
            // embedded-slash case, e.g. `10.0.0.0/20/8`.
            if network.is_empty()
                || prefix.is_empty()
                || !prefix.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }

            let addr = network.parse::<IpAddr>().ok()?;
            let prefix = prefix.parse::<u8>().ok()?;
            return match addr {
                IpAddr::V4(_) if prefix <= 32 => Some(IpFamily::V4),
                IpAddr::V6(_) if prefix <= 128 => Some(IpFamily::V6),
                _ => None,
            };
        }

        match destination.parse::<IpAddr>().ok()? {
            IpAddr::V4(_) => Some(IpFamily::V4),
            IpAddr::V6(_) => Some(IpFamily::V6),
        }
    }

    fn rule_action_arg(action: &RuleAction) -> &'static str {
        match action {
            RuleAction::Allow => "ACCEPT",
            RuleAction::Deny => "DROP",
        }
    }

    fn build_base_chain_rule_args(chain_name: &str) -> Vec<Vec<String>> {
        vec![
            vec!["-A", chain_name, "-i", "lo", "-j", "ACCEPT"],
            vec![
                "-A",
                chain_name,
                "-m",
                "state",
                "--state",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
            vec![
                "-A", chain_name, "-p", "udp", "--dport", "53", "-j", "ACCEPT",
            ],
            vec![
                "-A", chain_name, "-p", "tcp", "--dport", "53", "-j", "ACCEPT",
            ],
        ]
        .into_iter()
        .map(|args| args.into_iter().map(String::from).collect())
        .collect()
    }

    fn build_default_policy_rule_arg(chain_name: &str, policy: NetworkPolicy) -> Vec<String> {
        let default_action = match policy {
            NetworkPolicy::Block => "DROP",
            NetworkPolicy::Allow => "ACCEPT",
        };
        vec!["-A", chain_name, "-j", default_action]
            .into_iter()
            .map(String::from)
            .collect()
    }

    fn build_resolved_destination_rule_args(
        chain_name: &str,
        destinations: &ResolvedDestinations,
        action: &RuleAction,
    ) -> FirewallRuleArgs {
        let mut args = FirewallRuleArgs::default();
        for destination in &destinations.ipv4 {
            args.ipv4.push(Self::build_single_rule_args(
                chain_name,
                destination,
                action,
            ));
        }
        for destination in &destinations.ipv6 {
            args.ipv6.push(Self::build_single_rule_args(
                chain_name,
                destination,
                action,
            ));
        }
        args
    }

    fn build_single_rule_args(
        chain_name: &str,
        destination: &str,
        action: &RuleAction,
    ) -> Vec<String> {
        vec![
            "-A".to_string(),
            chain_name.to_string(),
            "-d".to_string(),
            destination.to_string(),
            "-j".to_string(),
            Self::rule_action_arg(action).to_string(),
        ]
    }

    /// Build the allow/deny rule args for a single host by resolving it once.
    /// Test-only: production goes through [`Self::build_policy_rules_logged`],
    /// which resolves every entry exactly once and reuses that result for both
    /// the unresolved-host warning and rule construction.
    #[cfg(test)]
    fn build_host_rule_args(chain_name: &str, host: &str, action: &RuleAction) -> FirewallRuleArgs {
        let destinations = Self::resolve_host(host);
        Self::build_resolved_destination_rule_args(chain_name, &destinations, action)
    }

    /// Build the allow/deny rule args for a container policy.
    ///
    /// Test-only: production uses [`Self::build_policy_rules_logged`] so each
    /// destination is resolved exactly once. This resolves each entry a second
    /// time relative to the warning pass and so must not be on the apply path.
    ///
    /// NOTE — interim ordering (tracked by AB#62830341): rules are emitted in
    /// allow-list then block-list order, and iptables/ip6tables apply
    /// first-match-wins within the chain. This model-1 change therefore does
    /// **not** yet implement deny-precedence: a destination present in both
    /// the allow and block lists is ACCEPTed. Reconciling this to the GA
    /// "deny-wins" ordering is owned by net-model-2 (AB#62830341); until then
    /// callers must not assume deny-precedence.
    #[cfg(test)]
    fn build_policy_rule_args(chain_name: &str, policy: &ContainerPolicy) -> FirewallRuleArgs {
        let mut args = FirewallRuleArgs::default();
        for host in &policy.allowed_hosts {
            args.extend(Self::build_host_rule_args(
                chain_name,
                host,
                &RuleAction::Allow,
            ));
        }
        for host in &policy.blocked_hosts {
            args.extend(Self::build_host_rule_args(
                chain_name,
                host,
                &RuleAction::Deny,
            ));
        }
        args
    }

    /// Resolve every allow/block entry exactly once and build the rule args
    /// from that single resolution, logging a warning for any entry that
    /// resolved to nothing.
    ///
    /// Resolving once is a correctness requirement, not just an optimization:
    /// the previous apply path resolved each host once for the warning pass
    /// and again inside rule construction, and two lookups of the same name
    /// can disagree — DNS round-robin returns a different address, or a TTL
    /// expires between the calls — so the rule installed would not match the
    /// rule that was validated and logged. The allow-before-block order and
    /// the interim AB#62830341 ordering semantics are unchanged.
    fn build_policy_rules_logged(
        chain_name: &str,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> FirewallRuleArgs {
        let mut args = FirewallRuleArgs::default();
        let entries = policy
            .allowed_hosts
            .iter()
            .map(|host| (host, RuleAction::Allow))
            .chain(
                policy
                    .blocked_hosts
                    .iter()
                    .map(|host| (host, RuleAction::Deny)),
            );
        for (host, action) in entries {
            let destinations = Self::resolve_host(host);
            if destinations.is_empty() {
                logger.log_line(&format!("Warning: could not resolve host '{}'", host));
            }
            args.extend(Self::build_resolved_destination_rule_args(
                chain_name,
                &destinations,
                &action,
            ));
        }
        args
    }

    /// Run an iptables command and return success/failure.
    fn run_iptables(args: &[&str], logger: &mut Logger) -> Result<bool, String> {
        Self::run_firewall_command("iptables", args, logger)
    }

    /// Run an ip6tables command and return success/failure.
    fn run_ip6tables(args: &[&str], logger: &mut Logger) -> Result<bool, String> {
        Self::run_firewall_command("ip6tables", args, logger)
    }

    /// Classify whether `ip6tables` is usable, given whether the read-only
    /// probe succeeded and whether the host currently has active IPv6. Pure so
    /// the fail-open-vs-fail-closed decision can be unit-tested without a
    /// privileged Linux host.
    ///
    /// A working probe means the tool is usable regardless of address state.
    /// A failed probe splits on whether IPv6 is live: if the kernel has no
    /// active IPv6 there is nothing to filter and skipping is safe, but if
    /// IPv6 is live the tool is genuinely missing or broken and setup must
    /// fail closed rather than leave IPv6 egress unfiltered.
    fn classify_ip6tables_status(probe_succeeded: bool, host_ipv6_active: bool) -> Ip6tablesStatus {
        match (probe_succeeded, host_ipv6_active) {
            (true, _) => Ip6tablesStatus::Available,
            (false, true) => Ip6tablesStatus::UnusableButIpv6Active,
            (false, false) => Ip6tablesStatus::KernelIpv6Disabled,
        }
    }

    /// Whether the host has an active IPv6 stack, independent of `ip6tables`.
    ///
    /// `/proc/net/if_inet6` is populated by the kernel only when the IPv6
    /// module is loaded, and lists every interface IPv6 address (including the
    /// link-local `fe80::` address present on any interface with IPv6 up). A
    /// host booted with `ipv6.disable=1` never creates the file, and a host
    /// with IPv6 fully disabled via sysctl has no addresses to list; either
    /// way there is no IPv6 egress to filter. A non-empty file means IPv6 is
    /// live, so a broken `ip6tables` is a real gap rather than a no-op.
    fn host_has_active_ipv6() -> bool {
        match std::fs::read_to_string("/proc/net/if_inet6") {
            Ok(contents) => contents.lines().any(|line| !line.trim().is_empty()),
            Err(_) => false,
        }
    }

    /// Probe whether `ip6tables` can be used on this host and classify the
    /// result. Runs a harmless, read-only `ip6tables -S` (list the filter
    /// table), then distinguishes a kernel with IPv6 disabled (safe to skip
    /// the parallel v6 chain) from an IPv6-capable host whose `ip6tables` is
    /// missing or broken (must fail setup, since applying only the v4 policy
    /// would silently leave IPv6 egress unfiltered).
    fn ip6tables_status(logger: &mut Logger) -> Ip6tablesStatus {
        let probe_succeeded = match Command::new("ip6tables").arg("-S").output() {
            Ok(output) if output.status.success() => true,
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                logger.log_line(&format!("ip6tables probe failed ({})", stderr.trim()));
                false
            }
            Err(e) => {
                logger.log_line(&format!("ip6tables not found ({})", e));
                false
            }
        };

        let status = Self::classify_ip6tables_status(probe_succeeded, Self::host_has_active_ipv6());
        match status {
            Ip6tablesStatus::Available => {}
            Ip6tablesStatus::KernelIpv6Disabled => {
                logger.log_line(
                    "Kernel IPv6 is not active; skipping IPv6 firewall rules \
                     (no IPv6 egress to filter).",
                );
            }
            Ip6tablesStatus::UnusableButIpv6Active => {
                logger.log_line(
                    "ip6tables is unusable but the host has active IPv6; \
                     failing firewall setup to avoid leaving IPv6 egress unfiltered.",
                );
            }
        }
        status
    }

    fn run_firewall_command(
        command: &str,
        args: &[&str],
        logger: &mut Logger,
    ) -> Result<bool, String> {
        let output = Command::new(command)
            .args(args)
            .output()
            .map_err(|e| format!("Failed to run {}: {}", command, e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let msg = format!("{} {} failed: {}", command, args.join(" "), stderr);
            logger.log_line(&msg);
            return Err(msg);
        }

        Ok(true)
    }

    fn run_iptables_rule_args(args: &[Vec<String>], logger: &mut Logger) -> Result<(), String> {
        for rule in args {
            let rule_args: Vec<&str> = rule.iter().map(String::as_str).collect();
            Self::run_iptables(&rule_args, logger)?;
        }
        Ok(())
    }

    fn run_ip6tables_rule_args(args: &[Vec<String>], logger: &mut Logger) -> Result<(), String> {
        for rule in args {
            let rule_args: Vec<&str> = rule.iter().map(String::as_str).collect();
            Self::run_ip6tables(&rule_args, logger)?;
        }
        Ok(())
    }

    /// Whether the given enforcement mode is served by the iptables firewall
    /// backend. Pure and side-effect-free so the gate can be exercised without
    /// invoking the host firewall.
    fn enforcement_mode_uses_firewall(mode: &NetworkEnforcementMode) -> bool {
        matches!(
            mode,
            NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
        )
    }

    /// Apply network firewall rules based on the container policy.
    ///
    /// On any failure after resources are created, the inner call rolls back
    /// exactly the per-family chains and FORWARD hooks this attempt installed
    /// before the error is returned, so a retry does not trip over a leftover
    /// `MXC-<name>` chain ("chain already exists") and a partial failure never
    /// tears down a chain this attempt did not create.
    pub fn apply_firewall_rules(
        &mut self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<bool, String> {
        // Skip if network enforcement doesn't use firewall.
        if !Self::enforcement_mode_uses_firewall(&policy.network_enforcement_mode) {
            logger.log_line("Network enforcement mode does not use firewall, skipping iptables.");
            return Ok(true);
        }

        match self.apply_firewall_rules_inner(policy, logger) {
            Ok(created) => {
                self.created = created;
                self.rules_applied = true;
                Ok(true)
            }
            Err(e) => {
                // The inner call has already rolled back exactly what it
                // created, so nothing is torn down that this attempt did not
                // install. Report and propagate.
                logger.log_line(&format!(
                    "Firewall setup failed: {}. Partial iptables state rolled back.",
                    e
                ));
                Err(e)
            }
        }
    }

    /// Fallible body of [`Self::apply_firewall_rules`]. Tracks the chains and
    /// hooks it creates, rolls back exactly those on the error path, and
    /// returns the created set on success so the manager can tear down only
    /// what it installed.
    fn apply_firewall_rules_inner(
        &self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<CreatedResources, String> {
        let mut created = CreatedResources::default();
        match self.install_firewall_rules(policy, logger, &mut created) {
            Ok(()) => Ok(created),
            Err(e) => {
                Self::teardown_created(
                    &self.chain_name,
                    self.veth_interface.as_deref(),
                    &created,
                    logger,
                );
                Err(e)
            }
        }
    }

    /// Install the per-family chains, rules, and FORWARD hooks, recording each
    /// resource in `created` immediately after it is successfully installed so
    /// the caller can roll back precisely on any later failure.
    fn install_firewall_rules(
        &self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
        created: &mut CreatedResources,
    ) -> Result<(), String> {
        logger.log_line(&format!(
            "Creating iptables/ip6tables chain: {}",
            self.chain_name
        ));

        // Probe ip6tables once. Skip the v6 chain when the kernel has no
        // active IPv6 (nothing to filter), but fail closed when IPv6 is live
        // and ip6tables is missing or broken rather than silently leaving
        // IPv6 egress unfiltered.
        let ipv6_enabled = match Self::ip6tables_status(logger) {
            Ip6tablesStatus::Available => true,
            Ip6tablesStatus::KernelIpv6Disabled => false,
            Ip6tablesStatus::UnusableButIpv6Active => {
                return Err(
                    "ip6tables is unusable but the host has active IPv6; refusing to \
                     apply an IPv4-only policy that would leave IPv6 egress unfiltered"
                        .to_string(),
                );
            }
        };

        // Create custom chains, recording each family as created so rollback
        // removes only the chains this attempt installed.
        Self::run_iptables(&["-N", &self.chain_name], logger)?;
        created.v4_chain = true;
        if ipv6_enabled {
            Self::run_ip6tables(&["-N", &self.chain_name], logger)?;
            created.v6_chain = true;
        }

        let base_rules = Self::build_base_chain_rule_args(&self.chain_name);
        Self::run_iptables_rule_args(&base_rules, logger)?;
        if ipv6_enabled {
            Self::run_ip6tables_rule_args(&base_rules, logger)?;
        }

        // Resolve every allow/block entry exactly once and reuse that single
        // resolution for both the unresolved-host warning and rule
        // construction, so the rule installed matches the entry that was
        // validated and logged.
        let policy_rules = Self::build_policy_rules_logged(&self.chain_name, policy, logger);
        Self::run_iptables_rule_args(&policy_rules.ipv4, logger)?;
        if ipv6_enabled {
            Self::run_ip6tables_rule_args(&policy_rules.ipv6, logger)?;
        } else if !policy_rules.ipv6.is_empty() {
            logger.log_line(&format!(
                "Warning: {} IPv6 firewall rule(s) not applied because ip6tables \
                 is unavailable; IPv6 egress is unfiltered on this host.",
                policy_rules.ipv6.len()
            ));
        }

        // Append default policy at end of each chain.
        let default_rule = Self::build_default_policy_rule_arg(
            &self.chain_name,
            policy.default_network_policy.clone(),
        );
        let default_args: Vec<&str> = default_rule.iter().map(String::as_str).collect();
        let default_action = default_args.last().copied().unwrap_or("ACCEPT");
        logger.log_line(&format!("Default network policy: {}", default_action));
        Self::run_iptables(&default_args, logger)?;
        if ipv6_enabled {
            Self::run_ip6tables(&default_args, logger)?;
        }

        // Hook the chains into FORWARD for the container's egress traffic.
        // Packets originating in the container arrive at the host on the
        // host-side veth, so they match FORWARD by input interface (`-i`);
        // `-o` would instead match traffic flowing toward the container.
        if let Some(ref iface) = self.veth_interface {
            Self::run_iptables(
                &["-I", "FORWARD", "-i", iface, "-j", &self.chain_name],
                logger,
            )?;
            created.v4_hook = true;
            logger.log_line(&format!(
                "FORWARD hook installed on {} for chain {} (iptables).",
                iface, self.chain_name
            ));
            if ipv6_enabled {
                Self::run_ip6tables(
                    &["-I", "FORWARD", "-i", iface, "-j", &self.chain_name],
                    logger,
                )?;
                created.v6_hook = true;
                logger.log_line(&format!(
                    "FORWARD hook installed on {} for chain {} (ip6tables).",
                    iface, self.chain_name
                ));
            }
        } else {
            // Without a veth interface, we cannot safely scope rules to the container.
            // Refuse to apply host-wide rules to avoid affecting all host traffic.
            logger.log_line(
                "Warning: No veth interface set for container. \
                 Cannot scope iptables rules. Skipping FORWARD hook.",
            );
        }

        Ok(())
    }

    /// Best-effort removal of the FORWARD hooks and per-container chains that
    /// `created` records were installed, in both tables. Only resources marked
    /// as created are touched, so a partial-failure rollback never tears down
    /// a chain this attempt did not create — which matters because chain names
    /// truncate at 20 characters and can collide across containers. A missing
    /// rule/chain still makes an individual `-D`/`-F`/`-X` call a no-op, so it
    /// doubles as the rollback path for a failed apply.
    fn teardown_created(
        chain_name: &str,
        veth_interface: Option<&str>,
        created: &CreatedResources,
        logger: &mut Logger,
    ) {
        // Remove from FORWARD only for families this attempt hooked. Must
        // match the `-i` direction used at insertion so the delete finds the
        // rule; a `-o` delete would leak the FORWARD hook.
        if let Some(iface) = veth_interface {
            if created.v4_hook {
                let _ =
                    Self::run_iptables(&["-D", "FORWARD", "-i", iface, "-j", chain_name], logger);
            }
            if created.v6_hook {
                let _ =
                    Self::run_ip6tables(&["-D", "FORWARD", "-i", iface, "-j", chain_name], logger);
            }
        }

        // Flush and delete only the chains this attempt created.
        if created.v4_chain {
            let _ = Self::run_iptables(&["-F", chain_name], logger);
            let _ = Self::run_iptables(&["-X", chain_name], logger);
        }
        if created.v6_chain {
            let _ = Self::run_ip6tables(&["-F", chain_name], logger);
            let _ = Self::run_ip6tables(&["-X", chain_name], logger);
        }
    }

    /// Remove all iptables/ip6tables rules created by this manager.
    pub fn remove_firewall_rules(&mut self, logger: &mut Logger) -> Result<(), String> {
        if !self.rules_applied {
            return Ok(());
        }

        logger.log_line(&format!(
            "Removing iptables/ip6tables chain: {}",
            self.chain_name
        ));

        Self::teardown_created(
            &self.chain_name,
            self.veth_interface.as_deref(),
            &self.created,
            logger,
        );

        self.rules_applied = false;
        self.created = CreatedResources::default();
        Ok(())
    }

    /// Best-effort cleanup of any iptables state the runner may have
    /// installed for a container, used when the original
    /// `NetworkIptablesManager` instance isn't reachable (e.g. signal-time
    /// cleanup from the watchdog thread). Builds a fresh manager pointed at
    /// the same chain name. Because the created-resource set from the original
    /// attempt is not reachable here, it assumes every family chain and hook
    /// may exist and removes them all best-effort; iptables itself is the
    /// source of truth, so a `-D`/`-F`/`-X` for a nonexistent resource no-ops.
    pub fn force_cleanup(container_name: &str, veth_interface: Option<&str>, logger: &mut Logger) {
        let mut mgr = Self::new(container_name);
        if let Some(v) = veth_interface {
            mgr.set_veth_interface(v);
        }
        // Bypass the rules_applied gate and assume all resources may exist; if
        // there's nothing to remove the iptables `-D`/`-F`/`-X` calls just
        // no-op.
        mgr.rules_applied = true;
        mgr.created = CreatedResources {
            v4_chain: true,
            v6_chain: true,
            v4_hook: veth_interface.is_some(),
            v6_hook: veth_interface.is_some(),
        };
        let _ = mgr.remove_firewall_rules(logger);
    }
}

impl Drop for NetworkIptablesManager {
    fn drop(&mut self) {
        if self.rules_applied {
            let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);
            let _ = self.remove_firewall_rules(&mut logger);
        }
    }
}

#[cfg(test)]
#[path = "network_iptables_resolution_spec_tests.rs"]
mod resolution_spec_tests;

#[cfg(test)]
#[path = "network_iptables_rulegen_spec_tests.rs"]
mod rulegen_spec_tests;

#[cfg(test)]
#[path = "network_iptables_lifecycle_spec_tests.rs"]
mod lifecycle_spec_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn chain_name_sanitization() {
        let mgr = NetworkIptablesManager::new("my-container_123");
        assert_eq!(mgr.chain_name, "MXC-my-container_123");
    }

    #[test]
    fn chain_name_truncation() {
        let long_name = "a".repeat(50);
        let mgr = NetworkIptablesManager::new(&long_name);
        // 4 chars for "MXC-" + 20 chars max
        assert!(mgr.chain_name.len() <= 24);
    }

    #[test]
    fn resolve_ip_address() {
        let ips = NetworkIptablesManager::resolve_host("127.0.0.1");
        assert_eq!(ips.ipv4, vec!["127.0.0.1"]);
        assert!(ips.ipv6.is_empty());
    }

    #[test]
    fn resolve_host_retains_ipv6_literal() {
        let ips = NetworkIptablesManager::resolve_host("::1");
        assert!(ips.ipv4.is_empty());
        assert_eq!(ips.ipv6, vec!["::1"]);
    }

    #[test]
    fn resolve_host_retains_ipv4_mapped_ipv6_literal() {
        let ips = NetworkIptablesManager::resolve_host("::ffff:127.0.0.1");
        assert!(ips.ipv4.is_empty());
        assert_eq!(ips.ipv6, vec!["::ffff:127.0.0.1"]);
    }

    #[test]
    fn resolve_host_keeps_ipv4_literal_unchanged() {
        // Round-trip: v4 literals must pass through verbatim.
        let ips = NetworkIptablesManager::resolve_host("10.0.0.1");
        assert_eq!(ips.ipv4, vec!["10.0.0.1"]);
        assert!(ips.ipv6.is_empty());
    }

    #[test]
    fn resolve_host_retains_valid_cidr_by_family() {
        let v4 = NetworkIptablesManager::resolve_host("140.82.112.0/20");
        assert_eq!(v4.ipv4, vec!["140.82.112.0/20"]);
        assert!(v4.ipv6.is_empty());

        let v6 = NetworkIptablesManager::resolve_host("2606:50c0::/32");
        assert!(v6.ipv4.is_empty());
        assert_eq!(v6.ipv6, vec!["2606:50c0::/32"]);
    }

    #[test]
    fn resolve_host_rejects_invalid_cidr_prefix() {
        // Out-of-range prefixes and non-numeric prefixes are dropped rather
        // than passed to iptables, which would reject them at apply time.
        assert!(NetworkIptablesManager::resolve_host("140.82.112.0/33").is_empty());
        assert!(NetworkIptablesManager::resolve_host("2606:50c0::/129").is_empty());
        assert!(NetworkIptablesManager::resolve_host("140.82.112.0/not-a-prefix").is_empty());
    }

    #[test]
    fn resolve_host_rejects_malformed_cidr_syntax() {
        assert!(NetworkIptablesManager::resolve_host("/20").is_empty());
        assert!(NetworkIptablesManager::resolve_host("140.82.112.0/").is_empty());
        assert!(NetworkIptablesManager::resolve_host("140.82.112.0/20/8").is_empty());
    }

    #[test]
    fn host_rule_args_route_ipv4_to_iptables_args() {
        let args = NetworkIptablesManager::build_host_rule_args(
            "MXC-test",
            "140.82.112.4",
            &RuleAction::Allow,
        );

        assert_eq!(
            args.ipv4,
            vec![strings(&[
                "-A",
                "MXC-test",
                "-d",
                "140.82.112.4",
                "-j",
                "ACCEPT",
            ])]
        );
        assert!(args.ipv6.is_empty());
    }

    #[test]
    fn host_rule_args_route_ipv6_to_ip6tables_args() {
        let args = NetworkIptablesManager::build_host_rule_args(
            "MXC-test",
            "2606:50c0:8000::64",
            &RuleAction::Deny,
        );

        assert!(args.ipv4.is_empty());
        assert_eq!(
            args.ipv6,
            vec![strings(&[
                "-A",
                "MXC-test",
                "-d",
                "2606:50c0:8000::64",
                "-j",
                "DROP",
            ])]
        );
    }

    #[test]
    fn host_rule_args_pass_cidr_through_unchanged() {
        // iptables/ip6tables apply the prefix mask themselves, so the CIDR is
        // forwarded verbatim rather than expanded or normalized.
        let v4 = NetworkIptablesManager::build_host_rule_args(
            "MXC-test",
            "140.82.112.0/20",
            &RuleAction::Allow,
        );
        assert_eq!(
            v4.ipv4,
            vec![strings(&[
                "-A",
                "MXC-test",
                "-d",
                "140.82.112.0/20",
                "-j",
                "ACCEPT",
            ])]
        );
        assert!(v4.ipv6.is_empty());

        let v6 = NetworkIptablesManager::build_host_rule_args(
            "MXC-test",
            "2606:50c0::/32",
            &RuleAction::Allow,
        );
        assert!(v6.ipv4.is_empty());
        assert_eq!(
            v6.ipv6,
            vec![strings(&[
                "-A",
                "MXC-test",
                "-d",
                "2606:50c0::/32",
                "-j",
                "ACCEPT",
            ])]
        );
    }

    #[test]
    fn host_rule_args_drop_unresolvable_destination() {
        let args = NetworkIptablesManager::build_host_rule_args(
            "MXC-test",
            "140.82.112.0/33",
            &RuleAction::Allow,
        );

        assert!(args.ipv4.is_empty());
        assert!(args.ipv6.is_empty());
    }

    #[test]
    fn build_policy_rule_args_splits_allow_and_block_lists_by_family() {
        let policy = ContainerPolicy {
            allowed_hosts: vec!["140.82.112.0/20".to_string(), "2606:50c0::/32".to_string()],
            blocked_hosts: vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()],
            ..Default::default()
        };

        let args = NetworkIptablesManager::build_policy_rule_args("MXC-test", &policy);

        assert_eq!(
            args.ipv4,
            vec![
                strings(&["-A", "MXC-test", "-d", "140.82.112.0/20", "-j", "ACCEPT"]),
                strings(&["-A", "MXC-test", "-d", "10.0.0.0/8", "-j", "DROP"]),
            ]
        );
        assert_eq!(
            args.ipv6,
            vec![
                strings(&["-A", "MXC-test", "-d", "2606:50c0::/32", "-j", "ACCEPT"]),
                strings(&["-A", "MXC-test", "-d", "2001:db8::/32", "-j", "DROP"]),
            ]
        );
    }

    #[test]
    fn base_chain_rule_args_are_family_agnostic() {
        // The same base rules are fed to both iptables and ip6tables, so they
        // must not name an address family or a v4-only protocol.
        let base = NetworkIptablesManager::build_base_chain_rule_args("MXC-test");

        assert_eq!(base.len(), 4);
        for rule in &base {
            assert!(!rule.iter().any(|arg| arg == "icmp"));
        }
    }
}
