// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Network policy enforcement via iptables rules scoped to the LXC container.
//!
//! Maps the platform-agnostic `ContainerPolicy` network settings to iptables
//! rules applied to the container's virtual ethernet (veth) interface.

use std::net::ToSocketAddrs;
use std::process::Command;

use wxc_common::logger::Logger;
use wxc_common::models::{ContainerPolicy, NetworkEnforcementMode, NetworkPolicy, ProxyConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProxyEndpoint {
    ip: String,
    port: u16,
}

/// Manages iptables rules for an LXC container's network policy.
pub struct NetworkIptablesManager {
    /// Chain name unique to this container (e.g., "MXC-<container-name>").
    chain_name: String,
    /// Whether rules have been applied.
    rules_applied: bool,
    /// The container's veth interface name on the host.
    veth_interface: Option<String>,
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

    /// Resolve a hostname to IPv4 addresses.
    ///
    /// IPv6 records (AAAA from DNS, or IPv6 literals like `"::1"` /
    /// IPv4-mapped IPv6 like `"::ffff:127.0.0.1"`) are silently dropped
    /// because `apply_firewall_rules` only invokes `iptables` (the IPv4
    /// tool), which rejects IPv6 destinations. Full dual-stack support
    /// via parallel `ip6tables` rules would require a separate change.
    /// A host that resolves only to AAAA records will return an empty
    /// vec, meaning no allow/deny rule is emitted and the host is
    /// effectively unreachable from the sandbox under firewall mode.
    fn resolve_host(host: &str) -> Vec<String> {
        // Try as IP address first
        if let Ok(addr) = host.parse::<std::net::IpAddr>() {
            return if addr.is_ipv4() {
                vec![host.to_string()]
            } else {
                Vec::new()
            };
        }

        // Try DNS resolution
        match format!("{}:0", host).to_socket_addrs() {
            Ok(addrs) => addrs
                .map(|a| a.ip())
                .filter(|ip| ip.is_ipv4())
                .map(|ip| ip.to_string())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Run an iptables command and return success/failure.
    fn run_iptables(args: &[&str], logger: &mut Logger) -> Result<bool, String> {
        Self::run_firewall_command("iptables", args, logger)
    }

    /// Run an ip6tables command and return success/failure.
    fn run_ip6tables(args: &[&str], logger: &mut Logger) -> Result<bool, String> {
        Self::run_firewall_command("ip6tables", args, logger)
    }

    /// Probe whether `ip6tables` can be used on this host.
    ///
    /// Runs a harmless, read-only `ip6tables -S` (list the filter table). This
    /// fails both when the binary is missing (IPv4-only images) and when the
    /// kernel has IPv6 disabled (`ip6tables` reports the table cannot be
    /// initialized). In either case the caller skips the parallel v6 chain and
    /// warns, instead of aborting an otherwise-valid IPv4 policy — a hard
    /// dependency on ip6tables would break pure-IPv4 hosts that worked before
    /// dual-stack support was added. When IPv6 is disabled there is also no v6
    /// egress to leak, so skipping is safe rather than fail-open.
    fn ip6tables_available(logger: &mut Logger) -> bool {
        match Command::new("ip6tables").arg("-S").output() {
            Ok(output) if output.status.success() => true,
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                logger.log_line(&format!(
                    "ip6tables unavailable ({}); skipping IPv6 firewall rules.",
                    stderr.trim()
                ));
                false
            }
            Err(e) => {
                logger.log_line(&format!(
                    "ip6tables not found ({}); skipping IPv6 firewall rules.",
                    e
                ));
                false
            }
        }
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

    fn run_iptables_args(args: &[String], logger: &mut Logger) -> Result<bool, String> {
        let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
        Self::run_iptables(&refs, logger)
    }

    fn run_ip6tables_args(args: &[String], logger: &mut Logger) -> Result<bool, String> {
        let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
        Self::run_ip6tables(&refs, logger)
    }

    /// Rules every chain opens with, identical in both address families: allow
    /// loopback and already-established/related flows.
    fn build_base_chain_rule_args(chain_name: &str) -> Vec<Vec<String>> {
        vec![
            vec![
                "-A".to_string(),
                chain_name.to_string(),
                "-i".to_string(),
                "lo".to_string(),
                "-j".to_string(),
                "ACCEPT".to_string(),
            ],
            vec![
                "-A".to_string(),
                chain_name.to_string(),
                "-m".to_string(),
                "state".to_string(),
                "--state".to_string(),
                "ESTABLISHED,RELATED".to_string(),
                "-j".to_string(),
                "ACCEPT".to_string(),
            ],
        ]
    }

    /// The closing catch-all rule appended to a chain.
    fn build_default_rule_arg(chain_name: &str, action: &str) -> Vec<String> {
        vec![
            "-A".to_string(),
            chain_name.to_string(),
            "-j".to_string(),
            action.to_string(),
        ]
    }

    /// The catch-all action for a chain. Proxy mode is "deny all except the
    /// proxy", so it always closes with DROP regardless of the configured
    /// default policy.
    fn default_policy_action(default_policy: NetworkPolicy, proxy_enabled: bool) -> &'static str {
        if proxy_enabled {
            return "DROP";
        }
        match default_policy {
            NetworkPolicy::Block => "DROP",
            NetworkPolicy::Allow => "ACCEPT",
        }
    }

    fn build_ordered_egress_rules(
        chain_name: &str,
        blocked_ips: &[String],
        allowed_ips: &[String],
        default_policy: NetworkPolicy,
        proxy_endpoints: &[ProxyEndpoint],
    ) -> Vec<Vec<String>> {
        let mut rules = Vec::new();

        if !proxy_endpoints.is_empty() {
            for endpoint in proxy_endpoints {
                rules.push(vec![
                    "-A".to_string(),
                    chain_name.to_string(),
                    "-p".to_string(),
                    "tcp".to_string(),
                    "-d".to_string(),
                    endpoint.ip.clone(),
                    "--dport".to_string(),
                    endpoint.port.to_string(),
                    "-j".to_string(),
                    "ACCEPT".to_string(),
                ]);
            }
            rules.push(Self::build_default_rule_arg(
                chain_name,
                Self::default_policy_action(default_policy, true),
            ));
            return rules;
        }

        for ip in blocked_ips {
            rules.push(vec![
                "-A".to_string(),
                chain_name.to_string(),
                "-d".to_string(),
                ip.clone(),
                "-j".to_string(),
                "DROP".to_string(),
            ]);
        }

        for ip in allowed_ips {
            rules.push(vec![
                "-A".to_string(),
                chain_name.to_string(),
                "-d".to_string(),
                ip.clone(),
                "-j".to_string(),
                "ACCEPT".to_string(),
            ]);
        }

        rules.push(Self::build_default_rule_arg(
            chain_name,
            Self::default_policy_action(default_policy, false),
        ));

        rules
    }

    fn resolve_policy_hosts(hosts: &[String], action: &str, logger: &mut Logger) -> Vec<String> {
        let mut resolved = Vec::new();

        for host in hosts {
            let ips = Self::resolve_host(host);
            if ips.is_empty() {
                logger.log_line(&format!("Warning: could not resolve host '{}'", host));
                continue;
            }
            for ip in ips {
                logger.log_line(&format!("{} host: {} ({})", action, host, ip));
                resolved.push(ip);
            }
        }

        resolved
    }

    /// Whether `host` is already an IP literal (v4 or v6) and therefore needs
    /// no DNS resolution to reach. Accepts bracketed IPv6 literals (e.g.
    /// `[::1]`) as stored by the proxy URL parser.
    fn host_is_ip_literal(host: &str) -> bool {
        let candidate = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        candidate.parse::<std::net::IpAddr>().is_ok()
    }

    /// Pin an enabled, hostname-addressed proxy to a single host-resolved IPv4
    /// address.
    ///
    /// Model 2 ("deny-all-except-proxy") allows exactly one destination, so the
    /// firewall rule and the `HTTP(S)_PROXY` handed to the container must name
    /// the *same* endpoint. Resolving host-side and injecting the resulting IP
    /// achieves that and removes the container's need to resolve anything, so
    /// DNS can stay closed — closing the DNS-tunnel exfil path that an open
    /// port 53 would otherwise leave in a deny-all posture.
    ///
    /// Returns the config unchanged when the proxy is disabled, has no address
    /// (built-in test server), or is already an IP literal. Multi-A-record
    /// hostnames collapse to the first resolved address, which is the point:
    /// both sides then agree on one IP instead of racing DNS.
    pub fn pin_proxy_to_resolved_ip(
        proxy: &ProxyConfig,
        logger: &mut Logger,
    ) -> Result<ProxyConfig, String> {
        if !proxy.is_enabled() {
            return Ok(proxy.clone());
        }

        let Some(address) = proxy.address.as_ref() else {
            return Ok(proxy.clone());
        };

        if Self::host_is_ip_literal(address.host()) {
            return Ok(proxy.clone());
        }

        let ips = Self::resolve_host(address.host());
        let Some(ip) = ips.first() else {
            return Err(format!(
                "Could not resolve network proxy host '{}' to an IPv4 address",
                address.host()
            ));
        };

        if ips.len() > 1 {
            logger.log_line(&format!(
                "Network proxy host '{}' resolved to {} addresses; pinning to {} so the \
                 firewall rule and the injected HTTP(S)_PROXY agree.",
                address.host(),
                ips.len(),
                ip
            ));
        } else {
            logger.log_line(&format!(
                "Pinning network proxy '{}' to resolved address {}.",
                address.host(),
                ip
            ));
        }

        Ok(ProxyConfig {
            address: Some(address.pinned_to_ip(ip)),
            builtin_test_server: proxy.builtin_test_server,
        })
    }

    fn resolve_proxy_endpoints(
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<Vec<ProxyEndpoint>, String> {
        if !policy.network_proxy.is_enabled() {
            return Ok(Vec::new());
        }

        let address = policy.network_proxy.address.as_ref().ok_or_else(|| {
            "Network proxy is enabled but no proxy address is configured".to_string()
        })?;

        if address.port() == 0 {
            return Err("Network proxy port must be between 1 and 65535".to_string());
        }

        let ips = Self::resolve_host(address.host());
        if ips.is_empty() {
            return Err(format!(
                "Could not resolve network proxy host '{}'",
                address.host()
            ));
        }

        Ok(ips
            .into_iter()
            .map(|ip| {
                logger.log_line(&format!(
                    "Allowing network proxy egress: {}:{} ({})",
                    address.host(),
                    address.port(),
                    ip
                ));
                ProxyEndpoint {
                    ip,
                    port: address.port(),
                }
            })
            .collect())
    }

    /// Apply network firewall rules based on the container policy.
    pub fn apply_firewall_rules(
        &mut self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<bool, String> {
        // Skip if network enforcement doesn't use firewall
        let use_firewall = matches!(
            policy.network_enforcement_mode,
            NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
        ) || policy.network_proxy.is_enabled();
        if !use_firewall {
            logger.log_line("Network enforcement mode does not use firewall, skipping iptables.");
            return Ok(true);
        }

        if self.veth_interface.is_none() {
            return Err(
                "No veth interface set for container; cannot scope iptables FORWARD hook"
                    .to_string(),
            );
        }

        match self.apply_firewall_rules_inner(policy, logger) {
            Ok(()) => {
                self.rules_applied = true;
                Ok(true)
            }
            Err(e) => {
                // Roll back whatever was created before the failure. Without
                // this, `remove_firewall_rules` short-circuits on
                // `rules_applied == false` and the orphan chain(s) survive, so
                // the next attempt fails permanently on `-N` ("chain already
                // exists") until someone cleans up by hand.
                logger.log_line(&format!(
                    "Firewall setup failed: {}. Cleaning up partial iptables state.",
                    e
                ));
                self.teardown_chains(logger);
                Err(e)
            }
        }
    }

    /// Fallible body of [`Self::apply_firewall_rules`]. Kept separate so the
    /// public method can roll back partial state on the error path.
    fn apply_firewall_rules_inner(
        &self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<(), String> {
        let iface = self.veth_interface.as_ref().ok_or_else(|| {
            "No veth interface set for container; cannot scope iptables FORWARD hook".to_string()
        })?;

        logger.log_line(&format!(
            "Creating iptables/ip6tables chain: {}",
            self.chain_name
        ));

        // Probe ip6tables once. On IPv4-only hosts (binary absent or IPv6
        // disabled in the kernel) enforce the v4 policy and skip the v6 chain
        // rather than failing a policy that worked before dual-stack support.
        // Such a host has no IPv6 egress to leak in the first place.
        let ipv6_enabled = Self::ip6tables_available(logger);

        // Create custom chains.
        Self::run_iptables(&["-N", &self.chain_name], logger)?;
        if ipv6_enabled {
            Self::run_ip6tables(&["-N", &self.chain_name], logger)?;
        }

        // Always allow loopback and established connections, in both families.
        let base_rules = Self::build_base_chain_rule_args(&self.chain_name);
        for args in &base_rules {
            Self::run_iptables_args(args, logger)?;
        }
        if ipv6_enabled {
            for args in &base_rules {
                Self::run_ip6tables_args(args, logger)?;
            }
        }

        let proxy_endpoints = Self::resolve_proxy_endpoints(policy, logger)?;
        let proxy_enabled = !proxy_endpoints.is_empty();

        // Outbound DNS (port 53) is opened only outside proxy mode, where the
        // hostname allow/block lists require the container to resolve names.
        //
        // Under "deny-all-except-proxy" DNS stays shut: the proxy endpoint is
        // resolved host-side and the container is handed that literal address
        // (see `pin_proxy_to_resolved_ip`), so it never needs a resolver. An
        // unscoped port-53 ACCEPT would otherwise leave a standing DNS-tunnel
        // exfil path straight through a posture whose whole point is that the
        // proxy is the only reachable destination.
        let allow_dns = !proxy_enabled;

        if allow_dns {
            for protocol in ["udp", "tcp"] {
                Self::run_iptables(
                    &[
                        "-A",
                        &self.chain_name,
                        "-p",
                        protocol,
                        "--dport",
                        "53",
                        "-j",
                        "ACCEPT",
                    ],
                    logger,
                )?;
            }
        }

        let (blocked_ips, allowed_ips) = if proxy_enabled {
            logger.log_line(
                "Network proxy enabled: allowing proxy egress only and dropping all other \
                 outbound traffic (including DNS).",
            );
            (Vec::new(), Vec::new())
        } else {
            (
                Self::resolve_policy_hosts(&policy.blocked_hosts, "Blocking", logger),
                Self::resolve_policy_hosts(&policy.allowed_hosts, "Allowing", logger),
            )
        };

        for args in Self::build_ordered_egress_rules(
            &self.chain_name,
            &blocked_ips,
            &allowed_ips,
            policy.default_network_policy.clone(),
            &proxy_endpoints,
        ) {
            Self::run_iptables_args(&args, logger)?;
        }

        // Mirror the closing stance into ip6tables.
        //
        // Every destination rule above is IPv4 (`resolve_host` keeps only v4
        // addresses, and the proxy endpoint is a v4 literal), so the v6 chain
        // carries no per-destination rules — just the same default stance. In
        // proxy mode that is DROP, which is what actually closes the model-2
        // bypass: without a v6 chain, a dual-stack container could reach the
        // internet over IPv6 while the v4 chain dropped everything.
        if ipv6_enabled {
            let ipv6_default =
                Self::default_policy_action(policy.default_network_policy.clone(), proxy_enabled);
            logger.log_line(&format!("IPv6 default egress policy: {}", ipv6_default));
            Self::run_ip6tables_args(
                &Self::build_default_rule_arg(&self.chain_name, ipv6_default),
                logger,
            )?;
        } else if proxy_enabled {
            logger.log_line(
                "Warning: ip6tables unavailable, so the deny-all-except-proxy rule set is \
                 IPv4-only; IPv6 egress is unfiltered if the host has IPv6 connectivity.",
            );
        }

        // Hook the chains into FORWARD for the container's egress traffic.
        // Packets originating in the container arrive at the host on the
        // host-side veth, so they match FORWARD by input interface (`-i`);
        // `-o` would instead match traffic flowing toward the container and
        // leave container egress — the thing this policy exists to restrict —
        // entirely unfiltered.
        Self::run_iptables(
            &["-I", "FORWARD", "-i", iface, "-j", &self.chain_name],
            logger,
        )?;
        if ipv6_enabled {
            Self::run_ip6tables(
                &["-I", "FORWARD", "-i", iface, "-j", &self.chain_name],
                logger,
            )?;
        }

        Ok(())
    }

    /// Best-effort removal of the FORWARD hooks and per-container chains in
    /// both tables. Safe to call even when only part of the state was created
    /// (a missing rule/chain just makes the individual `-D`/`-F`/`-X` call a
    /// no-op), so it doubles as the rollback path for a failed apply.
    fn teardown_chains(&self, logger: &mut Logger) {
        // Remove from FORWARD (only if we had a veth interface and hooked it).
        // Must match the `-i` direction used at insertion so the delete finds
        // the rule; a `-o` delete would silently leak the FORWARD hook.
        if let Some(ref iface) = self.veth_interface {
            let _ = Self::run_iptables(
                &["-D", "FORWARD", "-i", iface, "-j", &self.chain_name],
                logger,
            );
            let _ = Self::run_ip6tables(
                &["-D", "FORWARD", "-i", iface, "-j", &self.chain_name],
                logger,
            );
        }

        // Flush and delete the chains.
        let _ = Self::run_iptables(&["-F", &self.chain_name], logger);
        let _ = Self::run_iptables(&["-X", &self.chain_name], logger);
        let _ = Self::run_ip6tables(&["-F", &self.chain_name], logger);
        let _ = Self::run_ip6tables(&["-X", &self.chain_name], logger);
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

        self.teardown_chains(logger);

        self.rules_applied = false;
        Ok(())
    }

    /// Best-effort cleanup of any iptables state the runner may have
    /// installed for a container, used when the original
    /// `NetworkIptablesManager` instance isn't reachable (e.g. signal-time
    /// cleanup from the watchdog thread). Builds a fresh manager pointed at
    /// the same chain name so `remove_firewall_rules` does its work
    /// regardless of whether rules were actually installed; iptables itself
    /// is the source of truth.
    pub fn force_cleanup(container_name: &str, veth_interface: Option<&str>, logger: &mut Logger) {
        let mut mgr = Self::new(container_name);
        if let Some(v) = veth_interface {
            mgr.set_veth_interface(v);
        }
        // Bypass the rules_applied gate; if there's nothing to remove the
        // iptables `-D`/`-F`/`-X` calls just no-op.
        mgr.rules_applied = true;
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
mod tests {
    use super::*;
    use wxc_common::models::{ProxyAddress, ProxyConfig};

    fn test_logger() -> Logger {
        Logger::new(wxc_common::logger::Mode::Buffer)
    }

    fn proxy_from_url(url: &str, host: &str, port: u16) -> ProxyConfig {
        ProxyConfig {
            address: Some(ProxyAddress::from_url(url, host.to_string(), port)),
            builtin_test_server: false,
        }
    }

    #[test]
    fn proxy_mode_default_action_is_drop_regardless_of_default_policy() {
        // Model 2 is "deny all except the proxy": even an explicit
        // defaultPolicy=allow must not reopen the chain.
        assert_eq!(
            NetworkIptablesManager::default_policy_action(NetworkPolicy::Allow, true),
            "DROP"
        );
        assert_eq!(
            NetworkIptablesManager::default_policy_action(NetworkPolicy::Block, true),
            "DROP"
        );
        assert_eq!(
            NetworkIptablesManager::default_policy_action(NetworkPolicy::Allow, false),
            "ACCEPT"
        );
        assert_eq!(
            NetworkIptablesManager::default_policy_action(NetworkPolicy::Block, false),
            "DROP"
        );
    }

    #[test]
    fn base_chain_rules_are_family_agnostic() {
        // The same argv is replayed against iptables and ip6tables, so it must
        // not name an address family (no -4/-6, no literal addresses).
        let rules = NetworkIptablesManager::build_base_chain_rule_args("MXC-test");
        assert_eq!(rules.len(), 2);
        for rule in &rules {
            assert_eq!(rule[0], "-A");
            assert_eq!(rule[1], "MXC-test");
            assert!(
                !rule.iter().any(|a| a == "-4" || a == "-6" || a == "-d"),
                "base rule must be family-agnostic: {rule:?}"
            );
        }
    }

    #[test]
    fn proxy_endpoint_rule_is_followed_by_drop() {
        let endpoints = vec![ProxyEndpoint {
            ip: "10.1.2.3".to_string(),
            port: 8080,
        }];
        let rules = NetworkIptablesManager::build_ordered_egress_rules(
            "MXC-test",
            &[],
            &[],
            NetworkPolicy::Allow,
            &endpoints,
        );

        assert_eq!(rules.len(), 2, "expected one ACCEPT plus the closing DROP");
        assert!(rules[0].contains(&"10.1.2.3".to_string()));
        assert!(rules[0].contains(&"8080".to_string()));
        assert_eq!(rules[0].last().unwrap(), "ACCEPT");
        assert_eq!(rules[1].last().unwrap(), "DROP");
    }

    #[test]
    fn pin_proxy_rewrites_hostname_to_resolved_ip() {
        // localhost is the one hostname guaranteed resolvable in CI, so it is
        // used here as a stand-in for any A-record proxy host.
        let proxy = proxy_from_url("http://localhost:8080", "localhost", 8080);
        let mut logger = test_logger();

        let pinned = NetworkIptablesManager::pin_proxy_to_resolved_ip(&proxy, &mut logger)
            .expect("localhost should resolve");
        let address = pinned.address.expect("pinned proxy keeps an address");

        assert_eq!(address.host(), "127.0.0.1");
        assert_eq!(address.port(), 8080);
        // The injected HTTP(S)_PROXY must name the same literal the firewall
        // ACCEPT was written for — not the original hostname.
        assert_eq!(address.to_url(), "http://127.0.0.1:8080");
    }

    #[test]
    fn pin_proxy_leaves_ip_literals_untouched() {
        let proxy = proxy_from_url("http://10.0.0.9:3128", "10.0.0.9", 3128);
        let mut logger = test_logger();

        let pinned = NetworkIptablesManager::pin_proxy_to_resolved_ip(&proxy, &mut logger)
            .expect("IP literals need no resolution");
        let address = pinned.address.expect("address preserved");

        assert_eq!(address.host(), "10.0.0.9");
        assert_eq!(address.to_url(), "http://10.0.0.9:3128");
    }

    #[test]
    fn pin_proxy_is_a_noop_when_disabled() {
        let mut logger = test_logger();
        let pinned =
            NetworkIptablesManager::pin_proxy_to_resolved_ip(&ProxyConfig::default(), &mut logger)
                .expect("disabled proxy is not an error");
        assert!(!pinned.is_enabled());
    }

    #[test]
    fn pin_proxy_errors_when_hostname_does_not_resolve() {
        // Fail closed: model 2 allows exactly one destination, so an
        // unresolvable proxy must abort setup rather than silently produce a
        // chain that drops everything.
        let proxy = proxy_from_url(
            "http://proxy.invalid:8080",
            "this-host-does-not-exist.invalid",
            8080,
        );
        let mut logger = test_logger();

        assert!(NetworkIptablesManager::pin_proxy_to_resolved_ip(&proxy, &mut logger).is_err());
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
        assert_eq!(ips, vec!["127.0.0.1"]);
    }

    #[test]
    fn resolve_host_drops_ipv6_literal() {
        // IPv6 literals must be silently dropped — `iptables` (v4) would
        // reject them and fail the whole `apply_firewall_rules` call.
        let ips = NetworkIptablesManager::resolve_host("::1");
        assert!(
            ips.is_empty(),
            "expected empty vec for IPv6 literal, got {:?}",
            ips
        );
    }

    #[test]
    fn resolve_host_drops_ipv4_mapped_ipv6_literal() {
        // `::ffff:127.0.0.1` parses as `IpAddr::V6` and is the v6
        // wire-format encoding of an v4 address — `iptables` would
        // still reject it as a v6 destination, so we drop it.
        let ips = NetworkIptablesManager::resolve_host("::ffff:127.0.0.1");
        assert!(
            ips.is_empty(),
            "expected empty vec for v4-mapped-v6 literal, got {:?}",
            ips
        );
    }

    #[test]
    fn resolve_host_keeps_ipv4_literal_unchanged() {
        // Round-trip: v4 literals must pass through verbatim — the
        // IPv4-only filter must not regress the happy path.
        let ips = NetworkIptablesManager::resolve_host("10.0.0.1");
        assert_eq!(ips, vec!["10.0.0.1"]);
    }

    #[test]
    fn host_is_ip_literal_detects_ips_and_hostnames() {
        assert!(NetworkIptablesManager::host_is_ip_literal("10.0.0.5"));
        assert!(NetworkIptablesManager::host_is_ip_literal("127.0.0.1"));
        // Bracketed and bare IPv6 literals both count as "no DNS needed".
        assert!(NetworkIptablesManager::host_is_ip_literal("[::1]"));
        assert!(NetworkIptablesManager::host_is_ip_literal("::1"));
        // Hostnames require resolution, so they are not IP literals.
        assert!(!NetworkIptablesManager::host_is_ip_literal(
            "proxy.example.com"
        ));
        assert!(!NetworkIptablesManager::host_is_ip_literal("localhost"));
    }

    #[test]
    fn firewall_mode_without_veth_fails_fast() {
        let mut mgr = NetworkIptablesManager::new("no-veth");
        let policy = ContainerPolicy {
            network_enforcement_mode: NetworkEnforcementMode::Firewall,
            ..Default::default()
        };
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);

        let err = mgr.apply_firewall_rules(&policy, &mut logger).unwrap_err();

        assert!(err.contains("No veth interface set"));
        assert!(!mgr.rules_applied());
    }

    #[test]
    fn ordered_egress_rules_put_deny_before_allow() {
        let blocked = vec!["10.0.0.5".to_string()];
        let allowed = vec!["10.0.0.0".to_string()];

        let rules = NetworkIptablesManager::build_ordered_egress_rules(
            "MXC-test",
            &blocked,
            &allowed,
            NetworkPolicy::Block,
            &[],
        );

        assert_eq!(
            rules,
            vec![
                vec!["-A", "MXC-test", "-d", "10.0.0.5", "-j", "DROP"],
                vec!["-A", "MXC-test", "-d", "10.0.0.0", "-j", "ACCEPT"],
                vec!["-A", "MXC-test", "-j", "DROP"],
            ]
        );
    }

    #[test]
    fn proxy_egress_rules_allow_only_proxy_then_drop() {
        let blocked = vec!["10.0.0.5".to_string()];
        let allowed = vec!["10.0.0.0".to_string()];
        let proxy = vec![ProxyEndpoint {
            ip: "127.0.0.1".to_string(),
            port: 8080,
        }];

        let rules = NetworkIptablesManager::build_ordered_egress_rules(
            "MXC-test",
            &blocked,
            &allowed,
            NetworkPolicy::Allow,
            &proxy,
        );

        assert_eq!(
            rules,
            vec![
                vec![
                    "-A",
                    "MXC-test",
                    "-p",
                    "tcp",
                    "-d",
                    "127.0.0.1",
                    "--dport",
                    "8080",
                    "-j",
                    "ACCEPT",
                ],
                vec!["-A", "MXC-test", "-j", "DROP"],
            ]
        );
    }
}
