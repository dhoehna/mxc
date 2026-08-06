// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Network policy enforcement via iptables rules scoped to the LXC container.
//!
//! Maps the platform-agnostic `ContainerPolicy` network settings to iptables
//! rules applied to the container's virtual ethernet (veth) interface.

use std::net::ToSocketAddrs;
use std::process::Command;

use wxc_common::logger::Logger;
use wxc_common::models::{
    ContainerPolicy, NetworkEnforcementMode, NetworkPolicy, ProxyAddress, ProxyConfig,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProxyEndpoint {
    ip: String,
    port: u16,
}

/// Which firewall objects a single `apply` actually created.
///
/// Chain names are truncated to 20 sanitized characters (see
/// [`NetworkIptablesManager::new`]), so two containers can collide on one name.
/// Rolling back blindly after a failed `-N` would then flush and delete a chain
/// owned by a *different, live* container, and leave its hooks pointing at an
/// empty chain. Recording what this call created keeps the rollback to its own
/// resources.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct CreatedFirewallState {
    v4_chain: bool,
    v6_chain: bool,
    v4_hooks: bool,
    v6_hooks: bool,
    v4_dhcp: bool,
    v6_dhcp: bool,
}

impl CreatedFirewallState {
    /// Everything this manager could have created. Used by the teardown paths
    /// that run after a successful apply (and by `force_cleanup`), where the
    /// manager owns all of it and iptables is the source of truth.
    fn all() -> Self {
        Self {
            v4_chain: true,
            v6_chain: true,
            v4_hooks: true,
            v6_hooks: true,
            v4_dhcp: true,
            v6_dhcp: true,
        }
    }
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
    /// initialized). The two cases are **not** equivalent, so callers must pair
    /// this with [`Self::host_has_ipv6`]: skipping the v6 chain is safe only on
    /// a host that has no IPv6 stack to leak through.
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

    /// Whether this host has a live IPv6 stack.
    ///
    /// `/proc/net/if_inet6` exists only when the kernel's IPv6 support is
    /// present, and lists one line per configured address — so it is empty when
    /// IPv6 is administratively disabled everywhere
    /// (`net.ipv6.conf.all.disable_ipv6=1`). Absent or empty therefore means
    /// "no IPv6 egress to filter"; anything else means IPv6 is live.
    ///
    /// If the file exists but cannot be read we report `true` so the caller
    /// fails closed rather than assuming away a family it cannot filter.
    fn host_has_ipv6() -> bool {
        let path = std::path::Path::new("/proc/net/if_inet6");
        if !path.exists() {
            return false;
        }
        match std::fs::read_to_string(path) {
            Ok(contents) => contents.lines().any(|line| !line.trim().is_empty()),
            Err(_) => true,
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

    /// Build the **complete** ordered rule list for a container's chain.
    ///
    /// The chain is only ever reached from a hook scoped to the container's
    /// host-side veth (`-i <veth>`), so every packet that enters it originates
    /// in the container. Two consequences shape this list:
    ///
    /// * There is **no `ESTABLISHED,RELATED` accept.** Return traffic arrives
    ///   on `-o <veth>` and never traverses this chain, so such a rule would
    ///   not help reply packets — it would only let flows the container opened
    ///   *before* the chain was installed keep running afterwards, straight
    ///   through a deny-all posture. Every rule below matches on destination,
    ///   which holds for every packet of a flow, so permitted traffic works
    ///   without any conntrack exemption.
    /// * There is **no `-i lo` accept.** The input interface is `<veth>` by
    ///   construction, so a loopback match can never fire here.
    ///
    /// Deny rules are emitted before any accept (including the DNS accept) so
    /// that under first-match-wins a destination named in both lists is denied.
    fn build_chain_rules(
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

        // Outbound DNS, opened only outside proxy mode where the hostname
        // allow/block lists require the container to resolve names. Under
        // "deny-all-except-proxy" the proxy is resolved host-side and the
        // container is handed the literal address (see
        // `pin_proxy_to_resolved_ip`), so it never needs a resolver and an
        // unscoped port-53 accept would just be a standing DNS-tunnel exfil
        // path through a posture whose whole point is that the proxy is the
        // only reachable destination.
        for protocol in ["udp", "tcp"] {
            rules.push(vec![
                "-A".to_string(),
                chain_name.to_string(),
                "-p".to_string(),
                protocol.to_string(),
                "--dport".to_string(),
                "53".to_string(),
                "-j".to_string(),
                "ACCEPT".to_string(),
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

    /// Whether `host` is an IPv6 literal (bracketed `[..]` or bare).
    ///
    /// The proxy firewall rule is emitted with IPv4 `iptables` only, so an IPv6
    /// proxy endpoint cannot be enforced. It must be rejected explicitly rather
    /// than passed to IPv4-only resolution, which would drop it and leave a
    /// deny-all container whose proxy was silently discarded.
    fn host_is_ipv6_literal(host: &str) -> bool {
        let candidate = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        matches!(
            candidate.parse::<std::net::IpAddr>(),
            Ok(std::net::IpAddr::V6(_))
        )
    }

    /// The error returned when a proxy endpoint is an IPv6 literal, which the
    /// IPv4-only proxy firewall rule cannot enforce.
    fn ipv6_proxy_unsupported(host: &str) -> String {
        format!(
            "IPv6 network proxy endpoints are not supported: the proxy firewall rule is \
             emitted with IPv4 iptables only, so '{}' cannot be enforced and would be \
             silently dropped. Use an IPv4 proxy address.",
            host
        )
    }

    /// Whether the proxy is addressed with a TLS scheme, meaning the client
    /// opens a TLS connection *to the proxy itself* rather than tunneling
    /// through a plaintext one.
    ///
    /// This matters only when the host is about to be rewritten: replacing a
    /// hostname with a bare IP means the client presents no SNI for that name
    /// and validates the proxy's certificate against an IP, which fails unless
    /// the certificate carries a matching IP SAN.
    fn proxy_url_uses_tls(address: &ProxyAddress) -> bool {
        address
            .original_url
            .as_deref()
            .and_then(|raw| raw.split_once("://"))
            .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("https"))
    }

    /// The error returned when pinning would rewrite a TLS proxy's hostname to
    /// an IP and thereby break certificate validation.
    fn tls_proxy_pinning_unsupported(host: &str) -> String {
        format!(
            "A TLS-addressed network proxy ('https://{}') cannot be pinned to a resolved \
             address: deny-all-except-proxy rewrites the proxy host to the IP the host \
             resolved so the firewall rule and the injected HTTP(S)_PROXY name the same \
             endpoint, but that leaves the client validating the proxy certificate against \
             an IP with no SNI, which fails unless the certificate carries a matching IP \
             SAN. Address the proxy by IP in the config, or use an http:// proxy URL \
             (CONNECT tunneling still reaches https destinations).",
            host
        )
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
    /// (built-in test server), or is already an IPv4 literal. An IPv6 literal is
    /// rejected explicitly (the rule set is IPv4-only), as is a hostname behind
    /// an `https://` scheme (rewriting its host to an IP would break the
    /// proxy's own certificate validation). Multi-A-record hostnames collapse to
    /// the first resolved address, which is the point: both sides then agree on
    /// one IP instead of racing DNS.
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

        // Reject an IPv6 literal before the `host_is_ip_literal` short-circuit
        // below would treat it as "already pinned" and hand it downstream to
        // IPv4-only resolution, which drops it.
        if Self::host_is_ipv6_literal(address.host()) {
            return Err(Self::ipv6_proxy_unsupported(address.host()));
        }

        if Self::host_is_ip_literal(address.host()) {
            return Ok(proxy.clone());
        }

        // Checked only on the rewrite path. An address already given as an IP
        // literal is left untouched, so whatever the operator provisioned for it
        // keeps working.
        if Self::proxy_url_uses_tls(address) {
            return Err(Self::tls_proxy_pinning_unsupported(address.host()));
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

        // Reject an IPv6 literal explicitly. `resolve_host` is IPv4-only and
        // would return an empty vec for a v6 address, which the check below
        // would then report as an unresolvable host — a misleading error for a
        // perfectly valid literal we simply cannot enforce.
        if Self::host_is_ipv6_literal(address.host()) {
            return Err(Self::ipv6_proxy_unsupported(address.host()));
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
    ///
    /// LXC and Bubblewrap share this manager but not their scoping contract, so
    /// a missing veth is **not** rejected here. LXC enforcement is veth-scoped
    /// (every hook matches `-i <veth>`), and an LXC container whose veth cannot
    /// be discovered is refused up-stream in `lxc_runner` — failing closed
    /// where the backend that needs the veth actually runs. Bubblewrap has no
    /// veth (it runs in the host network namespace), so it builds the policy
    /// chain and skips the veth-scoped hooks rather than failing; see
    /// [`Self::apply_firewall_rules_inner`]. Rejecting a missing veth here made
    /// every Bubblewrap request with firewall host rules fail before `bwrap`
    /// started.
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

        let mut created = CreatedFirewallState::default();
        match self.apply_firewall_rules_inner(policy, logger, &mut created) {
            Ok(()) => {
                self.rules_applied = true;
                Ok(true)
            }
            Err(e) => {
                // Roll back what *this call* created, and only that. Without a
                // rollback, `remove_firewall_rules` short-circuits on
                // `rules_applied == false` and the orphan chain(s) survive, so
                // the next attempt fails permanently on `-N` ("chain already
                // exists"). But an unconditional teardown is just as wrong:
                // chain names are truncated to 20 sanitized characters, so a
                // different live container can already own this name, and a
                // failed `-N` would then have us flush and delete *its* rules.
                logger.log_line(&format!(
                    "Firewall setup failed: {}. Cleaning up partial iptables state.",
                    e
                ));
                self.teardown_created(created, logger);
                Err(e)
            }
        }
    }

    /// Fallible body of [`Self::apply_firewall_rules`]. Kept separate so the
    /// public method can roll back partial state on the error path; every
    /// object actually created is recorded in `created` so that rollback
    /// removes only this call's own state.
    fn apply_firewall_rules_inner(
        &self,
        policy: &ContainerPolicy,
        logger: &mut Logger,
        created: &mut CreatedFirewallState,
    ) -> Result<(), String> {
        logger.log_line(&format!(
            "Creating iptables/ip6tables chain: {}",
            self.chain_name
        ));

        let proxy_endpoints = Self::resolve_proxy_endpoints(policy, logger)?;
        let proxy_enabled = !proxy_endpoints.is_empty();

        // Probe ip6tables once. Being unable to run it is only safe when the
        // host has no IPv6 stack; on a host with live IPv6 it means we cannot
        // filter a whole address family. Skipping the v6 chain there would be
        // fail-open — the container would get unrestricted IPv6 egress while
        // the policy claims everything but the proxy is dropped — so a policy
        // whose v6 stance is DROP fails setup instead.
        let ipv6_enabled = Self::ip6tables_available(logger);
        let ipv6_stance_is_drop =
            proxy_enabled || matches!(policy.default_network_policy, NetworkPolicy::Block);
        if !ipv6_enabled {
            if ipv6_stance_is_drop {
                if Self::host_has_ipv6() {
                    return Err(format!(
                        "ip6tables is unusable on this host but IPv6 is live \
                         (/proc/net/if_inet6 lists addresses), so IPv6 egress for container \
                         '{}' cannot be filtered. Refusing to start with an unenforceable \
                         network policy: disable IPv6 on the host, or install/enable \
                         ip6tables.",
                        self.chain_name
                    ));
                }
                logger.log_line(
                    "ip6tables unusable and no live IPv6 stack on this host; enforcing the \
                     IPv4 policy only.",
                );
            } else {
                logger.log_line(
                    "ip6tables unusable; enforcing the IPv4 policy only. The default IPv6 \
                     stance is ACCEPT, so no IPv6 restriction is being dropped.",
                );
            }
        }

        // Create custom chains. A failure here means the name is already taken
        // (chain names are truncated, so a collision with another live
        // container is possible), which is why `created` is only marked after
        // the command succeeds — the rollback must not touch a chain we did
        // not make.
        Self::run_iptables(&["-N", &self.chain_name], logger)?;
        created.v4_chain = true;
        if ipv6_enabled {
            Self::run_ip6tables(&["-N", &self.chain_name], logger)?;
            created.v6_chain = true;
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

        for args in Self::build_chain_rules(
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
        }

        // Hook the chains for the container's egress traffic — but only when a
        // veth interface is known.
        //
        // The hooks are the point where LXC's and Bubblewrap's scoping
        // contracts diverge. LXC always has a veth and its enforcement is
        // veth-scoped, so the hooks below match `-i <veth>`. Bubblewrap runs in
        // the host network namespace and has no veth: there is no per-container
        // interface to scope to, and hooking an unscoped rule into FORWARD or
        // INPUT would filter the *host's* own traffic. So the no-veth path
        // builds the policy chain (above) and installs no hooks, which is the
        // behavior Bubblewrap had before veth-scoping was introduced. An LXC
        // container that reaches here without a veth is a bug caught up-stream
        // in `lxc_runner`, which fails closed before calling this.
        if let Some(iface) = self.veth_interface.as_ref() {
            // FORWARD covers traffic being routed *through* the host to
            // somewhere else. Packets originating in the container arrive at the
            // host on the host-side veth, so they match by input interface
            // (`-i`); `-o` would instead match traffic flowing toward the
            // container and leave container egress — the thing this policy
            // exists to restrict — entirely unfiltered.
            //
            // INPUT covers traffic addressed to the *host itself*. Netfilter
            // sends locally-destined packets to INPUT and never to FORWARD, so
            // hooking only FORWARD would leave the bridge gateway and every
            // service on the host reachable from inside the container — a hole
            // straight through "the proxy is the only destination you can
            // reach". The same chain is reused, so a host-local proxy is still
            // permitted by its own ACCEPT rule while everything else on the host
            // is dropped.
            // The hook flags (`v4_hooks`/`v6_hooks`) are set *before* the
            // inserts: each covers a FORWARD+INPUT pair, so marking after the
            // loop would leak the FORWARD hook if the INPUT insert failed, and a
            // rollback `-D` for a hook that was never inserted is a harmless
            // no-op because it is scoped to this container's own veth. (The
            // chain flags are the opposite case — `-F`/`-X` are name-scoped and
            // can hit another container, so those are only set once `-N` has
            // succeeded.)
            created.v4_hooks = true;
            for hook in ["FORWARD", "INPUT"] {
                Self::run_iptables(&["-I", hook, "-i", iface, "-j", &self.chain_name], logger)?;
            }

            // DHCP must survive the INPUT hook or the container loses its lease
            // on renewal: `lxc-net` runs dnsmasq on the bridge, so DHCPREQUEST is
            // addressed to the host and would otherwise hit the chain's DROP.
            // `-I` pushes this ahead of the jump inserted above. It is a
            // link-local exchange with the bridge, not an egress path, so it
            // does not weaken the deny-all posture.
            //
            // Unlike the hooks, this is a single insert, so the flag is set
            // *after* the command succeeds. Marking before would let a rollback
            // run `-D INPUT ... --dport 67` for a rule this attempt never
            // created, deleting a matching DHCP accept the host already had.
            Self::run_iptables(
                &[
                    "-I", "INPUT", "-i", iface, "-p", "udp", "--dport", "67", "-j", "ACCEPT",
                ],
                logger,
            )?;
            created.v4_dhcp = true;

            if ipv6_enabled {
                created.v6_hooks = true;
                for hook in ["FORWARD", "INPUT"] {
                    Self::run_ip6tables(
                        &["-I", hook, "-i", iface, "-j", &self.chain_name],
                        logger,
                    )?;
                }

                // Same as the v4 DHCP accept: mark ownership only after the
                // insert succeeds so a rollback never deletes a pre-existing
                // rule this attempt did not create.
                Self::run_ip6tables(
                    &[
                        "-I", "INPUT", "-i", iface, "-p", "udp", "--dport", "547", "-j", "ACCEPT",
                    ],
                    logger,
                )?;
                created.v6_dhcp = true;
            }
        } else {
            logger.log_line(
                "No veth interface set (Bubblewrap host-namespace scoping): built the policy \
                 chain but installed no FORWARD/INPUT hooks. Host-wide hooks would filter the \
                 host's own traffic, so none are applied.",
            );
        }

        Ok(())
    }

    /// Best-effort removal of every hook and chain this manager could have
    /// created, in both tables. Used by the post-apply teardown paths, where
    /// the manager owns all of it and iptables is the source of truth.
    fn teardown_chains(&self, logger: &mut Logger) {
        self.teardown_created(CreatedFirewallState::all(), logger);
    }

    /// Remove exactly the objects flagged in `created`.
    ///
    /// A missing rule/chain only makes the individual `-D`/`-F`/`-X` a no-op,
    /// so this is safe to call on a partially-built state — but the flags still
    /// matter: they keep a rollback from flushing a same-named chain that
    /// belongs to a different container (see [`Self::apply_firewall_rules`]).
    fn teardown_created(&self, created: CreatedFirewallState, logger: &mut Logger) {
        // Remove the hooks (only if we had a veth interface and installed
        // them). Must match the `-i` direction used at insertion so the delete
        // finds the rule; a `-o` delete would silently leak the hook.
        if let Some(ref iface) = self.veth_interface {
            if created.v4_dhcp {
                let _ = Self::run_iptables(
                    &[
                        "-D", "INPUT", "-i", iface, "-p", "udp", "--dport", "67", "-j", "ACCEPT",
                    ],
                    logger,
                );
            }
            if created.v4_hooks {
                for hook in ["FORWARD", "INPUT"] {
                    let _ = Self::run_iptables(
                        &["-D", hook, "-i", iface, "-j", &self.chain_name],
                        logger,
                    );
                }
            }
            if created.v6_dhcp {
                let _ = Self::run_ip6tables(
                    &[
                        "-D", "INPUT", "-i", iface, "-p", "udp", "--dport", "547", "-j", "ACCEPT",
                    ],
                    logger,
                );
            }
            if created.v6_hooks {
                for hook in ["FORWARD", "INPUT"] {
                    let _ = Self::run_ip6tables(
                        &["-D", hook, "-i", iface, "-j", &self.chain_name],
                        logger,
                    );
                }
            }
        }

        // Flush and delete the chains.
        if created.v4_chain {
            let _ = Self::run_iptables(&["-F", &self.chain_name], logger);
            let _ = Self::run_iptables(&["-X", &self.chain_name], logger);
        }
        if created.v6_chain {
            let _ = Self::run_ip6tables(&["-F", &self.chain_name], logger);
            let _ = Self::run_ip6tables(&["-X", &self.chain_name], logger);
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
    fn egress_chain_has_no_conntrack_or_loopback_accept() {
        // The chain is only reached from hooks scoped to `-i <veth>`, so reply
        // traffic never traverses it and the input interface is never `lo`. An
        // ESTABLISHED,RELATED accept would therefore do nothing for replies and
        // would instead let flows opened before the chain existed keep running
        // straight through the deny-all policy.
        let rules = NetworkIptablesManager::build_chain_rules(
            "MXC-test",
            &["10.0.0.5".to_string()],
            &["10.0.0.9".to_string()],
            NetworkPolicy::Block,
            &[],
        );

        for rule in &rules {
            assert!(
                !rule.iter().any(|a| a == "ESTABLISHED,RELATED"
                    || a == "--state"
                    || a == "--ctstate"
                    || a == "lo"),
                "egress chain must not exempt conntrack state or loopback: {rule:?}"
            );
        }
    }

    #[test]
    fn proxy_endpoint_rule_is_followed_by_drop() {
        let endpoints = vec![ProxyEndpoint {
            ip: "10.1.2.3".to_string(),
            port: 8080,
        }];
        let rules = NetworkIptablesManager::build_chain_rules(
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
    fn pin_proxy_refuses_a_tls_addressed_hostname_rather_than_breaking_its_certificate() {
        // Pinning rewrites the host to an IP. For an https-scheme proxy that
        // silently breaks SNI and certificate validation, so the run must be
        // refused with an explanation instead of failing obscurely at connect
        // time inside the container.
        let proxy = proxy_from_url("https://localhost:8443", "localhost", 8443);
        let mut logger = test_logger();

        let result = NetworkIptablesManager::pin_proxy_to_resolved_ip(&proxy, &mut logger);

        let message = result.expect_err("a TLS-addressed proxy hostname must be refused");
        assert!(
            message.contains("localhost"),
            "the error must name the offending host, got: {message}"
        );
        assert!(
            message.contains("IP SAN"),
            "the error must explain why pinning breaks TLS, got: {message}"
        );
    }

    #[test]
    fn pin_proxy_allows_a_tls_proxy_that_is_already_an_ip_literal() {
        // Nothing is rewritten, so whatever certificate the operator
        // provisioned for that literal keeps working.
        let proxy = proxy_from_url("https://127.0.0.1:8443", "127.0.0.1", 8443);
        let mut logger = test_logger();

        let pinned = NetworkIptablesManager::pin_proxy_to_resolved_ip(&proxy, &mut logger)
            .expect("an IP-literal TLS proxy needs no pinning and must be accepted");

        assert_eq!(
            pinned
                .address
                .expect("pinned proxy keeps an address")
                .to_url(),
            "https://127.0.0.1:8443"
        );
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
    fn ordered_egress_rules_put_deny_before_allow() {
        let blocked = vec!["10.0.0.5".to_string()];
        let allowed = vec!["10.0.0.0".to_string()];

        let rules = NetworkIptablesManager::build_chain_rules(
            "MXC-test",
            &blocked,
            &allowed,
            NetworkPolicy::Block,
            &[],
        );

        // Deny first, then the DNS carve-out, then allows, then the default.
        // DNS sits after the deny list so a blocked destination stays blocked
        // even on port 53.
        assert_eq!(
            rules,
            vec![
                vec!["-A", "MXC-test", "-d", "10.0.0.5", "-j", "DROP"],
                vec!["-A", "MXC-test", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
                vec!["-A", "MXC-test", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
                vec!["-A", "MXC-test", "-d", "10.0.0.0", "-j", "ACCEPT"],
                vec!["-A", "MXC-test", "-j", "DROP"],
            ]
        );
    }

    #[test]
    fn proxy_mode_opens_no_dns_port() {
        // Deny-all-except-proxy pins the proxy to a literal address host-side,
        // so the container never needs a resolver and port 53 must stay shut —
        // otherwise the posture carries a standing DNS-tunnel exfil path.
        let rules = NetworkIptablesManager::build_chain_rules(
            "MXC-test",
            &[],
            &[],
            NetworkPolicy::Block,
            &[ProxyEndpoint {
                ip: "10.1.2.3".to_string(),
                port: 3128,
            }],
        );

        assert!(
            !rules.iter().any(|r| r.contains(&"53".to_string())),
            "proxy mode must not open DNS: {rules:?}"
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

        let rules = NetworkIptablesManager::build_chain_rules(
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

    #[test]
    fn rollback_state_starts_empty_so_a_failed_chain_create_touches_nothing() {
        // Chain names are truncated to 20 sanitized characters, so a different
        // live container can already own this name. If `-N` fails because the
        // chain exists, nothing has been created yet and the rollback must be a
        // no-op — otherwise it flushes and deletes the other container's rules.
        let created = CreatedFirewallState::default();

        assert!(!created.v4_chain);
        assert!(!created.v6_chain);
        assert!(!created.v4_hooks);
        assert!(!created.v6_hooks);
        assert!(!created.v4_dhcp);
        assert!(!created.v6_dhcp);
    }

    #[test]
    fn full_teardown_state_covers_every_created_object() {
        // `teardown_chains` (post-success cleanup and `force_cleanup`) must
        // remove everything an apply can install, or cleanup leaks rules.
        let all = CreatedFirewallState::all();

        assert!(all.v4_chain);
        assert!(all.v6_chain);
        assert!(all.v4_hooks);
        assert!(all.v6_hooks);
        assert!(all.v4_dhcp);
        assert!(all.v6_dhcp);
    }
}
