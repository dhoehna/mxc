// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Network policy enforcement via iptables rules scoped to the LXC container.
//!
//! Maps the platform-agnostic `ContainerPolicy` network settings to iptables
//! rules applied to the container's virtual ethernet (veth) interface.

use std::net::ToSocketAddrs;
use std::process::Command;

use wxc_common::logger::Logger;
use wxc_common::models::{ContainerPolicy, NetworkEnforcementMode, NetworkPolicy};

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
        Self {
            chain_name: Self::chain_name_for(container_name),
            rules_applied: false,
            veth_interface: None,
        }
    }

    /// Derive the iptables chain name for a container.
    ///
    /// Two distinct container names should not map to the same chain: a
    /// collision would let one container's teardown flush and delete another's
    /// rules, leaving the incumbent running with no firewall (fail-open).
    /// Sanitizing and truncating the name alone is not enough — two names that
    /// share a prefix (`"web-frontend-1"` / `"web-frontend-2"` past the
    /// truncation point) or differ only in characters the sanitizer strips
    /// (`"a.b"` / `"ab"`) would collapse onto one chain. A deterministic hash of
    /// the **full, unsanitized** name is folded in to break that systematic
    /// collapse. FNV-1a is used rather than the std hasher because its output
    /// must be reproducible across processes (the signal-time `force_cleanup`
    /// rebuilds the manager from the name alone) and across builds.
    ///
    /// This is collision-*resistant*, not injective: the derivation compresses
    /// an unbounded name space into a fixed-width string, so collisions still
    /// exist in principle. The hash width is chosen so that finding one requires
    /// ~2^56.9 work (infeasible to search adversarially) and accidental
    /// collision follows a birthday bound of ~2^28 names. Injectivity over all
    /// inputs is not — and cannot be — guaranteed.
    ///
    /// The result stays within the netfilter chain-name limit (28 characters):
    /// `"MXC-"` (4) + up to 12 sanitized characters + `"-"` (1) + 11 base36
    /// digits. The sanitized allowance is 12 (not 15) so the wider hash fits.
    fn chain_name_for(container_name: &str) -> String {
        let sanitized: String = container_name
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
            .take(12)
            .collect();

        format!("MXC-{}-{}", sanitized, Self::hash_token(container_name))
    }

    /// 64-bit FNV-1a hash of the full container name. Deterministic across
    /// processes and builds so the teardown path can reconstruct the same chain
    /// from the name alone. The full 64 bits are retained — the previous
    /// implementation truncated to the low 32 bits, which collapsed the hash
    /// space and made adversarial chain-name collisions a sub-second brute force.
    fn name_hash(name: &str) -> u64 {
        const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

        let mut hash = FNV_OFFSET;
        for byte in name.bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash
    }

    /// Encode the full 64-bit name hash as a fixed 11-character base36 token
    /// (`0-9a-z`). 36^11 ≈ 2^56.9, so the hash is reduced modulo 36^11 rather
    /// than truncated to 32 bits: this preserves ~56.9 bits of the hash while
    /// fitting the tight length budget shared by the chain name (28 chars) and
    /// the veth interface name (`IFNAMSIZ` = 15 chars). Base36 is valid in both
    /// iptables chain names and Linux interface names. Zero-padded so the token
    /// is always exactly 11 characters, keeping both derived names fixed-width.
    fn hash_token(name: &str) -> String {
        const ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
        // 36^11 = 131_601_804_755_189_760 ≈ 2^56.9, fits in u64.
        const MODULUS: u64 = 36u64.pow(11);

        let mut value = Self::name_hash(name) % MODULUS;
        let mut buf = [b'0'; 11];
        for slot in buf.iter_mut().rev() {
            *slot = ALPHABET[(value % 36) as usize];
            value /= 36;
        }
        // `value` is now 0: 11 base36 digits cover the full [0, 36^11) range.
        String::from_utf8(buf.to_vec()).expect("base36 alphabet is valid ASCII")
    }

    /// Derive the deterministic host-side veth interface name for a container.
    ///
    /// The firewall must be installed *before* the container starts, but the
    /// veth pair liblxc creates by default has a random name that is only known
    /// once the container is running. Pinning `lxc.net.0.veth.pair` to this name
    /// lets the FORWARD hook reference the interface by name ahead of time —
    /// iptables accepts a not-yet-existing interface — so there is no window in
    /// which a started container has unfiltered network.
    ///
    /// The name must fit the kernel `IFNAMSIZ` limit of 15 characters and be
    /// unique per container, so a `mxcv` prefix (4) is followed by the same
    /// 11-character base36 hash token used for the chain name (15 chars total).
    pub fn deterministic_veth_name(container_name: &str) -> String {
        format!("mxcv{}", Self::hash_token(container_name))
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
        let output = Command::new("iptables")
            .args(args)
            .output()
            .map_err(|e| format!("Failed to run iptables: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let msg = format!("iptables {} failed: {}", args.join(" "), stderr);
            logger.log_line(&msg);
            return Err(msg);
        }

        Ok(true)
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
        );
        if !use_firewall {
            logger.log_line("Network enforcement mode does not use firewall, skipping iptables.");
            return Ok(true);
        }

        logger.log_line(&format!("Creating iptables chain: {}", self.chain_name));

        // Create custom chain
        Self::run_iptables(&["-N", &self.chain_name], logger)?;

        // Always allow loopback and established connections
        Self::run_iptables(
            &["-A", &self.chain_name, "-i", "lo", "-j", "ACCEPT"],
            logger,
        )?;
        Self::run_iptables(
            &[
                "-A",
                &self.chain_name,
                "-m",
                "state",
                "--state",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
            logger,
        )?;

        // Allow DNS (needed for hostname resolution)
        Self::run_iptables(
            &[
                "-A",
                &self.chain_name,
                "-p",
                "udp",
                "--dport",
                "53",
                "-j",
                "ACCEPT",
            ],
            logger,
        )?;
        Self::run_iptables(
            &[
                "-A",
                &self.chain_name,
                "-p",
                "tcp",
                "--dport",
                "53",
                "-j",
                "ACCEPT",
            ],
            logger,
        )?;

        // Add allowed host rules
        for host in &policy.allowed_hosts {
            let ips = Self::resolve_host(host);
            if ips.is_empty() {
                logger.log_line(&format!("Warning: could not resolve host '{}'", host));
                continue;
            }
            for ip in &ips {
                logger.log_line(&format!("Allowing host: {} ({})", host, ip));
                Self::run_iptables(&["-A", &self.chain_name, "-d", ip, "-j", "ACCEPT"], logger)?;
            }
        }

        // Add blocked host rules
        for host in &policy.blocked_hosts {
            let ips = Self::resolve_host(host);
            if ips.is_empty() {
                logger.log_line(&format!("Warning: could not resolve host '{}'", host));
                continue;
            }
            for ip in &ips {
                logger.log_line(&format!("Blocking host: {} ({})", host, ip));
                Self::run_iptables(&["-A", &self.chain_name, "-d", ip, "-j", "DROP"], logger)?;
            }
        }

        // Append default policy at end of chain
        let default_action = match policy.default_network_policy {
            NetworkPolicy::Block => "DROP",
            NetworkPolicy::Allow => "ACCEPT",
        };
        logger.log_line(&format!("Default network policy: {}", default_action));
        Self::run_iptables(&["-A", &self.chain_name, "-j", default_action], logger)?;

        // Hook the chain into FORWARD for the container's egress traffic.
        //
        // Packets originating in the container arrive at the host on the
        // host-side veth, so container egress matches FORWARD by *input*
        // interface (`-i`). `-o <veth>` matches traffic flowing the other way,
        // toward the container, which leaves container egress — the thing this
        // policy exists to restrict — entirely unfiltered.
        if let Some(ref iface) = self.veth_interface {
            Self::run_iptables(
                &["-I", "FORWARD", "-i", iface, "-j", &self.chain_name],
                logger,
            )?;
        } else {
            // Without a veth interface, we cannot safely scope rules to the container.
            // Refuse to apply host-wide rules to avoid affecting all host traffic.
            logger.log_line(
                "Warning: No veth interface set for container. \
                 Cannot scope iptables rules. Skipping FORWARD hook.",
            );
        }

        self.rules_applied = true;
        Ok(true)
    }

    /// Remove all iptables rules created by this manager.
    pub fn remove_firewall_rules(&mut self, logger: &mut Logger) -> Result<(), String> {
        if !self.rules_applied {
            return Ok(());
        }

        logger.log_line(&format!("Removing iptables chain: {}", self.chain_name));

        // Remove every FORWARD rule that jumps to this chain, regardless of the
        // interface it was hooked on. The old code deleted only the
        // `-i <veth>` rule it remembered installing, so a teardown that never
        // learned the veth (signal-time force_cleanup, or a veth that was never
        // discovered) left the FORWARD jump behind. Because the chain then
        // stayed referenced, the `-X` below failed too and the whole chain
        // leaked. Enumerating FORWARD and deleting by the `-j <chain>` target
        // removes exactly what was installed.
        self.remove_forward_hooks(logger);

        // Flush and delete the chain
        let _ = Self::run_iptables(&["-F", &self.chain_name], logger);
        let _ = Self::run_iptables(&["-X", &self.chain_name], logger);

        self.rules_applied = false;
        Ok(())
    }

    /// Delete every rule in the FORWARD chain that jumps to this manager's
    /// chain, whatever interface each was scoped to.
    ///
    /// Reads the live ruleset with `iptables -S FORWARD` and issues a matching
    /// `-D` for each jump, so the hook is removed even when the veth is unknown
    /// or was never discovered. If FORWARD cannot be read (no privilege, no
    /// iptables) it is a no-op — there is nothing this process can safely delete
    /// without the ruleset.
    fn remove_forward_hooks(&self, logger: &mut Logger) {
        let output = match Command::new("iptables").args(["-S", "FORWARD"]).output() {
            Ok(o) if o.status.success() => o,
            _ => return,
        };
        let dump = String::from_utf8_lossy(&output.stdout);
        for deletion in Self::forward_hook_deletions(&dump, &self.chain_name) {
            let args: Vec<&str> = deletion.iter().map(String::as_str).collect();
            let _ = Self::run_iptables(&args, logger);
        }
    }

    /// Parse `iptables -S FORWARD` output into a `-D` argument list for every
    /// rule that jumps to `chain`.
    ///
    /// Each `-A FORWARD ... -j <chain>` line becomes the same rule spec with the
    /// leading `-A` swapped for `-D`, so the delete matches the exact rule that
    /// was appended regardless of the `-i`/`-o` interface qualifiers it carries.
    /// Split out from process execution so the matching is testable without
    /// iptables.
    fn forward_hook_deletions(forward_dump: &str, chain: &str) -> Vec<Vec<String>> {
        let mut deletions = Vec::new();
        for line in forward_dump.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.first() != Some(&"-A") || tokens.get(1) != Some(&"FORWARD") {
                continue;
            }
            let jumps_to_chain = tokens.windows(2).any(|w| w[0] == "-j" && w[1] == chain);
            if !jumps_to_chain {
                continue;
            }
            let mut deletion: Vec<String> = tokens.iter().map(|t| t.to_string()).collect();
            deletion[0] = "-D".to_string();
            deletions.push(deletion);
        }
        deletions
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
#[path = "network_iptables_chainname_spec_tests.rs"]
mod chainname_spec_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_name_sanitization() {
        let mgr = NetworkIptablesManager::new("my-container_123");
        // Sanitized-and-truncated prefix (12 chars) plus an 11-char base36
        // disambiguating hash of the full name.
        assert!(
            mgr.chain_name.starts_with("MXC-my-container-"),
            "unexpected chain name: {}",
            mgr.chain_name
        );
        assert_eq!(mgr.chain_name.len(), "MXC-my-container-".len() + 11);
    }

    #[test]
    fn chain_name_truncation() {
        let long_name = "a".repeat(50);
        let mgr = NetworkIptablesManager::new(&long_name);
        // Must stay within the netfilter 28-character chain-name limit:
        // "MXC-" (4) + 12 sanitized + "-" (1) + 11 base36 = 28.
        assert!(
            mgr.chain_name.len() <= 28,
            "chain name too long: {} ({} chars)",
            mgr.chain_name,
            mgr.chain_name.len()
        );
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
    fn regression_previously_colliding_names_now_get_distinct_chains() {
        // TASK-1/TASK-4 REGRESSION: with the 32-bit-truncated hash these two
        // distinct names collided onto a byte-identical chain
        // ("MXC-web-frontend-01-3d4a49a5"), found by brute force after 793,379
        // candidates — a fail-open teardown hazard. With the full-64-bit base36
        // token they must now differ. This assertion fails against the pre-fix
        // code and passes after.
        let a = NetworkIptablesManager::chain_name_for("web-frontend-017m3b");
        let b = NetworkIptablesManager::chain_name_for("web-frontend-01kgar");
        assert_ne!(
            a, b,
            "previously-colliding names must now produce distinct chains; \
             both produced {a:?}"
        );
    }
}
