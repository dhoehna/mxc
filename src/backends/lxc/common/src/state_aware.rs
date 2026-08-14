// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! State-aware lifecycle implementation for the LXC backend.
//!
//! LXC keeps the durable sandbox state in the named container. Provision creates
//! the container, start applies mount/network policy and starts it, exec reuses
//! the one-shot `lxc-attach` PTY path, stop stops the container, and
//! deprovision destroys it plus any remaining iptables state.

use std::time::Duration;

use serde::Serialize;

use wxc_common::id::mint_random_token;
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{
    ContainerPolicy, ExecutionRequest, LxcConfig, NetworkEnforcementMode, NetworkPolicy,
};
use wxc_common::mxc_error::MxcError;
use wxc_common::state_aware_backend::{
    null_pipe_handle, DeprovisionResult, ExecConsumer, ExecHandle, ProvisionResult, StartResult,
    StatefulSandboxBackend, StopResult,
};

use crate::filesystem_mounts;
use crate::lxc_bindings::{mint_exec_marker, LxcContainer};
use crate::network_ingress::IngressManager;
use crate::network_iptables::{CreatedResources, NetworkIptablesManager};
use crate::signal_cleanup;

/// Stateless state-aware LXC runner.
pub struct LxcStateAwareRunner;

impl LxcStateAwareRunner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LxcStateAwareRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// Provision-phase metadata for diagnostics and caller cleanup visibility.
#[derive(Debug, Clone, Serialize)]
pub struct LxcProvisionMetadata {
    #[serde(rename = "containerName")]
    pub container_name: String,
    pub created: bool,
}

/// Parses the `lxc:<containerName>` sandbox_id form and returns the container
/// name segment.
fn extract_container_name(sandbox_id: &str) -> Result<&str, MxcError> {
    let prefix = <LxcStateAwareRunner as StatefulSandboxBackend>::ID_PREFIX;
    match sandbox_id.split_once(':') {
        Some((p, rest)) if p == prefix && is_valid_container_name(rest) => Ok(rest),
        _ => Err(MxcError::malformed_id(format!(
            "expected {}:<containerName>, got {:?}",
            prefix, sandbox_id
        ))),
    }
}

/// Maximum LXC sandbox container-name length.
///
/// Bounds a sandbox container name to a sane length and character set so the
/// name is well-formed for LXC and for the derived iptables chain name. The
/// bound is input hygiene, and on the state-aware path it is also the only
/// thing narrowing the set of names that reach chain derivation.
///
/// It does not make chain names unique. `NetworkIptablesManager` folds a
/// deterministic hash of the full container name into the chain name, which
/// breaks the systematic collapse of shared prefixes, but that derivation is
/// non-cryptographic and not injective — distinct names can still map to one
/// chain, and a caller that chooses `containerId` can construct such a pair.
/// See `NetworkIptablesManager::chain_name_for` for the work factor. A
/// collision lets one container's stop/deprovision tear down another
/// container's rules, leaving the incumbent running with no firewall. The
/// durable fix is persisted chain ownership verified before any flush or
/// delete, not a wider hash; tracked in AB#62953349.
const MAX_CONTAINER_NAME_LEN: usize = 20;

/// Returns whether `name` is a valid LXC sandbox container name: non-empty, at
/// most [`MAX_CONTAINER_NAME_LEN`] characters, and restricted to ASCII
/// alphanumerics, `-`, and `_`.
///
/// The character set keeps the name well-formed for LXC and for the derived
/// iptables chain name. `'.'` is intentionally excluded because it is stripped
/// by the chain-name sanitizer; the chain hash guards against collisions
/// regardless, but rejecting it up front keeps the sandbox id readable.
fn is_valid_container_name(name: &str) -> bool {
    // Valid characters are ASCII (one byte each), so the byte length reported
    // by `str::len` equals the character count for any otherwise-valid name.
    !name.is_empty()
        && name.len() <= MAX_CONTAINER_NAME_LEN
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

/// Where a container name came from.
///
/// Provision has to tell the two apart.  A caller-supplied name that already
/// exists is adopted on purpose, so provisioning the same named sandbox twice
/// is idempotent.  A name MXC minted and that already exists is a collision:
/// the token is 32 bits, so adopting it would silently hand the caller a
/// container somebody else is already using.
enum ContainerName {
    Supplied(String),
    Minted(String),
}

fn resolve_container_name(request: &ExecutionRequest) -> Result<ContainerName, MxcError> {
    if request.container_id.is_empty() {
        return Ok(ContainerName::Minted(format!(
            "mxc-{}",
            mint_random_token()
        )));
    }
    if is_valid_container_name(&request.container_id) {
        Ok(ContainerName::Supplied(request.container_id.clone()))
    } else {
        Err(MxcError::malformed_request(format!(
            "containerId contains characters that are not valid for an LXC sandbox id: {:?}",
            request.container_id
        )))
    }
}

/// Number of names `mint_unused_container_name` will try before giving up.
///
/// The token is 32 bits, so a single collision is already unlikely and eight
/// consecutive ones are not something a healthy host produces.  The bound
/// exists so a host that answers "taken" for every name -- a stuck probe, or a
/// `lxc-info` that reports every query as defined -- fails instead of looping.
const NAME_MINT_ATTEMPTS: usize = 8;

/// Re-mint until the name is free, rather than adopting whatever is there.
///
/// `is_taken` is injected so the decision can be tested without an LXC host.
/// A probe that cannot answer propagates: "unknown" must not be read as
/// "free", because that is how a collision becomes an adoption.
///
/// This narrows the collision window but does not close it -- another process
/// can define the name between the probe and the create.  That is the safe
/// direction: `create` fails on a name that now exists, so the caller gets an
/// error rather than someone else's container.
fn mint_unused_container_name(
    first: String,
    mut is_taken: impl FnMut(&str) -> Result<bool, MxcError>,
) -> Result<String, MxcError> {
    let mut candidate = first;
    for _ in 0..NAME_MINT_ATTEMPTS {
        if !is_taken(&candidate)? {
            return Ok(candidate);
        }
        candidate = format!("mxc-{}", mint_random_token());
    }
    Err(MxcError::backend_error(format!(
        "Could not mint an unused LXC container name in {NAME_MINT_ATTEMPTS} attempts; \
         the last candidate {candidate:?} was already defined"
    )))
}

fn validate_lxc_config(config: Option<&LxcConfig>) -> Result<(), MxcError> {
    let Some(config) = config else {
        return Err(MxcError::malformed_request(
            "experimental.lxc.provision with distribution and release is required",
        ));
    };
    if config.distribution.is_empty() || config.release.is_empty() {
        return Err(MxcError::malformed_request(
            "LXC distribution and release are required",
        ));
    }
    Ok(())
}

/// Map a container state-probe failure onto a backend error.
///
/// Every phase asks whether the container exists or is running before deciding
/// to create, start, stop, or unfilter it.  An unreadable answer is a backend
/// failure, never a licence to assume whichever value is convenient -- assuming
/// "gone" or "stopped" is what turns a broken probe into an unfiltered running
/// container.
fn probe_failed(question: &str, container_name: &str, detail: String) -> MxcError {
    MxcError::backend_error(format!(
        "Failed to determine whether LXC container {container_name:?} {question}: {detail}"
    ))
}

fn has_filesystem_policy(policy: &ContainerPolicy) -> bool {
    !policy.readwrite_paths.is_empty()
        || !policy.readonly_paths.is_empty()
        || !policy.denied_paths.is_empty()
}

fn has_network_policy(policy: &ContainerPolicy) -> bool {
    // `network_specified` is the outermost bit: it is true for any `network`
    // block at all, including an empty one and one that only sets
    // `allowLocalNetwork: false`. The narrower bits below cannot see those --
    // both produce a policy indistinguishable from the struct default -- so a
    // phase that documents "no network section" would otherwise accept one.
    policy.network_specified
        || matches!(
            policy.network_enforcement_mode,
            NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
        )
        || !policy.allowed_hosts.is_empty()
        || !policy.blocked_hosts.is_empty()
        || policy.allow_local_network
        || policy.network_proxy.is_enabled()
        || policy.default_network_policy_present
}

/// Whether `policy` expresses a network restriction that LXC can only deliver
/// through iptables.
///
/// LXC has no capability-based network enforcement, so under
/// `NetworkEnforcementMode::Capabilities` — the default when `enforcementMode`
/// is omitted — `apply_firewall_rules` returns a successful no-op. Any
/// restriction expressed here would therefore be silently unenforced, so the
/// caller rejects the start rather than run fail-open.
///
/// An explicit `defaultPolicy: "block"` counts as a restriction. The wire
/// carries the distinction as `Option<NetworkPolicy>`; the parser records it in
/// `default_network_policy_present`, so a requested default-deny is
/// distinguishable from the struct default a policy-free start produces. A
/// requested default of `Allow`, and the absent case (`default_network_policy`
/// left at its `Block` default without the presence bit), do not require
/// enforcement — the latter is exactly the plain start in
/// `run_lxc_state_aware_test.sh`, which must not be rejected.
fn requires_firewall_enforcement(policy: &ContainerPolicy) -> bool {
    !policy.allowed_hosts.is_empty()
        || !policy.blocked_hosts.is_empty()
        || (policy.default_network_policy_present
            && policy.default_network_policy == NetworkPolicy::Block)
}

fn uses_firewall_mode(policy: &ContainerPolicy) -> bool {
    matches!(
        policy.network_enforcement_mode,
        NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
    )
}

fn reject_start_policy_on_other_phase(
    phase: &str,
    policy: &ContainerPolicy,
) -> Result<(), MxcError> {
    if has_filesystem_policy(policy) || has_network_policy(policy) {
        return Err(MxcError::policy_validation(format!(
            "LXC state-aware {phase} does not accept filesystem or network policy; pass it to start"
        )));
    }
    Ok(())
}

fn normalized_policy(
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<ContainerPolicy, MxcError> {
    let policy =
        match wxc_common::filesystem_object::normalize_object_conflicts(&request.policy, logger) {
            Ok(Some(policy)) => policy,
            Ok(None) => request.policy.clone(),
            Err(msg) => return Err(MxcError::policy_validation(msg)),
        };

    wxc_common::filesystem_access::check_delegation(&policy)
        .map_err(MxcError::policy_validation)?;
    Ok(policy)
}

fn apply_filesystem_policy(
    container: &LxcContainer,
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<(), MxcError> {
    let policy = normalized_policy(request, logger)?;
    filesystem_mounts::configure_filesystem_mounts(container, &policy, logger)
        .map_err(|e| MxcError::policy_validation(format!("Failed to configure filesystem: {e}")))
}

/// The network rejections that depend on the requested policy alone.
///
/// Split out of `apply_network_policy` so `validate_start` can reach the same
/// verdict without a container. A dry run stops after `validate_start`
/// (`state_aware_dispatch.rs`, `Phase::Start`), so anything checked only inside
/// the apply path is invisible to it -- and a dry run that answers "this start
/// is fine" for a policy the real start refuses is worse than no dry run, since
/// the caller has asked precisely that question and been told the wrong answer.
fn reject_unenforceable_network_policy(policy: &ContainerPolicy) -> Result<(), MxcError> {
    if policy.network_proxy.is_enabled() {
        return Err(MxcError::policy_validation(
            "LXC state-aware start does not support network.proxy",
        ));
    }

    // `IngressManager` refuses this, but only once it is invoked, and it is
    // invoked only in a firewall mode. With `enforcementMode` omitted both
    // managers take their no-op paths, so without this the start reports
    // success and the container gets unrestricted inbound traffic -- broader
    // than the local-network access that was asked for. Rejecting before mode
    // dispatch also means a dry run gives the same verdict as a real start.
    if policy.allow_local_network {
        return Err(MxcError::policy_validation(
            "LXC state-aware start does not support network.allowLocalNetwork: the container's \
             inbound chain can only open a source range, and opening every source is broader \
             than the local-network access requested. See microsoft/mxc AB#63505947.",
        ));
    }

    // Reject a policy this backend cannot enforce, rather than reporting a
    // successful start that silently leaves the container unfiltered. LXC
    // enforces network policy only through iptables, and `apply_firewall_rules`
    // treats any non-firewall mode as a successful no-op.
    if requires_firewall_enforcement(policy) && !uses_firewall_mode(policy) {
        return Err(MxcError::policy_validation(format!(
            "LXC state-aware start cannot enforce this network policy under \
             enforcementMode {:?}: LXC has no capability-based network enforcement, \
             so allowedHosts/blockedHosts would be silently unenforced and an explicit \
             defaultPolicy 'block' would not be applied. \
             Use enforcementMode 'firewall' or 'both'.",
            policy.network_enforcement_mode
        )));
    }
    Ok(())
}

/// Every start rejection that needs only the request, in the order the real
/// start reaches them: filesystem normalization first (`apply_filesystem_policy`
/// runs before `apply_network_policy`), then the network verdicts. Keeping the
/// order means a dry run reports the same error the real start would, not merely
/// some error.
fn validate_start_policy(request: &ExecutionRequest) -> Result<(), MxcError> {
    let mut logger = Logger::new(Mode::Buffer);
    let policy = normalized_policy(request, &mut logger)?;
    reject_unenforceable_network_policy(&policy)
}

/// Apply the network policy, returning the record of what it installed.
///
/// The record is what lets the caller undo exactly this attempt if the start
/// then fails, without touching a chain that a concurrent start owns. An
/// enforcement-free policy installs nothing and returns an empty record.
fn apply_network_policy(
    container: &LxcContainer,
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<CreatedResources, MxcError> {
    reject_unenforceable_network_policy(&request.policy)?;

    let policy = normalized_policy(request, logger)?;

    let mut fw_manager = NetworkIptablesManager::new(container.name());

    // Under a firewall-enforced policy, pin a deterministic host-side veth name
    // in the container config so the chain and its FORWARD hook can be built
    // *before* the container runs. The prior flow discovered the veth only after
    // start and applied rules afterward, leaving a window in which a container
    // with a deny policy had unrestricted network. iptables accepts an interface
    // name that does not exist yet, so hooking the not-yet-created veth by its
    // pinned name closes that window entirely.
    if uses_firewall_mode(&policy) {
        // Only lxc.net.0 gets a pinned veth, and apply_firewall_rules hooks
        // exactly one interface. A container this run created has exactly that
        // one interface, but provision also adopts containers it did not create,
        // and an adopted one can carry lxc.net.1 and beyond. Those would keep
        // routing while start reported that a deny policy had been applied —
        // the policy would be a claim rather than a control. Refuse instead:
        // failing closed on a config MXC cannot fully enforce is the only
        // honest answer, and hooking every interface is the follow-up.
        let net = container
            .configured_net_interfaces()
            .map_err(|e| MxcError::backend_error(format!("Failed to read network config: {e}")))?;

        // An include can declare interfaces this config never mentions, so the
        // count above is a lower bound rather than an answer. Refusing is not
        // pedantry: accepting would mean enforcing on one interface and
        // reporting success for a container that may route around it.
        if net.has_include {
            return Err(MxcError::policy_validation(format!(
                "Container {:?} uses lxc.include, so its full set of network interfaces \
                 cannot be determined from its own config; a firewall-enforced network \
                 policy cannot be guaranteed to cover every interface and is refused. \
                 Inline the included network configuration, or run without firewall \
                 enforcement",
                container.name()
            )));
        }
        if net.indices.len() > 1 {
            return Err(MxcError::policy_validation(format!(
                "Container {:?} has {} configured network interfaces (lxc.net.{}); \
                 a firewall-enforced network policy can only be applied to a container \
                 with a single interface, because traffic on the others would bypass it",
                container.name(),
                net.indices.len(),
                net.indices
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(", lxc.net."),
            )));
        }
        // Zero is refused for the mirror-image reason. There is no interface to
        // pin or hook, so pinning lxc.net.0.veth.pair would write a property for
        // an interface that does not exist and the run would either fail later
        // or install a chain nothing routes through. Either way the caller asked
        // for enforced networking on a container that has no network to enforce.
        if net.indices.is_empty() {
            return Err(MxcError::policy_validation(format!(
                "Container {:?} has no configured network interface (no lxc.net.N entries), \
                 so a firewall-enforced network policy has nothing to attach to",
                container.name()
            )));
        }

        // Exactly one interface is necessary but not sufficient -- it also has
        // to be the one everything downstream assumes. The pin below, the veth
        // name, and the FORWARD hook are all written against `lxc.net.0`, so a
        // container whose single interface sits at another index would get a
        // chain built against an interface it never uses, while MXC reported the
        // policy as enforced.
        let index = net.indices[0];
        if index != 0 {
            return Err(MxcError::policy_validation(format!(
                "Container {:?} configures its only network interface at lxc.net.{} rather \
                 than lxc.net.0; a firewall-enforced network policy is pinned to lxc.net.0 \
                 and would not cover it. Renumber the interface to lxc.net.0, or run without \
                 firewall enforcement",
                container.name(),
                index,
            )));
        }

        // Same assumption, the other half. Enforcement works by naming the host
        // end of a veth pair and hooking that name in FORWARD, so the interface
        // has to actually be a veth. A macvlan or phys interface at index 0
        // satisfies every check above and then gets a hook pinned to a veth name
        // that will never exist, while its traffic uses the real interface
        // unfiltered. An undeclared type is refused for the same reason: it is
        // not evidence of a veth.
        match net.types.get(&index).map(String::as_str) {
            Some("veth") => {}
            Some(other) => {
                return Err(MxcError::policy_validation(format!(
                    "Container {:?} configures lxc.net.0.type = {:?}; a firewall-enforced \
                     network policy can only be applied to a veth interface, because \
                     enforcement pins the host end of the veth pair and hooks that name in \
                     FORWARD. Use a veth interface, or run without firewall enforcement",
                    container.name(),
                    other,
                )));
            }
            None => {
                return Err(MxcError::policy_validation(format!(
                    "Container {:?} does not declare lxc.net.0.type; a firewall-enforced \
                     network policy can only be applied to a declared veth interface, because \
                     enforcement pins the host end of the veth pair and hooks that name in \
                     FORWARD. Declare lxc.net.0.type = veth, or run without firewall \
                     enforcement",
                    container.name()
                )));
            }
        }

        let veth = NetworkIptablesManager::deterministic_veth_name(container.name());

        // The name is re-derived on every start, so drop any pin from a prior
        // run before setting it to avoid accumulating duplicate net entries.
        container
            .clear_config_item("lxc.net.0.veth.pair")
            .map_err(|e| MxcError::backend_error(format!("Failed to clear veth pair name: {e}")))?;
        container
            .set_config_item("lxc.net.0.veth.pair", &veth)
            .map_err(|e| MxcError::backend_error(format!("Failed to pin veth pair name: {e}")))?;
        fw_manager.set_veth_interface(&veth);
    }

    match fw_manager.apply_firewall_rules(&policy, logger) {
        Ok(true) => {
            if fw_manager.rules_applied() {
                // Rules must survive after the start phase returns. stop and
                // deprovision call force_cleanup_authoritative to remove this
                // persistent state.
                //
                // Read the ownership record out before forgetting the manager.
                // It is the only surviving evidence of what this attempt
                // installed, and the start path needs it to tear down exactly
                // that much if the container then fails to start.
                let created = fw_manager.created();
                std::mem::forget(fw_manager);
                return Ok(created);
            }
            Ok(CreatedResources::default())
        }
        Ok(false) => Err(MxcError::policy_validation(
            "Failed to apply network firewall rules",
        )),
        Err(e) => {
            // Fail closed: tear down any partially-applied chain so an aborted
            // policy application does not leak iptables state, and let the error
            // propagate so the caller does not start the container unfiltered.
            //
            // Only when this run created the chain, though. The chain name is
            // derived from the container name, so a concurrent start of the same
            // sandbox aims at the same chain and the loser's `iptables -N` fails
            // against the winner's. Cleaning up unconditionally would have the
            // loser delete the winner's chain and hooks, and the winner would
            // then start its container with nothing filtering it — turning a
            // recoverable collision into a fail-open.
            if fw_manager.owns_resources() {
                // Tear down through the manager that created the chain, not a
                // fresh one. `Drop` re-runs the teardown whenever
                // `chain_created` is still set, and a fresh manager cannot clear
                // that flag on the original -- so cleaning up any other way
                // leaves this function returning into a second teardown of a
                // chain it has already deleted. Between the two, another start
                // can create the same deterministic chain name and install its
                // rules, and the trailing teardown would then strip the new
                // owner's hooks and delete its chain, leaving *its* container
                // running unfiltered.
                //
                // Going through `fw_manager` clears `chain_created` on a
                // successful `-X`, so the drop is a no-op; when `-X` fails the
                // flag stays set and the drop is the retry it is there to be.
                // It also knows the pinned veth, which a fresh manager does not.
                let _ = fw_manager.remove_firewall_rules(logger);
                return Err(MxcError::policy_validation(format!(
                    "Network policy error: {e}"
                )));
            }
            // Nothing was created, so nothing is removed. Say so explicitly:
            // the chain existing without this run creating it means either a
            // concurrent start holds it or a previous run left it behind, and
            // the two are indistinguishable from iptables alone until ownership
            // is persisted (AB#62953349). Both are cleared the same way, so name
            // the remedy rather than leaving the caller to guess.
            Err(MxcError::policy_validation(format!(
                "Network policy error: could not create the firewall chain for container {:?}, \
                 so no rules were applied and none were removed. Its chain already exists, \
                 which means another start of this sandbox is in progress or an earlier run \
                 left it behind; stop or deprovision the sandbox to clear it, then start again. \
                 Underlying error: {e}",
                container.name()
            )))
        }
    }
}

/// Best-effort teardown of iptables state this process installed.
///
/// `veth` is the host-side veth interface name when it is known. Teardown no
/// longer needs it to find the FORWARD hooks — those are located by
/// enumerating the live FORWARD chain and matching the `-j <chain>` target —
/// but it is still passed through for logging and for the callers that
/// discovered it while the container was running.
///
/// `created` is the ownership record: only the chains and hooks named in it are
/// removed, so a process that created nothing removes nothing. Use this from
/// the start path, which knows what it installed.
/// Install the container's inbound default-deny chain, failing closed.
///
/// The egress chain is installed *before* the container runs, because iptables
/// accepts a veth name that does not exist yet. Ingress cannot work that way:
/// the chain lives inside the container's **own** network namespace, which does
/// not exist until the container starts, so this necessarily runs afterwards.
/// The one-shot path orders it the same way for the same reason.
///
/// Without this the state-aware path enforced only half the network policy.
/// `allowLocalNetwork` defaults to false, so a container started here accepted
/// inbound connections from the host and the LAN while MXC reported the policy
/// as enforced -- egress filtered, ingress wide open. `IngressManager` also
/// refuses `allowLocalNetwork: true` outright rather than installing an
/// over-broad accept, so wiring it in is what makes that value honored or
/// refused instead of silently ignored.
fn apply_ingress_policy(
    container: &LxcContainer,
    container_name: &str,
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<(), MxcError> {
    let policy = normalized_policy(request, logger)?;

    let Some(pid) = container.init_pid() else {
        if uses_firewall_mode(&policy) {
            // Enforcing inbound means entering the container's netns, and the
            // init PID is the only handle on it. Continuing would silently drop
            // the requested deny, so refuse the start instead.
            return Err(MxcError::backend_error(
                "Failed to discover the container init PID; cannot enter the container \
                 network namespace to enforce the inbound network policy",
            ));
        }
        return Ok(());
    };

    let mut manager = IngressManager::new(container_name, pid);
    let applied = manager
        .apply_firewall_rules(&policy, logger)
        .map_err(|e| MxcError::backend_error(format!("Inbound network policy error: {e}")))?;
    if !applied {
        return Err(MxcError::backend_error(
            "Failed to apply inbound network firewall rules",
        ));
    }

    // The container outlives this call, so its rules must too. `Drop` otherwise
    // tears them down on the way out of this function, undoing the install this
    // function exists to perform.
    manager.set_preserve_policy(true);
    Ok(())
}

fn cleanup_network_owned(
    container_name: &str,
    veth: Option<&str>,
    created: CreatedResources,
    logger: &mut Logger,
) {
    NetworkIptablesManager::force_cleanup(container_name, veth, created, logger);
}

/// Teardown of whatever iptables state exists for a container, whichever
/// process installed it.
///
/// For `stop` and `deprovision` only. They run in a different process from the
/// `start` that created the chain, so they hold no ownership record and an
/// ownership-gated teardown would silently do nothing — stranding the chain and
/// blocking every later start, which fails on a chain it did not create. Both
/// callers have already stopped or destroyed the container by this point, so
/// nothing is left for the chain to protect. See
/// `NetworkIptablesManager::force_cleanup_authoritative` for the full argument.
///
/// A failure is reported rather than swallowed. Discarding it made stop and
/// deprovision answer success over a chain that survived them, which is the
/// one outcome the caller has to know about: the stranded chain blocks every
/// later start of that container name.
fn cleanup_network_authoritative(
    container_name: &str,
    veth: Option<&str>,
    logger: &mut Logger,
) -> Result<(), MxcError> {
    NetworkIptablesManager::force_cleanup_authoritative(container_name, veth, logger).map_err(|e| {
        MxcError::backend_error(format!(
            "Failed to remove the network filtering state for LXC container {container_name:?}; \
             it is still installed and will block a later start: {e}"
        ))
    })
}

/// Advisory lock that makes each state transition one critical section per
/// sandbox.
///
/// `start` reads whether the container is running and then, if it is not,
/// writes filesystem policy, installs the firewall, and starts it.  Nothing
/// held the container still in between, so two concurrent starts both read
/// "not running" and both take the else arm.  Both then write policy: the
/// container that comes up can be running behind the other start's mounts, and
/// the `already_started` refusal — whose whole job is to stop start policy
/// being reapplied to a live container — never fires.  The loser gets `Ok`,
/// not the error the guard exists to produce.
///
/// `stop` and `deprovision` have to take the same lock, because excluding only
/// a second start leaves the worse race open: a concurrent stop reads "not
/// running" in the window after a start installs its FORWARD chain and before
/// `container.start()`, runs the authoritative network teardown, and removes
/// the chain.  The start then brings the container up with no egress filter at
/// all.  Teardown is only safely ordered against a running container if no
/// start can be part-way through one.
///
/// `exec` deliberately stays out.  It installs and removes no host state, so it
/// cannot produce that fail-open, and an exclusive lock there would serialize
/// concurrent execs into one sandbox, which is a supported thing to do.  Every
/// other phase takes it: `provision` because minting probes for an unused name
/// and then creates it, which is the same shape of race.
///
/// The lock file lives in the LXC root rather than in the container directory
/// because `deprovision` destroys that directory: a lock file inside it would
/// be unlinked while still held, and the next phase would create a fresh file
/// and take a *different* lock, which is no lock at all.  Container names are
/// validated for length and character set before they reach this, so the name
/// cannot escape the root.  `flock` is released by the kernel when the
/// descriptor closes, so a phase that dies mid-sequence frees it; an `O_EXCL`
/// lock file would instead wedge every later phase of that container name.
struct LifecycleLock {
    /// Held for its `Drop`, which is what releases the lock.  `None` when the
    /// LXC root does not exist; see `acquire`.
    #[cfg(target_os = "linux")]
    _guard: Option<nix::fcntl::Flock<std::fs::File>>,
}

/// How many times `acquire` will re-take a lock whose file was replaced under
/// it before giving up.
///
/// Each retry costs one open and one `flock`, and the only thing that triggers
/// one is a `deprovision` reclaiming the file, so the bound exists to stop an
/// adversary spinning the loop rather than to absorb ordinary contention.
/// Exhausting it refuses the phase, which is the safe direction.
#[cfg(target_os = "linux")]
const LOCK_ACQUIRE_ATTEMPTS: usize = 8;

impl LifecycleLock {
    /// Where the lock file for `container_name` lives.
    ///
    /// One function so `acquire` and `release_and_reclaim` cannot drift: a
    /// reclaim that computed a different path would unlink a file nobody holds
    /// and leave the real one behind.
    #[cfg(target_os = "linux")]
    fn lock_path(container: &LxcContainer, container_name: &str) -> String {
        format!(
            "{}/.mxc-lifecycle-{}.lock",
            container.lxc_path(),
            container_name
        )
    }

    /// Take the lock, waiting for any concurrent transition of the same sandbox.
    ///
    /// Off Linux there is no LXC to serialize, so this is a no-op that exists
    /// only so the phases read the same on every target.
    fn acquire(container: &LxcContainer, container_name: &str) -> Result<Self, MxcError> {
        #[cfg(target_os = "linux")]
        {
            let path = Self::lock_path(container, container_name);
            for _ in 0..LOCK_ACQUIRE_ATTEMPTS {
                let file = match std::fs::OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .write(true)
                    .open(&path)
                {
                    Ok(file) => file,
                    // No LXC root means no container directory under it, so
                    // nothing has passed the `is_defined` gate that every start
                    // clears before it touches host state — there is no
                    // transition to be serialized against. `stop` and
                    // `deprovision` are required to be idempotent, and refusing
                    // them here would make cleanup on a host that never had LXC
                    // an error. Any other failure, permission in particular,
                    // still refuses the phase.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(LifecycleLock { _guard: None })
                    }
                    Err(e) => {
                        return Err(MxcError::backend_error(format!(
                            "Failed to open the lifecycle lock for LXC container \
                             {container_name:?} at {path}: {e}"
                        )))
                    }
                };
                let guard = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive)
                    .map_err(|(_, errno)| {
                        MxcError::backend_error(format!(
                            "Failed to take the lifecycle lock for LXC container \
                             {container_name:?}: {errno}"
                        ))
                    })?;
                if Self::path_still_names(&guard, &path) {
                    return Ok(LifecycleLock {
                        _guard: Some(guard),
                    });
                }
                // A `deprovision` reclaimed the file between the open and the
                // lock, so this lock is on an inode nobody else can reach --
                // which excludes nobody. Drop it and take the current one.
                drop(guard);
            }
            Err(MxcError::backend_error(format!(
                "Failed to take the lifecycle lock for LXC container {container_name:?}: the lock \
                 file at {path} was replaced on every one of {LOCK_ACQUIRE_ATTEMPTS} attempts"
            )))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (container, container_name);
            Ok(LifecycleLock {})
        }
    }

    /// Whether `path` still names the inode `guard` holds a lock on.
    ///
    /// `flock` follows the open descriptor, not the name, so a lock taken on a
    /// file that has since been unlinked excludes nothing: the next phase
    /// creates a fresh file at the same path and locks that instead.  The
    /// inode is what makes the two distinguishable.
    ///
    /// Any error reading either side answers `false`, which costs a retry and
    /// eventually refuses the phase.  Answering `true` on an unreadable path
    /// would hand out a lock that excludes nothing.
    #[cfg(target_os = "linux")]
    fn path_still_names(guard: &nix::fcntl::Flock<std::fs::File>, path: &str) -> bool {
        use std::os::unix::fs::MetadataExt;

        let (Ok(locked), Ok(named)) = (guard.metadata(), std::fs::metadata(path)) else {
            return false;
        };
        locked.ino() == named.ino() && locked.dev() == named.dev()
    }

    /// Release the lock and remove its file.
    ///
    /// Only the terminal phase may call this, and only once the container is
    /// gone: the file is a permanent inode per sandbox name otherwise, and a
    /// host that provisions many short-lived sandboxes accumulates one for
    /// every name it ever used.
    ///
    /// The unlink happens while the lock is still held, so no other phase can
    /// be between its own open and its own `flock` and reach a state this did
    /// not create.  A phase that is already blocked on the lock wakes holding
    /// the now-unlinked inode, sees the path no longer names it, and retakes
    /// the current one; see `path_still_names`.
    ///
    /// A failed unlink is not reported.  The container is already destroyed by
    /// this point, so an error here would fail a `deprovision` that did
    /// everything it was asked to, and the only consequence is the zero-byte
    /// file this was trying to reclaim.
    fn release_and_reclaim(self, container: &LxcContainer, container_name: &str) {
        #[cfg(target_os = "linux")]
        {
            if self._guard.is_some() {
                let _ = std::fs::remove_file(Self::lock_path(container, container_name));
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (container, container_name);
        }
        // `self` is consumed, so the lock releases here -- after the unlink,
        // which is the order that matters.
    }
}

impl StatefulSandboxBackend for LxcStateAwareRunner {
    const ID_PREFIX: &'static str = "lxc";
    const BACKEND_KEY: &'static str = "lxc";

    type ProvisionConfig = LxcConfig;
    type StartConfig = ();
    type ExecConfig = ();
    type StopConfig = ();
    type DeprovisionConfig = ();
    type ProvisionMetadata = LxcProvisionMetadata;
    type StartMetadata = ();
    type StopMetadata = ();
    type DeprovisionMetadata = ();

    fn provision(
        &mut self,
        request: &ExecutionRequest,
        config: Option<LxcConfig>,
    ) -> Result<ProvisionResult<LxcProvisionMetadata>, MxcError> {
        validate_lxc_config(config.as_ref())?;
        reject_start_policy_on_other_phase("provision", &request.policy)?;

        let config = config.expect("validated above");
        let container_name = match resolve_container_name(request)? {
            ContainerName::Supplied(name) => name,
            ContainerName::Minted(first) => mint_unused_container_name(first, |candidate| {
                LxcContainer::new(candidate, None)
                    .is_defined()
                    .map_err(|e| probe_failed("exists", candidate, e))
            })?,
        };
        let container = LxcContainer::new(&container_name, None);
        // Same lock the other phases take. Minting probes for an unused name
        // and then creates it, so without this two provisions that mint the
        // same name both see it free and both create; and a supplied name can
        // race the same way. Holding the lock across the probe and the create
        // makes the loser adopt, which is what a second provision of a name
        // that already exists is supposed to do.
        let _lifecycle_lock = LifecycleLock::acquire(&container, &container_name)?;
        let created = !container
            .is_defined()
            .map_err(|e| probe_failed("exists", &container_name, e))?;
        if created {
            container
                .create(&config.distribution, &config.release)
                .map_err(|e| MxcError::backend_error(format!("Failed to create container: {e}")))?;
        }

        Ok(ProvisionResult {
            sandbox_id: format!("{}:{}", Self::ID_PREFIX, container_name),
            metadata: Some(LxcProvisionMetadata {
                container_name,
                created,
            }),
        })
    }

    fn start(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<StartResult<()>, MxcError> {
        let container_name = extract_container_name(sandbox_id)?;
        let container = LxcContainer::new(container_name, None);
        // Hold the sandbox still for the whole phase: the running/not-running
        // decision below and the policy writes that depend on it have to be one
        // critical section, or a second start slips past the `already_started`
        // refusal and applies its policy to a container the first one is
        // bringing up — and a concurrent stop tears this start's firewall back
        // off between installing it and running the container.
        let _lifecycle_lock = LifecycleLock::acquire(&container, container_name)?;
        if !container
            .is_defined()
            .map_err(|e| probe_failed("exists", container_name, e))?
        {
            return Err(MxcError::not_provisioned(format!(
                "LXC container {:?} is not provisioned",
                container_name
            )));
        }
        let mut logger = Logger::new(Mode::Buffer);
        if container
            .is_running()
            .map_err(|e| probe_failed("is running", container_name, e))?
        {
            if has_filesystem_policy(&request.policy) || has_network_policy(&request.policy) {
                return Err(MxcError::already_started(
                    "LXC container is already running; start policy cannot be reapplied",
                ));
            }
        } else {
            apply_filesystem_policy(&container, request, &mut logger)?;
            // Install the firewall *before* the container is allowed to run.
            // Applying it after start left a roughly 10-second window in which a
            // container with a deny policy had unrestricted network. A
            // firewall-install failure aborts the start (fail closed) rather
            // than proceeding unfiltered.
            //
            // Register a signal rollback across that same window first. The
            // chain is host state that outlives this process, so a SIGTERM
            // between installing it and finishing the start would strand it with
            // nobody to remove it. `set_active_network_only` is deliberately not
            // the one-shot `set_active`: this container is provisioned and must
            // survive, so only the firewall is rolled back.
            signal_cleanup::set_active_network_only(container_name);
            let installed = match apply_network_policy(&container, request, &mut logger) {
                Ok(created) => created,
                Err(e) => {
                    // Clear before returning. apply_network_policy already removed
                    // whatever it created, and when it failed because another start
                    // owns the chain it deliberately removed nothing — a signal
                    // arriving now would otherwise delete that owner's chain and
                    // leave its container running unfiltered.
                    signal_cleanup::clear_active();
                    return Err(e);
                }
            };
            if let Err(e) = container.start() {
                // The firewall is already installed; tear it down so an aborted
                // start does not leak iptables state. The veth never came up, so
                // no interface-scoped discovery is needed — the FORWARD hooks are
                // found by enumerating on the chain name.
                //
                // Ownership-scoped, not authoritative: `apply_network_policy` may
                // have installed nothing, and a chain present without this attempt
                // creating it belongs to a concurrent start whose container is
                // running behind it.
                cleanup_network_owned(container_name, None, installed, &mut logger);
                signal_cleanup::clear_active();
                return Err(MxcError::backend_error(format!(
                    "Failed to start container: {e}"
                )));
            }
            // Inbound enforcement lands only once the container's network
            // namespace exists, so unlike the egress chain it comes after start.
            if let Err(e) = apply_ingress_policy(&container, container_name, request, &mut logger) {
                // The container is up and its inbound deny is not in force, so
                // leaving it running is exactly the fail-open this guard exists
                // to prevent. Discover the veth while the container still has
                // one, then stop it -- which also discards the netns holding any
                // partial ingress chain -- and remove the egress state this
                // start installed.
                let veth = NetworkIptablesManager::discover_veth_interface(container_name);
                let stopped = container.stop();
                signal_cleanup::clear_active();
                if let Err(stop_err) = stopped {
                    // The container is still up, and the egress chain is the
                    // only half of its policy still in force. Removing it now
                    // would turn a half-filtered container into an unfiltered
                    // one, so it stays -- the same trade `stop` makes when it
                    // cannot stop the container, and the same one the signal
                    // rollback makes when its stop fails.
                    return Err(MxcError::backend_error(format!(
                        "{e}; the container could not be stopped afterwards ({stop_err}), so it \
                         is still running and its egress rules were left in place"
                    )));
                }
                cleanup_network_owned(container_name, veth.as_deref(), installed, &mut logger);
                return Err(e);
            }
            // Past this point the chain and the container are both meant to
            // persist, so a signal must not roll either back.
            signal_cleanup::clear_active();
        }
        Ok(StartResult { metadata: None })
    }

    fn exec(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<()>,
        _consumer: ExecConsumer,
    ) -> Result<ExecHandle, MxcError> {
        let container_name = extract_container_name(sandbox_id)?;
        reject_start_policy_on_other_phase("exec", &request.policy)?;

        let container = LxcContainer::new(container_name, None);
        if !container
            .is_defined()
            .map_err(|e| probe_failed("exists", container_name, e))?
        {
            return Err(MxcError::not_provisioned(format!(
                "LXC container {:?} is not provisioned",
                container_name
            )));
        }
        if !container
            .is_running()
            .map_err(|e| probe_failed("is running", container_name, e))?
        {
            return Err(MxcError::not_started(format!(
                "LXC container {:?} is not started",
                container_name
            )));
        }

        let timeout = if request.script_timeout == 0 {
            None
        } else {
            Some(Duration::from_millis(u64::from(request.script_timeout)))
        };

        // Registered for the whole attach, not just the timed part: a signal
        // kills this process without waiting for the timeout, and the container
        // is persistent, so anything the script started would otherwise be
        // inherited by the next exec.
        let marker = mint_exec_marker();
        signal_cleanup::set_active_exec(container_name, &marker);
        let outcome = container.attach_run(
            &request.script_code,
            &request.working_directory,
            &request.env,
            timeout,
            Some(&marker),
        );
        signal_cleanup::clear_active();

        let exit_code = outcome
            .map(|(exit_code, _, _)| exit_code)
            .map_err(|e| MxcError::backend_error(format!("Execution failed: {e}")))?;

        Ok(ExecHandle {
            stdout: null_pipe_handle(),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(move || Ok(exit_code)),
            terminator: Box::new(|| {}),
        })
    }

    fn stop(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<StopResult<()>, MxcError> {
        let container_name = extract_container_name(sandbox_id)?;
        reject_start_policy_on_other_phase("stop", &request.policy)?;

        let container = LxcContainer::new(container_name, None);
        // Same lock the start takes. Without it this teardown can observe a
        // start's container as not running, strip the FORWARD chain that start
        // just installed, and return before it calls `container.start()`,
        // leaving a running container with no egress filtering.
        let _lifecycle_lock = LifecycleLock::acquire(&container, container_name)?;
        if !container
            .is_defined()
            .map_err(|e| probe_failed("exists", container_name, e))?
        {
            return Err(MxcError::not_provisioned(format!(
                "LXC container {:?} is not provisioned",
                container_name
            )));
        }

        let mut logger = Logger::new(Mode::Buffer);
        // Discover the veth while the container is still running; it disappears
        // once stopped, but iptables can still delete a FORWARD rule that names
        // it. Stop the container *before* tearing down its firewall rules so no
        // process runs without egress filtering during the shutdown drain. If
        // the stop fails, propagate the error and leave the rules in place
        // rather than exposing a still-running container.
        let veth = NetworkIptablesManager::discover_veth_interface(container_name);
        if container
            .is_running()
            .map_err(|e| probe_failed("is running", container_name, e))?
        {
            container
                .stop()
                .map_err(|e| MxcError::backend_error(format!("Failed to stop container: {e}")))?;
        }
        cleanup_network_authoritative(container_name, veth.as_deref(), &mut logger)?;
        Ok(StopResult { metadata: None })
    }

    fn deprovision(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<DeprovisionResult<()>, MxcError> {
        let container_name = extract_container_name(sandbox_id)?;
        reject_start_policy_on_other_phase("deprovision", &request.policy)?;

        let mut logger = Logger::new(Mode::Buffer);
        let container = LxcContainer::new(container_name, None);
        // Same lock the start takes, for the same reason as `stop`: this path
        // also runs the authoritative network teardown, and must not do it
        // while a start is between installing the firewall and running the
        // container.
        let _lifecycle_lock = LifecycleLock::acquire(&container, container_name)?;
        // Discover the veth before teardown while the container may still be
        // running; it disappears once destroyed, but iptables can still delete
        // a FORWARD rule that names it.
        let veth = NetworkIptablesManager::discover_veth_interface(container_name); // A probe that could not answer must not be read as "already gone".
                                                                                    // Skipping the destroy and then running the authoritative network
                                                                                    // teardown below would strip filtering from a container that is still
                                                                                    // running, which is the fail-open this ordering exists to prevent. The
                                                                                    // `?` leaves the rules in place and lets the caller retry.
        if container
            .is_defined()
            .map_err(|e| probe_failed("exists", container_name, e))?
        {
            // `destroy` force-stops and removes the container, so once it
            // returns no container process can run. Destroy *before* removing
            // the firewall rules so nothing runs without egress filtering
            // during teardown; if the destroy fails, leave the rules in place.
            container.destroy().map_err(|e| {
                MxcError::backend_error(format!("Failed to destroy container: {e}"))
            })?;
        }
        cleanup_network_authoritative(container_name, veth.as_deref(), &mut logger)?;
        // Terminal phase: the container is gone, so nothing will take this
        // lock for that name again until something creates the container
        // afresh. Reclaim the file rather than leave one zero-byte inode per
        // sandbox name the host ever provisioned.
        _lifecycle_lock.release_and_reclaim(&container, container_name);
        Ok(DeprovisionResult { metadata: None })
    }

    fn validate_provision(
        &self,
        request: &ExecutionRequest,
        config: Option<&LxcConfig>,
    ) -> Result<(), MxcError> {
        validate_lxc_config(config)?;
        resolve_container_name(request)?;
        reject_start_policy_on_other_phase("provision", &request.policy)
    }

    fn validate_start(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        extract_container_name(sandbox_id)?;
        validate_start_policy(request)
    }

    fn validate_exec(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        extract_container_name(sandbox_id)?;
        reject_start_policy_on_other_phase("exec", &request.policy)
    }

    fn validate_stop(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        extract_container_name(sandbox_id)?;
        reject_start_policy_on_other_phase("stop", &request.policy)
    }

    fn validate_deprovision(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        extract_container_name(sandbox_id)?;
        reject_start_policy_on_other_phase("deprovision", &request.policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::LifecycleConfig;
    use wxc_common::models::NetworkPolicy;
    use wxc_common::models::ProxyConfig;
    use wxc_common::mxc_error::MxcErrorCode;

    fn provision_config() -> LxcConfig {
        LxcConfig {
            distribution: "alpine".to_string(),
            release: "3.20".to_string(),
        }
    }

    fn restrictive_policy() -> ContainerPolicy {
        ContainerPolicy {
            blocked_hosts: vec!["evil.example.com".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn restrictions_require_firewall_enforcement() {
        // Explicit host lists are only ever enforced through iptables on this
        // backend.
        assert!(requires_firewall_enforcement(&restrictive_policy()));
        assert!(requires_firewall_enforcement(&ContainerPolicy {
            allowed_hosts: vec!["example.com".to_string()],
            ..Default::default()
        }));
    }

    #[test]
    fn explicit_default_block_requires_firewall_but_absent_or_allow_does_not() {
        // Premise change for item 6: recovering the wire's presence bit
        // (`default_network_policy_present`) makes an explicitly-requested
        // `defaultPolicy: "block"` distinguishable from the struct default a
        // policy-free start produces, so it now drives enforcement where it
        // previously could not.

        // Absent network block: default-constructed, so `present` is false even
        // though `default_network_policy` reads `Block`. This is exactly what a
        // start with no `network` block produces, and it must not be treated as
        // a restriction — otherwise every plain start, including the basic
        // lifecycle in run_lxc_state_aware_test.sh, would be rejected.
        let no_network_block = ContainerPolicy::default();
        assert_eq!(
            no_network_block.default_network_policy,
            NetworkPolicy::Block
        );
        assert!(!no_network_block.default_network_policy_present);
        assert!(!requires_firewall_enforcement(&no_network_block));

        // Explicitly-requested `defaultPolicy: "block"`: the parser sets the
        // presence bit, so it is now an enforceable restriction. Under a
        // capabilities (non-firewall) mode the caller rejects the start rather
        // than run the default-deny fail-open.
        assert!(requires_firewall_enforcement(&ContainerPolicy {
            default_network_policy: NetworkPolicy::Block,
            default_network_policy_present: true,
            ..Default::default()
        }));

        // Explicitly-requested `defaultPolicy: "allow"` is permissive, so it
        // needs no iptables enforcement even though the presence bit is set.
        assert!(!requires_firewall_enforcement(&ContainerPolicy {
            default_network_policy: NetworkPolicy::Allow,
            default_network_policy_present: true,
            ..Default::default()
        }));
    }

    #[test]
    fn unrestricted_policy_does_not_require_firewall_enforcement() {
        let policy = ContainerPolicy {
            default_network_policy: NetworkPolicy::Allow,
            ..Default::default()
        };
        assert!(!requires_firewall_enforcement(&policy));
    }

    #[test]
    fn capabilities_mode_cannot_carry_lxc_network_restrictions() {
        // `Capabilities` is the default when `enforcementMode` is omitted, and
        // LXC has no capability-based network enforcement. A restrictive policy
        // under that mode must be rejected rather than reported as a successful
        // start that leaves the container unfiltered.
        let policy = ContainerPolicy {
            network_enforcement_mode: NetworkEnforcementMode::Capabilities,
            ..restrictive_policy()
        };
        assert!(requires_firewall_enforcement(&policy));
        assert!(!uses_firewall_mode(&policy));
    }

    #[test]
    fn allow_local_network_is_rejected_whatever_the_enforcement_mode() {
        // `IngressManager` refuses this, but it only gets the chance in a
        // firewall mode. With `enforcementMode` omitted both managers take
        // their no-op paths, so without a check here the start reports success
        // and the container gets every inbound source -- broader than the
        // local-network access that was asked for.
        for mode in [
            NetworkEnforcementMode::Capabilities,
            NetworkEnforcementMode::Firewall,
            NetworkEnforcementMode::Both,
        ] {
            let policy = ContainerPolicy {
                network_enforcement_mode: mode,
                allow_local_network: true,
                ..Default::default()
            };
            let err = reject_unenforceable_network_policy(&policy)
                .expect_err("allowLocalNetwork has no enforceable LXC implementation");
            assert!(
                format!("{err}").contains("allowLocalNetwork"),
                "the refusal has to name the field the caller set, got {err}"
            );
        }
    }

    #[test]
    fn a_policy_that_leaves_allow_local_network_alone_is_not_rejected_for_it() {
        // The negative control: the gate above must not swallow ordinary
        // starts.
        assert!(reject_unenforceable_network_policy(&ContainerPolicy::default()).is_ok());
    }

    #[test]
    fn firewall_modes_are_accepted_for_restrictive_policies() {
        for mode in [
            NetworkEnforcementMode::Firewall,
            NetworkEnforcementMode::Both,
        ] {
            let policy = ContainerPolicy {
                network_enforcement_mode: mode,
                ..restrictive_policy()
            };
            assert!(uses_firewall_mode(&policy));
        }
    }

    #[test]
    fn plain_start_with_no_network_block_is_not_rejected() {
        // The exact policy a start with no `network` block produces. This is
        // the basic lifecycle run_lxc_state_aware_test.sh exercises, so it must
        // pass the enforceability gate in `apply_network_policy`.
        let policy = ContainerPolicy::default();
        assert!(!requires_firewall_enforcement(&policy) || uses_firewall_mode(&policy));
        // And it must stay off the firewall path entirely: veth pinning and the
        // pre-start iptables install are scoped to the firewall modes, so a
        // default policy neither touches the container config nor installs rules.
        assert!(!uses_firewall_mode(&policy));
    }

    #[test]
    fn a_network_block_that_expresses_no_restriction_is_still_a_network_block() {
        // `network: {}`, and a block that only restates the `allowLocalNetwork:
        // false` default, both parse to a policy identical to the struct
        // default -- every narrower bit reads false. Only `network_specified`
        // can see them. The phase contract says provision, exec, stop, and
        // deprovision take no network section, so without this bit they were
        // accepted there and silently ignored.
        let empty_block = ContainerPolicy {
            network_specified: true,
            ..Default::default()
        };
        assert!(has_network_policy(&empty_block));
        assert!(reject_start_policy_on_other_phase("exec", &empty_block).is_err());
    }

    #[test]
    fn a_policy_with_no_network_section_is_not_a_network_policy() {
        // The negative control for the test above: without it, "reject
        // everything" would pass, and the plain start in
        // run_lxc_state_aware_test.sh would start failing on every phase.
        let none = ContainerPolicy::default();
        assert!(!has_network_policy(&none));
        assert!(reject_start_policy_on_other_phase("exec", &none).is_ok());
    }

    #[test]
    fn backend_key_matches_wire_format() {
        assert_eq!(
            <LxcStateAwareRunner as StatefulSandboxBackend>::BACKEND_KEY,
            "lxc"
        );
    }

    #[test]
    fn id_prefix_matches_wire_format() {
        assert_eq!(
            <LxcStateAwareRunner as StatefulSandboxBackend>::ID_PREFIX,
            "lxc"
        );
    }

    #[test]
    fn extract_container_name_unwraps_lxc_prefix() {
        assert_eq!(
            extract_container_name("lxc:mxc-abcd1234").unwrap(),
            "mxc-abcd1234"
        );
    }

    #[test]
    fn extract_container_name_rejects_other_prefix() {
        let err = extract_container_name("iso:abc").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_container_name_rejects_missing_colon() {
        let err = extract_container_name("no-colon").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_container_name_rejects_empty_payload() {
        let err = extract_container_name("lxc:").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_container_name_rejects_invalid_name_chars() {
        let err = extract_container_name("lxc:name/with/slash").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn is_valid_container_name_rejects_dot() {
        // '.' is stripped by the iptables chain-name derivation, so "a.b" and
        // "ab" would collide onto the same chain; reject dotted names.
        assert!(!is_valid_container_name("a.b"));
    }

    #[test]
    fn is_valid_container_name_rejects_overlong_name() {
        // One character over the bound: the chain derivation would truncate it,
        // letting names that differ only past the bound collide.
        assert!(!is_valid_container_name(
            &"a".repeat(MAX_CONTAINER_NAME_LEN + 1)
        ));
    }

    #[test]
    fn is_valid_container_name_accepts_max_length_name() {
        assert!(is_valid_container_name(&"a".repeat(MAX_CONTAINER_NAME_LEN)));
    }

    #[test]
    fn extract_container_name_rejects_dotted_name() {
        let err = extract_container_name("lxc:a.b").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn generated_container_name_fits_iptables_chain_bound() {
        // The auto-generated name must itself satisfy the tightened rules so the
        // firewall chain derived from it stays within the netfilter length bound
        // and is collision-resistant (a deterministic hash of the full name is
        // folded in; the mapping is not injective, only hard to collide).
        let ContainerName::Minted(name) = resolve_container_name(&ExecutionRequest::default())
            .expect("a default request carries an empty containerId")
        else {
            panic!("an empty containerId must mint a name rather than adopt one");
        };
        assert!(
            is_valid_container_name(&name),
            "generated name {name:?} is invalid"
        );
        assert!(name.len() <= MAX_CONTAINER_NAME_LEN);
    }

    #[test]
    fn a_minted_name_nobody_holds_is_the_one_used() {
        let chosen =
            mint_unused_container_name("mxc-first".to_string(), |_| Ok(false)).expect("free");
        assert_eq!(
            chosen, "mxc-first",
            "a name that is free must be used as minted"
        );
    }

    #[test]
    fn a_minted_name_that_collides_is_re_minted_rather_than_adopted() {
        // provision computed `created = !is_defined()` and skipped the create
        // when the name was taken, so a collision on a 32-bit token silently
        // handed the caller a container that was already in use.  Minting is
        // the phase that has to resolve it: by start the name is all that is
        // left, and a caller-supplied name is adopted on purpose.
        let mut probes = 0;
        let chosen = mint_unused_container_name("mxc-taken".to_string(), |_| {
            probes += 1;
            Ok(probes == 1)
        })
        .expect("a free name after one collision");

        assert_ne!(
            chosen, "mxc-taken",
            "a name that is already defined must not be adopted"
        );
        assert!(
            is_valid_container_name(&chosen),
            "the re-minted name {chosen:?} must still be a valid container name"
        );
        assert!(chosen.len() <= MAX_CONTAINER_NAME_LEN);
    }

    #[test]
    fn a_host_that_holds_every_name_is_an_error_not_an_adoption() {
        let err = mint_unused_container_name("mxc-taken".to_string(), |_| Ok(true))
            .expect_err("every candidate was taken");
        assert!(
            err.message.contains("Could not mint an unused"),
            "unexpected message: {}",
            err.message
        );
    }

    #[test]
    fn a_probe_that_cannot_answer_is_not_read_as_free() {
        // The whole point of the retry is that "taken" is detected.  A probe
        // that fails and is treated as "free" reinstates the adoption this
        // guards against, so the failure has to propagate.
        let err = mint_unused_container_name("mxc-unknown".to_string(), |_| {
            Err(MxcError::backend_error("lxc-info could not be run"))
        })
        .expect_err("the probe failed");
        assert!(
            err.message.contains("lxc-info could not be run"),
            "unexpected message: {}",
            err.message
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_lifecycle_lock_excludes_a_concurrent_phase_and_releases_on_drop() {
        // The lock is the whole of the fix for the check-then-act races, so
        // this asserts exclusion directly rather than racing two threads and
        // timing them: a second, non-blocking attempt must be refused while
        // the lock is held, and must succeed once it is dropped.
        let dir = std::env::temp_dir().join(format!("mxc-lifecycle-lock-{}", mint_random_token()));
        let name = "locked";
        std::fs::create_dir_all(dir.join(name)).expect("container directory");
        let container = LxcContainer::new(name, Some(dir.to_str().expect("utf-8 temp dir")));

        let held =
            LifecycleLock::acquire(&container, name).expect("the first phase takes the lock");

        let path = dir.join(format!(".mxc-lifecycle-{name}.lock"));
        let probe = || {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("the lock file the first phase created");
            nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        };

        assert!(
            probe().is_err(),
            "a second phase must not enter while the first holds the lock"
        );
        drop(held);
        assert!(
            probe().is_ok(),
            "the lock must be released when the phase that took it returns"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_lifecycle_lock_is_skipped_when_there_is_no_lxc_root() {
        // `stop` and `deprovision` have to stay idempotent on a host that never
        // had LXC. No root means no container directory under it, so no start
        // can have cleared its `is_defined` gate and there is no transition to
        // serialize against.
        let dir =
            std::env::temp_dir().join(format!("mxc-lifecycle-noroot-{}", mint_random_token()));
        let container = LxcContainer::new("absent", Some(dir.to_str().expect("utf-8 temp dir")));

        assert!(
            LifecycleLock::acquire(&container, "absent").is_ok(),
            "a missing LXC root must not refuse the phase"
        );
        assert!(
            !dir.exists(),
            "the lock must not create the LXC root as a side effect"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_lifecycle_lock_outlives_the_container_directory() {
        // `deprovision` holds this lock across the destroy that removes the
        // container directory. If the lock file lived in there it would be
        // unlinked while held, and the next phase would create a fresh file and
        // take a different lock — so the file has to sit in the LXC root and
        // still be acquirable once the container is gone.
        let dir = std::env::temp_dir().join(format!("mxc-lifecycle-gone-{}", mint_random_token()));
        let name = "destroyed";
        std::fs::create_dir_all(dir.join(name)).expect("container directory");
        let container = LxcContainer::new(name, Some(dir.to_str().expect("utf-8 temp dir")));

        let held =
            LifecycleLock::acquire(&container, name).expect("the deprovision takes the lock");
        std::fs::remove_dir_all(dir.join(name)).expect("the destroy removes the container");

        assert!(
            dir.join(format!(".mxc-lifecycle-{name}.lock")).exists(),
            "the lock file must survive the container it guards"
        );
        drop(held);
        assert!(
            LifecycleLock::acquire(&container, name).is_ok(),
            "a later phase must still be able to take the lock"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_terminal_phase_reclaims_the_lock_file() {
        // One zero-byte inode per sandbox name, forever, on a host that
        // provisions many short-lived sandboxes.
        let dir =
            std::env::temp_dir().join(format!("mxc-lifecycle-reclaim-{}", mint_random_token()));
        let name = "reclaimed";
        std::fs::create_dir_all(&dir).expect("lxc root");
        let container = LxcContainer::new(name, Some(dir.to_str().expect("utf-8 temp dir")));
        let path = dir.join(format!(".mxc-lifecycle-{name}.lock"));

        let held = LifecycleLock::acquire(&container, name).expect("deprovision takes the lock");
        assert!(path.exists(), "the lock file must exist while held");
        held.release_and_reclaim(&container, name);
        assert!(
            !path.exists(),
            "the terminal phase must not leave its lock file behind"
        );

        // And the next provision of the same name still works.
        assert!(
            LifecycleLock::acquire(&container, name).is_ok(),
            "reclaiming must not wedge the name"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_lock_on_a_replaced_file_is_not_accepted_as_held() {
        // `flock` follows the descriptor, not the name. A lock taken on a file
        // that has since been replaced excludes nobody, because the next phase
        // opens the new inode and locks that instead. Accepting it would hand
        // out two simultaneous "exclusive" locks on one sandbox.
        let dir = std::env::temp_dir().join(format!("mxc-lifecycle-inode-{}", mint_random_token()));
        std::fs::create_dir_all(&dir).expect("lxc root");
        let name = "replaced";
        let container = LxcContainer::new(name, Some(dir.to_str().expect("utf-8 temp dir")));
        let path = dir.join(format!(".mxc-lifecycle-{name}.lock"));

        let held = LifecycleLock::acquire(&container, name).expect("first acquire");
        // Stand a different inode at the same path, exactly as an unlink plus a
        // later create would.
        std::fs::remove_file(&path).expect("unlink the locked inode");
        std::fs::write(&path, b"").expect("a fresh inode at the same path");

        let guard = held._guard.as_ref().expect("the lock is held on Linux");
        assert!(
            !LifecycleLock::path_still_names(guard, &path.to_string_lossy()),
            "a lock on a replaced inode must not read as current"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_provision_requires_distribution_and_release() {
        let runner = LxcStateAwareRunner::new();
        let err = runner
            .validate_provision(&ExecutionRequest::default(), Some(&LxcConfig::default()))
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
    }

    #[test]
    fn validate_provision_accepts_config_and_generated_id() {
        let runner = LxcStateAwareRunner::new();
        runner
            .validate_provision(&ExecutionRequest::default(), Some(&provision_config()))
            .unwrap();
    }

    #[test]
    fn validate_provision_rejects_invalid_container_id() {
        let runner = LxcStateAwareRunner::new();
        let req = ExecutionRequest {
            container_id: "bad/name".to_string(),
            ..Default::default()
        };
        let err = runner
            .validate_provision(&req, Some(&provision_config()))
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
    }

    #[test]
    fn validate_provision_rejects_dotted_container_id() {
        // A dotted containerId would collide with its dot-stripped sibling on
        // the derived iptables chain, so provisioning must reject it up front.
        let runner = LxcStateAwareRunner::new();
        let req = ExecutionRequest {
            container_id: "has.dot".to_string(),
            ..Default::default()
        };
        let err = runner
            .validate_provision(&req, Some(&provision_config()))
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
    }

    #[test]
    fn validate_provision_rejects_start_phase_policy() {
        let runner = LxcStateAwareRunner::new();
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                readonly_paths: vec!["/workspace".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = runner
            .validate_provision(&req, Some(&provision_config()))
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn validate_start_accepts_policy_and_lxc_id() {
        let runner = LxcStateAwareRunner::new();
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                readonly_paths: vec!["/workspace".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        runner
            .validate_start("lxc:mxc-abcd1234", &req, None)
            .unwrap();
    }

    #[test]
    fn validate_start_rejects_a_start_the_real_start_would_refuse() {
        // A dry run stops after `validate_start` and answers with an empty
        // success envelope (`state_aware_dispatch.rs`, `Phase::Start`). While
        // the start-only rejections lived inside `apply_network_policy`, the
        // dry run could not see them, so it answered "this start is fine" for
        // policies the real start refuses outright -- the one question a dry run
        // exists to answer, answered wrongly. These are the two rejections that
        // need nothing but the request.
        let runner = LxcStateAwareRunner::new();

        let proxy = ExecutionRequest {
            policy: ContainerPolicy {
                network_proxy: ProxyConfig {
                    builtin_test_server: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let err = runner
            .validate_start("lxc:mxc-abcd1234", &proxy, None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
        assert!(
            err.message.contains("network.proxy"),
            "expected the proxy rejection, got: {}",
            err.message
        );

        // A host restriction under a non-firewall enforcement mode: LXC has no
        // capability-based network enforcement, so this would start unfiltered.
        let unenforceable = ExecutionRequest {
            policy: restrictive_policy(),
            ..Default::default()
        };
        assert!(!uses_firewall_mode(&unenforceable.policy));
        let err = runner
            .validate_start("lxc:mxc-abcd1234", &unenforceable, None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
        assert!(
            err.message.contains("enforcementMode"),
            "expected the enforcement-mode rejection, got: {}",
            err.message
        );
    }

    #[test]
    fn validate_start_still_accepts_an_enforceable_restriction() {
        // The negative control for the test above: the same host restriction
        // under `firewall` mode is exactly what this backend can enforce, so
        // validation must not reject it. Without this, "reject everything"
        // would pass.
        let runner = LxcStateAwareRunner::new();
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                network_enforcement_mode: NetworkEnforcementMode::Firewall,
                ..restrictive_policy()
            },
            ..Default::default()
        };
        runner
            .validate_start("lxc:mxc-abcd1234", &req, None)
            .unwrap();
    }

    #[test]
    fn validate_exec_rejects_policy() {
        let runner = LxcStateAwareRunner::new();
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                blocked_hosts: vec!["example.com".to_string()],
                network_enforcement_mode: NetworkEnforcementMode::Firewall,
                ..Default::default()
            },
            ..Default::default()
        };
        let err = runner
            .validate_exec("lxc:mxc-abcd1234", &req, None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn state_aware_runner_is_constructible_next_to_one_shot_lifecycle() {
        let _runner = LxcStateAwareRunner::new();
        let lifecycle = LifecycleConfig::default();
        assert!(lifecycle.destroy_on_exit);
    }
}
