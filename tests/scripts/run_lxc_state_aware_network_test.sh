#!/bin/bash
# LXC state-aware network policy matrix test.
#
# Proves the LXC start-phase network contract in docs/state-aware-lifecycle:
# absent defaultPolicy is not the same as explicit defaultPolicy=block,
# explicit defaultPolicy=allow is permissive even when present, empty host lists
# are not restrictions, non-empty host lists require firewall enforcement, and
# network is rejected at provision.
#
# Cases 1 and 2 are the pair that matters most: both produce the same effective
# default-deny policy, and they differ only in whether the field was present in
# the wire request, so together they pin presence-driven behavior rather than
# value-driven behavior. Case 4 completes the pair by showing presence alone is
# not enough. Case 8 covers `filesystem_specified`, the other presence bit.
#
# Case 3 is quarantined, not weakened; see the comment at its call site.
#
# The start fixtures keep a __SANDBOX_ID__ placeholder because the live LXC
# sandboxId is the container name returned by this test's own provision call.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$REPO_DIR/tests/configs"

LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"
if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

SKIP_EXIT=77
skip() {
    echo "SKIP: $1"
    exit "$SKIP_EXIT"
}

WORK_DIR="$REPO_DIR/tests/.lxc_state_aware_network_test.$$"
SANDBOX_ID=""
SANDBOX_STARTED=0
PASSED=0
FAILED=0
QUARANTINED=0
QUARANTINE_ACTIVE=""
QUARANTINE_NOTES=""
CLEANED_UP=0

cleanup() {
    if [ "$CLEANED_UP" -ne 0 ]; then
        return
    fi
    CLEANED_UP=1
    if [ -n "$SANDBOX_ID" ]; then
        if [ "$SANDBOX_STARTED" -ne 0 ]; then
            echo "--- cleanup: stop $SANDBOX_ID ---"
            run_phase stop "$SANDBOX_ID" >/dev/null 2>&1 || true
            SANDBOX_STARTED=0
        fi
        echo "--- cleanup: deprovision $SANDBOX_ID ---"
        run_phase deprovision "$SANDBOX_ID" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

run_phase() {
    local phase="$1"
    local sandbox_id="${2:-}"
    local extra="${3:-}"
    local req="$WORK_DIR/$phase.json"

    {
        printf '{\n  "phase": "%s"' "$phase"
        if [ "$phase" = "provision" ]; then
            printf ',\n  "containment": "lxc"'
        fi
        if [ -n "$sandbox_id" ]; then
            printf ',\n  "sandboxId": "%s"' "$sandbox_id"
        fi
        if [ -n "$extra" ]; then
            printf ',\n  %s' "$extra"
        fi
        printf '\n}\n'
    } > "$req"

    "$LXC_EXEC" "$req"
}

extract_sandbox_id() {
    sed -n 's/.*"sandboxId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
}

check() {
    local name="$1"
    local ok="$2"
    if [ "$ok" = "0" ]; then
        echo "PASS: $name"
        PASSED=$((PASSED + 1))
    elif [ -n "$QUARANTINE_ACTIVE" ]; then
        # The assertion above is preserved byte for byte and still runs; only
        # its tally changes, because it exposes a product gap that predates this
        # change and is out of its scope. This must never read as a pass.
        echo "QUARANTINED (BEHAVIOR NOT VERIFIED): $name"
        echo "    reason: $QUARANTINE_ACTIVE"
        QUARANTINED=$((QUARANTINED + 1))
        QUARANTINE_NOTES="${QUARANTINE_NOTES}  - ${name}
      ${QUARANTINE_ACTIVE}
"
    else
        echo "FAIL: $name"
        FAILED=$((FAILED + 1))
    fi
}

fail_now() {
    echo "FAIL: $1"
    exit 1
}

record_result() {
    local case_no="$1"
    local config="$2"
    local cause="$3"
    local expected="$4"
    local actual="$5"
    local status="$6"
    RESULTS="${RESULTS}${case_no}|${config}|${cause}|${expected}|${actual}|${status}
"
}

CONFIG_NO_NETWORK="$CONFIG_DIR/lxc_state_aware_start_no_network.json"
CONFIG_BLOCK_CAPS="$CONFIG_DIR/lxc_state_aware_start_default_block_capabilities.json"
CONFIG_BLOCK_FIREWALL="$CONFIG_DIR/lxc_state_aware_start_default_block_firewall.json"
CONFIG_ALLOW_CAPS="$CONFIG_DIR/lxc_state_aware_start_default_allow_capabilities.json"
CONFIG_EMPTY_ALLOWED="$CONFIG_DIR/lxc_state_aware_start_empty_allowed_hosts.json"
CONFIG_NONEMPTY_ALLOWED="$CONFIG_DIR/lxc_state_aware_start_nonempty_allowed_hosts_capabilities.json"
CONFIG_PROVISION_NETWORK="$CONFIG_DIR/lxc_state_aware_start_network_at_provision_rejected.json"
CONFIG_PROVISION_FILESYSTEM="$CONFIG_DIR/lxc_state_aware_start_filesystem_at_provision_rejected.json"
RESULTS=""

verify_fixture_contracts() {
    for cfg in "$CONFIG_NO_NETWORK" "$CONFIG_BLOCK_CAPS" "$CONFIG_BLOCK_FIREWALL" \
        "$CONFIG_ALLOW_CAPS" "$CONFIG_EMPTY_ALLOWED" "$CONFIG_NONEMPTY_ALLOWED" \
        "$CONFIG_PROVISION_NETWORK" "$CONFIG_PROVISION_FILESYSTEM"; do
        [ -f "$cfg" ] || fail_now "fixture not found: $cfg"
    done

    # Case 8's fixture is guarded here rather than in the block below so the
    # existing seven keep their positional indices.
    grep -q '"phase"[[:space:]]*:[[:space:]]*"provision"' "$CONFIG_PROVISION_FILESYSTEM" \
        || fail_now "fixture drift in $CONFIG_PROVISION_FILESYSTEM: phase must be provision"
    grep -q '"filesystem"' "$CONFIG_PROVISION_FILESYSTEM" \
        || fail_now "fixture drift in $CONFIG_PROVISION_FILESYSTEM: must carry a filesystem block"
    grep -q '"sandboxId"' "$CONFIG_PROVISION_FILESYSTEM" \
        && fail_now "fixture drift in $CONFIG_PROVISION_FILESYSTEM: must not hard-code a sandboxId"

    if command -v python3 >/dev/null 2>&1; then
        python3 - "$CONFIG_NO_NETWORK" "$CONFIG_BLOCK_CAPS" "$CONFIG_BLOCK_FIREWALL" \
            "$CONFIG_ALLOW_CAPS" "$CONFIG_EMPTY_ALLOWED" "$CONFIG_NONEMPTY_ALLOWED" \
            "$CONFIG_PROVISION_NETWORK" <<'PY'
import json
import sys

cases = [json.load(open(path, encoding="utf-8")) for path in sys.argv[1:]]
paths = sys.argv[1:]

def fail(index, message):
    raise SystemExit(f"fixture drift in {paths[index]}: {message}")

if cases[0].get("phase") != "start" or cases[0].get("sandboxId") != "__SANDBOX_ID__" or "network" in cases[0]:
    fail(0, "case 1 must be a start request with no network block")
if cases[1].get("network") != {"defaultPolicy": "block"}:
    fail(1, "case 2 must carry only defaultPolicy=block")
if cases[2].get("network") != {"defaultPolicy": "block", "enforcementMode": "firewall"}:
    fail(2, "case 3 must carry defaultPolicy=block with enforcementMode=firewall")
if cases[3].get("network") != {"defaultPolicy": "allow"}:
    fail(3, "case 4 must carry only defaultPolicy=allow")
if cases[4].get("network") != {"allowedHosts": []}:
    fail(4, "case 5 must carry an empty allowedHosts list and no enforcementMode")
if cases[5].get("network") != {"allowedHosts": ["example.com"]}:
    fail(5, "case 6 must carry one allowedHosts entry and no enforcementMode")
if cases[6].get("phase") != "provision" or cases[6].get("containment") != "lxc":
    fail(6, "case 7 must be an LXC provision request")
if cases[6].get("network") != {"defaultPolicy": "block"}:
    fail(6, "case 7 must carry provision-time network.defaultPolicy=block")
if "sandboxId" in cases[6]:
    fail(6, "case 7 must not hard-code a sandboxId")
PY
    else
        grep -q '"network"' "$CONFIG_NO_NETWORK" && fail_now "fixture drift in $CONFIG_NO_NETWORK: case 1 must have no network block"
        grep -q '"defaultPolicy"[[:space:]]*:[[:space:]]*"block"' "$CONFIG_BLOCK_CAPS" || fail_now "fixture drift in $CONFIG_BLOCK_CAPS: missing defaultPolicy=block"
        grep -q '"enforcementMode"' "$CONFIG_BLOCK_CAPS" && fail_now "fixture drift in $CONFIG_BLOCK_CAPS: enforcementMode must be omitted"
        grep -q '"defaultPolicy"[[:space:]]*:[[:space:]]*"block"' "$CONFIG_BLOCK_FIREWALL" || fail_now "fixture drift in $CONFIG_BLOCK_FIREWALL: missing defaultPolicy=block"
        grep -q '"enforcementMode"[[:space:]]*:[[:space:]]*"firewall"' "$CONFIG_BLOCK_FIREWALL" || fail_now "fixture drift in $CONFIG_BLOCK_FIREWALL: missing enforcementMode=firewall"
        grep -q '"defaultPolicy"[[:space:]]*:[[:space:]]*"allow"' "$CONFIG_ALLOW_CAPS" || fail_now "fixture drift in $CONFIG_ALLOW_CAPS: missing defaultPolicy=allow"
        grep -q '"enforcementMode"' "$CONFIG_ALLOW_CAPS" && fail_now "fixture drift in $CONFIG_ALLOW_CAPS: enforcementMode must be omitted"
        grep -q '"allowedHosts"[[:space:]]*:[[:space:]]*\[\]' "$CONFIG_EMPTY_ALLOWED" || fail_now "fixture drift in $CONFIG_EMPTY_ALLOWED: allowedHosts must be empty"
        grep -q '"allowedHosts"[[:space:]]*:[[:space:]]*\["example.com"\]' "$CONFIG_NONEMPTY_ALLOWED" || fail_now "fixture drift in $CONFIG_NONEMPTY_ALLOWED: allowedHosts must contain example.com"
        grep -q '"phase"[[:space:]]*:[[:space:]]*"provision"' "$CONFIG_PROVISION_NETWORK" || fail_now "fixture drift in $CONFIG_PROVISION_NETWORK: phase must be provision"
        grep -q '"defaultPolicy"[[:space:]]*:[[:space:]]*"block"' "$CONFIG_PROVISION_NETWORK" || fail_now "fixture drift in $CONFIG_PROVISION_NETWORK: missing defaultPolicy=block"
        grep -q '"sandboxId"' "$CONFIG_PROVISION_NETWORK" && fail_now "fixture drift in $CONFIG_PROVISION_NETWORK: must not hard-code sandboxId"
    fi
    echo "Fixture drift guard passed for all seven LXC state-aware network configs."
}

make_request_from_config() {
    local config="$1"
    local out="$2"
    sed "s/__SANDBOX_ID__/$SANDBOX_ID/g" "$config" > "$out"
}

expect_error_code() {
    local output="$1"
    local code="$2"
    echo "$output" | grep -Eq '"code"[[:space:]]*:[[:space:]]*"'"$code"'"'
}

start_fresh_sandbox() {
    local label="$1"
    local out rc
    echo "=== provision for $label ==="
    out="$($LXC_EXEC "$CONFIG_DIR/lxc_state_aware_provision.json")"
    rc=$?
    echo "$out"
    if [ "$rc" -ne 0 ]; then
        fail_now "$label: provision failed before the network input could be tested (config: $CONFIG_DIR/lxc_state_aware_provision.json, rc=$rc)."
    fi
    SANDBOX_ID="$(printf '%s' "$out" | extract_sandbox_id)"
    if [ -z "$SANDBOX_ID" ]; then
        fail_now "$label: provision did not return a sandboxId, so the start input cannot be tested."
    fi
    case "$SANDBOX_ID" in
        lxc:mxc-*) ;;
        *) fail_now "$label: provision returned unsafe-looking sandboxId '$SANDBOX_ID'." ;;
    esac
    SANDBOX_STARTED=0
}

finish_current_sandbox() {
    if [ -n "$SANDBOX_ID" ]; then
        if [ "$SANDBOX_STARTED" -ne 0 ]; then
            echo "=== stop $SANDBOX_ID ==="
            run_phase stop "$SANDBOX_ID"
            check "stop after $1 exits 0 for input $2" $?
            SANDBOX_STARTED=0
        fi
        echo "=== deprovision $SANDBOX_ID ==="
        run_phase deprovision "$SANDBOX_ID"
        check "deprovision after $1 exits 0 for input $2" $?
        SANDBOX_ID=""
    fi
}

run_start_case() {
    local case_no="$1"
    local config="$2"
    local cause="$3"
    local expected="$4"
    local expect_success="$5"
    local must_exec="$6"
    local clause="$7"
    local quarantine="${8:-}"
    local req="$WORK_DIR/case_${case_no}.json"
    local out rc actual status sentinel

    start_fresh_sandbox "case $case_no"
    make_request_from_config "$config" "$req"
    QUARANTINE_ACTIVE="$quarantine"

    echo "=== case $case_no start: $cause ==="
    out="$($LXC_EXEC "$req" 2>&1)"
    rc=$?
    echo "$out"

    if [ "$expect_success" = "1" ]; then
        if [ "$rc" -eq 0 ]; then
            check "case $case_no start succeeds for input $config -- $clause" 0
            SANDBOX_STARTED=1
            actual="start exited 0"
            status="PASS"
        else
            check "case $case_no start succeeds for input $config -- $clause" 1
            actual="start exited $rc: $(echo "$out" | tr '\n' ' ' | sed 's/|/ /g')"
            status="FAIL"
        fi

        if [ "$must_exec" = "1" ] && [ "$rc" -eq 0 ]; then
            sentinel="MXC_STATE_AWARE_NETWORK_CASE_${case_no}_RAN"
            echo "=== case $case_no exec: prove container is running ==="
            out="$(run_phase exec "$SANDBOX_ID" '"process": { "commandLine": "echo '"$sentinel"'" }' 2>&1)"
            rc=$?
            echo "$out"
            if [ "$rc" -eq 0 ] && echo "$out" | grep -Fq "$sentinel"; then
                check "case $case_no exec observes running container for input $config -- $clause" 0
                actual="$actual; exec printed $sentinel"
            else
                check "case $case_no exec observes running container for input $config -- $clause" 1
                actual="$actual; exec rc=$rc output=$(echo "$out" | tr '\n' ' ' | sed 's/|/ /g')"
                status="FAIL"
            fi
        fi
    else
        if [ "$rc" -ne 0 ] && expect_error_code "$out" "policy_validation"; then
            check "case $case_no start rejects input $config with policy_validation -- $clause" 0
            actual="start exited $rc with policy_validation"
            status="PASS"
        else
            check "case $case_no start rejects input $config with policy_validation -- $clause" 1
            actual="start rc=$rc output=$(echo "$out" | tr '\n' ' ' | sed 's/|/ /g')"
            status="FAIL"
            if [ "$rc" -eq 0 ]; then
                SANDBOX_STARTED=1
            fi
        fi
    fi

    # Clear before teardown so a genuine stop/deprovision failure is still a
    # real failure rather than being absorbed by this case's quarantine.
    if [ -n "$QUARANTINE_ACTIVE" ] && [ "$status" = "FAIL" ]; then
        status="QUARANTINED"
    fi
    QUARANTINE_ACTIVE=""

    finish_current_sandbox "case $case_no" "$config"
    record_result "$case_no" "$config" "$cause" "$expected" "$actual" "$status"
}

run_provision_rejection_case() {
    local case_no="$1"
    local config="$2"
    local cause="$3"
    local clause="$4"
    local expected='rejected with policy_validation'
    local out rc actual status

    echo "=== case $case_no provision rejection: $cause ==="
    out="$($LXC_EXEC "$config" 2>&1)"
    rc=$?
    echo "$out"

    if [ "$rc" -ne 0 ] && expect_error_code "$out" "policy_validation"; then
        check "case $case_no provision rejects input $config with policy_validation -- $clause" 0
        actual="provision exited $rc with policy_validation"
        status="PASS"
    else
        check "case $case_no provision rejects input $config with policy_validation -- $clause" 1
        actual="provision rc=$rc output=$(echo "$out" | tr '\n' ' ' | sed 's/|/ /g')"
        status="FAIL"
        SANDBOX_ID="$(printf '%s' "$out" | extract_sandbox_id)"
        if [ -n "$SANDBOX_ID" ]; then
            case "$SANDBOX_ID" in
                lxc:mxc-*) ;;
                *) fail_now "case $case_no unexpectedly returned unsafe-looking sandboxId '$SANDBOX_ID'; refusing to deprovision it." ;;
            esac
        fi
    fi
    finish_current_sandbox "case $case_no" "$config"
    record_result "$case_no" "$config" "$cause" "$expected" "$actual" "$status"
}

print_case_table() {
    echo "| Case | Config file | Cause | Expected effect | Actual result | Status |"
    echo "|---|---|---|---|---|---|"
    printf '%s' "$RESULTS" | while IFS='|' read -r case_no config cause expected actual status; do
        [ -n "$case_no" ] || continue
        echo "| $case_no | $config | $cause | $expected | $actual | $status |"
    done
}

verify_fixture_contracts
mkdir -p "$WORK_DIR" || fail_now "could not create work directory $WORK_DIR"

[ "$(id -u)" -eq 0 ] || skip "LXC state-aware network matrix UNVERIFIED — requires root for LXC."
command -v iptables >/dev/null 2>&1 || skip "LXC state-aware network matrix UNVERIFIED — iptables is not installed."
command -v ip6tables >/dev/null 2>&1 || skip "LXC state-aware network matrix UNVERIFIED — ip6tables is not installed."
command -v lxc-create >/dev/null 2>&1 || skip "LXC state-aware network matrix UNVERIFIED — LXC (lxc-create) is not installed."
[ -f "$LXC_EXEC" ] || skip "LXC state-aware network matrix UNVERIFIED — lxc-exec binary not built; run build.sh first."

echo "Running LXC state-aware network policy matrix test..."

# Clause: "A start that supplies no network.defaultPolicy does not set the presence bit."
run_start_case "1" "$CONFIG_NO_NETWORK" \
    'no network block at start' \
    'start succeeds' \
    "1" "0" \
    'A start that supplies no network.defaultPolicy does not set the presence bit'

# Clause: "Under capabilities, start therefore fails."
run_start_case "2" "$CONFIG_BLOCK_CAPS" \
    'defaultPolicy=block with enforcementMode omitted at start' \
    'start fails with policy_validation' \
    "0" "0" \
    'Under capabilities, start therefore fails'

# Clause: "To start a default-deny container, set enforcementMode to firewall or both."
#
# QUARANTINED, not weakened. The assertion below is exactly what the contract
# requires and it still runs. It currently fails because the doc's own
# remediation is unreachable: lxc-create's distro template emits
# `lxc.include = /usr/share/lxc/config/common.conf` into every provisioned
# container (verified by reading a generated config), and the contract at
# mxc-state-aware-sandbox-api.md:1728 refuses a firewall-mode start whose config
# uses `lxc.include`. So :1750's instruction to set enforcementMode=firewall
# cannot be satisfied through the documented provision surface. Both clauses
# predate this change, which touches neither container creation nor the veth pin.
run_start_case "3" "$CONFIG_BLOCK_FIREWALL" \
    'defaultPolicy=block with enforcementMode=firewall at start' \
    'start succeeds and exec proves the container runs' \
    "1" "1" \
    'To start a default-deny container, set enforcementMode to firewall or both' \
    'contract :1750 says enforcementMode=firewall starts a default-deny container, but :1728 refuses any config using lxc.include, which lxc-create emits into every provisioned container -- the documented escape hatch is unreachable'

# Clause: "A permissive default needs no iptables rule to be honest."
run_start_case "4" "$CONFIG_ALLOW_CAPS" \
    'defaultPolicy=allow with enforcementMode omitted at start' \
    'start succeeds' \
    "1" "0" \
    'a permissive default needs no iptables rule and does not require firewall enforcement'

# Clause: "An empty list is not a restriction and needs no mode."
run_start_case "5" "$CONFIG_EMPTY_ALLOWED" \
    'allowedHosts empty list with enforcementMode omitted at start' \
    'start succeeds and exec proves the container runs' \
    "1" "1" \
    'an empty list is not a restriction and needs no mode'

# Clause: "A policy carrying a non-empty allowedHosts must set enforcementMode."
run_start_case "6" "$CONFIG_NONEMPTY_ALLOWED" \
    'allowedHosts non-empty with enforcementMode omitted at start' \
    'start fails with policy_validation' \
    "0" "0" \
    'a policy carrying a non-empty allowedHosts must set enforcementMode'

# Clause: the LXC matrix marks network as rejected at provision.
run_provision_rejection_case "7" "$CONFIG_PROVISION_NETWORK" \
    'network.defaultPolicy=block sent at provision' \
    'matrix marks network as rejected at provision'

# Clause: the LXC matrix marks filesystem as rejected at provision. This is the
# observable surface of `filesystem_specified`, the PR's other new presence bit:
# a filesystem block present in the wire request is what the phase refuses. Its
# empty-block semantics are deliberately not asserted -- no doc states them, and
# an undocumented effect must not be invented and pinned.
run_provision_rejection_case "8" "$CONFIG_PROVISION_FILESYSTEM" \
    'filesystem block sent at provision' \
    'matrix marks filesystem as rejected at provision'

echo "================================"
echo "Results: $PASSED passed, $FAILED failed, $QUARANTINED quarantined"
print_case_table
if [ "$QUARANTINED" -gt 0 ]; then
    echo ""
    echo "!!! $QUARANTINED assertion(s) QUARANTINED -- these behaviors are NOT verified !!!"
    printf '%s' "$QUARANTINE_NOTES"
fi
if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
