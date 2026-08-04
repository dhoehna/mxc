#!/bin/bash
# LXC CIDR boundary network filtering test
#
# Proves roadmap item 19 / AB#62830559 accepts boundary-valid CIDR
# destinations while using the default-allow firewall path. The boundary values
# pinned here are IPv4/IPv6 /0, IPv4 /32, IPv6 /128, non-zero host-bit CIDRs,
# and a bare literal plus matching single-address CIDR spelling in one policy.
#
# NOTE: this fixture asserts that boundary prefixes are accepted and programmed,
# not effective reachability. Allow-list rules are emitted before block-list rules
# and iptables is first-match-wins (interim behaviour, AB#62830341), so the
# `0.0.0.0/0` and `::/0` allow entries shadow every blockedHosts entry here.
# Do not add reachability assertions to this file expecting the block list to win.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LXC_EXEC="$REPO_DIR/src/target/release/lxc-exec"

if [ ! -f "$LXC_EXEC" ]; then
    LXC_EXEC="$REPO_DIR/src/target/debug/lxc-exec"
fi

if [ ! -f "$LXC_EXEC" ]; then
    echo "Error: lxc-exec not found. Run build.sh first."
    exit 1
fi

CONFIG="$REPO_DIR/tests/configs/lxc_network_cidr_boundary.json"
CHAIN_NAME="MXC-CLI-LXC-Network-CIDR"
EXPECTED_ALLOWED_HOSTS=(
    "0.0.0.0/0"
    "::/0"
    "140.82.112.5"
    "140.82.112.5/20"
    "140.82.112.5/32"
    "2606:50c0:8000::153/32"
)
EXPECTED_BLOCKED_HOSTS=(
    "198.51.100.42"
    "198.51.100.42/32"
    "2001:db8::5"
    "2001:db8::5/128"
)

fail() {
    echo "FAIL: $1"
    exit 1
}

assert_firewall_chain_cleaned_up() {
    if iptables -S "$CHAIN_NAME" >/dev/null 2>&1; then
        fail "iptables chain '$CHAIN_NAME' was left behind after lxc-exec completed."
    fi
    if ip6tables -S "$CHAIN_NAME" >/dev/null 2>&1; then
        fail "ip6tables chain '$CHAIN_NAME' was left behind after lxc-exec completed."
    fi
}

load_config_hosts() {
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import json, sys; data=json.load(open(sys.argv[1], encoding="utf-8")); net=data["network"]; [print(f"allowed\t{h}") for h in net.get("allowedHosts", [])]; [print(f"blocked\t{h}") for h in net.get("blockedHosts", [])]' "$CONFIG"
    else
        awk '
            /"allowedHosts"[[:space:]]*:/ { list="allowed"; next }
            /"blockedHosts"[[:space:]]*:/ { list="blocked"; next }
            list && /]/ { list=""; next }
            list { print list "\t" $0 }
        ' "$CONFIG" | sed -n 's/^\([^[:space:]]*\)[[:space:]]*"\([^"]*\)".*/\1\t\2/p'
    fi
}

contains_host() {
    local needle="$1"
    shift
    local host
    for host in "$@"; do
        if [ "$host" = "$needle" ]; then
            return 0
        fi
    done
    return 1
}

mapfile -t CONFIG_HOST_LINES < <(load_config_hosts)
CONFIG_ALLOWED_HOSTS=()
CONFIG_BLOCKED_HOSTS=()
for line in "${CONFIG_HOST_LINES[@]}"; do
    list="${line%%$'\t'*}"
    host="${line#*$'\t'}"
    case "$list" in
        allowed) CONFIG_ALLOWED_HOSTS+=("$host") ;;
        blocked) CONFIG_BLOCKED_HOSTS+=("$host") ;;
        *) fail "unexpected host list '$list' in $CONFIG." ;;
    esac
done

if [ "${#CONFIG_ALLOWED_HOSTS[@]}" -ne "${#EXPECTED_ALLOWED_HOSTS[@]}" ]; then
    fail "allowed host count ${#CONFIG_ALLOWED_HOSTS[@]} does not match expected count ${#EXPECTED_ALLOWED_HOSTS[@]}."
fi
if [ "${#CONFIG_BLOCKED_HOSTS[@]}" -ne "${#EXPECTED_BLOCKED_HOSTS[@]}" ]; then
    fail "blocked host count ${#CONFIG_BLOCKED_HOSTS[@]} does not match expected count ${#EXPECTED_BLOCKED_HOSTS[@]}."
fi
for expected in "${EXPECTED_ALLOWED_HOSTS[@]}"; do
    if ! contains_host "$expected" "${CONFIG_ALLOWED_HOSTS[@]}"; then
        fail "expected allowed host '$expected' is missing from $CONFIG."
    fi
done
for expected in "${EXPECTED_BLOCKED_HOSTS[@]}"; do
    if ! contains_host "$expected" "${CONFIG_BLOCKED_HOSTS[@]}"; then
        fail "expected blocked host '$expected' is missing from $CONFIG."
    fi
done

ALL_CONFIG_HOSTS=("${CONFIG_ALLOWED_HOSTS[@]}" "${CONFIG_BLOCKED_HOSTS[@]}")

echo "Running LXC CIDR boundary network filtering test..."

set +e
OUTPUT=$("$LXC_EXEC" --debug "$CONFIG" 2>&1)
STATUS=$?
set -e
echo "$OUTPUT"

if [ "$STATUS" -ne 0 ]; then
    fail "lxc-exec exited with status $STATUS for boundary-valid prefixes."
fi

# SPEC_BRIEF §3 accepts prefix lengths at the inclusive family bounds, including /0.
for host in "${ALL_CONFIG_HOSTS[@]}"; do
    if echo "$OUTPUT" | grep -Fq "Warning: could not resolve host '$host'"; then
        fail "host '$host' was not resolved."
    fi
done

if ! echo "$OUTPUT" | grep -q "Default network policy: ACCEPT"; then
    fail "default-allow policy was not applied."
fi
if echo "$OUTPUT" | grep -q "Default network policy: DROP"; then
    fail "default-deny policy was applied unexpectedly."
fi

# The v6 half is required by roadmap item 19 / AB#62830559; skipping it would be a dual-stack bypass.
if echo "$OUTPUT" | grep -q "IPv6 firewall rule(s) not applied"; then
    fail "IPv6 rules were skipped; ip6tables is unusable on this host."
fi

if ! echo "$OUTPUT" | grep -q "Creating iptables/ip6tables chain:"; then
    fail "firewall chain creation was not logged."
fi

if echo "$OUTPUT" | grep -qE "^(ip6?tables) .* failed:|Firewall setup failed:"; then
    fail "iptables/ip6tables rejected a boundary-valid rule."
fi

# The FORWARD hook is what scopes the chain to this container's egress; a run
# that skipped it enforces nothing, so PASS must require it. Fail on the
# skipped-hook warning and require the positive install confirmation.
if echo "$OUTPUT" | grep -Fq "Skipping FORWARD hook"; then
    fail "FORWARD hook was skipped; the container's veth interface was not discovered."
fi
if ! echo "$OUTPUT" | grep -Fq "FORWARD hook installed"; then
    fail "FORWARD hook installation was not confirmed."
fi

assert_firewall_chain_cleaned_up

echo "PASS: CIDR boundary entries were resolved and programmed with default allow."
echo "LXC CIDR boundary network filtering test complete."
