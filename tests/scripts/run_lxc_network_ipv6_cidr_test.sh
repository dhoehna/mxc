#!/bin/bash
# LXC IPv6 + CIDR network filtering test
#
# Exercises tests/configs/lxc_network_ipv6_cidr.json, whose allow/block lists
# carry IPv4 CIDRs, IPv6 CIDRs, and IPv6 literals. The assertions are on the
# firewall setup rather than on whether the container reaches the network:
# reachability depends on the host's uplink, but rule programming does not.
#
# A misrouted address family is a hard failure, not a silent one --
# `run_firewall_command` returns Err when iptables/ip6tables rejects a rule, so
# handing an IPv6 CIDR to iptables (or a v4 CIDR to ip6tables) aborts setup and
# is caught here.
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

CONFIG="$REPO_DIR/tests/configs/lxc_network_ipv6_cidr.json"
CHAIN_NAME="MXC-CLI-LXC-Network-IPv6"
EXPECTED_HOSTS=(
    "140.82.112.0/20"
    "2606:50c0::/32"
    "2606:50c0:8000::153"
    "10.0.0.0/8"
    "2001:db8::/32"
    "fe80::1"
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
        python3 -c 'import json, sys; data=json.load(open(sys.argv[1], encoding="utf-8")); net=data["network"]; print("\n".join(net.get("allowedHosts", []) + net.get("blockedHosts", [])))' "$CONFIG"
    else
        awk '
            /"allowedHosts"[[:space:]]*:/ { in_hosts=1; next }
            /"blockedHosts"[[:space:]]*:/ { in_hosts=1; next }
            in_hosts && /]/ { in_hosts=0; next }
            in_hosts { print }
        ' "$CONFIG" | sed -n 's/^[[:space:]]*"\([^"]*\)".*/\1/p'
    fi
}

mapfile -t CONFIG_HOSTS < <(load_config_hosts)
if [ "${#CONFIG_HOSTS[@]}" -ne "${#EXPECTED_HOSTS[@]}" ]; then
    fail "config host count ${#CONFIG_HOSTS[@]} does not match expected count ${#EXPECTED_HOSTS[@]}."
fi
for expected in "${EXPECTED_HOSTS[@]}"; do
    found=0
    for actual in "${CONFIG_HOSTS[@]}"; do
        if [ "$actual" = "$expected" ]; then
            found=1
            break
        fi
    done
    if [ "$found" -ne 1 ]; then
        fail "expected host '$expected' is missing from $CONFIG."
    fi
done

echo "Running LXC IPv6/CIDR network filtering test..."

# The container command may fail on a host with no outbound route; the firewall
# assertions below are what this test is about.
OUTPUT=$("$LXC_EXEC" --debug "$CONFIG" 2>&1 || true)
echo "$OUTPUT"

# Every allow/block entry must survive resolution. An unparsed CIDR or IPv6
# literal is reported here instead of silently dropping a rule.
for host in "${EXPECTED_HOSTS[@]}"; do
    if echo "$OUTPUT" | grep -Fq "Warning: could not resolve host '$host'"; then
        fail "host '$host' was not resolved."
    fi
done

# A rejected rule aborts setup.
if echo "$OUTPUT" | grep -qE "^(ip6?tables) .* failed:|Firewall setup failed:"; then
    fail "iptables/ip6tables rejected a rule."
fi

if ! echo "$OUTPUT" | grep -q "Default network policy: DROP"; then
    fail "default-deny policy was not applied."
fi

# The v6 half is the point of the test: if ip6tables is unusable the v6 rules
# are skipped with a warning, which would make this a v4-only run.
if echo "$OUTPUT" | grep -q "IPv6 firewall rule(s) not applied"; then
    fail "IPv6 rules were skipped; ip6tables is unusable on this host."
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

echo "PASS: IPv6 and CIDR entries were resolved and programmed."
echo "LXC IPv6/CIDR network filtering test complete."
