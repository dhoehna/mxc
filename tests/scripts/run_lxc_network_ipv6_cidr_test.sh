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

echo "Running LXC IPv6/CIDR network filtering test..."

# The container command may fail on a host with no outbound route; the firewall
# assertions below are what this test is about.
OUTPUT=$("$LXC_EXEC" "$CONFIG" 2>&1 || true)
echo "$OUTPUT"

fail() {
    echo "FAIL: $1"
    exit 1
}

# Every allow/block entry must survive resolution. An unparsed CIDR or IPv6
# literal is reported here instead of silently dropping a rule.
if echo "$OUTPUT" | grep -q "could not resolve host"; then
    echo "$OUTPUT" | grep "could not resolve host"
    fail "an IPv6 literal or CIDR entry was not resolved."
fi

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

echo "PASS: IPv6 and CIDR entries were resolved and programmed."
echo "LXC IPv6/CIDR network filtering test complete."
