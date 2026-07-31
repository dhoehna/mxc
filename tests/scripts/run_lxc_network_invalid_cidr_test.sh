#!/bin/bash
# LXC invalid CIDR network filtering test
#
# Invalid CIDR entries should be reported as unresolved hosts and then skipped;
# they must not make firewall setup fail for the rest of the policy.
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

CONFIG="$REPO_DIR/tests/configs/lxc_network_invalid_cidr.json"
CHAIN_NAME="MXC-CLI-LXC-Network-Inva"
INVALID_HOSTS=(
    "140.82.112.0/33"
    "2606:50c0::/129"
    "140.82.112.0/not-a-prefix"
)

fail() {
    echo "FAIL: $1"
    exit 1
}

assert_firewall_chain_cleaned_up() {
    if sudo -n iptables -S "$CHAIN_NAME" >/dev/null 2>&1; then
        fail "iptables chain '$CHAIN_NAME' was left behind after lxc-exec completed."
    fi
    if sudo -n ip6tables -S "$CHAIN_NAME" >/dev/null 2>&1; then
        fail "ip6tables chain '$CHAIN_NAME' was left behind after lxc-exec completed."
    fi
}

echo "Running LXC invalid CIDR network filtering test..."

# The process may fail because the default policy blocks egress; this test is
# only asserting firewall validation and setup behavior.
OUTPUT=$("$LXC_EXEC" --debug "$CONFIG" 2>&1 || true)
echo "$OUTPUT"

for host in "${INVALID_HOSTS[@]}"; do
    if ! echo "$OUTPUT" | grep -Fq "Warning: could not resolve host '$host'"; then
        fail "invalid host '$host' did not produce an unresolved-host warning."
    fi
done

# Invalid CIDRs are warned about and omitted from rule generation; applying the
# remaining firewall policy should still succeed.
if echo "$OUTPUT" | grep -qE "^(ip6?tables) .* failed:|Firewall setup failed:"; then
    fail "invalid CIDR entry caused firewall setup to fail."
fi

if ! echo "$OUTPUT" | grep -q "Default network policy: DROP"; then
    fail "default-deny policy was not applied."
fi

assert_firewall_chain_cleaned_up

echo "PASS: invalid CIDR entries were warned about without failing firewall setup."
echo "LXC invalid CIDR network filtering test complete."
