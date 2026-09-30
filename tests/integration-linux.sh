#!/bin/bash
# Run only on a disposable Linux CI host, as root. All traffic tests use a netns.
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
ns="blocklists-test-$$"
peer="bl-peer-$$"
cleanup() {
    nsenter --net="/run/netns/$ns" python3 "$work/out/apply-ebpf.py" remove 2>/dev/null || true
    ip netns del "$ns" 2>/dev/null || true
    ip link del "$peer" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT
ip netns add "$ns"
ip link add "$peer" type veth peer name bl-test
ip link set bl-test netns "$ns"
ip addr add 198.18.0.1/24 dev "$peer"
ip -6 addr add 2001:db8:123::1/64 dev "$peer" nodad
ip link set "$peer" up
ip netns exec "$ns" ip link set lo up
ip netns exec "$ns" ip addr add 198.18.0.2/24 dev bl-test
ip netns exec "$ns" ip -6 addr add 2001:db8:123::2/64 dev bl-test nodad
ip netns exec "$ns" ip link set bl-test up
ip netns exec "$ns" ping -c 1 -W 2 198.18.0.1
ip netns exec "$ns" ping -6 -c 1 -W 2 2001:db8:123::1
printf '%s\n' 198.18.0.1 2001:db8:123::1 bad.example > "$work/feed"
python3 blocklists "$work/feed" --no-dns -o "$work/out"
unbound-checkconf "$work/out/unbound-blocklists.conf"
# Check actual ipset restoration and bidirectional iptables drops.
ip netns exec "$ns" sh "$work/out/apply-firewall.sh"
ip netns exec "$ns" ipset test blocklists4 198.18.0.1
ip netns exec "$ns" ipset test blocklists6 2001:db8:123::1
if ip netns exec "$ns" ping -c 1 -W 1 198.18.0.1; then exit 1; fi
ip netns exec "$ns" sh "$work/out/apply-firewall.sh"
ip netns exec "$ns" sh "$work/out/remove-firewall.sh"
ip netns exec "$ns" ping -c 1 -W 2 198.18.0.1
# No iptables blocks remain: eBPF alone must enforce both address families.
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
nsenter --net="/run/netns/$ns" python3 "$work/out/apply-ebpf.py" install
if ip netns exec "$ns" ping -c 1 -W 1 198.18.0.1; then exit 1; fi
if ip netns exec "$ns" ping -6 -c 1 -W 1 2001:db8:123::1; then exit 1; fi
if ping -c 1 -W 1 198.18.0.2; then exit 1; fi
if ping -6 -c 1 -W 1 2001:db8:123::2; then exit 1; fi
# An unlisted address still works, and updates do not duplicate TC filters.
ip addr add 198.18.0.3/24 dev "$peer"
ip netns exec "$ns" ping -c 1 -W 2 198.18.0.3
nsenter --net="/run/netns/$ns" python3 "$work/out/apply-ebpf.py" monitor > "$work/monitor.jsonl"
python3 - "$work/monitor.jsonl" <<'PY'
import json, sys
rows = [json.loads(s) for s in open(sys.argv[1])]
assert {'ingress', 'egress'} <= {r.get('direction') for r in rows}, rows
assert {'198.18.0.1', '2001:db8:123::1'} <= {r.get('ip') for r in rows}, rows
assert all(r['packets'] > 0 for r in rows if 'packets' in r), rows
PY
nsenter --net="/run/netns/$ns" python3 "$work/out/apply-ebpf.py" install
if ip netns exec "$ns" ping -c 1 -W 1 198.18.0.1; then exit 1; fi
nsenter --net="/run/netns/$ns" python3 "$work/out/apply-ebpf.py" remove
ip netns exec "$ns" ping -c 1 -W 2 198.18.0.1
ip netns exec "$ns" ping -6 -c 1 -W 2 2001:db8:123::1
