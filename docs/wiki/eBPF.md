# eBPF enforcement and monitoring

The eBPF layer is independent of iptables. It attaches TC direct-action programs
at priority 1 on **both ingress and egress**, checking source and destination
against IPv4/IPv6 LPM tries before returning `TC_ACT_SHOT` for a match. It checks
IP headers rather than TCP ports, so UDP, ICMP, IP fragments, and IPv6 extension
headers do not bypass address matching. Up to two in-band VLAN tags are handled;
detected malformed base headers and excess VLAN nesting are dropped. Non-IP traffic passes
to subsequent TC policies. Unrelated priority-1 filters cause a deployment error
rather than being overwritten. Packet drop telemetry counts attempted traffic;
it does not claim process attribution or one event per connection.

Requirements: a Linux kernel supporting TC eBPF, LPM tries and
`bpf_skb_load_bytes_relative`, plus clang with the BPF target, libbpf development
headers, Linux UAPI headers, bpftool, iproute2 (`ip`/`tc`), and mounted bpffs.
A modern distribution kernel (5.15+ recommended) is the intended target.
For Debian/Ubuntu, relevant packages include `clang libbpf-dev iproute2` and the
appropriate `linux-tools`/`bpftool` package for the running distribution/kernel.

```sh
# If bpffs is not already mounted:
sudo mount -t bpf bpf /sys/fs/bpf
sudo python3 generated/apply-ebpf.py install
# Or explicitly restrict interface coverage:
sudo python3 generated/apply-ebpf.py install --interfaces eth0 lo
sudo python3 generated/apply-ebpf.py monitor
# Foreground reconciliation + JSON counters every five seconds:
sudo python3 generated/apply-ebpf.py watch --interval 5
# Detach only owned filters; retain unrelated qdiscs/policies:
sudo python3 generated/apply-ebpf.py remove
```

The default covers all current interfaces in the **current network namespace**,
including loopback, bridge/veth and tunnel interfaces. `watch` attaches newly
created interfaces and restores missing owned filters. It is polling, so there
is a gap up to the interval before a new interface is protected. Run it under
your service supervisor if ongoing reconciliation is required. Programs remain
attached if the monitoring process exits; pinning is not persistence across a
reboot. Re-run `install` during boot after networking is initialized.

Updates stage a new program/map generation before replacing filters. Each TC
replacement is atomic; all interfaces are not updated simultaneously. Failed
updates preserve pins and recovery state, and exit nonzero. Re-running install
reconciles a partial update. State is `/var/lib/python-blocklists/ebpf.json` and
pins are `/sys/fs/bpf/python_blocklists`. This version manages one network
namespace per host state path; it refuses to reuse state from another namespace.

`monitor` emits JSON lines with IP, interface index, ingress/egress, matched
endpoint, packet count and byte count; it also emits aggregate map counters.
Counters are cumulative for the current installation, per CPU internally, and
reset on replacement/reboot. The 16,384-entry LRU detail map can evict old IPs;
aggregate matched/malformed drop counters are separate and are not LRU-evicted.

This prevents ordinary iptables ACCEPT rules or deletion of the iptables blocks
from overriding eBPF drops on covered paths. It is **not an unbypassable security
boundary against root/CAP_BPF/CAP_NET_ADMIN**, which can detach programs or alter
maps, namespaces and interfaces. XDP redirects, hardware forwarding, packet
injection paths bypassing TC, uncovered namespaces, and encrypted/proxied traffic
whose visible endpoint is not blocked require additional controls. Attach to the
decapsulated tunnel interface when inner-IP enforcement is needed. No process
can infer an encrypted tunnel's inner destination from its outer IP header alone.

## Command reference

| Argument | Default | Meaning |
|---|---|---|
| `install` | Action when omitted | Compile, populate new maps, and attach both directions |
| `monitor` | Explicit action | Print one counter snapshot and exit |
| `watch` | Explicit action | Reconcile interfaces and print counters repeatedly; requires an installed generation |
| `remove` | Explicit action | Detach owned filters and remove pins/state |
| `--interfaces NAME [NAME ...]` | All current interfaces | Selection for install/watch; monitor/remove use saved state |
| `--interval SECONDS` | `5` | Positive watch sleep interval; not a monitoring rate for `monitor` |

Previously covered interfaces still present are migrated during installation,
even when the new selection is narrower. A narrower `--interfaces` list is not
an automatic detach request. Remove/reinstall when intentionally reducing coverage.
The default action is install: use `--help` to inspect syntax without mutation.

## Counter layout

Detail lines contain `ip`, `ifindex`, `direction`, `endpoint`, `packets`, and
`bytes`. Each packet is counted once per rejecting hook. Source matching takes
precedence when both endpoints are blocked. Byte counts use `skb->len`.
The final `totals` line carries bpftool's raw per-CPU map dump: array index 0 is
matched-address drops and index 1 is malformed-header/excess-VLAN drops. It is
not already flattened into the detail schema. Sum per-CPU values to obtain
host totals for that installation.

This is address filtering, not full IP validation. Header-load failure, invalid
version, IPv4 IHL below five, and unsupported VLAN nesting are rejected; the
program does not verify every IP length, checksum, or extension-header field.

## Recovery

If install fails after staging, retain both pins and the state file. Correct the
reported dependency, namespace, or conflicting-filter problem, then rerun
`install` from the intended bundle. A failed first installation may have only
`pending_pin`, so `monitor`/`watch` are not recovery commands. Do not remove
foreign TC filters merely to make installation succeed without reviewing their
policy. The loader intentionally refuses conflicting priority-1 classifiers.

---
[Documentation home](Home.md) · [Source repository](https://github.com/ckcameron/python-blocklists)
