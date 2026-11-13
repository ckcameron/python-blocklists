# Troubleshooting

| Symptom | Check and action |
|---|---|
| `iprange is required` | Install FireHOL iprange, set `--iprange PATH`, or explicitly use `--optimizer python` |
| Source with zero recognized records | Check `sources` for feeds with zero networks and zero domains |
| `empty result` | Check the inputs and exclusions, or pass `--allow-empty` to generate an empty bundle intentionally |
| Partial output | Inspect `failed_sources`; `--allow-partial` explicitly permits omissions |
| Source exceeds limit | Review size, then deliberately raise `--max-source-bytes` if appropriate |
| PTR skipped | Prefix exceeds `--ptr-max-addresses`; full range remains blocked |
| DNS budget/round warnings | Inspect report fields before raising limits; use an independent resolver |
| Unexpected shared-host outage | Inspect DNS associations; IP blocks affect all services on an address |
| Allowed subdomain unblocks parent | Parent zones are excluded to avoid overriding the allowlist; use narrower input blocks |
| No animated spinner | Redirected stderr uses plain output; `--progress off` disables progress |
| Resolver check fails | Installer restores touched files; inspect checker output, paths, permissions, and chroot visibility |
| TC filter conflict | Inspect the named interface/direction and priority; resolve policy ownership explicitly |
| Missing bpffs | Mount bpffs at `/sys/fs/bpf` before installation |
| Missing compiler/BPF tools | Install the distribution's clang BPF target, libbpf headers, bpftool, and iproute2 |
| Wrong network namespace | Use the original namespace; this version has one fixed host state path |
| Partial eBPF install | Preserve recovery state and rerun `install`; do not rely on `watch` to finish staging |
| Counters disappear | Replacement/reboot resets maps; the LRU detail map also evicts old entries |
| Rules absent after reboot | Schedule explicit installation; no persistence service is installed automatically |

## Inspection commands

These commands inspect live state; they do not apply or remove policy:

```sh
python -m json.tool generated/report.json
sudo ipset list blocklists4
sudo ipset list blocklists6
sudo iptables -S
sudo ip6tables -S
ip -j link show
sudo tc -j filter show dev eth0 ingress
sudo tc -j filter show dev eth0 egress
sudo python3 generated/apply-ebpf.py monitor
```

Replace interface and set names with the actual deployment. Use the generated
removal scripts for packet policies, and the managed-section procedure in
[deployment](Deployment.md) for resolver/Wrappers removal. Avoid flushing entire
firewalls or qdiscs to undo one tool's configuration.

---
[Documentation home](Home.md) · [Source repository](https://github.com/ckcameron/python-blocklists)
