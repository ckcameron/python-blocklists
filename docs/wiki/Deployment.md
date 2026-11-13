# Firewall and resolver deployment

```sh
sudo sh generated/apply-firewall.sh
sudo python3 generated/apply-wrappers.py
sudo python3 generated/apply-unbound.py --config /etc/unbound/unbound.conf
sudo python3 generated/apply-dnscrypt.py --config /etc/dnscrypt-proxy/dnscrypt-proxy.toml
```

Use whichever resolvers you operate. Resolver installers preserve the existing
configuration, back up touched files with `.blocklists.bak`, run the resolver's
configuration checker, and use `systemctl reload-or-restart`. Failed validation
or reload restores previous file contents and attempts to restart the previous
configuration. `--no-reload` validates and installs without restarting;
`--service` selects a different systemd unit. Chroot/container installations may
need different paths and service handling; inspect the generated include path.

The dnscrypt installer edits `[blocked_names].blocked_names_file`; it preserves
existing manual rules and replaces only its marked generated block on later
runs. It rejects ambiguous dotted/inline TOML table syntax rather than rewriting
unrelated settings. The Wrappers installer preserves unmanaged `hosts.deny`
entries and updates its own marked section. IPv4 uses `network/netmask`; IPv6
uses `[address]/prefix` and requires an IPv6-capable libwrap build.

TCP Wrappers applies only to services that use libwrap; `hosts.allow` can take
precedence. It is **not an outbound firewall**. The ipset and eBPF layers provide
packet enforcement. No blackhole routing table is changed.

### ipset optimization

IPv4/IPv6 use separate `hash:net` sets with appropriately sized hash tables and
`maxelem`; no arbitrary 65,535-entry file splitting or IPv6 `bitmap:ip` is used.
`iprange --ipset-reduce` reduces prefix-length diversity, trading entry memory for
fewer prefix lookups without changing coverage. Defaults: 20% extra-entry budget
and a 16,384-entry minimum budget; tune `--reduce-percent` / `--reduce-entries`.
This is a tunable memory/lookup tradeoff, not a claim of universally optimal
performance for all workloads. Every optimizer result is checked for exact
address-set equality. Reduced prefixes are not collapsed again before ipset
loading. If reduction fails, times out, or returns unusable output, the
generator warns and uses exact Python CIDRs for the affected address family.
Some `iprange` releases can read IPv6 addresses but cannot reduce their prefix
lengths. `/0` is split into two `/1`s for `hash:net` compatibility.

eBPF LPM tries use the compact CIDRs rather than ipset's prefix-expanded layout.

Both ipsets are populated before either live set is swapped. Each swap is atomic;
the two families and their iptables rules are not one atomic transaction. Failure
is nonzero and leaves the previous live sets in place until the swap step.
An error after one swap may leave the families on different generations. The
installer serializes its own runs and never flushes unrelated rules. New rules
are inserted at the top of INPUT (source), OUTPUT (destination), and FORWARD
(source and destination). Repeated application does not duplicate existing
rules; an external firewall manager can subsequently reorder/remove them.

## Installer options

| Installer | Option | Default and behavior |
|---|---|---|
| All three Python resolver/wrappers installers | `--config PATH` | `/etc/hosts.deny`, `/etc/unbound/unbound.conf`, or `/etc/dnscrypt-proxy/dnscrypt-proxy.toml` |
| Resolver installers | `--service NAME` | `unbound` or `dnscrypt-proxy`; unit passed to systemctl |
| Resolver installers | `--no-reload` | Off; skip service reload, still validate and install files |
| Wrappers installer | `--service`, `--no-reload` | Accepted by the shared parser but have no effect for wrappers |
| Firewall shell scripts | None | Set names and rules were chosen at generation time |

All apply/remove operations require root. The resolver configuration must already
exist and be nonempty. Unbound adds a managed include pointing to
`python-blocklists.conf` beside the selected config. dnscrypt-proxy selects
`python-blocklists-blocked-names.txt` in that same directory. Custom chroots and
containers may not see the host absolute path; adapt deployment accordingly.

## Updates and removal

Keep a previous complete bundle before generating an update. Apply the new
bundle explicitly to every deployed layer; generating files never updates a
running firewall. To roll back IP policy, reapply the previous firewall and eBPF
installers. This resets eBPF counters. To remove these packet blocks:

```sh
sudo sh generated/remove-firewall.sh
sudo python3 generated/apply-ebpf.py remove
```

Use the removal script matching the live ipset names. A failed removal should be
inspected: an external reference may prevent destroying a set. These commands
do not remove resolver or Wrappers blocks.

Resolver/Wrappers installers do not have a removal subcommand. Remove only their
`# BEGIN python-blocklists` through `# END python-blocklists` section, preserving
unmanaged entries. For Unbound this section is the include in the main config.
For dnscrypt-proxy it is in the generated blocked-names file; retain the file and
its unmanaged entries, or deliberately restore the original file reference.
Validate resolver configuration and reload the corresponding service afterward.

`.blocklists.bak` files are overwritten by subsequent successful installation
attempts. They are not a versioned backup history. Automatic rollback restores
the files touched by the failed attempt and tries to reload the old resolver;
it cannot guarantee that a service with an independent failure starts correctly.

There is no automatic feed refresh, systemd unit installation, or reboot restore.
Use your existing scheduler/service manager for generation and explicit deployment.
For eBPF, install after interfaces exist and optionally supervise `watch`.

---
[Documentation home](Home.md) · [Source repository](https://github.com/ckcameron/python-blocklists)
