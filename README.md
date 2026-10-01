# python-blocklists

Compile mixed threat feeds into unified IPv4, IPv6 and domain lists, then generate
**self-contained installation scripts** for ipset/iptables, TCP Wrappers, Unbound,
dnscrypt-proxy and eBPF. Generation is unprivileged and never installs blocks.

Copyright 2025–2026 CK Cameron (chase@ckcameron.net). GPL-3.0-only; see LICENSE.md.
This software is provided WITHOUT ANY WARRANTY, including the implied warranties
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

## Install and generate

Python **3.11+** is required, including for the generated Python installers.
Install FireHOL `iprange` for the default optimizer; the explicit offline fallback
is `--optimizer python`. Linux enforcement additionally needs `ipset`, `iptables`,
`ip6tables`, and `flock`. DNS enrichment requires dnspython:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python blocklists ./feeds https://example.org/threat-ips.txt --output-dir ./generated
# Or use the curated sources retained from the original script:
python blocklists --default_lists --output-dir ./generated
```

Use actual feed URLs in place of the example URL. Downloads fail the build by
default; `--allow-partial` explicitly allows partial-source results. Empty feeds
and feeds with no recognized entries also fail. Individual unrecognized lines are
counted in `report.json`. No live threat feeds are embedded in this repository.

Offline generation:

```sh
python blocklists ./feeds --no-dns --optimizer python -o generated
```

The input formats are bare domains, IPv4/IPv6 addresses, CIDRs, IPv4 dotted
netmasks, inclusive `IP-IP` ranges, hosts files, HTTP/HTTPS/FTP URLs, CSV/TSV
indicator tokens, JSON string values, unconditional `||domain^` Adblock rules,
dnsmasq `address=/domain/IP` / `server=/domain/`, and blocking Unbound `local-zone`
records. Hostnames are normalized to lowercase IDNA ASCII. Hosts-file redirect
addresses (`0.0.0.0`, `127.0.0.1`, `::`, `::1`) are not added as threats when
followed by names. Domain block entries cover the named zone and its subdomains.

This is not a complete Adblock policy engine: exceptions, cosmetic rules,
URL-path rules, and conditional rules are skipped, not widened into domain bans.
Provide explicit allowlist files when exceptions must be honored. JSON object
keys are metadata, not indicators; only string values are read. Do not feed it
arbitrary prose or HTML pages as threat lists.

## Runtime progress

The generator reports seven stages: input discovery, reading/parsing feeds,
initial exclusions, DNS enrichment, final exclusions, IP optimization, and bundle
creation/publication. Interactive terminals show an animated spinner, current
file/query/address, completed/total counts and percentages when totals are known,
and elapsed time. The spinner continues while downloads or optimizer subprocesses
are busy. Feed details include bytes read and parsing line counts; DNS rounds
count queries as they complete (including failed lookups).

Progress goes to stderr; stdout and generated list formats stay unchanged.
Redirected output automatically uses plain stage summaries, with intermediate
updates rate-limited to once every five seconds during item processing. Errors
and warnings remain visible in every mode. No extra Python dependency is needed.

```sh
python blocklists ./feeds --progress auto   # default: spinner on a terminal
python blocklists ./feeds --progress plain # log-friendly stage/count updates
python blocklists ./feeds --progress off   # warnings/errors and final summary only
```

## DNS enrichment and exclusions

Each expansion round queries A/AAAA for new domains and PTR for new IPs, then
adds the results to the corresponding unified lists. By default three rounds,
32 workers, a three-second per-query deadline, and 100,000 total queries bound
the work. The last round may discover entries that need another round; this is
not an unlimited recursive crawl. Raise `--dns-rounds` / `--max-dns-queries` when
needed. `report.json` contains successful associations, error counts and skipped
PTR networks. Failed lookups never remove original input indicators.

PTR lookups enumerate networks containing at most 4,096 addresses by default;
larger ranges remain blocked in full but are reported as skipped for PTR.
Explicit individual addresses inside a larger input prefix still receive PTR
queries. `--ptr-max-addresses` changes this limit. PTR records are reverse DNS
associations, **not a complete inventory of all domains hosted at an IP**.
Forward records and PTR data are time-dependent and may be absent or misleading.
No passive-DNS service is assumed. The enrichment resolver should be independent
of these blocklists (or previously blocked names may resolve to NXDOMAIN).

```sh
python blocklists ./feeds --resolver 1.1.1.1 --resolver 9.9.9.9 \
  --allowed_ips management-networks.txt --allowed_domains trusted-domains.txt \
  --dns-rounds 4 --output-dir generated
```

Default IP exclusions: `0.0.0.0/8`, RFC1918 ranges, `100.64.0.0/10`, IPv4/IPv6
loopback and link-local, IPv4 multicast/reserved high space, IPv4-mapped IPv6,
IPv6 ULA and multicast. `--include-local` disables these built-in exclusions.
Explicit allowlisted IPs/CIDRs are subtracted precisely, including holes inside
larger blocked networks, both before and after DNS enrichment. Domain allowlists
remove a matching domain, its descendants, **and a blocked ancestor that would
otherwise block it**. That ancestor removal is deliberately conservative: it can
also unblock siblings. Other explicitly blocked descendants remain blocked.
Domain allowlisting does not automatically allow shared IPs; use `--allowed_ips`.

IP blocking derived from domains also blocks unrelated services sharing those
addresses. Review associations and add exclusions before deployment.

## Generated outputs

| File | Purpose |
|---|---|
| `ips-v4.txt`, `ips-v6.txt` | Sorted, minimal exact CIDR cover |
| `domains.txt` | Sorted unique normalized domains |
| `report.json` | Source counts, ignored lines, DNS associations/failures/limits, optimization metrics |
| `apply-firewall.sh` | Populate staged ipsets, swap into service, install bidirectional DROP rules |
| `remove-firewall.sh` | Remove this tool's rules and live sets |
| `hosts.deny.blocklists`, `apply-wrappers.py` | TCP Wrappers fragment and managed `/etc/hosts.deny` installer |
| `unbound-blocklists.conf`, `apply-unbound.py` | NXDOMAIN local zones and validated configuration installer |
| `dnscrypt-blocked-names.txt`, `apply-dnscrypt.py` | dnscrypt-proxy name list and TOML-aware installer |
| `blocklists.bpf.c`, `apply-ebpf.py` | eBPF source and self-contained compile/load/monitor/remove script |

All apply scripts contain their own data. They can be copied individually to a
target host. The C file is also emitted separately for inspection. Scripts do not
install software packages. Generate into a dedicated output directory outside
your source-feed tree. Directory input discovery excludes the selected output
directory; explicit input paths are still honored. Run one generator per output
directory at a time. Output files are staged first and replaced individually;
there is no multi-file filesystem transaction.

## Apply the firewall and resolver blocks

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
loading. Older iprange releases without IPv6 support use Python's exact IPv6
collapse with a warning. `/0` is split into two `/1`s for `hash:net` compatibility.

eBPF LPM tries use the compact CIDRs rather than ipset's prefix-expanded layout.

Both ipsets are populated before either live set is swapped. Each swap is atomic;
the two families and their iptables rules are not one atomic transaction. Failure
is nonzero and leaves the previous live sets in place until the swap step.
An error after one swap may leave the families on different generations. The
installer serializes its own runs and never flushes unrelated rules. New rules
are inserted at the top of INPUT (source), OUTPUT (destination), and FORWARD
(source and destination). Repeated application does not duplicate existing
rules; an external firewall manager can subsequently reorder/remove them.

## eBPF enforcement and monitoring

The eBPF layer is independent of iptables. It attaches TC direct-action programs
at priority 1 on **both ingress and egress**, checking source and destination
against IPv4/IPv6 LPM tries before returning `TC_ACT_SHOT` for a match. It checks
IP headers rather than TCP ports, so UDP, ICMP, IP fragments, and IPv6 extension
headers do not bypass address matching. Up to two in-band VLAN tags are handled;
malformed IP headers and excess VLAN nesting are dropped. Non-IP traffic passes
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

## CLI compatibility and testing

`--help` documents all options/defaults. Retained aliases include `-f`, `-u`,
`-dl`, `-el`, `-ad`, `-ai`, `-oi4`, `-oi6`, `-od`, `-in4`, `-in6`, and `-6`.
IPv6 is now enabled by default. `-is` and `-ipt` are accepted for compatibility,
but generation always writes scripts and never executes them. `-i` prompts for
input paths. Use `--output-dir` instead of the old `--ipset_location`; arbitrary
`--iptables_options` are replaced by explicit generated bidirectional DROP rules.
The old implicit rereading/appending of output files is removed; pass previous
lists explicitly as inputs if accumulation is intended.

```sh
python -m unittest discover -s tests -v
# ONLY on a disposable Linux test host; requires root and network/BPF capabilities:
sudo bash tests/integration-linux.sh
```

Unit tests cover mixed parsing, invalid/contextual rules, randomized exact
allowlist subtraction, DNS expansion/limits, optimizer equivalence, standalone
script generation, TOML updates, and eBPF key/counter encoding. CI additionally
compiles and loads the actual BPF object and exercises IPv4/IPv6 ingress/egress
blocking on a veth/network namespace with iptables blocks removed, plus allowed
traffic, replacement, counters and removal. It also checks real ipset loading and
Unbound configuration parsing.

## Upstream format and API references

- [FireHOL iprange optimization and IPv6 support](https://github.com/firehol/iprange)
- [ipset types, restore and swap](https://ipset.netfilter.org/ipset.man.html)
- [Unbound local-zone configuration](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html)
- [dnscrypt-proxy blocking patterns](https://github.com/DNSCrypt/dnscrypt-proxy/blob/master/dnscrypt-proxy/example-blocked-names.txt)
- [dnscrypt-proxy configuration](https://github.com/DNSCrypt/dnscrypt-proxy/blob/master/dnscrypt-proxy/example-dnscrypt-proxy.toml)
- [Linux BPF LPM trie API and key layout](https://docs.kernel.org/bpf/map_lpm_trie.html)
- [iproute2 tc-bpf manual](https://man7.org/linux/man-pages/man8/tc-bpf.8.html)
- [TCP Wrappers hosts_access manual](https://manpages.debian.org/bookworm/libwrap0/hosts_access.5.en.html)
