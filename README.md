# python-blocklists

Last signed commit: 11 November, 2026

Compile mixed threat feeds into unified IPv4, IPv6 and domain lists, then generate
**self-contained installation scripts** for ipset/iptables, TCP Wrappers, Unbound,
dnscrypt-proxy and eBPF. Generation is unprivileged and never installs blocks.
=======
Compile mixed threat feeds into unified IPv4, IPv6, and domain blocklists, then
produce self-contained installers for ipset/iptables, TCP Wrappers, Unbound,
dnscrypt-proxy, and TC eBPF. I keep generation separate from enforcement: running
`blocklists` writes a bundle; it never installs blocks on the host.


![python-blocklists](blocklists.png)

## Quick start

Python **3.11+** is required. Start with the included offline example:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python blocklists examples/mixed-feed.txt --no-dns --optimizer python -o generated
python -m json.tool generated/report.json
```

For live feeds, install FireHOL `iprange` and run:

```sh
python blocklists ./feeds --output-dir generated
# Or select the curated URLs in default_sources.py:
python blocklists --default_lists --output-dir generated
```

The default run starts forward DNS lookups while parsing feeds and finishes DNS
enrichment before iprange optimization. There is no default total DNS query
limit. `--no-dns` disables DNS, but does not stop downloads from URL
inputs. Live feed availability and access requirements depend on their providers.
The terminal displays stage spinners, current work, completion counts, and elapsed
time; redirected stderr uses plain progress. Use `--progress plain` or
`--progress off` to select the display explicitly.

## Documentation

The complete manual is in [docs/wiki/Home.md](docs/wiki/Home.md), with a
[GitHub wiki](https://github.com/ckcameron/python-blocklists/wiki) publication target.

- [Getting started](docs/wiki/Getting-Started.md)
- [Input formats and sources](docs/wiki/Input-Formats.md)
- [Complete CLI reference](docs/wiki/CLI-Reference.md)
- [DNS enrichment and exclusions](docs/wiki/DNS-and-Exclusions.md)
- [Progress and report fields](docs/wiki/Progress-and-Reports.md)
- [Output bundle](docs/wiki/Outputs.md)
- [Firewall, Wrappers, and resolver deployment](docs/wiki/Deployment.md)
- [eBPF enforcement and monitoring](docs/wiki/eBPF.md)
- [Troubleshooting and recovery](docs/wiki/Troubleshooting.md)
- [Development and testing](docs/wiki/Development.md)
- [References and license](docs/wiki/References.md)

## Deployment

Inspect the generated bundle before applying it. Apply only the layers you use:

```sh
sudo sh generated/apply-firewall.sh
sudo python3 generated/apply-wrappers.py
sudo python3 generated/apply-unbound.py --config /etc/unbound/unbound.conf
sudo python3 generated/apply-dnscrypt.py --config /etc/dnscrypt-proxy/dnscrypt-proxy.toml
sudo python3 generated/apply-ebpf.py install
```

The [deployment guide](docs/wiki/Deployment.md) covers dependencies, backups,
updates, and removal. The [eBPF guide](docs/wiki/eBPF.md) covers kernel/tooling
requirements, bpffs, interfaces, namespaces, monitoring, and recovery.
Generation and these installers do not install packages or reboot-persistence
services. Never run the privileged integration suite on a production host.

DNS-derived IP blocks can affect unrelated services on shared addresses. PTR
records are not a complete inventory of domains. TCP Wrappers only protects
libwrap-aware services. eBPF protects covered TC paths independently of iptables;
it cannot stop a privileged administrator from changing policy or reveal inner
destinations hidden by an encrypted tunnel.

## Development

```sh
python -m unittest discover -s tests -v
```

See the [developer guide](docs/wiki/Development.md) for the source map, data flow,
map ABI, integration tests, and wiki publication workflow.

Copyright 2025–2026 CK Cameron (chase@ckcameron.net). **GPL-3.0-only**;
see [LICENSE.md](LICENSE.md).

**This software is provided WITHOUT ANY WARRANTY, including the implied
warranties of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.**
