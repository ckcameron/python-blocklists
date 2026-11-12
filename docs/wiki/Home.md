# python-blocklists documentation

I use python-blocklists to turn mixed indicator feeds into one set of domain,
IPv4, and IPv6 blocklists, with installers for each enforcement layer. The
compiler runs without privileges. Applying its output is a separate operation.

Start with a local offline feed, inspect the generated lists and report, then
apply the layers your target host uses. DNS enrichment is bounded, IP coverage
is checked after optimization, and eBPF operates independently of iptables on
the interfaces it covers.

## Manual

- [Getting started](Getting-Started.md)
- [Input formats and sources](Input-Formats.md)
- [Complete CLI reference](CLI-Reference.md)
- [DNS enrichment and exclusions](DNS-and-Exclusions.md)
- [Progress and report fields](Progress-and-Reports.md)
- [Output bundle](Outputs.md)
- [Firewall, Wrappers, and resolver deployment](Deployment.md)
- [eBPF enforcement and monitoring](eBPF.md)
- [Troubleshooting and recovery](Troubleshooting.md)
- [Development and testing](Development.md)
- [References and license](References.md)

## Scope

The tool generates ipset/iptables rules, TCP Wrappers entries, Unbound zones,
dnscrypt-proxy patterns, and TC eBPF programs. It does not promise complete
reverse-domain enumeration, process-level connection tracing, or protection
against a privileged administrator who can change network policy.

The pages in `docs/wiki/` are the version-controlled source for this wiki.
Copyright and license terms are in [References](References.md).

---
[Documentation home](Home.md) · [Source repository](https://github.com/ckcameron/python-blocklists)
