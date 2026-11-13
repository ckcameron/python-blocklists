# DNS enrichment and exclusions

Forward A/AAAA lookups start as eligible domains are parsed and continue while
the generator reads other feeds and applies exclusions. Each expansion round
queries new domains and eligible IPs, adding the results to the unified lists
before the next round. Defaults are three rounds, 32 workers, and a three-second
deadline per query. There is no default total query cap. Set `--max-dns-queries`
to apply a cap. Capped runs wait for source parsing so they can prioritize queries
in the same sorted order regardless of source order. `report.json` contains
successful associations, error counts, and skipped PTR networks. Failed lookups
never remove original input indicators.

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

## Expansion and limits

A round schedules unseen `(name, record type)` pairs. A and AAAA count as two
queries. PTR counts once per enumerated address. The scheduler continuously
refills a window of up to `workers * 4` submitted queries as results arrive.
Association order can vary between runs. The report retains error class names
and successful answers. Failed queries are not retried within the same run.

PTR tasks are generated as needed. PTR enumeration includes every address in an
eligible network. Raising the PTR limit increases the potential query count.

`-6 N` removes IPv6 network entries before and after enrichment; it does not
suppress AAAA queries. A discovered name can still receive A/AAAA lookups in
later rounds. DNS output is a point-in-time snapshot, not a TTL-aware live policy.

## Built-in excluded networks

```text
0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.168.0.0/16
224.0.0.0/4
240.0.0.0/4
::/128
::1/128
::ffff:0:0/96
fc00::/7
fe80::/10
ff00::/8
```

For example, allowing `safe.bad.example` removes a broad `bad.example` block while
leaving a separately listed `other.bad.example` block intact. Apply an IP
allowlist separately when those names share addresses.

---
[Documentation home](Home.md) · [Source repository](https://github.com/ckcameron/python-blocklists)
