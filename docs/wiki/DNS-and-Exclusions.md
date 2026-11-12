# DNS enrichment and exclusions

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

## Expansion and limits

A round schedules unseen `(name, record type)` pairs. A and AAAA count as two
queries; PTR counts once per enumerated address. Up to `workers * 4` futures are
queued in a batch. Results are consumed as queries complete, so association
ordering in the report can vary between runs. Error class names and successful
answers are retained, but failed queries are not retried within the same run.

The query budget is applied after building a round's task list. Increasing the
PTR limit can therefore increase planning memory as well as DNS traffic. PTR
network enumeration includes all addresses, rather than using a hosts-only
iterator. No probabilistic sampling is performed.

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
