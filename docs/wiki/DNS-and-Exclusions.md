# DNS enrichment and exclusions

Forward A/AAAA lookups start as eligible domains are parsed and continue while
the generator reads other feeds and applies exclusions. The generator skips PTR
queries and excludes names under `local`, `localhost`, `home.arpa`, `internal`,
`lan`, `localdomain`, `in-addr.arpa`, and `ip6.arpa` from DNS enrichment. It also
ignores DNS answers in local, private, and special-use ranges. Explicit feed
records still follow the normal input and exclusion rules.

The defaults are 32 workers and a three-second deadline per query, with no total
query cap. Set `--max-dns-queries` to apply a cap. Capped runs wait for source
parsing so they can prioritize queries in the same sorted order regardless of
source order. `report.json` contains associations and error counts. Use an
enrichment resolver independent of these blocklists so blocked names can resolve.

```sh
python blocklists ./feeds --resolver 1.1.1.1 --resolver 9.9.9.9 \
  --allowed_ips management-networks.txt --allowed_domains trusted-domains.txt \
  --output-dir generated
```

Default IP exclusions: `0.0.0.0/8`, RFC1918 ranges, `100.64.0.0/10`, IPv4/IPv6
loopback and link-local, IPv4 multicast/reserved high space, IPv4-mapped IPv6,
IPv6 ULA and multicast. `--include-local` permits explicit feed IP entries in
these ranges. DNS answers in these ranges or the deprecated IPv6 site-local
range `fec0::/10` are always ignored.
Explicit allowlisted IPs/CIDRs are subtracted precisely, including holes inside
larger blocked networks, both before and after DNS enrichment. Domain allowlists
remove a matching domain, its descendants, **and a blocked ancestor that would
otherwise block it**. That ancestor removal is deliberately conservative: it can
also unblock siblings. Other explicitly blocked descendants remain blocked.
Domain allowlisting does not automatically allow shared IPs; use `--allowed_ips`.

IP blocking derived from domains also blocks unrelated services sharing those
addresses. Review associations and add exclusions before deployment.

## Query scheduling

The scheduler submits one A and one AAAA lookup per eligible name and continuously
refills a window of up to `workers * 4` submitted queries as results arrive.
Association order can vary between runs. Each lookup is attempted once per run.

`-6 N` removes IPv6 network entries before and after enrichment. The report still
includes AAAA lookup results. DNS output reflects the resolver's answers at the
time the generator ran.

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
