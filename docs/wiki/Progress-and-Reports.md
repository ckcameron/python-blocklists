# Progress and reports

The generator reports seven stages: input discovery, reading/parsing feeds,
initial exclusions, DNS enrichment, final exclusions, IP optimization, and bundle
creation/publication. Interactive terminals show an animated spinner, current
file/query/address, completed/total counts and percentages when totals are known,
and elapsed time. The spinner continues while downloads or optimizer subprocesses
are busy. Feed details include bytes read and parsing line counts. DNS progress
counts queries as they complete, including failed lookups.

The `DNS completed/scheduled` counter appears alongside the current stage while
lookups run. The scheduled count grows as the generator discovers eligible names
and submits A/AAAA queries.

Progress goes to stderr; stdout and generated list formats stay unchanged.
Redirected output automatically uses plain stage summaries, with intermediate
updates rate-limited to once every five seconds during item processing. Errors
and warnings remain visible in every mode. No extra Python dependency is needed.

```sh
python blocklists ./feeds --progress auto   # default: spinner on a terminal
python blocklists ./feeds --progress plain # log-friendly stage/count updates
python blocklists ./feeds --progress off   # warnings/errors and final summary only
```

Progress is stage-local, not an overall ETA. A completed DNS query may have
failed to resolve; the result is still counted as work completed. Unknown totals
show activity without a fabricated percentage. Parsing detail reports the current
line position. Plain output has no idle heartbeat while a blocking call is quiet.
Generated installers have their own command/status output, not this spinner UI.

## `report.json` reference

| Field | Meaning |
|---|---|
| `sources` | Source string, unique networks, unique domains, and ignored lines for each successfully parsed source, including those with zero recognized records |
| `failed_sources` | Sources omitted under `--allow-partial`, with error strings |
| `optimizer` | Requested optimization backend |
| `dns_enabled` | Whether enrichment ran |
| `dns_queries` | Scheduled A/AAAA queries |
| `dns_failures` | Counts keyed by dnspython exception class name |
| `associations` | Successful query names, types, and answers outside the built-in local ranges, in completion order |
| `dns_budget_exhausted` | Present when an explicit `--max-dns-queries` limit prevents further queries |
| `dns_unqueried_domains` | Eligible names still missing at least one forward query |
| `ptr_skipped_networks` | Legacy field, always empty |
| `dns_round_limit` | Legacy field, always `1` for the forward pass |
| `ipv6_optimizer_fallback` | Present when IPv6 optimization falls back to exact Python CIDRs |
| `ipv4_optimization`, `ipv6_optimization` | Minimal CIDRs, ipset entries, distinct prefix lengths, covered address count, and `fallback_reason` if iprange failed |
| `domain_count` | Final number of normalized domain entries |

DNS-specific fields are absent when DNS is disabled. Source counts precede
cross-source deduplication, exclusions, and enrichment. Do not sum them to infer
final coverage. When the explicit budget matches the number of eligible queries,
`dns_budget_exhausted` is absent.

---
[Documentation home](Home.md) · [Source repository](https://github.com/ckcameron/python-blocklists)
