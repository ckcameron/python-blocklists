# Progress and reports

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

Progress is stage-local, not an overall ETA. A completed DNS query may have
failed to resolve; the result is still counted as work completed. Unknown totals
show activity without a fabricated percentage. Parsing detail reports the current
line position. Plain output has no idle heartbeat while a blocking call is quiet.
Generated installers have their own command/status output, not this spinner UI.

## `report.json` reference

| Field | Meaning |
|---|---|
| `sources` | Successful source records: source string, unique networks, unique domains, ignored lines |
| `failed_sources` | Sources omitted under `--allow-partial`, with error strings |
| `optimizer` | Requested optimization backend |
| `dns_enabled` | Whether enrichment ran |
| `dns_queries` | Scheduled A/AAAA/PTR queries across completed rounds |
| `dns_failures` | Counts keyed by dnspython exception class name |
| `associations` | Successful query name/type/answers, in completion order |
| `dns_budget_exhausted` | Present when a round's task list exceeds the remaining budget |
| `dns_unqueried_domains` | Names still missing at least one forward query |
| `ptr_skipped_networks` | Prefixes too large for PTR enumeration |
| `dns_round_limit` | Configured maximum expansion rounds |
| `ipv6_optimizer_fallback` | Present when iprange lacks IPv6 support |
| `ipv4_optimization`, `ipv6_optimization` | Minimal CIDRs, ipset entries, distinct prefix lengths, covered address count |
| `domain_count` | Final number of normalized domain entries |

DNS-specific fields are absent when DNS is disabled. Source counts precede
cross-source deduplication, exclusions, and enrichment. Do not sum them to infer
final coverage. `dns_unqueried_domains` does not inventory every unqueried IP.
`dns_budget_exhausted` is not guaranteed to appear when the last scheduled query
exactly consumes the budget and there is no subsequent round to inspect.

---
[Documentation home](Home.md) · [Source repository](https://github.com/ckcameron/python-blocklists)
