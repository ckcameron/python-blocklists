# Command-line reference

The option table below lists all generator arguments and defaults. Retained aliases include `-f`, `-u`,
`-dl`, `-el`, `-ad`, `-ai`, `-oi4`, `-oi6`, `-od`, `-in4`, `-in6`, and `-6`.
IPv6 is now enabled by default. `-is` and `-ipt` are accepted for compatibility,
but generation always writes scripts and never executes them. `-i` prompts for
input paths. Use `--output-dir` instead of the old `--ipset_location`; arbitrary
`--iptables_options` are replaced by explicit generated bidirectional DROP rules.
The old implicit rereading/appending of output files is removed; pass previous
lists explicitly as inputs if accumulation is intended.



## Generator options

Boolean compatibility options accept `1/0`, `Y/N`, `yes/no`, and `true/false`
(case-insensitive). Supplying one without a value means true. Other switches,
such as `--no-dns`, are ordinary flags and take no value.

| Option | Default | Purpose |
|---|---|---|
| `--progress` | `auto` | stderr progress: auto animates terminals; plain logs stages; off disables progress |
| `inputs` | `unset` | local files/directories or HTTP(S) feed URLs |
| `-f`, `--files` | `empty string` | legacy comma-separated local paths |
| `-u`, `--urls` | `empty string` | legacy comma-separated feed URLs |
| `-el`, `--external_lists` | `unset` | file with one URL or NAME URL per line |
| `-dl`, `--default_lists` | `False` | include the curated feed URLs |
| `-o`, `--output-dir` | `generated` | directory for the generated bundle |
| `-ad`, `--allowed_domains` | `unset` | file of domain exclusions |
| `-ai`, `--allowed_ips` | `unset` | file of address/CIDR exclusions |
| `--include-local` | `False` | do not exclude built-in local/private/multicast ranges |
| `--no-dns` | `False` | skip DNS enrichment; URL inputs still download |
| `--resolver` | `[]` | DNS server IP; repeatable |
| `--dns-timeout` | `3.0` | deadline per DNS query in seconds |
| `--dns-rounds` | `3` | accepted for compatibility with older commands |
| `--max-dns-queries` | unlimited | optional total DNS query budget |
| `--ptr-max-addresses` | `4096` | accepted for compatibility with older commands |
| `--workers` | `32` | maximum concurrent DNS workers |
| `--optimizer` | `iprange` | IP prefix optimization backend |
| `--iprange` | `iprange` | iprange executable |
| `--reduce-percent` | `20` | iprange extra-entry percentage budget |
| `--reduce-entries` | `16384` | iprange minimum entry budget |
| `-in4`, `--ipset4_name` | `blocklists4` | IPv4 hash:net set name |
| `-in6`, `--ipset6_name` | `blocklists6` | IPv6 hash:net set name |
| `--max-source-bytes` | `67108864` | maximum bytes per input source |
| `--allow-partial` | `False` | explicitly permit failed input sources |
| `--allow-empty` | `False` | permit an empty block bundle |
| `-oi4`, `--output_ip_list_v4` | `unset` | also write a copy of the unified list here |
| `-oi6`, `--output_ip_list_v6` | `unset` | also write a copy of the unified list here |
| `-od`, `--output_domain_list` | `unset` | also write a copy of the unified list here |
| `-6`, `--ipv6` | `True` | IPv6 enabled by default |
| `-i`, `--interactive` | `False` | prompt for comma-separated input paths |
| `-is`, `--ipset` | `False` | compatibility: installers are always generated |
| `-ipt`, `--iptables_rules` | `False` | compatibility: installers are always generated, never executed |

`--dns-timeout` must be positive; `--reduce-percent` must be nonnegative.
Count/size limits use positive integers. ipset names must be different, start
with a letter, and contain 1–25 ASCII letters, digits, underscores, or hyphens.
The installer reserves a `_next` suffix for staging sets.

Exit status is 0 after successful generation, 1 for handled operational errors,
and 2 for argparse usage errors. Unexpected exceptions and interruption can
produce other nonzero statuses. Progress and logging use stderr; ordinary
noninteractive generation does not write list data to stdout.

See [deployment](Deployment.md) for resolver/Wrappers options and
[eBPF](eBPF.md) for loader actions and interface selection.

---
[Documentation home](Home.md) · [Source repository](https://github.com/ckcameron/python-blocklists)
