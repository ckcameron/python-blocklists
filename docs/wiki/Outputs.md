# Generated output bundle

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

Editing a separate text list does not update an already generated installer:
its payload is embedded. Regenerate the bundle when input changes. Files are
replaced individually, and an interrupted publication can leave a mixed bundle;
keep one generator per output directory and deploy only after a successful exit.

Generated Python installers need Python 3.11+, but do not import this repository
or dnspython. Generated shell scripts are POSIX shell. Existing unrelated files
inside the output directory are not deleted. The report contains source URLs and
DNS associations, so review it before publishing it elsewhere.

---
[Documentation home](Home.md) · [Source repository](https://github.com/ckcameron/python-blocklists)
