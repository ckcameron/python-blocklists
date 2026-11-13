# Getting started

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

Use actual feed URLs in place of the example URL. Sources with no recognized
entries, including empty files, contribute zero records. Failed downloads fail
the build by default.
`--allow-partial` permits partial-source results. See `report.json` for source
counts. No live threat feeds are embedded in this repository.

Offline generation:

```sh
python blocklists ./feeds --no-dns --optimizer python -o generated
```



## First run without network access

Run from the repository root. This example uses reserved documentation addresses
and a sample domain; it generates files without installing anything:

```sh
python blocklists examples/mixed-feed.txt --no-dns --optimizer python -o generated
python -m json.tool generated/report.json
```

`--no-dns` disables DNS enrichment only. HTTP(S) source URLs still download;
use local inputs as above when the entire run must stay offline. Generation does
not require root. Keep the generated directory outside your input directories
and retain the last known-good bundle before replacing it.

## Choose the enforcement layers

| Layer | Purpose | Applied by |
|---|---|---|
| ipset + iptables | Inbound, outbound, and forwarded IP drops | `apply-firewall.sh` |
| TCP Wrappers | Access control for services built with libwrap | `apply-wrappers.py` |
| Unbound | NXDOMAIN answers for blocked zones | `apply-unbound.py` |
| dnscrypt-proxy | Blocked-name rules for your existing resolver | `apply-dnscrypt.py` |
| TC eBPF | Independent packet drops and counters on covered interfaces | `apply-ebpf.py` |

Install only the layers used by the target system. Generation produces all of
these artifacts regardless of the old `-is` and `-ipt` compatibility switches.
See [deployment](Deployment.md) and [eBPF](eBPF.md) before applying them.

---
[Documentation home](Home.md) · [Source repository](https://github.com/ckcameron/python-blocklists)
