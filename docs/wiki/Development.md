# Development and implementation

## Source map

| File | Responsibility |
|---|---|
| `blocklists` | Small executable entry point |
| `blocklists_core.py` | Parsing, exclusions, DNS expansion, optimization, and bundle generation |
| `blocklists_progress.py` | Thread-safe terminal/log progress display |
| `blocklists_install.py` | Embedded resolver/Wrappers installer template |
| `default_sources.py` | Named default feed URLs |
| `ebpf/blocklists.bpf.c` | TC packet classification, LPM lookup, drop accounting |
| `ebpf/loader.py` | Embedded compile/load/reconcile/monitor/remove template |
| `tests/test_blocklists.py` | Parsing, coverage, resolver, installer, and map-layout tests |
| `tests/test_progress.py` | Progress modes, cleanup, logging, CLI stages, DNS completion order |
| `tests/integration-linux.sh` | Actual Linux enforcement on a disposable runner |
| `docs/wiki/` | Version-controlled wiki source pages |
| `scripts/publish-wiki.sh` | Publish these pages through a normal authenticated Git checkout |

## Data flow and invariants

`parse_text()` returns network and domain sets plus an ignored-line count.
`subtract()` sorts interval endpoints and subtracts exclusions without enumerating
whole networks. Initial filtering keeps explicit small prefixes separate so they
can still receive PTR queries when also covered by a larger input range.

`enrich()` performs bounded rounds and filters new answers before adding them.
The final exclusion pass and `optimize()` produce two network layouts: compact
CIDRs for readable lists/eBPF, and potentially expanded prefixes for ipset lookup
cost. Every external optimizer result must collapse back to identical coverage.
Never collapse the optimized layout again before populating ipset: that would
undo the intended prefix-length reduction.

`write_bundle()` embeds the installer modules and payloads into standalone files.
Do not add imports of repository modules to those templates unless the generated
bundle also supplies them. Change templates in the source tree, then regenerate;
do not maintain a second hand-edited generated implementation.

Progress rendering is serialized with log output by an RLock. The spinner thread
only renders; it does not own work scheduling or completion counts. Context-manager
cleanup stops it on success or failure. The DNS executor consumes completed
futures rather than waiting for submission order.

The C/Python map ABI uses native-endian u32 prefix lengths followed by network-order
address bytes. Detail keys are four u32 fields followed by 16 address bytes; values
are two u64 counters per CPU. Keep `prefix_key()` and `monitor()` aligned with the
C declarations and verify changes on an actual kernel.

## Tests

```sh
python -m unittest discover -s tests -v
# ONLY on a disposable Linux test host; requires root and network/BPF capabilities:
sudo bash tests/integration-linux.sh
```

Unit tests cover mixed parsing, invalid/contextual rules, randomized exact
allowlist subtraction, DNS expansion/limits, optimizer equivalence, standalone
script generation, TOML updates, and eBPF key/counter encoding. CI additionally
compiles and loads the actual BPF object and exercises IPv4/IPv6 ingress/egress
blocking on a veth/network namespace with iptables blocks removed, plus allowed
traffic, replacement, counters and removal. It also checks real ipset loading and
Unbound configuration parsing.

Do not run the privileged integration script on a production host: although traffic
uses a test namespace, it also creates host links and uses the loader's fixed
state/pin paths. The unit suite is safe to run without applying firewall rules.
DNS tests use injected resolvers; a passing suite does not certify live feed uptime.

## Documentation maintenance

Update the option table when `cli()` changes, and check `python blocklists --help`.
Keep examples offline and non-mutating by default. Document exact coverage,
atomicity, and telemetry limits instead of promising complete DNS enumeration or
unbypassable enforcement. Runtime defaults and implementation are authoritative.

The README is the short entry point; the wiki pages contain the complete manual.
Keep the wiki source in the same change as code updates, then publish it with
`scripts/publish-wiki.sh`. The script requires normal Git write access to the
wiki and an initialized wiki repository; it does not provision credentials.

---
[Documentation home](Home.md) · [Source repository](https://github.com/ckcameron/python-blocklists)

## Publishing the wiki

Create the first Home page in the repository's Wiki tab if the wiki has never
been initialized. Then, from a machine with Git write access:

```sh
sh scripts/publish-wiki.sh
# Or reuse a clean, authenticated checkout:
sh scripts/publish-wiki.sh /path/to/python-blocklists.wiki
```

The publisher converts repository-relative `.md` links to wiki page routes,
retains unrelated pages, refuses a dirty checkout, fast-forwards before editing,
and never force-pushes. Git uses your configured identity and authentication;
no token belongs in this script or the repository. A concurrent wiki edit may
reject the push; resolve it in a retained checkout and retry.
