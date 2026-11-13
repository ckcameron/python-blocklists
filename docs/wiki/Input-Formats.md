# Input formats and sources

The input formats are bare domains, IPv4/IPv6 addresses, CIDRs, IPv4 dotted
netmasks, inclusive `IP-IP` ranges, hosts files, HTTP/HTTPS/FTP URLs, CSV/TSV
indicator tokens, JSON string values, unconditional `||domain^` Adblock rules,
dnsmasq `address=/domain/IP` / `server=/domain/`, and blocking Unbound `local-zone`
records. Hostnames are normalized to lowercase IDNA ASCII. Hosts-file redirect
addresses (`0.0.0.0`, `127.0.0.1`, `::`, `::1`) are not added as threats when
followed by names. Domain block entries cover the named zone and its subdomains.

This is not a complete Adblock policy engine: exceptions, cosmetic rules,
URL-path rules, and conditional rules are skipped, not widened into domain bans.
Provide explicit allowlist files when exceptions must be honored. JSON object
keys are metadata, not indicators; only string values are read. Do not feed it
arbitrary prose or HTML pages as threat lists.

## Accepted record examples

| Input | Interpretation |
|---|---|
| `198.51.100.7` | One IPv4 address |
| `2001:db8::7` | One IPv6 address |
| `198.51.100.7/24` | Network normalized to `198.51.100.0/24` |
| `198.51.100.0/255.255.255.0` | IPv4 network with dotted netmask |
| `198.51.100.1-198.51.100.9` | Inclusive range, converted to exact CIDRs |
| `Bad.Example.` | Normalized to `bad.example` |
| `0.0.0.0 bad.example tracker.example` | Two names; sink address omitted |
| `https://bad.example/path` | Hostname only, not a path-specific rule |
| `{"indicators": ["bad.example", "198.51.100.7"]}` | JSON string values recursively |
| `address=/bad.example/0.0.0.0` | The named domain; directive address is ignored |
| `local-zone: "bad.example" always_nxdomain` | The named domain |

The unconditional Adblock form is `||bad.example^`. CSV/TSV support tokenizes
whitespace and commas; it is not a general CSV parser with column selection or
quoted multiline records. Feed text must decode as UTF-8 (an initial BOM is
accepted). Bare hostnames need at least two DNS labels; IP address tokens are
handled separately. Wildcard input `*.bad.example` becomes `bad.example`.

Blank lines and lines beginning with `#`, `!`, `;`, `[`, or `@@` are skipped.
Skipped comments and exceptions do not all increment `ignored_lines`; that field
is a parser diagnostic, not a complete count of every discarded source line.
Successful JSON flattening also means counts refer to flattened string records.

## Source selection

Positional arguments accept files, directories, or HTTP(S) URLs. Directories are
walked recursively, including every file except those below the chosen output
directory. Avoid pointing the generator at the repository or arbitrary document
trees: input tokenization is intended for indicator feeds, not prose.

`--external_lists sources.txt` reads one URL or `NAME URL` per line. The last
whitespace-separated field is the source; text after `#` is removed. `--files`
and `--urls` retain the old comma-separated syntax. Duplicate source strings
are read once. FTP URLs are supported as records inside feeds, not as remote
feed download locations.

`--default_lists` selects the URLs in `default_sources.py`; availability, content,
and provider access requirements can change. Provider names are labels, not an
assurance that every listed endpoint is currently reachable. Downloads use a
30-second urllib timeout and a 64 MiB per-source byte cap by default; the timeout
is not a total wall-clock deadline for the entire download.

Sources with no recognized records, including empty files, contribute zero
records. Invalid UTF-8, oversized or unreadable sources, and failed downloads
fail the run unless `--allow-partial` is set. If the final combined result is
empty, generation requires `--allow-empty`.

---
[Documentation home](Home.md) · [Source repository](https://github.com/ckcameron/python-blocklists)
