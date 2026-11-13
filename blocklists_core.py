"""Parse feeds, enrich through DNS, and generate deployable blocking bundles."""

# Copyright 2025-2026 CK Cameron. SPDX-License-Identifier: GPL-3.0-only
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager, nullcontext
from http.client import HTTPException
import ipaddress as ip
import json
import logging
from pathlib import Path
from queue import SimpleQueue
import re
import shutil
import subprocess
import sys
import tempfile
from threading import Event
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from default_sources import DEFAULT_BLOCKLISTS
from blocklists_progress import Progress

LOG = logging.getLogger("blocklists")
LOCAL_NETS = """0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8
169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4
::/128 ::1/128 ::ffff:0:0/96 fc00::/7 fe80::/10 ff00::/8""".split()
DNS_LOCAL_NETS = tuple(ip.ip_network(network) for network in (*LOCAL_NETS, "fec0::/10"))
LOCAL_DNS_ZONES = (
    "home.arpa",
    "in-addr.arpa",
    "ip6.arpa",
    "local",
    "localhost",
    "internal",
    "lan",
    "localdomain",
)
DNS_RECORD = re.compile(
    r"^(?:(?P<owner>\S+)\s+)?(?:(?:\d[\dwdhms]*|IN|CH|HS)\s+)*"
    r"(?P<kind>PTR|TYPE12|A|AAAA|CNAME|DNAME|NS|MX|SRV|TXT|SOA)\s+"
    r"(?P<value>\S+)(?:\s|$)",
    re.IGNORECASE,
)


def domain(value):
    """Normalize a DNS hostname, without accepting shell/config metacharacters."""
    value = value.strip().rstrip(".").lower()
    if value.startswith("*."):
        value = value[2:]
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = value.split(".")
    if len(value) > 253 or len(labels) < 2 or labels[-1].isdigit():
        return None
    if value == "localhost" or value.endswith(".localhost"):
        return None
    if all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
        return value
    return None


def local_dns_name(name):
    """Recognize local-only and reverse DNS zones after name normalization."""
    return any(name == zone or name.endswith("." + zone) for zone in LOCAL_DNS_ZONES)


def ignore_dns_record(line):
    """Keep DNS record fields from being mistaken for independent indicators."""
    if line.lower().startswith("ptr-record="):
        return True
    record = DNS_RECORD.match(line)
    if record is None:
        return False
    return ignore_dns_fields(record["kind"], record["owner"], record["value"])


def ignore_dns_fields(kind, owner, value):
    kind = str(kind).upper()
    if kind in ("12", "PTR", "TYPE12"):
        return True
    if isinstance(owner, str) and local_dns_name(owner.rstrip(".").lower()):
        return True
    if not isinstance(value, str):
        return False
    if kind in ("5", "39", "CNAME", "DNAME"):
        return local_dns_name(value.rstrip(".").lower())
    if kind not in ("1", "28", "A", "AAAA"):
        return False
    try:
        address = ip.ip_address(value)
    except ValueError:
        return False
    return any(address in network for network in DNS_LOCAL_NETS)


def networks(value):
    """Return exact CIDRs for an address, CIDR/netmask, or inclusive IP range."""
    try:
        return [ip.ip_network(value, strict=False)]
    except ValueError:
        pass
    if "-" in value:
        try:
            a, b = (ip.ip_address(x.strip()) for x in value.split("-", 1))
            return list(ip.summarize_address_range(a, b))
        except (ValueError, TypeError):
            pass
    return []


def parse_text(text, on_progress=None, on_domain=None, *, include_local_names=False):
    """Recognize list records, never scrape domains out of comments or prose.

    Supports IP/CIDR/range, hosts, URLs, CSV/TSV tokens, JSON values,
    domain-only Adblock rules, dnsmasq address/server and Unbound local-zone.
    Contextual Adblock rules are skipped rather than widened to whole domains.
    """
    nets, names = set(), set()
    ignored = 0
    stripped = text.lstrip("\ufeff \r\n\t")
    if stripped.startswith(("{", "[")):
        try:
            obj = json.loads(stripped)
        except ValueError:
            pass
        else:

            def strings(v):
                if isinstance(v, str):
                    yield v
                elif isinstance(v, list):
                    for child in v:
                        yield from strings(child)
                elif isinstance(v, dict):
                    record_type = v.get("type", v.get("rrtype"))
                    owner = v.get("owner", v.get("name"))
                    value = v.get("data", v.get("target", v.get("address")))
                    if record_type is not None and ignore_dns_fields(
                        record_type, owner, value
                    ):
                        return
                    for child in v.values():
                        yield from strings(child)

            text = "\n".join(strings(obj))
    rows = text.splitlines()
    for line_number, raw in enumerate(rows, 1):
        if on_progress and (
            line_number == 1 or line_number % 1024 == 0 or line_number == len(rows)
        ):
            on_progress(line_number, len(rows))
        line = raw.strip().lstrip("\ufeff")
        if not line or line.startswith(("#", "!", ";", "[", "@@")):
            continue
        # Cosmetic filters contain a '#' but are not domain-blocking rules.
        if "##" in line or "#@#" in line or "#?#" in line:
            ignored += 1
            continue
        line = re.sub(r"\s+#.*$", "", line).split(";", 1)[0].strip()
        if not line:
            continue
        if ignore_dns_record(line):
            ignored += 1
            continue
        rule = re.fullmatch(r"\|\|([^/^$|^]+)\^?", line)
        zone = re.fullmatch(
            r'local-zone:\s*["\']?([^\s"\']+)["\']?\s+(?:always_nxdomain|refuse|always_refuse|static)',
            line,
        )
        dnsmasq = re.fullmatch(
            r"(?:address|server)=/([^/]+(?:/[^/]+)*)/(?:#|[\d.:]*)", line
        )
        if rule or zone:
            line = (rule or zone).group(1)
        elif dnsmasq:
            line = dnsmasq.group(1).replace("/", " ")
        elif (
            line.startswith(("||", "|", "@", "/", "local-", "address=", "server="))
            or "$" in line
        ):
            ignored += 1
            continue
        found = networks(line)
        if found:
            nets.update(found)
            continue
        tokens = re.split(r"[\s,]+", line)
        # Hosts sink addresses are redirects, not threats to block.
        sentinel = (
            tokens[0] in ("0.0.0.0", "127.0.0.1", "::", "::1") and len(tokens) > 1
        )
        accepted = False
        for idx, token in enumerate(tokens):
            token = token.strip("\"'")
            if sentinel and idx == 0:
                continue
            if "://" in token:
                try:
                    parsed = urlsplit(token)
                    token = (
                        parsed.hostname
                        if parsed.scheme in ("http", "https", "ftp")
                        else None
                    )
                except ValueError:
                    token = None
                if not token:
                    continue
            found = networks(token)
            if found:
                nets.update(found)
                accepted = True
            else:
                name = domain(token)
                if name and (include_local_names or not local_dns_name(name)):
                    if on_domain and name not in names:
                        on_domain(name)
                    names.add(name)
                    accepted = True
        if not accepted:
            ignored += 1
    return nets, names, ignored


def collapse(nets):
    """Return a deterministic minimal CIDR cover, keeping address families separate."""
    return [
        n
        for version in (4, 6)
        for n in ip.collapse_addresses(x for x in nets if x.version == version)
    ]


def subtract(nets, exclusions):
    """Linear interval subtraction after sorting; never enumerate IP networks."""
    result = []
    for version, cls in ((4, ip.IPv4Address), (6, ip.IPv6Address)):
        blocked = [n for n in collapse(nets) if n.version == version]
        allowed = [
            (int(n.network_address), int(n.broadcast_address))
            for n in collapse(exclusions)
            if n.version == version
        ]
        # Both interval lists are sorted; skip exclusions entirely to the left.
        j = 0
        for n in blocked:
            lo, hi = int(n.network_address), int(n.broadcast_address)
            while j < len(allowed) and allowed[j][1] < lo:
                j += 1
            k = j
            while k < len(allowed) and allowed[k][0] <= hi:
                a, b = allowed[k]
                if a > lo:
                    result.extend(ip.summarize_address_range(cls(lo), cls(a - 1)))
                lo = max(lo, b + 1)
                if lo > hi:
                    break
                k += 1
            if lo <= hi:
                result.extend(ip.summarize_address_range(cls(lo), cls(hi)))
    return result


def domain_allowed(name, allowed):
    # Avoid emitting a parent zone that would override an allowed child.
    """Exclude an allowed zone, its descendants, and ancestors that would block it."""
    return any(
        name == a or name.endswith("." + a) or a.endswith("." + name) for a in allowed
    )


class Resolver:
    """dnspython has actual per-query deadlines (unlike libc getaddrinfo)."""

    def __init__(self, timeout, nameservers):
        import dns.resolver

        self.resolver = dns.resolver.Resolver()
        self.timeout = timeout
        if nameservers:
            self.resolver.nameservers = nameservers

    def query(self, task):
        """Return (task, answers, error_name), treating DNS failures as report data."""
        import dns.exception
        import dns.rdatatype

        name, kind = task
        if kind not in ("A", "AAAA"):
            return task, [], None
        try:
            answer = self.resolver.resolve(
                name + ".", kind, lifetime=self.timeout, search=False
            )
            canonical = domain(answer.canonical_name.to_text(omit_final_dot=True))
            if canonical is None or local_dns_name(canonical):
                return task, [], None
            expected_type = dns.rdatatype.from_text(kind)
            return task, [r.address for r in answer if r.rdtype == expected_type], None
        except dns.exception.DNSException as exc:
            return task, [], type(exc).__name__


def enrich(
    nets,
    names,
    allowed_nets,
    allowed_names,
    args,
    report,
    resolver=None,
    progress=None,
    queries=None,
    forward_nets=(),
):
    """Add allowed addresses from forward lookups of eligible feed domains."""
    progress = progress or Progress("off")
    nets, names = set(nets), set(names)
    query_context = (
        nullcontext(queries)
        if queries is not None
        else DNSQueries(args, progress, resolver)
    )
    eligible = sorted(name for name in names if dns_name_eligible(name, allowed_names))
    with query_context as queries:
        progress.start("[4/7] DNS enrichment", detail="Resolving public A/AAAA records")
        queries.run(forward_tasks(eligible), nets, allowed_nets)
    nets.update(forward_nets)
    pending_domains = [
        name
        for name in eligible
        if any((name, kind) not in queries.seen for kind in ("A", "AAAA"))
    ]
    report.update(
        dns_queries=len(queries.seen),
        dns_failures=queries.failures,
        dns_unqueried_domains=pending_domains,
        ptr_skipped_networks=[],
        dns_round_limit=1,
        associations=queries.associations,
    )
    if queries.budget_exhausted:
        report["dns_budget_exhausted"] = True
        LOG.warning("DNS query budget reached; see report.json")
    if pending_domains:
        LOG.warning(
            "%d domains await forward lookup; increase --max-dns-queries (see report.json)",
            len(pending_domains),
        )
    return nets, names


def dns_name_eligible(name, allowed_names):
    return not local_dns_name(name) and not domain_allowed(name, allowed_names)


def forward_tasks(names):
    return ((name, kind) for name in names for kind in ("A", "AAAA"))


class DNSQueries:
    """Reuse one worker pool and keep only a rolling window of futures in flight."""

    def __init__(self, args, progress, resolver=None):
        self.resolver = resolver
        self.timeout = args.dns_timeout
        self.nameservers = args.resolver
        self.progress = progress
        self.limit = args.max_dns_queries
        self.window = args.workers * 4
        self.pool = ThreadPoolExecutor(max_workers=args.workers)
        self.seen = set()
        self.failures = {}
        self.associations = []
        self.budget_exhausted = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.pool.shutdown(cancel_futures=True)

    def query(self, task):
        result = self.resolver.query(task)
        (name, kind), values, error = result
        outcome = error or f"{len(values)} answer(s)"
        self.progress.dns_update(completed=1, detail=f"{kind} {name}: {outcome}")
        return result

    def run(self, tasks, nets, allowed_nets, stopped=None):
        """Submit distinct tasks and apply completed answers on the calling thread."""
        ready = SimpleQueue()
        pending = set()

        def receive():
            future = ready.get()
            pending.remove(future)
            (name, kind), values, error = future.result()
            if error:
                self.failures[error] = self.failures.get(error, 0) + 1
            public_answers = []
            for value in values:
                address = ip.ip_address(value)
                if any(address in network for network in DNS_LOCAL_NETS):
                    continue
                public_answers.append(value)
                if not any(address in network for network in allowed_nets):
                    nets.add(ip.ip_network(address))
            if public_answers:
                self.associations.append(
                    {"name": name, "type": kind, "answers": public_answers}
                )

        try:
            for task in tasks:
                if task in self.seen:
                    continue
                if self.limit is not None and len(self.seen) >= self.limit:
                    self.budget_exhausted = True
                    break
                if len(pending) == self.window:
                    receive()
                if stopped and stopped.is_set():
                    break
                if self.resolver is None:
                    self.resolver = Resolver(self.timeout, self.nameservers)
                self.seen.add(task)
                self.progress.dns_update(scheduled=1)
                future = self.pool.submit(self.query, task)
                pending.add(future)
                future.add_done_callback(ready.put)
            while pending and (stopped is None or not stopped.is_set()):
                receive()
        finally:
            for future in pending:
                future.cancel()


@contextmanager
def background_forward_dns(queries, allowed_nets, allowed_names):
    """Send newly parsed domains to DNS without making the feed reader wait."""
    input_names = SimpleQueue()
    stopped = Event()
    forward_nets = set()

    def eligible_names():
        for name in iter(input_names.get, None):
            if stopped.is_set():
                return
            if dns_name_eligible(name, allowed_names):
                yield name

    with ThreadPoolExecutor(max_workers=1) as coordinator:
        future = coordinator.submit(
            queries.run,
            forward_tasks(eligible_names()),
            forward_nets,
            allowed_nets,
            stopped,
        )

        def collect():
            input_names.put(None)
            future.result()
            return forward_nets

        try:
            yield input_names.put, collect
        finally:
            stopped.set()
            input_names.put(None)


def reduce_with_iprange(executable, family, version, args):
    """Reduce one address family and verify the result covers the exact input."""
    if version == 6:
        probe = subprocess.run(
            [executable, "--has-ipv6"], capture_output=True, timeout=10
        )
        if probe.returncode != 0:
            raise ValueError("iprange does not support IPv6")
    command = [executable] + (["-6"] if version == 6 else [])
    command += [
        "--ipset-reduce",
        str(args.reduce_percent),
        "--ipset-reduce-entries",
        str(args.reduce_entries),
    ]
    proc = subprocess.run(
        command,
        input=lines(family),
        text=True,
        capture_output=True,
        timeout=300,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip()[:500]
        status = f"iprange exited with status {proc.returncode}"
        raise ValueError(f"{status} ({detail})" if detail else status)
    reduced = [
        ip.ip_network(line.strip()) for line in proc.stdout.splitlines() if line.strip()
    ]
    if collapse(reduced) != family:
        raise ValueError("iprange changed address coverage")
    return reduced


def optimize(nets, args, report, progress=None):
    """Reduce hash:net prefix diversity, verifying exact address-set equality."""
    progress = progress or Progress("off")
    progress.start("[6/7] Optimize IP sets", 2, "Collapsing exact address coverage")
    original = collapse(nets)
    result = []
    executable = shutil.which(args.iprange)
    if args.optimizer == "iprange" and not executable:
        raise ValueError(
            "iprange is required; install it or explicitly use --optimizer python"
        )
    for version in (4, 6):
        progress.update(
            detail=f"IPv{version}: {args.optimizer} optimization and coverage verification"
        )
        family = [n for n in original if n.version == version]
        reduced = family
        fallback_reason = None
        if family and args.optimizer == "iprange":
            try:
                reduced = reduce_with_iprange(executable, family, version, args)
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                fallback_reason = str(exc)
                LOG.warning(
                    "IPv%d optimization failed (%s). Using exact Python CIDRs.",
                    version,
                    fallback_reason,
                )
                if version == 6:
                    report["ipv6_optimizer_fallback"] = True
        # hash:net cannot store /0; two /1s cover the identical address set.
        reduced = [
            part
            for n in reduced
            for part in (n.subnets(prefixlen_diff=1) if n.prefixlen == 0 else [n])
        ]
        result.extend(reduced)
        progress.update(
            detail=f"IPv{version}: {len(family):,} compact CIDRs -> {len(reduced):,} ipset entries",
            advance=1,
        )
        optimization = {
            "minimal_cidrs": len(family),
            "ipset_entries": len(reduced),
            "prefix_lengths": len({n.prefixlen for n in reduced}),
            "addresses": sum(n.num_addresses for n in family),
        }
        if fallback_reason is not None:
            optimization["fallback_reason"] = fallback_reason
        report[f"ipv{version}_optimization"] = optimization
    return original, result


def lines(values):
    """Serialize records with one newline per item; an empty list stays empty."""
    return "".join(f"{v}\n" for v in values)


def list_records(nets, names):
    """Expose the three reusable text lists in their normal feed format."""
    return {
        "ips-v4.txt": (n for n in nets if n.version == 4),
        "ips-v6.txt": (n for n in nets if n.version == 6),
        "domains.txt": sorted(names),
    }


class Checkpoints:
    """Publish each snapshot as one directory and retain it independently of staging."""

    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.run = None

    def __call__(self, stage, nets, names):
        if not nets and not names:
            return
        if self.run is None:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            self.run = Path(
                tempfile.mkdtemp(prefix="checkpoints-", dir=self.output_dir)
            )
            LOG.info("Saving recovery checkpoints in %s", self.run)
        ordered_nets = sorted(
            nets, key=lambda n: (n.version, n.network_address, n.prefixlen)
        )
        with tempfile.TemporaryDirectory(prefix=".staging-", dir=self.run) as staging:
            directory = Path(staging)
            for filename, records in list_records(ordered_nets, names).items():
                with (directory / filename).open("w", encoding="utf-8") as stream:
                    stream.writelines(f"{record}\n" for record in records)
            directory.rename(self.run / stage)


def firewall_script(nets, args, remove=False):
    """One hash:net per family, staged restore + atomic per-set swap."""
    out = [
        "#!/bin/sh",
        "set -eu",
        "umask 077",
        '[ "$(id -u)" -eq 0 ] || { echo "Run as root" >&2; exit 1; }',
        "command -v flock >/dev/null",
        "exec 9>/run/lock/python-blocklists.lock",
        "flock -x 9",
    ]
    for cmd in ("ipset", "iptables", "ip6tables"):
        out.append(f"command -v {cmd} >/dev/null")
    names = [
        (4, args.ipset4_name, "inet", "iptables"),
        (6, args.ipset6_name, "inet6", "ip6tables"),
    ]
    if not remove:
        # Stage BOTH families before touching either live set.
        for version, name, family, cmd in names:
            values = [n for n in nets if n.version == version]
            capacity = max(1024, len(values) * 2)
            hashsize = max(
                1024, 1 << max(0, (max(1, len(values) // 2) - 1).bit_length())
            )
            out += [
                f"if ! ipset list {name} >/dev/null 2>&1; then",
                f"  ipset create {name} hash:net family {family}",
                "fi",
                f"ipset destroy {name}_next 2>/dev/null || true",
                "ipset restore <<'BLOCKLISTS_IPSET'",
                f"create {name}_next hash:net family {family} hashsize {hashsize} maxelem {capacity}",
            ]
            out += [f"add {name}_next {n}" for n in values]
            out += ["BLOCKLISTS_IPSET"]
        for _, name, _, _ in names:
            out += [f"ipset swap {name}_next {name}", f"ipset destroy {name}_next"]
    for _, name, _, cmd in names:
        for chain, direction in [
            ("INPUT", "src"),
            ("OUTPUT", "dst"),
            ("FORWARD", "src"),
            ("FORWARD", "dst"),
        ]:
            rule = f"{chain} -m set --match-set {name} {direction} -m comment --comment python-blocklists -j DROP"
            if not remove:
                out += [
                    f"if ! {cmd} -w -C {rule} 2>/dev/null; then",
                    f"  {cmd} -w -I {rule}",
                    "fi",
                ]
            else:
                out += [
                    f"while {cmd} -w -C {rule} 2>/dev/null; do",
                    f"  {cmd} -w -D {rule}",
                    "done",
                ]
    if remove:
        for _, name, _, _ in names:
            out += [f"ipset destroy {name}"]
    return "\n".join(out) + "\n"


def write_bundle(directory, compact, optimized, names, args, report, progress=None):
    """Render lists and standalone installers into the caller-provided staging directory.

    Compact prefixes feed eBPF and text outputs; expanded prefixes feed ipset.
    The caller publishes these files only after every payload has been written."""
    progress = progress or Progress("off")
    progress.start(
        "[7/7] Build output bundle",
        detail="Rendering blocklists and self-contained installers",
    )
    directory.mkdir(parents=True, exist_ok=True)
    payloads = {
        **{
            name: lines(records)
            for name, records in list_records(compact, names).items()
        },
        "unbound-blocklists.conf": "server:\n"
        + lines(f'    local-zone: "{d}" always_nxdomain' for d in sorted(names)),
        "dnscrypt-blocked-names.txt": lines(sorted(names)),
        "hosts.deny.blocklists": lines(
            (
                f"ALL: {n.network_address}/{n.netmask}"
                if n.version == 4
                else f"ALL: [{n.network_address}]/{n.prefixlen}"
            )
            for n in compact
        ),
        "apply-firewall.sh": firewall_script(optimized, args),
        "remove-firewall.sh": firewall_script(optimized, args, remove=True),
        "report.json": json.dumps(report, indent=2, sort_keys=True) + "\n",
    }
    installer = Path(__file__).with_name("blocklists_install.py").read_text()
    ebpf_dir = Path(__file__).parent / "ebpf"
    ebpf_source = (ebpf_dir / "blocklists.bpf.c").read_text()
    ebpf_loader = (ebpf_dir / "loader.py").read_text()
    payloads["apply-ebpf.py"] = (
        "#!/usr/bin/env python3\n"
        + ebpf_loader
        + "\n"
        + f"SOURCE = {ebpf_source!r}\nNETWORKS = {[str(n) for n in compact]!r}\n"
        + 'if __name__ == "__main__":\n    main(SOURCE, NETWORKS)\n'
    )
    payloads["blocklists.bpf.c"] = ebpf_source
    for kind, filename in [
        ("wrappers", "hosts.deny.blocklists"),
        ("unbound", "unbound-blocklists.conf"),
        ("dnscrypt", "dnscrypt-blocked-names.txt"),
    ]:
        payloads[f"apply-{kind}.py"] = (
            "#!/usr/bin/env python3\n"
            + installer
            + "\n"
            + f"PAYLOAD = {payloads[filename]!r}\n"
            + f'if __name__ == "__main__":\n    main({kind!r}, PAYLOAD)\n'
        )
    progress.start("[7/7] Write output bundle", len(payloads), "Writing staged files")
    for name, text in payloads.items():
        progress.update(detail=name)
        target = directory / name
        target.write_text(text, encoding="utf-8")
        target.chmod(0o755 if name.endswith((".sh", ".py")) else 0o644)
        progress.update(advance=1)


def positive(value):
    """Parse a strictly positive integer for a bounded-work CLI option."""
    value = int(value)
    if value < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def enabled(value):
    """Parse the historical boolean spellings used by compatibility options."""
    if str(value).lower() not in ("1", "y", "yes", "true", "0", "n", "no", "false"):
        raise argparse.ArgumentTypeError("expected 1/0 or Y/N")
    return str(value).lower() in ("1", "y", "yes", "true")


def read_source(stream, limit, source, progress):
    """Read at most limit + 1 bytes so the caller can detect an oversized source.

    Reading one extra byte distinguishes exact-size input from truncated input.
    The limit bounds each feed, not the combined memory used by all parsed feeds."""
    chunks, size = [], 0
    while size <= limit:
        chunk = stream.read(min(65536, limit + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        progress.update(detail=f"Reading {source}: {size:,} bytes received")
    return b"".join(chunks)


def cli():
    """Build the generator CLI; parsing arguments never installs blocking rules."""
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    p.add_argument(
        "--progress",
        choices=("auto", "plain", "off"),
        default="auto",
        help="stderr progress: auto animates terminals; plain logs stages; off disables progress",
    )
    p.add_argument(
        "inputs", nargs="*", help="local files/directories or HTTP(S) feed URLs"
    )
    p.add_argument(
        "-f", "--files", default="", help="legacy comma-separated local paths"
    )
    p.add_argument("-u", "--urls", default="", help="legacy comma-separated feed URLs")
    p.add_argument(
        "-el", "--external_lists", help="file with one URL or NAME URL per line"
    )
    p.add_argument(
        "-dl",
        "--default_lists",
        type=enabled,
        nargs="?",
        const=True,
        default=False,
        help="include the curated feed URLs",
    )
    p.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("generated"),
        help="directory for the generated bundle",
    )
    p.add_argument(
        "-ad", "--allowed_domains", type=Path, help="file of domain exclusions"
    )
    p.add_argument(
        "-ai", "--allowed_ips", type=Path, help="file of address/CIDR exclusions"
    )
    p.add_argument(
        "--include-local",
        action="store_true",
        help="keep explicit local/private/multicast IP entries from feeds",
    )
    p.add_argument(
        "--no-dns",
        action="store_true",
        help="skip DNS enrichment; URL inputs still download",
    )
    p.add_argument(
        "--resolver", action="append", default=[], help="DNS server IP; repeatable"
    )
    p.add_argument(
        "--dns-timeout",
        type=float,
        default=3.0,
        help="deadline per DNS query in seconds",
    )
    p.add_argument(
        "--dns-rounds",
        type=positive,
        default=3,
        help="legacy option accepted for compatibility",
    )
    p.add_argument(
        "--max-dns-queries",
        type=positive,
        help="optional total DNS query limit (unlimited by default)",
    )
    p.add_argument(
        "--ptr-max-addresses",
        type=positive,
        default=4096,
        help="legacy option accepted for compatibility",
    )
    p.add_argument(
        "--workers", type=positive, default=32, help="maximum concurrent DNS workers"
    )
    p.add_argument(
        "--optimizer",
        choices=("iprange", "python"),
        default="iprange",
        help="IP prefix optimization backend",
    )
    p.add_argument("--iprange", default="iprange", help="iprange executable")
    p.add_argument(
        "--reduce-percent",
        type=int,
        default=20,
        help="iprange extra-entry percentage budget",
    )
    p.add_argument(
        "--reduce-entries",
        type=positive,
        default=16384,
        help="iprange minimum entry budget",
    )
    p.add_argument(
        "-in4", "--ipset4_name", default="blocklists4", help="IPv4 hash:net set name"
    )
    p.add_argument(
        "-in6", "--ipset6_name", default="blocklists6", help="IPv6 hash:net set name"
    )
    p.add_argument(
        "--max-source-bytes",
        type=positive,
        default=64 * 1024 * 1024,
        help="maximum bytes per input source",
    )
    p.add_argument(
        "--allow-partial",
        action="store_true",
        help="explicitly permit failed input sources",
    )
    p.add_argument(
        "--allow-empty", action="store_true", help="permit an empty block bundle"
    )
    for flag, name in [
        ("-oi4", "output_ip_list_v4"),
        ("-oi6", "output_ip_list_v6"),
        ("-od", "output_domain_list"),
    ]:
        p.add_argument(
            flag,
            "--" + name,
            type=Path,
            help="also write a copy of the unified list here",
        )
    p.add_argument(
        "-6",
        "--ipv6",
        type=enabled,
        nargs="?",
        const=True,
        default=True,
        help="IPv6 enabled by default",
    )
    p.add_argument(
        "-i",
        "--interactive",
        type=enabled,
        nargs="?",
        const=True,
        default=False,
        help="prompt for comma-separated input paths",
    )
    p.add_argument(
        "-is",
        "--ipset",
        type=enabled,
        nargs="?",
        const=True,
        default=False,
        help="compatibility: installers are always generated",
    )
    p.add_argument(
        "-ipt",
        "--iptables_rules",
        type=enabled,
        nargs="?",
        const=True,
        default=False,
        help="compatibility: installers are always generated, never executed",
    )
    return p


def main(argv=None):
    """Discover, parse, enrich, and stage a bundle; return a shell-compatible status."""
    p = cli()
    args = p.parse_args(argv)
    checkpoint = Checkpoints(args.output_dir)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    with Progress(args.progress) as progress, progress.logging(
        LOG
    ), ExitStack() as dns_stack:
        try:
            if args.dns_timeout <= 0 or args.reduce_percent < 0:
                raise ValueError(
                    "DNS timeout must be positive and reduce-percent nonnegative"
                )
            for name in (args.ipset4_name, args.ipset6_name):
                if not re.fullmatch("[A-Za-z][A-Za-z0-9_-]{0,24}", name):
                    raise ValueError(
                        "ipset names must start with a letter and contain 1–25 letters/digits/_/-"
                    )
            if args.ipset4_name == args.ipset6_name:
                raise ValueError("IPv4 and IPv6 ipset names must differ")
            if args.interactive:
                args.files = (
                    input("Input paths (comma separated): ").strip() or args.files
                )
            progress.start(
                "[1/7] Discover inputs", detail="Reading source configuration"
            )
            sources = args.inputs + [
                s.strip()
                for s in (args.files + "," + args.urls).split(",")
                if s.strip()
            ]
            if args.default_lists:
                sources += [url for _, url in DEFAULT_BLOCKLISTS]
            if args.external_lists:
                for line in Path(args.external_lists).read_text().splitlines():
                    line = line.split("#", 1)[0].strip()
                    if line:
                        sources.append(line.split()[-1])
            if not sources:
                p.error(
                    "provide input paths, URLs, --external_lists, or --default_lists"
                )
            expanded = []
            progress.start("[1/7] Discover input files", len(sources))
            for source in sources:
                progress.update(detail=source)
                if (
                    not source.startswith(("https://", "http://"))
                    and Path(source).is_dir()
                ):
                    expanded += [
                        str(f)
                        for f in sorted(Path(source).rglob("*"))
                        if f.is_file()
                        and not f.resolve().is_relative_to(args.output_dir.resolve())
                    ]
                else:
                    expanded.append(source)
                progress.update(advance=1)
            progress.start(
                "[2/7] Load exclusions",
                detail="Built-in networks and optional allowlist files",
            )
            allowed_nets = (
                [ip.ip_network(n) for n in LOCAL_NETS] if not args.include_local else []
            )
            allowed_names = set()
            if args.allowed_ips:
                allowed_nets += list(parse_text(args.allowed_ips.read_text())[0])
            if args.allowed_domains:
                allowed_names = parse_text(
                    args.allowed_domains.read_text(), include_local_names=True
                )[1]
            nets, names = set(), set()
            report = {"sources": [], "failed_sources": [], "optimizer": args.optimizer}
            queries = on_domain = collect_forward = None
            # An explicit budget keeps the existing sorted query priority.
            if not args.no_dns and args.max_dns_queries is None:
                queries = dns_stack.enter_context(DNSQueries(args, progress))
                submit_domain, collect_forward = dns_stack.enter_context(
                    background_forward_dns(queries, allowed_nets, allowed_names)
                )

                def on_domain(name):
                    if name not in names:
                        submit_domain(name)

            unique_sources = list(dict.fromkeys(expanded))
            progress.start("[2/7] Read and parse feeds", len(unique_sources))
            for source in unique_sources:
                progress.update(detail=f"Reading {source}")
                try:
                    if source.startswith(("https://", "http://")):
                        with urlopen(
                            Request(
                                source, headers={"User-Agent": "python-blocklists/2"}
                            ),
                            timeout=30,
                        ) as response:
                            data = read_source(
                                response, args.max_source_bytes, source, progress
                            )
                    else:
                        with open(source, "rb") as stream:
                            data = read_source(
                                stream, args.max_source_bytes, source, progress
                            )
                    if len(data) > args.max_source_bytes:
                        raise ValueError("source exceeds --max-source-bytes")
                    progress.update(detail=f"Parsing {source}: {len(data):,} bytes")
                    ns, ds, ignored = parse_text(
                        data.decode("utf-8-sig"),
                        on_progress=lambda done, total: progress.update(
                            detail=f"Parsing {source}: line {done:,}/{total:,}"
                        ),
                        on_domain=on_domain,
                    )
                    nets.update(ns)
                    names.update(ds)
                    report["sources"].append(
                        {
                            "source": source,
                            "networks": len(ns),
                            "domains": len(ds),
                            "ignored_lines": ignored,
                        }
                    )
                except (OSError, ValueError, HTTPException, KeyboardInterrupt) as exc:
                    if not args.allow_partial or isinstance(exc, KeyboardInterrupt):
                        try:
                            checkpoint("02-partial-sources", nets, names)
                        except OSError as checkpoint_error:
                            LOG.warning(
                                "Could not save partial inputs: %s", checkpoint_error
                            )
                        if isinstance(exc, KeyboardInterrupt):
                            raise
                        raise ValueError(f"{source}: {exc}") from exc
                    report["failed_sources"].append(
                        {"source": source, "error": str(exc)}
                    )
                    LOG.warning("%s: %s", source, exc)
                progress.update(
                    advance=1,
                    detail=f'{source}; {len(nets):,} networks, {len(names):,} domains; {len(report["failed_sources"])} failed feeds',
                )
            checkpoint("03-before-exclusions", nets, names)
            progress.start("[3/7] Apply exclusions", len(nets) + len(names))
            filtered_nets = set()
            for n in nets:
                filtered_nets.update(subtract([n], allowed_nets))
                progress.update(detail=f"Network {n}", advance=1)
            nets = filtered_nets
            filtered_names = set()
            for n in names:
                if not domain_allowed(n, allowed_names):
                    filtered_names.add(n)
                progress.update(detail=f"Domain {n}", advance=1)
            names = filtered_names
            if not args.ipv6:
                nets = {n for n in nets if n.version == 4}
            checkpoint("04-before-dns", nets, names)
            if not args.no_dns:
                if collect_forward:
                    progress.start(
                        "[4/7] DNS enrichment", detail="Finishing input domain lookups"
                    )
                nets, names = enrich(
                    nets,
                    names,
                    allowed_nets,
                    allowed_names,
                    args,
                    report,
                    progress=progress,
                    queries=queries,
                    forward_nets=collect_forward() if collect_forward else (),
                )
                dns_stack.close()
            else:
                progress.start("[4/7] DNS enrichment", detail="Skipped (--no-dns)")
            if not args.ipv6:
                nets = {n for n in nets if n.version == 4}
            checkpoint("05-before-final-exclusions", nets, names)
            progress.start(
                "[5/7] Final exclusions",
                detail=f"Filtering {len(nets):,} networks after enrichment",
            )
            nets = subtract(nets, allowed_nets)
            if not nets and not names and not args.allow_empty:
                raise ValueError("empty result; use --allow-empty only if intentional")
            checkpoint("06-before-optimization", nets, names)
            compact, optimized = optimize(nets, args, report, progress=progress)
            checkpoint("07-before-bundle", compact, names)
            report["domain_count"] = len(names)
            report["dns_enabled"] = not args.no_dns
            # Generate everything successfully in staging before replacing any output.
            args.output_dir.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(dir=args.output_dir.parent) as staging:
                write_bundle(
                    Path(staging),
                    compact,
                    optimized,
                    names,
                    args,
                    report,
                    progress=progress,
                )
                args.output_dir.mkdir(parents=True, exist_ok=True)
                staged_files = list(Path(staging).iterdir())
                progress.start(
                    "[7/7] Publish output bundle",
                    len(staged_files),
                    str(args.output_dir),
                )
                for f in staged_files:
                    progress.update(detail=f.name)
                    f.replace(args.output_dir / f.name)
                    progress.update(advance=1)
            for dest, name in [
                (args.output_ip_list_v4, "ips-v4.txt"),
                (args.output_ip_list_v6, "ips-v6.txt"),
                (args.output_domain_list, "domains.txt"),
            ]:
                if dest and dest.resolve() != (args.output_dir / name).resolve():
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    progress.update(detail=f"Copying {name} to {dest}")
                    shutil.copyfile(args.output_dir / name, dest)
            progress.finish()
            LOG.info(
                "Generated %s: %d domain names, %d ipset entries. Nothing installed.",
                args.output_dir,
                len(names),
                len(optimized),
            )
            return 0
        except (OSError, ValueError, ImportError, subprocess.SubprocessError) as exc:
            progress.finish("failed")
            LOG.error("%s", exc)
            return 1
