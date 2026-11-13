import contextlib
import io
import ipaddress as ip
import json
from pathlib import Path
import random
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import blocklists_core as b
import blocklists_install as installer
from ebpf import loader


class Parsing(unittest.TestCase):
    def test_mixed(self):
        nets, names, _ = b.parse_text('''# ignore.example 1.1.1.1
0.0.0.0 ads.example track.example
::1 ipv6.example
198.51.100.8
2001:db8::1
198.51.100.0/25
198.51.100.128 - 198.51.100.255
||adblock.example^
https://url.example/path?q=foo.example
https://[2001:db8::2]/
address=/dnsmasq.example/#
local-zone: "unbound.example" always_nxdomain
"csv.example",198.51.100.9,42
EXAMPLE.ORG.
bücher.example
''')
        self.assertEqual(names, {'ads.example', 'track.example', 'ipv6.example', 'adblock.example', 'url.example',
                                 'dnsmasq.example', 'unbound.example', 'csv.example', 'example.org', 'xn--bcher-kva.example'})
        self.assertEqual(b.collapse(nets), [ip.ip_network('198.51.100.0/24'), ip.ip_network('2001:db8::1/128'), ip.ip_network('2001:db8::2/128')])

    def test_never_turn_exceptions_or_context_into_domain_blocks(self):
        nets, names, _ = b.parse_text('''@@||allowed.example^
||conditional.example^$third-party
cosmetic.example##.ad
invalid.example/path
999.999.999.999
bad.example; ignored.example
''')
        self.assertFalse(nets)
        self.assertEqual(names, {'bad.example'})

    def test_json(self):
        nets, names, _ = b.parse_text(json.dumps({'data': ['198.51.100.0/24', {'domain': 'example.org'}]}))
        self.assertEqual(names, {'example.org'})
        self.assertEqual(nets, {ip.ip_network('198.51.100.0/24')})

    def test_hostile_names(self):
        for name in ['x.example\n-j DROP', '$(id).example', 'x.example"', '*.com;touch /tmp/x', '-x.example', 'a' * 64 + '.example']:
            self.assertIsNone(b.domain(name))

    def test_ranges(self):
        self.assertEqual(sum(n.num_addresses for n in b.networks('2001:db8::1-2001:db8::ff')), 255)
        self.assertEqual(b.networks('198.51.100.2-198.51.100.1'), [])
        self.assertEqual(b.networks('198.51.100.1-2001:db8::1'), [])


class Networks(unittest.TestCase):
    def test_subtract_hole(self):
        blocked = b.subtract([ip.ip_network('198.51.100.0/24')], [ip.ip_network('198.51.100.42/32')])
        self.assertEqual(sum(n.num_addresses for n in blocked), 255)
        self.assertFalse(any(ip.ip_address('198.51.100.42') in n for n in blocked))

    def test_random_interval_subtraction_against_sets(self):
        rng = random.Random(42)
        base = int(ip.ip_address('198.51.100.0'))
        for _ in range(100):
            def generate():
                ranges = [sorted(rng.sample(range(256), 2)) for _ in range(5)]
                nets = [n for a, z in ranges for n in ip.summarize_address_range(ip.IPv4Address(base+a), ip.IPv4Address(base+z))]
                values = {i for a, z in ranges for i in range(base+a, base+z+1)}
                return nets, values
            ns, ns_values = generate()
            allowed, allowed_values = generate()
            actual = {int(i) for n in b.subtract(ns, allowed) for i in n}
            self.assertEqual(actual, ns_values - allowed_values)

    def test_zero_prefix_split(self):
        args = b.cli().parse_args(['--optimizer', 'python'])
        compact, optimized = b.optimize([ip.ip_network('::/0'), ip.ip_network('0.0.0.0/0')], args, {})
        self.assertEqual(len(optimized), 4)
        self.assertTrue(all(n.prefixlen == 1 for n in optimized))
        self.assertEqual(b.collapse(optimized), compact)

    def test_iprange_wrong_coverage_rejected(self):
        args = b.cli().parse_args([])
        proc = subprocess.CompletedProcess([], 0, '198.51.100.0/24\n', '')
        report = {}
        original = [ip.ip_network('198.51.100.1')]
        with patch.object(b.shutil, 'which', return_value='/usr/bin/iprange'), patch.object(b.subprocess, 'run', return_value=proc):
            compact, reduced = b.optimize(original, args, report)
        self.assertEqual((compact, reduced), (original, original))
        self.assertIn('coverage', report['ipv4_optimization']['fallback_reason'])

    def test_ipv6_iprange_failure_preserves_exact_coverage(self):
        args = b.cli().parse_args([])
        ipv4 = ip.ip_network('198.51.100.0/24')
        ipv6 = ip.ip_network('2001:db8::/120')
        reason = '--ipset-reduce is not supported in IPv6 mode'
        processes = [
            subprocess.CompletedProcess([], 0, '198.51.100.0/25\n198.51.100.128/25\n', ''),
            subprocess.CompletedProcess([], 0, b'yes', b''),
            subprocess.CompletedProcess([], 1, '', reason),
        ]
        report = {}
        with (
            patch.object(b.shutil, 'which', return_value='/usr/bin/iprange'),
            patch.object(b.subprocess, 'run', side_effect=processes) as run,
            self.assertLogs(b.LOG, 'WARNING') as warnings,
        ):
            compact, reduced = b.optimize([ipv4, ipv6], args, report)
        self.assertEqual(compact, [ipv4, ipv6])
        self.assertEqual(reduced, [*ipv4.subnets(), ipv6])
        self.assertEqual(run.call_args_list[-1].args[0][1], '-6')
        self.assertTrue(report['ipv6_optimizer_fallback'])
        self.assertNotIn('fallback_reason', report['ipv4_optimization'])
        self.assertIn(reason, report['ipv6_optimization']['fallback_reason'])
        self.assertIn(reason, warnings.output[0])

    def test_reduced_prefixes_not_collapsed_again(self):
        args = b.cli().parse_args([])
        proc = subprocess.CompletedProcess([], 0, '198.51.100.0/25\n198.51.100.128/25\n', '')
        with patch.object(b.shutil, 'which', return_value='/usr/bin/iprange'), patch.object(b.subprocess, 'run', return_value=proc):
            compact, reduced = b.optimize([ip.ip_network('198.51.100.0/24')], args, {})
        self.assertEqual((len(compact), len(reduced)), (1, 2))


class DNS(unittest.TestCase):
    def test_forward_lookups_skip_local_and_reverse_names(self):
        args = b.cli().parse_args([])
        answers = {('bad.example', 'A'): ['198.51.100.1'],
                   ('bad.example', 'AAAA'): ['2001:db8::8']}
        queried = []
        class Resolver:
            def query(self, task):
                queried.append(task)
                return task, answers.get(task, []), None
        report = {}
        explicit_names = {
            'bad.example', 'printer.local', 'router.home.arpa', 'a.localhost',
            '1.100.51.198.in-addr.arpa', 'a.ip6.arpa', 'dns.internal', 'a.lan',
            'a.localdomain',
        }
        explicit_network = ip.ip_network('198.51.100.0/24')
        nets, names = b.enrich({explicit_network}, explicit_names, [], set(), args, report, Resolver())
        self.assertEqual(set(queried), set(answers))
        self.assertEqual(nets, {explicit_network, ip.ip_network('198.51.100.1'), ip.ip_network('2001:db8::8')})
        self.assertEqual(names, explicit_names)
        self.assertEqual(report['dns_queries'], 2)
        self.assertEqual(report['dns_unqueried_domains'], [])

    def test_explicit_dns_query_budget(self):
        args = b.cli().parse_args(['--max-dns-queries', '2', '--dns-rounds', '5', '--ptr-max-addresses', '9'])
        class Resolver:
            def query(self, task):
                return task, [], None
        report = {}
        b.enrich(set(), {'a.example', 'b.example'}, [], set(), args, report, Resolver())
        self.assertEqual(report['dns_queries'], 2)
        self.assertEqual(report['dns_unqueried_domains'], ['b.example'])
        self.assertTrue(report['dns_budget_exhausted'])

    def test_allowed_dns_answer_excluded(self):
        args = b.cli().parse_args(['--include-local'])
        class Resolver:
            def query(self, task):
                values = ['127.0.0.1', '192.168.1.1', '198.51.100.1'] if task[1] == 'A' else ['fe80::1', 'fd00::1']
                return task, values, None
        local_feed = ip.ip_network('10.0.0.1')
        report = {}
        nets, _ = b.enrich({local_feed}, {'bad.example'}, [ip.ip_network('198.51.100.0/24')], set(), args, report, Resolver())
        self.assertEqual(nets, {local_feed})
        self.assertEqual(report['associations'], [
            {'name': 'bad.example', 'type': 'A', 'answers': ['198.51.100.1']},
        ])


class Installers(unittest.TestCase):
    def test_wrappers_preserves_manual_lines_and_replaces_stale(self):
        old = 'sshd: 1.2.3.4\n'
        one = installer.managed_block(old, 'ALL: 198.51.100.1/255.255.255.255\n')
        two = installer.managed_block(one, 'ALL: 198.51.100.2/255.255.255.255\n')
        self.assertIn(old, two)
        self.assertNotIn('198.51.100.1', two)
        self.assertEqual(installer.managed_block(two, 'ALL: 198.51.100.2/255.255.255.255\n'), two)

    def test_dnscrypt_table_edit(self):
        for original in ["server_names = ['x']\n", "[blocked_names]\n# blocked_names_file = 'old'\n[other]\nx=1\n", "[blocked_names]\nblocked_names_file = 'old'\n[other]\nx=1\n"]:
            result = installer.dnscrypt_config(original, Path('/etc/dnscrypt-proxy/new.txt'))
            self.assertEqual(installer.tomllib.loads(result)['blocked_names']['blocked_names_file'], '/etc/dnscrypt-proxy/new.txt')
            self.assertEqual(installer.dnscrypt_config(result, Path('/etc/dnscrypt-proxy/new.txt')), result)

    def test_dotted_toml_fails_safely(self):
        with self.assertRaises(ValueError):
            installer.dnscrypt_config("blocked_names.blocked_names_file = 'old'", Path('/new'))

    def test_bundle_end_to_end_and_standalone_syntax(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            feed = tmp / 'feed'
            feed.write_text('198.51.100.0/24\n2001:db8::/120\n0.0.0.0 bad.example\n')
            out = tmp / 'out'
            self.assertEqual(b.main([str(feed), '--no-dns', '--optimizer', 'python', '-o', str(out)]), 0)
            self.assertEqual((out / 'domains.txt').read_text(), 'bad.example\n')
            self.assertIn('ALL: [2001:db8::]/120', (out / 'hosts.deny.blocklists').read_text())
            for script in out.glob('*.py'):
                compile(script.read_text(), str(script), 'exec')
                subprocess.run(['python', str(script), '--help'], check=True, capture_output=True)
            for script in out.glob('*.sh'):
                subprocess.run(['sh', '-n', str(script)], check=True)
            firewall = (out / 'apply-firewall.sh').read_text()
            for cmd in ('iptables', 'ip6tables'):
                for chain, direction in [('INPUT','src'), ('OUTPUT','dst'), ('FORWARD','src'), ('FORWARD','dst')]:
                    self.assertIn(f'{cmd} -w -I {chain} -m set --match-set blocklists', firewall)
                    self.assertIn(f' {direction} -m comment', firewall)
            self.assertLess(firewall.index('create blocklists6_next'), firewall.index('swap blocklists4_next'))

    def test_failed_source_does_not_overwrite_existing_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp/'domains.txt').write_text('previous.example\n')
            self.assertEqual(b.main([str(tmp/'missing'), '--no-dns', '-o', str(tmp)]), 1)
            self.assertEqual((tmp/'domains.txt').read_text(), 'previous.example\n')

    def test_checkpoints_survive_failed_source_and_optimizer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            feed = root / 'feed.txt'
            feed.write_text('bad.example\n198.51.100.7\n2001:db8::7\n')
            out = root / 'out'
            out.mkdir()
            (out / 'domains.txt').write_text('previous.example\n')
            args = ['--no-dns', '--optimizer', 'python', '--progress', 'off']

            self.assertEqual(b.main([str(feed), str(root / 'missing'), *args, '-o', str(out)]), 1)
            partial, = out.glob('checkpoints-*/02-partial-sources')
            self.assertEqual((partial / 'domains.txt').read_text(), 'bad.example\n')

            with patch.object(b, 'optimize', side_effect=ValueError('optimizer failed')):
                self.assertEqual(b.main([str(feed), *args, '-o', str(out)]), 1)
            checkpoint, = out.glob('checkpoints-*/06-before-optimization')
            self.assertNotEqual(partial.parent, checkpoint.parent)
            self.assertEqual(
                sorted(path.name for path in checkpoint.parent.iterdir()),
                ['03-before-exclusions', '04-before-dns', '05-before-final-exclusions',
                 '06-before-optimization'],
            )
            self.assertEqual((out / 'domains.txt').read_text(), 'previous.example\n')

            recovered = root / 'recovered'
            self.assertEqual(b.main([str(checkpoint), *args, '-o', str(recovered)]), 0)
            for filename in ('domains.txt', 'ips-v4.txt', 'ips-v6.txt'):
                self.assertEqual((recovered / filename).read_bytes(), (checkpoint / filename).read_bytes())
            self.assertEqual(len(list(recovered.glob('checkpoints-*/07-before-bundle'))), 1)

    def test_checkpoint_survives_background_dns_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            feed = root / 'feed.txt'
            feed.write_text('bad.example\n198.51.100.7\n')
            out = root / 'out'
            with patch.object(b, 'Resolver', side_effect=ImportError('DNS unavailable')):
                self.assertEqual(b.main([
                    str(feed), '--optimizer', 'python', '--progress', 'off', '-o', str(out),
                ]), 1)
            checkpoint, = out.glob('checkpoints-*/04-before-dns')
            self.assertEqual((checkpoint / 'domains.txt').read_text(), 'bad.example\n')
            self.assertEqual((checkpoint / 'ips-v4.txt').read_text(), '198.51.100.7/32\n')
            self.assertFalse((out / 'domains.txt').exists())

    def test_local_files_without_block_records_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            feeds = root / 'feeds'
            feeds.mkdir()
            (feeds / '01-empty.txt').touch()
            (feeds / '02-comments.txt').write_text(' \n# comment\n', encoding='utf-8')
            (feeds / '03-unrecognized.txt').write_text('???\n', encoding='utf-8')
            (feeds / '04-valid.txt').write_text('bad.example\n', encoding='utf-8')
            out = root / 'out'
            args = [str(feeds), '--no-dns', '--optimizer', 'python', '--progress', 'off', '-o', str(out)]

            self.assertEqual(b.main(args), 0)
            self.assertEqual((out / 'domains.txt').read_text(), 'bad.example\n')
            report = json.loads((out / 'report.json').read_text())
            self.assertEqual(report['failed_sources'], [])
            self.assertEqual(
                [(item['networks'], item['domains']) for item in report['sources']],
                [(0, 0), (0, 0), (0, 0), (0, 1)],
            )

            (feeds / '04-valid.txt').unlink()
            self.assertEqual(b.main(args), 1)
            self.assertEqual((out / 'domains.txt').read_text(), 'bad.example\n')
            self.assertEqual(b.main([*args, '--allow-empty']), 0)
            self.assertEqual((out / 'domains.txt').read_text(), '')

    def test_remote_adblock_exceptions_are_ignored_silently(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            feed = root / 'feed.txt'
            feed.write_text('bad.example\n', encoding='utf-8')
            out = root / 'out'
            url = 'https://feeds.example/adblock-allow.txt'
            args = [url, str(feed), '--no-dns', '--optimizer', 'python', '--progress', 'off', '-o', str(out)]

            with patch.object(b, 'urlopen', return_value=io.BytesIO(b'@@||allowed.example^\n')):
                with self.assertNoLogs(b.LOG, level='WARNING'):
                    self.assertEqual(b.main(args), 0)

            self.assertEqual((out / 'domains.txt').read_text(), 'bad.example\n')
            report = json.loads((out / 'report.json').read_text())
            self.assertEqual(report['failed_sources'], [])
            self.assertEqual(report['sources'][0]['domains'], 0)


class EBPF(unittest.TestCase):
    def test_tc_nested_program_metadata(self):
        self.assertEqual(loader.filter_program_id({'options': {'prog': {'id': 42}}}), 42)
        self.assertEqual(loader.filter_program_id({'options': {'id': 43}}), 43)
        self.assertIsNone(loader.filter_program_id({'kind': 'bpf', 'pref': 1}))

    def test_lpm_endianness(self):
        import struct
        self.assertEqual(loader.prefix_key('198.51.100.0/24'), struct.pack('=I', 24) + bytes([198,51,100,0]))
        self.assertEqual(len(loader.prefix_key('2001:db8::/32')), 20)

    def test_bpftool_single_object_or_array(self):
        for value in ({'id': 42}, [{'id':42}]):
            with patch.object(loader, 'query', return_value=value):
                self.assertEqual(loader.program_id(Path('/x')), 42)

    def test_monitor_raw_percpu(self):
        import struct
        def hexes(value):
            return [f'0x{x:02x}' for x in value]
        data = [{'key': hexes(struct.pack('=IIII',4,7,1,1) + bytes([198,51,100,1]) + bytes(12)),
                 'values': [{'cpu':0, 'value':hexes(struct.pack('=QQ',3,180))}, {'cpu':1, 'value':hexes(struct.pack('=QQ',2,120))}]}]
        output = io.StringIO()
        with patch.object(loader,'query',side_effect=[data,[]]), contextlib.redirect_stdout(output):
            loader.monitor({'pin':'/x'})
        row = json.loads(output.getvalue().splitlines()[0])
        self.assertEqual((row['ip'],row['packets'],row['bytes'],row['direction']), ('198.51.100.1',5,300,'egress'))


if __name__ == '__main__':
    unittest.main()
