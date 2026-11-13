import contextlib
import io
import logging
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import blocklists_core as b
from blocklists_progress import Progress


class ProgressTests(unittest.TestCase):
    def test_plain_counts_and_no_terminal_controls(self):
        stream = io.StringIO()
        with Progress('plain', stream=stream) as progress:
            progress.start('DNS', 2, 'example.org')
            progress.update(advance=1)
            progress.update(advance=1, detail='done.example')
        text = stream.getvalue()
        self.assertIn('2/2 completed (100%)', text)
        self.assertNotIn('\x1b', text)
        self.assertNotIn('\r', text)

    def test_spinner_animates_during_blocking_work_and_stops(self):
        class Terminal(io.StringIO):
            ticked = threading.Event()
            def isatty(self):
                return True
            def write(self, value):
                if value.startswith('\r\x1b[2K|'):
                    self.ticked.set()
                return super().write(value)
        stream = Terminal()
        with Progress(stream=stream, interval=0.01) as progress:
            progress.start('Waiting', detail='blocked DNS query')
            self.assertTrue(stream.ticked.wait(1))
        self.assertFalse(progress.thread.is_alive())
        self.assertTrue(stream.getvalue().endswith('\n'))

    def test_error_does_not_claim_completion(self):
        stream = io.StringIO()
        with self.assertRaises(ValueError):
            with Progress('plain', stream=stream) as progress:
                progress.start('Parse', 10)
                progress.update(advance=2)
                raise ValueError('bad input')
        self.assertIn('failed Parse | 2/10', stream.getvalue())
        self.assertNotIn('100%', stream.getvalue())

    def test_off_still_logs_errors_and_restores_logger(self):
        stream = io.StringIO()
        logger = logging.getLogger('progress-test')
        before = logger.handlers[:], logger.propagate, logger.level
        with Progress('off', stream=stream) as progress, progress.logging(logger):
            progress.start('Hidden', 1)
            logger.error('failure')
        self.assertEqual(stream.getvalue(), 'ERROR: failure\n')
        self.assertEqual((logger.handlers, logger.propagate, logger.level), before)

    def test_untrusted_terminal_controls_are_removed(self):
        stream = io.StringIO()
        with Progress('plain', stream=stream) as progress:
            progress.start('Feed', detail='x\x1b[2J\nspoof')
        self.assertNotIn('\x1b', stream.getvalue())
        self.assertNotIn('\nspoof', stream.getvalue())

    def test_bounded_read_reports_bytes(self):
        stream = io.BytesIO(b'x' * 20)
        output = io.StringIO()
        with Progress('plain', stream=output) as progress:
            progress.start('Read', 1)
            data = b.read_source(stream, 10, 'feed', progress)
        self.assertEqual(len(data), 11)
        self.assertIn('11 bytes received', output.getvalue())

    def test_cli_all_stages_and_unchanged_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            feed = root / 'feed'
            feed.write_text('198.51.100.1\nexample.org\n')
            stderr, stdout = io.StringIO(), io.StringIO()
            with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
                self.assertEqual(b.main([str(feed), '--no-dns', '--optimizer', 'python', '--progress', 'plain', '-o', str(root/'out')]), 0)
            for stage in range(1, 8):
                self.assertIn(f'[{stage}/7]', stderr.getvalue())
            self.assertEqual(stdout.getvalue(), '')
            self.assertEqual((root/'out'/'domains.txt').read_text(), 'example.org\n')

    def test_dns_progress_counts_actual_completion_order(self):
        release = threading.Event()
        class Reporter(Progress):
            def dns_update(self, scheduled=0, completed=0, detail=None):
                if completed:
                    seen.append(detail)
                    release.set()
        seen = []
        class Resolver:
            def query(self, task):
                if task[1] == 'A':
                    if not release.wait(1):
                        raise AssertionError('fast completion was not reported')
                return task, [], None
        args = b.cli().parse_args(['--dns-rounds', '1'])
        b.enrich(set(), {'example.org'}, [], set(), args, {}, Resolver(), Reporter('off'))
        self.assertTrue(seen[0].startswith('AAAA '))
        self.assertEqual(len(seen), 2)

    def test_dns_refills_worker_window_while_first_lookup_is_pending(self):
        beyond_first_window = threading.Event()

        class Resolver:
            def query(self, task):
                if task == ('a.example', 'A'):
                    if not beyond_first_window.wait(5):
                        raise AssertionError('later queries waited for the first window to drain')
                if task == ('e.example', 'A'):
                    beyond_first_window.set()
                return task, [], None

        args = b.cli().parse_args(['--dns-rounds', '1', '--workers', '2'])
        self.assertIsNone(args.max_dns_queries)
        report = {}
        names = {f'{letter}.example' for letter in 'abcde'}
        b.enrich(set(), names, [], set(), args, report, Resolver())
        self.assertEqual(report['dns_queries'], 10)

    def test_forward_dns_runs_during_parsing_and_later_source_reads(self):
        started = threading.Event()
        reading_second = threading.Event()
        real_read = b.read_source

        class Resolver:
            def __init__(self, *args):
                pass

            def query(self, task):
                if task == ('first.example', 'A'):
                    started.set()
                    if not reading_second.wait(5):
                        raise AssertionError('DNS blocked the next source read')
                    return task, ['198.51.100.7'], None
                return task, [], None

        class Reporter(Progress):
            def update(self, detail=None, completed=None, advance=0):
                if detail and 'line 1,024/' in detail and not started.wait(5):
                    raise AssertionError('DNS did not start while parsing the first source')
                super().update(detail, completed, advance)

        def read_source(stream, limit, source, progress):
            if source == str(second):
                reading_second.set()
            return real_read(stream, limit, source, progress)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, second = root / 'first.txt', root / 'second.txt'
            first.write_text('first.example\n' + '# comment\n' * 1024)
            second.write_text('second.example\n')
            stderr = io.StringIO()
            with (patch.object(b, 'Resolver', Resolver), patch.object(b, 'Progress', Reporter),
                  patch.object(b, 'read_source', read_source), contextlib.redirect_stderr(stderr)):
                self.assertEqual(b.main([
                    str(first), str(second), '--optimizer', 'python', '--progress', 'plain',
                    '-o', str(root / 'out'),
                ]), 0)
            self.assertIn('[2/7] Read and parse feeds | DNS ', stderr.getvalue())
            self.assertIn('DNS 5/5 completed', stderr.getvalue())
            self.assertEqual((root / 'out' / 'ips-v4.txt').read_text(), '198.51.100.7/32\n')
