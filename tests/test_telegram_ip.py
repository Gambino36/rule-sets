"""Exercise source changes, exact coverage, and failure-safe publication."""

from contextlib import redirect_stdout
import io
import ipaddress
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

from scripts import update_telegram_ip as updater


class RulesTest(unittest.TestCase):
    def test_real_source_formats_and_host_bits(self):
        cases = {
            'IP-CIDR6:2001:b28:f23c::/47': '2001:b28:f23c::/47',
            'IP-CIDR,2001:5000::/21': '2001:5000::/21',
            'IP-CIDR,91.108.0.0/16,no-resolve': '91.108.0.0/16',
            '185.76.151.0/22 # comment': '185.76.148.0/22',
            '149.154.175.0/22': '149.154.172.0/22',
        }
        for rule, expected in cases.items():
            with self.subTest(rule=rule):
                self.assertEqual(str(updater.parse_rule(rule)), expected)

    def test_invalid_rules_fail(self):
        for rule in ('999.0.0.0/8', '0.0.0.0/33', 'IP-CIDR6:10.0.0.0/8',
                     'DOMAIN,telegram.org', '10.0.0.1', 'IP-CIDR,10.0.0.0/8,Proxy', 123):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                updater.parse_rule(rule)

    def test_yaml_rejects_duplicate_keys_and_empty_sources(self):
        for source in (b'payload: []\n', b'payload: []\npayload: []\n',
                       b'payload: [null]\n', b'payload: [10.0.0.0/8]\nextra: []\n'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                updater.parse_source('davoyan.yaml', source)
        with self.assertRaises(ValueError):
            updater.parse_source('666OS.txt', b'# only comments\n')

    def test_duplicates_containment_and_adjacent_merge_preserve_union(self):
        sources = {
            '666OS.txt': b'10.0.0.0/9\n10.128.0.0/9\n10.1.0.0/16\n',
            'metacubex.list': b'10.0.0.0/9\n192.0.2.0/25\n',
            'davoyan.yaml': b'payload:\n  - IP-CIDR,2001:db8::/32\n  - IP-CIDR,192.0.2.128/25\n',
        }
        with redirect_stdout(io.StringIO()):
            result = updater.combine(sources)
        self.assertEqual(list(map(str, result)), ['2001:db8::/32', '192.0.2.0/24', '10.0.0.0/8'])
        # Independently assert addresses immediately outside the original union stay out.
        for address in ('9.255.255.255', '11.0.0.0', '192.0.1.255', '192.0.3.0', '2001:db9::'):
            ip = ipaddress.ip_address(address)
            self.assertFalse(any(ip in network for network in result if ip.version == network.version))
        self.assertEqual(yaml.safe_load(updater.render(result))['payload'], list(map(str, result)))


class UpdatesTest(unittest.TestCase):
    def setUp(self):
        self.directory = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(self.directory) / 'repo'
        self.snapshot = Path(self.directory) / 'snapshot'
        self.root.mkdir()
        self.output = Path(self.directory) / 'github-output'
        self.sources = {
            '666OS.txt': b'10.0.0.0/9\n',
            'metacubex.list': b'10.128.0.0/9\n',
            'davoyan.yaml': b'payload:\n  - IP-CIDR,2001:db8::/32\n',
        }
        self.calls = []
        self.exported = []
        self.fetch = self.enterContext(patch.object(updater, 'fetch_source', self.fake_fetch))
        self.compiler = self.enterContext(patch.object(updater, 'run_mihomo', self.fake_compiler))
        self.enterContext(redirect_stdout(io.StringIO()))

    def fake_fetch(self, item):
        return item[0], self.sources[item[0]]

    def fake_compiler(self, mihomo, *args):
        self.calls.append(args)
        if args == ('-v',):
            return 'Mihomo Meta v1.19.32 linux amd64'
        if args[:3] == ('convert-ruleset', 'ipcidr', 'yaml'):
            self.exported = yaml.safe_load(Path(args[3]).read_bytes())['payload']
            Path(args[4]).write_bytes(b'fake-validated-mrs\0' + '\n'.join(self.exported).encode())
        elif args[:3] == ('convert-ruleset', 'ipcidr', 'mrs'):
            Path(args[4]).write_text('\n'.join(self.exported) + '\n')
        else:
            raise AssertionError(f'Unexpected compiler arguments: {args!r}')
        return ''

    def check(self):
        return updater.check(self.snapshot, self.output, self.root)

    def build(self):
        return updater.build(self.snapshot, Path('/unused/mihomo'), self.root)

    def seed(self):
        self.assertTrue(self.check())
        self.assertTrue(self.build())
        self.calls.clear()

    def tracked(self):
        return {p: (self.root / p).read_bytes() for p in (updater.YAML, updater.MRS, updater.STATE)}

    def test_initial_build_and_unchanged_sources_skip_compiler(self):
        self.seed()
        before = self.tracked()
        self.assertFalse(self.check())
        self.assertFalse(self.build())
        self.assertEqual(self.calls, [])
        self.assertEqual(before, self.tracked())
        self.assertIn('changed=false\n', self.output.read_text())

    def test_source_removal_and_addition_replace_previous_union(self):
        self.seed()
        self.sources['666OS.txt'] = b'192.0.2.0/24\n'
        self.assertTrue(self.check())
        self.assertTrue(self.build())
        rules = yaml.safe_load((self.root / updater.YAML).read_bytes())['payload']
        self.assertEqual(rules, ['2001:db8::/32', '192.0.2.0/24', '10.128.0.0/9'])
        self.assertEqual(len(self.calls), 3)  # version, compile, MRS round trip

    def test_comment_only_change_still_counts_as_original_file_change(self):
        self.seed()
        before = self.tracked()
        self.sources['666OS.txt'] += b'# new upstream timestamp\n'
        self.assertTrue(self.check())
        self.assertTrue(self.build())
        after = self.tracked()
        self.assertEqual(before[updater.YAML], after[updater.YAML])
        self.assertNotEqual(before[updater.STATE], after[updater.STATE])
        self.assertEqual(len(self.calls), 3)

    def test_invalid_upstream_leaves_current_files_and_state_intact(self):
        self.seed()
        before = self.tracked()
        self.sources['metacubex.list'] = b'not-a-network\n'
        with self.assertRaises(ValueError):
            self.check()
        self.assertEqual(before, self.tracked())
        self.assertEqual(self.calls, [])

    def test_failed_download_leaves_current_files_and_state_intact(self):
        self.seed()
        before = self.tracked()
        with patch.object(updater, 'fetch_source', side_effect=OSError('source unavailable')):
            with self.assertRaises(OSError):
                self.check()
        self.assertEqual(before, self.tracked())

    def test_corrupt_snapshot_fails_before_compilation(self):
        self.seed()
        before = self.tracked()
        self.sources['666OS.txt'] = b'192.0.2.0/24\n'
        self.check()
        (self.snapshot / '666OS.txt').write_bytes(b'0.0.0.0/0\n')
        with self.assertRaisesRegex(ValueError, 'snapshot checksums'):
            self.build()
        self.assertEqual(before, self.tracked())
        self.assertEqual(self.calls, [])

    def test_mrs_coverage_loss_prevents_publication(self):
        self.seed()
        before = self.tracked()
        self.sources['666OS.txt'] = b'192.0.2.0/24\n'
        self.check()

        def corrupt_export(mihomo, *args):
            result = self.fake_compiler(mihomo, *args)
            if args[:3] == ('convert-ruleset', 'ipcidr', 'mrs'):
                Path(args[4]).write_text('192.0.2.0/25\n')
            return result

        with patch.object(updater, 'run_mihomo', corrupt_export):
            with self.assertRaisesRegex(ValueError, 'MRS address coverage'):
                self.build()
        self.assertEqual(before, self.tracked())

    def test_unchanged_sources_detect_corrupt_output_without_compiling(self):
        self.seed()
        (self.root / updater.MRS).write_bytes(b'corrupted')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.check()
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
