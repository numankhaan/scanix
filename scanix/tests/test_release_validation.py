"""Offline release mutation coverage; regular CI needs no privileges or public network."""
import unittest
from unittest.mock import patch

from validation.parser_corpus import mutations, run
from validation.package_smoke import wheel_inventory


class ReleaseCorpusTests(unittest.TestCase):
    def test_corpus_is_deterministic_bounded_and_offline(self):
        # Import Scapy before blocking socket construction; no traffic in the corpus.
        import scanix.modules.packets  # noqa: F401
        with patch('socket.socket', side_effect=AssertionError('corpus attempted network')):
            first, second = run(16), run(16)
        self.assertEqual(first, second)
        self.assertGreater(first['inputs'], 300)
        for family in (4, 6):
            self.assertGreater(first['groups']['packet_ipv' + str(family)]['accepted'], 0)
        self.assertEqual(first['groups']['tls']['accepted'], 0)
        self.assertTrue(all(item['inputs'] == item['accepted'] + item['rejected']
                            for item in first['groups'].values()))

    def test_corpus_budget_rejects_unbounded_inputs(self):
        for limit in (0, -1, 4097, True):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                list(mutations(b'synthetic', limit))
        self.assertTrue(all(len(data) <= 16385 for data in mutations(b'x' * 20000, 8)))

    def test_distribution_rejects_private_or_unexpected_members(self):
        self.assertEqual(wheel_inventory(['scanix/__init__.py', 'scanix/data/probes-v1.json',
                                         'scanix-1.dist-info/METADATA']),
                         {'scanix/__init__.py', 'scanix/data/probes-v1.json'})
        for name in ('scanix/tests/fixture.py', 'scanix/secret.key', 'scanix/.env',
                     'scanix/__pycache__/x.pyc', '/scanix/x.py', '../scanix/x.py',
                     'other/x.py', 'scanix-1.dist-info/private.json'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                wheel_inventory([name])
