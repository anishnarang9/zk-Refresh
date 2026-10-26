import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.part5.compare_v3_matched_k1 import (
    REGISTERED_LIMITS, REPO, check_invocation, compare,
)


class MatchedPairTests(unittest.TestCase):
    def pair(self):
        shared = {name: 'same' for name in (
            'freeze_sha256', 'packet_sha256', 'source_sha256', 'clone_inventory_sha256',
            'clone_source', 'base_input_sha256', 'near_input_sha256',
            'base_public_sha256', 'near_public_sha256',
            'base_wtns_sha256', 'near_wtns_sha256',
            'application_stage_pins', 'package_digest',
            'setup_manifest_sha256', 'ordinary_vk_file_sha256',
            'proof_binary_sha256', 'proof_source_identity', 'proof_identity',
            'proof_support_preflight')}
        shared['outer_limits'] = REGISTERED_LIMITS
        shared['outer_environment'] = {'RAYON_NUM_THREADS': None,
                                       'OMP_NUM_THREADS': None, 'TZ': None}
        full = {**shared, 'outer_wall_seconds': 100.0,
                'registry_history_authenticated': False,
                'final_account_sha256': ['config', 'issuer', 'head-full', 'request', 'queue'],
                'proof_public_material_prepare_ms': 0.0,
                'proof_private_anchor_prepare_ms': None}
        anchor = {**shared, 'outer_wall_seconds': 150.0,
                  'registry_history_authenticated': False,
                  'final_account_sha256': ['config', 'issuer', 'head-anchor', 'request', 'queue'],
                  'proof_public_material_prepare_ms': 10.0,
                  'proof_private_anchor_prepare_ms': 20.0}
        return full, anchor

    def test_negative_pilot_is_not_a_break_even_claim(self):
        result = compare(*self.pair())
        self.assertEqual(result['full_minus_anchor_wall_seconds'], -50.0)
        self.assertEqual(result['wall_savings_fraction'], -0.5)
        self.assertIsNone(result['measured_break_even'])
        self.assertFalse(result['application_benefit_established'])
        self.assertIsNone(result['cpu_savings'])
        self.assertFalse(result['registry_history_authenticated'])

    def test_rejects_unmatched_request_witness_and_final_queue(self):
        for key in ('freeze_sha256', 'base_wtns_sha256',
                    'application_stage_pins'):
            full, anchor = self.pair()
            anchor[key] = 'changed'
            with self.subTest(key=key), self.assertRaises(ValueError):
                compare(full, anchor)
        full, anchor = self.pair()
        anchor['final_account_sha256'][4] = 'different-queue'
        with self.assertRaises(ValueError):
            compare(full, anchor)

    def test_rejects_outer_receipt_from_different_session(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            freeze = root / 'freeze.json'
            status = root / 'artifacts/dynark/part5/control/status.json'
            status.parent.mkdir(parents=True)
            freeze.write_text('freeze')
            status.write_text('status')
            work, clone, branch, monitor = (root / name for name in
                                           ('work', 'clone', 'branch', 'monitor'))
            args = ['python3', '-B', 'tools/part5/run_v3_matched_k1.py',
                    '--mode', 'full', '--freeze', str(freeze),
                    '--clone-report', str(clone / 'clone-report.json'),
                    '--work-root', str(work), '--branch-output', str(branch),
                    '--control-output', str(status.parent)]
            invocation = {'owner': 'part5-v3-matched-k1-full-002', 'argv': args,
                          'cwd': str(REPO), 'storage_roots': list(map(str, (
                              monitor, work, branch, status.parent, clone / 'ledger')))}
            outer = {'owner': invocation['owner'], 'duration_seconds': 10.0}
            session = {'freeze_sha256': 'freeze-hash',
                       'branch_status_sha256': 'status-hash',
                       'total_command_wall_seconds': 9.0}
            with patch('tools.part5.compare_v3_matched_k1.REPO', root), \
                 patch('tools.part5.compare_v3_matched_k1.sha',
                       side_effect=lambda path: {'freeze.json': 'freeze-hash',
                                                 'status.json': 'status-hash'}[Path(path).name]):
                invocation['cwd'] = str(root)
                (root / 'results/dynark/part5').mkdir(parents=True)
                actual_freeze = root / 'results/dynark/part5/freeze.json'
                freeze.replace(actual_freeze)
                args[6] = str(actual_freeze)
                check_invocation('full', invocation, monitor, work, clone,
                                 branch, session, outer)
                mismatched = {**invocation, 'argv': list(args)}
                mismatched['argv'][10] = str(root / 'other-work')
                with self.assertRaisesRegex(ValueError, 'outer invocation/session mismatch'):
                    check_invocation('full', mismatched, monitor, work, clone,
                                     branch, session, outer)


if __name__ == '__main__':
    unittest.main()
