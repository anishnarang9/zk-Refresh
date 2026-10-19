import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import fcntl

from tools.part5 import run_v3_heldout_direct_arm as direct


def h(value):
    return hashlib.sha256(value.encode()).hexdigest()


def arm(mode, *, action='action', clone='same-tree', destination=None):
    return {
        'schema': direct.ARM_SCHEMA,
        'variant': 0,
        'mode': mode,
        'status': 'passed',
        'run_manifest_sha256': h('manifest'),
        'identity': {
            'credential_sha256': h('credential'),
            'finalized_request_sha256': h('request'),
            'finalized_action_transport_sha256': h('transport'),
            'action_hash': h(action),
            'roots': {'R0': h('R0'), 'R1': h('R1')},
            'setup_sha256': h('setup'),
            'vk_sha256': h('vk'),
            'elf_sha256': h('elf'),
        },
        'proof': {'mode': mode, 'proof_created': True, 'ordinary_verified': True},
        'clone': {
            'receipt_sha256': h(mode + '-clone-receipt'),
            'tree_sha256': h(clone),
            'copy_identical': True,
            'destination': destination or '/private/' + mode + '/ledger',
        },
        'effect': {
            'report_sha256': h(mode + '-effect'),
            'mode': mode,
            'passed': True,
            'effect_count': 1,
            'request_consumed': True,
        },
    }


def outer(seconds):
    return {
        'schema': 1,
        'measurement': 'bounded_complete_session',
        'passed': True,
        'exit_code': 0,
        'censored': False,
        'stop_reason': None,
        'runner_error_type': None,
        'cleanup_remaining_owned_processes': 0,
        'cleanup_status_unknown': False,
        'duration_seconds': seconds,
        'sample_count': 3,
        'cpu': {'complete_tree_cpu_qualified': False},
    }


class DirectHeldoutPairTests(unittest.TestCase):
    def test_counterbalances_four_of_eight_each_way(self):
        orders = [direct.arm_order(v) for v in range(8)]
        self.assertEqual(orders.count(('full', 'anchor')), 4)
        self.assertEqual(orders.count(('anchor', 'full')), 4)
        self.assertEqual(direct.arm_order(0), ('full', 'anchor'))
        self.assertEqual(direct.arm_order(1), ('anchor', 'full'))

    def test_pair_uses_outer_direct_durations_after_complete_cleanup(self):
        result = direct.validate_direct_pair(
            arm('full'), arm('anchor'), outer(100), outer(80),
            variant=0, order=('full', 'anchor'))
        self.assertTrue(result['matched'])
        self.assertEqual(result['full_direct_wall_seconds'], 100)
        self.assertEqual(result['anchor_direct_wall_seconds'], 80)
        self.assertEqual(result['anchor_wall_savings_fraction'], 0.2)
        self.assertEqual(result['update_count'], 1)
        self.assertFalse(result['k_gt_1_measured'])

    def test_rejects_mismatched_finalized_action_or_root_sequence(self):
        with self.assertRaisesRegex(ValueError, 'action'):
            direct.validate_direct_pair(
                arm('full'), arm('anchor', action='different'), outer(100), outer(80),
                variant=0, order=('full', 'anchor'))
        other = arm('anchor')
        other['identity']['roots']['R1'] = h('different-root')
        with self.assertRaisesRegex(ValueError, 'root'):
            direct.validate_direct_pair(
                arm('full'), other, outer(100), outer(80),
                variant=0, order=('full', 'anchor'))

    def test_requires_independent_byte_identical_r1_clones_and_effects(self):
        full, anchor = arm('full'), arm('anchor')
        anchor['clone']['tree_sha256'] = h('different-tree')
        with self.assertRaisesRegex(ValueError, 'byte-identical'):
            direct.validate_direct_pair(
                full, anchor, outer(100), outer(80),
                variant=0, order=('full', 'anchor'))

        full, anchor = arm('full'), arm('anchor')
        anchor['clone']['destination'] = full['clone']['destination']
        with self.assertRaisesRegex(ValueError, 'independent'):
            direct.validate_direct_pair(
                full, anchor, outer(100), outer(80),
                variant=0, order=('full', 'anchor'))

        full, anchor = arm('full'), arm('anchor')
        anchor['effect']['effect_count'] = 0
        with self.assertRaisesRegex(ValueError, 'effect'):
            direct.validate_direct_pair(
                full, anchor, outer(100), outer(80),
                variant=0, order=('full', 'anchor'))

    def test_rejects_censored_or_unclean_outer_arm(self):
        bad = outer(100)
        bad['cleanup_remaining_owned_processes'] = 1
        with self.assertRaisesRegex(ValueError, 'cleanup'):
            direct.validate_direct_pair(
                arm('full'), arm('anchor'), bad, outer(80),
                variant=0, order=('full', 'anchor'))

        bad = outer(100)
        bad['censored'] = True
        with self.assertRaisesRegex(ValueError, 'outer'):
            direct.validate_direct_pair(
                arm('full'), arm('anchor'), bad, outer(80),
                variant=0, order=('full', 'anchor'))

    def test_fresh_directory_rejects_symlink_parent_before_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / 'target'
            target.mkdir()
            alias = root / 'alias'
            alias.symlink_to(target, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, 'canonical'):
                direct._private_dir(alias / 'new-output', fresh=True)

            self.assertFalse((target / 'new-output').exists())

    def test_lock_creation_rejects_symlink_parent_before_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / 'target'
            target.mkdir()
            alias = root / 'alias'
            alias.symlink_to(target, target_is_directory=True)
            previous_artifacts, previous_lock = direct.ARTIFACTS, direct.HEAVY_LOCK
            direct.ARTIFACTS = alias
            direct.HEAVY_LOCK = alias / '.v3-heldout-heavy.lock'
            try:
                with self.assertRaisesRegex(ValueError, 'canonical'):
                    direct._acquire_heavy_lock()
                self.assertFalse((target / '.v3-heldout-heavy.lock').exists())
            finally:
                direct.ARTIFACTS, direct.HEAVY_LOCK = previous_artifacts, previous_lock

    def test_worker_requires_ticket_from_parent_that_holds_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            mode_root = root / 'arm-full'
            mode_root.mkdir(mode=0o700)
            case_output = mode_root / 'case-run'
            lock_path = root / 'heavy.lock'
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            parent_pid = os.getpid()
            token = 'a' * 64
            manifest_sha = h('manifest')
            ticket = {
                'schema': 'credential-v3-heldout-worker-ticket-v1',
                'mode': 'full',
                'case_output_root': str(case_output),
                'manifest_sha256': manifest_sha,
                'supervisor_pid': parent_pid,
                'token': token,
            }
            ticket_path = mode_root / 'worker-launch.json'
            authorize = getattr(direct, '_authorize_worker', None)
            self.assertTrue(callable(authorize), 'locked-parent worker gate is required')
            prior_token = os.environ.get('P5_V3_DIRECT_ARM_WORKER_TOKEN')
            os.environ['P5_V3_DIRECT_ARM_WORKER_TOKEN'] = token

            try:
                with self.assertRaisesRegex(ValueError, 'ticket'):
                    authorize(
                        ticket_path, case_output, 'full', manifest_sha, token,
                        child_parent_pid=parent_pid, lock_path=lock_path)

                lock_doc = json.dumps({
                    'schema': direct.LOCK_OWNER_SCHEMA,
                    'pid': parent_pid,
                }, sort_keys=True, separators=(',', ':')).encode()
                os.write(lock_fd, lock_doc)
                direct._write_new(ticket_path, ticket)
                with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                    authorize(
                        ticket_path, case_output, 'full', manifest_sha, token,
                        child_parent_pid=parent_pid + 1, lock_path=lock_path)
                with self.assertRaisesRegex(ValueError, 'does not hold'):
                    authorize(
                        ticket_path, case_output, 'full', manifest_sha, token,
                        child_parent_pid=parent_pid, lock_path=lock_path)
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                claimed = authorize(
                    ticket_path, case_output, 'full', manifest_sha, token,
                    child_parent_pid=parent_pid, lock_path=lock_path)
                self.assertEqual(claimed, mode_root)
                self.assertFalse(ticket_path.exists())
                with self.assertRaisesRegex(ValueError, 'ticket'):
                    authorize(
                        ticket_path, case_output, 'full', manifest_sha, token,
                        child_parent_pid=parent_pid, lock_path=lock_path)
            finally:
                if prior_token is None:
                    os.environ.pop('P5_V3_DIRECT_ARM_WORKER_TOKEN', None)
                else:
                    os.environ['P5_V3_DIRECT_ARM_WORKER_TOKEN'] = prior_token
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(lock_fd)

    def test_worker_output_root_is_the_supplied_case_root(self):
        requested = Path('/private/pair/arm-full/custom-case-root')
        path_helper = getattr(direct, '_worker_output_paths', None)
        self.assertTrue(callable(path_helper), 'worker must resolve the supplied output root')
        mode_root, case_root = path_helper(requested)
        self.assertEqual(mode_root, requested.parent)
        self.assertEqual(case_root, requested)

    def test_pair_report_hash_is_detached_and_matches_saved_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / 'direct-pair-report.json'
            report = {'schema': direct.PAIR_SCHEMA, 'variant': 0}

            report_writer = getattr(direct, '_write_pair_report', None)
            self.assertTrue(callable(report_writer), 'pair report digest must be persisted separately')
            report_sha256 = report_writer(path, report)
            saved = json.loads(path.read_text())
            sidecar = json.loads(Path(str(path) + '.sha256.json').read_text())

            self.assertEqual(saved, report)
            self.assertNotIn('report_sha256', saved)
            self.assertEqual(sidecar['report_sha256'], report_sha256)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), report_sha256)

if __name__ == '__main__':
    unittest.main()
