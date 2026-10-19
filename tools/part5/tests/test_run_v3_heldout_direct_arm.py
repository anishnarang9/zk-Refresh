import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import fcntl
from unittest import mock

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
        'shared_context_sha256': h('shared-b-context'),
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
        'evidence': {
            'stage_report_sha256': h('shared-stage-report'),
            'transition_report_sha256': h('shared-transition-report'),
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

    def test_pair_requires_one_shared_stopped_transition_and_labels_post_transition_scope(self):
        full, anchor = arm('full'), arm('anchor')
        result = direct.validate_direct_pair(
            full, anchor, outer(100), outer(80),
            variant=0, order=('full', 'anchor'))
        self.assertEqual(result['basis'], 'separate directly timed post-transition B segment outer wall')
        self.assertEqual(result['shared_context_sha256'], h('shared-b-context'))
        self.assertIs(result.get('complete_import_to_execute_arm'), False)

        anchor['shared_context_sha256'] = h('another-transition')
        with self.assertRaisesRegex(ValueError, 'shared B context'):
            direct.validate_direct_pair(
                full, anchor, outer(100), outer(80),
                variant=0, order=('full', 'anchor'))

        anchor['shared_context_sha256'] = full['shared_context_sha256']
        anchor['evidence']['transition_report_sha256'] = h('different-transition')
        with self.assertRaisesRegex(ValueError, 'shared B context'):
            direct.validate_direct_pair(
                full, anchor, outer(100), outer(80),
                variant=0, order=('full', 'anchor'))

    def test_rejects_matching_arm_hashes_that_do_not_bind_to_shared_context(self):
        full, anchor = arm('full'), arm('anchor')
        shared = {
            'stage': {'report_sha256': h('actual-shared-stage')},
            'transition': {'report_sha256': h('actual-shared-transition')},
        }
        wrong_stage = h('same-but-wrong-stage')
        wrong_transition = h('same-but-wrong-transition')
        for row in (full, anchor):
            row['evidence']['stage_report_sha256'] = wrong_stage
            row['evidence']['transition_report_sha256'] = wrong_transition

        binding = getattr(direct, 'validate_shared_arm_binding', None)
        self.assertTrue(callable(binding), 'shared report hashes must be bound to pair arms')
        with self.assertRaisesRegex(ValueError, 'shared stage report'):
            binding(full, anchor, shared)

        shared['stage']['report_sha256'] = wrong_stage
        with self.assertRaisesRegex(ValueError, 'shared transition report'):
            binding(full, anchor, shared)

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
                'schema': direct.WORKER_TICKET_SCHEMA,
                'mode': 'full',
                'case_output_root': str(case_output),
                'manifest_sha256': manifest_sha,
                'shared_context_sha256': h('shared-b-context'),
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

    def test_shared_context_reader_pins_setup_files_and_runner_root_layout(self):
        artifacts_root = direct.ROOT / 'artifacts'
        artifacts_existed = artifacts_root.exists()
        artifacts_root.mkdir(mode=0o700, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(
            prefix='.direct-arm-shared-context-test-', dir=artifacts_root)
        if not artifacts_existed:
            self.addCleanup(lambda: artifacts_root.rmdir()
                            if artifacts_root.exists() and not any(artifacts_root.iterdir())
                            else None)
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        pair_root = root / 'pair'
        pair_root.mkdir(mode=0o700)
        shared_root = pair_root / 'shared-B'

        case_runner = direct._load_module(
            'test_direct_arm_shared_case_runner',
            direct.ROOT / 'tools/part5/run_v3_heldout_case.py')
        manifest = {
            'variant': 0,
            'cohort_root': str(root / 'cohort'),
            'cohort_sha256': h('cohort'),
            'base_prepare_config_sha256': h('prepare-template'),
        }
        manifest_sha = case_runner.digest(case_runner.encoded(manifest))
        manifest_path = root / 'manifest.json'
        direct._write_new(manifest_path, manifest)
        run_ref = {'path': str(manifest_path), 'sha256': manifest_sha}

        def write_ref(base, name):
            path = base / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            sha = direct._write_new(path, {'artifact': name})
            return str(path), sha

        def fake_prepare(runner, request, request_root, case_root, stage_context):
            config, config_sha = write_ref(request_root, 'prepare-config.json')
            status, status_sha = write_ref(request_root, 'prepare-status.json')
            monitor, monitor_sha = write_ref(request_root, 'prepare-monitor.json')
            return {'config': config, 'config_sha256': config_sha,
                    'status_path': status, 'status_sha256': status_sha,
                    'monitor': monitor, 'monitor_sha256': monitor_sha,
                    'monitor_owner': 'fake-shared-prepare-owner',
                    'runtime': str(request_root / 'runtime'),
                    'control': str(request_root / 'prepare-control'),
                    'wall_seconds': 0.01}

        def fake_stage_transition(runner, request, request_root, case_root,
                                  request_inputs, prepared):
            stage = {}
            for key, sha_key, name in (
                    ('config', 'config_sha256', 'stage-config.json'),
                    ('status_path', 'status_sha256', 'stage-status.json'),
                    ('monitor', 'monitor_sha256', 'stage-monitor.json'),
                    ('report', 'report_sha256', 'stage-report.json'),
                    ('plan', 'plan_sha256', 'stage-plan.json')):
                stage[key], stage[sha_key] = write_ref(request_root, name)
            transition = {}
            for key, sha_key, name in (
                    ('config', 'config_sha256', 'transition-config.json'),
                    ('status_path', 'status_sha256', 'transition-status.json'),
                    ('monitor', 'monitor_sha256', 'transition-monitor.json'),
                    ('context', 'context_sha256', 'transition-context.json'),
                    ('report', 'report_sha256', 'transition-report.json')):
                transition[key], transition[sha_key] = write_ref(request_root, name)
            stage['root'] = str(request_root / 'stage')
            stage['monitor_owner'] = 'fake-shared-stage-owner'
            transition['root'] = str(request_root / 'transition')
            transition['monitor_owner'] = 'fake-shared-transition-owner'
            stage = runner.journal.run_step(request + ':stage',
                inputs={'request': request},
                job=lambda: {'status': 'passed', **stage})
            transition = runner.journal.run_step(request + ':transition',
                inputs={'request': request},
                job=lambda: {'status': 'passed', **transition})
            return stage, transition, None

        class FakeContextBuilder:
            @staticmethod
            def prepare(cohort_root, cohort_sha256, variant, case_root):
                direct._write_new(case_root / 'case-context.json', {
                    'target': {'variant': variant}})
                direct._write_new(case_root / 'cohort-receipt.json', {
                    'heldout_acceptance': False})

        original_loader = direct._load_module

        def load_context_builder(name, path):
            if name == 'direct_arm_shared_context_builder':
                return FakeContextBuilder
            return original_loader(name, path)

        with (mock.patch.object(case_runner, 'validate_manifest', return_value=({}, {}, {})),
              mock.patch.object(case_runner.HeldoutCaseRunner, '_prepare', fake_prepare),
              mock.patch.object(case_runner.HeldoutCaseRunner, '_stage_transition',
                                fake_stage_transition),
              mock.patch.object(direct, '_load_module', side_effect=load_context_builder)):
            shared, context_path, context_sha = direct._run_shared_b_setup(
                case_runner, manifest, run_ref, manifest_sha, shared_root)

        self.assertEqual(context_path, shared_root / 'shared-context.json')
        self.assertTrue((shared_root / 'case-run' / 'run-id.json').is_file())
        self.assertEqual(shared['case_root'], str(shared_root / 'case-run' / 'pair-view'))
        mode_root = pair_root / 'arm-full'
        mode_root.mkdir(mode=0o700)
        direct._write_new(mode_root / direct.WORKER_CLAIM_NAME, {
            'shared_context_sha256': context_sha})
        loaded, loaded_sha = direct._read_shared_b_context(
            mode_root, case_runner, manifest_sha, 0)
        self.assertEqual(loaded_sha, context_sha)
        self.assertEqual(loaded['stage']['report_sha256'],
                         shared['stage']['report_sha256'])

        stage_report = Path(shared['stage']['report'])
        stage_bytes = stage_report.read_bytes()
        stage_report.write_bytes(b'mutated stage report\n')
        with self.assertRaisesRegex(ValueError, 'setup artifact changed'):
            direct._read_shared_b_context(mode_root, case_runner, manifest_sha, 0)
        stage_report.write_bytes(stage_bytes)

        transition_report = Path(shared['transition']['report'])
        transition_report.write_bytes(b'mutated transition report\n')
        with self.assertRaisesRegex(ValueError, 'setup artifact changed'):
            direct._read_shared_b_context(mode_root, case_runner, manifest_sha, 0)

if __name__ == '__main__':
    unittest.main()
