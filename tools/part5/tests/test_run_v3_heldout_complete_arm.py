import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from tools.part5 import run_v3_heldout_complete_arm as complete
from tools.part5.tests.test_run_v3_heldout_direct_arm import arm, h, outer


def complete_arm(mode):
    row = arm(mode)
    row['schema'] = complete.ARM_SCHEMA
    row['identity']['finalized_request_account_sha256'] = row['identity'].pop('finalized_request_sha256')
    row['identity'].update(program_id='program', genesis='common-genesis', request_address='request-pda')
    row['identity'].update(circuit_id=h('circuit'), r1cs_sha256=h('r1cs'), profile_sha256=h('profile'))
    row['shared_context_sha256'] = h('common-fixture')
    row['prepared_import'] = {
        'source_ledger': '/private/baseline/ledger',
        'destination': '/private/' + mode + '/prepared/ledger',
        'tree_sha256': h('prepared-tree'), 'config_sha256': h(mode + '-import-config'),
        'status_sha256': h(mode + '-import-status'),
        'source_prepare_status_sha256': h('prepare-status')}
    row['evidence']['stage_report_sha256'] = h(mode + '-stage')
    row['evidence']['transition_report_sha256'] = h(mode + '-transition')
    row['evidence']['plan_sha256'] = h('plan')
    row['evidence']['replay_package_sha256'] = h('replay')
    row['clone']['tree_sha256'] = h(mode + '-own-r1-tree')
    return row


def mode_outer(mode, seconds):
    report = outer(seconds)
    limits = complete.OUTER_LIMITS[mode]
    report['owner'] = f'heldout-v00-import-{mode}'
    report['limits'] = {
        'runtime_seconds': limits['runtime_seconds'],
        'owned_tree_rss_bytes': limits['rss_bytes'],
        'storage_growth_bytes': limits['storage_bytes'],
    }
    return report


def source_manifest():
    return {'variant': 0, 'frozen_bundles': {
        role: [{'path': relative,
                'artifact': {'path': str(complete.ROOT / relative),
                             'sha256': complete.hashlib.sha256(
                                 (complete.ROOT / relative).read_bytes()).hexdigest()}}
               for relative in paths]
        for role, paths in complete.MEASUREMENT_FILES.items()}}


class CompletePairTests(unittest.TestCase):
    def validate(self, full=None, anchor=None, full_outer=None, anchor_outer=None):
        return complete.validate_pair(full or complete_arm('full'),
            anchor or complete_arm('anchor'), full_outer or mode_outer('full', 100),
            anchor_outer or mode_outer('anchor', 110), variant=0, order=('full', 'anchor'))

    def test_independent_stage_reports_and_r1_trees_are_allowed(self):
        result = self.validate()
        self.assertTrue(result['matched'])
        self.assertEqual(result['anchor_wall_savings_seconds'], -10)
        self.assertFalse(result['registered_complete_session_gate_satisfied'])
        self.assertFalse(result['complete_import_to_execute_arm'])
        self.assertEqual(result['measurement_scope'], 'direct prepared-ledger-import-to-Execute k1')

    def test_exact_action_roots_plan_import_baseline_must_match(self):
        for path in (('identity', 'action_hash'), ('identity', 'finalized_request_account_sha256'),
                     ('identity', 'finalized_action_transport_sha256'),
                     ('identity', 'credential_sha256'), ('identity', 'roots'),
                     ('identity', 'program_id'), ('identity', 'genesis'),
                     ('identity', 'request_address'),
                     ('identity', 'circuit_id'), ('identity', 'r1cs_sha256'),
                     ('prepared_import', 'tree_sha256'),
                     ('prepared_import', 'source_prepare_status_sha256'),
                     ('prepared_import', 'source_ledger'),
                     ('evidence', 'plan_sha256'), ('evidence', 'replay_package_sha256')):
            with self.subTest(path=path), self.assertRaises(ValueError):
                changed = complete_arm('anchor')
                changed[path[0]][path[1]] = h('mismatch')
                self.validate(anchor=changed)

    def test_separate_imported_and_r1_destinations_required(self):
        for group, key in (('prepared_import', 'destination'), ('clone', 'destination')):
            full, anchor = complete_arm('full'), complete_arm('anchor')
            anchor[group][key] = full[group][key]
            with self.subTest(group=group), self.assertRaises(ValueError):
                self.validate(full, anchor)

    def test_failed_censored_unclean_arms_yield_no_comparison(self):
        for field, value in (('passed', False), ('censored', True),
                             ('cleanup_remaining_owned_processes', 1),
                             ('cleanup_status_unknown', True),
                             ('duration_seconds', float('nan'))):
            report = mode_outer('anchor', 110)
            report[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(anchor_outer=report)

    def test_swapped_mode_outer_owners_are_rejected(self):
        full_outer = mode_outer('full', 100)
        anchor_outer = mode_outer('anchor', 110)
        full_outer['owner'], anchor_outer['owner'] = anchor_outer['owner'], full_outer['owner']
        with self.assertRaises(ValueError):
            self.validate(full_outer=full_outer, anchor_outer=anchor_outer)

    def test_weakened_mode_outer_resource_caps_are_rejected(self):
        for mode, field, source_key in (
                ('full', 'runtime_seconds', 'runtime_seconds'),
                ('full', 'owned_tree_rss_bytes', 'rss_bytes'),
                ('full', 'storage_growth_bytes', 'storage_bytes'),
                ('anchor', 'runtime_seconds', 'runtime_seconds'),
                ('anchor', 'owned_tree_rss_bytes', 'rss_bytes'),
                ('anchor', 'storage_growth_bytes', 'storage_bytes')):
            with self.subTest(mode=mode, field=field):
                full_outer, anchor_outer = mode_outer('full', 100), mode_outer('anchor', 110)
                report = full_outer if mode == 'full' else anchor_outer
                report['limits'][field] = complete.OUTER_LIMITS[mode][source_key] - 1
                with self.assertRaises(ValueError):
                    self.validate(full_outer=full_outer, anchor_outer=anchor_outer)

    def test_counterbalance_and_incomplete_receipt_rejected(self):
        self.assertEqual(complete.arm_order(1), ('anchor', 'full'))
        incomplete = complete_arm('anchor')
        incomplete['proof']['ordinary_verified'] = False
        with self.assertRaises(ValueError):
            self.validate(anchor=incomplete)
        with self.assertRaises(ValueError):
            complete.validate_pair(complete_arm('full'), complete_arm('anchor'),
                outer(1), outer(1), variant=0, order=('anchor', 'full'))

    def test_fixture_receipt_binding_is_checked(self):
        fixture = {'prepared': {'status_sha256': h('prepare-status'),
                                'runtime': '/private/baseline'},
                   'replay_package': {'sha256': h('replay')},
                   'domain': {'program_id': 'program', 'genesis': 'common-genesis',
                              'request_address': 'request-pda'},
                   'request_account_sha256': h('request'),
                   'plan_sha256': h('plan')}
        complete.validate_fixture_binding(complete_arm('full'), complete_arm('anchor'), fixture)
        changed = copy.deepcopy(fixture)
        changed['prepared']['status_sha256'] = h('other')
        with self.assertRaises(ValueError):
            complete.validate_fixture_binding(complete_arm('full'), complete_arm('anchor'), changed)

    def test_frame_hash_may_change_while_exact_account_action_remains_matched(self):
        full, anchor = complete_arm('full'), complete_arm('anchor')
        full['evidence']['r0_v3f1_frame_sha256'] = h('full-r0-frame-with-clock')
        anchor['evidence']['r0_v3f1_frame_sha256'] = h('anchor-r0-frame-with-different-clock')
        self.assertTrue(self.validate(full, anchor)['matched'])


class SupervisorTests(unittest.TestCase):
    def run_fake_pair(self, root, *, failed=False, fixture_failure=None,
                      arm_outer_failure=None):
        artifact = root / 'artifacts'
        artifact.mkdir(mode=0o700)
        output = artifact / 'pair'
        seen = []
        fixture = {'prepared': {'status_sha256': h('prepare-status'),
                                'runtime': '/private/baseline'},
                   'domain': {'program_id': 'program', 'genesis': 'common-genesis',
                              'request_address': 'request-pda'},
                   'request_account_sha256': h('request'),
                   'replay_package': {'sha256': h('replay')}, 'plan_sha256': h('plan'),
                   'costs': {'direct_fixture_wall_seconds': 9,
                             'baseline_prepare_wall_seconds': 2}}
        def fixture_call(*args, **kwargs):
            fixture_root = args[-1]
            fixture_root.mkdir(mode=0o700)
            path = fixture_root / 'fixture.json'
            fixture.update(schema=complete.FIXTURE_SCHEMA, variant=0,
                           run_manifest_sha256=h('manifest'),
                           launch_request_sha256=kwargs['launch_sha256'])
            digest = complete.direct._write_new(path, fixture)
            return fixture, path, digest
        def bounded(**kwargs):
            command = kwargs['command']
            mode = 'fixture' if '--_fixture-worker' in command else command[-1]
            seen.append(mode)
            mode_root = Path(command[command.index('--output-root') + 1]).parent
            ticket = json.loads((mode_root / complete.direct.WORKER_TICKET_NAME).read_bytes())
            self.assertEqual(ticket['supervisor_pid'], complete.os.getpid())
            self.assertEqual(kwargs['storage_paths'], (str(artifact),))
            private_output = Path(kwargs['private_output'])
            self.assertNotIn(artifact, private_output.parents)
            self.assertNotIn(private_output, artifact.parents)
            self.assertEqual(private_output.parent.parent, artifact.parent)
            self.assertEqual(kwargs['environment']['P5_V3_DIRECT_ARM_WORKER_TOKEN'], ticket['token'])
            report = outer(12 if mode == 'fixture' else 100 if mode == 'full' else 110)
            report['owner'] = kwargs['owner']
            report['limits'] = {'runtime_seconds': kwargs['runtime_seconds'],
                                'owned_tree_rss_bytes': kwargs['rss_bytes'],
                                'storage_growth_bytes': kwargs['storage_bytes']}
            if mode == 'fixture' and fixture_failure:
                field, value = fixture_failure
                report[field] = value
            elif failed and mode != 'fixture':
                report['censored'] = True
            elif arm_outer_failure and mode == arm_outer_failure[0]:
                field, value = arm_outer_failure[1:]
                if field.startswith('limits.'):
                    report['limits'][field.split('.', 1)[1]] = value
                else:
                    report[field] = value
            complete.direct._write_new(Path(kwargs['report']), report)
            if mode == 'fixture':
                fixture_call(None, Path(command[command.index('--output-root') + 1]),
                             launch_sha256=ticket['shared_context_sha256'])
                return report
            row = complete_arm(mode)
            row['shared_context_sha256'] = ticket['shared_context_sha256']
            complete.direct._write_new(mode_root / 'arm-report.json', row)
            return report
        real_private = complete.direct._private_dir
        def private(path, **kwargs):
            kwargs['ignored'] = False
            return real_private(path, **kwargs)
        fake_case = SimpleNamespace()
        def load(name, path):
            return SimpleNamespace(run=bounded) if name == 'import_arm_session_runner' else fake_case
        with mock.patch.object(complete, 'ARTIFACTS', artifact), mock.patch.object(
                complete, 'global_heavy_lock', return_value=root / 'global.lock'), mock.patch.object(
                complete.direct, '_read_manifest', return_value=(b'', source_manifest(), {}, h('manifest'))), mock.patch.object(
                complete.direct, '_load_module', side_effect=load), mock.patch.object(
                complete.direct, '_private_dir', side_effect=private), mock.patch.object(
                complete, '_build_fixture', side_effect=fixture_call):
            if failed or fixture_failure or arm_outer_failure:
                with self.assertRaises(ValueError):
                    complete.run_pair(root / 'manifest.json', output)
                self.assertFalse((output / 'import-pair-report.json').exists())
                if fixture_failure:
                    expected_seen = ['fixture']
                elif failed or (arm_outer_failure and arm_outer_failure[0] == 'full'):
                    expected_seen = ['fixture', 'full']
                else:
                    expected_seen = ['fixture', 'full', 'anchor']
                self.assertEqual(seen, expected_seen)
                if fixture_failure:
                    self.assertFalse((output / 'arm-full').exists())
                    self.assertFalse((output / 'arm-anchor').exists())
            else:
                result = complete.run_pair(root / 'manifest.json', output)
                self.assertEqual(seen, ['fixture', 'full', 'anchor'])
                self.assertEqual(result['report']['fixture']['costs']['direct_fixture_wall_seconds'], 9)
                self.assertEqual(result['report']['fixture']['costs']['direct_fixture_outer_wall_seconds'], 12)
                self.assertTrue(result['report']['fixture']['outer_cleanup_verified'])
                self.assertEqual(result['report']['comparison']['full_direct_wall_seconds'], 100)
                self.assertFalse(result['report']['registered_complete_session_gate_satisfied'])
                self.assertTrue(Path(result['report_path']).exists())

    def test_serial_outer_boundaries_and_shared_cost_separation(self):
        with tempfile.TemporaryDirectory() as directory:
            self.run_fake_pair(Path(directory).resolve())

    def test_censored_first_arm_prevents_pair_report_and_second_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            self.run_fake_pair(Path(directory).resolve(), failed=True)

    def test_wrong_arm_owner_prevents_acceptance_before_next_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            self.run_fake_pair(Path(directory).resolve(),
                arm_outer_failure=('full', 'owner', 'heldout-v00-import-anchor'))

    def test_weak_arm_storage_cap_prevents_pair_report(self):
        with tempfile.TemporaryDirectory() as directory:
            self.run_fake_pair(Path(directory).resolve(), arm_outer_failure=(
                'anchor', 'limits.storage_growth_bytes',
                complete.OUTER_LIMITS['anchor']['storage_bytes'] - 1))

    def test_failed_censored_or_unclean_fixture_prevents_any_arm_launch(self):
        for field, value in (('passed', False), ('censored', True),
                             ('cleanup_remaining_owned_processes', 1),
                             ('cleanup_status_unknown', True), ('exit_code', 1),
                             ('owner', 'other-owner'), ('limits', {})):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                self.run_fake_pair(Path(directory).resolve(), fixture_failure=(field, value))

    def test_global_lock_is_shared_and_worker_can_verify_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'global.lock'
            fd = complete._acquire_lock(path)
            try:
                self.assertEqual(complete.direct._locked_parent_pid(path), complete.os.getpid())
                with self.assertRaises(BlockingIOError):
                    complete._acquire_lock(path)
            finally:
                complete.fcntl.flock(fd, complete.fcntl.LOCK_UN)
                complete.os.close(fd)

    def test_old_freeze_missing_import_helper_or_changed_measurement_is_rejected(self):
        manifest = source_manifest()
        self.assertEqual(len(complete.require_measurement_freeze(manifest)), 4)
        manifest['frozen_bundles']['registry'].pop(0)
        with self.assertRaises(ValueError):
            complete.require_measurement_freeze(manifest)
        manifest = source_manifest()
        manifest['frozen_bundles']['client'][0]['artifact']['sha256'] = h('old-source')
        with self.assertRaises(ValueError):
            complete.require_measurement_freeze(manifest)

    def test_global_lock_reuses_shared_resolver_under_git_environment_injection(self):
        with tempfile.TemporaryDirectory() as directory:
            owner_artifacts = Path(directory).resolve()
            with mock.patch.dict(complete.os.environ,
                    {'GIT_DIR': '/injected/.git', 'GIT_WORK_TREE': '/injected'}), mock.patch.object(
                    complete.direct, '_shared_lock_artifacts', create=True,
                    return_value=owner_artifacts) as resolver:
                self.assertEqual(complete.global_heavy_lock(),
                                 owner_artifacts / '.v3-heldout-heavy.lock')
                resolver.assert_called_once_with(complete.ROOT)

    def test_fresh_ignored_monitor_siblings_are_private_disjoint_and_overlap_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory).resolve() / 'part5'
            artifact.mkdir(mode=0o700)
            real_private = complete.direct._private_dir
            def private(path, **kwargs):
                self.assertTrue(kwargs.get('ignored'))
                return real_private(path, **{**kwargs, 'ignored': False})
            with mock.patch.object(complete, 'ARTIFACTS', artifact), mock.patch.object(
                    complete.direct, '_private_dir', side_effect=private):
                first = complete._new_supervision_root()
                second = complete._new_supervision_root()
                self.assertNotEqual(first, second)
                self.assertEqual(first.parent, artifact.parent)
                self.assertEqual(first.stat().st_mode & 0o7777, 0o700)
                self.assertEqual(complete._outer_storage_paths(first / 'monitor'), (str(artifact),))
                for bad in (artifact / 'monitor', artifact, artifact.parent):
                    with self.subTest(bad=bad), self.assertRaises(ValueError):
                        complete._outer_storage_paths(bad)


class FixtureWorkerAuthorizationTests(unittest.TestCase):
    def exercise(self, failure=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            artifact = root / 'part5'
            artifact.mkdir(mode=0o700)
            pair = artifact / 'pair'
            pair.mkdir(mode=0o700)
            mode_root = pair / 'shared-fixture'
            mode_root.mkdir(mode=0o700)
            output = mode_root / 'case-run'
            manifest_sha = h('manifest')
            token = 'fixture-token'
            ticket = {'schema': complete.direct.WORKER_TICKET_SCHEMA, 'mode': 'fixture',
                      'case_output_root': str(output), 'manifest_sha256': manifest_sha,
                      'shared_context_sha256': complete._fixture_launch_sha(manifest_sha, output),
                      'supervisor_pid': complete.os.getpid(), 'token': token}
            if failure == 'parent':
                ticket['supervisor_pid'] += 1
            elif failure == 'manifest':
                ticket['manifest_sha256'] = h('other-manifest')
            elif failure == 'root':
                ticket['case_output_root'] = str(mode_root / 'other-root')
            elif failure == 'launch':
                ticket['shared_context_sha256'] = h('unbound-launch')
            complete.direct._write_new(mode_root / complete.direct.WORKER_TICKET_NAME, ticket)
            lock = root / 'global.lock'
            fd = complete._acquire_lock(lock)
            if failure == 'lock':
                complete.fcntl.flock(fd, complete.fcntl.LOCK_UN)
            real_private = complete.direct._private_dir
            def private(path, **kwargs):
                return real_private(path, **{**kwargs, 'ignored': False})
            try:
                with mock.patch.object(complete, 'ARTIFACTS', artifact), mock.patch.object(
                        complete, 'global_heavy_lock', return_value=lock), mock.patch.object(
                        complete.direct, '_private_dir', side_effect=private), mock.patch.object(
                        complete.direct, '_load_module', return_value=SimpleNamespace()), mock.patch.object(
                        complete.direct, '_read_manifest', return_value=(b'', source_manifest(), {}, manifest_sha)), mock.patch.object(
                        complete.os, 'getppid', return_value=complete.os.getpid()), mock.patch.dict(
                        complete.os.environ, {'P5_V3_DIRECT_ARM_WORKER_TOKEN': token}), mock.patch.object(
                        complete, '_build_fixture', return_value=({'variant': 0}, None, None)) as build:
                    if failure:
                        with self.assertRaises(ValueError):
                            complete._run_fixture_worker(root / 'manifest.json', output,
                                                         'wrong-token' if failure == 'token' else token)
                        build.assert_not_called()
                    else:
                        self.assertEqual(complete._run_fixture_worker(root / 'manifest.json', output, token),
                                         {'variant': 0})
                        build.assert_called_once()
                        self.assertEqual(build.call_args.kwargs['launch_sha256'], ticket['shared_context_sha256'])
                        with self.assertRaises(ValueError):
                            complete._run_fixture_worker(root / 'manifest.json', output, token)
                        self.assertEqual(build.call_count, 1)
            finally:
                complete.fcntl.flock(fd, complete.fcntl.LOCK_UN)
                complete.os.close(fd)

    def test_authenticated_fixture_worker_consumes_one_time_ticket(self):
        self.exercise()

    def test_missing_lock_wrong_parent_token_manifest_root_or_launch_is_rejected(self):
        for failure in ('lock', 'parent', 'token', 'manifest', 'root', 'launch'):
            with self.subTest(failure=failure):
                self.exercise(failure)
