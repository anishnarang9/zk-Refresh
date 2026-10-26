"""Source-only registration, boundary and matching tests; never starts a validator."""
import copy
import importlib.util
import unittest
import json
import os
from pathlib import Path
import tempfile
from unittest import mock
from types import SimpleNamespace
from tools.part5.tests.test_run_v3_heldout_complete_arm import complete_arm
from tools.part5.tests.test_run_v3_heldout_direct_arm import h, outer


def row(mode, repeat=0):
    from tools.part5 import run_v3_heldout_whole_session as whole
    item = complete_arm(mode)
    item['schema'] = whole.ARM_SCHEMA
    item['repeat'] = repeat
    item['boundary_steps'] = list(whole.BOUNDARY)
    item['seed'] = {'manifest_sha256': h('blank-seed'), 'tree_sha256': h('blank-tree'),
                    'genesis_file_sha256': h('genesis'),
                    'initial_ledger': '/private/' + mode + '/main/ledger',
                    'control_ledger': '/private/' + mode + '/control/ledger',
                    'deployed_inside_timer': True}
    item['effect']['final_request_sha256'] = h('consumed')
    item['effect']['final_queue_sha256'] = h('queue-effect')
    item['transaction_metrics'] = {'transaction_bytes': 1100, 'compute_units': 210000,
                                   'fee_lamports': 5000}
    return item


def owned_outer(mode, repeat=0, seconds=100):
    from tools.part5 import run_v3_heldout_whole_session as whole
    result = outer(seconds)
    result['owner'] = f'heldout-v00-whole-r{repeat}-{mode}'
    cap = whole.OUTER_LIMITS[mode]
    result['limits'] = {'runtime_seconds': cap['runtime_seconds'],
                        'owned_tree_rss_bytes': cap['rss_bytes'],
                        'storage_growth_bytes': cap['storage_bytes']}
    return result


class RegistrationTests(unittest.TestCase):
    def test_whole_session_module_and_fixed_four_pair_registration(self):
        name = 'tools.part5.run_v3_heldout_whole_session'
        self.assertIsNotNone(importlib.util.find_spec(name),
                             'registered whole-session supervisor is missing')
        module = __import__(name, fromlist=['registered_order'])
        self.assertEqual([module.registered_order(i) for i in range(4)],
                         [('full', 'anchor'), ('anchor', 'full'),
                          ('full', 'anchor'), ('anchor', 'full')])
        for invalid in (-1, 4, True, 1.0):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                module.registered_order(invalid)


class MatchingTests(unittest.TestCase):
    def validate(self, full=None, anchor=None, fouter=None, aouter=None):
        from tools.part5 import run_v3_heldout_whole_session as whole
        return whole.validate_pair(full or row('full'), anchor or row('anchor'),
            fouter or owned_outer('full'), aouter or owned_outer('anchor', seconds=110),
            repeat=0, order=('full', 'anchor'))

    def test_direct_wall_reports_real_loss_and_full_boundary(self):
        result = self.validate()
        self.assertAlmostEqual(result['anchor_wall_savings_fraction'], -.1)
        self.assertTrue(result['registered_complete_session_gate_satisfied'])
        self.assertFalse(result['complete_tree_cpu_qualified'])

    def test_action_roots_seed_and_final_effect_mismatch_rejected(self):
        for group, field in (
            ('identity', 'action_hash'), ('identity', 'finalized_request_account_sha256'),
            ('identity', 'setup_sha256'), ('identity', 'roots'),
            ('seed', 'manifest_sha256'), ('seed', 'tree_sha256'),
            ('effect', 'final_request_sha256'), ('effect', 'final_queue_sha256')):
            changed = row('anchor')
            changed[group][field] = h('mismatch')
            with self.subTest(group=group, field=field), self.assertRaises(ValueError):
                self.validate(anchor=changed)

    def test_missing_prep_control_or_ordinary_work_cannot_pass(self):
        for omitted in ('initial_prepare', 'control_fixture', 'proof_and_ordinary_verification'):
            changed = row('anchor')
            changed['boundary_steps'].remove(omitted)
            with self.subTest(omitted=omitted), self.assertRaises(ValueError):
                self.validate(anchor=changed)
        changed = row('anchor')
        changed['seed']['deployed_inside_timer'] = False
        with self.assertRaises(ValueError):
            self.validate(anchor=changed)

    def test_shared_or_nested_ledger_destinations_rejected(self):
        for path in ('/private/full/main/ledger', '/private/full/main/ledger/child'):
            changed = row('anchor')
            changed['seed']['initial_ledger'] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.validate(anchor=changed)

    def test_censored_unclean_wrong_owner_and_weaker_caps_are_rejected(self):
        for field, value in (('censored', True), ('passed', False),
                             ('cleanup_remaining_owned_processes', 1),
                             ('cleanup_status_unknown', True), ('owner', 'other'),
                             ('duration_seconds', float('nan'))):
            changed = owned_outer('anchor')
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(aouter=changed)
        changed = owned_outer('anchor')
        changed['limits']['runtime_seconds'] -= 1
        with self.assertRaises(ValueError):
            self.validate(aouter=changed)

    def test_summary_never_replaces_excluded_pair_or_claims_four_valid(self):
        from tools.part5 import run_v3_heldout_whole_session as whole
        pairs = [{'repeat': i, 'status': 'valid', 'anchor_wall_savings_fraction': v}
                 for i, v in enumerate((.3, .2, -.1, .1))]
        result = whole.summarize(pairs)
        self.assertEqual(result['all_pair_savings_fractions'], [.3, .2, -.1, .1])
        self.assertAlmostEqual(result['median_savings_fraction'], .15)
        self.assertFalse(result['registered_twenty_percent_target_met'])
        pairs[1] = {'repeat': 1, 'status': 'excluded', 'reason': 'censored'}
        result = whole.summarize(pairs)
        self.assertEqual(result['valid_pairs'], 3)
        self.assertFalse(result['four_valid_pairs'])
        with self.assertRaises(ValueError):
            whole.summarize(pairs + [pairs[1]])


class BoundaryTests(unittest.TestCase):
    def test_runner_rejects_application_output_outside_outer_storage_coverage(self):
        from tools.part5 import run_v3_heldout_whole_session as whole
        class Base:
            def __init__(self, *args, **kwargs): pass
            def _art(self, req, label): return '/artifacts/' + label
        runner = whole._seeded_runner(SimpleNamespace(HeldoutCaseRunner=Base), {},
            Path('/unused'), {}, h('manifest'), {}, {}, allowed_outputs={'/artifacts/runtime'})
        self.assertEqual(runner._art('unrelated_compare', 'runtime'), '/artifacts/runtime')
        with self.assertRaises(ValueError):
            runner._art('unrelated_compare', 'untracked-output')

    def test_seed_profile_deactivates_exactly_legacy_deployment_gate(self):
        from tools.part5 import run_v3_heldout_whole_session as whole
        self.assertTrue(hasattr(whole.seed, 'LOCAL_COMPATIBILITY_PROFILE'),
                        'explicit local V0 feature profile is missing')
        profile = whole.seed.LOCAL_COMPATIBILITY_PROFILE
        self.assertEqual(profile['deactivated_features'],
                         ['B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g'])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            config = {'scope': whole.seed.CREATE_SCOPE,
                      'outer_limits_required': whole.seed.base.LIMITS,
                      'runtime_feature_profile': {**profile, 'deactivated_features': []}}
            path = root / 'config.json'
            whole.direct._write_new(path, config)
            with mock.patch.object(whole.subprocess, 'Popen') as process:
                with self.assertRaises(ValueError):
                    whole._create_seed(whole._pin(path))
                process.assert_not_called()

    def test_arm_storage_covers_only_fresh_mode_root_and_exact_application_siblings(self):
        from tools.part5 import run_v3_heldout_whole_session as whole
        from tools.part5 import run_v3_heldout_case as case
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            mode_root = root / 'mode'; mode_root.mkdir(mode=0o700)
            ids = {'control': 'a' * 32, 'main': 'b' * 32}
            with mock.patch.object(whole, 'ARTIFACTS', root):
                paths = whole.arm_storage_paths(case, mode_root, ids, 'full')
                self.assertEqual(paths[0], str(mode_root))
                self.assertEqual(len(paths), 13)
                self.assertNotIn(str(root), paths)
                expected = root / case.application_artifact_name(0, ids['main'],
                                                                 'unrelated_compare', 'unrelated_full')
                self.assertIn(str(expected), paths)
                self.assertTrue(all(Path(p).parent == root for p in paths[1:]))
                expected.mkdir(mode=0o700)
                with self.assertRaises(ValueError):
                    whole.arm_storage_paths(case, mode_root, ids, 'full')

    def test_preassigned_run_id_files_are_created_only_in_worker_initialization(self):
        from tools.part5 import run_v3_heldout_whole_session as whole
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            output = root / 'main-case'
            self.assertFalse(output.exists())
            real_private = whole.direct._private_dir
            def private(path, **kwargs):
                return real_private(path, **{**kwargs, 'ignored': False})
            with mock.patch.object(whole.direct, '_private_dir', side_effect=private):
                whole.initialize_runner_root(output, 'a' * 32)
            self.assertEqual(json.loads((output / 'run-id.json').read_bytes()),
                {'schema': 'credential-v3-heldout-run-id-v1', 'run_id': 'a' * 32})
            self.assertEqual([p.name for p in output.iterdir()], ['run-id.json'])

    def test_stopped_seed_removes_only_normal_validator_log_alias(self):
        from tools.part5 import run_v3_heldout_whole_session as whole
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary).resolve()
            target = ledger / 'validator-1792470927446.log'
            target.write_bytes(b'unchanged validator log')
            target.chmod(0o600)
            alias = ledger / 'validator.log'
            alias.symlink_to(target.name)
            cleanup = {'spawned': True, 'reaped': True, 'graceful': False, 'exit_code': -2}
            result = whole.normalize_stopped_log_alias(ledger, cleanup)
            self.assertTrue(result['removed'])
            self.assertFalse(alias.is_symlink())
            self.assertEqual(target.read_bytes(), b'unchanged validator log')
            self.assertEqual(result['target_sha256'], h('unchanged validator log'))

    def test_log_alias_cleanup_rejects_unsafe_links_without_mutation(self):
        from tools.part5 import run_v3_heldout_whole_session as whole
        for mutation in ('escaping', 'absolute', 'directory', 'wrong-name', 'hardlink',
                         'extra-link', 'unreaped', 'wrong-mode'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                ledger = Path(temporary).resolve()
                target = ledger / 'validator-123.log'
                target.write_bytes(b'log bytes'); target.chmod(0o600)
                alias = ledger / 'validator.log'
                destination = target.name
                if mutation == 'escaping': destination = '../validator-123.log'
                if mutation == 'absolute': destination = str(target)
                if mutation == 'directory':
                    target.unlink(); target.mkdir(mode=0o700)
                if mutation == 'wrong-name': destination = 'genesis.bin'
                if mutation == 'hardlink': os.link(target, ledger / 'another-log')
                if mutation == 'extra-link': (ledger / 'ledger-state').symlink_to(target.name)
                if mutation == 'wrong-mode': target.chmod(0o644)
                alias.symlink_to(destination)
                cleanup = {'spawned': True, 'reaped': mutation != 'unreaped',
                           'graceful': False, 'exit_code': -2}
                with self.assertRaises(ValueError):
                    whole.normalize_stopped_log_alias(ledger, cleanup)
                self.assertTrue(alias.is_symlink())

    def test_real_source_three_root_contract_projects_only_registered_R0_R1(self):
        from tools.part5 import run_v3_heldout_whole_session as whole
        source = {'membership_roots': {k: h(k) for k in ('R0', 'R1', 'R2')}}
        self.assertEqual(whole.selected_roots(source), {'R0': h('R0'), 'R1': h('R1')})
        with self.assertRaises(ValueError):
            whole.selected_roots({'membership_roots': {'R0': h('R0'), 'R1': h('R1')}})

    def test_every_operation_runs_inside_one_outer_owner_and_in_order(self):
        from tools.part5 import run_v3_heldout_whole_session as whole
        active, events = [], []
        operations = {}
        for name in whole.BOUNDARY:
            def operation(name=name):
                self.assertEqual(active, ['outer'])
                events.append(name)
                return {'step': name}
            operations[name] = operation
        active.append('outer')
        result = whole.run_boundary(operations)
        active.pop()
        self.assertEqual(events, list(whole.BOUNDARY))
        self.assertEqual(list(result), list(whole.BOUNDARY))
        with self.assertRaises(ValueError):
            whole.run_boundary({k: v for k, v in operations.items() if k != 'initial_prepare'})

    def test_replay_reconstruction_is_deterministic_and_context_bound(self):
        from tools.part5 import run_v3_heldout_whole_session as whole
        from harness.tests import queue_v3_local_prepare as prep
        from harness.tests import queue_v3_local_stage as stage
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            entropy = {'schema': 'credential-v3-whole-session-entropy-v1',
                       'keys': {k: bytes([i + 1] * 32).hex() for i, k in
                                enumerate(('admin', 'publisher', 'source', 'creator'))},
                       'seed': bytes([5] * 32).hex(), 'nonce': bytes([6] * 32).hex()}
            context = {k: h(k) for k in ('root', 'issuer_hash', 'aki', 'policy_id')}
            context.update(not_before=1, not_after=2000000000)
            context_path = root / 'stage-context.json'
            context_path.write_text(json.dumps(context))
            context_path.chmod(0o600)
            domain = {'program': prep.b58(bytes([8] * 32)),
                      'genesis': prep.b58(bytes([9] * 32))}
            first = whole.reconstruct_replay(root / 'first', entropy, context_path, domain)
            second = whole.reconstruct_replay(root / 'second', entropy, context_path, domain)
            self.assertEqual(first['sha256'], second['sha256'])
            plan = json.loads((root / 'first/plan.json').read_bytes())
            self.assertEqual(plan['deadline'], context['not_after'])
            self.assertEqual(plan['recipient'], plan['source'])
            self.assertEqual(len(json.loads((root / 'first/admin.json').read_bytes())), 64)
            config = {'replay_package': first, 'context_sha256': h('wrong-context')}
            with self.assertRaises(ValueError):
                stage.replay_environment(config, context)

    def test_shared_allocation_is_equal_and_never_added_to_direct_clock(self):
        from tools.part5 import run_v3_heldout_whole_session as whole
        result = whole.allocate_shared_costs(seed_seconds=80, entropy_seconds=8,
                                            setup_seconds=800, setup_actions=8)
        self.assertEqual(result['seed_and_entropy_seconds_per_action'], 11)
        self.assertEqual(result['setup_seconds_per_action'], 100)
        self.assertEqual(result['equal_common_seconds_per_mode_action'], 111)
        self.assertFalse(result['added_to_direct_outer_wall'])
        with self.assertRaises(ValueError):
            whole.allocate_shared_costs(seed_seconds=80, entropy_seconds=8,
                                        setup_seconds=float('nan'), setup_actions=8)

    def test_seed_creator_uses_blank_argv_and_retains_reviewed_sigint(self):
        from tools.part5 import run_v3_heldout_whole_session as whole
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            output = root / 'seed'
            program, payer, genesis = [whole.seed.base.b58(bytes([i] * 32)) for i in (7, 8, 9)]
            validator = root / 'validator'
            validator.write_bytes(b'test executable identity')
            config = {'schema': 1, 'scope': whole.seed.CREATE_SCOPE,
                      'outer_limits_required': whole.seed.base.LIMITS,
                      'runtime_feature_profile': whole.seed.LOCAL_COMPATIBILITY_PROFILE,
                      'runtime_output': str(output / 'runtime'),
                      'control_output': str(output / 'control'),
                      'validator': str(validator), 'validator_sha256': h('test executable identity'),
                      'program': program, 'payer': payer}
            config_path = root / 'config.json'
            whole.direct._write_new(config_path, config)
            captured = []
            def popen(argv, **kwargs):
                captured.append(argv)
                current_umask = os.umask(0o077)
                os.umask(current_umask)
                self.assertEqual(current_umask, 0o077)
                self.assertNotIn('--bpf-program', argv)
                self.assertIn('--reset', argv)
                self.assertEqual(argv.count('--deactivate-feature'), 1)
                self.assertEqual(argv[argv.index('--deactivate-feature') + 1],
                                 'B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g')
                ledger = Path(argv[argv.index('--ledger') + 1])
                ledger.mkdir(mode=0o700)
                log = ledger / 'validator-123.log'
                log.write_bytes(b'validator log'); log.chmod(0o600)
                (ledger / 'validator.log').symlink_to(log.name)
                return SimpleNamespace(poll=lambda: None)
            real_private = whole.direct._private_dir
            def private(path, **kwargs):
                return real_private(path, **{**kwargs, 'ignored': False})
            initial_umask = os.umask(0o077)
            os.umask(initial_umask)
            with mock.patch.object(whole.direct, '_private_dir', side_effect=private), \
                    mock.patch.object(whole.seed.base, 'ports_free'), \
                    mock.patch.object(whole.subprocess, 'Popen', side_effect=popen), \
                    mock.patch.object(whole.seed.base, 'LocalRpc', return_value=lambda *args: genesis), \
                    mock.patch.object(whole.seed, 'observe_blank', return_value={'genesis': genesis}), \
                    mock.patch.object(whole.seed.base, 'cleanup', return_value={
                        'spawned': True, 'reaped': True, 'graceful': False, 'exit_code': -2}):
                status = whole._create_seed(whole._pin(config_path))
            restored_umask = os.umask(initial_umask)
            self.assertEqual(restored_umask, initial_umask)
            self.assertEqual(len(captured), 1)
            self.assertEqual(status['status'], 'failed')
            self.assertIsNone(status['error_type'])
            self.assertTrue(status['blank_verified'])
            self.assertNotIn('loaded_program', status)
            self.assertNotIn('elf_sha256', status)
            self.assertEqual(status, json.loads((output / 'control/status.json').read_bytes()))

    def test_seed_outer_caps_match_source_contract(self):
        from tools.part5 import run_v3_heldout_whole_session as whole
        self.assertEqual(whole.OUTER_LIMITS['seed']['runtime_seconds'],
                         whole.seed.base.LIMITS['runtime_seconds'])
        self.assertEqual(whole.OUTER_LIMITS['seed']['rss_bytes'],
                         whole.seed.base.LIMITS['rss_bytes'])
        self.assertEqual(whole.OUTER_LIMITS['seed']['storage_bytes'],
                         whole.seed.base.LIMITS['storage_growth_bytes'])

    def test_pre_freeze_seed_worker_accepts_only_labeled_pilot_without_heldout_admission(self):
        from tools.part5 import run_v3_heldout_whole_session as whole
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest = root / 'pilot.json'
            whole.direct._write_new(manifest, {'schema': 'credential-v3-blank-seed-pilot-v1'})
            worker = root / 'case-run'
            config = {'owner_manifest': whole._pin(manifest),
                      'runtime_output': str(worker / 'runtime'), 'control_output': str(worker / 'control'),
                      'owner_source': {'path': str(Path(whole.__file__).resolve()),
                                       'sha256': whole.direct._digest(Path(whole.__file__).read_bytes())}}
            path = root / 'config.json'
            whole.direct._write_new(path, config)
            ref = whole._pin(path)
            whole.direct._write_new(root / whole.direct.WORKER_CLAIM_NAME,
                                    {'shared_context_sha256': ref['sha256']})
            with mock.patch.object(whole.direct, '_authorize_worker') as authorize, \
                    mock.patch.object(whole.complete, 'global_heavy_lock', return_value=root / 'lock'), \
                    mock.patch.object(whole.direct, '_read_manifest', side_effect=AssertionError('heldout validation forbidden')), \
                    mock.patch.object(whole, '_create_seed', return_value={'status': 'passed'}) as create:
                self.assertEqual(whole._create_seed_worker(manifest, worker, ref), {'status': 'passed'})
                authorize.assert_called_once()
                create.assert_called_once_with(ref)

    def test_seed_launcher_pins_exact_worker_argv_and_source_owner(self):
        from tools.part5 import run_v3_heldout_whole_session as whole
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            artifacts = root / 'part5'; artifacts.mkdir(mode=0o700)
            output = artifacts / 'pilot'; output.mkdir(mode=0o700)
            supervision = root / 'supervision'; supervision.mkdir(mode=0o700)
            manifest = root / 'pilot.json'
            whole.direct._write_new(manifest, {'schema': 'credential-v3-blank-seed-pilot-v1'})
            captured = []
            def bounded(**kwargs):
                captured.append(kwargs)
                argv = kwargs['command']
                mode_root = Path(argv[argv.index('--output-root') + 1]).parent
                config_ref = {'path': argv[argv.index('--seed-config') + 1],
                              'sha256': argv[argv.index('--seed-config-sha256') + 1]}
                config = whole.seed.pin(config_ref)
                self.assertEqual(config['owner_manifest'], whole._pin(manifest))
                self.assertEqual(config['runtime_feature_profile'], whole.seed.LOCAL_COMPATIBILITY_PROFILE)
                self.assertNotIn('elf', config)
                self.assertEqual(argv[-1], '--_create-seed')
                self.assertEqual(kwargs['storage_paths'], (str(output),))
                monitor = Path(kwargs['private_output']); monitor.mkdir(mode=0o700)
                self.assertNotIn(artifacts, monitor.parents)
                whole.direct._write_new(monitor / 'invocation.json', {
                    'owner': kwargs['owner'], 'argv': argv, 'cwd': kwargs['cwd'],
                    'started_at_utc': '2026-10-20T00:00:00Z',
                    'storage_roots': [str(monitor), *kwargs['storage_paths']]})
                worker = Path(config['control_output']); worker.mkdir(mode=0o700, parents=True)
                whole.direct._write_new(worker / 'status.json', {'status': 'failed'})
                report = outer(2)
                report.update(owner=kwargs['owner'], limits={
                    'runtime_seconds': kwargs['runtime_seconds'],
                    'owned_tree_rss_bytes': kwargs['rss_bytes'],
                    'storage_growth_bytes': kwargs['storage_bytes']})
                whole.direct._write_new(Path(kwargs['report']), report)
                return report
            real_private = whole.direct._private_dir
            def private(path, **kwargs):
                return real_private(path, **{**kwargs, 'ignored': False})
            with mock.patch.object(whole, 'ARTIFACTS', artifacts), \
                    mock.patch.object(whole.direct, '_private_dir', side_effect=private), \
                    mock.patch.object(whole.seed, 'signer', return_value='payer'), \
                    mock.patch.object(whole.seed, 'build_manifest', return_value={'schema': whole.seed.SCHEMA}) as build:
                ref, costs = whole._launch_seed(SimpleNamespace(run=bounded), manifest,
                    whole._pin(manifest), {'validator': '/validator', 'validator_sha256': h('validator'),
                                          'program': 'program'},
                    {'deployment_payer': {'path': '/payer', 'sha256': h('payer')}}, output, supervision)
            self.assertEqual(len(captured), 1)
            self.assertEqual(costs['seed_creation_outer_seconds'], 2)
            self.assertEqual(set(build.call_args.args[0]),
                             {'config', 'status', 'monitor', 'monitor_owner', 'invocation'})
            self.assertEqual(whole.seed.pin(ref)['schema'], whole.seed.SCHEMA)


class CampaignTests(unittest.TestCase):
    def campaign(self, *, failure=None):
        from tools.part5 import run_v3_heldout_whole_session as whole
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            artifacts = root / 'part5'; artifacts.mkdir(mode=0o700)
            output = artifacts / 'campaign'
            base_path = root / 'base.json'
            whole.direct._write_new(base_path, {'validator': '/validator', 'program': 'program'})
            manifest_path = root / 'manifest.json'
            manifest = {'variant': 0, 'cohort_sha256': h('cohort'),
                        'frozen_files': {'setup_manifest': {'sha256': h('setup')}},
                        'base_prepare_config': str(base_path),
                        'base_prepare_config_sha256': whole._pin(base_path)['sha256']}
            whole.direct._write_new(manifest_path, manifest)
            run_ref = whole._pin(manifest_path)
            deployment_path = root / 'deployment.json'
            whole.direct._write_new(deployment_path,
                {name: {'path': '/' + name, 'sha256': h(name)} for name in
                 ('solana_cli', 'program_signer', 'deployment_payer')})
            monitor = root / 'setup-monitor.json'
            whole.direct._write_new(monitor, outer(800))
            prerequisite_path = root / 'prerequisites.json'
            whole.direct._write_new(prerequisite_path, {
                'schema': 'credential-v3-whole-session-prerequisites-v1',
                'setup_manifest_sha256': h('setup'), 'cohort_sha256': h('cohort'),
                'setup_monitor': whole._pin(monitor), 'setup_allocation_actions': 8,
                'issuance_and_enrollment': {'status': 'separate pinned cohort receipt'}})
            events = []
            def bounded(**kwargs):
                argv = kwargs['command']
                mode, repeat = argv[argv.index('--_mode') + 1], int(argv[argv.index('--repeat') + 1])
                events.append((repeat, mode))
                worker = Path(argv[argv.index('--output-root') + 1])
                launch = whole.seed.pin({'path': argv[argv.index('--launch') + 1],
                    'sha256': argv[argv.index('--launch-sha256') + 1]})
                ticket = json.loads((worker.parent / whole.direct.WORKER_TICKET_NAME).read_bytes())
                self.assertEqual(ticket['shared_context_sha256'],
                                 argv[argv.index('--launch-sha256') + 1])
                storage = kwargs['storage_paths']
                self.assertEqual(storage[0], str(worker.parent))
                self.assertEqual(len(storage), 13)
                self.assertNotIn(str(artifacts), storage)
                self.assertTrue(all(Path(p).parent == artifacts for p in storage[1:]))
                report = owned_outer(mode, repeat, 100 if mode == 'full' else 110)
                if repeat == 0 and failure:
                    report[failure[0]] = failure[1]
                whole.direct._write_new(Path(kwargs['report']), report)
                receipt = row(mode, repeat)
                receipt['run_ids'] = launch['run_ids']
                receipt['shared_context_sha256'] = launch['shared_identity_sha256']
                whole.direct._write_new(worker.parent / 'arm-report.json', receipt)
                return report
            case = SimpleNamespace(_json=lambda path, *args: json.loads(Path(path).read_bytes()),
                application_artifact_name=lambda variant, run_id, request, label:
                    f'application-v3-heldout-{variant:02d}-{run_id}-{request}-{label}')
            def load(name, path):
                return SimpleNamespace(run=bounded) if name == 'whole_campaign_session' else case
            real_private = whole.direct._private_dir
            def private(path, **kwargs):
                return real_private(path, **{**kwargs, 'ignored': False})
            def seed_launch(*args):
                events.append('seed')
                return {'path': '/blank-seed', 'sha256': h('blank-seed')}, {'seed_creation_outer_seconds': 80}
            with mock.patch.object(whole, 'ARTIFACTS', artifacts), \
                    mock.patch.object(whole.direct, '_private_dir', side_effect=private), \
                    mock.patch.object(whole.direct, '_load_module', side_effect=load), \
                    mock.patch.object(whole.direct, '_read_manifest', return_value=(b'', manifest, run_ref, h('manifest'))), \
                    mock.patch.object(whole, 'require_freeze', return_value={}), \
                    mock.patch.object(whole.complete, 'global_heavy_lock', return_value=root / 'global.lock'), \
                    mock.patch.object(whole, '_launch_seed', side_effect=seed_launch):
                result = whole.run_campaign(manifest_path, output,
                    whole._pin(deployment_path), whole._pin(prerequisite_path))
            return result['report'], events

    def test_four_fresh_serial_pairs_have_one_outer_per_mode_and_equal_common_costs(self):
        report, events = self.campaign()
        self.assertEqual(events, ['seed', (0, 'full'), (0, 'anchor'),
            (1, 'anchor'), (1, 'full'), (2, 'full'), (2, 'anchor'), (3, 'anchor'), (3, 'full')])
        self.assertTrue(report['summary']['four_valid_pairs'])
        self.assertFalse(report['summary']['registered_twenty_percent_target_met'])
        for pair in report['pairs']:
            self.assertEqual(pair['full_direct_wall_seconds'], 100)
            self.assertEqual(pair['anchor_direct_wall_seconds'], 110)
            self.assertGreater(pair['allocated_common_seconds_per_action'], 100)

    def test_censored_pair_is_preserved_without_replacement(self):
        report, events = self.campaign(failure=('censored', True))
        self.assertEqual(report['pairs'][0]['status'], 'excluded')
        self.assertEqual(report['summary']['valid_pairs'], 3)
        self.assertEqual(len(events), 8)  # seed + failed first arm + six later arms
        self.assertNotIn((0, 'anchor'), events)

    def test_unclean_owner_stops_all_later_launches_and_retains_exclusions(self):
        report, events = self.campaign(failure=('cleanup_remaining_owned_processes', 1))
        self.assertEqual(events, ['seed', (0, 'full')])
        self.assertEqual(report['summary']['excluded_pairs'], 4)
        self.assertEqual([p['repeat'] for p in report['pairs']], [0, 1, 2, 3])


class HistoricalSetupTests(unittest.TestCase):
    def fixture(self, root):
        from tools.part5 import run_v3_heldout_whole_session as whole
        def write(path, value):
            if isinstance(value, bytes):
                path.write_bytes(value); path.chmod(0o600)
            else:
                whole.direct._write_new(path, value)
            return whole._pin(path)
        binary = write(root / 'setup-runner', b'actual setup executable')
        r1cs = write(root / 'credential.r1cs', b'relation')
        wasm = write(root / 'credential.wasm', b'witness runtime')
        profile = write(root / 'profile.json', {'bounded_profile': True})
        suite = write(root / 'suite.json', {'qualified': True})
        output = root / 'setup'; output.mkdir(mode=0o700)
        setup = write(output / 'setup-manifest.json', {
            'schema': 'credential-v3-bounded-setup-v1', 'binary_sha256': binary['sha256'],
            'r1cs_sha256': r1cs['sha256'], 'wasm_sha256': wasm['sha256'],
            'profile_sha256': profile['sha256'], 'accepted_suite_path': suite['path'],
            'accepted_suite_sha256': suite['sha256'], 'elapsed_ms': 1100.0})
        private = root / 'monitor'; private.mkdir(mode=0o700)
        report = {'schema': 1, 'owner': 'historical-setup-owner', 'duration_seconds': 1.4,
            'limits': {'runtime_seconds': 10.0, 'owned_tree_rss_bytes': 1000,
                       'storage_growth_bytes': 1000, 'poll_seconds': .25},
            'stop_reason': None, 'exit_code': 0, 'runner_error_type': None,
            'cleanup_remaining_owned_processes': 0, 'cleanup_status_unknown': False,
            'sample_count': 2, 'samples': [
                {'elapsed_seconds': .1, 'owned_process_count': 1,
                 'owned_tree_rss_bytes': 10, 'storage_growth_bytes': 20},
                {'elapsed_seconds': 1.3, 'owned_process_count': 0,
                 'owned_tree_rss_bytes': 0, 'storage_growth_bytes': 500}],
            'sampled_peak_owned_tree_rss_bytes': 10,
            'sampled_peak_storage_growth_bytes': 500, 'passed': True}
        monitor = write(private / 'report.json', report)
        invocation = {'owner': report['owner'], 'cwd': str(whole.ROOT),
            'started_at_utc': '2026-10-15T13:20:55Z',
            'storage_roots': [str(private), str(output)],
            'argv': [binary['path'], 'setup', r1cs['path'], wasm['path'], profile['path'],
                     suite['path'], suite['sha256'], str(output)]}
        invoke = write(private / 'invocation.json', invocation)
        manifest = {'frozen_files': {'setup_manifest': setup, 'r1cs': r1cs, 'profile': profile}}
        prerequisite = {'setup_measurement_kind': 'historical-bounded-runner-v1',
            'setup_monitor': monitor, 'setup_invocation': invoke,
            'setup_manifest_sha256': setup['sha256']}
        return prerequisite, manifest, report, invocation

    def test_historical_setup_is_explicit_pinned_and_keeps_old_schema_caveat(self):
        from tools.part5 import run_v3_heldout_whole_session as whole
        with tempfile.TemporaryDirectory() as temporary:
            prereq, manifest, report, _ = self.fixture(Path(temporary).resolve())
            before = copy.deepcopy(report)
            value = whole.setup_accounting(prereq, manifest)
            self.assertEqual(value['duration_seconds'], 1.4)
            self.assertEqual(value['qualification'], 'historical bounded setup wall only')
            self.assertFalse(value['current_session_schema_qualified'])
            self.assertEqual(value['missing_current_fields'], ['measurement', 'censored'])
            self.assertEqual(report, before)
            self.assertNotIn('censored', json.loads(Path(prereq['setup_monitor']['path']).read_bytes()))
            prereq.pop('setup_measurement_kind')
            with self.assertRaises(ValueError): whole.setup_accounting(prereq, manifest)

    def test_historical_failures_samples_caps_cleanup_and_mixed_schema_fail_closed(self):
        from tools.part5 import run_v3_heldout_whole_session as whole
        for field, value in (('passed', False), ('exit_code', 1), ('stop_reason', 'runtime_seconds'),
            ('cleanup_remaining_owned_processes', 1), ('cleanup_status_unknown', True),
            ('sample_count', 3), ('duration_seconds', float('nan')),
            ('sampled_peak_owned_tree_rss_bytes', 999), ('censored', False)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                prereq, manifest, report, _ = self.fixture(Path(temporary).resolve())
                report[field] = value
                path = Path(prereq['setup_monitor']['path'])
                # JSON fixture may encode NaN; admission must reject it.
                path.write_text(json.dumps(report)); path.chmod(0o600)
                prereq['setup_monitor'] = whole._pin(path)
                with self.assertRaises(ValueError): whole.setup_accounting(prereq, manifest)

    def test_historical_invocation_product_pins_and_live_bytes_cannot_drift(self):
        from tools.part5 import run_v3_heldout_whole_session as whole
        for mutation in ('owner', 'argv', 'binary', 'r1cs', 'profile', 'suite', 'output', 'storage'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                prereq, manifest, _, invocation = self.fixture(Path(temporary).resolve())
                if mutation == 'owner': invocation['owner'] = 'different-owner'
                if mutation == 'argv': invocation['argv'][1] = 'prove'
                if mutation in ('binary', 'r1cs', 'profile', 'suite'):
                    position = {'binary': 0, 'r1cs': 2, 'profile': 4, 'suite': 5}[mutation]
                    Path(invocation['argv'][position]).write_bytes(b'changed bytes')
                if mutation == 'output': invocation['argv'][-1] += '-different'
                if mutation == 'storage': invocation['storage_roots'] = [invocation['storage_roots'][0]]
                path = Path(prereq['setup_invocation']['path'])
                path.write_text(json.dumps(invocation)); path.chmod(0o600)
                prereq['setup_invocation'] = whole._pin(path)
                with self.assertRaises(ValueError): whole.setup_accounting(prereq, manifest)

    def test_missing_fields_and_out_of_cap_or_nonmonotonic_samples_rejected(self):
        from tools.part5 import run_v3_heldout_whole_session as whole
        for mutation in ('missing-stop', 'rss-cap', 'runtime-cap', 'negative-sample',
                         'backwards-sample', 'last-owner-active', 'infinite-poll'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                prereq, manifest, report, _ = self.fixture(Path(temporary).resolve())
                if mutation == 'missing-stop': report.pop('stop_reason')
                if mutation == 'rss-cap': report['limits']['owned_tree_rss_bytes'] = 1
                if mutation == 'runtime-cap': report['limits']['runtime_seconds'] = 1
                if mutation == 'negative-sample': report['samples'][0]['elapsed_seconds'] = -.1
                if mutation == 'backwards-sample': report['samples'][1]['elapsed_seconds'] = .05
                if mutation == 'last-owner-active': report['samples'][-1]['owned_process_count'] = 1
                if mutation == 'infinite-poll': report['limits']['poll_seconds'] = float('inf')
                path = Path(prereq['setup_monitor']['path'])
                path.write_text(json.dumps(report)); path.chmod(0o600)
                prereq['setup_monitor'] = whole._pin(path)
                with self.assertRaises(ValueError): whole.setup_accounting(prereq, manifest)


if __name__ == '__main__':
    unittest.main()
