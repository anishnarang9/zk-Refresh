"""Synthetic retained-evidence checks; no RPC, proof, validator or build jobs."""
import copy
import hashlib
import contextlib
import io
import json
import shutil
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from harness.tests.test_queue_v3_local_expired_status_negative import (
    candidate_fixture, config, make_preflight_artifacts,
)
from tools.part5 import finalize_v3_expired_status_negative as finalizer


def save(path, value):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw = value if type(value) is bytes else (json.dumps(value, sort_keys=True) + '\n').encode()
    path.write_bytes(raw)
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}


def monitored(owner, command, config_pin, roots, exit_code=0):
    sample = {'elapsed_seconds': 40, 'owned_process_count': 1,
              'sampled_tree_self_cpu_seconds_lower_bound': 1,
              'owned_tree_rss_bytes': 1024, 'storage_growth_bytes': 2048}
    report = {'schema': 1, 'measurement': 'bounded_complete_session',
              'owner': owner, 'passed': exit_code == 0, 'censored': False,
              'exit_code': exit_code, 'stop_reason': None, 'runner_error_type': None,
              'cleanup_remaining_owned_processes': 0, 'cleanup_status_unknown': False,
              'limits': {'runtime_seconds': 180, 'owned_tree_rss_bytes': 4294967296,
                         'storage_growth_bytes': 268435456, 'poll_seconds': 0.2},
              'duration_seconds': 40, 'sample_count': 1, 'samples': [sample],
              'sampled_peak_owned_tree_rss_bytes': 1024,
              'sampled_peak_storage_growth_bytes': 2048}
    invocation = {'owner': owner, 'cwd': str(finalizer.REPO), 'storage_roots': list(map(str, roots)),
                  'argv': ['/usr/bin/python3', str(command), '--config', config_pin['path'],
                           '--config-sha256', config_pin['sha256']]}
    return report, invocation


class FinalizerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        repo = self.root / 'repo'
        for relative in finalizer.SOURCE_PATHS:
            target = repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(finalizer.REPO / relative, target)
        repo_patch = patch.object(finalizer, 'REPO', repo)
        repo_patch.start()
        self.addCleanup(repo_patch.stop)
        self.config = config()
        make_preflight_artifacts(self.root, self.config)
        candidate, loaded, output = candidate_fixture(self.root, self.config)
        self.config['output_dir'] = str(output)
        self.config['control_output'] = str(self.root / 'control')
        stage_path = Path(self.config['stage_report'])
        stage = json.loads(stage_path.read_bytes())
        config_key, request_key = bytes([1]) * 32, bytes([2]) * 32
        config_bytes = b'DYNCONF3' + bytes(373)
        request_bytes = bytearray(2249)
        request_bytes[:8] = b'DYNREQ03'
        request_bytes[8:40] = config_key
        request_bytes[183] = 1
        queue_bytes = bytearray(2090)
        queue_bytes[:8] = b'DYNQUE03'
        queue_bytes[8:40] = config_key
        initial = [config_bytes, b'issuer-bytes', b'head-bytes', bytes(request_bytes), bytes(queue_bytes)]
        stage['account_sha256'] = []
        stage['finalized_slot'] = 8
        for index, name in enumerate(finalizer.supervisor.ACCOUNT_NAMES):
            stage[name] = finalizer.supervisor.execute.base.b58(
                config_key if name == 'config' else request_key if name == 'request' else bytes([index + 3]) * 32)
            stage['account_sha256'].append(save(Path(self.config['stage_root']) / (name + '.bin'), initial[index])['sha256'])
            for phase in ('before', 'after'):
                candidate['snapshots'][index][phase] = save(output / phase / (name + '.bin'), initial[index])
        self.config['stage_report_sha256'] = save(stage_path, stage)['sha256']
        # Refresh immutable references after the synthetic stage is populated.
        for path_field, hash_field in (('source_receipt', 'source_receipt_sha256'),
                                       ('clone_receipt', 'clone_receipt_sha256'),
                                       ('stage_status', 'stage_status_sha256')):
            path = Path(self.config[path_field])
            doc = json.loads(path.read_bytes())
            doc['stage_report_sha256'] = self.config['stage_report_sha256']
            self.config[hash_field] = save(path, doc)['sha256']
        proof_path = Path(self.config['full_proof_receipt'])
        proof = json.loads(proof_path.read_bytes())
        proof['stage_report_sha256'] = self.config['stage_report_sha256']
        proof['source_receipts']['R0']['sha256'] = self.config['source_receipt_sha256']
        self.config['full_proof_receipt_sha256'] = save(proof_path, proof)['sha256']
        self.config_pin = save(self.root / 'config.json', self.config)
        candidate['config_ref'] = self.config_pin
        candidate['identities'] = finalizer.supervisor._expected_identities(self.config)
        candidate['input_refs'] = {
            path: finalizer.config_ref(self.config, path, digest)
            for path, digest, _ in finalizer.supervisor.INPUT_ARTIFACTS}
        candidate['input_refs']['runner'] = finalizer.config_ref(self.config, 'runner', 'runner_sha256')
        candidate['source_refs'] = {'full_proof': candidate['input_refs']['full_proof_receipt'],
                                    'full_wire': candidate['input_refs']['full_wire']}
        self.candidate = candidate
        candidate_pin = save(output / finalizer.supervisor.REPORT_NAME, candidate)
        status = {'schema': 1, 'scope': finalizer.supervisor.SCOPE,
                  'status': 'candidate_verified_pending_external_finalization',
                  'candidate_verified': True, 'error_type': None,
                  'candidate_path': candidate_pin['path'], 'candidate_sha256': candidate_pin['sha256'],
                  'candidate_schema': finalizer.supervisor.CANDIDATE_SCHEMA,
                  'config_path': self.config_pin['path'], 'config_sha256': self.config_pin['sha256'],
                  'owner': self.config['owner'], 'output_dir': str(output),
                  'application_effect': False, 'external_finalization_required': True,
                  'runner_cleanup': {'spawned': True, 'reaped': True, 'exit_code': 0},
                  'validator_cleanup': {'spawned': True, 'reaped': True, 'graceful': False, 'exit_code': -2},
                  'validator_alive_before_cleanup': True, 'loaded_program': loaded,
                  'live_rechecked_finalized_slot': 23, 'elapsed_seconds': 35}
        status_pin = save(self.root / 'control/status.json', status)
        monitor, invocation = monitored(self.config['owner'],
            finalizer.REPO / 'harness/tests/queue_v3_local_expired_status_negative.py', self.config_pin,
            [self.root / 'monitor-private',
             *[Path(self.config[p]) for p in ('ledger', 'output_dir', 'control_output')]])
        self.monitor, self.invocation = monitor, invocation
        self.manifest = {'schema': finalizer.MANIFEST_SCHEMA,
            'refs': {'config': self.config_pin, 'candidate': candidate_pin,
                     'supervisor_status': status_pin,
                     'monitor': save(self.root / 'monitor.json', monitor),
                     'monitor_invocation': save(self.root / 'monitor-private/invocation.json', invocation)},
            'source_pins': {p: hashlib.sha256((finalizer.REPO / p).read_bytes()).hexdigest()
                            for p in finalizer.SOURCE_PATHS}, 'positive_full': None}
        save(self.root / 'monitor-private/report.json', monitor)
        self.positive = self.positive_fixture(stage, loaded, initial)

    def positive_fixture(self, stage, loaded, initial):
        output = finalizer.REPO / 'artifacts/dynark/part5/application-v3-positive-output'
        control = output.parent / 'application-v3-positive-control'
        positive = {p: self.config[p] for p in ('stage_root', 'stage_report_sha256',
            'stage_plan_sha256', 'full_wire_sha256', 'full_wire', 'expected_genesis')}
        positive.update({'schema': 1, 'scope': 'part5-v3-local-execute',
            'outer_limits_required': copy.deepcopy(finalizer.supervisor.execute.LIMITS),
            'execute_output': str(output), 'control_output': str(control),
            'prior_stage_config': self.config['stage_config'],
            'prior_stage_config_sha256': self.config['stage_config_sha256'],
            'prior_stage_status': self.config['stage_status'],
            'prior_stage_status_sha256': self.config['stage_status_sha256'],
            'prior_stage_monitor': str(self.root / 'stage-monitor.json'),
            'prior_stage_monitor_sha256': save(self.root / 'stage-monitor.json',
                {'owner': 'synthetic-stage-owner', 'stop_reason': None, 'runner_error_type': None,
                 'cleanup_remaining_owned_processes': 0, 'cleanup_status_unknown': False})['sha256'],
            'prior_monitor_owner': 'synthetic-stage-owner',
            'runner': self.config['runner'], 'runner_sha256': self.config['runner_sha256'],
            'context': str(self.root / 'context.json'),
            'context_sha256': save(self.root / 'context.json', {'synthetic': True})['sha256'],
            'replay_full_wire': str(self.root / 'replay-full-wire.bin')})
        positive['ledger'] = str(self.root / 'positive-ledger')
        wire = Path(positive['full_wire']).read_bytes()
        replay = wire[:192] + bytes([wire[192] ^ 1]) + wire[193:]
        positive['replay_full_wire_sha256'] = save(positive['replay_full_wire'], replay)['sha256']
        config_pin = save(self.root / 'positive-config.json', positive)
        post = list(initial)
        request = bytearray(post[3]); request[183] = 2; post[3] = bytes(request)
        queue = bytearray(post[4]); queue[40:42] = (1).to_bytes(2, 'big')
        queue[42:74] = bytes([2]) * 32; post[4] = bytes(queue)
        hashes = [save(output / (name + '.bin'), raw)['sha256']
                  for name, raw in zip(finalizer.supervisor.ACCOUNT_NAMES, post)]
        report = {'schema': 'part5-v3-local-execute-v1', 'passed': True,
                  'application_effect': True, 'effect_count': 1, 'request_consumed': True,
                  'proof_mode': 'Full', 'stage_report_sha256': self.config['stage_report_sha256'],
                  'stage_plan_sha256': self.config['stage_plan_sha256'],
                  'wire_sha256': self.config['full_wire_sha256'],
                  'replay_wire_sha256': positive['replay_full_wire_sha256'],
                  'program': self.config['expected_program'], 'genesis': self.config['expected_genesis'],
                  'finalized_slot': 100, 'account_sha256': hashes, 'loaded_program': loaded}
        report_pin = save(output / 'execute-report.json', report)
        status = {'schema': 1, 'scope': 'part5-v3-local-execute', 'status': 'failed',
                  'effect_verified': True, 'application_effect': True, 'effect_count': 1,
                  'effect_outcome': 'verified', 'error_type': None,
                  'config_sha256': config_pin['sha256'], 'execute_report_sha256': report_pin['sha256'],
                  'execute_output': str(output), 'loaded_program': loaded, 'finalized_slot': 101,
                  'runner_cleanup': {'reaped': True, 'exit_code': 0},
                  'validator_cleanup': {'reaped': True, 'graceful': False, 'exit_code': -2}}
        status_pin = save(control / 'status.json', status)
        owner = 'separate-positive-full-owner'
        monitor, invocation = monitored(owner,
            finalizer.REPO / 'harness/tests/queue_v3_local_execute.py', config_pin,
            [str(self.root / 'positive-monitor-private'), positive['ledger'], str(output), str(control)], exit_code=1)
        save(self.root / 'positive-monitor-private/report.json', monitor)
        return {'config': config_pin, 'report': report_pin, 'status': status_pin,
                'monitor': save(self.root / 'positive-monitor.json', monitor),
                'monitor_invocation': save(self.root / 'positive-monitor-private/invocation.json', invocation),
                'monitor_owner': owner}

    def with_positive(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['positive_full'] = copy.deepcopy(self.positive)
        return manifest

    def test_missing_positive_proof_evidence_blocks_without_final_report(self):
        result = finalizer.finalize_or_block(self.manifest)
        self.assertEqual(result['schema'], finalizer.BLOCKED_SCHEMA)
        self.assertIn('same-wire positive loaded Full', result['blocker'])
        self.assertNotIn('evidence', result)
        self.assertFalse(result['proof_validity_established'])

    def test_synthetic_complete_retained_bundle_and_reviewed_sigint_positive(self):
        result = finalizer.finalize(self.with_positive())
        self.assertEqual(result['schema'], finalizer.FINAL_SCHEMA)
        self.assertEqual(result['bindings']['refs']['candidate'], self.manifest['refs']['candidate'])
        self.assertEqual(result['bindings']['refs']['supervisor_status'], self.manifest['refs']['supervisor_status'])
        self.assertTrue(result['evidence']['preconditions']['full_wire_valid'])
        self.assertEqual(result['evidence']['measured']['owner_wall_seconds'], 40)
        self.assertEqual(result['facts']['custom_error'], 705)
        self.assertFalse(result['heldout_acceptance_established'])

    def test_no_job_or_rpc_is_started(self):
        with patch('subprocess.Popen', side_effect=AssertionError('process execution forbidden')):
            self.assertEqual(finalizer.finalize(self.with_positive())['schema'], finalizer.FINAL_SCHEMA)

    def test_external_monitor_rejects_bad_cleanup_bounds_samples_invocation_and_coverage(self):
        mutations = (
            lambda m, i: m.update(cleanup_status_unknown=True),
            lambda m, i: m.update(cleanup_remaining_owned_processes=1),
            lambda m, i: m.update(cleanup_remaining_owned_processes=False),
            lambda m, i: m.update(censored=True),
            lambda m, i: m.update(duration_seconds=181),
            lambda m, i: m.update(duration_seconds=float('nan')),
            lambda m, i: m.update(sampled_peak_owned_tree_rss_bytes=0),
            lambda m, i: m.update(sample_count=True),
            lambda m, i: m['samples'][0].update(owned_process_count=0),
            lambda m, i: m['samples'][0].update(storage_growth_bytes=268435457),
            lambda m, i: m['samples'][0].update(elapsed_seconds=41),
            lambda m, i: i['argv'].__setitem__(-1, 'f' * 64),
            lambda m, i: i.update(storage_roots=[self.config['ledger']]),
        )
        for mutate in mutations:
            monitor, invocation = copy.deepcopy(self.monitor), copy.deepcopy(self.invocation)
            mutate(monitor, invocation)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                finalizer.check_monitor(monitor, invocation, self.config['owner'],
                    finalizer.REPO / 'harness/tests/queue_v3_local_expired_status_negative.py',
                    self.config_pin, [self.config[p] for p in ('ledger', 'output_dir', 'control_output')],
                    finalizer.REPO, private_output=self.root / 'monitor-private')

    def test_hash_drift_and_source_drift_fail_closed(self):
        for role in finalizer.REF_ROLES:
            manifest = self.with_positive()
            manifest['refs'][role]['sha256'] = 'a' * 64
            result = finalizer.finalize_or_block(manifest)
            self.assertEqual(result['schema'], finalizer.BLOCKED_SCHEMA)
        manifest = self.with_positive()
        manifest['source_pins'][finalizer.SOURCE_PATHS[0]] = 'a' * 64
        self.assertFalse(finalizer.finalize_or_block(manifest)['evidence_emitted'])

    def test_positive_wrong_request_or_wire_or_loaded_identity_cannot_establish_validity(self):
        for role, mutate in (
            ('config', lambda d: d.update(full_wire_sha256='a' * 64)),
            ('config', lambda d: d.update(stage_report_sha256='a' * 64)),
            ('report', lambda d: d.update(proof_mode='Anchor')),
            ('status', lambda d: d['loaded_program'].update(genesis='other')),
            ('status', lambda d: d.update(effect_verified=False)),
            ('monitor', lambda d: d.update(cleanup_status_unknown=True)),
        ):
            manifest = self.with_positive()
            original = manifest['positive_full'][role]
            doc = json.loads(Path(original['path']).read_bytes())
            mutate(doc)
            manifest['positive_full'][role] = save(self.root / ('mutated-' + role + '.json'), doc)
            self.assertEqual(finalizer.finalize_or_block(manifest)['schema'], finalizer.BLOCKED_SCHEMA)

    def refreshed_positive_config(self, manifest, mutate):
        refs = manifest['positive_full']
        positive = json.loads(Path(refs['config']['path']).read_bytes())
        mutate(positive)
        refs['config'] = save(refs['config']['path'], positive)
        status = json.loads(Path(refs['status']['path']).read_bytes())
        status['config_sha256'] = refs['config']['sha256']
        refs['status'] = save(refs['status']['path'], status)
        invocation = json.loads(Path(refs['monitor_invocation']['path']).read_bytes())
        invocation['argv'][-1] = refs['config']['sha256']
        refs['monitor_invocation'] = save(refs['monitor_invocation']['path'], invocation)

    def test_positive_actual_execute_contract_with_refreshed_hashes(self):
        mutations = (
            ('schema', lambda d: d.update(schema=2)),
            ('scope', lambda d: d.update(scope='unrelated')),
            ('limits', lambda d: d['outer_limits_required'].update(runtime_seconds=181)),
            ('missing-limits', lambda d: d.pop('outer_limits_required')),
            ('execute-output', lambda d: d.update(execute_output=str(
                Path(d['execute_output']).parent / 'application-v3-other-output'))),
            ('control-output', lambda d: d.update(control_output=str(
                Path(d['control_output']).parent / 'application-v3-other-control'))),
            ('ledger', lambda d: d.update(ledger=str(self.root / 'uncovered-positive-ledger'))),
        )
        for name, mutate in mutations:
            with self.subTest(mutation=name):
                # Restore all positive bytes because every mutation refreshes the lineage.
                snapshot = {role: Path(ref['path']).read_bytes()
                            for role, ref in self.positive.items() if type(ref) is dict}
                manifest = self.with_positive()
                self.refreshed_positive_config(manifest, mutate)
                result = finalizer.finalize_or_block(manifest)
                self.assertEqual(result['schema'], finalizer.BLOCKED_SCHEMA)
                self.assertFalse(result['evidence_emitted'])
                for role, raw in snapshot.items():
                    Path(self.positive[role]['path']).write_bytes(raw)

    def test_positive_report_and_status_paths_must_match_configured_outputs(self):
        for role in ('report', 'status'):
            manifest = self.with_positive()
            source = manifest['positive_full'][role]
            manifest['positive_full'][role] = save(self.root / ('relocated-' + role + '.json'),
                                                  Path(source['path']).read_bytes())
            result = finalizer.finalize_or_block(manifest)
            self.assertEqual(result['schema'], finalizer.BLOCKED_SCHEMA)
            self.assertFalse(result['evidence_emitted'])

    def test_each_monitor_must_measure_its_private_output_with_refreshed_hashes(self):
        for positive in (False, True):
            manifest = self.with_positive()
            refs = manifest['positive_full'] if positive else manifest['refs']
            pin = refs['monitor_invocation']
            original_invocation = Path(pin['path']).read_bytes()
            invocation = json.loads(original_invocation)
            private_output = str(Path(pin['path']).parent)
            self.assertIn(private_output, invocation['storage_roots'])
            invocation['storage_roots'].remove(private_output)
            refs['monitor_invocation'] = save(pin['path'], invocation)
            result = finalizer.finalize_or_block(manifest)
            self.assertEqual(result['schema'], finalizer.BLOCKED_SCHEMA)
            self.assertFalse(result['evidence_emitted'])
            self.assertIn('private_output', result['blocker'])
            Path(pin['path']).write_bytes(original_invocation)

    def test_same_stage_different_proof_wire_is_rejected(self):
        manifest = self.with_positive()
        positive = json.loads(Path(self.positive['config']['path']).read_bytes())
        old_wire = Path(positive['full_wire']).read_bytes()
        different_proof = old_wire[:192] + bytes([old_wire[192] ^ 1]) + old_wire[193:]
        wire_ref = save(self.root / 'different-proof-wire.bin', different_proof)
        positive['full_wire'], positive['full_wire_sha256'] = wire_ref['path'], wire_ref['sha256']
        self.assertEqual(positive['stage_report_sha256'], self.config['stage_report_sha256'])
        self.assertEqual(old_wire[:192], different_proof[:192])
        manifest['positive_full']['config'] = save(self.root / 'different-proof-config.json', positive)
        result = finalizer.finalize_or_block(manifest)
        self.assertEqual(result['schema'], finalizer.BLOCKED_SCHEMA)
        self.assertIn('different stage, root, request, or wire', result['blocker'])
        self.assertNotIn('evidence', result)

    def test_external_report_and_retained_invocation_need_same_private_report(self):
        (self.root / 'monitor-private/report.json').write_bytes(b'{}')
        result = finalizer.finalize_or_block(self.with_positive())
        self.assertEqual(result['schema'], finalizer.BLOCKED_SCHEMA)
        self.assertFalse(result['proof_validity_established'])

    def test_cli_writes_only_blocker_when_positive_evidence_is_absent(self):
        manifest_ref = save(self.root / 'manifest.json', self.manifest)
        output = self.root / 'finalization.json'
        argv = ['finalizer', '--manifest', manifest_ref['path'],
                '--manifest-sha256', manifest_ref['sha256'], '--output', str(output)]
        with patch('sys.argv', argv), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(finalizer.main(), 2)
        result = json.loads(output.read_bytes())
        self.assertEqual(result['schema'], finalizer.BLOCKED_SCHEMA)
        self.assertNotIn('evidence', result)
        self.assertFalse(result['evidence_emitted'])

    def test_recheck_rejects_input_changed_after_initial_read(self):
        reads = finalizer.Inputs()
        ref = save(self.root / 'changing', b'first')
        reads.raw(ref)
        Path(ref['path']).write_bytes(b'other')
        with self.assertRaises(ValueError):
            reads.recheck()

    def test_duplicate_nonfinite_and_symlink_inputs_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":1e999}', b'{"a":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                finalizer.Inputs().doc(save(self.root / 'bad-json', raw))
        ref = save(self.root / 'target', b'{}')
        link = self.root / 'symlink'; link.symlink_to(ref['path'])
        ref['path'] = str(link)
        with self.assertRaises(ValueError):
            finalizer.Inputs().doc(ref)


if __name__ == '__main__':
    unittest.main()
