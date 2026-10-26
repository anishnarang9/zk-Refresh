import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.part5 import build_v3_expired_status_negative_inputs as builder


def write(path, raw):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def doc(path, value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    return write(path, raw)


def bundle_identity(rows, repo):
    hashing = hashlib.sha256(b'part5-v3-campaign-identity-bundle-v1\0')
    for row in rows:
        relative = row['path']
        raw = (Path(repo) / relative).read_bytes()
        path_bytes = relative.encode()
        hashing.update(len(path_bytes).to_bytes(4, 'big'))
        hashing.update(path_bytes)
        hashing.update(len(raw).to_bytes(8, 'big'))
        hashing.update(raw)
    return hashing.hexdigest()


class ExpiredStatusInputBuilderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.repo = self.root / 'repo'
        self.case = self.root / 'case00'
        self.case.mkdir()
        self.run_id = '0123456789abcdef0123456789abcdef'
        doc(self.case / 'run-id.json', {
            'schema': 'credential-v3-heldout-run-id-v1', 'run_id': self.run_id})

        source_paths = ('src/supervisor.py', 'src/finalizer.py')
        source_pins = {f'program/source-{index}.rs': f'{index + 1:064x}'
                       for index in range(12)}
        bundle_rows = {'registry': [], 'client': []}
        for index, relative in enumerate(source_paths):
            source_sha = write(self.repo / relative, f'source-{index}'.encode())
            row = {'path': relative, 'artifact': {
                'path': str(self.repo / relative), 'sha256': source_sha}}
            bundle_rows['registry' if index == 0 else 'client'].append(row)
        source_manifest = self.root / 'application-source.json'
        source_sha = doc(source_manifest, {'schema': 1, 'source_pins': source_pins})
        loaded_elf = self.root / 'accepted.so'
        elf_sha = write(loaded_elf, b'accepted loaded ELF')
        freeze = self.root / 'freeze.json'
        freeze_sha = doc(freeze, {
            'schema': 'credential-v3-frozen-holdout-boundary-v1',
            'identities': {
                'loaded_elf': elf_sha,
                'registry': bundle_identity(bundle_rows['registry'], self.repo),
                'client': bundle_identity(bundle_rows['client'], self.repo),
            }})

        self.manifest = {
            'schema': 'credential-v3-heldout-case-run-v1', 'variant': 0,
            'freeze_receipt': str(freeze), 'freeze_sha256': freeze_sha,
            'frozen_files': {'loaded_elf': {'path': str(loaded_elf), 'sha256': elf_sha}},
            'frozen_bundles': bundle_rows,
            'application_source_manifest': {'path': str(source_manifest),
                                            'sha256': source_sha},
        }
        self.manifest_path = self.root / 'run-manifest.json'
        doc(self.manifest_path, self.manifest)

        stage_root = self.case / 'positive_full' / 'stage'
        stage_root.mkdir(parents=True)
        self.stage_ledger = self.case / 'positive_full' / 'stage-ledger'
        self.stage_ledger.mkdir()
        self.clone_ledger = self.case / 'positive_full' / 'expired-status-r0-clone' / 'ledger'
        self.clone_ledger.mkdir(parents=True)
        genesis_sha = write(self.stage_ledger / 'genesis.bin', b'genesis bytes')
        write(self.clone_ledger / 'genesis.bin', b'genesis bytes')
        self.program = bytes(range(1, 33))
        self.genesis = bytes(range(33, 65))
        plan = {'program': list(self.program), 'genesis': list(self.genesis)}
        plan_path = stage_root / 'plan.json'
        plan_sha = doc(plan_path, plan)
        self.program_text = builder.supervisor.execute.base.b58(self.program)
        self.genesis_text = builder.supervisor.execute.base.b58(self.genesis)
        stage_report = {'schema': 'part5-v3-local-stage-v1', 'passed': True,
                        'program': self.program_text, 'genesis': self.genesis_text,
                        'loaded_program': {'elf_match': True, 'elf_sha256': elf_sha}}
        stage_report_path = stage_root / 'stage-report.json'
        stage_report_sha = doc(stage_report_path, stage_report)
        stage_config_path = self.case / 'positive_full' / 'stage-config.json'
        stage_config_sha = doc(stage_config_path, {
            'schema': 1, 'scope': 'part5-v3-local-stage',
            'ledger': str(self.stage_ledger), 'stage_output': str(stage_root),
            'control_output': str(self.case / 'stage-control'),
            'expected_genesis': self.genesis_text})
        stage_control = self.case / 'stage-control'
        stage_status_path = stage_control / 'status.json'
        stage_status_sha = doc(stage_status_path, {
            'schema': 1, 'scope': 'part5-v3-local-stage', 'status': 'failed',
            'stage_verified': True, 'config_sha256': stage_config_sha,
            'stage_report_sha256': stage_report_sha, 'stage_output': str(stage_root)})

        source_path = self.case / 'positive_full' / 'source-R0' / 'source-receipt.json'
        source_sha = doc(source_path, {
            'schema': 'credential-v3-heldout-request-source-v1', 'variant': 'R0',
            'case_index': 0, 'target_variant': 0, 'freeze_sha256': freeze_sha,
            'stage_report_sha256': stage_report_sha, 'stage_plan_sha256': plan_sha,
            'proof_created': False, 'application_effect': False,
            'live_state_authenticated': False})
        clone_root = self.clone_ledger.parent
        clone_path = clone_root / 'clone-report.json'
        clone_sha = doc(clone_path, {
            'schema': 'part5-v3-heldout-r0-ledger-clone-v1',
            'heldout_acceptance': False,
            'stage_report_sha256': stage_report_sha,
            'stage_status_sha256': stage_status_sha,
            'stage_monitor_sha256': 'b' * 64,
            'source': str(self.stage_ledger), 'destination': str(self.clone_ledger),
            'source_stable': True, 'copy_identical': True,
            'loaded_identity_rechecked_after_restart': False,
            'application_effect': False, 'excluded_stale_admin_socket': False})
        clone_monitor = self.case / 'positive_full' / 'expired-status-r0-clone-monitor.json'
        clone_monitor_sha = doc(clone_monitor, {'passed': True})

        proof_root = self.case / 'positive_full' / 'proof-full'
        proof_path = proof_root / 'work' / 'proof' / 'request_bound_training_full_base.proof'
        proof_sha = write(proof_path, b'synthetic Full proof')
        wire_path = proof_root / 'work' / 'base' / 'full-solana-wire.bin'
        wire_sha = write(wire_path, b'w' * 448)
        proof_receipt_path = proof_root / 'proof-receipt.json'
        proof_receipt_sha = doc(proof_receipt_path, {
            'schema': 'credential-v3-heldout-proof-evidence-v1', 'mode': 'full',
            'target_variant': 0, 'freeze_sha256': freeze_sha,
            'stage_report_sha256': stage_report_sha, 'stage_plan_sha256': plan_sha,
            'source_receipts': {'R0': {'path': str(source_path), 'sha256': source_sha}},
            'artifacts': {'proof/request_bound_training_full_base.proof':
                          {'path': str(proof_path), 'sha256': proof_sha}},
            'wires': {'r0_full_wire': {'path': str(wire_path), 'sha256': wire_sha}},
            'proof_created': True, 'application_verified': False,
            'validator_run': False, 'application_effect': False})

        positive_output = self.case / 'positive_full' / 'execute-output'
        positive_control = self.case / 'positive_full' / 'execute-control'
        positive_config_path = self.case / 'positive_full' / 'execute-config.json'
        runner = self.root / 'runner'
        runner_sha = write(runner, b'synthetic runner')
        positive_config_sha = doc(positive_config_path, {
            'schema': 1, 'scope': 'part5-v3-local-execute',
            'ledger': str(self.case / 'positive_full' / 'r0-clone' / 'ledger'),
            'stage_root': str(stage_root), 'execute_output': str(positive_output),
            'control_output': str(positive_control), 'stage_report_sha256': stage_report_sha,
            'stage_plan_sha256': plan_sha, 'full_wire': str(wire_path),
            'full_wire_sha256': wire_sha, 'expected_genesis': self.genesis_text,
            'runner': str(runner), 'runner_sha256': runner_sha,
            'outer_limits_required': builder.supervisor.execute.LIMITS})
        positive_report_path = positive_output / 'execute-report.json'
        positive_report_sha = doc(positive_report_path, {
            'schema': 'part5-v3-local-execute-v1', 'passed': True,
            'application_effect': True, 'effect_count': 1, 'request_consumed': True,
            'proof_mode': 'Full', 'stage_report_sha256': stage_report_sha,
            'stage_plan_sha256': plan_sha, 'wire_sha256': wire_sha,
            'program': self.program_text, 'genesis': self.genesis_text,
            'loaded_program': {'elf_match': True, 'elf_sha256': elf_sha,
                               'genesis': self.genesis_text},
            'finalized_slot': 20})
        positive_status_path = positive_control / 'status.json'
        positive_status_sha = doc(positive_status_path, {
            'schema': 1, 'scope': 'part5-v3-local-execute', 'status': 'failed',
            'effect_verified': True, 'application_effect': True,
            'effect_outcome': 'verified', 'effect_count': 1, 'error_type': None,
            'config_sha256': positive_config_sha,
            'execute_report_sha256': positive_report_sha,
            'execute_output': str(positive_output),
            'loaded_program': {'elf_match': True, 'elf_sha256': elf_sha,
                               'genesis': self.genesis_text},
            'finalized_slot': 21})
        positive_monitor = self.case / 'positive_full' / 'execute-monitor.json'
        positive_monitor_sha = doc(positive_monitor, {'passed': True})
        positive_invocation = positive_monitor.with_suffix('') / 'invocation.json'
        positive_invocation_sha = doc(positive_invocation, {'owner': 'positive-owner'})

        self.steps = {
            'positive_full:stage': {
                'status': 'passed', 'config': str(stage_config_path),
                'config_sha256': stage_config_sha, 'status_path': str(stage_status_path),
                'status_sha256': stage_status_sha, 'report': str(stage_report_path),
                'report_sha256': stage_report_sha, 'plan': str(plan_path),
                'plan_sha256': plan_sha, 'root': str(stage_root),
            },
            'positive_full:source-R0': {
                'status': 'passed', 'receipt': str(source_path),
                'receipt_sha256': source_sha,
            },
            'positive_full:proof-full': {
                'status': 'passed', 'mode': 'full', 'receipt': str(proof_receipt_path),
                'receipt_sha256': proof_receipt_sha,
                'wires': {'r0_full_wire': {'path': str(wire_path), 'sha256': wire_sha}},
            },
            'positive_full:execute': {
                'status': 'passed', 'config': str(positive_config_path),
                'config_sha256': positive_config_sha, 'report': str(positive_report_path),
                'report_sha256': positive_report_sha, 'status_path': str(positive_status_path),
                'status_sha256': positive_status_sha, 'monitor': str(positive_monitor),
                'monitor_sha256': positive_monitor_sha,
                'monitor_owner': 'positive-owner',
            },
            'positive_full:expired-status-clone': {
                'status': 'passed', 'label': 'expired-status-r0',
                'ledger': str(self.clone_ledger), 'receipt': str(clone_path),
                'receipt_sha256': clone_sha, 'monitor': str(clone_monitor),
                'monitor_sha256': clone_monitor_sha,
                'monitor_owner': 'heldout-v00-positive_full-clone-expired-status-r0',
            },
        }
        self.journal = self.case / 'run-journal.json'
        self.manifest_sha = hashlib.sha256(
            builder.canonical_json(self.manifest)).hexdigest()
        doc(self.journal, {'schema': 'credential-v3-heldout-case-run-journal-v1',
                           'manifest_sha256': self.manifest_sha, 'steps': self.steps})
        self.source_paths = source_paths
        self.source_pins = source_pins

    def run_builder(self):
        with mock.patch.object(builder, 'REPO', self.repo), \
                mock.patch.object(builder, 'SOURCE_PATHS', self.source_paths):
            return builder.build(self.case, self.manifest_path, repo_root=self.repo)

    def test_builds_deterministic_config_and_same_full_finalizer_seed(self):
        first = self.run_builder()
        second = self.run_builder()
        self.assertEqual(first, second)
        config = first['config']
        self.assertEqual(config['variant'], 0)
        self.assertEqual(config['ledger'], str(self.clone_ledger))
        positive_config = json.loads(
            Path(self.steps['positive_full:execute']['config']).read_text())
        self.assertEqual(config['full_wire'], positive_config['full_wire'])
        self.assertEqual(config['full_proof'], str(
            self.case / 'positive_full/proof-full/work/proof/request_bound_training_full_base.proof'))
        self.assertEqual(config['full_wire_sha256'],
                         self.steps['positive_full:proof-full']['wires']['r0_full_wire']['sha256'])
        self.assertEqual(first['finalizer_seed']['positive_full']['monitor_owner'], 'positive-owner')
        self.assertEqual(first['finalizer_seed']['source_pins'], {
            relative: write(self.repo / relative, f'source-{index}'.encode())
            for index, relative in enumerate(self.source_paths)})
        self.assertEqual(first['finalizer_seed']['source_pins'], {
            row['path']: row['artifact']['sha256']
            for rows in self.manifest['frozen_bundles'].values() for row in rows})
        self.assertEqual(first['finalizer_seed']['schema'], builder.SEED_SCHEMA)
        self.assertNotIn('refs', first['finalizer_seed'])
        self.assertEqual(first['finalizer_seed']['pending_negative_refs'],
                         ['candidate', 'supervisor_status', 'monitor', 'monitor_invocation'])
        self.assertEqual(first['finalizer_seed']['config']['sha256'],
                         hashlib.sha256(builder.canonical_json(config)).hexdigest())

    def test_finalizer_pins_come_from_frozen_bundle_rows(self):
        self.assertTrue(set(self.source_paths).isdisjoint(self.source_pins))
        result = self.run_builder()
        self.assertEqual(result['finalizer_seed']['source_pins'], {
            row['path']: row['artifact']['sha256']
            for rows in self.manifest['frozen_bundles'].values() for row in rows})

    def test_execute_report_uses_top_level_genesis_identity(self):
        report_path = Path(self.steps['positive_full:execute']['report'])
        report = json.loads(report_path.read_text())
        report['loaded_program'] = {
            'elf_match': True, 'elf_sha256': report['loaded_program']['elf_sha256']}
        report_sha = doc(report_path, report)
        self.steps['positive_full:execute']['report_sha256'] = report_sha
        status_path = Path(self.steps['positive_full:execute']['status_path'])
        status = json.loads(status_path.read_text())
        status['execute_report_sha256'] = report_sha
        self.steps['positive_full:execute']['status_sha256'] = doc(status_path, status)
        doc(self.journal, {'schema': 'credential-v3-heldout-case-run-journal-v1',
                           'manifest_sha256': self.manifest_sha, 'steps': self.steps})
        result = self.run_builder()
        self.assertEqual(result['config']['expected_genesis'], self.genesis_text)

    def test_missing_expired_status_clone_fails_closed(self):
        self.steps.pop('positive_full:expired-status-clone')
        doc(self.journal, {'schema': 'credential-v3-heldout-case-run-journal-v1',
                           'manifest_sha256': self.manifest_sha, 'steps': self.steps})
        with self.assertRaisesRegex(ValueError, 'expired-status-clone'):
            self.run_builder()

    def test_changed_positive_full_wire_fails_closed(self):
        positive_path = Path(self.steps['positive_full:execute']['config'])
        positive = json.loads(positive_path.read_text())
        alternate_wire = self.case / 'positive_full' / 'different-wire.bin'
        alternate_sha = write(alternate_wire, b'x' * 448)
        positive['full_wire'] = str(alternate_wire)
        positive['full_wire_sha256'] = alternate_sha
        positive_sha = doc(positive_path, positive)
        self.steps['positive_full:execute']['config_sha256'] = positive_sha
        status_path = Path(self.steps['positive_full:execute']['status_path'])
        status = json.loads(status_path.read_text())
        status['config_sha256'] = positive_sha
        status_sha = doc(status_path, status)
        self.steps['positive_full:execute']['status_sha256'] = status_sha
        doc(self.journal, {'schema': 'credential-v3-heldout-case-run-journal-v1',
                           'manifest_sha256': self.manifest_sha, 'steps': self.steps})
        with self.assertRaisesRegex(ValueError, 'positive Full Execute must use'):
            self.run_builder()


if __name__ == '__main__':
    unittest.main()
