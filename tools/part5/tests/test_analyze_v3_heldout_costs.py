import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.part5 import analyze_v3_heldout_costs as analyzer


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class HeldoutCostAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.manifest, self.acceptance = self.make_inputs()

    def write_json(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value, sort_keys=True) + '\n')
        path.chmod(0o600)
        raw = path.read_bytes()
        return {'path': str(path), 'sha256': sha(raw)}

    @staticmethod
    def step_names():
        names = ['pair-view']
        requests = {
            'positive_full': ['full'],
            'unrelated_compare': ['full', 'anchor'],
            'own_revocation': ['anchor'],
        }
        for req, modes in requests.items():
            names.extend(f'{req}:{suffix}' for suffix in
                         ('prepare', 'stage', 'transition', 'source-R0', 'source-R1'))
            names.extend(f'{req}:proof-{mode}' for mode in modes)
        names.extend(('positive_full:r0-clone', 'positive_full:execute',
                      'unrelated_compare:unrelated_full:clone',
                      'unrelated_compare:unrelated_full:effect',
                      'unrelated_compare:anchor:clone',
                      'unrelated_compare:anchor:effect',
                      'own_revocation:r1-clone', 'own_revocation:effect'))
        return names

    def test_step_map_matches_all_registered_runner_steps(self):
        expected = {
            'pair-view',
            'positive_full:prepare', 'positive_full:stage',
            'positive_full:transition', 'positive_full:source-R0',
            'positive_full:source-R1', 'positive_full:proof-full',
            'positive_full:r0-clone', 'positive_full:execute',
            'unrelated_compare:prepare', 'unrelated_compare:stage',
            'unrelated_compare:transition', 'unrelated_compare:source-R0',
            'unrelated_compare:source-R1', 'unrelated_compare:proof-full',
            'unrelated_compare:proof-anchor',
            'unrelated_compare:unrelated_full:clone',
            'unrelated_compare:unrelated_full:effect',
            'unrelated_compare:anchor:clone',
            'unrelated_compare:anchor:effect',
            'own_revocation:prepare', 'own_revocation:stage',
            'own_revocation:transition', 'own_revocation:source-R0',
            'own_revocation:source-R1', 'own_revocation:proof-anchor',
            'own_revocation:r1-clone', 'own_revocation:effect',
        }
        self.assertEqual(analyzer._step_names(), expected)
        self.assertEqual(len(expected), 28)

    def make_inputs(self):
        manifest_cases, acceptance_cases = [], []
        for variant in range(8):
            target_credential = f'{variant + 501:064x}'
            target_tbs = f'{variant + 601:064x}'
            roots = {'R0': f'{variant + 701:064x}',
                     'R1': f'{variant + 801:064x}',
                     'R2': f'{variant + 901:064x}'}
            target = {'variant': variant, 'credential_sha256': target_credential,
                      'tbs_sha256': target_tbs, 'issuer_index': variant // 2,
                      'holder_index': variant}
            context_ref = self.write_json(f'context-{variant}.json', {
                'schema': 'credential-v3-heldout-case-context-v1',
                'target': target, 'membership': roots,
            })
            run_manifest_ref = self.write_json(f'run-manifest-{variant}.json', {
                'schema': analyzer.RUN_MANIFEST_SCHEMA, 'variant': variant,
            })
            run_manifest = json.loads(Path(run_manifest_ref['path']).read_text())
            canonical_manifest = (json.dumps(run_manifest, sort_keys=True,
                separators=(',', ':'), allow_nan=False) + '\n').encode()
            steps = {name: {'status': 'passed', 'wall_seconds': 1.0}
                     for name in self.step_names()}
            steps.update({
                'pair-view': {'status': 'passed', 'wall_seconds': 0.5},
                'unrelated_compare:prepare': {'status': 'passed', 'wall_seconds': 1.0},
                'unrelated_compare:stage': {'status': 'passed', 'wall_seconds': 2.0},
                'unrelated_compare:transition': {'status': 'passed', 'wall_seconds': 3.0},
                'unrelated_compare:source-R0': {'status': 'passed', 'wall_seconds': 4.0},
                'unrelated_compare:source-R1': {'status': 'passed', 'wall_seconds': 5.0},
                'unrelated_compare:proof-full': {'status': 'passed', 'wall_seconds': 6.0},
                'unrelated_compare:proof-anchor': {'status': 'passed', 'wall_seconds': 7.0},
                'unrelated_compare:unrelated_full:clone': {'status': 'passed', 'wall_seconds': 8.0},
                'unrelated_compare:unrelated_full:effect': {'status': 'passed', 'wall_seconds': 9.0},
                'unrelated_compare:anchor:clone': {'status': 'passed', 'wall_seconds': 10.0},
                'unrelated_compare:anchor:effect': {'status': 'passed', 'wall_seconds': 11.0},
            })
            journal = {
                'schema': analyzer.JOURNAL_SCHEMA,
                'manifest_sha256': sha(canonical_manifest),
                'steps': steps,
                'costs': {'shared_stage_seconds': 4.0,
                          'shared_transition_seconds': 5.0},
            }
            all_steps = {name: row['wall_seconds'] for name, row in steps.items()}
            branch_components = {
                'full': {'proof_seconds': 1.0, 'clone_seconds': 1.0,
                         'effect_seconds': 1.0, 'total_seconds': 3.0},
                'unrelated_full': {'proof_seconds': 6.0, 'clone_seconds': 8.0,
                                   'effect_seconds': 9.0, 'total_seconds': 23.0},
                'anchor': {'proof_seconds': 7.0, 'clone_seconds': 10.0,
                           'effect_seconds': 11.0, 'total_seconds': 28.0},
                'own_revocation': {'proof_seconds': 1.0, 'clone_seconds': 1.0,
                                   'effect_seconds': 1.0, 'total_seconds': 3.0},
            }
            monitors = {}
            for key, duration in (('stage', 1.5), ('transition', 2.5),
                                  ('unrelated_full', 4.0), ('anchor', 5.0),
                                  ('full', 0.5), ('own_revocation', 0.5)):
                rss = 5000 + variant if key == 'unrelated_full' else (
                    6000 + variant if key == 'anchor' else 1000 + variant)
                storage = 7000 + variant if key == 'unrelated_full' else (
                    8000 + variant if key == 'anchor' else 2000 + variant)
                outer = {
                    'schema': 1, 'passed': False, 'exit_code': 1,
                    'stop_reason': None, 'runner_error_type': None,
                    'cleanup_remaining_owned_processes': 0,
                    'cleanup_status_unknown': False,
                    'duration_seconds': duration, 'sample_count': 3,
                    'sampled_peak_owned_tree_rss_bytes': rss,
                    'sampled_peak_storage_growth_bytes': storage,
                }
                monitors[key] = self.write_json(
                    f'outer-{variant}-{key}.json', outer)
            generic_outer = self.write_json(f'outer-{variant}-generic.json', {
                'schema': 1, 'passed': True, 'exit_code': 0,
                'stop_reason': None, 'runner_error_type': None,
                'cleanup_remaining_owned_processes': 0,
                'cleanup_status_unknown': False, 'duration_seconds': 0.25,
                'sample_count': 2,
                'sampled_peak_owned_tree_rss_bytes': 900 + variant,
                'sampled_peak_storage_growth_bytes': 1900 + variant,
            })
            full_clone = self.write_json(f'full-clone-{variant}.json', {
                'schema': 'part5-v3-r1-ledger-clone-v1', 'training_only': True,
                'source_stable': True, 'copy_identical': True,
                'application_effect': False,
                'destination': f'/clone/full/{variant}'})
            anchor_clone = self.write_json(f'anchor-clone-{variant}.json', {
                'schema': 'part5-v3-r1-ledger-clone-v1', 'training_only': True,
                'source_stable': True, 'copy_identical': True,
                'application_effect': False,
                'destination': f'/clone/anchor/{variant}'})
            def proof_bundle(label):
                supervisors = {}
                for supervisor in ('r0-witness', 'r0-relation', 'r1-witness',
                                   'r1-relation', 'proof', 'adapter'):
                    ref = self.write_json(f'{variant}-{label}-{supervisor}.json', {
                        'schema': 1, 'passed': True, 'exit_code': 0,
                        'sample_count': 2,
                        'stop_reason': None, 'runner_error_type': None,
                        'cleanup_remaining_owned_processes': 0,
                        'cleanup_status_unknown': False, 'duration_seconds': 0.1,
                        'sampled_peak_owned_tree_rss_bytes': 800 + variant,
                        'sampled_peak_storage_growth_bytes': 1800 + variant,
                    })
                    supervisors[supervisor] = {**ref, 'limits': {}}
                receipt = self.write_json(f'{variant}-{label}-proof-receipt.json', {
                    'schema': 'credential-v3-heldout-proof-evidence-v1',
                    'supervisor_reports': supervisors,
                })
                return {'receipt': receipt, 'artifacts': {}}
            proof_a = proof_bundle('A-full')
            proof_b_full = proof_bundle('B-full')
            proof_b_anchor = proof_bundle('B-anchor')
            proof_c = proof_bundle('C-anchor')
            sources, stages, accepted_branch_ids = {}, {}, {}
            for slot, offset in (('A', 1), ('B', 11), ('C', 21)):
                action = f'{variant + offset:064x}'
                request_file = self.root / f'request-account-{variant}-{slot}.bin'
                request_file.write_bytes(f'request-account:{variant}:{slot}'.encode())
                request_file.chmod(0o600)
                request_ref = {'path': str(request_file),
                               'sha256': sha(request_file.read_bytes())}
                stages[slot] = {'accounts': {'request': request_ref}}
                slot_sources = {}
                for root_name, finalized in (
                        ('R0', f'{variant + offset + 1000:064x}'),
                        ('R1', f'{variant + offset + 2000:064x}')):
                    source_receipt = self.write_json(
                        f'source-{variant}-{slot}-{root_name}.json', {
                            'target_der_sha256': target_credential,
                            'target_tbs_sha256': target_tbs,
                            'action_hash': action,
                            'finalized_request_sha256': finalized,
                        })
                    slot_sources[root_name] = {'receipt': source_receipt,
                                               'artifacts': {}}
                sources[slot] = slot_sources
                accepted_branch_ids[slot] = {
                    'action_hash': action,
                    'source_receipt_sha256': slot_sources['R0']['receipt']['sha256'],
                    'r1_source_receipt_sha256': slot_sources['R1']['receipt']['sha256'],
                    'request_account_sha256': request_ref['sha256'],
                    'finalized_R0': f'{variant + offset + 1000:064x}',
                    'finalized_R1': f'{variant + offset + 2000:064x}',
                }
            monitor_for_step = {}
            for step in steps:
                if step == 'pair-view' or ':proof-' in step:
                    continue
                ref = generic_outer
                if step == 'unrelated_compare:stage':
                    ref = monitors['stage']
                elif step == 'unrelated_compare:transition':
                    ref = monitors['transition']
                elif step == 'unrelated_compare:unrelated_full:effect':
                    ref = monitors['unrelated_full']
                elif step == 'unrelated_compare:anchor:effect':
                    ref = monitors['anchor']
                elif step == 'positive_full:execute':
                    ref = monitors['full']
                elif step == 'own_revocation:effect':
                    ref = monitors['own_revocation']
                steps[step]['monitor'] = ref['path']
                steps[step]['monitor_sha256'] = ref['sha256']
                monitor_for_step[step] = ref
            stage_evidence = {
                'A': {'monitor': monitor_for_step['positive_full:stage']},
                'B': {'monitor': monitors['stage']},
                'C': {'monitor': monitor_for_step['own_revocation:stage']},
            }
            for slot in ('A', 'B', 'C'):
                stage_evidence[slot]['accounts'] = stages[slot]['accounts']
            journal_ref = self.write_json(f'journal-{variant}.json', journal)
            case = {
                'variant': variant,
                'case_context': context_ref,
                'sources': sources,
                'stage': stages,
                'run_manifest': run_manifest_ref,
                'run_journal': journal_ref,
                'all_step_wall_seconds': all_steps,
                'shared_costs': journal['costs'],
                'branch_wall_components': branch_components,
                'branch_wall_seconds': {name: row['total_seconds']
                                        for name, row in branch_components.items()},
                'shared_stage_transition_wall_seconds': {
                    'stage': {'A': 1.0, 'B': 2.0, 'C': 1.0},
                    'transition': {'A': 1.0, 'B': 3.0, 'C': 1.0}},
                'branch_order': (['unrelated_full', 'anchor'] if variant % 2 == 0
                                 else ['anchor', 'unrelated_full']),
                'proof_order': {'unrelated_compare': (
                    ['full', 'anchor'] if variant % 2 == 0 else ['anchor', 'full'])},
                'stage': stage_evidence,
                'transition': {'A': {'monitor': monitor_for_step['positive_full:transition']},
                               'B': {'outer': monitors['transition'],
                                     'monitor': monitors['transition']},
                               'C': {'monitor': monitor_for_step['own_revocation:transition']}},
                'branches': {
                    'full': {'result': {'outer': monitors['full']}, 'proof': proof_a},
                    'unrelated_full': {
                        'result': {'outer': monitors['unrelated_full']},
                        'proof': {'full': proof_b_full, 'anchor': proof_b_anchor},
                        'r1_clone': {'receipt': full_clone}},
                    'anchor': {
                        'result': {'outer': monitors['anchor']},
                        'proof': proof_b_anchor,
                        'r1_clone': {'receipt': anchor_clone}},
                    'own_revocation': {
                        'result': {'outer': monitors['own_revocation']},
                        'proof': proof_c},
                },
            }
            manifest_cases.append(case)
            branch_id = {
                'full': accepted_branch_ids['A'],
                'unrelated_full': accepted_branch_ids['B'],
                'anchor': accepted_branch_ids['B'],
                'own_revocation': accepted_branch_ids['C'],
            }
            branch_roots = {'full': roots['R0'],
                            'unrelated_full': roots['R1'],
                            'anchor': roots['R1'],
                            'own_revocation': roots['R2']}
            branch_slots = {'full': 'A', 'unrelated_full': 'B',
                            'anchor': 'B', 'own_revocation': 'C'}
            acceptance_cases.append({
                'variant': variant,
                'target_credential_sha256': target_credential,
                'target_tbs_sha256': target_tbs,
                'issuer_index': target['issuer_index'],
                'holder_index': target['holder_index'],
                'roots': roots,
                'branches': {name: {
                    'request_slot': branch_slots[name],
                    'action_hash': branch_id[name]['action_hash'],
                    'current_root': branch_roots[name],
                    'finalized_request_sha256': branch_id[name][
                        'finalized_R0' if name == 'full' else 'finalized_R1'],
                    'request_account_sha256': branch_id[name]['request_account_sha256'],
                    'source_receipt_sha256': branch_id[name]['source_receipt_sha256'],
                    'r1_source_receipt_sha256': branch_id[name]['r1_source_receipt_sha256'],
                    'effect_count': 0 if name == 'own_revocation' else 1,
                    'request_consumed': name != 'own_revocation',
                } for name in ('full', 'unrelated_full', 'anchor', 'own_revocation')},
            })

        analyzer_path = Path(analyzer.__file__).resolve()
        analyzer_ref = {'path': str(analyzer_path),
                        'sha256': sha(analyzer_path.read_bytes())}
        manifest_ref = self.write_json('manifest.json', {
            'schema': analyzer.MANIFEST_SCHEMA,
            'freeze_receipt': {'path': '/freeze', 'sha256': 'a' * 64},
            'cohort_receipt': {'path': '/cohort', 'sha256': 'c' * 64},
            'frozen_bundles': {'client': [
                {'path': 'tools/part5/analyze_v3_heldout_costs.py',
                 'artifact': analyzer_ref}]},
            'cases': manifest_cases,
        })
        # The acceptance report binds the receipt's actual cohort receipt digest.
        manifest_doc = json.loads(Path(manifest_ref['path']).read_text())
        manifest_doc['cohort_receipt']['sha256'] = 'b' * 64
        path = Path(manifest_ref['path'])
        path.write_text(json.dumps(manifest_doc, sort_keys=True) + '\n')
        path.chmod(0o600)
        manifest_ref['sha256'] = sha(path.read_bytes())
        acceptance_ref = self.write_json('acceptance.json', {
            'schema': analyzer.ACCEPTANCE_SCHEMA,
            'verified': True, 'heldout_acceptance': True,
            'internal_training_mode_reused': True,
            'manifest_sha256': manifest_ref['sha256'],
            'freeze_sha256': 'a' * 64,
            'cohort_receipt_sha256': 'b' * 64,
            'counts': {'variants': 8}, 'cases': acceptance_cases,
        })
        return manifest_ref, acceptance_ref

    def test_recomputes_request_b_costs_and_reports_matched_pairs(self):
        result = analyzer.analyze(self.manifest, self.acceptance)
        self.assertEqual(result['schema'], analyzer.OUTPUT_SCHEMA)
        self.assertEqual(len(result['pairs']), 8)
        pair = result['pairs'][0]
        self.assertEqual(pair['shared_B_seconds'], 15.0)
        self.assertEqual(pair['full_B_seconds'], 38.0)
        self.assertEqual(pair['anchor_B_seconds'], 43.0)
        self.assertEqual(pair['pair_view_one_time_seconds'], 0.5)
        self.assertEqual(result['summary']['full_B_seconds']['median'], 38.0)
        self.assertEqual(result['summary']['anchor_B_seconds']['spread'], 0.0)
        self.assertEqual(pair['B_sampled_resources']['full'], {
            'monitor_report_count': 13,
            'sampled_peak_owned_tree_rss_bytes': 5000,
            'sampled_peak_storage_growth_bytes': 7000,
        })
        self.assertEqual(pair['B_sampled_resources']['anchor'], {
            'monitor_report_count': 13,
            'sampled_peak_owned_tree_rss_bytes': 6000,
            'sampled_peak_storage_growth_bytes': 8000,
        })
        self.assertIn('samples', result['resource_observations']['caveat'])
        self.assertFalse(result['claims']['cpu_savings'])
        self.assertFalse(result['claims']['whole_application_benefit'])

    def test_accepts_reference_shape_without_measurement_or_censored_fields(self):
        # Both application and proof monitor fixtures intentionally use the
        # accepted session_runner schema variant that omits these optional keys.
        result = analyzer.analyze(self.manifest, self.acceptance)
        self.assertEqual(result['resource_observations']['monitor_report_count'],
                         8 * (23 + 4 * 6))

    def test_rejects_manifest_pin_mismatch(self):
        with self.assertRaisesRegex(ValueError, 'manifest pin'):
            analyzer.analyze({**self.manifest, 'sha256': '0' * 64}, self.acceptance)

    def test_rejects_acceptance_report_for_different_manifest(self):
        report = json.loads(Path(self.acceptance['path']).read_text())
        report['manifest_sha256'] = '0' * 64
        path = Path(self.acceptance['path'])
        path.write_text(json.dumps(report, sort_keys=True) + '\n')
        path.chmod(0o600)
        self.acceptance['sha256'] = sha(path.read_bytes())
        with self.assertRaisesRegex(ValueError, 'exact assembled manifest'):
            analyzer.analyze(self.manifest, self.acceptance)

    def test_rejects_journal_not_bound_to_pinned_run_manifest(self):
        manifest = json.loads(Path(self.manifest['path']).read_text())
        journal_ref = manifest['cases'][0]['run_journal']
        journal = json.loads(Path(journal_ref['path']).read_text())
        journal['manifest_sha256'] = '0' * 64
        journal_path = Path(journal_ref['path'])
        journal_path.write_text(json.dumps(journal, sort_keys=True) + '\n')
        journal_path.chmod(0o600)
        journal_ref['sha256'] = sha(journal_path.read_bytes())
        manifest_path = Path(self.manifest['path'])
        manifest_path.write_text(json.dumps(manifest, sort_keys=True) + '\n')
        manifest_path.chmod(0o600)
        self.manifest['sha256'] = sha(manifest_path.read_bytes())
        self._repin_acceptance_manifest()
        with self.assertRaisesRegex(ValueError, 'journal schema/identity'):
            analyzer.analyze(self.manifest, self.acceptance)

    def test_rejects_accepted_target_identity_drift(self):
        report = json.loads(Path(self.acceptance['path']).read_text())
        report['cases'][0]['target_credential_sha256'] = 'f' * 64
        path = Path(self.acceptance['path'])
        path.write_text(json.dumps(report, sort_keys=True) + '\n')
        path.chmod(0o600)
        self.acceptance['sha256'] = sha(path.read_bytes())
        with self.assertRaisesRegex(ValueError, 'target identity differs'):
            analyzer.analyze(self.manifest, self.acceptance)

    def test_rejects_run_manifest_variant_mismatch(self):
        manifest = json.loads(Path(self.manifest['path']).read_text())
        ref = manifest['cases'][0]['run_manifest']
        run_manifest = json.loads(Path(ref['path']).read_text())
        run_manifest['variant'] = 7
        path = Path(ref['path'])
        path.write_text(json.dumps(run_manifest, sort_keys=True) + '\n')
        path.chmod(0o600)
        ref['sha256'] = sha(path.read_bytes())
        manifest_path = Path(self.manifest['path'])
        manifest_path.write_text(json.dumps(manifest, sort_keys=True) + '\n')
        manifest_path.chmod(0o600)
        self.manifest['sha256'] = sha(manifest_path.read_bytes())
        self._repin_acceptance_manifest()
        with self.assertRaisesRegex(ValueError, 'per-variant heldout run manifest'):
            analyzer.analyze(self.manifest, self.acceptance)

    def test_requires_live_analyzer_as_frozen_client_member(self):
        manifest = json.loads(Path(self.manifest['path']).read_text())
        manifest['frozen_bundles']['client'][0]['path'] = 'tools/part5/not-the-analyzer.py'
        path = Path(self.manifest['path'])
        path.write_text(json.dumps(manifest, sort_keys=True) + '\n')
        path.chmod(0o600)
        self.manifest['sha256'] = sha(path.read_bytes())
        self._repin_acceptance_manifest()
        with self.assertRaisesRegex(ValueError, 'pinned frozen client bundle member'):
            analyzer.analyze(self.manifest, self.acceptance)

    def test_rejects_inconsistent_summary_cost(self):
        mpath = Path(self.manifest['path'])
        manifest = json.loads(mpath.read_text())
        manifest['cases'][0]['all_step_wall_seconds']['unrelated_compare:stage'] = 12.0
        mpath.write_text(json.dumps(manifest, sort_keys=True) + '\n')
        mpath.chmod(0o600)
        self.manifest['sha256'] = sha(mpath.read_bytes())
        self._repin_acceptance_manifest()
        with self.assertRaisesRegex(ValueError, 'journal timing summaries'):
            analyzer.analyze(self.manifest, self.acceptance)

    def test_rejects_shared_cost_total_not_joined_to_journal(self):
        mpath = Path(self.manifest['path'])
        manifest = json.loads(mpath.read_text())
        manifest['cases'][0]['shared_costs']['shared_stage_seconds'] = 999.0
        mpath.write_text(json.dumps(manifest, sort_keys=True) + '\n')
        mpath.chmod(0o600)
        self.manifest['sha256'] = sha(mpath.read_bytes())
        self._repin_acceptance_manifest()
        with self.assertRaisesRegex(ValueError, 'journal timing summaries'):
            analyzer.analyze(self.manifest, self.acceptance)

    def test_rejects_mismatched_b_request_identity(self):
        report = json.loads(Path(self.acceptance['path']).read_text())
        report['cases'][0]['branches']['anchor']['action_hash'] = 'f' * 64
        path = Path(self.acceptance['path'])
        path.write_text(json.dumps(report, sort_keys=True) + '\n')
        path.chmod(0o600)
        self.acceptance['sha256'] = sha(path.read_bytes())
        with self.assertRaisesRegex(ValueError, 'request/source identity|same B request identity'):
            analyzer.analyze(self.manifest, self.acceptance)

    def test_rejects_monitor_duration_above_journal_step(self):
        manifest = json.loads(Path(self.manifest['path']).read_text())
        ref = manifest['cases'][0]['stage']['B']['monitor']
        outer = json.loads(Path(ref['path']).read_text())
        outer['duration_seconds'] = 2.1
        path = Path(ref['path'])
        path.write_text(json.dumps(outer) + '\n')
        path.chmod(0o600)
        ref['sha256'] = sha(path.read_bytes())
        journal_ref = manifest['cases'][0]['run_journal']
        journal = json.loads(Path(journal_ref['path']).read_text())
        journal['steps']['unrelated_compare:stage']['monitor_sha256'] = ref['sha256']
        jpath = Path(journal_ref['path'])
        jpath.write_text(json.dumps(journal) + '\n')
        jpath.chmod(0o600)
        journal_ref['sha256'] = sha(jpath.read_bytes())
        mpath = Path(self.manifest['path'])
        mpath.write_text(json.dumps(manifest, sort_keys=True) + '\n')
        mpath.chmod(0o600)
        self.manifest['sha256'] = sha(mpath.read_bytes())
        self._repin_acceptance_manifest()
        with self.assertRaisesRegex(ValueError, 'journal wall time is below monitor duration'):
            analyzer.analyze(self.manifest, self.acceptance)

    def _repin_acceptance_manifest(self):
        path = Path(self.acceptance['path'])
        report = json.loads(path.read_text())
        report['manifest_sha256'] = self.manifest['sha256']
        path.write_text(json.dumps(report, sort_keys=True) + '\n')
        path.chmod(0o600)
        self.acceptance['sha256'] = sha(path.read_bytes())


if __name__ == '__main__':
    unittest.main()
