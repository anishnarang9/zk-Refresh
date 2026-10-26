"""Synthetic exporter-to-offline-verifier integration; no live campaign evidence."""
from contextlib import ExitStack
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.part5 import export_v3_campaign_public_metrics as exporter
from tools.part5 import verify_v3_campaign_public_metrics as verifier
from tools.part5.tests.test_verify_v3_campaign_public_metrics import _fixture
from tools.part5.tests.test_verify_v3_campaign_public_projection import _read_json, _write_json
from tools.part5.tests.test_verify_v3_campaign_public_receipts import _sha


class PublicMetricsInteropTests(unittest.TestCase):
    def test_exported_capsule_verifies_with_real_public_checks_and_arithmetic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            plan_root, receipt_root, output, clock_path = _fixture(root)
            template = _read_json(output)
            output.unlink()
            def write(name, value):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                _write_json(path, value)
                return path
            sequence_path = receipt_root / 'sequence-receipt.json'
            sequence_sha = _sha(sequence_path.read_bytes())
            shared = {'prepare_seconds': 2.0, 'stage_seconds': 3.0,
                      'transition_seconds': {k: 1.0 for k in exporter.COUNTS[1:]}}
            shared['by_count_seconds'] = exporter.costs.by_count_seconds(2.0, 3.0, shared['transition_seconds'])
            one_time = {'development_setup_seconds': 100, 'cohort_preparation_seconds': 200,
                        'charged_per_request': False}
            evidence = {'stage_config': write('private/stage-config.json', {
                'prior_status': str(write('private/prepare-status.json', {})),
                'prior_monitor': str(write('private/prepare-monitor.json', {}))}),
                'stage_status': write('private/stage-status.json', {}),
                'stage_monitor': write('private/stage-monitor.json', {}),
                'cohort_receipt': write('private/cohort.json', {})}
            write('artifacts/dynark/part5/v3-development-setup-001/setup-manifest.json', {})
            transitions = {str(k): {kind: write(f'private/transition-{k}-{kind}.json', {})
                                   for kind in ('config', 'status', 'monitor')} for k in exporter.COUNTS[1:]}
            validated = {'campaign_id': 'training-011', 'manifest_sha256': template['source_hashes']['matrix_manifest_canonical_sha256'],
                         'driver_sha256': 'd' * 64,
                         'output_root': root / 'private/campaign', 'evidence_paths': evidence, 'transitions': transitions}
            planned, paths_by_key, sessions = [], {}, []
            identity_fields = ('freeze_sha256', 'cohort_receipt_sha256', 'current_root',
                               'current_report_sha256', 'source_identities', 'exact_request_sha256',
                               'outer_environment', 'preexisting_signed_history_preparation_charged',
                               'preexisting_ledger_clone_charged', 'preexisting_state_wait_charged',
                               'shared_public_setup_material_charged', 'coalesced_state_wait_seconds_observed')
            for slot in template['slots']:
                key = (slot['repetition'], slot['target_count'], slot['mode'])
                planned.append({field: slot[field] for field in ('sequence', 'repetition', 'target_count', 'mode')})
                planned[-1]['identity_sha256'] = slot['slot_identity_sha256']
                # Public receipt report hashes are opaque fixture pins. Private report files
                # use those exact bytes, leaving both public verifiers fully independent.
                # Update each receipt-chain hash below after creating private reports.
                paths = {'slot_receipt': receipt_root / f'slot-receipts/slot-{slot["sequence"]:04d}.json'}
                for kind in ('session', 'clone', 'outer'):
                    paths[kind + '_report'] = write(f'private/slot-{slot["sequence"]}/{kind}.json',
                        {'duration_seconds': slot['outer_wall_seconds']} if kind == 'outer' else {})
                planned[-1]['paths'] = {name: str(path) for name, path in paths.items()}
                paths_by_key[key] = paths
                session = {field: slot[field] for field in ('repetition', 'target_count', 'mode')}
                session.update(dict.fromkeys(identity_fields, 'publisher-private-identity'))
                session.update(source_identities={'private': 'withheld'}, current_root='/PRIVATE/SECRET',
                               status='valid', outer_wall_seconds=slot['outer_wall_seconds'],
                               outer_limits={}, sampled_peak_owned_tree_rss_bytes=1,
                               sampled_peak_storage_growth_bytes=0)
                session.update({kind + '_report_sha256': _sha(paths[kind + '_report'].read_bytes()) for kind in ('session', 'outer')})
                sessions.append(session)
            # Rebuild a genuine contiguous public receipt chain with the synthetic private bytes.
            index = _read_json(receipt_root / 'index.json')
            sequence = _read_json(sequence_path)
            audit = _read_json(clock_path)
            previous = None
            for slot, entry, ref, audit_row in zip(planned, sequence['sequence'], index['slot_receipts'], audit['slots']):
                paths = paths_by_key[(slot['repetition'], slot['target_count'], slot['mode'])]
                receipt = _read_json(paths['slot_receipt'])
                receipt['previous_slot_receipt_sha256'] = entry['previous_slot_receipt_sha256'] = previous
                for kind in ('session', 'clone', 'outer'):
                    receipt[kind + '_report_sha256'] = _sha(paths[kind + '_report'].read_bytes())
                _write_json(paths['slot_receipt'], receipt)
                previous = _sha(paths['slot_receipt'].read_bytes())
                entry['slot_receipt_sha256'] = ref['sha256'] = audit_row['slot_receipt_sha256'] = previous
                audit_row['outer_report_sha256'] = receipt['outer_report_sha256']
            sequence['final_slot_receipt_sha256'] = previous
            _write_json(sequence_path, sequence)
            sequence_sha = _sha(sequence_path.read_bytes())
            index['sequence_receipt']['sha256'] = sequence_sha
            _write_json(receipt_root / 'index.json', index)
            audit['sequence_receipt_sha256'] = sequence_sha
            _write_json(clock_path, audit)
            write('private/campaign/sequence-receipt.json', sequence)
            manifest_path = write('private/matrix.json', {})
            write('private/campaign/matrix-plan.json', {
                'schema': 'part5-v3-campaign-matrix-plan-v1',
                'manifest_sha256': validated['manifest_sha256'],
                'driver_sha256': validated['driver_sha256'],
                'campaign_id': validated['campaign_id'],
                'campaign_runtime_seconds': exporter.matrix.CAMPAIGN_SECONDS,
                'slot_count': len(planned), 'slots': planned,
            })
            training_012_manifest = write('private/matrix-012.json', {})
            economics_manifest = write('private/campaign/economics-input-manifest.json', exporter.matrix.economics_input_manifest(planned))
            pairs = []
            by_key = {(row['repetition'], row['target_count'], row['mode']): row for row in sessions}
            for rep in range(1, 5):
                for k in exporter.COUNTS:
                    pairs.append(exporter.economics._pair({'repetition': rep, 'target_count': k},
                        *(by_key[(rep, k, mode)] for mode in exporter.MODES)))
            direct = {'schema': exporter.total.ECONOMICS_SCHEMA, 'training_only': True,
                      'grid_complete': True, 'sessions': sessions, 'pairs': pairs,
                      'input_manifest_sha256': _sha(economics_manifest.read_bytes())}
            economics_report = write('private/economics.json', direct)
            reconciliation_path, total_path = root / 'private/reconciliation.json', root / 'private/total.json'
            # Mock only private provenance/measurement acquisition. Public shape/chain,
            # cross-binding, pair equality, cost derivation, and total summaries run normally.
            with ExitStack() as stack:
                for replacement in (
                    patch.object(exporter.matrix, 'REPO', root),
                    patch.object(exporter.registration, 'REGISTERED_CAMPAIGNS', {
                        'training-011': {
                            'manifest_path': manifest_path,
                            'manifest_raw_sha256': _sha(manifest_path.read_bytes()),
                            'manifest_canonical_sha256': validated['manifest_sha256'],
                            'output_root': validated['output_root'],
                            'actual_plan_sha256': None,
                        },
                        'training-012': {
                            'manifest_path': training_012_manifest,
                            'manifest_raw_sha256': _sha(training_012_manifest.read_bytes()),
                            'manifest_canonical_sha256': validated['manifest_sha256'],
                            'output_root': validated['output_root'],
                            'actual_plan_sha256': None,
                        },
                    }),
                    patch.object(exporter.registration, 'REGISTERED_MANIFEST_PATH', manifest_path),
                    patch.object(exporter.registration, 'REGISTERED_MANIFEST_RAW_SHA256', _sha(manifest_path.read_bytes())),
                    patch.object(exporter.registration, 'REGISTERED_MANIFEST_CANONICAL_SHA256', validated['manifest_sha256']),
                    patch.object(exporter.registration, 'REGISTERED_OUTPUT_ROOT', validated['output_root']),
                    patch.object(exporter.matrix, 'validate_manifest', return_value=validated),
                    patch.object(exporter.matrix, 'plan_slots', return_value=planned),
                    patch.object(exporter.matrix, 'output_paths', side_effect=lambda _, s: paths_by_key[(s['repetition'], s['target_count'], s['mode'])]),
                    patch.object(exporter.costs, 'verify_completed_matrix', return_value=sequence_sha),
                    patch.object(exporter.costs, 'shared_steps', return_value=shared),
                    patch.object(exporter.costs, 'one_time_costs', return_value=one_time),
                    patch.object(exporter.clock, 'audit', return_value=audit),
                    patch.object(exporter.economics, 'aggregate', return_value=direct),
                ):
                    stack.enter_context(replacement)
                reconciled = exporter.costs.reconcile(validated, direct)
                reconciled['economics_report_sha256'] = _sha(economics_report.read_bytes())
                _write_json(reconciliation_path, reconciled)
                summary = exporter.total.summarize(reconciled, direct)
                _write_json(total_path, summary)
                before = {str(path): path.read_bytes() for directory in (plan_root, receipt_root)
                          for path in directory.rglob('*.json')}
                capsule = exporter.export_public_metrics(manifest_path, economics_manifest, economics_report,
                    reconciliation_path, total_path, clock_path, plan_root, receipt_root, output)
                result = verifier.verify_metrics(plan_root, receipt_root, output, _sha(output.read_bytes()), clock_path)
                self.assertEqual(result['matched_pair_count'], 20)
                self.assertEqual(set(capsule['source_hashes']), verifier.SOURCE_FIELDS)
                for k, row in zip(exporter.COUNTS, result['per_target_count']):
                    expected = summary['by_update_count'][str(k)]
                    self.assertEqual(row['median_full_total_seconds'], expected['median_full_total_wall_seconds'])
                    self.assertEqual(row['median_anchor_total_seconds'], expected['median_anchor_total_wall_seconds'])
                    self.assertEqual(row['median_delta_seconds'], expected['median_full_minus_anchor_total_wall_seconds'])
                    self.assertEqual(row['median_savings_fraction'], expected['median_total_wall_savings_fraction'])
                    self.assertEqual(row['paired_fraction_at_least_20_percent'],
                                     expected['registered_20_percent_total_wall_target'] == 'met_by_median')
                    self.assertEqual(row['positive_count'], expected['paired_sign_counts']['full_minus_anchor_positive'])
                self.assertEqual(result['median_sampled_break_even']['first_positive_target_count'],
                                 summary['break_even']['measured_median']['first_sampled_k'])
                self.assertEqual(before, {str(path): path.read_bytes() for directory in (plan_root, receipt_root)
                                         for path in directory.rglob('*.json')})
                self.assertFalse(output.is_relative_to(plan_root))
                self.assertFalse(output.is_relative_to(receipt_root))
                self.assertNotIn('/PRIVATE/SECRET', output.read_text())
                with self.assertRaises(ValueError):
                    verifier.verify_metrics(plan_root, receipt_root, output, '0' * 64, clock_path)


if __name__ == '__main__':
    unittest.main()
