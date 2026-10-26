"""Synthetic private publisher gates; no campaign execution or live evidence."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.part5 import export_v3_campaign_public_metrics as exporter

H = 'a' * 64


class MetricsExportTests(unittest.TestCase):
    def test_cli_suppresses_private_exception_text(self):
        flags = ('matrix-manifest', 'economics-manifest', 'economics-report',
                 'reconciliation-report', 'total-report', 'clock-report',
                 'projection-dir', 'receipt-dir', 'output')
        argv = ['exporter'] + [item for flag in flags for item in ('--' + flag, '/SECRET/private')]
        with patch('sys.argv', argv), patch.object(exporter, 'export_public_metrics',
                side_effect=ValueError('/SECRET/private')):
            with self.assertRaises(SystemExit) as raised:
                exporter.main()
        self.assertNotIn('SECRET', str(raised.exception))

    def test_strict_json(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                exporter._decode(raw)

    def test_training_012_registration_pins_are_exact(self):
        self.assertEqual(exporter.registration.REGISTERED_CAMPAIGNS['training-012'], {
            'manifest_path': exporter.registration.ROOT / 'results/dynark/part5/v3-campaign-matrix-training-012.json',
            'manifest_raw_sha256': '21612a6451c00b7a46d9abaa3445e5acecec3c14583317884800b49b2614ff53',
            'manifest_canonical_sha256': '21612a6451c00b7a46d9abaa3445e5acecec3c14583317884800b49b2614ff53',
            'output_root': exporter.registration.ROOT / 'artifacts/dynark/part5/v3-matrix-training-012',
            'actual_plan_sha256': 'e1cd1b9eb1c08fed70cd7544b0286af82422eb50a49a63875be267b57907f467',
        })

    def test_boolean_and_nonfinite_times_rejected(self):
        for value in (True, False, -1, float('inf'), float('nan')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                exporter._seconds(value)

    def test_source_recheck_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'private.json'
            path.write_text('{"private":"/secret/request"}')
            sources = exporter.Sources()
            sources.tree(path)
            path.write_text('{"private":"changed"}')
            with self.assertRaises(ValueError):
                sources.recheck()
            path.write_text('{"private":1,"private":2}')
            with self.assertRaises(ValueError):
                exporter.Sources().read(path)

    def test_fresh_output_gate_precedes_private_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'metrics.json'
            path.write_text('existing')
            with patch.object(exporter.matrix, 'validate_manifest') as validate:
                with self.assertRaises(FileExistsError):
                    exporter.export_public_metrics(*(['missing'] * 8), path)
                validate.assert_not_called()
            self.assertEqual(path.read_text(), 'existing')

    def test_complete_synthetic_projection_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            def write(name, value):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(value))
                return path
            def sha(path):
                return hashlib.sha256(Path(path).read_bytes()).hexdigest()
            stage = write('stage.json', {'prior_status': str(write('prepare-status.json', {})),
                                         'prior_monitor': str(write('prepare-monitor.json', {}))})
            evidence = {'stage_config': stage, 'stage_status': write('stage-status.json', {}),
                        'stage_monitor': write('stage-monitor.json', {}),
                        'cohort_receipt': write('cohort.json', {})}
            write('artifacts/dynark/part5/v3-development-setup-001/setup-manifest.json', {})
            transitions = {str(k): {name: write(f'transition-{k}-{name}.json', {})
                                   for name in ('config', 'status', 'monitor')} for k in exporter.COUNTS[1:]}
            planned, sessions, sequence, clocks, path_map = [], [], [], [], {}
            for rep in range(1, 5):
                for count in exporter.COUNTS:
                    for mode in exporter.MODES:
                        n = len(planned) + 1
                        slot = dict(sequence=n, repetition=rep, target_count=count, mode=mode, identity_sha256=H)
                        planned.append(slot)
                        paths = {name + '_report': write(f'{n}-{name}.json', {'duration_seconds': 10.123456789012345}
                                  if name == 'outer' else {}) for name in ('outer', 'session', 'clone')}
                        receipt = {key: slot[key] for key in ('sequence', 'repetition', 'target_count', 'mode')}
                        receipt.update(slot_identity_sha256=H, clone_preparation_wall_seconds=0.123456789012345)
                        receipt.update({name + '_report_sha256': sha(paths[name + '_report']) for name in ('outer', 'session', 'clone')})
                        paths['slot_receipt'] = write(f'{n}-receipt.json', receipt)
                        path_map[n] = paths
                        sequence.append({**receipt, 'slot_receipt_sha256': sha(paths['slot_receipt'])})
                        sessions.append({**receipt, 'status': 'valid', 'outer_wall_seconds': 10.123456789012345,
                                         'current_root': '/SECRET/credential', 'source_identities': {'SECRET': '/SECRET'}})
                        clocks.append({**sequence[-1], 'monotonic_duration_seconds': 10.123456789012345})
            sequence_path = write('sequence-receipt.json', {'sequence': sequence})
            validated = {'campaign_id': 'training-011', 'manifest_sha256': H,
                         'driver_sha256': H, 'output_root': root,
                         'evidence_paths': evidence, 'transitions': transitions}
            pairs = [dict(repetition=r, target_count=k, status='matched', full_session_wall_seconds=10.123456789012345,
                          anchor_session_wall_seconds=10.123456789012345) for r in range(1, 5) for k in exporter.COUNTS]
            direct = {'grid_complete': True, 'sessions': sessions, 'pairs': pairs}
            shared = {'prepare_seconds': 1.25, 'stage_seconds': 2.75,
                      'transition_seconds': {k: 3.125 for k in exporter.COUNTS[1:]}}
            one_time = {'development_setup_seconds': 5.5, 'cohort_preparation_seconds': 6.5, 'charged_per_request': False}
            audit = {'passed': True, 'slots': clocks}
            econ_manifest = write('economics-input-manifest.json', {})
            direct['input_manifest_sha256'] = sha(econ_manifest)
            econ_report = write('economics.json', direct)
            reconciled = {'pairs': exporter.costs.derive(pairs, exporter.costs.by_count_seconds(1.25, 2.75, shared['transition_seconds']),
                {(row['target_count'], row['repetition'], row['mode']): row['clone_preparation_wall_seconds'] for row in sessions}),
                'economics_report_sha256': sha(econ_report)}
            summary = {'matched_pairs': 20, 'matrix_grid_complete': True}
            args = [write('matrix.json', {}), econ_manifest, econ_report,
                    write('reconciliation.json', reconciled), write('total.json', summary), write('clock.json', audit),
                    root / 'public-projection', root / 'public-receipts', root / 'metrics.json']
            args[6].mkdir(); args[7].mkdir()
            for name in ('index.json', 'matrix-plan.json', 'matrix-manifest.json'):
                write('public-projection/' + name, {})
            for name in ('index.json', 'sequence-receipt.json'):
                write('public-receipts/' + name, {})
            for number in range(1, 61):
                write(f'public-receipts/slot-receipts/slot-{number:04d}.json', {})
            bound = {'campaign_id': 'training-011', 'matrix_manifest_canonical_sha256': H,
                     'sequence_receipt_sha256': sha(sequence_path), 'projection_index_sha256': sha(args[6] / 'index.json'), 'receipt_index_sha256': sha(args[7] / 'index.json')}
            campaign_manifest = write('matrix-012.json', {})

            def write_private_plan():
                return write('matrix-plan.json', {
                    'schema': 'part5-v3-campaign-matrix-plan-v1',
                    'manifest_sha256': validated['manifest_sha256'],
                    'driver_sha256': validated['driver_sha256'],
                    'campaign_id': validated['campaign_id'],
                    'campaign_runtime_seconds': exporter.matrix.CAMPAIGN_SECONDS,
                    'slot_count': len(planned), 'slots': planned,
                })

            write_private_plan()
            registrations = {
                'training-011': {
                    'manifest_path': args[0], 'manifest_raw_sha256': sha(args[0]),
                    'manifest_canonical_sha256': H, 'output_root': root,
                    'actual_plan_sha256': None,
                },
                'training-012': {
                    'manifest_path': campaign_manifest,
                    'manifest_raw_sha256': sha(campaign_manifest),
                    'manifest_canonical_sha256': H, 'output_root': root,
                    'actual_plan_sha256': None,
                },
            }
            patches = [patch.object(exporter.registration, 'REGISTERED_MANIFEST_PATH', args[0]),
                       patch.object(exporter.registration, 'REGISTERED_MANIFEST_RAW_SHA256', sha(args[0])),
                       patch.object(exporter.registration, 'REGISTERED_MANIFEST_CANONICAL_SHA256', H),
                       patch.object(exporter.registration, 'REGISTERED_OUTPUT_ROOT', root),
                       patch.object(exporter.registration, 'REGISTERED_CAMPAIGNS', registrations,
                                    create=True),
                       patch.object(exporter.matrix, 'economics_input_manifest', return_value={}),
                       patch.object(exporter.matrix, 'validate_manifest', return_value=validated),
                       patch.object(exporter.matrix, 'plan_slots', return_value=planned),
                       patch.object(exporter.matrix, 'output_paths', side_effect=lambda _, s: path_map[s['sequence']]),
                       patch.object(exporter.matrix, 'REPO', root),
                       patch.object(exporter.costs, 'verify_completed_matrix', return_value=sha(sequence_path)),
                       patch.object(exporter.bindings, 'verify_bundles', return_value=bound),
                       patch.object(exporter.clock, 'audit', return_value=audit),
                       patch.object(exporter.economics, 'aggregate', return_value=direct),
                       patch.object(exporter.economics, '_pair', return_value={'status': 'matched'}),
                       patch.object(exporter.costs, 'reconcile', return_value=reconciled),
                       patch.object(exporter.costs, 'shared_steps', return_value=shared),
                       patch.object(exporter.costs, 'one_time_costs', return_value=one_time),
                       patch.object(exporter.total, 'summarize', return_value=summary)]
            from contextlib import ExitStack
            with ExitStack() as stack:
                for mocked in patches:
                    stack.enter_context(mocked)
                for directory in args[6:8]:
                    with self.assertRaises(ValueError):
                        exporter.export_public_metrics(*args[:-1], directory / 'metrics.json')
                capsule = exporter.export_public_metrics(*args)
                raw = args[-1].read_text()
                self.assertNotIn('SECRET', raw)
                self.assertNotIn('current_root', raw)
                self.assertNotIn(str(root), raw)
                self.assertEqual(len(capsule['slots']), 60)
                self.assertEqual(capsule['slots'][0]['outer_wall_seconds'], 10.123456789012345)
                self.assertEqual(len({row['match_group'] for row in capsule['slots']}), 20)
                args[-1].unlink()
                with patch.object(exporter.clock, 'audit', return_value={**audit, 'passed': False}):
                    with self.assertRaises(ValueError):
                        exporter.export_public_metrics(*args)
                self.assertFalse(args[-1].exists())
                with patch.object(exporter.economics, '_pair', return_value={'status': 'unmatched'}):
                    with self.assertRaises(ValueError):
                        exporter.export_public_metrics(*args)
                self.assertFalse(args[-1].exists())
                with patch.object(exporter.total, 'summarize', return_value={**summary, 'matched_pairs': 19}):
                    with self.assertRaises(ValueError):
                        exporter.export_public_metrics(*args)
                self.assertFalse(args[-1].exists())
                sessions[0]['status'] = 'invalid'
                econ_report.write_text(json.dumps(direct))
                with self.assertRaises(ValueError):
                    exporter.export_public_metrics(*args)
                self.assertFalse(args[-1].exists())

                # A second allowlisted identity uses the completion binding's
                # campaign ID in the public capsule and is joined to its own
                # manifest path and raw pin.
                sessions[0]['status'] = 'valid'
                econ_report.write_text(json.dumps(direct))
                validated['campaign_id'] = 'training-012'
                args[0] = campaign_manifest
                bound['campaign_id'] = 'training-012'
                plan_path = write_private_plan()
                registrations['training-012']['actual_plan_sha256'] = sha(plan_path)
                capsule = exporter.export_public_metrics(*args)
                self.assertEqual(capsule['campaign_id'], 'training-012')
                self.assertFalse(any(value == 'training-011' for value in capsule.values()))
                args[-1].unlink()

                with patch.object(exporter.matrix, 'plan_slots', return_value=planned[:-1]):
                    with self.assertRaises(ValueError):
                        exporter.export_public_metrics(*args)
                self.assertFalse(args[-1].exists())

                bound['campaign_id'] = 'training-011'
                with self.assertRaises(ValueError):
                    exporter.export_public_metrics(*args)
                self.assertFalse(args[-1].exists())
                bound['campaign_id'] = 'training-012'

                registered_raw = registrations['training-012']['manifest_raw_sha256']
                registrations['training-012']['manifest_raw_sha256'] = 'b' * 64
                with self.assertRaises(ValueError):
                    exporter.export_public_metrics(*args)
                self.assertFalse(args[-1].exists())
                registrations['training-012']['manifest_raw_sha256'] = registered_raw

                registered_plan = registrations['training-012']['actual_plan_sha256']
                registrations['training-012']['actual_plan_sha256'] = 'c' * 64
                with self.assertRaises(ValueError):
                    exporter.export_public_metrics(*args)
                self.assertFalse(args[-1].exists())
                registrations['training-012']['actual_plan_sha256'] = registered_plan


if __name__ == '__main__':
    unittest.main()
