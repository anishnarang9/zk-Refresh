import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools.part5 import verify_v3_campaign_public_metrics as tool
from tools.part5.tests.test_verify_v3_campaign_public_projection import (
    _public_bundle, _read_json, _write_json, _rehash_public,
)
from tools.part5.tests.test_verify_v3_campaign_public_receipts import _bundle, _sha, _json_bytes
from tools.part5.tests.test_verify_v3_campaign_public_bundle_bindings import _save_sequence
from tools.part5.tests.test_verify_v3_campaign_public_clock_audit import _report


def _fixture(root, campaign_id='training-011'):
    plan = _public_bundle(root, campaign_id)
    chain = _bundle(root / 'receipts')
    doc = _read_json(plan / 'matrix-plan.json')
    for slot in doc['slots']:
        slot['slot_identity_sha256'] = f'{slot["sequence"]:064x}'
    _write_json(plan / 'matrix-plan.json', doc)
    _rehash_public(_read_json(plan / 'index.json'), plan, 'matrix_plan')
    index, sequence = _read_json(chain / 'index.json'), _read_json(chain / 'sequence-receipt.json')
    index['campaign_id'] = sequence['campaign_id'] = campaign_id
    index['matrix_manifest_canonical_sha256'] = sequence['manifest_sha256'] = doc['matrix_manifest_canonical_sha256']
    _save_sequence(chain, index, sequence)
    bound = tool.bindings.verify_bundles(plan, chain)
    audit = _report(campaign_id=campaign_id)
    audit['matrix_manifest_sha256'] = bound['matrix_manifest_canonical_sha256']
    audit['sequence_receipt_sha256'] = bound['sequence_receipt_sha256']
    slots = []
    for row, audit_row in zip(sequence['sequence'], audit['slots']):
        receipt = _read_json(chain / f'slot-receipts/slot-{row["sequence"]:04d}.json')
        slot = {field: row[field] for field in ('sequence', 'repetition', 'target_count', 'mode', 'slot_identity_sha256', 'slot_receipt_sha256')}
        slot.update({field: receipt[field] for field in ('session_report_sha256', 'outer_report_sha256', 'clone_report_sha256')})
        slot.update(status='valid', match_group=(row['repetition'] - 1) * 5 + tool.COUNTS.index(row['target_count']) + 1,
                    outer_wall_seconds=60.0 if row['mode'] != 'anchor' else 30.0,
                    clone_preparation_seconds=1.25)
        slots.append(slot)
        for field in ('slot_receipt_sha256', 'outer_report_sha256'):
            audit_row[field] = slot[field]
        audit_row['utc_elapsed_seconds'] = audit_row['monotonic_duration_seconds'] = slot['outer_wall_seconds']
    clock_path = root / 'clock.json'
    _write_json(clock_path, audit)
    sources = dict.fromkeys(tool.SOURCE_FIELDS, 'e' * 64)
    sources.update({field: bound[field] for field in ('projection_index_sha256', 'receipt_index_sha256', 'sequence_receipt_sha256', 'matrix_manifest_canonical_sha256')})
    sources['clock_audit_report_sha256'] = _sha(clock_path.read_bytes())
    capsule = dict(schema=tool.SCHEMA, campaign_id=campaign_id, training_only=True,
                   matrix_grid_complete=True, source_hashes=sources, slots=slots,
                   shared=dict(prepare_seconds=2.0, stage_seconds=3.0,
                               transitions=[dict(target_count=k, seconds=1.0, config_sha256='e'*64,
                                                 status_sha256='e'*64, monitor_sha256='e'*64) for k in tool.COUNTS[1:]],
                               **dict.fromkeys(tool.SHARED_HASHES, 'e'*64)),
                   one_time=dict(development_setup_seconds=100, cohort_preparation_seconds=200,
                                 charged_per_request=False, **dict.fromkeys(tool.ONE_TIME_HASHES, 'e'*64)),
                   claims=dict(tool.CLAIMS))
    path = root / 'metrics.json'
    _write_json(path, capsule)
    (root / 'private-manifest.json').unlink()
    (root / 'private-plan.json').unlink()
    return plan, chain, path, clock_path


def _verify(paths):
    plan, chain, metrics, clock = paths
    return tool.verify_metrics(plan, chain, metrics, _sha(metrics.read_bytes()), clock)


class PublicMetricsTests(unittest.TestCase):
    def test_training_012_accepts_matching_public_bundles_and_rejects_mixed_campaign(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = _fixture(Path(temporary).resolve(), 'training-012')
            result = _verify(paths)
            self.assertEqual(result['campaign_id'], 'training-012')
            self.assertEqual(result['matched_pair_count'], 20)
            capsule = _read_json(paths[2])
            capsule['campaign_id'] = 'training-011'
            _write_json(paths[2], capsule)
            with self.assertRaisesRegex(ValueError, 'campaign'):
                _verify(paths)

    def test_independent_checks_and_component_arithmetic_without_private_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = _fixture(Path(temporary).resolve())
            with mock.patch.object(tool.projection, 'verify_bundle', wraps=tool.projection.verify_bundle) as p, \
                    mock.patch.object(tool.receipts, 'verify_bundle', wraps=tool.receipts.verify_bundle) as r, \
                    mock.patch.object(tool.bindings, 'verify_bundles', wraps=tool.bindings.verify_bundles) as b, \
                    mock.patch.object(tool.clock, 'verify_report', wraps=tool.clock.verify_report) as c:
                result = _verify(paths)
            self.assertGreaterEqual(p.call_count, 1)
            self.assertGreaterEqual(r.call_count, 1)
            b.assert_called_once()
            c.assert_called_once()
            self.assertEqual(result['matched_pair_count'], 20)
            self.assertEqual(result['pair_totals'][0]['full_total_seconds'], 66.25)
            self.assertEqual(result['pair_totals'][0]['anchor_total_seconds'], 36.25)
            self.assertEqual(result['per_target_count'][0]['positive_count'], 4)
            self.assertTrue(result['per_target_count'][0]['paired_fraction_at_least_20_percent'])
            self.assertEqual(result['median_sampled_break_even']['first_positive_target_count'], 0)
            self.assertIn('not independently verifiable', result['scope'])
            self.assertNotIn(temporary, json.dumps(result))

    def test_rehashed_capsule_tampering(self):
        mutations = [lambda x: x['slots'].pop(),
                     lambda x: x['slots'][0].update(sequence=True),
                     lambda x: x['slots'][0].update(match_group=2),
                     lambda x: x['slots'][0].update(session_report_sha256='f'*64),
                     lambda x: x['slots'][0].update(clone_preparation_seconds=2),
                     lambda x: x['slots'][0].update(outer_wall_seconds=59),
                     lambda x: x['slots'][0].update(private_path='/private/SECRET'),
                     lambda x: x['shared'].update(prepare_seconds=True),
                     lambda x: x['shared'].update(stage_seconds=0),
                     lambda x: x['one_time'].update(development_setup_seconds=-1),
                     lambda x: x['source_hashes'].update(projection_index_sha256='f'*64),
                     lambda x: x['claims'].update(whole_application_benefit_established=True),
                     lambda x: x['shared']['transitions'].reverse(),
                     lambda x: x['shared'].update(prepare_seconds=float('inf'))]
        for mutate in mutations:
            with self.subTest(mutation=mutate), tempfile.TemporaryDirectory() as temporary:
                paths = _fixture(Path(temporary).resolve())
                doc = _read_json(paths[2])
                mutate(doc)
                _write_json(paths[2], doc)
                with self.assertRaises(ValueError):
                    _verify(paths)

    def test_digest_duplicate_key_and_clock_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = _fixture(Path(temporary).resolve())
            with self.assertRaisesRegex(ValueError, 'byte hash'):
                tool.verify_metrics(paths[0], paths[1], paths[2], '0'*64, paths[3])
            raw = paths[2].read_bytes()
            paths[2].write_bytes(raw.replace(b'"training_only":true', b'"training_only":true,"training_only":true'))
            with self.assertRaises(ValueError):
                _verify(paths)
            paths[2].write_bytes(raw)
            audit = _read_json(paths[3])
            audit['slots'][0]['outer_report_sha256'] = 'f'*64
            _write_json(paths[3], audit)
            doc = _read_json(paths[2])
            doc['source_hashes']['clock_audit_report_sha256'] = _sha(paths[3].read_bytes())
            _write_json(paths[2], doc)
            with self.assertRaisesRegex(ValueError, 'clock slot'):
                _verify(paths)

    def test_cli_does_not_echo_untrusted_paths_or_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = _fixture(Path(temporary).resolve())
            doc = _read_json(paths[2])
            doc['SECRET_PRIVATE_PATH'] = '/private/TOKEN'
            _write_json(paths[2], doc)
            result = subprocess.run([sys.executable, tool.__file__, str(paths[0]), str(paths[1]),
                                     str(paths[2]), '--expected-sha256', _sha(paths[2].read_bytes()),
                                     '--clock-audit', str(paths[3])], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            for secret in ('SECRET', 'TOKEN', temporary):
                self.assertNotIn(secret, result.stdout + result.stderr)

    def test_medians_use_paired_differences_and_fractions(self):
        # Full and Anchor ranks differ, so subtracting separate medians is wrong.
        full, anchor = [10, 20, 100, 200], [9, 19, 1, 199]
        slots = []
        for rep in range(1, 5):
            for index, k in enumerate(tool.COUNTS):
                for mode in ('full', 'anchor', 'coalesced-full'):
                    slots.append(dict(repetition=rep, target_count=k, match_group=(rep-1)*5+index+1,
                                      mode=mode, outer_wall_seconds=(anchor if mode == 'anchor' else full)[rep-1],
                                      clone_preparation_seconds=0))
        capsule = {'slots': slots, 'shared': {'prepare_seconds': 1, 'stage_seconds': 1,
                                            'transitions': [{'target_count': k, 'seconds': 1} for k in tool.COUNTS[1:]]}}
        summary = tool._arithmetic(capsule)['per_target_count'][0]
        self.assertEqual(summary['median_delta_seconds'], 1)
        self.assertNotEqual(summary['median_delta_seconds'],
                            summary['median_full_total_seconds'] - summary['median_anchor_total_seconds'])
        self.assertNotEqual(summary['median_savings_fraction'],
                            summary['median_delta_seconds'] / summary['median_full_total_seconds'])

    def test_paired_medians_zero_and_nonpersistent_crossing(self):
        capsule = {'shared': {'prepare_seconds': 1, 'stage_seconds': 1,
                             'transitions': [{'target_count': k, 'seconds': 1} for k in tool.COUNTS[1:]]}, 'slots': []}
        for rep in range(1, 5):
            for i, k in enumerate(tool.COUNTS):
                # Crossing at k1, followed by losses; later losses do not erase it.
                delta = [0, 3, -2, -4, -5][i]
                for mode in ('full', 'anchor', 'coalesced-full'):
                    capsule['slots'].append(dict(repetition=rep, target_count=k, match_group=(rep-1)*5+i+1,
                                                 mode=mode, outer_wall_seconds=10 if mode != 'anchor' else 10-delta,
                                                 clone_preparation_seconds=1))
        result = tool._arithmetic(capsule)
        self.assertEqual(result['median_sampled_break_even']['first_positive_target_count'], 1)
        self.assertEqual(result['median_sampled_break_even']['preceding_sampled_target_count'], 0)
        self.assertEqual(result['per_target_count'][0]['zero_count'], 4)
        for slot in capsule['slots']:
            slot['outer_wall_seconds'] = 10
        self.assertTrue(tool._arithmetic(capsule)['median_sampled_break_even']['not_crossed_through_k10'])


if __name__ == '__main__':
    unittest.main()
