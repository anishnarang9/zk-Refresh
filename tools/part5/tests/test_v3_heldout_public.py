import hashlib
import json
from pathlib import Path

import pytest

from tools.part5 import publish_v3_heldout_public as publisher
from tools.part5 import verify_v3_heldout_public as verifier
from tools.part5 import model_v3_heldout_break_even as break_even


def _sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _fixtures():
    acceptance = {
        'schema': 'credential-v3-heldout-application-report-v1',
        'verified': True,
        'heldout_acceptance': True,
        'source_drift_detected': False,
        'manifest_sha256': _sha('manifest'),
        'freeze_sha256': _sha('freeze'),
        'cohort_receipt_sha256': _sha('cohort'),
        'counts': {
            'variants': 8,
            'loaded_disabled_config_negatives': 8,
            'loaded_disabled_issuer_negatives': 8,
            'loaded_ambiguous_restarts': 8,
        },
        # These sensitive-looking source fields must never enter the projection.
        'cases': [
            {'variant': index, 'current_root': '/private/root',
             'action_hash': _sha(f'action-{index}'),
             'disabled_config_negative': {'verified': True},
             'ambiguous_restart': {'verified': True}}
            for index in range(8)
        ],
    }
    pairs = []
    for variant in range(8):
        shared = 10.0 + variant
        full_branch = 5.0 + variant
        anchor_branch = 4.0 + variant
        full = shared + full_branch
        anchor = shared + anchor_branch
        pairs.append({
            'variant': variant,
            'pair_view_one_time_seconds': 1.0,
            'shared_B_seconds': shared,
            'full_B_branch_only_seconds': full_branch,
            'anchor_B_branch_only_seconds': anchor_branch,
            'full_B_seconds': full,
            'anchor_B_seconds': anchor,
            'anchor_minus_full_B_seconds': anchor - full,
            'B_total_wall_savings_fraction': (full - anchor) / full,
            'action_hash': _sha(f'action-{variant}'),
            'current_root': '/private/root',
        })
    cost = {
        'schema': 'credential-v3-heldout-cost-analysis-v1',
        'assembled_manifest_sha256': _sha('manifest'),
        'basis': 'request-B preparation, stage, transition, source, proof, clone, and effect wall time',
        'acceptance_report_sha256': _sha('acceptance-bytes'),
        'pairs': pairs,
        'summary': {},
        'claims': {'cpu_savings': False, 'whole_application_benefit': False,
                  'independent_production_freshness': False},
    }
    source_hashes = {
        'acceptance_report_sha256': _sha('acceptance-bytes'),
        'cost_report_sha256': _sha('cost-bytes'),
        'conditional_model_report_sha256': _sha('model-bytes'),
        'training_total_summary_sha256': _sha('training-bytes'),
    }
    training = {
        'schema': 'part5-v3-campaign-total-cost-summary-v1',
        'training_only': True,
        'matrix_grid_complete': True,
        'matched_pairs': 20,
        'expected_pairs': 20,
        'source_hashes': {
            'matrix_manifest_sha256': _sha('matrix'),
            'sequence_receipt_sha256': _sha('sequence'),
            'economics_report_sha256': _sha('economics'),
        },
        'pairs': [
            {'repetition': repetition, 'target_count': count,
             'status': 'matched', 'full_total_wall_seconds': 20.0 + count,
             'anchor_total_wall_seconds': 19.0 + count}
            for repetition in range(1, 5) for count in (0, 1, 2, 5, 10)
        ],
    }
    model = break_even.build(cost, training, source_hashes['cost_report_sha256'],
                             source_hashes['training_total_summary_sha256'])
    return acceptance, cost, model, training, source_hashes


def test_projection_has_allowlisted_core_path_evidence_only():
    acceptance, cost, model, training, hashes = _fixtures()
    summary, report = publisher.project_reports(acceptance, cost, model, training, hashes)

    assert summary['scope'] == 'core-path-only'
    assert summary['acceptance']['verified_variants'] == 8
    assert summary['acceptance']['loaded_disabled_config_negatives'] == 8
    assert summary['acceptance']['loaded_ambiguous_restart_negatives'] == 8
    assert summary['acceptance']['missing_loaded_expired_status_negatives'] == 8
    assert summary['acceptance']['missing_loaded_queue_capacity_negatives'] == 1
    assert summary['timing']['measured_target_count'] == 1
    assert summary['timing']['basis'] == 'matched request-B component-sum wall time'
    assert summary['conditional_model']['non_k1_values_are_conditional'] is True
    assert summary['claims']['economic_winner'] is False
    serialized = json.dumps({'summary': summary, 'report': report})
    for forbidden in ('current_root', '/private/root', 'action_hash', 'credential-',
                      'account_address', 'witness', 'proof_path'):
        assert forbidden not in serialized


def test_projection_recomputes_pair_arithmetic_and_eight_case_medians():
    acceptance, cost, model, training, hashes = _fixtures()
    summary, _ = publisher.project_reports(acceptance, cost, model, training, hashes)
    values = summary['timing']['variants']
    assert len(values) == 8
    assert values[0]['full_B_seconds'] == 15.0
    assert values[0]['anchor_B_seconds'] == 14.0
    assert values[0]['anchor_minus_full_B_seconds'] == -1.0
    assert summary['timing']['eight_case_medians']['full_B_seconds'] == 22.0
    assert summary['timing']['eight_case_medians']['anchor_B_seconds'] == 21.0

    cost['pairs'][0]['anchor_minus_full_B_seconds'] = 123.0
    with pytest.raises(ValueError, match='arithmetic'):
        publisher.project_reports(acceptance, cost, model, training, hashes)


def test_negative_savings_is_published_as_no_component_sum_benefit():
    acceptance, cost, model, training, hashes = _fixtures()
    for row in cost['pairs']:
        row['anchor_B_branch_only_seconds'] += 8.0
        row['anchor_B_seconds'] = row['shared_B_seconds'] + row[
            'anchor_B_branch_only_seconds']
        row['anchor_minus_full_B_seconds'] = (
            row['anchor_B_seconds'] - row['full_B_seconds'])
        row['B_total_wall_savings_fraction'] = (
            row['full_B_seconds'] - row['anchor_B_seconds']) / row['full_B_seconds']
    model = break_even.build(cost, training, hashes['cost_report_sha256'],
                             hashes['training_total_summary_sha256'])

    summary, report = publisher.project_reports(acceptance, cost, model, training, hashes)

    assert summary['timing']['median_component_direction'] == 'full_lower_cost'
    assert summary['timing']['eight_case_medians']['wall_savings_fraction'] < 0
    assert all(row['wall_savings_fraction'] < 0
               for row in summary['timing']['variants'])
    assert 'no request-B component-sum benefit was measured' in report
    assert summary['claims']['economic_winner'] is False


def test_projection_rejects_missing_negative_coverage_and_unverified_acceptance():
    acceptance, cost, model, training, hashes = _fixtures()
    acceptance['counts']['loaded_disabled_config_negatives'] = 7
    with pytest.raises(ValueError, match='disabled-config'):
        publisher.project_reports(acceptance, cost, model, training, hashes)

    acceptance, cost, model, training, hashes = _fixtures()
    acceptance['verified'] = False
    with pytest.raises(ValueError, match='verified'):
        publisher.project_reports(acceptance, cost, model, training, hashes)


def test_bundle_is_exact_four_files_and_offline_verifier_checks_digest(tmp_path):
    acceptance, cost, model, training, hashes = _fixtures()
    summary, report = publisher.project_reports(acceptance, cost, model, training, hashes)
    sums_sha = publisher.write_bundle(tmp_path / 'public', summary, report)

    assert {p.name for p in (tmp_path / 'public').iterdir()} == {
        'index.json', 'summary.json', 'report.md', 'SHA256SUMS'}
    verified = verifier.verify_bundle(tmp_path / 'public', sums_sha)
    assert verified['schema'] == 'part5-v3-heldout-public-summary-v1'
    with pytest.raises(ValueError, match='digest'):
        verifier.verify_bundle(tmp_path / 'public', _sha('wrong'))


def test_offline_verifier_rejects_extra_duplicate_and_tampered_fields(tmp_path):
    acceptance, cost, model, training, hashes = _fixtures()
    summary, report = publisher.project_reports(acceptance, cost, model, training, hashes)
    out = tmp_path / 'public'
    publisher.write_bundle(out, summary, report)
    projected = json.loads((out / 'summary.json').read_text())
    projected['unexpected'] = 'extra'
    (out / 'summary.json').write_text(json.dumps(projected))
    _rebind_public_hashes(out)
    with pytest.raises(ValueError, match='unknown fields'):
        verifier.verify_bundle(out, _sha((out / 'SHA256SUMS').read_text()))

    out2 = tmp_path / 'duplicate'
    publisher.write_bundle(out2, summary, report)
    (out2 / 'summary.json').write_text('{"schema":"x","schema":"y"}')
    _rebind_public_hashes(out2)
    with pytest.raises(ValueError, match='duplicate JSON key'):
        verifier.verify_bundle(out2, _sha((out2 / 'SHA256SUMS').read_text()))


def _rebind_public_hashes(directory):
    index_path = directory / 'index.json'
    index = json.loads(index_path.read_text())
    index['files']['summary.json'] = hashlib.sha256(
        (directory / 'summary.json').read_bytes()).hexdigest()
    index['files']['report.md'] = hashlib.sha256(
        (directory / 'report.md').read_bytes()).hexdigest()
    index_path.write_text(json.dumps(index, sort_keys=True, indent=2) + '\n')
    lines = ''.join(
        f"{hashlib.sha256((directory / name).read_bytes()).hexdigest()}  {name}\n"
        for name in ('index.json', 'summary.json', 'report.md'))
    (directory / 'SHA256SUMS').write_text(lines)
