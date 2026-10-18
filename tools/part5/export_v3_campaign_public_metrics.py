#!/usr/bin/env python3
"""Privately revalidate a completed allowlisted campaign and publish metrics only."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.part5 import analyze_v3_campaign_economics as economics
from tools.part5 import audit_v3_campaign_clock_drift as clock
from tools.part5 import bind_v3_campaign_completion as registration
from tools.part5 import reconcile_v3_campaign_costs as costs
from tools.part5 import run_v3_campaign_matrix as matrix
from tools.part5 import summarize_v3_campaign_total as total
from tools.part5 import export_v3_campaign_public_receipts as receipts
from tools.part5 import verify_v3_campaign_public_bundle_bindings as bindings
from tools.part5 import verify_v3_campaign_public_receipts as public_receipts

SCHEMA = 'part5-v3-public-metrics-capsule-v1'
COUNTS = (0, 1, 2, 5, 10)
MODES = ('full', 'anchor', 'coalesced-full')
CAMPAIGN_IDS = ('training-011', 'training-012')


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _decode(raw):
    def reject(_):
        raise ValueError('nonfinite JSON number')
    value = json.loads(raw, object_pairs_hook=_object, parse_constant=reject)
    _finite(value)
    return value


def _finite(value):
    if type(value) is float and not math.isfinite(value):
        raise ValueError('nonfinite JSON number')
    if isinstance(value, dict):
        for child in value.values():
            _finite(child)
    elif isinstance(value, list):
        for child in value:
            _finite(child)


class Sources:
    """Keep byte pins for explicitly selected evidence roles."""
    def __init__(self):
        self.pins = {}

    def pin(self, path):
        path = Path(path).absolute()
        digest = matrix.sha256(path)
        if path in self.pins and self.pins[path] != digest:
            raise ValueError('source changed during export')
        self.pins[path] = digest
        return digest

    def read(self, path):
        path = Path(path).absolute()
        digest = self.pin(path)
        raw = public_receipts._read_regular(path, 16 * 1024 * 1024, 'private source')
        if _hash(raw) != digest:
            raise ValueError('source changed during read')
        return _decode(raw)

    def tree(self, path):
        # Decode only an explicitly selected JSON evidence role. Never interpret
        # arbitrary strings in reports as additional filesystem references.
        self.read(path)

    def recheck(self):
        if any(matrix.sha256(path) != digest for path, digest in self.pins.items()):
            raise ValueError('source changed during export')


def _seconds(value, positive=False):
    if (type(value) not in (int, float) or not math.isfinite(value)
            or value < 0 or (positive and value == 0)):
        raise ValueError('finite timing scalar required')
    return value


def _same(actual, expected, label):
    # Existing private reports use integer count keys before JSON serialization.
    if isinstance(expected, dict):
        expected = {str(key): value for key, value in expected.items()}
    # JSON equality must distinguish booleans from numbers.
    if type(actual) is not type(expected):
        raise ValueError(label + ' differs from recomputation')
    if isinstance(actual, dict):
        if set(actual) != set(expected):
            raise ValueError(label + ' fields differ from recomputation')
        for key in actual:
            _same(actual[key], expected[key], label)
    elif isinstance(actual, list):
        if len(actual) != len(expected):
            raise ValueError(label + ' length differs from recomputation')
        for left, right in zip(actual, expected):
            _same(left, right, label)
    elif actual != expected:
        raise ValueError(label + ' differs from recomputation')


def _registered_campaign(manifest_path, manifest_raw_sha256):
    registered = getattr(registration, 'REGISTERED_CAMPAIGNS', None)
    if not isinstance(registered, dict) or set(registered) != set(CAMPAIGN_IDS):
        raise ValueError('registered Training-011/012 campaign map required')
    matches = []
    required = {'manifest_path', 'manifest_raw_sha256', 'manifest_canonical_sha256',
                'output_root', 'actual_plan_sha256'}
    for campaign_id in CAMPAIGN_IDS:
        row = registered[campaign_id]
        if not isinstance(row, dict) or set(row) != required:
            raise ValueError('complete registered campaign pins required')
        if (Path(manifest_path) == Path(row['manifest_path'])
                and manifest_raw_sha256 == row['manifest_raw_sha256']):
            matches.append((campaign_id, row))
    if len(matches) != 1:
        raise ValueError('registered campaign manifest path and raw digest required')
    campaign_id, row = matches[0]
    if (not isinstance(row['manifest_canonical_sha256'], str)
            or not isinstance(row['output_root'], Path)
            or (row['actual_plan_sha256'] is not None
                and not isinstance(row['actual_plan_sha256'], str))):
        raise ValueError('valid registered campaign pins required')
    return campaign_id, row


def export_public_metrics(matrix_manifest, economics_manifest, economics_report,
                          reconciliation_report, total_report, clock_report,
                          projection_dir, receipt_dir, output):
    output = Path(output)
    if output.name != 'metrics.json':
        raise ValueError('output must be a fresh metrics.json')
    if output.exists() or output.is_symlink():
        raise FileExistsError('fresh metrics output required')
    resolved_output = output.parent.resolve(strict=True) / output.name
    for directory in (projection_dir, receipt_dir):
        if resolved_output.is_relative_to(Path(directory).resolve(strict=True)):
            raise ValueError('metrics output must be separate from public bundles')
    sources = Sources()
    for path in (matrix_manifest, economics_manifest, economics_report,
                 reconciliation_report, total_report, clock_report):
        sources.tree(path)
    for module in (sys.modules[__name__], economics, costs, total, clock, matrix,
                   registration, bindings, public_receipts, receipts):
        sources.pin(module.__file__)
    campaign_id, registered = _registered_campaign(
        Path(matrix_manifest), sources.pin(matrix_manifest))
    validated = matrix.validate_manifest(Path(matrix_manifest))
    if (validated['campaign_id'] != campaign_id
            or validated['manifest_sha256'] != registered['manifest_canonical_sha256']
            or validated['output_root'] != registered['output_root']):
        raise ValueError('registered campaign manifest identity required')
    for path in validated['evidence_paths'].values():
        sources.tree(path)
    for row in validated['transitions'].values():
        for role in ('config', 'report', 'status', 'monitor'):
            if role in row:
                sources.tree(row[role])
    for path in validated.get('tools', {}).values():
        if Path(path).suffix == '.json':
            sources.tree(path)
        else:
            sources.pin(path)
    stage_config = sources.read(validated['evidence_paths']['stage_config'])
    for role in ('prior_config', 'prior_status', 'prior_monitor'):
        if role in stage_config:
            sources.tree(stage_config[role])
    sequence_sha = costs.verify_completed_matrix(validated)
    planned = matrix.plan_slots(validated)
    if len(planned) != 60:
        raise ValueError('complete 60-slot plan required')
    plan_path = Path(validated['output_root']) / 'matrix-plan.json'
    actual_plan_sha = sources.pin(plan_path)
    plan = sources.read(plan_path)
    expected_plan = {
        'schema': 'part5-v3-campaign-matrix-plan-v1',
        'manifest_sha256': validated['manifest_sha256'],
        'driver_sha256': validated['driver_sha256'],
        'campaign_id': campaign_id,
        'campaign_runtime_seconds': matrix.CAMPAIGN_SECONDS,
        'slot_count': len(planned),
        'slots': planned,
    }
    _same(plan, expected_plan, 'registered actual matrix plan')
    if (registered['actual_plan_sha256'] is not None
            and actual_plan_sha != registered['actual_plan_sha256']):
        raise ValueError('registered actual matrix plan byte pin required')
    # Pin private reports before recomputation, including their referenced evidence.
    for slot in planned:
        paths = matrix.output_paths(validated, slot)
        for key in ('slot_receipt', 'session_report', 'outer_report', 'clone_report'):
            sources.tree(paths[key])
        session_document = sources.read(paths['session_report'])
        if 'effect_monitor_sha256' in session_document:
            sources.tree(Path(paths['session_report']).parent / 'effect-monitor.json')
        if 'effect_config_sha256' in session_document:
            effect_config_path = Path(paths['session_report']).parent / 'effect-config.json'
            sources.tree(effect_config_path)
            effect_config = sources.read(effect_config_path)
            if Path(effect_config['effect_output']) != Path(paths['effect_output']):
                raise ValueError('effect output must be the registered slot output')
            sources.tree(Path(paths['effect_output']) / 'effect-report.json')
        if 'outer_private' in paths:
            sources.tree(Path(paths['outer_private']) / 'report.json')
    sources.tree(matrix.REPO / 'artifacts/dynark/part5/v3-development-setup-001/setup-manifest.json')
    sequence_path = Path(validated['output_root']) / 'sequence-receipt.json'
    sources.tree(sequence_path)
    sequence = sources.read(sequence_path)
    if sources.pin(sequence_path) != sequence_sha:
        raise ValueError('sequence receipt changed')
    bound = bindings.verify_bundles(projection_dir, receipt_dir)
    for name in ('index.json', 'matrix-plan.json', 'matrix-manifest.json'):
        sources.tree(Path(projection_dir) / name)
    for name in ('index.json', 'sequence-receipt.json'):
        sources.tree(Path(receipt_dir) / name)
    for number in range(1, 61):
        sources.tree(Path(receipt_dir) / 'slot-receipts' / f'slot-{number:04d}.json')
    if (sources.pin(Path(projection_dir) / 'index.json') != bound['projection_index_sha256']
            or sources.pin(Path(receipt_dir) / 'index.json') != bound['receipt_index_sha256']):
        raise ValueError('public bundle index changed after verification')
    if (bound['campaign_id'] != campaign_id
            or bound['matrix_manifest_canonical_sha256'] != validated['manifest_sha256']
            or bound['sequence_receipt_sha256'] != sequence_sha):
        raise ValueError('public bundle differs from private campaign')
    audited = clock.audit(Path(matrix_manifest), sources.read(clock_report).get('tolerance_seconds'))
    if audited.get('passed') is not True:
        raise ValueError('passing recomputed clock audit required')
    _same(sources.read(clock_report), audited, 'clock audit')
    manifest = sources.read(economics_manifest)
    if (Path(economics_manifest) != Path(validated['output_root']) / 'economics-input-manifest.json'
            or manifest != matrix.economics_input_manifest(planned)):
        raise ValueError('registered complete economics input manifest required')
    direct = economics.aggregate(manifest, Path(economics_manifest).absolute().parent)
    direct['input_manifest_sha256'] = sources.pin(economics_manifest)
    _same(sources.read(economics_report), direct, 'economics')
    if (direct.get('grid_complete') is not True or len(direct['sessions']) != 60
            or len(direct['pairs']) != 20
            or any(row['status'] != 'valid' for row in direct['sessions'])
            or any(row['status'] != 'matched' for row in direct['pairs'])):
        raise ValueError('60 valid sessions and 20 matched pairs required')
    reconciled = costs.reconcile(validated, direct)
    reconciled['economics_report_sha256'] = sources.pin(economics_report)
    _same(sources.read(reconciliation_report), reconciled, 'reconciliation')
    summary = total.summarize(reconciled, direct)
    _same(sources.read(total_report), summary, 'total summary')
    if summary.get('matched_pairs') != 20 or summary.get('matrix_grid_complete') is not True:
        raise ValueError('complete total summary required')
    indexed = {}
    for row in direct['sessions']:
        key = (row['repetition'], row['target_count'], row['mode'])
        if key in indexed:
            raise ValueError('duplicate validated session')
        indexed[key] = row
    for repetition in range(1, 5):
        for count in COUNTS:
            pair = economics._pair({'repetition': repetition, 'target_count': count},
                *(indexed[(repetition, count, mode)] for mode in MODES))
            if pair['status'] != 'matched':
                raise ValueError('full three-mode private identity equality required')
    slots = []
    for slot, entry, clock_row in zip(planned, sequence['sequence'], audited['slots']):
        paths = matrix.output_paths(validated, slot)
        receipt = sources.read(paths['slot_receipt'])
        row = indexed[(slot['repetition'], slot['target_count'], slot['mode'])]
        for key in ('sequence', 'repetition', 'target_count', 'mode'):
            if receipt[key] != slot[key] or entry[key] != slot[key] or clock_row[key] != slot[key]:
                raise ValueError('slot sequence/tuple join mismatch')
        if (receipt['slot_identity_sha256'] != slot['identity_sha256']
                or receipt['slot_identity_sha256'] != entry['slot_identity_sha256']
                or sources.pin(paths['slot_receipt']) != entry['slot_receipt_sha256']
                or clock_row['slot_receipt_sha256'] != entry['slot_receipt_sha256']):
            raise ValueError('slot identity/receipt mismatch')
        for name in ('session', 'outer', 'clone'):
            digest = sources.pin(paths[name + '_report'])
            if receipt[name + '_report_sha256'] != digest:
                raise ValueError('slot report byte pin mismatch')
            if name != 'clone' and row[name + '_report_sha256'] != digest:
                raise ValueError('analyzed report join mismatch')
        outer = sources.read(paths['outer_report'])
        if (row['outer_wall_seconds'] != outer['duration_seconds']
                or clock_row['monotonic_duration_seconds'] != outer['duration_seconds']
                or clock_row['outer_report_sha256'] != receipt['outer_report_sha256']):
            raise ValueError('outer timing join mismatch')
        slots.append({**{key: slot[key] for key in ('sequence', 'repetition', 'target_count', 'mode')},
            **{key: receipt[key] for key in ('slot_identity_sha256', 'session_report_sha256',
                                             'outer_report_sha256', 'clone_report_sha256')},
            'slot_receipt_sha256': entry['slot_receipt_sha256'], 'status': 'valid',
            'match_group': (slot['repetition'] - 1) * 5 + COUNTS.index(slot['target_count']) + 1,
            'outer_wall_seconds': _seconds(row['outer_wall_seconds']),
            'clone_preparation_seconds': _seconds(receipt['clone_preparation_wall_seconds'])})
    if len(slots) != 60 or len(audited['slots']) != 60 or len(sequence['sequence']) != 60:
        raise ValueError('complete joined slots required')
    shared = costs.shared_steps(validated)
    stage_config = sources.read(validated['evidence_paths']['stage_config'])
    shared_public = {key: _seconds(shared[key], True) for key in ('prepare_seconds', 'stage_seconds')}
    for name in ('status', 'monitor'):
        shared_public['prepare_' + name + '_sha256'] = sources.pin(stage_config['prior_' + name])
    for name in ('status', 'monitor', 'config'):
        shared_public['stage_' + name + '_sha256'] = sources.pin(validated['evidence_paths']['stage_' + name])
    shared_public['transitions'] = [
        {'target_count': count, 'seconds': _seconds(shared['transition_seconds'][count], True),
         **{name + '_sha256': sources.pin(validated['transitions'][str(count)][name])
            for name in ('config', 'status', 'monitor')}} for count in COUNTS[1:]]
    one_time = costs.one_time_costs(validated)
    setup_path = matrix.REPO / 'artifacts/dynark/part5/v3-development-setup-001/setup-manifest.json'
    one_time_public = {key: _seconds(one_time[key], True) for key in
                       ('development_setup_seconds', 'cohort_preparation_seconds')}
    one_time_public.update(setup_manifest_sha256=sources.pin(setup_path),
        cohort_receipt_sha256=sources.pin(validated['evidence_paths']['cohort_receipt']), charged_per_request=False)
    # Rebuild every pair from the projected scalars, then rerun all summaries/crossings.
    common = costs.by_count_seconds(shared_public['prepare_seconds'], shared_public['stage_seconds'],
                                   {row['target_count']: row['seconds'] for row in shared_public['transitions']})
    projected_pairs = []
    for pair in direct['pairs']:
        modes = {row['mode']: row for row in slots if row['repetition'] == pair['repetition']
                 and row['target_count'] == pair['target_count']}
        projected_pairs.append({**pair, 'full_session_wall_seconds': modes['full']['outer_wall_seconds'],
                               'anchor_session_wall_seconds': modes['anchor']['outer_wall_seconds']})
    clones = {(row['target_count'], row['repetition'], row['mode']): row['clone_preparation_seconds'] for row in slots}
    projected_costs = {**reconciled, 'pairs': costs.derive(projected_pairs, common, clones)}
    _same(total.summarize(projected_costs, {**direct, 'pairs': projected_pairs}), summary,
          'projected total arithmetic')
    hashes = {key: bound[key] for key in ('projection_index_sha256', 'receipt_index_sha256')}
    hashes.update(sequence_receipt_sha256=sequence_sha, matrix_manifest_canonical_sha256=validated['manifest_sha256'])
    for key, path in (('clock_audit_report', clock_report), ('economics_input_manifest', economics_manifest),
                      ('economics_report', economics_report), ('reconciliation_report', reconciliation_report),
                      ('total_summary_report', total_report), ('exporter_source', __file__),
                      ('economics_analyzer_source', economics.__file__), ('reconciler_source', costs.__file__),
                      ('total_summarizer_source', total.__file__)):
        hashes[key + '_sha256'] = sources.pin(path)
    capsule = {'schema': SCHEMA, 'campaign_id': campaign_id, 'training_only': True,
        'matrix_grid_complete': True, 'source_hashes': hashes, 'slots': slots,
        'shared': shared_public, 'one_time': one_time_public,
        'claims': {'directly_timed_whole_application_session': False,
                   'whole_application_benefit_established': False, 'complete_tree_cpu_qualified': False,
                   'interpolation_or_extrapolation_used': False,
                   'identity_join_scope': 'publisher-validated equality; underlying private reports omitted'}}
    raw = (json.dumps(capsule, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    sources.recheck()
    receipts._write_new(output, raw)
    return capsule


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ('matrix-manifest', 'economics-manifest', 'economics-report',
                 'reconciliation-report', 'total-report', 'clock-report',
                 'projection-dir', 'receipt-dir', 'output'):
        parser.add_argument('--' + flag, type=Path, required=True)
    args = parser.parse_args()
    try:
        export_public_metrics(**vars(args))
    except Exception as error:
        raise SystemExit(f'private metrics export rejected ({type(error).__name__}); no result established') from None
    print('Exported one verified training campaign metrics capsule.')


if __name__ == '__main__':
    main()
