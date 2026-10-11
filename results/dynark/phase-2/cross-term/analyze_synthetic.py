"""Reproduce the registered T4 public synthetic evidence analysis; no source execution."""
import csv
import datetime
import hashlib
import json
import pathlib
import statistics
from collections import Counter

ROOT = pathlib.Path('/Users/anishnarang/Zk-refresh')
RESULTS = ROOT / 'results/dynark/phase-2/cross-term'
ARTIFACTS = ROOT / 'artifacts/dynark/phase-2/cross-term'


def read_json(path):
    return json.loads(path.read_text())


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        while b := f.read(1 << 20):
            h.update(b)
    return h.hexdigest()


def write_json(name, value):
    p = RESULTS / name
    p.write_text(json.dumps(value, indent=2) + '\n')
    p.chmod(0o600)


def quantile(values, q):
    values = sorted(values)
    if not values:
        return None
    position = (len(values) - 1) * q
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    return values[lower] + (values[upper] - values[lower]) * (position - lower)


def ratio_stats(rows, denominator, numerator):
    ratios = [r[numerator] / r[denominator] for r in rows if r[denominator]]
    return {
        'sample_count': len(rows),
        'defined_ratio_count': len(ratios),
        'undefined_zero_denominator_count': len(rows) - len(ratios),
        'median_denominator_ns': statistics.median(r[denominator] for r in rows),
        'median_numerator_ns': statistics.median(r[numerator] for r in rows),
        'median_paired_ratio': statistics.median(ratios) if ratios else None,
        'p10_paired_ratio': quantile(ratios, .1),
        'p90_paired_ratio': quantile(ratios, .9),
        'numerator_faster_samples': sum(r[numerator] < r[denominator] for r in rows),
        'ties': sum(r[numerator] == r[denominator] for r in rows),
    }


freeze = read_json(RESULTS / 'source-005.json')
drift = []
for entry in freeze['files']:
    p = ROOT / freeze['snapshot'] / entry['path']
    if p.stat().st_size != entry['bytes'] or digest(p) != entry['sha256']:
        drift.append(str(p))
for relative in freeze['overlays']:
    entry = next(e for e in freeze['files'] if e['path'] == relative)
    if digest(ROOT / relative) != entry['sha256']:
        drift.append(relative)
assert not drift, drift

proposal = read_json(RESULTS / 'timing-invocation-proposal.json')
runs = []
logs = []
for command in proposal['commands']:
    name = command['name']
    output = ARTIFACTS / name
    report = read_json(output / 'report.json')
    assert report['passed'] and report['exit_code'] == 0 and report['stop_reason'] is None
    assert report['cleanup_remaining_owned_processes'] == 0 and not report['cleanup_status_unknown']
    assert report['sampled_peak_owned_tree_rss_bytes'] <= report['limits']['owned_tree_rss_bytes']
    assert report['sampled_peak_storage_growth_bytes'] <= report['limits']['storage_growth_bytes']
    assert report['duration_seconds'] <= report['limits']['runtime_seconds']
    binary = pathlib.Path(command['argv'][command['argv'].index('CARGO_BUILD_JOBS=2') + 1])
    assert digest(binary) == command['binary_sha256']
    assert binary.stat().st_mode & 0o777 == 0o700
    for n, expected in command['weights_sha256'].items():
        table = ARTIFACTS / 'public-weights-001' / f'weights-{n}.fr'
        assert digest(table) == expected and table.stat().st_size == int(n) * 32
        assert table.stat().st_mode & 0o777 == 0o600
    records = [json.loads(line) for line in (output / 'stdout.log').read_text().splitlines()]
    assert all(r['equal'] for r in records if 'equal' in r)
    assert records[-1]['event'] == 'complete'
    assert records[-1]['pairs'] == command['expected_pair_visits']
    loaded = [r for r in records if r['event'] == 'public_table_loaded']
    assert len(loaded) == 2
    assert all(r['sha256'] == command['weights_sha256'][str(r['n'])] for r in loaded)
    assert records[-1]['group_calls'] <= proposal['group_hard_cap']
    runs.append({
        'name': name,
        'argv': command['argv'],
        'binary_sha256': command['binary_sha256'],
        'weights_sha256': command['weights_sha256'],
        'runner': {k: report[k] for k in ['passed', 'duration_seconds', 'sample_count',
            'sampled_peak_owned_tree_rss_bytes', 'sampled_peak_storage_growth_bytes',
            'exit_code', 'stop_reason', 'cleanup_remaining_owned_processes', 'cleanup_status_unknown']},
        'stdout_sha256': digest(output / 'stdout.log'),
        'stderr_sha256': digest(output / 'stderr.log'),
        'runner_report_sha256': digest(output / 'report.json'),
        'event_counts': dict(Counter(r['event'] for r in records)),
        'complete': records[-1],
        'table_loads': loaded,
    })
    logs.append(records)

timing, diagnostic = logs
inputs = [r for r in timing if r['event'] == 'public_input']
assert len(inputs) == 18
assert [r['case'] for r in diagnostic if r['event'] == 'public_input'] == [r['case'] for r in inputs]
field = [r for r in timing if r['event'] == 'field_pair']
groups = [r for r in timing if r['event'] == 'synthetic_group_pair']
assert len(field) == len(groups) == 474
assert Counter(r['kind'] for r in field) == Counter(measured=428, warmup=28, equality=18)
assert sum(r['pairs'] for r in field) == 240428847
assert sum(r['a'] * r['b'] for r in inputs) == 8551759
assert sum(r['complete']['pairs'] for r in runs) == proposal['plan_inclusive_pairs'] == 248980606
assert sum(r['complete']['group_calls'] for r in runs) == 657404 <= proposal['group_hard_cap']
for records in logs:
    assert sum(r['construction_calls'] for r in records if r['event'] == 'synthetic_basis') == 20094
    group_work = sum(r['accepted_calls'] + r['grouped_calls'] for r in records if r['event'] == 'synthetic_group_pair')
    assert group_work + 20094 == records[-1]['group_calls']

cases = []
raw_measured = []
diagnostic_cases = []
for shape in inputs:
    name = shape['case']
    f = [r for r in field if r['case'] == name and r['kind'] == 'measured']
    g = [r for r in groups if r['case'] == name and r['kind'] == 'measured']
    primary = not name.startswith('intermediate')
    expected = 30 if primary else 2
    assert len(f) == len(g) == expected
    assert [r['sample'] for r in f] == list(range(expected))
    assert Counter(r['order'] for r in f) == Counter(accepted_fast=expected // 2, fast_accepted=expected // 2)
    assert Counter(r['order'] for r in g) == Counter(accepted_grouped=expected // 2, grouped_accepted=expected // 2)
    assert all(r['pairs'] == shape['a'] * shape['b'] <= proposal['per_case_pair_cap'] for r in f)
    required_fft = 0 if shape['union'] <= 1 else 1 << shape['union'].bit_length()
    assert all(r['fft_max'] <= required_fft for r in f)
    basis = next(r for r in timing if r['event'] == 'synthetic_basis' and r['case'] == name)
    c = {'case': name, 'primary_30_pairs': primary, 'shape': shape,
         'field': ratio_stats(f, 'accepted_weighted_ns', 'fast_whole_ns'),
         'field_order_strata': {order: ratio_stats([r for r in f if r['order'] == order],
             'accepted_weighted_ns', 'fast_whole_ns') for order in ['accepted_fast', 'fast_accepted']},
         'group': ratio_stats(g, 'accepted_separate_ns', 'grouped_ns'),
         'group_order_strata': {order: ratio_stats([r for r in g if r['order'] == order],
             'accepted_separate_ns', 'grouped_ns') for order in ['accepted_grouped', 'grouped_accepted']},
         'basis': basis,
         'field_counters': {k: f[0][k] for k in ['pairs', 'fft_max', 'fft_elements',
             'preflight_bytes', 'accepted_returned_bytes', 'fast_returned_bytes']},
         'group_calls_per_pair': {'accepted': g[0]['accepted_calls'], 'grouped': g[0]['grouped_calls']}}
    cases.append(c)
    for fr, gr in zip(f, g):
        assert fr['sample'] == gr['sample']
        raw_measured.append({'case': name, 'primary_30_pairs': primary, 'n': shape['n'],
            'a': shape['a'], 'b': shape['b'], 'union': shape['union'], 'overlap': shape['overlap'],
            'sample': fr['sample'], 'field_order': fr['order'], 'accepted_weighted_ns': fr['accepted_weighted_ns'],
            'fast_whole_ns': fr['fast_whole_ns'], 'paired_fast_over_accepted':
                fr['fast_whole_ns'] / fr['accepted_weighted_ns'] if fr['accepted_weighted_ns'] else None,
            'group_order': gr['order'], 'accepted_group_ns': gr['accepted_separate_ns'],
            'grouped_ns': gr['grouped_ns'], 'paired_grouped_over_accepted':
                gr['grouped_ns'] / gr['accepted_separate_ns'] if gr['accepted_separate_ns'] else None,
            'accepted_group_calls': gr['accepted_calls'], 'grouped_calls': gr['grouped_calls']})
    whole = next(r for r in diagnostic if r['event'] == 'diagnostic_whole' and r['case'] == name)
    phases = [r for r in diagnostic if r['event'] == 'diagnostic_phase' and r['case'] == name]
    expected_phases = ['Preflight', 'Normalize', 'Preflight', 'Nodes']
    if shape['union'] > 1:
        expected_phases += ['ProductTree', 'Numerators', 'Derivatives', 'RemainderEvaluation', 'FinitePart']
    expected_phases += ['Collect']
    assert [r['phase'] for r in phases] == expected_phases
    assert sum(r['ns'] for r in phases) == whole['phase_sum_ns']
    assert whole['phase_sum_ns'] + whole['residual_ns'] == whole['fast_observed_ns']
    assert whole['fast_allocation']['peak_additional'] <= c['field_counters']['preflight_bytes']
    fast_net = whole['fast_allocation']['end_live'] - whole['fast_allocation']['start_live']
    extra_retained = fast_net - c['field_counters']['fast_returned_bytes']
    assert extra_retained >= 0
    assert whole['accepted_allocation']['end_live'] - whole['accepted_allocation']['start_live'] == c['field_counters']['accepted_returned_bytes']
    diagnostic_cases.append({'case': name, 'whole': whole, 'ordered_complete_phases': phases,
        'reported_fast_coefficient_vector_bytes': c['field_counters']['fast_returned_bytes'],
        'allocator_net_bytes': fast_net,
        'unclassified_allocator_net_beyond_returned_coefficients_bytes': extra_retained,
        'input_allocation': next(r for r in diagnostic if r['event'] == 'diagnostic_input_allocation' and r['case'] == name),
        'basis_allocation': next(r for r in diagnostic if r['event'] == 'diagnostic_basis_allocation' and r['case'] == name),
        'group_allocation': next(r for r in diagnostic if r['event'] == 'diagnostic_synthetic_group_allocation' and r['case'] == name)})

assert len(raw_measured) == 428
csv_path = RESULTS / 'synthetic-measured-pairs.csv'
with csv_path.open('w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=list(raw_measured[0]))
    writer.writeheader()
    writer.writerows(raw_measured)
csv_path.chmod(0o600)
write_json('synthetic-diagnostic-analysis.json', diagnostic_cases)
write_json('synthetic-timing-summary.json', {
    'schema': 1,
    'analysis_checked_at_utc': datetime.datetime.now(datetime.UTC).isoformat(),
    'source_manifest': 'source-005.json',
    'baseline_commit': freeze['baseline_commit'],
    'all_39_snapshot_files_and_4_live_owned_overlay_hashes_match': True,
    'drift': drift,
    'runs': runs,
    'inclusive_pair_visits': 248980606,
    'inclusive_group_calls': 657404,
    'conservative_preregistered_group_calls': 657438,
    'basis_construction_calls_per_process': 20094,
    'measured_field_and_group_pairs': 428,
    'primary_cases_and_samples': [14, 30],
    'exploratory_cases_and_samples': [4, 2],
    'quantiles': 'linear interpolation on sorted ratios at (n-1)*q; descriptive only',
    'zero_denominator_ratios': 'undefined null/empty CSV; raw zero timings retained; no data dropped',
    'allocator_retention_caveat': 'tiny2 first FFT-bearing case retains 34328 additional process allocator bytes beyond its 160 coefficient vector bytes, appearing in ProductTree. Possible lazy runtime/library initialization, not isolated by this run. Preserved as unclassified process retention.',
    'measured_pairs_csv': {'path': 'synthetic-measured-pairs.csv', 'sha256': digest(csv_path)},
    'diagnostic_analysis': 'synthetic-diagnostic-analysis.json',
    'cases': cases,
    'decision_proposal': 'Retain accepted production direct Quadratic. No reliable crossover; no selector, CrossConfig integration, held-out timing or extra run authorized.',
    'parent_disposition': 'Parent agreed to retain existing production direct Quadratic; DynamicConfig/schema frozen at accepted04b01b0. Final evidence review remains with parent.',
    'scope': 'Public synthetic one seed/index layout; near/middle/far only aggregate size matched. Credential support and total-session gates remain open.',
})
print(json.dumps({'validated': True, 'inclusive_pairs': 248980606, 'inclusive_group_calls': 657404,
    'measured_rows': len(raw_measured), 'snapshot_files': len(freeze['files']), 'drift': drift}))
