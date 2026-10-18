#!/usr/bin/env python3
"""Bind completed campaign evidence after T011, without running campaign work."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.part5 import analyze_v3_campaign_economics as economics
from tools.part5 import audit_v3_campaign_clock_drift as clock
from tools.part5 import reconcile_v3_campaign_costs as costs
from tools.part5 import run_v3_campaign_matrix as matrix
from tools.part5 import summarize_v3_campaign_total as total

SCHEMA = 'part5-v3-campaign-completion-qualification-v1'
REGISTERED_CAMPAIGN_ID = 'training-011'
REGISTERED_MANIFEST_PATH = ROOT / 'results/dynark/part5/v3-campaign-matrix-training-011.json'
REGISTERED_MANIFEST_RAW_SHA256 = '0b7f6340a34d43e1c1680c1f306a993b36a409e13fc427d24e207df4fa676a96'
REGISTERED_MANIFEST_CANONICAL_SHA256 = REGISTERED_MANIFEST_RAW_SHA256
REGISTERED_OUTPUT_ROOT = ROOT / 'artifacts/dynark/part5/v3-matrix-training-011'
TRAINING_012_ACTUAL_PLAN_SHA256 = 'e1cd1b9eb1c08fed70cd7544b0286af82422eb50a49a63875be267b57907f467'
REGISTERED_CAMPAIGNS = {
    'training-011': {
        'manifest_path': REGISTERED_MANIFEST_PATH,
        'manifest_raw_sha256': REGISTERED_MANIFEST_RAW_SHA256,
        'manifest_canonical_sha256': REGISTERED_MANIFEST_CANONICAL_SHA256,
        'output_root': REGISTERED_OUTPUT_ROOT,
        'actual_plan_sha256': None,
    },
    'training-012': {
        'manifest_path': ROOT / 'results/dynark/part5/v3-campaign-matrix-training-012.json',
        'manifest_raw_sha256': '21612a6451c00b7a46d9abaa3445e5acecec3c14583317884800b49b2614ff53',
        'manifest_canonical_sha256': '21612a6451c00b7a46d9abaa3445e5acecec3c14583317884800b49b2614ff53',
        'output_root': ROOT / 'artifacts/dynark/part5/v3-matrix-training-012',
        'actual_plan_sha256': TRAINING_012_ACTUAL_PLAN_SHA256,
    },
}


def _registered_campaign(manifest_path, raw_sha256):
    for campaign_id, registration in REGISTERED_CAMPAIGNS.items():
        if Path(manifest_path) == registration['manifest_path']:
            if raw_sha256 != registration['manifest_raw_sha256']:
                raise ValueError(f'registered {campaign_id} manifest path and raw digest required')
            return campaign_id, registration
    raise ValueError('registered campaign manifest path and raw digest required')


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate report field')
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError('nonfinite report number')


def _read(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError('absolute nonsymlink source required')
    raw = economics._read_bounded_file(path)
    return json.loads(raw, object_pairs_hook=_unique_object,
                      parse_constant=_reject_constant), hashlib.sha256(raw).hexdigest()


def _output(path):
    path = Path(path)
    if (not path.is_absolute() or path.exists() or path.is_symlink()
            or path.parent.resolve(strict=True) != path.parent):
        raise ValueError('fresh absolute nonsymlink output required')
    return path


def bind(matrix_manifest, clock_report, economics_report, reconciliation_report,
         total_summary, output):
    output = _output(output)
    paths = dict(matrix_manifest=Path(matrix_manifest), clock_report=Path(clock_report),
                 economics_report=Path(economics_report),
                 reconciliation_report=Path(reconciliation_report),
                 total_summary=Path(total_summary))
    loaded = {key: _read(path) for key, path in paths.items()}
    registered_campaign_id, registration = _registered_campaign(
        paths['matrix_manifest'], loaded['matrix_manifest'][1])
    validated = matrix.validate_manifest(paths['matrix_manifest'])
    if (validated['campaign_id'] != registered_campaign_id
            or validated['manifest_sha256'] != registration['manifest_canonical_sha256']
            or validated['output_root'] != registration['output_root']):
        raise ValueError(f'registered {registered_campaign_id} campaign identity required')
    if registration['actual_plan_sha256'] is not None:
        paths['matrix_plan'] = registration['output_root'] / 'matrix-plan.json'
        loaded['matrix_plan'] = _read(paths['matrix_plan'])
        if loaded['matrix_plan'][1] != registration['actual_plan_sha256']:
            raise ValueError(f'registered {registered_campaign_id} matrix plan digest required')
    sequence_sha = costs.verify_completed_matrix(validated)
    planned = matrix.plan_slots(validated)
    if len(planned) != 60:
        raise ValueError('complete 60-slot matrix required')
    paths['sequence_receipt'] = validated['output_root'] / 'sequence-receipt.json'
    paths['economics_input_manifest'] = validated['output_root'] / 'economics-input-manifest.json'
    for key in ('sequence_receipt', 'economics_input_manifest'):
        loaded[key] = _read(paths[key])
    if loaded['sequence_receipt'][1] != sequence_sha:
        raise ValueError('sequence changed')
    if loaded['economics_input_manifest'][0] != matrix.economics_input_manifest(planned):
        raise ValueError('economics inputs differ from completed matrix')
    tolerance = loaded['clock_report'][0].get('tolerance_seconds')
    audited = clock.audit(paths['matrix_manifest'], tolerance)
    if (audited != loaded['clock_report'][0] or audited.get('passed') is not True
            or audited.get('slot_count') != 60):
        raise ValueError('passing current clock audit required')
    recomputed = economics.aggregate(loaded['economics_input_manifest'][0],
                                     paths['economics_input_manifest'].parent)
    recomputed['input_manifest_sha256'] = loaded['economics_input_manifest'][1]
    if recomputed != loaded['economics_report'][0]:
        raise ValueError('economics recomputation mismatch')
    reconciled = costs.reconcile(validated, recomputed)
    reconciled['economics_report_sha256'] = loaded['economics_report'][1]
    if reconciled != loaded['reconciliation_report'][0]:
        raise ValueError('reconciliation recomputation mismatch')
    summarized = total.summarize(reconciled, recomputed)
    if (summarized != loaded['total_summary'][0]
            or summarized.get('matched_pairs') != 20
            or summarized.get('expected_pairs') != 20
            or summarized.get('matrix_grid_complete') is not True):
        raise ValueError('complete 20-pair total recomputation required')
    campaign_id = validated['campaign_id']
    if not isinstance(campaign_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', campaign_id):
        raise ValueError('safe campaign identity required')
    receipt = {
        'schema': SCHEMA, 'qualified': True, 'campaign_id': campaign_id,
        'matrix_manifest_canonical_sha256': validated['manifest_sha256'],
        'source_sha256': {key: digest for key, (_, digest) in loaded.items()},
        'completed_slots': 60, 'matched_pairs': 20,
        'clock_tolerance_seconds': tolerance,
        'scope': 'Completed training matrix; recomputed observed component sums only.',
        'limitations': [
            'Private source reports are required for independent revalidation.',
            'Component sums are not directly timed whole application sessions.',
            'No profitability admission condition; no whole application benefit, deployment, or production readiness established.',
            'Clock agreement does not establish CPU accounting or absence of suspension.',
        ],
    }
    # Repeat the completion gate and raw pins immediately before publication.
    if costs.verify_completed_matrix(validated) != sequence_sha:
        raise ValueError('completed sequence changed')
    if any(_read(paths[key])[1] != digest for key, (_, digest) in loaded.items()):
        raise ValueError('source changed during qualification')
    output = _output(output)
    raw = (json.dumps(receipt, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return receipt


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('invalid qualification arguments')


def main(argv=None):
    try:
        parser = _Parser(description=__doc__)
        for name in ('matrix-manifest', 'clock-report', 'economics-report',
                     'reconciliation-report', 'total-summary', 'output'):
            parser.add_argument('--' + name, required=True, type=Path)
        args = parser.parse_args(argv)
        bind(**vars(args))
    except Exception:
        # Validators and parser errors may contain private paths or argv.
        raise SystemExit('Campaign qualification rejected; no qualification established.') from None
    print('Campaign completion qualification receipt written.')


if __name__ == '__main__':
    main()
