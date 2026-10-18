#!/usr/bin/env python3
"""Export a path-free public projection of registered training matrix inputs (010 or later)."""
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

from tools.part5 import run_v3_campaign_matrix as matrix

MANIFEST_PROJECTION_SCHEMA = 'part5-v3-campaign-public-manifest-v1'
PLAN_PROJECTION_SCHEMA = 'part5-v3-campaign-public-plan-v1'
INDEX_SCHEMA = 'part5-v3-campaign-public-projection-index-v1'
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_PLAN_BYTES = 16 * 1024 * 1024
HEX_SHA256 = re.compile(r'[0-9a-f]{64}')
MANIFEST_FIELDS = frozenset({
    'schema', 'campaign_id', 'campaign_runtime_seconds', 'output_root',
    'limits', 'evidence', 'tools',
})
EVIDENCE_FILE_FIELDS = (
    'freeze', 'cohort_receipt', 'context', 'stage_config', 'stage_report',
    'stage_plan', 'stage_status', 'stage_monitor',
)
EVIDENCE_FIELDS = frozenset({
    *EVIDENCE_FILE_FIELDS, 'cohort_root', 'stage_root',
    'stage_monitor_owner', 'transitions',
})
TRANSITION_FIELDS = frozenset({'config', 'report', 'status', 'monitor', 'root', 'monitor_owner'})
PIN_FIELDS = frozenset({'path', 'sha256'})
PLAN_FIELDS = frozenset({
    'schema', 'manifest_sha256', 'driver_sha256', 'campaign_id',
    'campaign_runtime_seconds', 'slot_count', 'slots',
})
PLAN_SLOT_FIELDS = frozenset({
    'sequence', 'repetition', 'target_count', 'mode', 'registered_order',
    'registered_order_position', 'owner', 'limits', 'identity_sha256',
    'paths', 'clone_argv', 'outer_argv', 'environment',
})
PLAN_PATH_FIELDS = frozenset({
    'slot_root', 'clone_dir', 'clone_ledger', 'clone_report', 'work_root',
    'outer_private', 'outer_report', 'session_report', 'slot_receipt',
    'effect_output', 'control_output',
})
MODES = frozenset(matrix.session.MODES)
COUNTS = frozenset(matrix.session.COUNTS)


def _sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def _sha(value, field):
    if not isinstance(value, str) or HEX_SHA256.fullmatch(value) is None:
        raise ValueError(f'canonical SHA-256 required for {field}')
    return value


def _fields(value, expected, label):
    if type(value) is not dict:
        raise ValueError(f'{label} must be an object')
    unknown = set(value) - expected
    if unknown:
        raise ValueError(f'unknown {label} fields: {", ".join(sorted(map(str, unknown)))}')
    missing = expected - set(value)
    if missing:
        raise ValueError(f'missing {label} fields: {", ".join(sorted(missing))}')


def _pin_sha(pin, label):
    _fields(pin, PIN_FIELDS, f'{label} pin')
    if not isinstance(pin['path'], str) or not pin['path']:
        raise ValueError(f'{label} path required')
    return _sha(pin['sha256'], f'{label} pin')


def _campaign_id(value):
    # Full export additionally validates the explicit registered manifest and
    # every tool's exact path/hash through matrix.validate_manifest.
    match = re.fullmatch(r'training-([0-9]{3,})', value) if isinstance(value, str) else None
    if (match is None or int(match.group(1)) < 10
            or value != f'training-{int(match.group(1)):03d}'):
        raise ValueError('canonical training campaign ID 010 or later required')
    return value


def project_manifest(manifest, canonical_sha256):
    """Keep only campaign semantics and SHA pins; discard all source paths."""
    _fields(manifest, MANIFEST_FIELDS, 'matrix manifest')
    campaign_id = _campaign_id(manifest['campaign_id'])
    if (manifest['schema'] != matrix.SCHEMA
            or manifest['campaign_runtime_seconds'] != matrix.CAMPAIGN_SECONDS):
        raise ValueError('registered training matrix manifest required')
    canonical_sha256 = _sha(canonical_sha256, 'canonical matrix manifest')

    evidence = manifest['evidence']
    _fields(evidence, EVIDENCE_FIELDS, 'matrix evidence')
    if any(not isinstance(evidence[name], str) or not evidence[name]
           for name in ('cohort_root', 'stage_root', 'stage_monitor_owner')):
        raise ValueError('matrix evidence directory roles and stage owner required')
    projected_evidence = {
        name: {'sha256': _pin_sha(evidence[name], f'evidence {name}')}
        for name in EVIDENCE_FILE_FIELDS
    }
    transitions = evidence['transitions']
    expected_counts = {'1', '2', '5', '10'}
    if type(transitions) is not dict or set(transitions) != expected_counts:
        raise ValueError('k=1,2,5,10 transition pins required')
    projected_evidence['transitions'] = {}
    for count in ('1', '2', '5', '10'):
        row = transitions[count]
        _fields(row, TRANSITION_FIELDS, f'k={count} transition')
        if (not isinstance(row['root'], str) or not row['root']
                or not isinstance(row['monitor_owner'], str) or not row['monitor_owner']):
            raise ValueError(f'k={count} transition role and monitor owner required')
        projected_evidence['transitions'][count] = {
            name: {'sha256': _pin_sha(row[name], f'k={count} {name}')}
            for name in ('config', 'report', 'status', 'monitor')
        }

    tool_names = matrix.tool_names_for_campaign(campaign_id)
    tools = manifest['tools']
    if type(tools) is not dict or set(tools) != set(tool_names):
        raise ValueError('exact per-campaign tool pins required')
    tool_pins = {name: {'sha256': _pin_sha(tools[name], f'tool {name}')}
                 for name in tool_names}

    # The driver has already validated the detailed limits. Copy only numeric
    # caps, which are public experiment design data and contain no local paths.
    limits = manifest['limits']
    if type(limits) is not dict or set(limits) != {str(count) for count in COUNTS}:
        raise ValueError('complete registered count limits required')
    projected_limits = {}
    for count in sorted(COUNTS):
        by_mode = limits[str(count)]
        if type(by_mode) is not dict or set(by_mode) != set(MODES):
            raise ValueError(f'complete mode limits required for k={count}')
        projected_limits[str(count)] = {}
        for mode in sorted(MODES):
            cap = by_mode[mode]
            expected_cap_fields = {'runtime_seconds', 'rss_bytes', 'storage_bytes'}
            _fields(cap, expected_cap_fields, f'{mode} k={count} limits')
            if any(type(value) is not int or value <= 0 for value in cap.values()):
                raise ValueError(f'positive integer limits required for {mode} k={count}')
            projected_limits[str(count)][mode] = dict(cap)

    return {
        'schema': MANIFEST_PROJECTION_SCHEMA,
        'source_schema': manifest['schema'],
        'campaign_id': campaign_id,
        'campaign_runtime_seconds': manifest['campaign_runtime_seconds'],
        'matrix_manifest_canonical_sha256': canonical_sha256,
        'limits': projected_limits,
        'evidence': projected_evidence,
        'tool_pins': tool_pins,
    }


def project_plan(plan):
    """Project a validated matrix plan without argv, owners, paths or env."""
    _fields(plan, PLAN_FIELDS, 'matrix plan')
    campaign_id = _campaign_id(plan['campaign_id'])
    if (plan['schema'] != 'part5-v3-campaign-matrix-plan-v1'
            or plan['campaign_runtime_seconds'] != matrix.CAMPAIGN_SECONDS
            or type(plan['slot_count']) is not int or plan['slot_count'] != 60
            or type(plan['slots']) is not list or len(plan['slots']) != 60):
        raise ValueError('complete registered training matrix plan required')
    manifest_sha256 = _sha(plan['manifest_sha256'], 'plan manifest binding')
    driver_sha256 = _sha(plan['driver_sha256'], 'plan driver')
    slots = []
    registered_slots = matrix.slot_specs()
    for expected_sequence, slot in enumerate(plan['slots'], 1):
        _fields(slot, PLAN_SLOT_FIELDS, 'matrix plan slot')
        registered = registered_slots[expected_sequence - 1]
        sequence = slot['sequence']
        repetition = slot['repetition']
        target_count = slot['target_count']
        mode = slot['mode']
        order = slot['registered_order']
        position = slot['registered_order_position']
        if (type(sequence) is not int or sequence != expected_sequence
                or type(repetition) is not int or repetition not in (1, 2, 3, 4)
                or type(target_count) is not int or target_count not in COUNTS
                or not isinstance(mode, str) or mode not in MODES or type(order) is not list
                or len(order) != len(MODES)
                or any(not isinstance(item, str) or item not in MODES for item in order)
                or type(position) is not int or position not in (1, 2, 3)):
            raise ValueError('invalid registered matrix slot identity')
        if any(slot[name] != registered[name] for name in (
                'sequence', 'repetition', 'target_count', 'mode',
                'registered_order', 'registered_order_position')):
            raise ValueError('matrix plan slot order differs from registration')
        if not isinstance(slot['owner'], str) or not slot['owner']:
            raise ValueError('slot owner required by validated plan')
        if type(slot['limits']) is not dict or set(slot['limits']) != {
                'runtime_seconds', 'rss_bytes', 'storage_bytes'}:
            raise ValueError('slot limits required by validated plan')
        if any(type(value) is not int or value <= 0 for value in slot['limits'].values()):
            raise ValueError('positive integer slot limits required')
        _sha(slot['identity_sha256'], 'slot identity')
        paths = slot['paths']
        if type(paths) is not dict or set(paths) != PLAN_PATH_FIELDS \
                or any(not isinstance(value, str) or not value for value in paths.values()):
            raise ValueError('complete private slot path map required')
        for field in ('clone_argv', 'outer_argv'):
            if type(slot[field]) is not list or any(not isinstance(value, str) for value in slot[field]):
                raise ValueError(f'{field} must be an argv list')
        if type(slot['environment']) is not dict or any(
                not isinstance(k, str) or not isinstance(v, str)
                for k, v in slot['environment'].items()):
            raise ValueError('environment object required by validated plan')
        slots.append({
            'sequence': sequence,
            'repetition': repetition,
            'target_count': target_count,
            'mode': mode,
            'registered_order': list(order),
            'registered_order_position': position,
            'slot_identity_sha256': slot['identity_sha256'],
            'limits': dict(slot['limits']),
        })
    return {
        'schema': PLAN_PROJECTION_SCHEMA,
        'campaign_id': campaign_id,
        'matrix_manifest_canonical_sha256': manifest_sha256,
        'driver_sha256': driver_sha256,
        'campaign_runtime_seconds': plan['campaign_runtime_seconds'],
        'slot_count': 60,
        'slots': slots,
    }


def _read_private_input(path, cap, label):
    path = Path(path).absolute()
    if path.resolve(strict=True) != path:
        raise ValueError(f'canonical {label} path required')
    actual_sha256 = matrix.sha256(path, cap=cap)
    raw = path.read_bytes()
    if len(raw) > cap or _sha256(raw) != actual_sha256:
        raise ValueError(f'{label} changed while being read')
    return path, raw, actual_sha256


def _decode_json(raw, label):
    def no_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f'duplicate JSON key in {label}')
            value[key] = item
        return value

    return json.loads(raw, object_pairs_hook=no_duplicates,
                      parse_constant=lambda value: (_ for _ in ()).throw(
                          ValueError(f'non-finite JSON value in {label}: {value}')))


def _canonical_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def _plan_document(validated):
    return {
        'schema': 'part5-v3-campaign-matrix-plan-v1',
        'manifest_sha256': validated['manifest_sha256'],
        'driver_sha256': validated['driver_sha256'],
        'campaign_id': validated['campaign_id'],
        'campaign_runtime_seconds': matrix.CAMPAIGN_SECONDS,
        'slot_count': 60,
        'slots': matrix.plan_slots(validated),
    }


def _fresh_output_directory(path):
    path = Path(path)
    if not path.name or path.name in ('.', '..') or path.exists() or path.is_symlink():
        raise FileExistsError('fresh public matrix projection directory required')
    parent = path.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError('public projection parent must be a directory')
    output = parent / path.name
    if output.exists() or output.is_symlink():
        raise FileExistsError('fresh public matrix projection directory required')
    return output


def _write_new(path, raw):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o644)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def export_public_projection(matrix_manifest, matrix_plan, output_dir):
    output = _fresh_output_directory(output_dir)
    manifest_path = Path(matrix_manifest).absolute()
    validated = matrix.validate_manifest(manifest_path)
    manifest_path, manifest_raw, manifest_raw_sha256 = _read_private_input(
        manifest_path, MAX_MANIFEST_BYTES, 'matrix manifest')
    manifest = _decode_json(manifest_raw, 'matrix manifest')
    if manifest != validated['manifest']:
        raise ValueError('matrix manifest changed after validation')
    manifest_canonical_sha256 = _sha256(matrix.canonical_json(manifest))
    if manifest_canonical_sha256 != validated['manifest_sha256']:
        raise ValueError('matrix manifest canonical identity changed')

    plan_path, plan_raw, plan_raw_sha256 = _read_private_input(
        matrix_plan, MAX_PLAN_BYTES, 'matrix plan')
    plan = _decode_json(plan_raw, 'matrix plan')
    expected_plan = _plan_document(validated)
    if plan != expected_plan:
        raise ValueError('matrix plan does not match validated manifest')
    if plan['manifest_sha256'] != manifest_canonical_sha256:
        raise ValueError('plan does not bind the canonical matrix manifest')

    public_manifest = project_manifest(manifest, manifest_canonical_sha256)
    public_plan = project_plan(plan)
    manifest_public_raw = _canonical_bytes(public_manifest)
    plan_public_raw = _canonical_bytes(public_plan)
    index = {
        'schema': INDEX_SCHEMA,
        'campaign_id': public_manifest['campaign_id'],
        'source_inputs': {
            'matrix_manifest': {
                'sha256': manifest_raw_sha256,
                'canonical_sha256': manifest_canonical_sha256,
            },
            'matrix_plan': {
                'sha256': plan_raw_sha256,
                'manifest_canonical_sha256': manifest_canonical_sha256,
            },
        },
        'public_files': {
            'matrix_manifest': {
                'path': 'matrix-manifest.json',
                'sha256': _sha256(manifest_public_raw),
            },
            'matrix_plan': {
                'path': 'matrix-plan.json',
                'sha256': _sha256(plan_public_raw),
            },
        },
    }
    index_raw = json.dumps(index, sort_keys=True, indent=2).encode() + b'\n'

    output.mkdir(mode=0o755)
    _write_new(output / 'matrix-manifest.json', manifest_public_raw)
    _write_new(output / 'matrix-plan.json', plan_public_raw)
    _write_new(output / 'index.json', index_raw)
    return index


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix-manifest', required=True, type=Path)
    parser.add_argument('--matrix-plan', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    index = export_public_projection(args.matrix_manifest, args.matrix_plan, args.output_dir)
    print(json.dumps({'campaign_id': index['campaign_id'],
                      'public_file_count': len(index['public_files'])}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
