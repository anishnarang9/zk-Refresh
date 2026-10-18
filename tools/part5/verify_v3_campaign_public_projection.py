#!/usr/bin/env python3
"""Verify a path-free public projection of campaign matrix inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat


INDEX_SCHEMA = 'part5-v3-campaign-public-projection-index-v1'
MANIFEST_SCHEMA = 'part5-v3-campaign-public-manifest-v1'
PLAN_SCHEMA = 'part5-v3-campaign-public-plan-v1'
SOURCE_MANIFEST_SCHEMA = 'part5-v3-campaign-matrix-input-v1'
SCOPE = ('public projection only; raw private manifest and session/effect reports '
         'not independently verified')
COUNTS = (0, 1, 2, 5, 10)
MODES = ('full', 'anchor', 'coalesced-full')
ORDERS = (
    ('full', 'anchor', 'coalesced-full'),
    ('anchor', 'coalesced-full', 'full'),
    ('full', 'coalesced-full', 'anchor'),
    ('coalesced-full', 'anchor', 'full'),
)
CAMPAIGN_SECONDS = 129600
MAX_RSS_BYTES = 4 * 1024**3
MAX_STORAGE_BYTES = 512 * 1024**2
TRAINING_012_ANCHOR_K10_MAX_STORAGE_BYTES = 1024 * 1024**2
HEX_SHA256 = re.compile(r'[0-9a-f]{64}')
CAMPAIGN_ID = re.compile(r'training-([0-9]{3,})')

# The matrix driver requires this exact set for every registered campaign 010+.
TOOL_PINS_010_PLUS = frozenset({
    'python', 'proof_binary', 'adapter_binary', 'exporter', 'node',
    'old_packet', 'effect_runner', 'session_script', 'bounded_runner',
    'effect_config', 'effect_supervisor', 'clone_r0', 'clone_final',
    'effect_execute',
})

INDEX_FIELDS = {
    'schema', 'campaign_id', 'source_inputs', 'public_files',
}
SOURCE_INPUTS_FIELDS = {'matrix_manifest', 'matrix_plan'}
SOURCE_MANIFEST_FIELDS = {'sha256', 'canonical_sha256'}
SOURCE_PLAN_FIELDS = {'sha256', 'manifest_canonical_sha256'}
PUBLIC_FILES_FIELDS = {'matrix_manifest', 'matrix_plan'}
PUBLIC_FILE_FIELDS = {'path', 'sha256'}
MANIFEST_FIELDS = {
    'schema', 'source_schema', 'campaign_id', 'campaign_runtime_seconds',
    'matrix_manifest_canonical_sha256', 'limits', 'evidence', 'tool_pins',
}
EVIDENCE_FILE_ROLES = (
    'freeze', 'cohort_receipt', 'context', 'stage_config', 'stage_report',
    'stage_plan', 'stage_status', 'stage_monitor',
)
EVIDENCE_FIELDS = set(EVIDENCE_FILE_ROLES) | {'transitions'}
TRANSITION_COUNTS = ('1', '2', '5', '10')
TRANSITION_FIELDS = {'config', 'report', 'status', 'monitor'}
HASH_REF_FIELDS = {'sha256'}
LIMIT_FIELDS = {'runtime_seconds', 'rss_bytes', 'storage_bytes'}
PLAN_FIELDS = {
    'schema', 'campaign_id', 'matrix_manifest_canonical_sha256',
    'driver_sha256', 'campaign_runtime_seconds', 'slot_count', 'slots',
}
PLAN_SLOT_FIELDS = {
    'sequence', 'repetition', 'target_count', 'mode', 'registered_order',
    'registered_order_position', 'slot_identity_sha256', 'limits',
}

MAX_INDEX_BYTES = 128 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_PLAN_BYTES = 16 * 1024 * 1024


def _sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def _require_fields(value, expected, description):
    if type(value) is not dict:
        raise ValueError(f'{description} must be an object')
    if set(value) - expected:
        raise ValueError(f'unknown {description} fields')
    if expected - set(value):
        raise ValueError(f'missing {description} fields')


def _require_sha(value, description):
    if type(value) is not str or HEX_SHA256.fullmatch(value) is None:
        raise ValueError(f'{description} must be a lowercase SHA-256')
    return value


def _require_campaign_id(value):
    match = CAMPAIGN_ID.fullmatch(value) if type(value) is str else None
    if match is None or int(match.group(1)) < 10:
        raise ValueError('canonical training campaign ID 010 or later required')
    if value != f'training-{int(match.group(1)):03d}':
        raise ValueError('canonical training campaign ID 010 or later required')
    return value


def _json_object(raw, description):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON object key')
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode('utf-8'), object_pairs_hook=unique_object,
            parse_constant=lambda item: (_ for _ in ()).throw(
                ValueError(f'non-finite JSON value: {item}')))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f'{description} must be valid UTF-8 JSON') from error
    if type(value) is not dict:
        raise ValueError(f'{description} must be an object')
    return value


def _read_regular(path, cap, description):
    flags = os.O_RDONLY
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise ValueError(f'{description} must be a regular non-symlink file') from error
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > cap:
            raise ValueError(f'{description} must be a bounded regular file')
        chunks = []
        remaining = cap + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b''.join(chunks)
        after = os.fstat(fd)
        if (len(raw) > cap or len(raw) != before.st_size
                or before.st_dev != after.st_dev or before.st_ino != after.st_ino
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns):
            raise ValueError(f'{description} changed or exceeded its size cap')
        return raw
    finally:
        os.close(fd)


def _check_inventory(root):
    try:
        root_info = root.lstat()
    except OSError as error:
        raise ValueError('projection directory is unavailable') from error
    if not stat.S_ISDIR(root_info.st_mode) or root.resolve(strict=True) != root:
        raise ValueError('projection root must be a real directory, not a symlink')
    expected = {'index.json', 'matrix-manifest.json', 'matrix-plan.json'}
    if {entry.name for entry in root.iterdir()} != expected:
        raise ValueError('unexpected projection entries')
    for name in expected:
        try:
            info = (root / name).lstat()
        except OSError as error:
            raise ValueError('projection file is unavailable') from error
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('projection files must be regular non-symlink files')


def _canonical_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def _check_index(index):
    _require_fields(index, INDEX_FIELDS, 'index')
    if index.get('schema') != INDEX_SCHEMA:
        raise ValueError('unsupported public projection index schema')
    campaign_id = _require_campaign_id(index.get('campaign_id'))

    source = index.get('source_inputs')
    _require_fields(source, SOURCE_INPUTS_FIELDS, 'source input map')
    _require_fields(source['matrix_manifest'], SOURCE_MANIFEST_FIELDS,
                    'source manifest identity')
    _require_fields(source['matrix_plan'], SOURCE_PLAN_FIELDS,
                    'source plan identity')
    _require_sha(source['matrix_manifest']['sha256'], 'raw source manifest digest')
    manifest_sha = _require_sha(
        source['matrix_manifest']['canonical_sha256'],
        'canonical source manifest digest')
    _require_sha(source['matrix_plan']['sha256'], 'raw source plan digest')
    if _require_sha(source['matrix_plan']['manifest_canonical_sha256'],
                    'plan manifest binding') != manifest_sha:
        raise ValueError('canonical manifest digest differs in index source pins')

    public_files = index.get('public_files')
    _require_fields(public_files, PUBLIC_FILES_FIELDS, 'public file map')
    for role, expected_path in (
            ('matrix_manifest', 'matrix-manifest.json'),
            ('matrix_plan', 'matrix-plan.json')):
        reference = public_files[role]
        _require_fields(reference, PUBLIC_FILE_FIELDS, f'{role} public reference')
        if reference.get('path') != expected_path:
            raise ValueError(f'{role} public path is not the registered relative path')
        _require_sha(reference.get('sha256'), f'{role} public byte digest')
    return campaign_id, manifest_sha


def _check_limits(limits, campaign_id):
    expected_counts = {str(count) for count in COUNTS}
    _require_fields(limits, expected_counts, 'manifest limits')
    for count in COUNTS:
        by_mode = limits[str(count)]
        _require_fields(by_mode, set(MODES), f'k={count} mode limits')
        for mode in MODES:
            cap = by_mode[mode]
            _require_fields(cap, LIMIT_FIELDS, f'{mode} k={count} limits')
            runtime = cap['runtime_seconds']
            rss = cap['rss_bytes']
            storage = cap['storage_bytes']
            storage_limit = MAX_STORAGE_BYTES
            if campaign_id == 'training-012' and count == 10 and mode == 'anchor':
                storage_limit = TRAINING_012_ANCHOR_K10_MAX_STORAGE_BYTES
            if (type(runtime) is not int or not 1 <= runtime <= CAMPAIGN_SECONDS
                    or type(rss) is not int or not 1 <= rss <= MAX_RSS_BYTES
                    or type(storage) is not int or not 1 <= storage <= storage_limit):
                raise ValueError(f'limits exceed registered bounds for {mode} k={count}')
            if count == 1 and mode == 'anchor' and runtime < 2400:
                raise ValueError('Anchor k=1 runtime is below its registered limit')


def _check_public_manifest(manifest, campaign_id, manifest_sha):
    _require_fields(manifest, MANIFEST_FIELDS, 'public manifest')
    if (manifest.get('schema') != MANIFEST_SCHEMA
            or manifest.get('source_schema') != SOURCE_MANIFEST_SCHEMA):
        raise ValueError('unsupported public manifest schema')
    if manifest.get('campaign_id') != campaign_id:
        raise ValueError('campaign id differs between index and public manifest')
    if (type(manifest.get('campaign_runtime_seconds')) is not int
            or manifest['campaign_runtime_seconds'] != CAMPAIGN_SECONDS):
        raise ValueError('registered campaign runtime required')
    if _require_sha(manifest.get('matrix_manifest_canonical_sha256'),
                    'public manifest canonical digest') != manifest_sha:
        raise ValueError('canonical manifest digest differs in public manifest')

    _check_limits(manifest.get('limits'), campaign_id)

    evidence = manifest.get('evidence')
    _require_fields(evidence, EVIDENCE_FIELDS, 'public evidence')
    for role in EVIDENCE_FILE_ROLES:
        _require_fields(evidence[role], HASH_REF_FIELDS, f'{role} evidence reference')
        _require_sha(evidence[role]['sha256'], f'{role} evidence hash')
    transitions = evidence['transitions']
    _require_fields(transitions, set(TRANSITION_COUNTS), 'public transitions')
    for count in TRANSITION_COUNTS:
        row = transitions[count]
        _require_fields(row, TRANSITION_FIELDS, f'k={count} public transition')
        for role in TRANSITION_FIELDS:
            _require_fields(row[role], HASH_REF_FIELDS,
                            f'k={count} {role} transition reference')
            _require_sha(row[role]['sha256'], f'k={count} {role} transition hash')

    tool_pins = manifest.get('tool_pins')
    _require_fields(tool_pins, TOOL_PINS_010_PLUS, 'tool pin allowlist')
    for name, pin in tool_pins.items():
        _require_fields(pin, HASH_REF_FIELDS, f'{name} tool pin')
        _require_sha(pin['sha256'], f'{name} tool hash')


def _registered_slots():
    result = []
    sequence = 0
    for repetition, order in enumerate(ORDERS, 1):
        for count in COUNTS:
            for position, mode in enumerate(order, 1):
                sequence += 1
                result.append({
                    'sequence': sequence,
                    'repetition': repetition,
                    'target_count': count,
                    'mode': mode,
                    'registered_order': list(order),
                    'registered_order_position': position,
                })
    return result


def _check_plan(plan, campaign_id, manifest_sha, manifest_limits):
    _require_fields(plan, PLAN_FIELDS, 'public plan')
    if plan.get('schema') != PLAN_SCHEMA:
        raise ValueError('unsupported public plan schema')
    if plan.get('campaign_id') != campaign_id:
        raise ValueError('campaign id differs between index and public plan')
    if _require_sha(plan.get('matrix_manifest_canonical_sha256'),
                    'plan canonical manifest digest') != manifest_sha:
        raise ValueError('canonical manifest digest differs in public plan')
    _require_sha(plan.get('driver_sha256'), 'matrix driver digest')
    if (type(plan.get('campaign_runtime_seconds')) is not int
            or plan['campaign_runtime_seconds'] != CAMPAIGN_SECONDS
            or type(plan.get('slot_count')) is not int or plan['slot_count'] != 60
            or type(plan.get('slots')) is not list or len(plan['slots']) != 60):
        raise ValueError('complete registered 60-slot plan required')

    for expected, slot in zip(_registered_slots(), plan['slots']):
        _require_fields(slot, PLAN_SLOT_FIELDS, 'plan slot')
        for field, expected_value in expected.items():
            if type(slot.get(field)) is not type(expected_value) or slot[field] != expected_value:
                raise ValueError('plan slot differs from registered grid')
        _require_sha(slot.get('slot_identity_sha256'), 'slot identity digest')
        _require_fields(slot.get('limits'), LIMIT_FIELDS, 'plan slot limits')
        expected_limits = manifest_limits[str(slot['target_count'])][slot['mode']]
        if slot['limits'] != expected_limits:
            raise ValueError('plan slot limits differ from registered manifest limits')


def verify_bundle(bundle_dir):
    """Verify public projection inventory, byte pins, schemas, and matrix registration."""
    root = Path(bundle_dir).absolute()
    _check_inventory(root)
    index_raw = _read_regular(root / 'index.json', MAX_INDEX_BYTES, 'projection index')
    manifest_raw = _read_regular(
        root / 'matrix-manifest.json', MAX_MANIFEST_BYTES, 'public matrix manifest')
    plan_raw = _read_regular(root / 'matrix-plan.json', MAX_PLAN_BYTES, 'public matrix plan')
    index = _json_object(index_raw, 'projection index')
    manifest = _json_object(manifest_raw, 'public matrix manifest')
    plan = _json_object(plan_raw, 'public matrix plan')

    campaign_id, manifest_sha = _check_index(index)
    for role, raw in (('matrix_manifest', manifest_raw), ('matrix_plan', plan_raw)):
        if index['public_files'][role]['sha256'] != _sha256(raw):
            raise ValueError(f'{role} public file byte hash mismatch')
    if manifest_raw != _canonical_bytes(manifest):
        raise ValueError('public matrix manifest is not in canonical encoding')
    if plan_raw != _canonical_bytes(plan):
        raise ValueError('public matrix plan is not in canonical encoding')

    _check_public_manifest(manifest, campaign_id, manifest_sha)
    _check_plan(plan, campaign_id, manifest_sha, manifest['limits'])
    _check_inventory(root)
    return {
        'status': 'verified',
        'scope': SCOPE,
        'campaign_id': campaign_id,
        'slot_count': 60,
        'canonical_manifest_digest_consistent': True,
        'matrix_manifest_canonical_sha256': manifest_sha,
        'index_sha256': _sha256(index_raw),
        'public_manifest_sha256': _sha256(manifest_raw),
        'public_plan_sha256': _sha256(plan_raw),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path,
                        help='public matrix projection directory')
    args = parser.parse_args()
    try:
        result = verify_bundle(args.bundle)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
