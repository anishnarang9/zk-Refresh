#!/usr/bin/env python3
"""Prepare one private heldout matched-k1 proof and adapter-wire bundle.

The helper consumes independently pinned R0/R1 source receipts, generates and
fully checks both witnesses, runs the existing matched Full or Anchor proof
mode under an external sampled process-tree supervisor, and derives the 448-byte
adapter wires. It has no validator or application-side effects.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.part5 import freeze_v3_heldout_cohort as frozen_product
from tools.part5 import generate_v3_heldout_keys as keygen
from tools.part5 import build_v3_request_bound_anchor_packet as packet_builder

SCHEMA = 'credential-v3-heldout-proof-evidence-v1'
SOURCE_SCHEMA = 'credential-v3-heldout-request-source-v1'
PROOF_SCHEMA = 'credential-v3-matched-k1-proof-v1'
SOURCE_CAPS = {
    'request.bin': 1918, 'summary.bin': 459, 'input.json': 65536,
    'public.json': 1024, 'input-coordinates.bin': 4096,
    'internal-coordinate.bin': 4, 'training-receipt.json': 8192,
    'staged-request.bin': 2249, 'finalized-request.bin': 2874,
    'action-transport.bin': 561,
}
PROOF_COUNTS = {
    'proofs': 2, 'positive_checks': 2,
    'altered_public_checks': 12, 'cross_root_checks': 2,
    'ordinary_checks': 16,
}
PROOF_STAGE_PIN_FIELDS = frozenset({
    'program_id', 'genesis_hash', 'loaded_elf_sha256',
    'base_stage_report_sha256', 'base_config_sha256',
    'finalized_request_sha256', 'request_address', 'base_finalized_slot',
    'near_state_report_sha256', 'near_config_sha256', 'near_finalized_slot',
    'base_root', 'near_root', 'action_hash',
})
FULL_LIMITS = {'runtime_seconds': 1800, 'rss_bytes': 4 * 1024**3,
               'storage_bytes': 512 * 1024**2}
ANCHOR_LIMITS = {'runtime_seconds': 3600, 'rss_bytes': 4 * 1024**3,
                 'storage_bytes': 512 * 1024**2}
WITNESS_LIMITS = {'runtime_seconds': 300, 'rss_bytes': 4 * 1024**3,
                  'storage_bytes': 512 * 1024**2}
RELATION_LIMITS = {'runtime_seconds': 600, 'rss_bytes': 4 * 1024**3,
                   'storage_bytes': 512 * 1024**2}
ADAPTER_LIMITS = {'runtime_seconds': 600, 'rss_bytes': 4 * 1024**3,
                  'storage_bytes': 512 * 1024**2}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)
            + '\n').encode('ascii')


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _json(raw):
    def unique(items):
        output = {}
        for key, value in items:
            if key in output:
                raise ValueError('duplicate JSON key')
            output[key] = value
        return output
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid JSON number')))


def _hash(value):
    return (type(value) is str and len(value) == 64
            and all(character in '0123456789abcdef' for character in value))


def _private_dir(path, *, empty=False):
    path = Path(path)
    info = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
            or (empty and any(path.iterdir()))):
        raise ValueError('canonical owner0700 directory required')
    return path


def _read(path, cap, *, expected=None, private=True):
    path = Path(path)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > cap
            or before.st_nlink != 1 or before.st_uid != os.getuid()
            or (private and stat.S_IMODE(before.st_mode) != 0o600)):
        raise ValueError('bounded single-link artifact required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        if _identity(os.fstat(stream.fileno())) != _identity(before):
            raise ValueError('artifact changed at open')
        raw = stream.read(cap + 1)
        if _identity(os.fstat(stream.fileno())) != _identity(before):
            raise ValueError('artifact changed during read')
    if (len(raw) != before.st_size or _identity(path.lstat()) != _identity(before)
            or (expected is not None and digest(raw) != expected)):
        raise ValueError('artifact digest or identity mismatch')
    return raw


def _write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _source(root, expected_sha, freeze_sha, variant):
    root = _private_dir(root)
    raw = _read(root / 'source-receipt.json', 16384, expected=expected_sha)
    receipt = _json(raw)
    hashes = receipt.get('artifacts_sha256')
    if (receipt.get('schema') != SOURCE_SCHEMA or receipt.get('variant') != variant
            or receipt.get('freeze_sha256') != freeze_sha or type(hashes) is not dict
            or set(hashes) != set(SOURCE_CAPS)):
        raise ValueError(f'pinned {variant} heldout source receipt required')
    artifacts = {}
    for name, cap in SOURCE_CAPS.items():
        expected = hashes.get(name)
        if not _hash(expected):
            raise ValueError('complete heldout source artifact hashes required')
        artifact = _read(root / name, cap, expected=expected)
        artifacts[name] = artifact
    training_raw = artifacts['training-receipt.json']
    training = _json(training_raw)
    if (training.get('schema') != 'v3-request-bound-training-input-v1'
            or training.get('training_only') is not True
            or training.get('live_state_authenticated') is not False
            or training.get('proof_created') is not False
            or receipt.get('training_receipt_sha256') != digest(training_raw)
            or type(training.get('artifact_sha256')) is not dict
            or any(training['artifact_sha256'].get(name) != digest(artifacts[name])
                   for name in ('request.bin', 'input.json', 'public.json'))):
        raise ValueError('request-bound source helper receipt mismatch')
    request = artifacts['staged-request.bin']
    finalized = artifacts['finalized-request.bin']
    action_transport = artifacts['action-transport.bin']
    if (len(request) != 2249 or request[:8] != b'DYNREQ03'
            or len(finalized) != 2874 or finalized[:4] != b'V3F1'
            or finalized[625:] != request
            or len(action_transport) != 561 or action_transport[:4] != b'V3F2'
            or action_transport[164:196].hex() != receipt.get('action_hash')
            or receipt.get('staged_request_sha256') != digest(request)
            or receipt.get('finalized_request_sha256') != digest(finalized)
            or receipt.get('finalized_action_transport_sha256') != digest(action_transport)
            or receipt.get('selected_root') != receipt.get('membership_roots', {}).get(variant)
            or receipt.get('proof_created') is not False
            or receipt.get('application_effect') is not False
            or receipt.get('live_state_authenticated') is not False
            or not _hash(receipt.get('exporter_sha256'))
            or not _hash(receipt.get('training_helper_sha256'))):
        raise ValueError('pinned source request or action transport mismatch')
    public = _json(artifacts['public.json'])
    source_input = _json(artifacts['input.json'])
    roots = receipt.get('membership_roots')
    if (type(public) is not list or len(public) != 6
            or any(type(value) is not str or not value.isdecimal() or str(int(value)) != value
                   for value in public)
            or type(source_input) is not dict
            or type(roots) is not dict or set(roots) != {'R0', 'R1', 'R2'}
            or any(not _hash(value) for value in roots.values())
            or not _hash(receipt.get('selected_root'))
            or not _hash(receipt.get('action_hash'))
            or source_input.get('root') != public[0]
            or source_input.get('actionHash') != public[4]
            or public[0] != str(int(receipt['selected_root'], 16))
            or public[4] != str(int(receipt.get('action_hash'), 16))):
        raise ValueError('complete witness public statement differs from source receipt')
    if (receipt.get('target_variant') is None or type(receipt.get('issuer_index')) is not int
            or type(receipt.get('holder_index')) is not int
            or not _hash(receipt.get('target_der_sha256'))
            or not _hash(receipt.get('target_tbs_sha256'))
            or not _hash(receipt.get('issuer_public_key_sha256'))
            or not _hash(receipt.get('holder_public_key_sha256'))):
        raise ValueError('heldout source public identity fields required')
    return {'root': root, 'raw': raw, 'sha256': expected_sha,
            'receipt': receipt, 'artifacts': artifacts,
            'training_receipt': training, 'public': public}


def validate_source_pair(r0_root, r0_sha256, r1_root, r1_sha256, freeze_sha256):
    if not (_hash(r0_sha256) and _hash(r1_sha256) and _hash(freeze_sha256)):
        raise ValueError('canonical source and freeze SHA pins required')
    r0 = _source(r0_root, r0_sha256, freeze_sha256, 'R0')
    r1 = _source(r1_root, r1_sha256, freeze_sha256, 'R1')
    left, right = r0['receipt'], r1['receipt']
    for field in ('freeze_sha256', 'cohort_receipt_sha256', 'case_context_sha256',
                  'pair_receipt_sha256', 'case_index', 'target_variant',
                  'unrelated_variant', 'issuer_index', 'holder_index',
                  'target_der_sha256', 'target_tbs_sha256', 'unrelated_der_sha256',
                  'issuer_public_key_sha256', 'holder_public_key_sha256',
                  'stage_report_sha256', 'stage_plan_sha256', 'context_sha256',
                  'stage_context_sha256', 'membership_sha256', 'membership_roots',
                  'staged_request_sha256', 'action_hash', 'finalized_action_transport_sha256',
                  'exporter_sha256', 'training_helper_sha256'):
        if left.get(field) != right.get(field):
            raise ValueError('R0/R1 source identity or action continuity mismatch')
    if (left.get('transition_report_sha256') is not None
            or left.get('transition_context_sha256') is not None
            or right.get('transition_report_sha256') is None
            or not _hash(right['transition_report_sha256'])
            or not _hash(right.get('transition_context_sha256'))
            or right.get('selected_root') != right['membership_roots'].get('R1')
            or left.get('selected_root') != left['membership_roots'].get('R0')
            or left.get('selected_root') == right.get('selected_root')
            or left.get('finalized_request_sha256') == right.get('finalized_request_sha256')
            or right.get('r0_source_receipt_sha256') != r0_sha256):
        raise ValueError('R0/R1 roots and source receipt link required')
    if (r0['public'][1:4] != r1['public'][1:4]
            or r0['public'][5] != r1['public'][5]
            or r0['public'][4] != r1['public'][4]):
        raise ValueError('R0/R1 complete witness statements do not preserve action')
    return {'R0': r0, 'R1': r1}


def validate_proof_report(report, mode, packet_sha256, expected_stage_pins,
                          expected_identities):
    proof_mode = 'matched-full-k1' if mode == 'full' else 'matched-anchor-k1'
    if (mode not in ('full', 'anchor') or report.get('schema') != PROOF_SCHEMA
            or report.get('passed') is not True or report.get('mode') != proof_mode
            or report.get('packet_sha256') != packet_sha256
            or report.get('counts') != PROOF_COUNTS
            or report.get('application_verified') is not False
            or report.get('setup_executed') is not False
            or report.get('private_cache_persisted') is not False
            or report.get('qualification_extras_executed') is not False
            or report.get('old_base_full_rejected_at_near_publics') is not True
            or report.get('application_stage_pins_authority')
               != 'caller-supplied; external finalized-state verification required'
            or type(expected_stage_pins) is not dict
            or set(expected_stage_pins) != PROOF_STAGE_PIN_FIELDS
            or report.get('application_stage_pins') != expected_stage_pins
            or any(report.get(name) != value
                   for name, value in expected_identities.items())):
        raise ValueError('matched heldout proof report, pins, or ordinary check counts mismatch')
    return report


def validate_wire(raw, root_hex, action_hex):
    if (not _hash(root_hex) or not _hash(action_hex) or len(raw) != 448
            or raw[:32].hex() != root_hex or raw[128:160].hex() != action_hex):
        raise ValueError('adapter wire does not pin expected root and action')
    return True


def _pinned_file(path, expected, *, executable=False, cap=1024 * 1024 * 1024):
    path = Path(path)
    info = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or info.st_size <= 0 or info.st_size > cap
            or info.st_mode & 0o022 or (executable and not info.st_mode & 0o111)):
        raise ValueError('canonical pinned product file required')
    raw = _read(path, cap, private=False, expected=expected)
    return path, raw


def _client_sources(boundary):
    actual, _ = frozen_product.prior_freeze.bundle(frozen_product.CLIENT_FILES)
    if actual != boundary['identities']['client']:
        raise ValueError('frozen client source bundle changed')
    return actual


def _run_bounded(supervisor, work, supervision, label, command, *, env=None, limits):
    monitor = supervision / (label + '-monitor')
    report_path = supervision / (label + '-report.json')
    runner_command = [sys.executable, '-B', str(supervisor), '--owner',
        f'heldout-v3-{label}-{uuid.uuid4().hex[:10]}', '--cwd', str(ROOT),
        '--private-output', str(monitor), '--report', str(report_path),
        '--runtime-seconds', str(limits['runtime_seconds']), '--rss-bytes',
        str(limits['rss_bytes']), '--storage-bytes', str(limits['storage_bytes']),
        '--storage-path', str(work), '--poll-seconds', '0.25', '--',
        *[str(part) for part in command]]
    started = time.monotonic()
    process_env = os.environ.copy()
    process_env.update({'RAYON_NUM_THREADS': '4', 'OMP_NUM_THREADS': '1', 'TZ': 'UTC'})
    process_env.update(env or {})
    completed = subprocess.run(runner_command, cwd=ROOT, env=process_env,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, check=False)
    report_raw = _read(report_path, 1024 * 1024)
    report = _json(report_raw)
    if (completed.returncode != 0 or report.get('passed') is not True
            or report.get('exit_code') != 0 or report.get('stop_reason') is not None
            or report.get('cleanup_remaining_owned_processes') != 0
            or report.get('cleanup_status_unknown') is not False):
        raise ValueError(f'bounded {label} process tree did not complete cleanly')
    return {'path': str(report_path), 'sha256': digest(report_raw),
            'monitor': str(monitor), 'wall_seconds': time.monotonic() - started,
            'limits': limits}


def _source_inputs(source, dest, *, skip=()):
    dest.mkdir(mode=0o700)
    for name in SOURCE_CAPS:
        if name in skip:
            continue
        _write(dest / name, source['artifacts'][name])


def matched_proof_names(mode):
    if mode == 'full':
        return ('request_bound_training_full_base', 'request_bound_training_full_near')
    if mode == 'anchor':
        return ('request_bound_training_full_base', 'request_bound_training_anchor_near')
    raise ValueError('matched Full or Anchor proof mode required')


def proof_tool_hashes(product, bounded_supervisor_sha256, exporter_sha256,
                     proof_helper_sha256):
    values = {
        'packet_template': product['packet_template_sha256'],
        'witness_js': product['witness_sha256'],
        'relation_checker': product['relation_sha256'],
        'node': product['node_sha256'],
        'proof_runner': product['proof_runner_sha256'],
        'adapter_binary': product['adapter_sha256'],
        'bounded_supervisor': bounded_supervisor_sha256,
        'exporter': exporter_sha256,
        'packet_builder': product['packet_builder_sha256'],
        'proof_helper': proof_helper_sha256,
    }
    if any(not _hash(value) for value in values.values()):
        raise ValueError('complete pinned heldout proof tool hashes required')
    return values


def validate_node_pin(node, expected_sha256):
    if not _hash(expected_sha256):
        raise ValueError('canonical node runtime SHA-256 required')
    path, _ = _pinned_file(node, expected_sha256, executable=True,
                           cap=512 * 1024 * 1024)
    return path


def _near_receipt(r0, r1):
    artifacts = r1['artifacts']
    return encoded({
        'schema': 'v3-request-bound-near-training-input-v1',
        'training_only': True, 'registry_history_authenticated': False,
        'live_state_authenticated': False, 'proof_created': False,
        'base_receipt_sha256': r0['receipt']['training_receipt_sha256'],
        'unrelated_credential_sha256': r1['receipt']['unrelated_der_sha256'],
        'membership_sha256': r1['receipt']['membership_sha256'],
        'action_hash': str(int(r1['receipt']['action_hash'], 16)),
        'artifact_sha256': {name: digest(artifacts[name])
                            for name in ('request.bin', 'input.json', 'public.json')},
    })


def _check_product_inputs(freeze_path, freeze_sha, template_path, template_sha,
                          setup_manifest, ordinary_vk, proof_runner, adapter,
                          witness_js, relation_checker, node, node_sha256,
                          supervisor, supervisor_sha):
    raw = _read(freeze_path, 65536, expected=freeze_sha)
    freeze = _json(raw)
    if (freeze.get('schema') != keygen.FREEZE_SCHEMA
            or type(freeze.get('frozen_at_unix_ns')) is not int
            or not isinstance(freeze.get('identities'), dict)):
        raise ValueError('exact frozen heldout boundary required')
    boundary = freeze['identities']
    _, template_raw = _pinned_file(template_path, template_sha, cap=262144)
    template = _json(template_raw)
    _, setup_raw = _pinned_file(setup_manifest, boundary.get('setup_manifest'), cap=65536)
    if (template.get('setup_manifest_path') != str(Path(setup_manifest))
            or template.get('setup_manifest_sha256') != boundary['setup_manifest']):
        raise ValueError('packet template differs from frozen setup manifest')
    _pinned_file(ordinary_vk, boundary.get('ordinary_vk'), cap=1024 * 1024)
    proof_runner, _ = _pinned_file(proof_runner, boundary.get('proof_runner'), executable=True)
    adapter, _ = _pinned_file(adapter, boundary.get('ordinary_adapter'), executable=True)
    _, r1cs_raw = _pinned_file(template.get('r1cs_path'), boundary.get('r1cs'), cap=192 * 1024 * 1024)
    _, wasm_raw = _pinned_file(template.get('wasm_path'), boundary.get('witness_executable'), cap=16 * 1024 * 1024)
    _, profile_raw = _pinned_file(template.get('profile_path'), boundary.get('profile'), cap=65536)
    _, input_map_raw = _pinned_file(template.get('input_map_path'), template.get('input_map_sha256'), cap=8 * 1024 * 1024)
    _, package_check_raw = _pinned_file(template.get('package_check_path'), template.get('package_check_sha256'), cap=65536)
    if (digest(setup_raw) != boundary['setup_manifest']
            or digest(r1cs_raw) != boundary['r1cs']
            or digest(wasm_raw) != boundary['witness_executable']
            or digest(profile_raw) != boundary['profile']
            or not _hash(template.get('package_digest'))
            or not _hash(template.get('package_check_sha256'))):
        raise ValueError('pinned setup/package inputs mismatch')
    witness_js = Path(witness_js)
    relation_checker = Path(relation_checker)
    node = validate_node_pin(node, node_sha256)
    supervisor, _ = _pinned_file(supervisor, supervisor_sha, cap=1024 * 1024)
    client_sha = _client_sources(freeze)
    # The source bundle freezes both proof-input programs; this check also
    # ensures caller paths select those exact sources.
    expected_witness = frozen_product.ROOT / 'crates/dynark-native-client/tests/support/v3_relation_witness.cjs'
    expected_relation = frozen_product.ROOT / 'crates/dynark-native-client/tests/support/prepare_v3_relation.py'
    if (witness_js.resolve(strict=True) != expected_witness.resolve(strict=True)
            or relation_checker.resolve(strict=True) != expected_relation.resolve(strict=True)):
        raise ValueError('unfrozen complete witness tools required')
    witness_raw = _read(witness_js, 131072, private=False)
    relation_raw = _read(relation_checker, 131072, private=False)
    return {'freeze': freeze, 'freeze_raw': raw, 'template': template,
            'template_raw': template_raw, 'proof_runner': proof_runner,
            'adapter': adapter, 'witness_js': witness_js,
            'relation_checker': relation_checker, 'node': node,
            'supervisor': supervisor, 'client_sha256': client_sha,
            'proof_runner_sha256': boundary['proof_runner'],
            'adapter_sha256': boundary['ordinary_adapter'],
            'setup_manifest_sha256': boundary['setup_manifest'],
            'ordinary_vk_sha256': boundary['ordinary_vk'],
            'r1cs_sha256': digest(r1cs_raw), 'wasm_sha256': digest(wasm_raw),
            'profile_sha256': digest(profile_raw),
            'input_map_sha256': digest(input_map_raw),
            'package_check_sha256': digest(package_check_raw),
            'proof_source_identity': packet_builder.proof_source_identity(),
            'packet_template_sha256': template_sha,
            'packet_builder_sha256': digest(Path(packet_builder.__file__).read_bytes()),
            'witness_sha256': digest(witness_raw),
            'relation_sha256': digest(relation_raw),
            'node_sha256': node_sha256}


def _write_json(path, value):
    raw = encoded(value)
    _write(path, raw)
    return raw


def _clear_output(output):
    for child in list(output.iterdir()):
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink(missing_ok=True)


def _prepare(case_name, r0_source_root, r0_source_sha256, r1_source_root,
             r1_source_sha256, freeze_receipt, freeze_sha256, stage_root,
             transition_root, packet_template, packet_template_sha256,
             setup_manifest, ordinary_vk, witness_js, relation_checker, node,
             node_sha256,
             proof_runner, adapter_binary, bounded_supervisor,
             bounded_supervisor_sha256, mode, output):
    if mode not in ('full', 'anchor'):
        raise ValueError('matched Full or Anchor proof mode required')
    output = _private_dir(output, empty=True)
    roots = tuple(map(_private_dir, (stage_root, transition_root)))
    stage_root, transition_root = roots
    input_roots = [*roots, Path(r0_source_root), Path(r1_source_root)]
    if any(output == path or output in path.parents or path in output.parents
           for path in input_roots):
        raise ValueError('separate private proof output required')
    source_pair = validate_source_pair(r0_source_root, r0_source_sha256,
                                       r1_source_root, r1_source_sha256, freeze_sha256)
    r0, r1 = source_pair['R0'], source_pair['R1']
    src0, src1 = r0['receipt'], r1['receipt']
    if not isinstance(case_name, str) or not case_name.isascii() or not case_name.replace('_', '').isalnum():
        raise ValueError('safe heldout case label required')
    if (src0.get('stage_report_sha256') != digest(_read(stage_root / 'stage-report.json', 65536))
            or src0.get('stage_plan_sha256') != digest(_read(stage_root / 'plan.json', 8192))
            or src1.get('transition_report_sha256')
                != digest(_read(transition_root / 'transition-report.json', 65536))):
        raise ValueError('source receipts do not pin supplied stage and transition')
    product = _check_product_inputs(
        freeze_receipt, freeze_sha256, packet_template, packet_template_sha256,
        setup_manifest, ordinary_vk, proof_runner, adapter_binary, witness_js,
        relation_checker, node, node_sha256, bounded_supervisor,
        bounded_supervisor_sha256)
    identities = {output: _identity(output.lstat()), stage_root: _identity(stage_root.lstat()),
                  transition_root: _identity(transition_root.lstat()),
                  r0['root']: _identity(r0['root'].lstat()),
                  r1['root']: _identity(r1['root'].lstat())}
    freeze_at = product['freeze']['frozen_at_unix_ns']
    work, supervision = output / 'work', output / 'supervisor'
    work.mkdir(mode=0o700)
    supervision.mkdir(mode=0o700)
    base, near = work / 'base', work / 'near'
    _source_inputs(r0, base)
    _source_inputs(r1, near, skip=('training-receipt.json',))
    # The adapter's existing host test accepts the canonical near-input receipt.
    # Source artifact bytes remain identical and are cross-pinned by R1's receipt.
    _write(near / 'training-receipt.json', _near_receipt(r0, r1))

    bounded = {}
    for label, directory in (('r0-witness', base), ('r1-witness', near)):
        bounded[label] = _run_bounded(
            product['supervisor'], work, supervision, label,
            [product['node'], product['witness_js'], directory], limits=WITNESS_LIMITS)
        wtns = _read(directory / 'output.wtns', 32 * 1024 * 1024)
        if len(wtns) != 25113548 or wtns[:4] != b'wtns':
            raise ValueError('full heldout witness output required')
        bounded[label.replace('witness', 'relation')] = _run_bounded(
            product['supervisor'], work, supervision, label.replace('witness', 'relation'),
            [sys.executable, '-B', product['relation_checker'], 'check', directory],
            limits=RELATION_LIMITS)
        if _read(directory / 'preflight.bin', 64) != b'V3R1' + (784796).to_bytes(4, 'little') \
                + (793681).to_bytes(4, 'little') + (4257583).to_bytes(4, 'little'):
            raise ValueError('complete independent heldout relation preflight required')

    packet = packet_builder.build(stage_root, transition_root, base, near,
                                  Path(packet_template))
    packet_path = work / 'packet.json'
    packet_raw = _write_json(packet_path, packet)
    packet_sha = digest(packet_raw)
    mode_arg = 'matched-full-k1' if mode == 'full' else 'matched-anchor-k1'
    proof_dir = work / 'proof'
    limits = FULL_LIMITS if mode == 'full' else ANCHOR_LIMITS
    bounded['proof'] = _run_bounded(
        product['supervisor'], work, supervision, 'proof',
        [product['proof_runner'], mode_arg, packet_path, packet_sha, proof_dir],
        limits=limits)
    proof_report_raw = _read(proof_dir / 'proof-report.json', 1024 * 1024)
    proof_report = _json(proof_report_raw)
    packet_stage_pins = packet.get('application_stage')
    expected_identities = {
        'package_digest': product['template'].get('package_digest'),
        'proof_binary_sha256': product['proof_runner_sha256'],
        'ordinary_vk_file_sha256': product['ordinary_vk_sha256'],
        'setup_manifest_sha256': product['setup_manifest_sha256'],
        'proof_source_identity': product['proof_source_identity'],
    }
    if (type(packet_stage_pins) is not dict
            or set(packet_stage_pins) != PROOF_STAGE_PIN_FIELDS
            or packet_stage_pins.get('base_root') != str(int(src0['selected_root'], 16))
            or packet_stage_pins.get('near_root') != str(int(src1['selected_root'], 16))
            or packet_stage_pins.get('action_hash') != str(int(src0['action_hash'], 16))
            or packet_stage_pins.get('finalized_request_sha256')
               != src0['staged_request_sha256']
            or src0['staged_request_sha256'] != src1['staged_request_sha256']
            or packet_stage_pins.get('base_stage_report_sha256') != src0['stage_report_sha256']
            or packet_stage_pins.get('near_state_report_sha256') != src1['transition_report_sha256']
            or packet_stage_pins.get('loaded_elf_sha256') != product['freeze']['identities']['loaded_elf']):
        raise ValueError('proof packet does not bind staged request, transition, roots, and ELF')
    validate_proof_report(proof_report, mode, packet_sha, packet_stage_pins,
                          expected_identities)
    if proof_report.get('proof_binary_sha256') != product['proof_runner_sha256']:
        raise ValueError('proof report differs from frozen proof/setup implementation')

    # Packet builder fixes the pair name to request_bound_training, which is
    # also the filename contract consumed by the adapter host test.
    proof_names = []
    for proof_name in matched_proof_names(mode):
        for extension in ('.proof', '-public.bin'):
            source_path = proof_dir / f'{proof_name}{extension}'
            raw = _read(source_path, 4096)
            proof_names.append(source_path.name)

    adapter_env = {
        'M2_V3_MATCHED_MODE': mode_arg, 'M2_V3_MATCHED_BASE': str(base),
        'M2_V3_MATCHED_NEAR': str(near), 'M2_V3_MATCHED_PROOFS': str(proof_dir),
        'M2_V3_MATCHED_REPORT_SHA256': digest(proof_report_raw),
    }
    bounded['adapter'] = _run_bounded(
        product['supervisor'], work, supervision, 'adapter',
        [product['adapter'], 'private_matched_k1_wires_pass_adapter_and_program_host',
         '--exact', '--ignored', '--test-threads=1'], env=adapter_env,
        limits=ADAPTER_LIMITS)
    base_wire = _read(base / 'full-solana-wire.bin', 448)
    near_wire_name = 'full-near-solana-wire.bin' if mode == 'full' else 'anchor-solana-wire.bin'
    near_wire = _read(near / near_wire_name, 448)
    validate_wire(base_wire, src0['selected_root'], src0['action_hash'])
    validate_wire(near_wire, src1['selected_root'], src1['action_hash'])

    report_ref = {'path': str(proof_dir / 'proof-report.json'), 'sha256': digest(proof_report_raw)}
    wire_refs = {
        'r0_full_wire': {'path': str(base / 'full-solana-wire.bin'), 'sha256': digest(base_wire)},
        'r1_wire': {'path': str(near / near_wire_name), 'sha256': digest(near_wire)},
    }
    artifact_paths = {
        'packet.json': packet_path, 'proof/proof-report.json': proof_dir / 'proof-report.json',
        'base/full-solana-wire.bin': base / 'full-solana-wire.bin',
        f'near/{near_wire_name}': near / near_wire_name,
    }
    for name in proof_names:
        artifact_paths['proof/' + name] = proof_dir / name
    for label, directory in (('base', base), ('near', near)):
        for name in ('input.json', 'public.json', 'output.wtns', 'preflight.bin', 'request.bin',
                     'training-receipt.json'):
            artifact_paths[f'{label}/{name}'] = directory / name
    artifact_refs = {}
    for name, path in artifact_paths.items():
        cap = 32 * 1024 * 1024 if name.endswith('output.wtns') else 1024 * 1024
        content = _read(path, cap)
        artifact_refs[name] = {'path': str(path), 'sha256': digest(content)}
    sup_refs = {}
    for label, value in bounded.items():
        report_bytes = _read(value['path'], 1024 * 1024)
        sup_refs[label] = {'path': value['path'], 'sha256': digest(report_bytes),
                           'limits': value['limits']}
    helper_sha = digest(Path(__file__).read_bytes())
    tool_hashes = proof_tool_hashes(product, bounded_supervisor_sha256,
                                    src0['exporter_sha256'], helper_sha)
    receipt = {
        'schema': SCHEMA, 'case': case_name, 'mode': mode, 'proof_mode': mode_arg,
        'freeze_sha256': freeze_sha256,
        'cohort_receipt_sha256': src0['cohort_receipt_sha256'],
        'case_context_sha256': src0['case_context_sha256'],
        'target_variant': src0['target_variant'], 'issuer_index': src0['issuer_index'],
        'holder_index': src0['holder_index'],
        'target_der_sha256': src0['target_der_sha256'],
        'target_tbs_sha256': src0['target_tbs_sha256'],
        'issuer_public_key_sha256': src0['issuer_public_key_sha256'],
        'holder_public_key_sha256': src0['holder_public_key_sha256'],
        'membership_roots': src0['membership_roots'], 'action_hash': src0['action_hash'],
        'stage_report_sha256': src0['stage_report_sha256'],
        'stage_plan_sha256': src0['stage_plan_sha256'],
        'transition_report_sha256': src1['transition_report_sha256'],
        'source_receipts': {
            'R0': {'path': str(r0['root'] / 'source-receipt.json'), 'sha256': r0_sha256},
            'R1': {'path': str(r1['root'] / 'source-receipt.json'), 'sha256': r1_sha256},
        },
        'packet': {'path': str(packet_path), 'sha256': packet_sha},
        'proof_report': report_ref, 'proof_counts': proof_report['counts'],
        'ordinary_verification': {'passed': True, **proof_report['counts']},
        'proof_runner_sha256': product['proof_runner_sha256'],
        'adapter_sha256': product['adapter_sha256'],
        'exporter_sha256': src0['exporter_sha256'],
        'proof_source_identity': product['proof_source_identity'],
        'packet_builder_sha256': product['packet_builder_sha256'],
        'proof_helper_sha256': helper_sha,
        'witness_js_sha256': product['witness_sha256'],
        'relation_checker_sha256': product['relation_sha256'],
        'node_sha256': product['node_sha256'],
        'bounded_supervisor_sha256': bounded_supervisor_sha256,
        'setup_manifest_sha256': product['setup_manifest_sha256'],
        'ordinary_vk_sha256': product['ordinary_vk_sha256'],
        'r1cs_sha256': product['r1cs_sha256'], 'wasm_sha256': product['wasm_sha256'],
        'profile_sha256': product['profile_sha256'],
        'input_map_sha256': product['input_map_sha256'],
        'package_check_sha256': product['package_check_sha256'],
        'proof_tool_hashes': tool_hashes,
        'wires': wire_refs, 'artifacts': artifact_refs,
        'supervisor_reports': sup_refs,
        'proof_created': True, 'application_verified': False,
        'validator_run': False, 'application_effect': False,
        'complete_relation_checked': True, 'live_state_authenticated': False,
    }
    if time.time_ns() < freeze_at:
        raise ValueError('proof output predates heldout freeze')
    for path, identity in identities.items():
        if _identity(path.lstat()) != identity:
            raise ValueError('heldout proof input directory changed')
    receipt_path = output / 'proof-receipt.json'
    receipt_raw = _write_json(receipt_path, receipt)
    return receipt


def prepare(case_name, r0_source_root, r0_source_sha256, r1_source_root,
            r1_source_sha256, freeze_receipt, freeze_sha256, stage_root,
            transition_root, packet_template, packet_template_sha256,
            setup_manifest, ordinary_vk, witness_js, relation_checker, node,
            node_sha256,
            proof_runner, adapter_binary, bounded_supervisor,
            bounded_supervisor_sha256, mode, output):
    output = Path(output)
    cleanable = False
    identity = None
    try:
        info = output.lstat()
        cleanable = (output.is_absolute() and output.resolve(strict=True) == output
                     and stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                     and stat.S_IMODE(info.st_mode) == 0o700 and not any(output.iterdir()))
        identity = (info.st_dev, info.st_ino)
    except OSError:
        pass
    try:
        return _prepare(case_name, r0_source_root, r0_source_sha256,
                        r1_source_root, r1_source_sha256, freeze_receipt,
                        freeze_sha256, stage_root, transition_root, packet_template,
                        packet_template_sha256, setup_manifest, ordinary_vk,
                        witness_js, relation_checker, node, node_sha256, proof_runner,
                        adapter_binary, bounded_supervisor,
                        bounded_supervisor_sha256, mode, output)
    except Exception:
        if cleanable:
            try:
                current = output.lstat()
                if (stat.S_ISDIR(current.st_mode) and current.st_uid == os.getuid()
                        and (current.st_dev, current.st_ino) == identity
                        and stat.S_IMODE(current.st_mode) == 0o700):
                    _clear_output(output)
            except OSError:
                pass
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', required=True)
    for name in ('r0-source-root', 'r1-source-root', 'freeze-receipt', 'stage-root',
                 'transition-root', 'packet-template', 'setup-manifest', 'ordinary-vk',
                 'witness-js', 'relation-checker', 'node', 'proof-runner',
                 'adapter-binary', 'bounded-supervisor', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('r0-source-sha256', 'r1-source-sha256', 'freeze-sha256',
                 'packet-template-sha256', 'node-sha256',
                 'bounded-supervisor-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--mode', choices=('full', 'anchor'), required=True)
    args = parser.parse_args()
    values = vars(args)
    try:
        receipt = prepare(
            case_name=values['case'], r0_source_root=values['r0_source_root'],
            r0_source_sha256=values['r0_source_sha256'],
            r1_source_root=values['r1_source_root'],
            r1_source_sha256=values['r1_source_sha256'],
            freeze_receipt=values['freeze_receipt'], freeze_sha256=values['freeze_sha256'],
            stage_root=values['stage_root'], transition_root=values['transition_root'],
            packet_template=values['packet_template'],
            packet_template_sha256=values['packet_template_sha256'],
            setup_manifest=values['setup_manifest'], ordinary_vk=values['ordinary_vk'],
            witness_js=values['witness_js'], relation_checker=values['relation_checker'],
            node=values['node'], node_sha256=values['node_sha256'],
            proof_runner=values['proof_runner'],
            adapter_binary=values['adapter_binary'],
            bounded_supervisor=values['bounded_supervisor'],
            bounded_supervisor_sha256=values['bounded_supervisor_sha256'],
            mode=values['mode'], output=values['output'])
    except Exception:
        raise SystemExit('heldout proof preparation rejected') from None
    receipt_raw = _read(values['output'] / 'proof-receipt.json', 65536)
    print(json.dumps({'schema': receipt['schema'], 'mode': receipt['mode'],
                      'proof_receipt_sha256': digest(receipt_raw)}, sort_keys=True))


if __name__ == '__main__':
    main()
