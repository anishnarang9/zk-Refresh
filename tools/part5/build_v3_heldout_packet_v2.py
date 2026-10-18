#!/usr/bin/env python3
"""Build a v2 proof-runner packet from frozen heldout inputs and explicit pins.

The v2 runner validates the full external package record before proving.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

ROOT = Path(__file__).resolve().parents[2]
SOURCE = 'circuits/credential-v3-bounded/qualification/proof-runner-v2'
SOURCE_FILES = [
    ('main.rs', 'src/main.rs'),
    ('artifacts.rs', 'src/artifacts.rs'),
    ('context.rs', 'src/context.rs'),
    ('ordinary.rs', 'src/ordinary.rs'),
    ('pins.rs', 'src/pins.rs'),
    ('Cargo.lock', 'Cargo.lock'),
    ('Cargo.toml', 'Cargo.toml'),
]
PACKAGE_PINS_RELATIVE = 'docs/dynark/part5/v3-fresh-package-v2-package-pins.json'
PACKAGE_PINS_SCHEMA = 'part5-v3-fresh-package-output-pins-v2'
FREEZE_SCHEMA = 'credential-v3-frozen-holdout-boundary-v1'
TEMPLATE_FIELDS = (
    'package_digest', 'setup_manifest_path', 'setup_manifest_sha256',
    'package_check_path', 'package_check_sha256', 'r1cs_path', 'wasm_path',
    'profile_path', 'input_map_path', 'input_map_sha256',
)


def _sha(value):
    return (type(value) is str and len(value) == 64
            and all(char in '0123456789abcdef' for char in value))


def private_directory(path):
    path = Path(path)
    info = path.lstat()
    if (not path.is_absolute() or path.resolve() != path
            or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('canonical private artifact directory required')
    return path


def private_file(path, maximum, expected_sha256=None):
    path = Path(path)
    info = path.lstat()
    if (not path.is_absolute() or path.resolve() != path
            or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
            or not 0 < info.st_size <= maximum):
        raise ValueError('owner-only bounded artifact required')
    raw = path.read_bytes()
    if expected_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError('pinned private artifact digest mismatch')
    return raw


def pinned_source(path, expected_sha256, maximum=1024 * 1024):
    path = Path(path)
    if not _sha(expected_sha256):
        raise ValueError('explicit source SHA-256 required')
    info = path.lstat()
    if (not path.is_absolute() or path.resolve() != path
            or not stat.S_ISREG(info.st_mode) or info.st_size <= 0
            or info.st_size > maximum or info.st_uid != os.getuid()):
        raise ValueError('canonical bounded pinned source required')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError('pinned source digest mismatch')
    return path


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON field')
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=unique)


def proof_source_identity(root=None):
    root = Path(root) if root is not None else ROOT
    hasher = hashlib.sha256(b'dynark-v3-proof/source-closure/v2')
    for name, relative in SOURCE_FILES:
        data = (root / SOURCE / relative).read_bytes()
        hasher.update(len(name).to_bytes(4, 'big'))
        hasher.update(name.encode())
        hasher.update(len(data).to_bytes(8, 'big'))
        hasher.update(data)
    return hasher.hexdigest()


def _canonical_artifact_path(value, field):
    if type(value) is not str or not value:
        raise ValueError(f'{field} required')
    path = Path(value)
    if not path.is_absolute() or str(path) != value or path.resolve() != path:
        raise ValueError(f'canonical absolute {field} required')
    return value


def _package_pin_record(path, expected_sha256):
    path = Path(path)
    expected_path = ROOT / PACKAGE_PINS_RELATIVE
    if (not path.is_absolute() or path != expected_path
            or path.resolve() != path or not _sha(expected_sha256)):
        raise ValueError('exact external v2 package-pins path and digest required')
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_size <= 0
            or info.st_size > 65536 or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) not in (0o600, 0o644)):
        raise ValueError('bounded external v2 package-pins record required')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError('external v2 package-pins digest mismatch')
    record = _json(raw)
    if (type(record) is not dict
            or set(record) != {
                'schema', 'source_commit', 'input_pins', 'setup_manifest',
                'package_check_report', 'ordinary_vk', 'proving_key',
                'package_identity', 'setup_launcher', 'semantic_hashes',
                'census', 'ordered_public_inputs',
            }
            or record.get('schema') != PACKAGE_PINS_SCHEMA):
        raise ValueError('external v2 package-pins schema required')
    return record


def _match_pin_reference(record, field, root, packet_path, packet_sha):
    reference = record.get(field)
    if (type(reference) is not dict or set(reference) != {'path', 'sha256'}
            or not _sha(reference.get('sha256'))):
        raise ValueError(f'external v2 {field} pin required')
    relative = reference['path']
    if (type(relative) is not str or not relative or Path(relative).is_absolute()
            or any(part.startswith('.') for part in relative.split('/'))
            or str(Path(relative)) != relative
            or str(root / relative) != packet_path
            or reference['sha256'] != packet_sha):
        raise ValueError(f'v2 package pin differs from packet {field}')


def _case(directory, version, frozen_at):
    directory = private_directory(directory)
    files = {
        'wtns': directory / 'output.wtns',
        'public': directory / 'public.json',
        'input': directory / 'input.json',
    }
    hashes = {}
    for kind, path in files.items():
        raw = private_file(path, 32 * 1024 * 1024 if kind == 'wtns' else 65536)
        if kind == 'input' and path.stat().st_ctime_ns <= frozen_at:
            raise ValueError('heldout input must follow freeze receipt')
        hashes[kind] = hashlib.sha256(raw).hexdigest()
    return {
        'wtns_path': str(files['wtns']),
        'wtns_sha256': hashes['wtns'],
        'public_path': str(files['public']),
        'public_sha256': hashes['public'],
        'input_path': str(files['input']),
        'input_sha256': hashes['input'],
        'issuer_version': 1,
        'policy_version': 1,
        'allocation_epoch': 1,
        'root_version': version,
    }


def build(template_path, template_sha256, freeze_path, freeze_sha256, pairs,
          package_pins_path, package_pins_sha256, proof_binary_sha256,
          input_preparer_path, input_preparer_sha256):
    template_raw = private_file(template_path, 262144, template_sha256)
    template = _json(template_raw)
    if type(template) is not dict or any(key not in template for key in TEMPLATE_FIELDS):
        raise ValueError('complete externally pinned v2 packet template required')
    selected = {key: template[key] for key in TEMPLATE_FIELDS}
    if (not _sha(selected['package_digest'])
            or any(not _sha(selected[key]) for key in (
                'setup_manifest_sha256', 'package_check_sha256', 'input_map_sha256'))):
        raise ValueError('explicit package, setup, and input-map pins required')
    for key in ('setup_manifest_path', 'package_check_path', 'r1cs_path',
                'wasm_path', 'profile_path', 'input_map_path'):
        _canonical_artifact_path(selected[key], key)

    pins_path = Path(package_pins_path)
    record = _package_pin_record(pins_path, package_pins_sha256)
    package_identity = record.get('package_identity')
    if (type(package_identity) is not dict
            or set(package_identity) != {
                'matrix', 'circuit', 'pk', 'engine_extended_vk', 'package',
            }
            or package_identity.get('package') != selected['package_digest']):
        raise ValueError('external v2 package identity differs from template')
    _match_pin_reference(record, 'setup_manifest', ROOT,
                         selected['setup_manifest_path'], selected['setup_manifest_sha256'])
    _match_pin_reference(record, 'package_check_report', ROOT,
                         selected['package_check_path'], selected['package_check_sha256'])

    if not _sha(proof_binary_sha256):
        raise ValueError('explicit v2 proof binary SHA-256 required')
    if not _sha(input_preparer_sha256):
        raise ValueError('explicit v2 heldout input-preparer SHA-256 required')
    preparer_path = pinned_source(input_preparer_path, input_preparer_sha256)

    freeze_raw = private_file(freeze_path, 65536, freeze_sha256)
    frozen = _json(freeze_raw)
    source_id = proof_source_identity()
    frozen_at = frozen.get('frozen_at_unix_ns') if type(frozen) is dict else None
    if (type(frozen) is not dict
            or frozen.get('schema') != FREEZE_SCHEMA
            or type(frozen_at) is not int or not 0 < frozen_at < 2**64
            or frozen.get('setup_manifest_sha256') != selected['setup_manifest_sha256']
            or frozen.get('package_digest') != selected['package_digest']
            or frozen.get('proof_binary_sha256') != proof_binary_sha256
            or frozen.get('proof_source_identity') != source_id
            or frozen.get('input_preparer_sha256') != input_preparer_sha256
            or any(not _sha(frozen.get(key)) for key in (
                'client_sha256', 'adapter_sha256',
                'application_source_sha256', 'application_elf_sha256'))):
        raise ValueError('v2 heldout freeze identity mismatch')

    if type(pairs) is not list or not 1 <= len(pairs) <= 16:
        raise ValueError('bounded heldout pair list required')
    packet_pairs = []
    for index, pair in enumerate(pairs):
        expected_name = f'holdout_{index}'
        if (type(pair) is not dict or set(pair) != {'name', 'base', 'near'}
                or pair['name'] != expected_name):
            raise ValueError('ordered heldout pair names required')
        packet_pairs.append({
            'name': expected_name,
            'base': _case(pair['base'], 1, frozen_at),
            'near': _case(pair['near'], 2, frozen_at),
        })

    packet = {
        **selected,
        'schema': 'credential-v3-bounded-proof-contexts-v1',
        'synthetic_only': True,
        'application_verified': False,
        'cohort': 'heldout-v1',
        'proof_source_identity': source_id,
        'proof_binary_sha256': proof_binary_sha256,
        'package_pins_path': str(pins_path),
        'package_pins_sha256': package_pins_sha256,
        'input_preparer_path': str(preparer_path),
        'input_preparer_sha256': input_preparer_sha256,
        'freeze_receipt_path': str(Path(freeze_path)),
        'freeze_receipt_sha256': freeze_sha256,
        'pairs': packet_pairs,
        'pilot_pair': 'holdout_0',
    }
    return packet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template', type=Path, required=True)
    parser.add_argument('--template-sha256', required=True)
    parser.add_argument('--freeze-receipt', type=Path, required=True)
    parser.add_argument('--freeze-sha256', required=True)
    parser.add_argument('--package-pins', type=Path, required=True)
    parser.add_argument('--package-pins-sha256', required=True)
    parser.add_argument('--proof-binary-sha256', required=True)
    parser.add_argument('--input-preparer', type=Path, required=True)
    parser.add_argument('--input-preparer-sha256', required=True)
    parser.add_argument('--pair', nargs=3, action='append', metavar=('NAME', 'BASE', 'NEAR'),
                        required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    pairs = [{'name': name, 'base': Path(base), 'near': Path(near)}
             for name, base, near in args.pair]
    packet = build(
        args.template, args.template_sha256, args.freeze_receipt,
        args.freeze_sha256, pairs, args.package_pins,
        args.package_pins_sha256, args.proof_binary_sha256,
        args.input_preparer, args.input_preparer_sha256,
    )
    private_directory(args.output.parent)
    raw = (json.dumps(packet, sort_keys=True, separators=(',', ':')) + '\n').encode()
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print(hashlib.sha256(raw).hexdigest())


if __name__ == '__main__':
    main()
