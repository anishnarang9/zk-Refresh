#!/usr/bin/env python3
"""Build a complete changed-root training input for an unchanged request action.

Usage: python this-file SOURCE BASE_OUTPUT FRESH_NEAR_OUTPUT. All directories
are canonical, owner0700. SOURCE contains the original six private input files
plus unrelated.der, signed by the same enrolled issuer. This builds no WTNS or
proof and authenticates no live application or registry publication state.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

source_file = Path(__file__).with_name('prepare_v3_request_bound_training.py')
spec = importlib.util.spec_from_file_location('base_preparer', source_file)
base_preparer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base_preparer)

from tools.part5 import prepare_v3_request_fixture as bridge
from tools.part5.credential_profile import admit_certificate, public_bindings
from tools.part5.registry_v3_vectors import rebuild, siblings


def one_sibling_delta(base, near):
    if (type(base) is not dict or type(near) is not dict
            or set(base) != set(near) or base.get('root') == near.get('root')
            or any(base[key] != near[key] for key in base if key not in ('root', 'siblings'))
            or type(base.get('siblings')) is not list
            or type(near.get('siblings')) is not list
            or len(base['siblings']) != 10 or len(near['siblings']) != 10
            or sum(a != b for a, b in zip(base['siblings'], near['siblings'])) != 1):
        raise ValueError('exact same-action one-sibling transition required')


def prepare(source, base, output):
    try:
        return _prepare(source, base, output)
    except Exception:
        raise ValueError('request-bound near preparation rejected') from None


def _prepare(source, base, output):
    source_info = base_preparer._directory(source)
    base_preparer._directory(base)
    output_info = base_preparer._directory(output)
    if source == base or output in (source, base) or any(output.iterdir()):
        raise ValueError()
    _read = base_preparer._read
    raw = {name: _read(source / name, cap) for name, cap in {
        'credential.der': 952, 'unrelated.der': 952, 'holder.pem': 4096,
        'issuer-modulus.bin': 256, 'config.bin': 381, 'membership.json': 16384,
        'parameters.json': 8192}.items()}
    if any(len(raw[name]) != size for name, size in
           [('credential.der', 952), ('unrelated.der', 952),
            ('issuer-modulus.bin', 256), ('config.bin', 381)]):
        raise ValueError()
    receipt = base_preparer._json(_read(base / 'training-receipt.json', 8192))
    if (receipt.get('schema') != 'v3-request-bound-training-input-v1'
            or receipt.get('membership_sha256') != hashlib.sha256(raw['membership.json']).hexdigest()
            or receipt.get('parameters_sha256') != hashlib.sha256(raw['parameters.json']).hexdigest()
            or receipt.get('config_sha256') != hashlib.sha256(raw['config.bin']).hexdigest()):
        raise ValueError()
    artifacts = receipt['artifact_sha256']
    base_input = base_preparer._json(_read(base / 'input.json', 65536,
                                          expected=artifacts['input.json']))
    base_public = base_preparer._json(_read(base / 'public.json', 1024,
                                           expected=artifacts['public.json']))
    _read(base / 'request.bin', 1918, expected=artifacts['request.bin'])
    coordinates = _read(base / 'input-coordinates.bin', 4096)
    internal = _read(base / 'internal-coordinate.bin', 4)
    membership = base_preparer._json(raw['membership.json'])
    modulus = int.from_bytes(raw['issuer-modulus.bin'], 'big')
    own = admit_certificate(raw['credential.der'], modulus)
    unrelated = admit_certificate(raw['unrelated.der'], modulus)
    issuer, policy = public_bindings(own, modulus)
    other_issuer, _ = public_bindings(unrelated, modulus)
    own_digest = hashlib.sha256(own['tbs']).digest()
    other_digest = hashlib.sha256(unrelated['tbs']).digest()
    slot, other_slot = membership['slot'], membership['unrelated_slot']
    if (other_issuer != issuer or own['aki'] != unrelated['aki']
            or membership['issuer_hash'] != issuer or membership['policy_hash'] != policy
            or membership['own_tbs_digest'] != own_digest.hex()
            or membership['unrelated_tbs_digest'] != other_digest.hex()
            or type(slot) is not int or not 0 <= slot < 1024 or other_slot != slot ^ 1):
        raise ValueError()
    for name, active in [('active', True), ('unrelated', False)]:
        levels = rebuild([(slot, own_digest, True), (other_slot, other_digest, active)])
        if (membership[name + '_root'] != levels[-1][0]
                or membership[name + '_siblings'] !=
                [int(word, 16) for word in siblings(levels, slot)]):
            raise ValueError()
    if (type(base_public) is not list or len(base_public) != 6
            or base_public != [base_input[name] for name in
                               ('root', 'issuerHash', 'notBefore', 'notAfter', 'actionHash', 'policyHash')]
            or base_public != [str(v) for v in (membership['active_root'], issuer,
                          own['not_before'], own['not_after'], int(base_public[4]), policy)]):
        raise ValueError()
    action = int(base_public[4]).to_bytes(32, 'big')
    q1 = bridge.build_v3q1(raw['credential.der'], modulus, source / 'holder.pem',
                           action, membership, root_kind='unrelated')
    worker = base_preparer.load_worker()
    response = worker.build(q1)
    if type(response) is not bytes or len(response) != 24495 or response[:4] != b'V3I1':
        raise ValueError()
    fields = [int.from_bytes(response[i:i + 32], 'little') for i in range(463, 24495, 32)]
    expected = [membership['unrelated_root'], issuer, own['not_before'],
                own['not_after'], int.from_bytes(action, 'big'), policy]
    if fields[:6] != expected or len(fields) != 751 or any(value >= base_preparer.FR for value in fields):
        raise ValueError()
    near_input, cursor = {}, 0
    for name, count in worker.INPUT_FIELDS:
        values = [str(value) for value in fields[cursor:cursor + count]]
        near_input[name] = values[0] if count == 1 else values
        cursor += count
    if cursor != 751:
        raise ValueError()
    one_sibling_delta(base_input, near_input)
    encoded = base_preparer._encoded
    input_json, public_json = encoded(near_input), encoded([str(value) for value in expected])
    near_receipt = {'schema': 'v3-request-bound-near-training-input-v1',
                    'training_only': True, 'registry_history_authenticated': False,
                    'live_state_authenticated': False, 'proof_created': False,
                    'base_receipt_sha256': hashlib.sha256(_read(base / 'training-receipt.json', 8192)).hexdigest(),
                    'unrelated_credential_sha256': hashlib.sha256(raw['unrelated.der']).hexdigest(),
                    'membership_sha256': hashlib.sha256(raw['membership.json']).hexdigest(),
                    'action_hash': str(expected[4]),
                    'artifact_sha256': {name: hashlib.sha256(data).hexdigest()
                                        for name, data in [('request.bin', q1),
                                                           ('input.json', input_json),
                                                           ('public.json', public_json)]}}
    files = {'request.bin': q1, 'summary.bin': response[4:463], 'input.json': input_json,
             'public.json': public_json, 'input-coordinates.bin': coordinates,
             'internal-coordinate.bin': internal,
             'training-receipt.json': encoded(near_receipt)}
    if base_preparer._identity(base_preparer._directory(source)) != base_preparer._identity(source_info):
        raise ValueError()
    if base_preparer._identity(base_preparer._directory(output)) != base_preparer._identity(output_info):
        raise ValueError()
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    created = []
    try:
        for name, data in files.items():
            target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=fd)
            created.append(name)
            with os.fdopen(target, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        os.fsync(fd)
    except Exception:
        for name in created:
            os.unlink(name, dir_fd=fd)
        raise
    finally:
        os.close(fd)
    return near_receipt


if __name__ == '__main__':
    try:
        if len(sys.argv) != 4:
            raise ValueError()
        prepare(*(Path(value) for value in sys.argv[1:]))
    except Exception:
        raise SystemExit(2) from None
