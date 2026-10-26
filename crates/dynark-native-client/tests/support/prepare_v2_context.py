#!/usr/bin/env python3
"""Synthetic-only fixed v2 credential preparation and exact-action signing.

This helper neither generates a witness/proof nor publishes registry state.
ROOT retains synthetic keys in ignored private artifacts for the coordinated
local test. Public context is explicitly shareable; input/certificate/keys are
private. Source/profile pins preserve the accepted fixed-template v2 setup.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import types

REPO = Path(__file__).resolve().parents[4]
PROFILE = 'eb77028b2bd1e324c6ee74c40b43739ec2ce519014f6d04aebe2ca7f82aa1f68'
CIRCUIT = 'da0ad2e5e92f3879951ac3e56e077967eb5fcf6a9814839d680037d620ae9146'
PACKAGE = '04d5ad5776bea03ee014790f54c2572adde796f4d8caeacb88f8a54b0e98b6eb'
SCHEMA = 'de111be59b7a21f5e9aa757506a9ec679d892d6342c88729b6b7997c8b472611'
PUBLIC_SCHEMA = 'dynark-part5-v2-public-context-v1'


def read_bound(path, maximum, private=False):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError('canonical absolute file required')
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise ValueError('file type or bound')
    if private and (stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.getuid()):
        raise ValueError('private file authority')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise ValueError('file changed at open')
        result = handle.read(maximum + 1)
    if len(result) != before.st_size or len(result) > maximum:
        raise ValueError('file changed or bound')
    return result


def pinned(path, expected, maximum, private=False):
    data = read_bound(path, maximum, private)
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('artifact identity')
    return data


def sources():
    pinned(REPO / 'circuits/credential-v2-dev/profile.json', PROFILE, 65536)
    modules = []
    for name, relative, expected in [
        ('profile', 'tools/pre_part5/credential_profile.py', '59ede81c415356efb90517d7dbf62fc75efd1b2fbcb5d41ba8ad74d88147c827'),
        ('witness', 'circuits/credential-v2-dev/qualification/profile_witness.py', 'f0102703c1957ba6c2a1e86460dd25fcab3d4d67f2026d2a554232f0a751bf8b'),
    ]:
        path = REPO / relative
        source = pinned(path, expected, 128 * 1024)
        module = types.ModuleType(name)
        module.__file__ = str(path)
        exec(compile(source, str(path), 'exec'), module.__dict__)
        modules.append(module)
    return modules


def private_root(path):
    path = Path(path)
    metadata = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != os.getuid()):
        raise ValueError('private root authority')
    return path


def write_new(path, data, mode):
    path = Path(path)
    if not path.is_absolute() or path.parent.resolve(strict=True) != path.parent:
        raise ValueError('canonical output parent required')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def context_for(profile, witness, certificate, issuer_modulus, registry):
    parsed = profile.admit_certificate(certificate, issuer_modulus)
    constants = REPO / 'node_modules/circomlib/circuits/poseidon_constants.circom'
    limbs = profile.rsa_limbs(issuer_modulus)
    issuer_hash = witness.poseidon([witness.poseidon(limbs[:8], constants),
        witness.poseidon(limbs[8:], constants)], constants)
    root = witness.registry_root({'tbs': list(parsed['tbs']),
        'slot': registry['slot'], 'siblings': registry['siblings']}, constants)
    return {'schema': PUBLIC_SCHEMA, 'synthetic_only': True,
        'circuit_id': CIRCUIT, 'package_id': PACKAGE, 'semantic_schema': SCHEMA,
        'profile_id': PROFILE, 'issuer_hash': str(issuer_hash), 'root': str(root),
        'not_before': str(parsed['not_before']), 'not_after': str(parsed['not_after'])}


def prepare(private, public):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    profile, witness = sources()
    private, public = Path(private), Path(public)
    if not private.is_absolute() or private.parent.resolve(strict=True) != private.parent:
        raise ValueError('canonical private parent required')
    private.mkdir(mode=0o700)
    private_root(private)
    issuer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    holder = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Exact development profile permits fresh holder/issuer key material while
    # preserving its signed template, dates, organization, group and EKU.
    certificate = profile.sign_certificate(profile.build_tbs(holder.public_key().public_numbers().n), issuer)
    issuer_modulus = issuer.public_key().public_numbers().n
    registry = {'slot': 7, 'siblings': [17 + index for index in range(10)]}
    context = context_for(profile, witness, certificate, issuer_modulus, registry)
    public_bytes = json_bytes(context)
    for name, key in [('issuer', issuer), ('holder', holder)]:
        encoded = key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        write_new(private / f'{name}.synthetic.pem', encoded, 0o600)
    write_new(private / 'certificate.synthetic.der', certificate, 0o600)
    write_new(private / 'registry.synthetic.json', json_bytes(registry), 0o600)
    write_new(private / 'context-binding.json', json_bytes({
        'schema': 'dynark-part5-v2-private-context-v1', 'synthetic_only': True,
        'public_context_sha256': hashlib.sha256(public_bytes).hexdigest()}), 0o600)
    write_new(public, public_bytes, 0o644)
    return context


def sign(private, public, public_sha256, action, action_sha256):
    from cryptography.hazmat.primitives import serialization
    private = private_root(private)
    profile, witness = sources()
    public_bytes = pinned(Path(public), public_sha256, 65536)
    binding = json.loads(read_bound(private / 'context-binding.json', 65536, True))
    if (binding.get('schema') != 'dynark-part5-v2-private-context-v1'
            or binding.get('synthetic_only') is not True
            or binding.get('public_context_sha256') != public_sha256):
        raise ValueError('private context binding')
    certificate = read_bound(private / 'certificate.synthetic.der', 4096, True)
    registry = json.loads(read_bound(private / 'registry.synthetic.json', 65536, True))
    issuer = serialization.load_pem_private_key(read_bound(private / 'issuer.synthetic.pem', 8192, True), None)
    holder = serialization.load_pem_private_key(read_bound(private / 'holder.synthetic.pem', 8192, True), None)
    issuer_modulus = issuer.public_key().public_numbers().n
    context = context_for(profile, witness, certificate, issuer_modulus, registry)
    if json.loads(public_bytes) != context:
        raise ValueError('credential context mismatch')
    parsed = profile.admit_certificate(certificate, issuer_modulus)
    if holder.public_key().public_numbers().n != parsed['holder_modulus']:
        raise ValueError('holder key mismatch')
    action_bytes = pinned(Path(action), action_sha256, 32)
    profile.check_action_field(action_bytes)
    signature = profile.SyntheticSigner(holder).sign_action(action_bytes)
    material = profile.credential_witness_material(parsed, issuer_modulus, action_bytes, signature)
    material.update({'root': int(context['root']), 'issuerHash': int(context['issuer_hash']),
        'slot': registry['slot'], 'siblings': registry['siblings'],
        'pathIndices': [(registry['slot'] >> level) & 1 for level in range(10)]})
    output = private / 'request-input.json'
    write_new(output, json_bytes(witness._strings(material)), 0o600)
    write_new(private / 'request-binding.json', json_bytes({
        'schema': 'dynark-part5-v2-private-request-v1', 'synthetic_only': True,
        'public_context_sha256': public_sha256, 'action_field_sha256': action_sha256,
        'input_sha256': hashlib.sha256(read_bound(output, 65536, True)).hexdigest()}), 0o600)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    prep = sub.add_parser('prepare')
    prep.add_argument('--private-output', type=Path, required=True)
    prep.add_argument('--public-context', type=Path, required=True)
    signing = sub.add_parser('sign')
    signing.add_argument('--private-output', type=Path, required=True)
    signing.add_argument('--public-context', type=Path, required=True)
    signing.add_argument('--public-context-sha256', required=True)
    signing.add_argument('--action-field', type=Path, required=True)
    signing.add_argument('--action-field-sha256', required=True)
    args = parser.parse_args()
    if args.command == 'prepare':
        prepare(args.private_output, args.public_context)
    else:
        sign(args.private_output, args.public_context, args.public_context_sha256,
            args.action_field, args.action_field_sha256)
    print(json.dumps({'operation': args.command, 'passed': True, 'synthetic_only': True}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Avoid raw key/certificate/input values or exception details in logs.
        print(json.dumps({'passed': False, 'error': 'synthetic_context_operation_failed'}))
        raise SystemExit(1)
