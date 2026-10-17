#!/usr/bin/env python3
"""Bind a signed two-leaf training cohort to one staged request fixture.

The output is private input for the matched k=1 proof workflow. It does not
replace finalized RPC verification at submission or authorize a proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tools.part5.credential_profile import admit_certificate, public_bindings
from tools.part5.registry_v3_vectors import rebuild, siblings


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def private_dir(path, empty=False):
    path = Path(path)
    info = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700 or (empty and any(path.iterdir()))):
        raise ValueError('owner-only canonical directory required')
    return path


def private_file(path, cap):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or not 0 < info.st_size <= cap):
        raise ValueError('owner-only bounded source file required')
    identity = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_uid,
                            row.st_nlink, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        if identity(os.fstat(stream.fileno())) != identity(info):
            raise ValueError('source changed at open')
        raw = stream.read(cap + 1)
        if identity(os.fstat(stream.fileno())) != identity(info):
            raise ValueError('source changed during read')
    if len(raw) != info.st_size or identity(path.lstat()) != identity(info):
        raise ValueError('source file changed')
    return raw


def write_new(directory, name, raw):
    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return digest(raw)


def prepare(stage_root, cohort_root, context_path, output, exporter):
    stage_root, cohort_root = private_dir(stage_root), private_dir(cohort_root)
    output = private_dir(output, empty=True)
    context_path, exporter = Path(context_path), Path(exporter)
    if private_dir(context_path.parent) == output:
        raise ValueError('separate context and output required')
    context = json.loads(private_file(context_path, 8192))
    staged = json.loads(private_file(stage_root / 'stage-report.json', 65536))
    plan = json.loads(private_file(stage_root / 'plan.json', 8192))
    receipt_raw = private_file(cohort_root / 'cohort-receipt.json', 8192)
    receipt = json.loads(receipt_raw)
    membership_raw = private_file(cohort_root / 'membership.json', 16384)
    membership = json.loads(membership_raw)
    own = private_file(cohort_root / 'credential.der', 952)
    other = private_file(cohort_root / 'unrelated.der', 952)
    holder_pem = private_file(cohort_root / 'holder.pem', 4096)
    modulus_raw = private_file(cohort_root / 'issuer-modulus.bin', 256)
    config = private_file(stage_root / 'config.bin', 381)
    exporter_info = exporter.lstat()
    if (not exporter.is_absolute() or exporter.resolve(strict=True) != exporter
            or not stat.S_ISREG(exporter_info.st_mode) or exporter_info.st_uid != os.getuid()
            or exporter_info.st_nlink != 1 or not exporter_info.st_mode & 0o111
            or exporter_info.st_mode & 0o022 or not 0 < exporter_info.st_size <= 64 * 1024 * 1024):
        raise ValueError('pinned exporter binary required')
    exporter_raw = exporter.read_bytes()
    if (staged.get('schema') != 'part5-v3-local-stage-v1' or staged.get('passed') is not True
            or staged.get('registry_history_authenticated') is not True
            or staged.get('allocation_history_authenticated') is not True
            or staged.get('application_effect') is not False
            or receipt.get('schema') != 'v3-two-signed-training-credentials-v1'
            or context.get('schema') != 'part5-v3-local-training-context-v1'
            or context.get('training_only') is not True
            or context.get('initial_allocations', {}).get('cohort_receipt_sha256') != digest(receipt_raw)
            or context['initial_allocations'].get('membership_sha256') != digest(membership_raw)
            or staged['account_sha256'][0] != digest(config)
            or staged['signed_history_sha256'] != digest(private_file(stage_root / 'signed-history.json', 65536))
            or staged['initial_allocations_sha256'] != digest(private_file(stage_root / 'initial-allocations.json', 8192))
            or len(own) != 952 or len(other) != 952 or len(modulus_raw) != 256
            or digest(own) != receipt['credential_sha256']
            or digest(other) != receipt['unrelated_credential_sha256']
            or digest(membership_raw) != receipt['membership_sha256']
            or len(exporter_raw) != exporter_info.st_size):
        raise ValueError('signed training stage/cohort identity mismatch')
    modulus = int.from_bytes(modulus_raw, 'big')
    parsed = admit_certificate(own, modulus)
    other_parsed = admit_certificate(other, modulus)
    issuer, policy = public_bindings(parsed, modulus)
    other_issuer, _ = public_bindings(other_parsed, modulus)
    own_digest = hashlib.sha256(parsed['tbs']).digest()
    other_digest = hashlib.sha256(other_parsed['tbs']).digest()
    slot, unrelated_slot = membership['slot'], membership['unrelated_slot']
    tree = rebuild([(slot, own_digest, True), (unrelated_slot, other_digest, True)])
    if (issuer != other_issuer or issuer != membership['issuer_hash']
            or policy != membership['policy_hash']
            or membership['active_root'] != tree[-1][0]
            or membership['active_siblings'] != [int(x, 16) for x in siblings(tree, slot)]
            or context['root'] != tree[-1][0].to_bytes(32, 'big').hex()
            or context['issuer_hash'] != issuer.to_bytes(32, 'big').hex()
            or context['policy_id'] != policy.to_bytes(32, 'big').hex()
            or context['initial_allocations']['own_tbs_digest'] != own_digest.hex()
            or context['initial_allocations']['unrelated_tbs_digest'] != other_digest.hex()
            or context['initial_allocations']['slot'] != slot
            or bytes(plan['root']) != tree[-1][0].to_bytes(32, 'big')
            or bytes(plan['issuer_hash']) != issuer.to_bytes(32, 'big')
            or bytes(plan['policy_id']) != policy.to_bytes(32, 'big')
            or config[332:364] != bytes(plan['root'])
            or config[104:136] != bytes(plan['genesis'])):
        raise ValueError('signed membership or finalized request context mismatch')
    last = next((row for row in reversed(staged['transactions'])
                 if row['scenario'] == 'v3-bind-head'), None)
    now = last['blockTime'] if last else None
    if type(now) is not int or now <= 0 or now >= plan['deadline']:
        raise ValueError('staged request clock invalid')
    params = {name: bytes(plan[name]).hex() for name in
              ('program', 'genesis', 'creator', 'nonce', 'recipient')}
    params['program_id'] = params.pop('program')
    params.update(payload=bytes(plan['payload']).hex(), request_type=1,
                  deadline=plan['deadline'], now=now,
                  exporter_sha256=digest(exporter_raw))
    encoded = lambda value: (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    outputs = {'credential.der': own, 'unrelated.der': other, 'holder.pem': holder_pem,
               'issuer-modulus.bin': modulus_raw, 'membership.json': membership_raw,
               'config.bin': config, 'parameters.json': encoded(params)}
    hashes = {name: write_new(output, name, raw) for name, raw in outputs.items()}
    result = {'schema':'part5-v3-matched-training-source-v1', 'training_only':True,
              'live_state_authenticated':False,
              'stage_report_sha256':digest(private_file(stage_root / 'stage-report.json', 65536)),
              'signed_history_sha256':staged['signed_history_sha256'],
              'cohort_receipt_sha256':digest(receipt_raw), 'source_sha256':hashes}
    write_new(output, 'source-receipt.json', encoded(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('stage_root', 'cohort_root', 'context_path', 'output', 'exporter'):
        parser.add_argument('--' + name.replace('_', '-'), required=True, type=Path)
    args = parser.parse_args()
    result = prepare(**vars(args))
    print(json.dumps({'schema':result['schema'], 'stage_report_sha256':result['stage_report_sha256'],
                      'source_receipt_sha256':digest(private_file(args.output / 'source-receipt.json', 8192))}))


if __name__ == '__main__':
    main()
