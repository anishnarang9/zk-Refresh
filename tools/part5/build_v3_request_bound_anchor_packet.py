#!/usr/bin/env python3
"""Pin one staged v3 request, finalized unrelated root, and complete witness pair.

This builds a private proof-runner packet. Its stage hashes are caller supplied
artifact evidence; the runner does not turn this packet into chain authority.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

ROOT = Path(__file__).resolve().parents[2]
SOURCE = 'circuits/credential-v3-bounded/qualification/proof-runner-v1'
SOURCE_FILES = [('main.rs', 'src/main.rs'), ('artifacts.rs', 'src/artifacts.rs'),
                ('context.rs', 'src/context.rs'), ('ordinary.rs', 'src/ordinary.rs'),
                ('Cargo.lock', 'Cargo.lock'), ('Cargo.toml', 'Cargo.toml')]


def private_directory(path):
    path = Path(path)
    info = path.lstat()
    if (not path.is_absolute() or path.resolve() != path or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('canonical private artifact directory required')
    return path


def private_file(path, maximum):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= maximum):
        raise ValueError('owner-only bounded artifact required')
    return path.read_bytes()


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def proof_source_identity():
    h = hashlib.sha256(b'dynark-v3-proof/source-closure/v1')
    for name, relative in SOURCE_FILES:
        data = (ROOT / SOURCE / relative).read_bytes()
        h.update(len(name).to_bytes(4, 'big'))
        h.update(name.encode())
        h.update(len(data).to_bytes(8, 'big'))
        h.update(data)
    return h.hexdigest()


def build(stage_root, transition_root, base, near, old_packet):
    for directory in (stage_root, transition_root, base, near, old_packet.parent):
        private_directory(directory)
    staged = json.loads(private_file(stage_root / 'stage-report.json', 65536))
    changed = json.loads(private_file(transition_root / 'transition-report.json', 65536))
    template = json.loads(private_file(old_packet, 262144))
    plan = json.loads(private_file(stage_root / 'plan.json', 8192))
    base_public = json.loads(private_file(base / 'public.json', 1024))
    near_public = json.loads(private_file(near / 'public.json', 1024))
    if (staged.get('schema') != 'part5-v3-local-stage-v1' or staged.get('passed') is not True
            or staged.get('application_effect') is not False
            or changed.get('schema') != 'part5-v3-unrelated-local-transition-v1'
            or changed.get('passed') is not True
            or changed.get('request_unconsumed') is not True
            or changed.get('upstream_source_authentication') is not True
            or changed.get('application_effect') is not False
            or changed.get('stage_report_sha256') != digest(stage_root / 'stage-report.json')
            or changed.get('stage_plan_sha256') != digest(stage_root / 'plan.json')
            or changed.get('program') != staged.get('program')
            or changed.get('genesis') != staged.get('genesis')
            or changed.get('loaded_program', {}).get('elf_sha256')
               != staged.get('loaded_program', {}).get('elf_sha256')
            or len(base_public) != 6 or len(near_public) != 6
            or base_public[1:] != near_public[1:]
            or changed['base_root'] != int(base_public[0]).to_bytes(32, 'big').hex()
            or changed['near_root'] != int(near_public[0]).to_bytes(32, 'big').hex()
            or bytes(plan['root']).hex() != changed['base_root']
            or digest(stage_root / 'request.bin') != digest(transition_root / 'request.bin')
            or digest(stage_root / 'queue.bin') != digest(transition_root / 'queue.bin')
            or digest(stage_root / 'request.bin') != staged['account_sha256'][3]
            or changed['account_sha256'][3] != staged['account_sha256'][3]
            or changed['account_sha256'][4] != staged['account_sha256'][4]):
        raise ValueError('exact unconsumed request/root artifact relationship required')
    app = {'program_id': staged['program'], 'genesis_hash': staged['genesis'],
           'loaded_elf_sha256': staged['loaded_program']['elf_sha256'],
           'base_stage_report_sha256': digest(stage_root / 'stage-report.json'),
           'base_config_sha256': digest(stage_root / 'config.bin'),
           'finalized_request_sha256': digest(stage_root / 'request.bin'),
           'request_address': staged['request'],
           'base_finalized_slot': staged['finalized_slot'],
           'near_state_report_sha256': digest(transition_root / 'transition-report.json'),
           'near_config_sha256': digest(transition_root / 'config.bin'),
           'near_finalized_slot': changed['finalized_slot'],
           'base_root': base_public[0], 'near_root': near_public[0],
           'action_hash': base_public[4]}
    packet = {name: template[name] for name in ('package_digest', 'setup_manifest_path',
              'setup_manifest_sha256', 'package_check_path', 'package_check_sha256',
              'r1cs_path', 'wasm_path', 'profile_path', 'input_map_path', 'input_map_sha256')}
    packet.update(schema='credential-v3-request-bound-anchor-v1', synthetic_only=False,
                  application_verified=False, cohort='request-bound-training-v1',
                  proof_source_identity=proof_source_identity(), application_stage=app)
    def case(directory, version):
        files = {'wtns': directory / 'output.wtns', 'public': directory / 'public.json',
                 'input': directory / 'input.json'}
        for kind, path in files.items():
            private_file(path, 32 * 1024 * 1024 if kind == 'wtns' else 65536)
        return {**{kind + '_path': str(path) for kind, path in files.items()},
                **{kind + '_sha256': digest(path) for kind, path in files.items()},
                'issuer_version': 1, 'policy_version': 1,
                'allocation_epoch': 1, 'root_version': version}
    packet['pairs'] = [{'name': 'request_bound_training',
                        'base': case(base, 0), 'near': case(near, 1)}]
    return packet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('stage_root', 'transition_root', 'base', 'near', 'old_packet', 'output'):
        parser.add_argument('--' + name.replace('_', '-'), required=True, type=Path)
    args = parser.parse_args()
    result = build(args.stage_root, args.transition_root, args.base, args.near, args.old_packet)
    private_directory(args.output.parent)
    raw = (json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print(hashlib.sha256(raw).hexdigest())


if __name__ == '__main__':
    main()
