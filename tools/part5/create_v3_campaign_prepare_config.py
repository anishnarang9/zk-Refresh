#!/usr/bin/env python3
"""Create a pinned, fresh local v3 prepare config without historical fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

from harness.tests import queue_v3_build_prep
from harness.tests import queue_v3_local_prepare


REPO = Path(__file__).resolve().parents[2]
PART5 = REPO / 'artifacts/dynark/part5'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pin_file(path, cap):
    path = Path(path)
    raw = queue_v3_build_prep.regular(path, cap)
    expected = digest(raw)
    if queue_v3_local_prepare.checked(path, expected, cap) != raw:
        raise ValueError('input changed while pinning')
    return raw, expected


def validate_build_plan(plan):
    if (not isinstance(plan, dict) or plan.get('schema') != 1
            or plan.get('status') != 'prepared_only' or plan.get('cwd') != str(REPO)):
        raise ValueError('reviewed v3 build plan required')
    argv = plan.get('argv')
    if (not isinstance(argv, list) or argv.count('--sbf-out-dir') != 1
            or argv.index('--sbf-out-dir') + 1 >= len(argv)):
        raise ValueError('reviewed SBF build plan required')
    sbf_output = Path(argv[argv.index('--sbf-out-dir') + 1])
    build_output = sbf_output.parent
    if (sbf_output.name != 'elf'
            or not build_output.name.startswith('application-v3-sbf-')):
        raise ValueError('versioned v3 SBF output required')

    # prepare_build requires a not-yet-created build output. Reconstruct its
    # full plan against a fresh sentinel, then substitute the registered SBF
    # output path so an already-built ELF can still be admitted.
    sentinel = PART5 / ('application-v3-sbf-plan-check-' + uuid.uuid4().hex)
    expected = queue_v3_build_prep.prepare_build(
        REPO, plan['source_manifest'], Path(argv[0]), plan['builder_sha256'], sentinel)
    expected['argv'][expected['argv'].index('--sbf-out-dir') + 1] = str(sbf_output)
    if expected != plan:
        raise ValueError('build plan differs from current source/tool inputs')


def fresh_output(path):
    path = Path(path)
    if (not path.is_absolute() or not path.is_relative_to(PART5)
            or path == PART5 or path.resolve() != path
            or path.parent.resolve(strict=True) != path.parent
            or not stat.S_ISDIR(path.parent.lstat().st_mode)
            or path.exists() or path.is_symlink()):
        raise ValueError('fresh canonical prepare-config output required')
    return path


def create(args):
    build_plan = Path(args.build_plan)
    elf = Path(args.elf)
    validator = Path(args.validator)
    build_plan_raw, build_plan_sha256 = pin_file(build_plan, 65536)
    plan = queue_v3_local_prepare.decode_json(build_plan_raw)
    validate_build_plan(plan)
    _, elf_sha256 = pin_file(elf, 4 * 1024 * 1024)
    _, validator_sha256 = pin_file(validator, 128 * 1024 * 1024)
    config = {
        'schema': 1,
        'scope': 'part5-v3-local-prepare',
        'build_plan': str(build_plan),
        'build_plan_sha256': build_plan_sha256,
        'elf': str(elf),
        'elf_sha256': elf_sha256,
        'validator': str(validator),
        'validator_sha256': validator_sha256,
        'program': args.program,
        'mint': args.mint,
        'runtime_output': args.runtime_output,
        'control_output': args.control_output,
        'outer_limits_required': dict(queue_v3_local_prepare.LIMITS),
    }

    # Reuse the exact admission gate consumed by queue_v3_local_prepare. It
    # checks current source/Cargo pins, the plan command, all artifact hashes,
    # canonical keys, and fresh disjoint runtime/control paths.
    queue_v3_local_prepare.admit(config)

    output = fresh_output(args.output)
    for runtime_output in (Path(args.runtime_output), Path(args.control_output)):
        if (output == runtime_output or output in runtime_output.parents
                or runtime_output in output.parents):
            raise ValueError('config and runtime/control outputs must be disjoint')
    raw = (json.dumps(config, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return digest(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-plan', required=True)
    parser.add_argument('--elf', required=True)
    parser.add_argument('--validator', required=True)
    parser.add_argument('--program', required=True)
    parser.add_argument('--mint', required=True)
    parser.add_argument('--runtime-output', required=True)
    parser.add_argument('--control-output', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    config_sha256 = create(args)
    print(json.dumps({'path': args.output, 'config_sha256': config_sha256}))


if __name__ == '__main__':
    raise SystemExit(main())
