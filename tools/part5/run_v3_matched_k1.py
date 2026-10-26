#!/usr/bin/env python3
"""One bounded k=1 training session: fresh inputs through finalized R1 effect.

Run only inside results/dynark/part5/session_runner.py. The stopped R1 ledger
clone is prepared outside the timed command and supplied once per mode. This
command charges source import checks, both complete witnesses, proof work,
adapter encoding, validator restart, submission, reconciliation and cleanup.
It does not establish a heldout result or complete-tree CPU accounting.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tools.part5 import build_v3_request_bound_anchor_packet as packet_builder
from tools.part5 import create_v3_branch_config as branch_config


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            h.update(block)
    return h.hexdigest()


def private_dir(path, empty=False):
    path = Path(path)
    info = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
            or (empty and any(path.iterdir()))):
        raise ValueError('canonical owner-only directory required')
    return path


def write_json(path, value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(raw).hexdigest()


def checked_freeze(path):
    freeze = json.loads(Path(path).read_bytes())
    if freeze.get('schema') != 'part5-v3-matched-k1-freeze-v1':
        raise ValueError('registered k1 freeze required')
    files = freeze.get('files')
    if not isinstance(files, dict) or set(files) != {
        'base_preparer', 'near_preparer', 'witness_js', 'relation_checker',
        'packet_builder', 'config_builder', 'branch_supervisor',
        'proof_binary', 'adapter_binary', 'branch_runner', 'exporter', 'node',
        'old_packet', 'transition_config', 'transition_report',
        'transition_status', 'transition_monitor', 'session_source'}:
        raise ValueError('exact frozen file roles required')
    paths = {}
    for role, row in files.items():
        target = Path(row['path'])
        info = target.lstat()
        if (not target.is_absolute() or target.resolve(strict=True) != target
                or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or digest(target) != row['sha256']):
            raise ValueError('frozen file identity changed: ' + role)
        paths[role] = target
    if paths['session_source'] != Path(__file__).resolve():
        raise ValueError('different session source invoked')
    source = private_dir(freeze['source_dir'])
    if set(freeze['source_sha256']) != {
        'config.bin', 'credential.der', 'unrelated.der', 'holder.pem',
        'issuer-modulus.bin', 'membership.json', 'parameters.json'}:
        raise ValueError('exact source inputs required')
    for name, expected in freeze['source_sha256'].items():
        if digest(source / name) != expected:
            raise ValueError('private source changed')
    stage = private_dir(freeze['stage_root'])
    transition = private_dir(freeze['transition_root'])
    if paths['transition_report'] != transition / 'transition-report.json':
        raise ValueError('transition report role')
    return freeze, paths, source, stage, transition


def child_cpu():
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def run_stage(stages, work, name, argv, environment=None, accepted=(0,)):
    before_cpu = child_cpu()
    start = time.monotonic()
    with (work / (name + '.stdout.log')).open('xb') as out, \
            (work / (name + '.stderr.log')).open('xb') as err:
        completed = subprocess.run([str(x) for x in argv], cwd=REPO,
                                   env=environment, stdin=subprocess.DEVNULL,
                                   stdout=out, stderr=err, check=False)
    stages.append({'stage': name, 'wall_seconds': time.monotonic() - start,
                   'waited_child_cpu_seconds': child_cpu() - before_cpu,
                   'exit_code': completed.returncode})
    if completed.returncode not in accepted:
        raise RuntimeError(name + ' exited ' + str(completed.returncode))


def direct_output(path):
    path = Path(path)
    if (not path.is_absolute() or path.parent != REPO / 'artifacts/dynark/part5'
            or path.exists() or path.is_symlink()):
        raise ValueError('fresh direct private artifact output required')
    return path


def run(mode, freeze_path, clone_report, work, branch_output, control_output):
    os.umask(0o077)
    began = time.monotonic()
    stages = []
    work = private_dir(work, empty=True)
    branch_output = direct_output(branch_output)
    control_output = direct_output(control_output)
    if branch_output == control_output:
        raise ValueError('distinct branch output paths required')
    result = {'schema': 'part5-v3-matched-k1-session-v1', 'mode': mode,
              'passed': False, 'effect_verified': False,
              'freeze_sha256': digest(freeze_path), 'stages': stages,
              'complete_tree_cpu_qualified': False}
    try:
        freeze, paths, source, stage, transition = checked_freeze(freeze_path)
        result['source_sha256'] = freeze['source_sha256']
        clone = json.loads(Path(clone_report).read_bytes())
        if (clone.get('schema') != 'part5-v3-r1-ledger-clone-v1'
                or clone.get('copy_identical') is not True
                or clone.get('transition_report_sha256') != digest(paths['transition_report'])
                or Path(clone['destination']).parent != Path(clone_report).parent):
            raise ValueError('fresh matching R1 clone required')
        private_dir(clone['destination'])
        base = work / 'base'
        near = work / 'near'
        base.mkdir(mode=0o700)
        near.mkdir(mode=0o700)
        run_stage(stages, work, 'base_input', [sys.executable, '-B', paths['base_preparer'],
                  source, base, paths['exporter']])
        run_stage(stages, work, 'near_input', [sys.executable, '-B', paths['near_preparer'],
                  source, base, near])
        for label, directory in [('base', base), ('near', near)]:
            run_stage(stages, work, label + '_witness', [paths['node'], paths['witness_js'], directory])
            run_stage(stages, work, label + '_relation', [sys.executable, '-B',
                      paths['relation_checker'], 'check', directory])
        packet = packet_builder.build(stage, transition, base, near, paths['old_packet'])
        packet_path = work / 'packet.json'
        packet_sha = write_json(packet_path, packet)
        result['packet_sha256'] = packet_sha
        proof_dir = work / 'proof'
        run_stage(stages, work, 'proof', [paths['proof_binary'],
                  'matched-full-k1' if mode == 'full' else 'matched-anchor-k1',
                  packet_path, packet_sha, proof_dir],
                  {**os.environ, 'RAYON_NUM_THREADS': '4'})
        report_path = proof_dir / 'proof-report.json'
        proof_sha = digest(report_path)
        result['proof_report_sha256'] = proof_sha
        adapter_env = {**os.environ, 'M2_V3_MATCHED_MODE':
                       'matched-full-k1' if mode == 'full' else 'matched-anchor-k1',
                       'M2_V3_MATCHED_BASE': str(base), 'M2_V3_MATCHED_NEAR': str(near),
                       'M2_V3_MATCHED_PROOFS': str(proof_dir),
                       'M2_V3_MATCHED_REPORT_SHA256': proof_sha}
        run_stage(stages, work, 'adapter', [paths['adapter_binary'],
                  'private_matched_k1_wires_pass_adapter_and_program_host', '--exact',
                  '--ignored', '--test-threads=1'], adapter_env)
        full_wire = base / 'full-solana-wire.bin'
        near_wire = near / ('full-near-solana-wire.bin' if mode == 'full'
                            else 'anchor-solana-wire.bin')
        result['full_wire_sha256'] = digest(full_wire)
        result['near_wire_sha256'] = digest(near_wire)
        args = argparse.Namespace(mode=mode,
            transition_config=str(paths['transition_config']),
            transition_report=str(paths['transition_report']),
            transition_status=str(paths['transition_status']),
            transition_monitor=str(paths['transition_monitor']),
            clone_report=str(clone_report), full_wire=str(full_wire),
            anchor_wire=str(near_wire),
            full_near_wire=str(near_wire) if mode == 'full' else None,
            full_near_proof_report=str(report_path) if mode == 'full' else None,
            matched_proof_report=str(report_path), runner=str(paths['branch_runner']),
            branch_output=str(branch_output), control_output=str(control_output),
            output=str(work / 'branch-config.json'))
        start = time.monotonic()
        cpu = child_cpu()
        config_sha = branch_config.create(args)
        stages.append({'stage': 'branch_config', 'wall_seconds': time.monotonic() - start,
                       'waited_child_cpu_seconds': child_cpu() - cpu, 'exit_code': 0})
        result['branch_config_sha256'] = config_sha
        branch_env = {**os.environ, 'P5_V3_BRANCH_SUPERVISOR': 'reviewed-r1-clone'}
        run_stage(stages, work, 'application', [sys.executable, '-B', paths['branch_supervisor'],
                  '--config', args.output, '--config-sha256', config_sha], branch_env,
                  accepted=(0, 1))
        status = json.loads((control_output / 'status.json').read_bytes())
        signaled = (status.get('status') == 'failed'
                    and status.get('validator_cleanup', {}).get('exit_code') == -2
                    and status.get('validator_cleanup', {}).get('reaped') is True
                    and status.get('runner_cleanup', {}).get('exit_code') == 0
                    and status.get('runner_cleanup', {}).get('reaped') is True)
        if (not signaled or status.get('branch_verified') is not True
                or status.get('application_effect') is not True
                or status.get('effect_count') != 1
                or status.get('ledger_reuse_requires_review') is not True):
            raise ValueError('finalized matched effect or cleanup policy failed')
        result['supervisor_status'] = status['status']
        result['validator_cleanup'] = status['validator_cleanup']
        result['ledger_reuse_requires_review'] = True
        result['branch_status_sha256'] = digest(control_output / 'status.json')
        result['branch_report_sha256'] = status['branch_report_sha256']
        result['effect_verified'] = True
        result['passed'] = True
    except Exception as error:
        result['error_type'] = type(error).__name__
        result['error_message'] = str(error)[:160]
    finally:
        result['total_command_wall_seconds'] = time.monotonic() - began
        write_json(work / 'session-report.json', result)
    return 0 if result['passed'] else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('full', 'anchor'), required=True)
    parser.add_argument('--freeze', type=Path, required=True)
    parser.add_argument('--clone-report', type=Path, required=True)
    parser.add_argument('--work-root', type=Path, required=True)
    parser.add_argument('--branch-output', type=Path, required=True)
    parser.add_argument('--control-output', type=Path, required=True)
    args = parser.parse_args()
    return run(args.mode, args.freeze, args.clone_report, args.work_root,
               args.branch_output, args.control_output)


if __name__ == '__main__':
    sys.exit(main())
