#!/usr/bin/env python3
"""Build deterministic inputs for the variant-00 expired-status pilot.

This reads retained case evidence and writes only a supervisor config plus an
incomplete finalizer seed. It never starts a proof, validator, build, or RPC.
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

from harness.tests import queue_v3_local_expired_status_negative as supervisor
from tools.part5 import finalize_v3_expired_status_negative as finalizer

SOURCE_PATHS = finalizer.SOURCE_PATHS
SEED_SCHEMA = 'part5-v3-expired-status-finalizer-seed-v1'
JOURNAL_SCHEMA = 'credential-v3-heldout-case-run-journal-v1'
FULL_PROOF_KEY = 'proof/request_bound_training_full_base.proof'
FULL_WIRE_ROLE = 'r0_full_wire'
STEP_NAMES = (
    'positive_full:stage', 'positive_full:source-R0',
    'positive_full:proof-full', 'positive_full:execute',
    'positive_full:expired-status-clone',
)


def canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                        allow_nan=False) + '\n').encode()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _pin(value):
    return (type(value) is str and len(value) == 64
            and all(char in '0123456789abcdef' for char in value))


def _file(path, *, cap, expected=None):
    path = Path(path) if type(path) is str else path
    try:
        meta = path.lstat()
    except (OSError, TypeError):
        raise ValueError('pinned regular input file required') from None
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISREG(meta.st_mode) or meta.st_size > cap):
        raise ValueError('pinned regular input file required')
    raw = path.read_bytes()
    actual = _sha(raw)
    if expected is not None and (not _pin(expected) or actual != expected):
        raise ValueError('input file SHA-256 mismatch')
    return path, raw, actual


def _json(path, *, cap=1024 * 1024, expected=None):
    path, raw, actual = _file(path, cap=cap, expected=expected)
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise ValueError('pinned JSON object required') from None
    if type(value) is not dict:
        raise ValueError('pinned JSON object required')
    return path, value, actual


def _absolute(path, label, *, exists=False):
    path = Path(path) if type(path) is str else path
    try:
        resolved = path.resolve(strict=exists)
    except (OSError, TypeError):
        raise ValueError(f'canonical {label} path required') from None
    if not path.is_absolute() or resolved != path:
        raise ValueError(f'canonical {label} path required')
    return path


def _step(steps, name):
    value = steps.get(name)
    if type(value) is not dict or value.get('status') != 'passed':
        raise ValueError(f'completed {name} journal step required')
    return value


def _artifact(step, path_field, hash_field, *, cap=1024 * 1024):
    path, _, digest = _file(step.get(path_field), cap=cap,
                            expected=step.get(hash_field))
    return {'path': str(path), 'sha256': digest}


def _same(ref, path, digest, message):
    if ref != {'path': str(path), 'sha256': digest}:
        raise ValueError(message)


def _require_loaded(value, elf_sha, genesis, *, require_genesis=True):
    if (type(value) is not dict or value.get('elf_match') is not True
            or value.get('elf_sha256') != elf_sha
            or (require_genesis and value.get('genesis') != genesis)):
        raise ValueError('positive Full loaded identity mismatch')


def _frozen_bundle_source_pins(manifest, freeze, repo):
    """Verify the frozen registry/client bundles and return their source pins."""
    bundles = manifest.get('frozen_bundles')
    identities = freeze.get('identities')
    if (type(bundles) is not dict or set(bundles) != {'registry', 'client'}
            or type(identities) is not dict):
        raise ValueError('frozen registry and client bundle references required')
    source_pins = {}
    for role in ('registry', 'client'):
        rows = bundles[role]
        if type(rows) is not list or not rows or not _pin(identities.get(role)):
            raise ValueError('ordered frozen bundle file references required')
        hashing = hashlib.sha256(b'part5-v3-campaign-identity-bundle-v1\0')
        for row in rows:
            if (type(row) is not dict or type(row.get('path')) is not str
                    or not row['path'] or type(row.get('artifact')) is not dict):
                raise ValueError('repo-relative bundled artifact reference required')
            relative = row['path']
            rel = Path(relative)
            artifact = row['artifact']
            if (rel.is_absolute() or '..' in rel.parts or rel.as_posix() != relative
                    or not _pin(artifact.get('sha256'))):
                raise ValueError('safe frozen bundle source pin required')
            expected_path = repo / rel
            artifact_path = Path(artifact.get('path'))
            if (not expected_path.is_absolute()
                    or expected_path.resolve(strict=True) != expected_path
                    or artifact_path != expected_path):
                raise ValueError('bundle artifact path differs from frozen repository member')
            _, raw, digest = _file(artifact_path, cap=128 * 1024 * 1024,
                                   expected=artifact['sha256'])
            path_bytes = relative.encode()
            hashing.update(len(path_bytes).to_bytes(4, 'big'))
            hashing.update(path_bytes)
            hashing.update(len(raw).to_bytes(8, 'big'))
            hashing.update(raw)
            previous = source_pins.get(relative)
            if previous is not None and previous != digest:
                raise ValueError('conflicting frozen bundle source pins')
            source_pins[relative] = digest
        if hashing.hexdigest() != identities[role]:
            raise ValueError(f'current {role} bundle differs from freeze')
    return source_pins


def build(case_root, run_manifest_path, *, repo_root=None):
    """Return the supervisor config and retained-positive finalizer seed."""
    repo = Path(repo_root) if repo_root is not None else REPO
    repo = _absolute(repo, 'repository root', exists=True)
    case_root = _absolute(case_root, 'case root', exists=True)
    if not case_root.is_dir():
        raise ValueError('case root directory required')

    _, manifest, _ = _json(run_manifest_path, cap=2 * 1024 * 1024)
    if type(manifest.get('variant')) is not int or manifest['variant'] != 0:
        raise ValueError('variant-00 run manifest required')
    _, run_id_doc, _ = _json(case_root / 'run-id.json', cap=1024)
    run_id = run_id_doc.get('run_id')
    if (run_id_doc.get('schema') != 'credential-v3-heldout-run-id-v1'
            or type(run_id) is not str or len(run_id) != 32
            or any(char not in '0123456789abcdef' for char in run_id)):
        raise ValueError('canonical case run id required')
    _, journal, _ = _json(case_root / 'run-journal.json', cap=8 * 1024 * 1024)
    if (journal.get('schema') != JOURNAL_SCHEMA
            or journal.get('manifest_sha256') != _sha(canonical_json(manifest))
            or type(journal.get('steps')) is not dict):
        raise ValueError('run manifest and case journal identity mismatch')
    steps = journal['steps']
    stage_step, source_step, proof_step, execute_step, clone_step = (
        _step(steps, name) for name in STEP_NAMES)

    freeze_path, freeze, freeze_sha = _json(
        manifest.get('freeze_receipt'), cap=1024 * 1024,
        expected=manifest.get('freeze_sha256'))
    if (freeze.get('schema') != 'credential-v3-frozen-holdout-boundary-v1'
            or type(freeze.get('identities')) is not dict):
        raise ValueError('pinned heldout freeze receipt required')
    frozen_files = manifest.get('frozen_files')
    elf_ref = frozen_files.get('loaded_elf') if type(frozen_files) is dict else None
    if type(elf_ref) is not dict or not _pin(elf_ref.get('sha256')):
        raise ValueError('frozen loaded ELF reference required')
    elf_path, _, elf_sha = _file(elf_ref.get('path'), cap=4 * 1024 * 1024,
                                  expected=elf_ref['sha256'])
    if freeze['identities'].get('loaded_elf') != elf_sha:
        raise ValueError('freeze loaded ELF identity mismatch')

    source_manifest_ref = manifest.get('application_source_manifest')
    if type(source_manifest_ref) is not dict:
        raise ValueError('frozen application source manifest required')
    _, app_source, _ = _json(source_manifest_ref.get('path'), cap=2 * 1024 * 1024,
                             expected=source_manifest_ref.get('sha256'))
    app_source_pins = app_source.get('source_pins')
    if type(app_source_pins) is not dict:
        raise ValueError('frozen application source pins required')
    frozen_bundle_pins = _frozen_bundle_source_pins(manifest, freeze, repo)

    stage_config_ref = _artifact(stage_step, 'config', 'config_sha256')
    stage_status_ref = _artifact(stage_step, 'status_path', 'status_sha256')
    stage_report_ref = _artifact(stage_step, 'report', 'report_sha256')
    stage_plan_ref = _artifact(stage_step, 'plan', 'plan_sha256')
    stage_config_path, stage_config, _ = _json(stage_config_ref['path'],
                                                expected=stage_config_ref['sha256'])
    _, stage_status, _ = _json(stage_status_ref['path'], expected=stage_status_ref['sha256'])
    _, stage_report, _ = _json(stage_report_ref['path'], expected=stage_report_ref['sha256'])
    _, stage_plan, _ = _json(stage_plan_ref['path'], expected=stage_plan_ref['sha256'])
    stage_root = _absolute(stage_step.get('root'), 'staged output root', exists=True)
    if (stage_config.get('schema') != 1
            or stage_config.get('scope') != 'part5-v3-local-stage'
            or stage_config.get('stage_output') != str(stage_root)
            or Path(stage_step['report']) != stage_root / 'stage-report.json'
            or Path(stage_step['plan']) != stage_root / 'plan.json'
            or stage_status.get('schema') != 1
            or stage_status.get('scope') != 'part5-v3-local-stage'
            or stage_status.get('stage_verified') is not True
            or stage_status.get('config_sha256') != stage_config_ref['sha256']
            or stage_status.get('stage_report_sha256') != stage_report_ref['sha256']
            or stage_report.get('schema') != 'part5-v3-local-stage-v1'
            or stage_report.get('passed') is not True
            or stage_report.get('loaded_program', {}).get('elf_sha256') != elf_sha):
        raise ValueError('pinned successful fresh staged case00 required')
    program_bytes, genesis_bytes = stage_plan.get('program'), stage_plan.get('genesis')
    if (type(program_bytes) is not list or len(program_bytes) != 32
            or any(type(byte) is not int or not 0 <= byte <= 255 for byte in program_bytes)
            or type(genesis_bytes) is not list or len(genesis_bytes) != 32
            or any(type(byte) is not int or not 0 <= byte <= 255 for byte in genesis_bytes)):
        raise ValueError('pinned stage plan public key arrays required')
    expected_program = supervisor.execute.base.b58(bytes(program_bytes))
    expected_genesis = supervisor.execute.base.b58(bytes(genesis_bytes))
    if (stage_report.get('program') != expected_program
            or stage_report.get('genesis') != expected_genesis):
        raise ValueError('stage plan identities differ from stage report')
    source_ledger = _absolute(stage_config.get('ledger'), 'staged source ledger', exists=True)

    source_ref = _artifact(source_step, 'receipt', 'receipt_sha256')
    _, source_doc, _ = _json(source_ref['path'], expected=source_ref['sha256'])
    if (source_doc.get('schema') != 'credential-v3-heldout-request-source-v1'
            or source_doc.get('variant') != 'R0' or source_doc.get('case_index') != 0
            or source_doc.get('target_variant') != 0
            or source_doc.get('freeze_sha256') != freeze_sha
            or source_doc.get('stage_report_sha256') != stage_report_ref['sha256']
            or source_doc.get('stage_plan_sha256') != stage_plan_ref['sha256']
            or source_doc.get('proof_created') is not False
            or source_doc.get('application_effect') is not False):
        raise ValueError('fresh case00 R0 source receipt mismatch')

    if (proof_step.get('mode') != 'full'
            or clone_step.get('label') != 'expired-status-r0'):
        raise ValueError('variant00 expired-status clone and Full proof steps required')
    clone_ref = _artifact(clone_step, 'receipt', 'receipt_sha256')
    clone_ledger = _absolute(clone_step.get('ledger'), 'expired-status clone ledger', exists=True)
    clone_monitor_ref = _artifact(clone_step, 'monitor', 'monitor_sha256')
    _, clone_doc, _ = _json(clone_ref['path'], expected=clone_ref['sha256'])
    clone_source = clone_doc.get('source')
    if (clone_doc.get('schema') != 'part5-v3-heldout-r0-ledger-clone-v1'
            or clone_doc.get('heldout_acceptance') is not False
            or clone_doc.get('stage_report_sha256') != stage_report_ref['sha256']
            or clone_doc.get('stage_status_sha256') != stage_status_ref['sha256']
            or clone_doc.get('destination') != str(clone_ledger)
            or clone_source != str(source_ledger)
            or clone_doc.get('source_stable') is not True
            or clone_doc.get('copy_identical') is not True
            or clone_doc.get('loaded_identity_rechecked_after_restart') is not False
            or clone_doc.get('application_effect') is not False
            or type(clone_doc.get('excluded_stale_admin_socket')) is not bool
            or not _pin(clone_doc.get('stage_monitor_sha256'))):
        raise ValueError('expired-status clone must be the reviewed stage-source clone')
    if clone_ref['path'] != str(clone_ledger.parent / 'clone-report.json'):
        raise ValueError('expired-status clone receipt must be next to cloned ledger')
    if (clone_monitor_ref['path'] != str(clone_ledger.parent.parent /
            'expired-status-r0-clone-monitor.json')
            or clone_step.get('monitor_owner') !=
            'heldout-v00-positive_full-clone-expired-status-r0'):
        raise ValueError('expired-status clone monitor identity mismatch')

    proof_ref = _artifact(proof_step, 'receipt', 'receipt_sha256', cap=2 * 1024 * 1024)
    _, proof_doc, _ = _json(proof_ref['path'], cap=2 * 1024 * 1024,
                            expected=proof_ref['sha256'])
    proof_artifacts = proof_doc.get('artifacts')
    proof_artifact = proof_artifacts.get(FULL_PROOF_KEY) if type(proof_artifacts) is dict else None
    if type(proof_artifact) is not dict:
        raise ValueError('retained Full proof artifact reference required')
    full_proof_ref = {'path': proof_artifact.get('path'),
                      'sha256': proof_artifact.get('sha256')}
    full_proof_ref = _ref_file(full_proof_ref, cap=32 * 1024 * 1024)
    proof_wire = proof_doc.get('wires', {}).get(FULL_WIRE_ROLE)
    proof_wire_ref = _ref_file(proof_wire, cap=448)
    _same(proof_step.get('wires', {}).get(FULL_WIRE_ROLE),
          Path(proof_wire_ref['path']), proof_wire_ref['sha256'],
          'proof journal Full wire differs from retained receipt')
    if Path(proof_wire_ref['path']).stat().st_size != 448:
        raise ValueError('retained Full proof wire must be 448 bytes')

    execute_config_ref = _artifact(execute_step, 'config', 'config_sha256')
    execute_report_ref = _artifact(execute_step, 'report', 'report_sha256')
    execute_status_ref = _artifact(execute_step, 'status_path', 'status_sha256')
    execute_monitor_ref = _artifact(execute_step, 'monitor', 'monitor_sha256')
    _, execute_config, _ = _json(execute_config_ref['path'],
                                 expected=execute_config_ref['sha256'])
    _, execute_report, _ = _json(execute_report_ref['path'],
                                 expected=execute_report_ref['sha256'])
    _, execute_status, _ = _json(execute_status_ref['path'],
                                 expected=execute_status_ref['sha256'])
    full_wire_ref = {'path': execute_config.get('full_wire'),
                     'sha256': execute_config.get('full_wire_sha256')}
    full_wire_ref = _ref_file(full_wire_ref, cap=448)
    if (execute_config.get('schema') != 1
            or execute_config.get('scope') != 'part5-v3-local-execute'
            or execute_config.get('stage_root') != str(stage_root)
            or execute_config.get('stage_report_sha256') != stage_report_ref['sha256']
            or execute_config.get('stage_plan_sha256') != stage_plan_ref['sha256']
            or execute_config.get('expected_genesis') != expected_genesis
            or execute_config.get('full_wire') != proof_wire_ref['path']
            or execute_config.get('full_wire_sha256') != proof_wire_ref['sha256']):
        raise ValueError('positive Full Execute must use the retained stage and proof wire')
    _same(proof_wire_ref, Path(full_wire_ref['path']), full_wire_ref['sha256'],
          'positive Full and retained proof use a different Full wire')
    if (proof_doc.get('schema') != 'credential-v3-heldout-proof-evidence-v1'
            or proof_doc.get('mode') != 'full' or proof_doc.get('target_variant') != 0
            or proof_doc.get('freeze_sha256') != freeze_sha
            or proof_doc.get('stage_report_sha256') != stage_report_ref['sha256']
            or proof_doc.get('stage_plan_sha256') != stage_plan_ref['sha256']
            or proof_doc.get('source_receipts', {}).get('R0') != source_ref
            or proof_doc.get('proof_created') is not True):
        raise ValueError('retained Full proof provenance mismatch')
    if (execute_report.get('schema') != 'part5-v3-local-execute-v1'
            or execute_report.get('passed') is not True
            or execute_report.get('application_effect') is not True
            or execute_report.get('effect_count') != 1
            or execute_report.get('request_consumed') is not True
            or execute_report.get('proof_mode') != 'Full'
            or execute_report.get('stage_report_sha256') != stage_report_ref['sha256']
            or execute_report.get('stage_plan_sha256') != stage_plan_ref['sha256']
            or execute_report.get('wire_sha256') != full_wire_ref['sha256']
            or execute_report.get('program') != expected_program
            or execute_report.get('genesis') != expected_genesis):
        raise ValueError('successful same-wire positive Full effect required')
    if (execute_status.get('schema') != 1
            or execute_status.get('scope') != 'part5-v3-local-execute'
            or execute_status.get('effect_verified') is not True
            or execute_status.get('application_effect') is not True
            or execute_status.get('effect_outcome') != 'verified'
            or execute_status.get('effect_count') != 1
            or execute_status.get('config_sha256') != execute_config_ref['sha256']
            or execute_status.get('execute_report_sha256') != execute_report_ref['sha256']
            or execute_status.get('execute_output') != execute_config.get('execute_output')):
        raise ValueError('independently supervised positive Full effect required')
    _require_loaded(execute_report.get('loaded_program'), elf_sha, expected_genesis,
                    require_genesis=False)
    _require_loaded(execute_status.get('loaded_program'), elf_sha, expected_genesis)
    positive_invocation_path = Path(execute_monitor_ref['path']).with_suffix('') / 'invocation.json'
    positive_invocation_path, _, positive_invocation_sha = _file(
        positive_invocation_path, cap=65536)
    positive_monitor_invocation_ref = {
        'path': str(positive_invocation_path), 'sha256': positive_invocation_sha}
    monitor_owner = execute_step.get('monitor_owner')
    if type(monitor_owner) is not str or not monitor_owner:
        raise ValueError('positive Full monitor owner required')

    genesis_path, genesis_raw, genesis_sha = _file(
        clone_ledger / 'genesis.bin', cap=16 * 1024 * 1024)
    _, source_genesis_raw, source_genesis_sha = _file(
        source_ledger / 'genesis.bin', cap=16 * 1024 * 1024)
    if genesis_raw != source_genesis_raw or genesis_sha != source_genesis_sha:
        raise ValueError('expired-status clone genesis differs from staged source')

    negative_root = case_root / 'positive_full' / 'expired-status-negative'
    output_dir = negative_root / 'output'
    control_output = negative_root / 'control'
    owner = f'heldout-v00-expired-status-negative-{run_id}'
    config = {
        'schema': supervisor.CONFIG_SCHEMA,
        'scope': supervisor.SCOPE,
        'variant': 0,
        'request_slot': 'A',
        'freeze_report': str(freeze_path),
        'stage_config': stage_config_ref['path'],
        'stage_status': stage_status_ref['path'],
        'stage_report': stage_report_ref['path'],
        'stage_plan': stage_plan_ref['path'],
        'source_receipt': source_ref['path'],
        'clone_receipt': clone_ref['path'],
        'full_proof_receipt': proof_ref['path'],
        'full_proof': full_proof_ref['path'],
        'full_wire': full_wire_ref['path'],
        'runner': execute_config['runner'],
        'expected_elf': str(elf_path),
        'expected_program': expected_program,
        'expected_genesis': expected_genesis,
        'ledger': str(clone_ledger),
        'stage_root': str(stage_root),
        'output_dir': str(output_dir),
        'control_output': str(control_output),
        'owner': owner,
        'observation_lifetime_seconds': 20,
        'wait_deadline_seconds': 45,
        'owner_process_limits': supervisor.PROCESS_LIMITS,
        'outer_limits_required': supervisor.LIMITS,
    }
    pin_refs = {
        'freeze_sha256': freeze_path,
        'expected_genesis_sha256': genesis_path,
        'stage_report_sha256': stage_report_ref['path'],
        'stage_plan_sha256': stage_plan_ref['path'],
        'stage_config_sha256': stage_config_ref['path'],
        'stage_status_sha256': stage_status_ref['path'],
        'source_receipt_sha256': source_ref['path'],
        'clone_receipt_sha256': clone_ref['path'],
        'full_proof_receipt_sha256': proof_ref['path'],
        'full_proof_sha256': full_proof_ref['path'],
        'full_wire_sha256': full_wire_ref['path'],
        'runner_sha256': execute_config['runner'],
        'expected_elf_sha256': elf_path,
    }
    for field, path in pin_refs.items():
        _, _, config[field] = _file(path, cap=_pin_cap(field))
    if config['runner_sha256'] != execute_config.get('runner_sha256'):
        raise ValueError('positive Full runner pin mismatch')
    supervisor._validate_config(config)

    source_pins = {}
    for relative in SOURCE_PATHS:
        rel = Path(relative)
        if rel.is_absolute() or '..' in rel.parts or type(relative) is not str:
            raise ValueError('safe finalizer source path required')
        expected = frozen_bundle_pins.get(relative)
        if not _pin(expected):
            raise ValueError('finalizer source absent from frozen registry/client bundles')
        _, _, actual = _file(repo / rel, cap=128 * 1024 * 1024, expected=expected)
        source_pins[relative] = actual

    config_path = case_root / 'positive_full' / 'expired-status-negative-config.json'
    seed_path = case_root / 'positive_full' / 'expired-status-finalizer-seed.json'
    config_ref = {'path': str(config_path), 'sha256': _sha(canonical_json(config))}
    positive_full = {
        'config': execute_config_ref,
        'report': execute_report_ref,
        'status': execute_status_ref,
        'monitor': execute_monitor_ref,
        'monitor_invocation': positive_monitor_invocation_ref,
        'monitor_owner': monitor_owner,
    }
    seed = {
        'schema': SEED_SCHEMA,
        'finalizer_manifest_schema': finalizer.MANIFEST_SCHEMA,
        'config': config_ref,
        'positive_full': positive_full,
        'source_pins': source_pins,
        'pending_negative_refs': list(finalizer.REF_ROLES[1:]),
    }
    return {'config_path': str(config_path), 'seed_path': str(seed_path),
            'config': config, 'finalizer_seed': seed}


def _ref_file(ref, *, cap):
    if type(ref) is not dict or set(ref) != {'path', 'sha256'}:
        raise ValueError('pinned artifact reference required')
    path, _, digest = _file(ref['path'], cap=cap, expected=ref['sha256'])
    return {'path': str(path), 'sha256': digest}


def _pin_cap(field):
    if field in ('freeze_sha256',):
        return 1024 * 1024
    if field in ('full_proof_sha256',):
        return 32 * 1024 * 1024
    if field in ('full_wire_sha256',):
        return 448
    if field in ('runner_sha256',):
        return 128 * 1024 * 1024
    if field in ('expected_elf_sha256',):
        return 4 * 1024 * 1024
    if field == 'expected_genesis_sha256':
        return 16 * 1024 * 1024
    return 2 * 1024 * 1024


def _write_idempotent(path, value):
    path = Path(path)
    raw = canonical_json(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        _, existing, _ = _json(path, cap=8 * 1024 * 1024)
        if canonical_json(existing) != raw:
            raise ValueError('existing builder output differs; manual review required') from None
        return
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case-root', required=True)
    parser.add_argument('--run-manifest', required=True)
    args = parser.parse_args()
    try:
        bundle = build(args.case_root, args.run_manifest)
        _write_idempotent(bundle['config_path'], bundle['config'])
        _write_idempotent(bundle['seed_path'], bundle['finalizer_seed'])
        print(json.dumps({'config': bundle['config_path'],
                          'config_sha256': bundle['finalizer_seed']['config']['sha256'],
                          'finalizer_seed': bundle['seed_path']}, sort_keys=True))
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise SystemExit(f'blocked: {type(error).__name__}') from None


if __name__ == '__main__':
    main()
