#!/usr/bin/env python3
"""Direct matched prepared-ledger-import-to-Execute heldout k=1 arms.

A common stopped prepared baseline and random control-stage replay fixture are
paid outside the arm timers and reported separately. This is not the registered
complete-session gate. Real invocation performs heavy work; unit tests do not.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.part5 import run_v3_heldout_direct_arm as direct
from harness.tests import queue_v3_clone_prepared as imports

ARTIFACTS = ROOT / 'artifacts/dynark/part5'
ARM_SCHEMA = 'credential-v3-heldout-import-arm-v1'
PAIR_SCHEMA = 'credential-v3-heldout-import-pair-v1'
FIXTURE_SCHEMA = 'credential-v3-heldout-import-fixture-v1'
MEASUREMENT_FILES = {
    'registry': ('harness/tests/queue_v3_clone_prepared.py',
                 'harness/tests/queue_v3_local_stage.py'),
    'client': ('tools/part5/run_v3_heldout_complete_arm.py',
               'tools/part5/run_v3_heldout_direct_arm.py'),
}
OUTER_LIMITS = {
    'fixture': {'runtime_seconds': 900, 'rss_bytes': 4294967296, 'storage_bytes': 2147483648},
    'full': {'runtime_seconds': 7200, 'rss_bytes': 4294967296, 'storage_bytes': 2147483648},
    'anchor': {'runtime_seconds': 9600, 'rss_bytes': 4294967296, 'storage_bytes': 2147483648},
}
arm_order = direct.arm_order


def require_measurement_freeze(manifest):
    """Refuse a manifest whose freeze omits any new executable dependency."""
    pinned = {}
    for role, paths in MEASUREMENT_FILES.items():
        members = manifest.get('frozen_bundles', {}).get(role, [])
        by_path = {row.get('path'): row.get('artifact') for row in members
                   if type(row) is dict}
        for relative in paths:
            ref = by_path.get(relative)
            expected = ROOT / relative
            if (type(ref) is not dict or ref.get('path') != str(expected)
                    or not direct._hash(ref.get('sha256'))
                    or expected.resolve(strict=True) != expected
                    or hashlib.sha256(expected.read_bytes()).hexdigest() != ref['sha256']):
                raise ValueError('fresh freeze must include current measurement source: ' + relative)
            pinned[relative] = ref['sha256']
    return pinned


def validate_pair(full, anchor, full_outer, anchor_outer, *, variant, order):
    if tuple(order) != arm_order(variant):
        raise ValueError('counterbalanced mode order required')
    parsed = {}
    for mode, row in (('full', full), ('anchor', anchor)):
        if type(row) is not dict or row.get('schema') != ARM_SCHEMA:
            raise ValueError('completed import-arm receipt required')
        identity = row.get('identity')
        if (type(identity) is not dict or 'finalized_request_sha256' in identity
                or 'finalized_request_account_sha256' not in identity):
            raise ValueError('exact finalized request-account identity required')
        compatible_identity = dict(identity)
        for key in ('circuit_id', 'r1cs_sha256', 'profile_sha256'):
            if not direct._hash(compatible_identity.pop(key, None)):
                raise ValueError('frozen circuit, relation and profile identities required')
        for key in ('program_id', 'genesis', 'request_address'):
            value = compatible_identity.pop(key, None)
            if type(value) is not str or not 0 < len(value) <= 128:
                raise ValueError('explicit program, genesis and request PDA required')
        compatible_identity['finalized_request_sha256'] = compatible_identity.pop(
            'finalized_request_account_sha256')
        compatible = {**row, 'schema': direct.ARM_SCHEMA, 'identity': compatible_identity}
        identity, clone, shared, evidence = direct._arm_identity(compatible, mode, variant)
        imported = row.get('prepared_import')
        if (type(imported) is not dict
                or any(not direct._hash(imported.get(key)) for key in
                       ('tree_sha256', 'config_sha256', 'status_sha256',
                        'source_prepare_status_sha256'))
                or any(type(imported.get(key)) is not str
                       or not Path(imported[key]).is_absolute()
                       for key in ('source_ledger', 'destination'))
                or imported['source_ledger'] == imported['destination']
                or not direct._hash(evidence.get('plan_sha256'))
                or not direct._hash(evidence.get('replay_package_sha256'))):
            raise ValueError('pinned independent prepared import required')
        parsed[mode] = (identity, clone, shared, evidence, imported)
    f, a = parsed['full'], parsed['anchor']
    if (full.get('run_manifest_sha256') != anchor.get('run_manifest_sha256')
            or full['identity'] != anchor['identity'] or f[2] != a[2]
            or any(f[3][key] != a[3][key] for key in
                   ('plan_sha256', 'replay_package_sha256'))
            or any(f[4][key] != a[4][key] for key in
                   ('tree_sha256', 'source_ledger', 'source_prepare_status_sha256'))):
        raise ValueError('matched exact action, roots, fixture and prepared baseline required')
    destinations = [f[4]['destination'], a[4]['destination'],
                    f[1]['destination'], a[1]['destination']]
    if len(set(destinations + [f[4]['source_ledger']])) != 5:
        raise ValueError('separate prepared imports and effect ledgers required')
    for left in destinations:
        for right in destinations:
            if left != right and Path(left) in Path(right).parents:
                raise ValueError('disjoint prepared imports and effect ledgers required')
    full_seconds = _mode_outer_seconds(full_outer, 'full', variant)
    anchor_seconds = _mode_outer_seconds(anchor_outer, 'anchor', variant)
    return {'matched': True, 'variant': variant, 'arm_order': list(order),
            'measurement_scope': 'direct prepared-ledger-import-to-Execute k1',
            'complete_import_to_execute_arm': False,
            'registered_complete_session_gate_satisfied': False,
            'update_count': 1, 'k_gt_1_measured': False,
            'full_direct_wall_seconds': full_seconds,
            'anchor_direct_wall_seconds': anchor_seconds,
            'anchor_wall_savings_seconds': full_seconds - anchor_seconds,
            'anchor_wall_savings_fraction': (full_seconds - anchor_seconds) / full_seconds,
            'same_finalized_action_and_root_sequence': True,
            'independent_prepared_imports': True,
            'each_r1_clone_matches_own_stopped_source': True,
            'outer_cleanup_verified': True, 'complete_tree_cpu_qualified': False}


def validate_fixture_binding(full, anchor, fixture):
    try:
        for row in (full, anchor):
            if (row['prepared_import']['source_prepare_status_sha256']
                    != fixture['prepared']['status_sha256']
                    or row['prepared_import']['source_ledger']
                    != str(Path(fixture['prepared']['runtime']) / 'ledger')
                    or row['evidence']['replay_package_sha256'] != fixture['replay_package']['sha256']
                    or row['evidence']['plan_sha256'] != fixture['plan_sha256']
                    or any(row['identity'][key] != fixture['domain'][key]
                           for key in ('program_id', 'genesis', 'request_address'))
                    or row['identity']['finalized_request_account_sha256']
                       != fixture['request_account_sha256']):
                raise ValueError('arm does not bind to produced fixture')
    except (KeyError, TypeError) as error:
        raise ValueError('complete fixture evidence required') from error


def global_heavy_lock():
    resolver = getattr(direct, '_shared_lock_artifacts', None)
    if not callable(resolver):
        raise ValueError('updated shared heavyweight-lock resolver required')
    owner_artifacts = resolver(ROOT)
    direct._canonical_directory(owner_artifacts)
    return owner_artifacts / '.v3-heldout-heavy.lock'


def _acquire_lock(path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError('owner-only global heldout lock required')
        raw = json.dumps({'schema': direct.LOCK_OWNER_SCHEMA, 'pid': os.getpid()},
                         sort_keys=True).encode()
        os.ftruncate(fd, 0)
        os.write(fd, raw)
        os.fsync(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _source_refs(prepared):
    return {'config': {'path': prepared['config'], 'sha256': prepared['config_sha256']},
            'status': {'path': prepared['status_path'], 'sha256': prepared['status_sha256']},
            'monitor': {'path': prepared['monitor'], 'sha256': prepared['monitor_sha256']},
            'monitor_owner': prepared['monitor_owner']}


def _import_runner(case_runner, manifest, output, run_ref, manifest_sha, prepared, replay):
    class ImportedRunner(case_runner.HeldoutCaseRunner):
        def _prepare(self, req, root, case_root, stage_context):
            return imports.clone(_source_refs(prepared), Path(self._art(req, 'runtime')),
                                 Path(self._art(req, 'prepare-import-control')))

        def _write_config(self, path, value):
            if value.get('scope') == 'part5-v3-local-stage' and replay is not None:
                value['replay_package'] = replay
            return super()._write_config(path, value)

    return ImportedRunner(manifest, output, run_manifest_ref=run_ref,
                          manifest_sha256=manifest_sha)


def _setup(case_runner, runner, manifest, *, transition_required):
    builder = direct._load_module('import_arm_context_builder',
                                  ROOT / 'tools/part5/prepare_v3_heldout_context.py')
    case_root = runner.output_root / 'pair-view'
    req = 'unrelated_compare'
    root = runner._layout(req)
    with runner.journal:
        def pair_job():
            case_root.mkdir(mode=0o700)
            builder.prepare(Path(manifest['cohort_root']), manifest['cohort_sha256'],
                            manifest['variant'], case_root)
            return {'status': 'passed', 'case_context_sha256':
                    case_runner.digest(case_runner._read(case_root / 'case-context.json'))}
        pair = runner.journal.run_step('pair-view',
            inputs={'cohort': manifest['cohort_sha256'], 'variant': manifest['variant']},
            job=pair_job)
        inputs = {'case_context_sha256': pair['case_context_sha256'],
                  'prepare_template_sha256': manifest['base_prepare_config_sha256'],
                  'request_slot': 'B'}
        prepared = runner.journal.run_step(req + ':prepared-import', inputs=inputs,
            job=lambda: {'status': 'passed', **runner._prepare(
                req, root, case_root, case_root / 'stage-context.json')})
        stage = runner.journal.run_step(req + ':stage', inputs=inputs,
            job=lambda: {'status': 'passed', **runner._stage(
                req, root, case_root, case_root / 'stage-context.json', prepared)})
        transition = None
        if transition_required:
            transition = runner.journal.run_step(req + ':transition',
                inputs={**inputs, 'stage_report_sha256': stage['report_sha256']},
                job=lambda: {'status': 'passed', **runner._transition(req, root, case_root, stage)})
    return {'pair_view': pair, 'prepared_import': prepared, 'stage': stage,
            'transition': transition, 'case_root': str(case_root), 'root': str(root)}


def _build_fixture(case_runner, manifest, run_ref, manifest_sha, fixture_root, *, launch_sha256):
    direct._private_dir(fixture_root, fresh=True, ignored=True)
    began = time.monotonic()
    baseline_runner = case_runner.HeldoutCaseRunner(manifest, fixture_root / 'baseline',
        run_manifest_ref=run_ref, manifest_sha256=manifest_sha)
    req = 'unrelated_compare'
    baseline_started = time.monotonic()
    prepared = baseline_runner._prepare(req, baseline_runner._layout(req), None, None)
    baseline_wall = time.monotonic() - baseline_started
    control_started = time.monotonic()
    control_runner = _import_runner(case_runner, manifest, fixture_root / 'control-case',
                                   run_ref, manifest_sha, prepared, None)
    control = _setup(case_runner, control_runner, manifest, transition_required=False)
    control_wall = time.monotonic() - control_started
    replay_root = direct._private_dir(fixture_root / 'replay-package', fresh=True, ignored=True)
    stage_root = Path(control['stage']['root'])
    files = {}
    for name in ('plan.json', 'admin.json', 'publisher.json', 'source.json', 'creator.json'):
        raw = imports._raw(stage_root / name, 65536 if name == 'plan.json' else 1024)
        fd = os.open(replay_root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
        files[name] = hashlib.sha256(raw).hexdigest()
    context_sha = case_runner.digest(case_runner._read(Path(control['case_root']) / 'stage-context.json'))
    package = {'schema': 'part5-v3-stage-replay-v1', 'context_sha256': context_sha, 'files': files}
    replay_path = replay_root / 'replay-package.json'
    replay_sha = direct._write_new(replay_path, package)
    source_status = case_runner._json(prepared['status_path'], prepared['status_sha256'])
    control_report = case_runner._json(control['stage']['report'], control['stage']['report_sha256'])
    fixture = {'schema': FIXTURE_SCHEMA, 'variant': manifest['variant'],
               'launch_request_sha256': launch_sha256,
               'run_manifest_sha256': manifest_sha, 'prepared': prepared,
               'control': control, 'plan_sha256': files['plan.json'],
               'domain': {'program_id': source_status['loaded_program']['program'],
                          'genesis': source_status['loaded_program']['genesis'],
                          'request_address': control_report['request']},
               'request_account_sha256': control_report['account_sha256'][3],
               'replay_package': {'path': str(replay_path), 'sha256': replay_sha},
               'costs': {'scope': 'shared prepared baseline and control-stage replay fixture',
                         'direct_fixture_wall_seconds': time.monotonic() - began,
                         'baseline_prepare_wall_seconds': baseline_wall,
                         'control_pair_import_stage_wall_seconds': control_wall,
                         'issuance_and_cohort_costs': 'excluded; report from pinned cohort records separately'}}
    path = fixture_root / 'fixture.json'
    return fixture, path, direct._write_new(path, fixture)


def _fixture_launch_sha(manifest_sha, output_root):
    return direct._digest(json.dumps({
        'schema': 'credential-v3-heldout-fixture-launch-v1',
        'run_manifest_sha256': manifest_sha, 'fixture_root': str(output_root),
    }, sort_keys=True, separators=(',', ':')).encode())


def _run_fixture_worker(manifest_path, output_root, token):
    case_runner = direct._load_module('import_fixture_case_runner', ROOT / 'tools/part5/run_v3_heldout_case.py')
    _, manifest, run_ref, manifest_sha = direct._read_manifest(case_runner, Path(manifest_path))
    require_measurement_freeze(manifest)
    mode_root, output_root = direct._worker_output_paths(output_root)
    if (mode_root.name != 'shared-fixture' or output_root.name != 'case-run'
            or mode_root.parent.parent != ARTIFACTS):
        raise ValueError('canonical shared fixture worker output required')
    direct._private_dir(mode_root, ignored=True)
    direct._authorize_worker(mode_root / direct.WORKER_TICKET_NAME, output_root,
        'fixture', manifest_sha, token, lock_path=global_heavy_lock())
    claim = direct._load_json(mode_root / direct.WORKER_CLAIM_NAME)
    launch_sha = _fixture_launch_sha(manifest_sha, output_root)
    if claim.get('shared_context_sha256') != launch_sha:
        raise ValueError('fixture ticket does not bind the requested root and manifest')
    fixture, _, _ = _build_fixture(case_runner, manifest, run_ref, manifest_sha,
                                    output_root, launch_sha256=launch_sha)
    require_measurement_freeze(manifest)
    return fixture


def _new_supervision_root():
    parent = direct._canonical_directory(ARTIFACTS.parent)
    root = parent / ('.v3-import-supervisor-' + uuid.uuid4().hex)
    return direct._private_dir(root, fresh=True, ignored=True)


def _outer_storage_paths(private_output):
    private_output = Path(private_output)
    covered = direct._canonical_directory(ARTIFACTS)
    if (not private_output.is_absolute() or private_output.resolve() != private_output
            or private_output.exists() or private_output.is_symlink()
            or private_output == covered or private_output in covered.parents
            or covered in private_output.parents):
        raise ValueError('fresh outer monitor must be disjoint from covered Part 5 artifacts')
    direct._private_dir(private_output.parent, ignored=True)
    # session_runner independently measures its private_output root, including
    # logs and metadata; this covers every fixture/arm output and app sibling.
    return (str(covered),)


def _mode_outer_seconds(report, mode, variant):
    expected_owner = f'heldout-v{variant:02d}-import-{mode}'
    limits = OUTER_LIMITS[mode]
    expected_limits = {
        'runtime_seconds': limits['runtime_seconds'],
        'owned_tree_rss_bytes': limits['rss_bytes'],
        'storage_growth_bytes': limits['storage_bytes'],
    }
    if type(report) is not dict or report.get('owner') != expected_owner:
        raise ValueError(f'{mode} outer report owner does not match its arm')
    reported_limits = report.get('limits')
    if (type(reported_limits) is not dict
            or any(type(reported_limits.get(key)) is not int
                   or reported_limits[key] != value
                   for key, value in expected_limits.items())):
        raise ValueError(f'{mode} outer resource limits do not match its arm')
    return direct._outer_seconds(report)


def _launch_fixture(session, manifest_path, manifest, manifest_sha, output_root, supervision):
    mode_root = direct._private_dir(output_root / 'shared-fixture', fresh=True, ignored=True)
    fixture_root = mode_root / 'case-run'
    launch_sha = _fixture_launch_sha(manifest_sha, fixture_root)
    token = uuid.uuid4().hex
    direct._write_new(mode_root / direct.WORKER_TICKET_NAME, {
        'schema': direct.WORKER_TICKET_SCHEMA, 'mode': 'fixture',
        'case_output_root': str(fixture_root), 'manifest_sha256': manifest_sha,
        'shared_context_sha256': launch_sha, 'supervisor_pid': os.getpid(), 'token': token})
    monitor = supervision / 'fixture-monitor'
    outer_path = supervision / 'fixture-outer.json'
    limits = OUTER_LIMITS['fixture']
    owner = f'heldout-v{manifest["variant"]:02d}-import-fixture'
    outer = session.run(owner=owner,
        command=[sys.executable, str(Path(__file__).resolve()),
                 '--manifest', str(manifest_path), '--output-root', str(fixture_root),
                 '--_fixture-worker'], cwd=str(ROOT),
        private_output=str(monitor), report=str(outer_path),
        runtime_seconds=limits['runtime_seconds'], rss_bytes=limits['rss_bytes'],
        storage_bytes=limits['storage_bytes'], storage_paths=_outer_storage_paths(monitor),
        environment={'RAYON_NUM_THREADS': '4', 'OMP_NUM_THREADS': '1', 'TZ': 'UTC',
                     'P5_V3_DIRECT_ARM_WORKER_TOKEN': token})
    duration = direct._outer_seconds(outer)
    reported_limits = outer.get('limits')
    expected_limits = {'runtime_seconds': limits['runtime_seconds'],
                       'owned_tree_rss_bytes': limits['rss_bytes'],
                       'storage_growth_bytes': limits['storage_bytes']}
    if (outer.get('owner') != owner or type(reported_limits) is not dict
            or any(reported_limits.get(key) != value for key, value in expected_limits.items())):
        raise ValueError('fixture outer owner or resource caps do not match the launch')
    fixture_path = fixture_root / 'fixture.json'
    raw = imports._raw(fixture_path, 1024 * 1024)
    fixture = json.loads(raw)
    if (fixture.get('schema') != FIXTURE_SCHEMA
            or fixture.get('run_manifest_sha256') != manifest_sha
            or fixture.get('variant') != manifest['variant']
            or fixture.get('launch_request_sha256') != launch_sha):
        raise ValueError('bounded fixture receipt does not bind the authorized request')
    receipt = {'owner': owner, 'outer_report': str(outer_path),
               'outer_report_sha256': direct._digest(imports._raw(outer_path)),
               'storage_roots': [str(monitor), str(ARTIFACTS)],
               'limits': reported_limits,
               'direct_fixture_outer_wall_seconds': duration,
               'outer_cleanup_verified': True,
               'cost_scope': 'excluded shared fixture; outside both mode timers'}
    return fixture, fixture_path, direct._digest(raw), receipt


def _run_worker(manifest_path, mode, case_output_root, token):
    case_runner = direct._load_module('import_arm_case_runner', ROOT / 'tools/part5/run_v3_heldout_case.py')
    _, manifest, run_ref, manifest_sha = direct._read_manifest(case_runner, Path(manifest_path))
    require_measurement_freeze(manifest)
    variant = manifest['variant']
    mode_root, output_root = direct._worker_output_paths(case_output_root)
    direct._private_dir(mode_root, ignored=True)
    direct._authorize_worker(mode_root / direct.WORKER_TICKET_NAME, output_root,
        mode, manifest_sha, token, lock_path=global_heavy_lock())
    fixture_path = mode_root.parent / 'shared-fixture/case-run/fixture.json'
    fixture_raw = imports._raw(fixture_path, 1024 * 1024)
    fixture_sha256 = hashlib.sha256(fixture_raw).hexdigest()
    claim = direct._load_json(mode_root / direct.WORKER_CLAIM_NAME)
    fixture = json.loads(fixture_raw)
    if (fixture_sha256 != claim['shared_context_sha256']
            or fixture.get('schema') != FIXTURE_SCHEMA
            or fixture.get('variant') != variant or fixture.get('run_manifest_sha256') != manifest_sha):
        raise ValueError('pinned common import fixture required')
    imports.review_source(_source_refs(fixture['prepared']))
    runner = _import_runner(case_runner, manifest, output_root, run_ref, manifest_sha,
                            fixture['prepared'], fixture['replay_package'])
    setup = _setup(case_runner, runner, manifest, transition_required=True)
    root, case_root = Path(setup['root']), Path(setup['case_root'])
    req = 'unrelated_compare'
    stage, transition, imported = setup['stage'], setup['transition'], setup['prepared_import']
    if stage['plan_sha256'] != fixture['plan_sha256']:
        raise ValueError('replayed arm plan differs from common control plan')
    with runner.journal:
        def source_call(source_variant, out, r0_source=None):
            out = Path(out)
            if out.exists() or out.is_symlink():
                raise ValueError('fresh B-arm source directory required')
            out.mkdir(mode=0o700)
            receipt_path = out / 'source-receipt.json'
            command = [sys.executable,
                str(ROOT / 'tools/part5/prepare_v3_heldout_source.py'),
                '--case-root', str(case_root), '--cohort-root', manifest['cohort_root'],
                '--freeze-receipt', manifest['freeze_receipt'],
                '--freeze-sha256', manifest['freeze_sha256'],
                '--stage-root', stage['root'],
                '--exporter', manifest['proof_inputs']['exporter']['path'],
                '--variant', source_variant, '--output', str(out)]
            if source_variant == 'R1':
                command.extend(['--transition-root', transition['root'],
                    '--transition-context', transition['context'],
                    '--transition-context-sha256', transition['context_sha256'],
                    '--r0-source-receipt', r0_source['receipt'],
                    '--r0-source-receipt-sha256', r0_source['receipt_sha256']])
            monitor_dir = root / ('source-' + source_variant + '-monitor')
            monitor_path = root / ('source-' + source_variant + '-monitor.json')
            owner = f'direct-v{variant:02d}-B-source-{source_variant}'
            outer = runner.bounded_run(owner, command, monitor_dir, monitor_path,
                runtime=case_runner.LIMITS['runtime_seconds'], storage_paths=(out,))
            if (outer.get('passed') is not True or outer.get('stop_reason') is not None
                    or outer.get('cleanup_remaining_owned_processes') != 0
                    or outer.get('cleanup_status_unknown') is not False):
                raise ValueError('bounded B-arm source preparation failed')
            receipt = case_runner._json(receipt_path)
            if receipt.get('schema') != 'credential-v3-heldout-request-source-v1':
                raise ValueError('pinned B-arm request source receipt required')
            return {'status': 'passed', 'root': str(out),
                'receipt': str(receipt_path),
                'receipt_sha256': case_runner.digest(case_runner._read(receipt_path)),
                'monitor': str(monitor_path),
                'monitor_sha256': case_runner.digest(case_runner._read(monitor_path)),
                'monitor_owner': owner}

        source_inputs = {'stage_report_sha256': stage['report_sha256'],
                         'freeze_sha256': manifest['freeze_sha256']}
        r0 = runner.journal.run_step(req + ':source-R0', inputs=source_inputs,
            job=lambda: source_call('R0', root / 'source-R0'),
            reuse=lambda saved: runner._verify_record(saved,
                ('receipt', 'monitor'), ('receipt_sha256', 'monitor_sha256')))
        r1 = runner.journal.run_step(req + ':source-R1',
            inputs={**source_inputs,
                    'transition_report_sha256': transition['report_sha256'],
                    'r0_receipt_sha256': r0['receipt_sha256']},
            job=lambda: source_call('R1', root / 'source-R1', r0),
            reuse=lambda saved: runner._verify_record(saved,
                ('receipt', 'monitor'), ('receipt_sha256', 'monitor_sha256')))
        proof = runner._request_proof(req, mode, root, case_root, stage,
                                      transition, r0, r1)
        clone_label = 'r1-full' if mode == 'full' else 'r1-anchor'
        clone = runner.journal.run_step(
            f'unrelated_compare:{"unrelated_full" if mode == "full" else "anchor"}:clone',
            inputs={'transition_report_sha256': transition['report_sha256'],
                    'label': clone_label},
            job=lambda: {'status': 'passed', **runner._clone_r1(
                req, clone_label, root, transition)},
            reuse=lambda saved: runner._verify_record(
                saved, ('receipt',), ('receipt_sha256',)))
        wires = {'full': proof['wires']['r0_full_wire'],
                 'anchor': proof['wires']['r1_wire']}
        if mode == 'full':
            wires['full_near'] = proof['wires']['r1_wire']
        branch_label = 'unrelated_full' if mode == 'full' else 'anchor'
        effect = runner.journal.run_step(
            f'unrelated_compare:{branch_label}:effect',
            inputs={'transition_report_sha256': transition['report_sha256'],
                    'source_r0_sha256': r0['receipt_sha256'],
                    'source_r1_sha256': r1['receipt_sha256'],
                    'proof_mode': mode,
                    'clone_receipt_sha256': clone['receipt_sha256']},
            job=lambda: {'status': 'passed', **runner._run_branch(
                req, branch_label, mode, root, stage, transition, clone,
                {mode: proof}, wires)},
            reuse=lambda saved: runner._verify_record(
                saved, ('report', 'status_path', 'config', 'outer', 'signed_history'),
                ('report_sha256', 'status_sha256')))

    r0_doc = case_runner._json(r0['receipt'], r0['receipt_sha256'])
    r1_doc = case_runner._json(r1['receipt'], r1['receipt_sha256'])
    proof_doc = case_runner._json(proof['receipt'], proof['receipt_sha256'])
    proof_report_ref = proof_doc.get('proof_report')
    proof_report = case_runner._json(proof_report_ref['path'], proof_report_ref['sha256'])
    stage_doc = case_runner._json(stage['report'], stage['report_sha256'])
    clone_doc = case_runner._json(clone['receipt'], clone['receipt_sha256'])
    branch_doc = case_runner._json(effect['report'], effect['report_sha256'])
    setup_sha = manifest['frozen_files']['setup_manifest']['sha256']
    vk = manifest['frozen_files']['ordinary_vk']['sha256']
    elf = manifest['frozen_files']['loaded_elf']['sha256']
    if (proof_doc.get('mode') != mode
            or proof_doc.get('proof_created') is not True
            or proof_doc.get('application_verified') is not False
            or proof_report.get('mode') != ('matched-full-k1' if mode == 'full'
                                             else 'matched-anchor-k1')
            or proof_report.get('passed') is not True
            or proof_doc.get('ordinary_verification', {}).get('passed') is not True
            or branch_doc.get('passed') is not True
            or branch_doc.get('mode') != mode
            or branch_doc.get('effect_count') != 1
            or branch_doc.get('request_consumed') is not True
            or clone_doc.get('copy_identical') is not True):
        raise ValueError('complete matched proof and loaded effect evidence required')
    roots = r0_doc.get('membership_roots')
    if (type(roots) is not dict or set(roots) != {'R0', 'R1'}
            or r0_doc.get('selected_root') != roots['R0']
            or r1_doc.get('selected_root') != roots['R1']
            or r0_doc.get('target_der_sha256') != r1_doc.get('target_der_sha256')
            or r0_doc.get('staged_request_sha256')
                != r1_doc.get('staged_request_sha256')
            or r0_doc.get('finalized_action_transport_sha256')
                != r1_doc.get('finalized_action_transport_sha256')
            or r0_doc.get('action_hash') != r1_doc.get('action_hash')):
        raise ValueError('B-arm finalized request and R0/R1 continuity required')
    identity = {
        'circuit_id': runner.freeze_doc['identities']['circuit'],
        'r1cs_sha256': manifest['frozen_files']['r1cs']['sha256'],
        'profile_sha256': manifest['frozen_files']['profile']['sha256'],
        'program_id': stage_doc['program'],
        'genesis': stage_doc['genesis'],
        'request_address': stage_doc['request'],
        'credential_sha256': r0_doc['target_der_sha256'],
        'finalized_request_account_sha256': r0_doc['staged_request_sha256'],
        'finalized_action_transport_sha256': r0_doc['finalized_action_transport_sha256'],
        'action_hash': r0_doc['action_hash'],
        'roots': roots,
        'setup_sha256': setup_sha,
        'vk_sha256': vk,
        'elf_sha256': elf,
    }
    arm = {
        'schema': ARM_SCHEMA, 'variant': variant, 'mode': mode, 'status': 'passed',
        'run_manifest_sha256': manifest_sha,
        'shared_context_sha256': fixture_sha256,
        'identity': identity,
        'prepared_import': {
            'source_ledger': imported['source_ledger'],
            'destination': str(Path(imported['runtime']) / 'ledger'),
            'tree_sha256': imported['tree_sha256'],
            'config_sha256': imported['config_sha256'],
            'status_sha256': imported['status_sha256'],
            'source_prepare_status_sha256': fixture['prepared']['status_sha256'],
        },
        'proof': {'mode': mode, 'proof_created': True,
                  'ordinary_verified': True,
                  'receipt_sha256': proof['receipt_sha256'],
                  'proof_report_sha256': proof_report_ref['sha256']},
        'clone': {'receipt_sha256': clone['receipt_sha256'],
                  'tree_sha256': clone_doc['tree_sha256'],
                  'copy_identical': clone_doc['copy_identical'],
                  'destination': clone_doc['destination']},
        'effect': {'report_sha256': effect['report_sha256'], 'mode': mode,
                   'passed': True, 'effect_count': 1, 'request_consumed': True},
        'evidence': {
            'r0_v3f1_frame_sha256': r0_doc['finalized_request_sha256'],
            'r1_v3f1_frame_sha256': r1_doc['finalized_request_sha256'],
            'pair_context_sha256': setup['pair_view']['case_context_sha256'],
            'plan_sha256': stage['plan_sha256'],
            'replay_package_sha256': fixture['replay_package']['sha256'],
            'stage_report_sha256': stage['report_sha256'],
            'transition_report_sha256': transition['report_sha256'],
            'source_r0_receipt_sha256': r0['receipt_sha256'],
            'source_r1_receipt_sha256': r1['receipt_sha256'],
            'clone_receipt_sha256': clone['receipt_sha256'],
            'proof_receipt_sha256': proof['receipt_sha256'],
            'branch_report_sha256': effect['report_sha256'],
        },
        'limitations': {
            'private_proof_state_serialization_reload': 'not implemented by current heldout path',
            'loaded_expired_status_negative': 'not part of B arm',
            'loaded_full_queue_negative': 'not part of B arm',
        },
    }
    arm_path = mode_root / 'arm-report.json'
    require_measurement_freeze(manifest)
    direct._write_new(arm_path, arm)
    return arm


def run_pair(manifest_path, output_root):
    case_runner = direct._load_module('import_pair_case_runner', ROOT / 'tools/part5/run_v3_heldout_case.py')
    manifest_path, output_root = Path(manifest_path), Path(output_root)
    _, manifest, _, manifest_sha = direct._read_manifest(case_runner, manifest_path)
    measurement_sources = require_measurement_freeze(manifest)
    if (not output_root.is_absolute() or output_root.parent != ARTIFACTS
            or output_root.name in ('', '.', '..')):
        raise ValueError('fresh Part 5 child output root required')
    lock_fd = _acquire_lock(global_heavy_lock())
    try:
        direct._private_dir(output_root, fresh=True, ignored=True)
        supervision = _new_supervision_root()
        session = direct._load_module('import_arm_session_runner', ROOT / 'results/dynark/part5/session_runner.py')
        fixture, fixture_path, fixture_sha, fixture_outer = _launch_fixture(
            session, manifest_path, manifest, manifest_sha, output_root, supervision)
        rows, outers, receipts = {}, {}, {}
        variant, order = manifest['variant'], arm_order(manifest['variant'])
        for mode in order:
            mode_root = direct._private_dir(output_root / ('arm-' + mode), fresh=True, ignored=True)
            worker_output = mode_root / 'case-run'
            token = uuid.uuid4().hex
            direct._write_new(mode_root / direct.WORKER_TICKET_NAME, {
                'schema': direct.WORKER_TICKET_SCHEMA, 'mode': mode,
                'case_output_root': str(worker_output), 'manifest_sha256': manifest_sha,
                'shared_context_sha256': fixture_sha, 'supervisor_pid': os.getpid(), 'token': token})
            outer_path = supervision / (mode + '-outer.json')
            limits = OUTER_LIMITS[mode]
            outer = session.run(owner=f'heldout-v{variant:02d}-import-{mode}',
                command=[sys.executable, str(Path(__file__).resolve()),
                         '--manifest', str(manifest_path), '--output-root', str(worker_output),
                         '--_arm-mode', mode], cwd=str(ROOT),
                private_output=str(supervision / (mode + '-monitor')), report=str(outer_path),
                runtime_seconds=limits['runtime_seconds'], rss_bytes=limits['rss_bytes'],
                storage_bytes=limits['storage_bytes'],
                storage_paths=_outer_storage_paths(supervision / (mode + '-monitor')),
                environment={'RAYON_NUM_THREADS': '4', 'OMP_NUM_THREADS': '1', 'TZ': 'UTC',
                             'P5_V3_DIRECT_ARM_WORKER_TOKEN': token})
            _mode_outer_seconds(outer, mode, variant)
            arm_path = mode_root / 'arm-report.json'
            row = json.loads(imports._raw(arm_path, 1024 * 1024))
            if row.get('shared_context_sha256') != fixture_sha or row.get('run_manifest_sha256') != manifest_sha:
                raise ValueError('mode receipt does not pin fixture and manifest')
            rows[mode], outers[mode] = row, outer
            receipts[mode] = {'arm_report': str(arm_path),
                              'arm_report_sha256': hashlib.sha256(imports._raw(arm_path)).hexdigest(),
                              'outer_report': str(outer_path),
                              'outer_report_sha256': hashlib.sha256(imports._raw(outer_path)).hexdigest()}
        comparison = validate_pair(rows['full'], rows['anchor'], outers['full'], outers['anchor'],
                                   variant=variant, order=order)
        validate_fixture_binding(rows['full'], rows['anchor'], fixture)
        require_measurement_freeze(manifest)
        report = {'schema': PAIR_SCHEMA, 'variant': variant,
                  'measurement_sources': measurement_sources,
                  'run_manifest': {'path': str(manifest_path), 'sha256': manifest_sha},
                  'fixture': {'path': str(fixture_path), 'sha256': fixture_sha,
                              'costs': {**fixture['costs'], 'direct_fixture_outer_wall_seconds':
                                        fixture_outer['direct_fixture_outer_wall_seconds']},
                              **fixture_outer},
                  'comparison': comparison, 'arms': receipts,
                  'timing_notes': [
                      'one outer timer per mode covers private prepared-ledger import, pair-view, replayed stage, authenticated transition, independent source preparation, selected proof including ordinary verification, R1 clone, loaded Execute and owned cleanup',
                      'common baseline prepare, random control-stage fixture and initial issuance/cohort work are outside both mode timers',
                      'shared fixture has its own authenticated outer runtime/RSS/storage owner and cleanup check before either mode launches',
                      'outer report setup/writing is outside its timer; nested durations are attribution only',
                      'outer storage sampling covers all Part 5 artifacts; nested source/proof/application caps remain in force',
                      'CPU is unqualified; private proof-state serialization/reload is not implemented',
                      'this bounded k1 pair does not establish registered complete-session economics or eight-credential acceptance'],
                  'registered_complete_session_gate_satisfied': False,
                  'complete_import_to_execute_arm': False}
        path = output_root / 'import-pair-report.json'
        sha = direct._write_pair_report(path, report)
        return {'report': report, 'report_path': str(path), 'report_sha256': sha}
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--output-root', required=True, type=Path)
    workers = parser.add_mutually_exclusive_group()
    workers.add_argument('--_arm-mode', choices=('full', 'anchor'), help=argparse.SUPPRESS)
    workers.add_argument('--_fixture-worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args._fixture_worker:
            token = os.environ.get('P5_V3_DIRECT_ARM_WORKER_TOKEN')
            if not token:
                raise ValueError('one-time locked-parent fixture authorization required')
            report = _run_fixture_worker(args.manifest, args.output_root, token)
            print(json.dumps({'schema': FIXTURE_SCHEMA, 'variant': report['variant'],
                              'status': 'passed'}))
        elif args._arm_mode:
            token = os.environ.get('P5_V3_DIRECT_ARM_WORKER_TOKEN')
            if not token:
                raise ValueError('one-time locked-parent authorization required')
            report = _run_worker(args.manifest, args._arm_mode, args.output_root, token)
            print(json.dumps({'schema': ARM_SCHEMA, 'variant': report['variant'],
                              'mode': report['mode'], 'status': report['status']}))
        else:
            result = run_pair(args.manifest, args.output_root)
            print(json.dumps({'schema': PAIR_SCHEMA, 'report': result['report_path'],
                              'report_sha256': result['report_sha256']}))
    except Exception as error:
        raise SystemExit(f'heldout import arm rejected: {type(error).__name__}: {str(error)[:180]}') from None


if __name__ == '__main__':
    main()
