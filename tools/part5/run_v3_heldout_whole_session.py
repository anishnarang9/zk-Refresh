#!/usr/bin/env python3
"""Registered v3 variant-00 k=1 whole-session campaign.

Only blank-chain creation and fixed random entropy precede the eight mode clocks.
Every mode independently deploys on its control and main ledgers, reconstructs
the replay package, and completes source/proof/ordinary-verification/Execute.
Two deployments are charged because the control fixture must not consume the
main request. CPU sampling is unqualified. Real invocation performs heavy work.
"""
import argparse
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import statistics
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.part5 import run_v3_heldout_complete_arm as complete
from tools.part5 import run_v3_heldout_direct_arm as direct
from harness.tests import queue_v3_blank_seed as seed

ARTIFACTS = ROOT / 'artifacts/dynark/part5'
ARM_SCHEMA = 'credential-v3-whole-session-arm-v1'
PAIR_SCHEMA = 'credential-v3-whole-session-pair-v1'
CAMPAIGN_SCHEMA = 'credential-v3-whole-session-campaign-v1'
BOUNDARY = ('initial_prepare', 'replay_package', 'control_fixture',
            'main_prepare', 'main_stage', 'authenticated_transition',
            'source_R0', 'source_R1', 'proof_and_ordinary_verification',
            'persisted_R1_clone', 'finalized_execute')
OUTER_LIMITS = {
    'seed': {'runtime_seconds': 180, 'rss_bytes': 4294967296, 'storage_bytes': 268435456},
    'full': {'runtime_seconds': 8400, 'rss_bytes': 4294967296, 'storage_bytes': 4294967296},
    'anchor': {'runtime_seconds': 10800, 'rss_bytes': 4294967296, 'storage_bytes': 4294967296},
}


def registered_order(repeat):
    if type(repeat) is not int or not 0 <= repeat < 4:
        raise ValueError('registered repeat must be 0..3')
    return ('full', 'anchor') if repeat % 2 == 0 else ('anchor', 'full')


def _outer(report, mode, repeat):
    expected = ('heldout-v00-whole-seed' if mode == 'seed' else
                f'heldout-v00-whole-r{repeat}-{mode}')
    limits = OUTER_LIMITS[mode]
    expected_limits = {'runtime_seconds': limits['runtime_seconds'],
                       'owned_tree_rss_bytes': limits['rss_bytes'],
                       'storage_growth_bytes': limits['storage_bytes']}
    if (report.get('owner') != expected or type(report.get('limits')) is not dict
            or any(type(report['limits'].get(k)) is not int
                   or report['limits'][k] != v for k, v in expected_limits.items())):
        raise ValueError('whole-session outer owner/caps mismatch')
    if mode == 'seed':
        # A reviewed validator SIGINT can make the creator exit one while its
        # uncensored monitor proves clean ownership; seed.build_manifest checks it.
        return report['duration_seconds']
    return direct._outer_seconds(report)


def _disjoint(paths):
    paths = [Path(p) for p in paths]
    if any(not p.is_absolute() or '..' in p.parts for p in paths):
        raise ValueError('absolute independent ledger destinations required')
    for i, left in enumerate(paths):
        for right in paths[i + 1:]:
            if left == right or left in right.parents or right in left.parents:
                raise ValueError('disjoint fresh ledger destinations required')


def validate_pair(full, anchor, full_outer, anchor_outer, *, repeat, order):
    """Pair only completed real boundaries and exact action/root/effect identities."""
    if tuple(order) != registered_order(repeat):
        raise ValueError('registered AB/BA repeat order required')
    destinations = []
    for mode, row in (('full', full), ('anchor', anchor)):
        if (row.get('schema') != ARM_SCHEMA or row.get('variant') != 0
                or row.get('repeat') != repeat
                or row.get('boundary_steps') != list(BOUNDARY)):
            raise ValueError('complete registered arm boundary required')
        identity = dict(row.get('identity', {}))
        for key in ('circuit_id', 'r1cs_sha256', 'profile_sha256'):
            if not direct._hash(identity.pop(key, None)):
                raise ValueError('frozen circuit/relation/profile required')
        for key in ('program_id', 'genesis', 'request_address'):
            if type(identity.pop(key, None)) is not str:
                raise ValueError('explicit program/genesis/request PDA required')
        identity['finalized_request_sha256'] = identity.pop(
            'finalized_request_account_sha256', None)
        direct._arm_identity({**row, 'schema': direct.ARM_SCHEMA,
                              'identity': identity}, mode, 0)
        blank = row.get('seed', {})
        if (blank.get('deployed_inside_timer') is not True
                or any(not direct._hash(blank.get(k)) for k in
                       ('manifest_sha256', 'tree_sha256', 'genesis_file_sha256'))):
            raise ValueError('timed blank seed import and application deployment required')
        for key in ('final_request_sha256', 'final_queue_sha256'):
            if not direct._hash(row['effect'].get(key)):
                raise ValueError('finalized exact effect bytes required')
        destinations.extend((blank.get('initial_ledger'), blank.get('control_ledger'),
                             row['clone']['destination']))
        for key in ('transaction_bytes', 'compute_units', 'fee_lamports'):
            value = row.get('transaction_metrics', {}).get(key)
            if type(value) is not int or value < (0 if key == 'fee_lamports' else 1):
                raise ValueError('direct finalized transaction metrics required')
    if (full['identity'] != anchor['identity']
            or full['run_manifest_sha256'] != anchor['run_manifest_sha256']
            or full['shared_context_sha256'] != anchor['shared_context_sha256']
            or any(full['seed'][k] != anchor['seed'][k] for k in
                   ('manifest_sha256', 'tree_sha256', 'genesis_file_sha256'))
            or any(full['evidence'].get(k) != anchor['evidence'].get(k)
                   for k in ('plan_sha256', 'replay_package_sha256'))
            or any(full['effect'][k] != anchor['effect'][k]
                   for k in ('final_request_sha256', 'final_queue_sha256'))):
        raise ValueError('matched exact request/action/roots/product/seed/effect required')
    _disjoint(destinations)
    fseconds = _outer(full_outer, 'full', repeat)
    aseconds = _outer(anchor_outer, 'anchor', repeat)
    return {'schema': PAIR_SCHEMA, 'repeat': repeat, 'status': 'valid',
            'variant': 0, 'update_count': 1, 'order': list(order),
            'full_direct_wall_seconds': fseconds, 'anchor_direct_wall_seconds': aseconds,
            'anchor_wall_savings_fraction': (fseconds - aseconds) / fseconds,
            'registered_complete_session_gate_satisfied': True,
            'complete_tree_cpu_qualified': False}


def summarize(pairs):
    if (len(pairs) != 4 or [p.get('repeat') for p in pairs] != list(range(4))
            or any(p.get('status') not in ('valid', 'excluded') for p in pairs)):
        raise ValueError('exactly four registered outcomes, with no replacements, required')
    values = [p['anchor_wall_savings_fraction'] for p in pairs if p['status'] == 'valid']
    if any(type(v) not in (int, float) or not math.isfinite(v) for v in values):
        raise ValueError('finite paired savings required')
    median = statistics.median(values) if values else None
    return {'valid_pairs': len(values), 'excluded_pairs': 4 - len(values),
            'four_valid_pairs': len(values) == 4,
            'all_pair_savings_fractions': [p.get('anchor_wall_savings_fraction') for p in pairs],
            'median_savings_fraction': median,
            'spread_min_max': [min(values), max(values)] if values else None,
            'registered_target_fraction': .20,
            'registered_twenty_percent_target_met': len(values) == 4 and median >= .20,
            'break_even_crossing_directly_measured': False, 'k_gt_1_measured': False,
            'complete_tree_cpu_qualified': False}


def run_boundary(operations):
    if set(operations) != set(BOUNDARY) or any(not callable(v) for v in operations.values()):
        raise ValueError('every charged whole-session operation is required')
    results = {}
    for name in BOUNDARY:
        started = time.monotonic()
        value = operations[name]()
        results[name] = {'result': value, 'attribution_wall_seconds': time.monotonic() - started}
    return results


def reconstruct_replay(output, entropy, context_path, domain):
    """Action-specific derivation occurs inside each mode clock; only entropy is shared."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    roles = ('admin', 'publisher', 'source', 'creator')
    if (type(entropy) is not dict or set(entropy) != {'schema', 'keys', 'seed', 'nonce'}
            or entropy['schema'] != 'credential-v3-whole-session-entropy-v1'
            or type(entropy['keys']) is not dict or set(entropy['keys']) != set(roles)
            or any(not direct._hash(v) for v in list(entropy['keys'].values()) +
                   [entropy['seed'], entropy['nonce']])):
        raise ValueError('exact fixed random entropy receipt required')
    output = direct._private_dir(output, fresh=True)
    context_raw = seed._raw(context_path)
    context = json.loads(context_raw)
    plan = {k: list(bytes.fromhex(context[k])) for k in ('root', 'issuer_hash', 'aki', 'policy_id')}
    plan.update(program=list(seed.base.key(domain['program'])),
                genesis=list(seed.base.key(domain['genesis'])),
                seed=list(bytes.fromhex(entropy['seed'])), nonce=list(bytes.fromhex(entropy['nonce'])),
                deadline=context['not_after'], payload=[0, 1, 2, 3])
    files = {}
    for role in roles:
        secret = bytes.fromhex(entropy['keys'][role])
        public = Ed25519PrivateKey.from_private_bytes(secret).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        plan[role] = list(public)
        files[role + '.json'] = direct._write_new(output / (role + '.json'), list(secret + public))
    plan['recipient'] = plan['source']
    files['plan.json'] = direct._write_new(output / 'plan.json', plan)
    path = output / 'replay-package.json'
    sha = direct._write_new(path, {'schema': 'part5-v3-stage-replay-v1',
        'context_sha256': direct._digest(context_raw), 'files': files})
    return {'path': str(path), 'sha256': sha}


def selected_roots(source):
    roots = source.get('membership_roots')
    if (type(roots) is not dict or set(roots) != {'R0', 'R1', 'R2'}
            or any(not direct._hash(v) for v in roots.values())):
        raise ValueError('source must retain all three authenticated membership roots')
    return {key: roots[key] for key in ('R0', 'R1')}


def allocate_shared_costs(*, seed_seconds, entropy_seconds, setup_seconds, setup_actions):
    values = (seed_seconds, entropy_seconds, setup_seconds)
    if (any(type(v) not in (int, float) or not math.isfinite(v) or v <= 0 for v in values)
            or type(setup_actions) is not int or setup_actions < 1):
        raise ValueError('positive measured common costs and allocation denominator required')
    common = (seed_seconds + entropy_seconds) / 8
    setup = setup_seconds / setup_actions
    return {'seed_creation_outer_seconds': seed_seconds, 'entropy_generation_seconds': entropy_seconds,
            'seed_and_entropy_allocation_actions': 8,
            'seed_and_entropy_seconds_per_action': common,
            'setup_outer_seconds': setup_seconds, 'setup_allocation_actions': setup_actions,
            'setup_seconds_per_action': setup, 'equal_common_seconds_per_mode_action': common + setup,
            'same_allocation_for_full_and_anchor': True, 'added_to_direct_outer_wall': False,
            'issuance_and_enrollment': 'common prerequisites outside authorization; see pinned prerequisite receipt'}


def _checked_blob(path, expected, cap=512 * 1024 * 1024):
    """Stream historical product pins without retaining a large R1CS in memory."""
    path = Path(path)
    info = path.lstat()
    if (not direct._hash(expected) or not path.is_absolute() or path.resolve() != path
            or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or not 0 < info.st_size <= cap):
        raise ValueError('bounded canonical setup artifact required')
    ident = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mode,
                           value.st_uid, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    digest, count = hashlib.sha256(), 0
    with os.fdopen(fd, 'rb') as stream:
        if ident(info) != ident(os.fstat(stream.fileno())):
            raise ValueError('setup artifact changed at open')
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
            count += len(block)
        if ident(info) != ident(os.fstat(stream.fileno())):
            raise ValueError('setup artifact changed during read')
    if (count != info.st_size or ident(info) != ident(path.lstat())
            or digest.hexdigest() != expected):
        raise ValueError('historical setup product pin mismatch')


def _historical_setup_wall(report):
    # This is an explicit historical schema, never a fallback for failed current
    # mode evidence. No measurement/censored fields are inserted or inferred.
    required = {'schema', 'owner', 'duration_seconds', 'limits', 'stop_reason', 'exit_code',
                'runner_error_type', 'cleanup_remaining_owned_processes', 'cleanup_status_unknown',
                'sample_count', 'samples', 'sampled_peak_owned_tree_rss_bytes',
                'sampled_peak_storage_growth_bytes', 'passed'}
    if type(report) is not dict or not required <= set(report):
        raise ValueError('complete explicit historical bounded setup fields required')
    duration = report.get('duration_seconds')
    if (report.get('schema') != 1 or 'measurement' in report or 'censored' in report
            or report.get('passed') is not True or type(report.get('exit_code')) is not int
            or report['exit_code'] != 0 or report.get('stop_reason') is not None
            or report.get('runner_error_type') is not None
            or type(report.get('cleanup_remaining_owned_processes')) is not int
            or report['cleanup_remaining_owned_processes'] != 0
            or report.get('cleanup_status_unknown') is not False
            or type(duration) not in (int, float) or not math.isfinite(duration) or duration <= 0):
        raise ValueError('successful stopped historical bounded setup report required')
    limits = report.get('limits')
    keys = ('runtime_seconds', 'owned_tree_rss_bytes', 'storage_growth_bytes', 'poll_seconds')
    if (type(limits) is not dict or set(limits) != set(keys)
            or any(type(limits[k]) not in (int, float) or not math.isfinite(limits[k])
                   or limits[k] <= 0 for k in keys) or duration > limits['runtime_seconds']):
        raise ValueError('finite historical setup caps required')
    samples = report.get('samples')
    if (type(samples) is not list or not samples or type(report.get('sample_count')) is not int
            or report['sample_count'] != len(samples)):
        raise ValueError('complete historical setup sample sequence required')
    previous = -1.0
    for sample in samples:
        if type(sample) is not dict:
            raise ValueError('historical setup resource sample object required')
        elapsed = sample.get('elapsed_seconds')
        if (type(elapsed) not in (int, float) or not math.isfinite(elapsed)
                or not 0 <= elapsed <= duration or elapsed <= previous
                or any(type(sample.get(k)) is not int or sample[k] < 0 for k in
                       ('owned_process_count', 'owned_tree_rss_bytes', 'storage_growth_bytes'))):
            raise ValueError('monotonic finite historical setup samples required')
        previous = elapsed
    if samples[-1]['owned_process_count'] != 0:
        raise ValueError('historical setup final sample must show stopped owner')
    for peak, sampled, cap in (
        ('sampled_peak_owned_tree_rss_bytes', 'owned_tree_rss_bytes', 'owned_tree_rss_bytes'),
        ('sampled_peak_storage_growth_bytes', 'storage_growth_bytes', 'storage_growth_bytes')):
        actual = max(s[sampled] for s in samples)
        if report.get(peak) != actual or actual > limits[cap]:
            raise ValueError('historical setup sampled resource evidence differs from caps')
    return float(duration)


def setup_accounting(prerequisites, manifest):
    """Keep historical common setup disclosure distinct from strict mode clocks."""
    report = seed.pin(prerequisites['setup_monitor'])
    kind = prerequisites.get('setup_measurement_kind', 'bounded_complete_session')
    if kind == 'bounded_complete_session':
        return {'measurement_kind': kind, 'duration_seconds': direct._outer_seconds(report),
                'qualification': 'current bounded complete-session setup wall',
                'current_session_schema_qualified': True,
                'monitor': prerequisites['setup_monitor'], 'complete_tree_cpu_qualified': False}
    if kind != 'historical-bounded-runner-v1':
        raise ValueError('explicit supported common setup measurement kind required')
    duration = _historical_setup_wall(report)
    invocation_ref = prerequisites.get('setup_invocation')
    invocation = seed.pin(invocation_ref)
    frozen = manifest['frozen_files']
    setup_ref = frozen['setup_manifest']
    setup = seed.pin(setup_ref)
    if (prerequisites.get('setup_manifest_sha256') != setup_ref['sha256']
            or setup.get('schema') != 'credential-v3-bounded-setup-v1'
            or setup.get('r1cs_sha256') != frozen['r1cs']['sha256']
            or setup.get('profile_sha256') != frozen['profile']['sha256']
            or type(setup.get('elapsed_ms')) not in (int, float)
            or not math.isfinite(setup['elapsed_ms']) or not 0 < setup['elapsed_ms'] <= duration * 1000):
        raise ValueError('historical setup must bind the frozen relation/profile and own inner timer')
    argv = invocation.get('argv')
    output = str(Path(setup_ref['path']).parent)
    monitor_parent = str(Path(prerequisites['setup_monitor']['path']).parent)
    if (set(invocation) != {'owner', 'argv', 'cwd', 'started_at_utc', 'storage_roots'}
            or type(report.get('owner')) is not str or not report['owner']
            or invocation.get('owner') != report['owner'] or invocation.get('cwd') != str(ROOT)
            or type(invocation.get('started_at_utc')) is not str or not invocation['started_at_utc']
            or str(Path(invocation_ref['path']).parent) != monitor_parent
            or invocation.get('storage_roots') != [monitor_parent, output]
            or type(argv) is not list or len(argv) != 8
            or any(type(v) is not str for v in argv) or argv[1] != 'setup'
            or argv[2] != frozen['r1cs']['path'] or argv[4] != frozen['profile']['path']
            or argv[5] != setup.get('accepted_suite_path')
            or argv[6] != setup.get('accepted_suite_sha256') or argv[7] != output):
        raise ValueError('exact historical setup invocation and storage coverage required')
    _disjoint(invocation['storage_roots'])
    for path, expected in ((argv[0], setup.get('binary_sha256')), (argv[2], setup['r1cs_sha256']),
            (argv[3], setup.get('wasm_sha256')), (argv[4], setup['profile_sha256']),
            (argv[5], setup['accepted_suite_sha256'])):
        _checked_blob(path, expected)
    return {'measurement_kind': kind, 'duration_seconds': duration,
            'qualification': 'historical bounded setup wall only',
            'current_session_schema_qualified': False,
            'missing_current_fields': ['measurement', 'censored'],
            'monitor': prerequisites['setup_monitor'], 'invocation': invocation_ref,
            'setup_manifest': setup_ref, 'inner_setup_seconds': setup['elapsed_ms'] / 1000,
            'historical_producer_source_pin_available': False,
            'complete_tree_cpu_qualified': False,
            'caveat': 'Historical report retains its original schema and pins; its producer source was not pinned in the invocation. This common setup disclosure does not qualify any current per-mode clock.'}


def _pin(path):
    return {'path': str(path), 'sha256': direct._digest(seed._raw(path, 4 * 1024 * 1024))}


def normalize_stopped_log_alias(ledger, cleanup):
    """Remove only the validator's stopped log alias, never ledger-state bytes."""
    if not seed.reviewed_stop(cleanup):
        raise ValueError('reviewed stopped validator required before log alias cleanup')
    ledger = seed._directory(ledger)
    alias = ledger / 'validator.log'
    links = []
    for directory, names, files in os.walk(ledger, followlinks=False):
        for name in names + files:
            path = Path(directory) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                links.append(path)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                raise ValueError('linked ledger files cannot be normalized')
    if not links:
        return {'schema': 'part5-v3-stopped-validator-log-alias-v1', 'removed': False}
    if links != [alias]:
        raise ValueError('only the root validator log alias may be normalized')
    info = alias.lstat()
    target_name = os.readlink(alias)
    if (info.st_uid != os.getuid() or info.st_nlink != 1
            or re.fullmatch(r'validator-[0-9]+\.log', target_name) is None):
        raise ValueError('normal same-directory validator log target required')
    target = ledger / target_name
    target_info = target.lstat()
    if (not stat.S_ISREG(target_info.st_mode) or target_info.st_uid != os.getuid()
            or stat.S_IMODE(target_info.st_mode) != 0o600 or target_info.st_nlink != 1):
        raise ValueError('owner-only unlinked regular validator log target required')
    target_hash = direct._digest(seed._raw(target, seed.base.LIMITS['storage_growth_bytes']))
    ident = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_uid,
                         row.st_nlink, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    if (ident(alias.lstat()) != ident(info) or os.readlink(alias) != target_name
            or ident(target.lstat()) != ident(target_info)):
        raise ValueError('validator log alias changed after stopped inspection')
    alias.unlink()
    return {'schema': 'part5-v3-stopped-validator-log-alias-v1', 'removed': True,
            'alias': 'validator.log', 'target': target_name, 'target_sha256': target_hash,
            'target_bytes_unchanged': True, 'ledger_state_bytes_changed': False}


def _create_seed(config_ref):
    """Bounded worker body; creation has no ELF or application program load."""
    config = seed.pin(config_ref)
    if (config.get('scope') != seed.CREATE_SCOPE
            or config.get('outer_limits_required') != seed.base.LIMITS
            or config.get('runtime_feature_profile') != seed.LOCAL_COMPATIBILITY_PROFILE):
        raise ValueError('explicit bounded blank creation contract required')
    seed.base.checked(config['validator'], config['validator_sha256'], 128 * 1024 * 1024)
    root = Path(config['runtime_output']).parent
    runtime, control = Path(config['runtime_output']), Path(config['control_output'])
    if runtime != root / 'runtime' or control != root / 'control':
        raise ValueError('canonical blank creation layout required')
    direct._private_dir(root, fresh=True, ignored=True)
    direct._private_dir(runtime, fresh=True, ignored=True)
    direct._private_dir(control, fresh=True, ignored=True)
    status = {'schema': 1, 'scope': seed.CREATE_SCOPE, 'status': 'failed',
              'config_sha256': config_ref['sha256'], 'ledger': str(runtime / 'ledger'),
              'application_effect': False, 'prepared_application_accounts': False,
              'runtime_feature_profile': seed.LOCAL_COMPATIBILITY_PROFILE,
              'error_type': None, 'blank_verified': False}
    proc, handlers = None, {}
    previous_umask = os.umask(0o077)
    def interrupted(signum, frame):
        raise InterruptedError('blank creation interrupted')
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            handlers[signum] = signal.signal(signum, interrupted)
        seed.base.ports_free(timeout_seconds=seed.base.PORT_WAIT_SECONDS)
        argv = seed.creation_argv(config['validator'], runtime / 'ledger', config['payer'])
        with (control / 'validator.stdout.log').open('xb') as out, \
                (control / 'validator.stderr.log').open('xb') as err:
            Path(out.name).chmod(0o600); Path(err.name).chmod(0o600)
            proc = subprocess.Popen(argv, cwd=ROOT, stdin=subprocess.DEVNULL,
                                    stdout=out, stderr=err, start_new_session=False)
            rpc = seed.base.LocalRpc()
            deadline = time.monotonic() + 30
            genesis = None
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise RuntimeError('blank validator exited during startup')
                try:
                    genesis = rpc('getGenesisHash', [])
                    seed.base.key(genesis)
                    break
                except (OSError, seed.base.NotReady):
                    time.sleep(.1)
            if genesis is None:
                raise TimeoutError('blank genesis readiness deadline')
            observation_domain = {'program': config['program'], 'payer': config['payer'],
                'programdata': seed.programdata_address(config['program']), 'genesis': genesis,
                'runtime_feature_profile': seed.LOCAL_COMPATIBILITY_PROFILE}
            status['seed_observation'] = seed.observe_blank(rpc, proc, observation_domain)
            status['blank_verified'] = True
            status['status'] = 'passed'
    except Exception as error:
        status['error_type'] = type(error).__name__
    finally:
        for signum in handlers:
            signal.signal(signum, signal.SIG_IGN)
        try:
            status['cleanup'] = seed.base.cleanup(proc)
        except Exception as error:
            status['cleanup'] = {'spawned': proc is not None, 'reaped': False,
                                 'graceful': False, 'error_type': type(error).__name__}
        if not status['cleanup'].get('graceful'):
            status['status'] = 'failed'
        if status.get('blank_verified') is True and status.get('error_type') is None:
            try:
                status['ledger_log_normalization'] = normalize_stopped_log_alias(
                    runtime / 'ledger', status['cleanup'])
            except Exception as error:
                status['error_type'] = type(error).__name__
                status['status'] = 'failed'
        try:
            direct._write_new(control / 'status.json', status)
        finally:
            os.umask(previous_umask)
            for signum, previous in handlers.items():
                signal.signal(signum, previous)
    return status


def _seeded_runner(case_runner, manifest, output, run_ref, manifest_sha,
                   seed_ref, deployment_inputs, replay=None, allowed_outputs=None):
    class SeededRunner(case_runner.HeldoutCaseRunner):
        def _art(self, req, label):
            path = super()._art(req, label)
            if allowed_outputs is not None and path not in allowed_outputs:
                raise ValueError('application output is outside predeclared storage coverage')
            return path

        def _prepare(self, req, root, case_root, stage_context):
            runtime, control = self._art(req, 'runtime'), self._art(req, 'prepare-control')
            config = {**self.base_prepare, **deployment_inputs, 'blank_seed': seed_ref,
                      'runtime_output': runtime, 'control_output': control}
            config_path = root / 'prepare-config.json'
            config_sha = self._write_config(config_path, config)
            monitor_path, monitor_dir = root / 'prepare-monitor.json', root / 'prepare-monitor'
            owner = f'whole-v00-{self.run_id}-{req}-prepare'
            outer = self.bounded_run(owner,
                [sys.executable, str(self.toolpaths['prepare']), '--config', str(config_path),
                 '--config-sha256', config_sha], monitor_dir, monitor_path,
                runtime=case_runner.LIMITS['runtime_seconds'], storage_paths=(Path(runtime),),
                env={'P5_V3_PREPARE_SCOPE': 'local-validator-prepare'})
            status_path = Path(control) / 'status.json'
            status = case_runner._json(status_path)
            seed.review_prepare(status, outer, config,
                {'prior_config_sha256': config_sha, 'ledger': str(Path(runtime) / 'ledger'),
                 'expected_genesis': status.get('loaded_program', {}).get('genesis'),
                 'prior_monitor_owner': owner})
            return {'config': str(config_path), 'config_sha256': config_sha,
                    **case_runner.status_artifact(status_path),
                    'monitor': str(monitor_path), 'monitor_sha256': direct._digest(seed._raw(monitor_path)),
                    'monitor_owner': owner, 'runtime': runtime, 'control': control}

        def _write_config(self, path, value):
            if value.get('scope') == 'part5-v3-local-stage' and replay is not None:
                value['replay_package'] = replay
            return super()._write_config(path, value)

    return SeededRunner(manifest, output, run_manifest_ref=run_ref, manifest_sha256=manifest_sha)


def _pair_view(runner, manifest):
    builder = direct._load_module('whole_session_context_builder',
                                  ROOT / 'tools/part5/prepare_v3_heldout_context.py')
    case_root = direct._private_dir(runner.output_root / 'pair-view', fresh=True, ignored=True)
    builder.prepare(Path(manifest['cohort_root']), manifest['cohort_sha256'], 0, case_root)
    return case_root


def _source(runner, manifest, root, case_root, stage, transition, variant, r0=None):
    out = direct._private_dir(root / ('source-' + variant), fresh=True, ignored=True)
    command = [sys.executable, str(ROOT / 'tools/part5/prepare_v3_heldout_source.py'),
        '--case-root', str(case_root), '--cohort-root', manifest['cohort_root'],
        '--freeze-receipt', manifest['freeze_receipt'], '--freeze-sha256', manifest['freeze_sha256'],
        '--stage-root', stage['root'], '--exporter', manifest['proof_inputs']['exporter']['path'],
        '--variant', variant, '--output', str(out)]
    if variant == 'R1':
        command.extend(['--transition-root', transition['root'], '--transition-context', transition['context'],
            '--transition-context-sha256', transition['context_sha256'],
            '--r0-source-receipt', r0['receipt'], '--r0-source-receipt-sha256', r0['receipt_sha256']])
    monitor_path = root / ('source-' + variant + '-monitor.json')
    monitor = runner.bounded_run(f'whole-v00-{runner.run_id}-source-{variant}', command,
        root / ('source-' + variant + '-monitor'), monitor_path,
        runtime=direct._load_module('whole_source_case_limits',
            ROOT / 'tools/part5/run_v3_heldout_case.py').LIMITS['runtime_seconds'], storage_paths=(out,))
    direct._outer_seconds(monitor)
    receipt = out / 'source-receipt.json'
    if json.loads(seed._raw(receipt)).get('schema') != 'credential-v3-heldout-request-source-v1':
        raise ValueError('complete request source receipt required')
    return {'status': 'passed', 'root': str(out), 'receipt': str(receipt),
            'receipt_sha256': direct._digest(seed._raw(receipt)), 'monitor': str(monitor_path),
            'monitor_sha256': direct._digest(seed._raw(monitor_path))}


def _run_mode(case_runner, manifest, run_ref, manifest_sha, worker_root, mode,
              repeat, launch):
    blank_ref, deployment = launch['blank_seed'], launch['deployment_inputs']
    blank = seed.review_manifest(blank_ref, {
        'program': manifest['program'] if 'program' in manifest else
            case_runner._json(manifest['base_prepare_config'])['program'],
        'validator_sha256': case_runner._json(manifest['base_prepare_config'])['validator_sha256']})
    entropy = seed.pin(launch['entropy'])
    allowed_outputs = frozenset(arm_storage_paths(case_runner, worker_root.parent,
                                                launch['run_ids'], mode)[1:])
    direct._private_dir(worker_root, fresh=True, ignored=True)
    run_ids = launch['run_ids']
    initialize_runner_root(worker_root / 'control-case', run_ids['control'])
    initialize_runner_root(worker_root / 'main-case', run_ids['main'])
    control = _seeded_runner(case_runner, manifest, worker_root / 'control-case',
                             run_ref, manifest_sha, blank_ref, deployment,
                             allowed_outputs=allowed_outputs)
    main = _seeded_runner(case_runner, manifest, worker_root / 'main-case',
                          run_ref, manifest_sha, blank_ref, deployment,
                          allowed_outputs=allowed_outputs)
    req = 'unrelated_compare'
    croot, root = control._layout(req), main._layout(req)
    state = {}

    def initial():
        state['control_view'] = _pair_view(control, manifest)
        value = control._prepare(req, croot, state['control_view'], None)
        state['control_prepared'] = value
        return value

    def replay():
        value = reconstruct_replay(worker_root / 'replay-package', entropy,
                                    state['control_view'] / 'stage-context.json', blank)
        state['replay'] = value
        return value

    def control_fixture():
        # Replay injection is confined to this runner instance and executed inside
        # the outer worker. It never changes a frozen global helper or source.
        original = control._write_config
        def write(path, value):
            if value.get('scope') == 'part5-v3-local-stage':
                value = {**value, 'replay_package': state['replay']}
            return original(path, value)
        control._write_config = write
        value = control._stage(req, croot, state['control_view'], None,
                                state['control_prepared'])
        state['control_stage'] = value
        return value

    def main_prepare():
        state['main_view'] = _pair_view(main, manifest)
        original = main._write_config
        def write(path, value):
            if value.get('scope') == 'part5-v3-local-stage':
                value = {**value, 'replay_package': state['replay']}
            return original(path, value)
        main._write_config = write
        value = main._prepare(req, root, state['main_view'], None)
        state['prepared'] = value
        return value

    def main_stage():
        value = main._stage(req, root, state['main_view'], None, state['prepared'])
        control_doc = case_runner._json(state['control_stage']['report'],
                                        state['control_stage']['report_sha256'])
        doc = case_runner._json(value['report'], value['report_sha256'])
        if (doc['request'] != control_doc['request']
                or doc['account_sha256'][3] != control_doc['account_sha256'][3]
                or value['plan_sha256'] != state['control_stage']['plan_sha256']):
            raise ValueError('independent control and main request bytes differ')
        state['stage'] = value
        return value

    def transition():
        value = main._transition(req, root, state['main_view'], state['stage'])
        state['transition'] = value
        return value

    def source(variant):
        value = _source(main, manifest, root, state['main_view'], state['stage'],
                         state['transition'], variant, state.get('R0'))
        state[variant] = value
        return value

    def proof():
        value = main._request_proof(req, mode, root, state['main_view'], state['stage'],
                                    state['transition'], state['R0'], state['R1'])
        state['proof'] = value
        return value

    def clone():
        value = main._clone_r1(req, 'r1-' + mode, root, state['transition'])
        state['clone'] = value
        return value

    def effect():
        proof = state['proof']
        wires = {'full': proof['wires']['r0_full_wire'], 'anchor': proof['wires']['r1_wire']}
        if mode == 'full':
            wires['full_near'] = proof['wires']['r1_wire']
        value = main._run_branch(req, 'unrelated_full' if mode == 'full' else 'anchor', mode,
            root, state['stage'], state['transition'], state['clone'], {mode: proof}, wires)
        state['effect'] = value
        return value

    with main.journal:
        stages = run_boundary(dict(zip(BOUNDARY, (initial, replay, control_fixture,
            main_prepare, main_stage, transition, lambda: source('R0'), lambda: source('R1'),
            proof, clone, effect))))
    r0 = case_runner._json(state['R0']['receipt'], state['R0']['receipt_sha256'])
    r1 = case_runner._json(state['R1']['receipt'], state['R1']['receipt_sha256'])
    stage_doc = case_runner._json(state['stage']['report'], state['stage']['report_sha256'])
    proof_doc = case_runner._json(state['proof']['receipt'], state['proof']['receipt_sha256'])
    proof_report = case_runner._json(proof_doc['proof_report']['path'],
                                      proof_doc['proof_report']['sha256'])
    branch = case_runner._json(state['effect']['report'], state['effect']['report_sha256'])
    clone_doc = case_runner._json(state['clone']['receipt'], state['clone']['receipt_sha256'])
    prepare_status = case_runner._json(state['prepared']['status_path'], state['prepared']['status_sha256'])
    if (r0.get('membership_roots') != r1.get('membership_roots')
            or r0.get('selected_root') != r0['membership_roots']['R0']
            or r1.get('selected_root') != r0['membership_roots']['R1']
            or any(r0.get(k) != r1.get(k) for k in ('target_der_sha256', 'staged_request_sha256',
                'finalized_action_transport_sha256', 'action_hash'))
            or r0.get('staged_request_sha256') != stage_doc['account_sha256'][3]
            or proof_doc.get('proof_created') is not True
            or proof_doc.get('mode') != mode
            or proof_doc.get('ordinary_verification', {}).get('passed') is not True
            or proof_report.get('passed') is not True
            or proof_report.get('mode') != ('matched-full-k1' if mode == 'full' else 'matched-anchor-k1')
            or branch.get('passed') is not True or branch.get('effect_count') != 1
            or branch.get('request_consumed') is not True or branch.get('mode') != mode
            or clone_doc.get('copy_identical') is not True):
        raise ValueError('complete whole-session proof/source/finalized-effect evidence required')
    scenario = 'v3-valid-full-R1' if mode == 'full' else 'v3-valid-anchor-R1'
    txs = [t for t in branch['transactions'] if t.get('scenario') == scenario and t.get('err') is None]
    if len(txs) != 1:
        raise ValueError('one finalized successful Execute transaction required')
    frozen = manifest['frozen_files']
    identity = {k: r0[v] for k, v in (
        ('credential_sha256', 'target_der_sha256'), ('finalized_request_account_sha256', 'staged_request_sha256'),
        ('finalized_action_transport_sha256', 'finalized_action_transport_sha256'), ('action_hash', 'action_hash'))}
    identity.update(circuit_id=main.freeze_doc['identities']['circuit'],
        r1cs_sha256=frozen['r1cs']['sha256'], profile_sha256=frozen['profile']['sha256'],
        program_id=stage_doc['program'], genesis=stage_doc['genesis'], request_address=stage_doc['request'],
        roots=selected_roots(r0), setup_sha256=frozen['setup_manifest']['sha256'],
        vk_sha256=frozen['ordinary_vk']['sha256'], elf_sha256=frozen['loaded_elf']['sha256'])
    return {'schema': ARM_SCHEMA, 'variant': 0, 'repeat': repeat, 'mode': mode, 'status': 'passed',
        'run_manifest_sha256': manifest_sha, 'shared_context_sha256': launch['shared_identity_sha256'],
        'identity': identity, 'boundary_steps': list(stages), 'run_ids': run_ids,
        'stage_attribution_seconds': {k: v['attribution_wall_seconds'] for k, v in stages.items()},
        'seed': {'manifest_sha256': blank_ref['sha256'], 'tree_sha256': blank['tree_sha256'],
                 'genesis_file_sha256': blank['genesis_file_sha256'],
                 'initial_ledger': str(Path(state['prepared']['runtime']) / 'ledger'),
                 'control_ledger': str(Path(state['control_prepared']['runtime']) / 'ledger'),
                 'deployed_inside_timer': prepare_status.get('preparation_kind') == seed.KIND},
        'proof': {'mode': mode, 'proof_created': True, 'ordinary_verified': True,
                  'receipt_sha256': state['proof']['receipt_sha256']},
        'clone': {k: clone_doc[k] for k in ('tree_sha256', 'destination', 'copy_identical')}
                  | {'receipt_sha256': state['clone']['receipt_sha256']},
        'effect': {'mode': mode, 'passed': True, 'effect_count': 1, 'request_consumed': True,
                   'report_sha256': state['effect']['report_sha256'],
                   'final_request_sha256': branch['account_sha256'][3],
                   'final_queue_sha256': branch['account_sha256'][4]},
        'transaction_metrics': {k: txs[0].get(v) for k, v in (
            ('transaction_bytes', 'transactionBytes'), ('compute_units', 'computeUnits'),
            ('fee_lamports', 'feeLamports'))},
        'evidence': {'stage_report_sha256': state['stage']['report_sha256'],
            'transition_report_sha256': state['transition']['report_sha256'],
            'plan_sha256': state['stage']['plan_sha256'], 'replay_package_sha256': state['replay']['sha256'],
            'control_stage_report_sha256': state['control_stage']['report_sha256'],
            'source_R0_sha256': state['R0']['receipt_sha256'], 'source_R1_sha256': state['R1']['receipt_sha256']},
        'limitations': {'complete_tree_cpu_qualified': False, 'k_gt_1_measured': False,
            'private_proof_state_serialization_reload': 'not used; ledger persistence/reload is charged',
            'two_charged_deployments_per_mode': 'independent control and main blank-seed ledgers'}}


def _new_supervision():
    parent = direct._canonical_directory(ARTIFACTS.parent)
    return direct._private_dir(parent / ('.v3-whole-supervisor-' + uuid.uuid4().hex),
                                fresh=True, ignored=True)


def _storage_paths(monitor, covered):
    covered = Path(covered)
    _disjoint((str(monitor), str(covered)))
    direct._private_dir(Path(monitor).parent, ignored=True)
    direct._canonical_directory(covered)
    if Path(monitor).exists() or Path(monitor).is_symlink():
        raise ValueError('fresh disjoint whole-session monitor required')
    return (str(covered),)


def initialize_runner_root(path, run_id):
    if (type(run_id) is not str or len(run_id) != 32
            or any(c not in direct.HEX for c in run_id)):
        raise ValueError('pinned random application output run id required')
    path = direct._private_dir(path, fresh=True, ignored=True)
    direct._write_new(path / 'run-id.json', {
        'schema': 'credential-v3-heldout-run-id-v1', 'run_id': run_id})


def arm_storage_paths(case_runner, mode_root, run_ids, mode):
    """Cover every new output without walking historical Part 5 artifacts."""
    if (type(run_ids) is not dict or set(run_ids) != {'control', 'main'}
            or run_ids['control'] == run_ids['main'] or mode not in ('full', 'anchor')):
        raise ValueError('separate pinned control/main output identities required')
    paths = [str(mode_root)]
    common = ('runtime', 'prepare-control', 'stage', 'stage-control')
    branch = 'unrelated_full' if mode == 'full' else 'anchor'
    labels = {'control': common,
              'main': common + ('transition', 'transition-control', branch, branch + '-control')}
    for role in ('control', 'main'):
        for label in labels[role]:
            path = ARTIFACTS / case_runner.application_artifact_name(
                0, run_ids[role], 'unrelated_compare', label)
            if path.parent != ARTIFACTS or path.exists() or path.is_symlink():
                raise ValueError('fresh canonical application storage sibling required')
            paths.append(str(path))
    _disjoint(paths)
    return tuple(paths)


def _ticket(mode_root, worker_output, mode, manifest_sha, context_sha):
    token = uuid.uuid4().hex
    direct._write_new(mode_root / direct.WORKER_TICKET_NAME, {
        'schema': direct.WORKER_TICKET_SCHEMA, 'mode': mode,
        'case_output_root': str(worker_output), 'manifest_sha256': manifest_sha,
        'shared_context_sha256': context_sha, 'supervisor_pid': os.getpid(), 'token': token})
    return token


def _launch_seed(session, manifest_path, manifest_ref, base_prepare, deployment,
                 output_root, supervision):
    mode_root = direct._private_dir(output_root / 'shared-seed', fresh=True, ignored=True)
    seed_root = mode_root / 'case-run'
    config = {'schema': 1, 'scope': seed.CREATE_SCOPE,
        'outer_limits_required': seed.base.LIMITS,
        'runtime_feature_profile': seed.LOCAL_COMPATIBILITY_PROFILE,
        'owner_source': {'path': str(Path(__file__).resolve()),
                         'sha256': direct._digest(Path(__file__).read_bytes())},
        'owner_manifest': manifest_ref, 'runtime_output': str(seed_root / 'runtime'),
        'control_output': str(seed_root / 'control'),
        'validator': base_prepare['validator'], 'validator_sha256': base_prepare['validator_sha256'],
        'program': base_prepare['program'], 'payer': seed.signer(deployment['deployment_payer'])}
    config_path = mode_root / 'seed-config.json'
    config_sha = direct._write_new(config_path, config)
    token = _ticket(mode_root, seed_root, 'seed', manifest_ref['sha256'], config_sha)
    monitor, outer_path = supervision / 'seed-monitor', supervision / 'seed-outer.json'
    caps = OUTER_LIMITS['seed']
    command = [sys.executable, str(Path(__file__).resolve()), '--manifest', str(manifest_path),
        '--output-root', str(seed_root), '--seed-config', str(config_path),
        '--seed-config-sha256', config_sha, '--_create-seed']
    outer = session.run(owner='heldout-v00-whole-seed', command=command, cwd=str(ROOT),
        private_output=str(monitor), report=str(outer_path),
        runtime_seconds=caps['runtime_seconds'], rss_bytes=caps['rss_bytes'],
        storage_bytes=caps['storage_bytes'], storage_paths=_storage_paths(monitor, output_root),
        environment={'TZ': 'UTC', 'RAYON_NUM_THREADS': '4', 'OMP_NUM_THREADS': '1',
                     'P5_V3_DIRECT_ARM_WORKER_TOKEN': token})
    duration = _outer(outer, 'seed', None)
    sources = {'config': {'path': str(config_path), 'sha256': config_sha},
        'status': _pin(seed_root / 'control/status.json'), 'monitor': _pin(outer_path),
        'invocation': _pin(monitor / 'invocation.json'), 'monitor_owner': 'heldout-v00-whole-seed'}
    blank = seed.build_manifest(sources)
    path = mode_root / 'blank-seed.json'
    sha = direct._write_new(path, blank)
    return {'path': str(path), 'sha256': sha}, {'seed_creation_outer_seconds': duration,
        'source_creation': sources, 'scope': 'immutable blank-chain creation outside mode timers'}


def run_seed_pilot(manifest_path, output_root):
    """Credential-independent source-only registration; invocation is a heavy pilot."""
    manifest_path, output_root = Path(manifest_path), Path(output_root)
    ref = _pin(manifest_path)
    pilot = seed.pin(ref)
    if (set(pilot) != {'schema', 'prepare_config', 'deployment_inputs'}
            or pilot['schema'] != 'credential-v3-blank-seed-pilot-v1'):
        raise ValueError('explicit credential-independent blank-seed pilot manifest required')
    base, deployment = seed.pin(pilot['prepare_config']), seed.pin(pilot['deployment_inputs'])
    if (output_root.parent != ARTIFACTS or not output_root.is_absolute()
            or set(deployment) != {'solana_cli', 'program_signer', 'deployment_payer'}):
        raise ValueError('fresh Part 5 pilot root and exact deployment refs required')
    lock_fd = complete._acquire_lock(complete.global_heavy_lock())
    try:
        direct._private_dir(output_root, fresh=True, ignored=True)
        supervision = _new_supervision()
        session = direct._load_module('whole_seed_pilot_session', ROOT / 'results/dynark/part5/session_runner.py')
        blank_ref, costs = _launch_seed(session, manifest_path, ref, base, deployment, output_root, supervision)
        report = {'schema': 'credential-v3-blank-seed-pilot-result-v1', 'pilot_manifest': ref,
                  'blank_seed': blank_ref, 'creation': costs, 'heldout_acceptance': False,
                  'runtime_feature_profile': seed.LOCAL_COMPATIBILITY_PROFILE,
                  'registered_complete_session_gate_satisfied': False,
                  'application_deployment_run': False, 'credential_issuance_run': False}
        path = output_root / 'seed-pilot-report.json'
        direct._write_new(path, report)
        return report
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _create_seed_worker(manifest_path, output_root, config_ref):
    # This command also supports the pre-freeze pilot. The owner manifest pins
    # provenance and purpose; it is never admitted as a final heldout case here.
    manifest_ref = _pin(manifest_path)
    manifest = seed.pin(manifest_ref)
    config = seed.pin(config_ref)
    allowed = ('credential-v3-blank-seed-pilot-v1', 'credential-v3-whole-session-seed-launch-v1')
    if (manifest.get('schema') not in allowed or config.get('owner_manifest') != manifest_ref
            or config.get('runtime_output') != str(Path(output_root) / 'runtime')
            or config.get('control_output') != str(Path(output_root) / 'control')
            or config.get('owner_source') != {'path': str(Path(__file__).resolve()),
                'sha256': direct._digest(Path(__file__).read_bytes())}):
        raise ValueError('pinned pilot or final seed owner manifest required')
    mode_root = Path(output_root).parent
    token = os.environ.get('P5_V3_DIRECT_ARM_WORKER_TOKEN')
    direct._authorize_worker(mode_root / direct.WORKER_TICKET_NAME, output_root,
        'seed', manifest_ref['sha256'], token, lock_path=complete.global_heavy_lock())
    claim = direct._load_json(mode_root / direct.WORKER_CLAIM_NAME)
    if claim['shared_context_sha256'] != config_ref['sha256']:
        raise ValueError('seed owner ticket does not bind creation config')
    return _create_seed(config_ref)


def require_freeze(manifest):
    pins = complete.require_measurement_freeze(manifest)
    for role, files in {'client': ('tools/part5/run_v3_heldout_whole_session.py',),
            'registry': ('harness/tests/queue_v3_blank_seed.py',
                         'harness/tests/queue_v3_local_prepare.py',
                         'harness/tests/queue_v3_local_stage.py')}.items():
        members = {r.get('path'): r.get('artifact') for r in manifest.get('frozen_bundles', {}).get(role, [])}
        for relative in files:
            ref = members.get(relative)
            path = ROOT / relative
            if (type(ref) is not dict or ref.get('path') != str(path)
                    or ref.get('sha256') != direct._digest(path.read_bytes())):
                raise ValueError('fresh freeze must pin whole-session dependency: ' + relative)
            pins[relative] = ref['sha256']
    return pins


def _mode_worker(manifest_path, worker_output, launch_ref, mode, repeat):
    case = direct._load_module('whole_worker_case', ROOT / 'tools/part5/run_v3_heldout_case.py')
    _, manifest, run_ref, manifest_sha = direct._read_manifest(case, Path(manifest_path))
    if manifest['variant'] != 0:
        raise ValueError('registered primary credential is variant 00')
    require_freeze(manifest)
    registered_order(repeat)
    launch = seed.pin(launch_ref)
    mode_root = Path(worker_output).parent
    direct._authorize_worker(mode_root / direct.WORKER_TICKET_NAME, worker_output,
        mode, manifest_sha, os.environ.get('P5_V3_DIRECT_ARM_WORKER_TOKEN'),
        lock_path=complete.global_heavy_lock())
    claim = direct._load_json(mode_root / direct.WORKER_CLAIM_NAME)
    if (claim['shared_context_sha256'] != launch_ref['sha256']
            or launch.get('repeat') != repeat or launch.get('mode') != mode
            or launch.get('run_manifest_sha256') != manifest_sha):
        raise ValueError('whole-session launch does not bind owner/mode/repeat/manifest')
    row = _run_mode(case, manifest, run_ref, manifest_sha, Path(worker_output), mode, repeat, launch)
    require_freeze(manifest)
    direct._write_new(mode_root / 'arm-report.json', row)
    return row


def _clean_outer(report):
    return (report.get('cleanup_remaining_owned_processes') == 0
            and report.get('cleanup_status_unknown') is False
            and report.get('runner_error_type') is None)


def run_campaign(manifest_path, output_root, deployment_ref, prerequisite_ref):
    case = direct._load_module('whole_campaign_case', ROOT / 'tools/part5/run_v3_heldout_case.py')
    _, manifest, run_ref, manifest_sha = direct._read_manifest(case, Path(manifest_path))
    if manifest['variant'] != 0:
        raise ValueError('registered primary credential must be final-cohort variant 00')
    measurement_sources = require_freeze(manifest)
    deployment, prerequisites = seed.pin(deployment_ref), seed.pin(prerequisite_ref)
    if set(deployment) != {'solana_cli', 'program_signer', 'deployment_payer'}:
        raise ValueError('exact independent deployment input refs required')
    if (prerequisites.get('schema') != 'credential-v3-whole-session-prerequisites-v1'
            or prerequisites.get('setup_manifest_sha256') != manifest['frozen_files']['setup_manifest']['sha256']
            or prerequisites.get('cohort_sha256') != manifest['cohort_sha256']
            or type(prerequisites.get('issuance_and_enrollment')) is not dict):
        raise ValueError('pinned setup and separately disclosed issuance/enrollment costs required')
    setup_evidence = setup_accounting(prerequisites, manifest)
    setup_seconds = setup_evidence['duration_seconds']
    output_root = Path(output_root)
    if not output_root.is_absolute() or output_root.parent != ARTIFACTS:
        raise ValueError('fresh Part 5 whole-session campaign root required')
    lock_fd = complete._acquire_lock(complete.global_heavy_lock())
    try:
        direct._private_dir(output_root, fresh=True, ignored=True)
        supervision = _new_supervision()
        session = direct._load_module('whole_campaign_session', ROOT / 'results/dynark/part5/session_runner.py')
        base_prepare = case._json(manifest['base_prepare_config'], manifest['base_prepare_config_sha256'])
        # Final seed creation has a separate source-bound launch manifest. Pilot
        # receipts can never be silently reused as final campaign seed evidence.
        seed_owner_path = output_root / 'seed-owner-manifest.json'
        seed_owner_sha = direct._write_new(seed_owner_path, {
            'schema': 'credential-v3-whole-session-seed-launch-v1', 'run_manifest': run_ref,
            'measurement_sources': measurement_sources, 'deployment_inputs': deployment_ref})
        blank_ref, creation = _launch_seed(session, seed_owner_path,
            {'path': str(seed_owner_path), 'sha256': seed_owner_sha}, base_prepare,
            deployment, output_root, supervision)
        entropy_started = time.monotonic()
        entropy = {'schema': 'credential-v3-whole-session-entropy-v1',
            'keys': {role: os.urandom(32).hex() for role in ('admin', 'publisher', 'source', 'creator')},
            'seed': os.urandom(32).hex(), 'nonce': os.urandom(32).hex()}
        entropy_path = output_root / 'fixed-entropy.json'
        entropy_ref = {'path': str(entropy_path), 'sha256': direct._write_new(entropy_path, entropy)}
        entropy_seconds = time.monotonic() - entropy_started
        allocation = allocate_shared_costs(seed_seconds=creation['seed_creation_outer_seconds'],
            entropy_seconds=entropy_seconds, setup_seconds=setup_seconds,
            setup_actions=prerequisites['setup_allocation_actions'])
        allocation['setup_measurement'] = setup_evidence
        shared_sha = direct._digest(json.dumps({'blank_seed': blank_ref['sha256'],
            'entropy': entropy_ref['sha256'], 'manifest': manifest_sha,
            'deployment': deployment_ref['sha256']}, sort_keys=True).encode())
        pairs, arm_refs, abort = [], [], False
        for repeat in range(4):
            order = registered_order(repeat)
            if abort:
                pairs.append({'repeat': repeat, 'status': 'excluded',
                    'reason': 'not launched after incompletely cleaned prior owner'})
                continue
            rows, outers, receipts, reason = {}, {}, {}, None
            for mode in order:
                mode_root = direct._private_dir(output_root / f'repeat-{repeat}-{mode}', fresh=True, ignored=True)
                worker_output = mode_root / 'case-run'
                launch = {'schema': 'credential-v3-whole-session-launch-v1', 'repeat': repeat,
                    'mode': mode, 'run_manifest_sha256': manifest_sha, 'blank_seed': blank_ref,
                    'entropy': entropy_ref, 'deployment_inputs': deployment,
                    'run_ids': {'control': uuid.uuid4().hex, 'main': uuid.uuid4().hex},
                    'shared_identity_sha256': shared_sha}
                launch_path = mode_root / 'launch.json'
                launch_ref = {'path': str(launch_path), 'sha256': direct._write_new(launch_path, launch)}
                token = _ticket(mode_root, worker_output, mode, manifest_sha, launch_ref['sha256'])
                outer_path = supervision / f'r{repeat}-{mode}-outer.json'
                monitor = supervision / f'r{repeat}-{mode}-monitor'
                caps = OUTER_LIMITS[mode]
                outer = session.run(owner=f'heldout-v00-whole-r{repeat}-{mode}',
                    command=[sys.executable, str(Path(__file__).resolve()), '--manifest', str(manifest_path),
                        '--output-root', str(worker_output), '--launch', str(launch_path),
                        '--launch-sha256', launch_ref['sha256'], '--_mode', mode, '--repeat', str(repeat)],
                    cwd=str(ROOT), private_output=str(monitor), report=str(outer_path),
                    runtime_seconds=caps['runtime_seconds'], rss_bytes=caps['rss_bytes'],
                    storage_bytes=caps['storage_bytes'],
                    storage_paths=arm_storage_paths(case, mode_root, launch['run_ids'], mode),
                    environment={'TZ': 'UTC', 'RAYON_NUM_THREADS': '4', 'OMP_NUM_THREADS': '1',
                                 'P5_V3_DIRECT_ARM_WORKER_TOKEN': token})
                receipts[mode] = {'outer_report': _pin(outer_path),
                    'sampled_peak_owned_tree_rss_bytes': outer.get('sampled_peak_owned_tree_rss_bytes'),
                    'sampled_peak_storage_growth_bytes': outer.get('sampled_peak_storage_growth_bytes'),
                    'cpu': {'complete_tree_cpu_qualified': False}}
                try:
                    _outer(outer, mode, repeat)
                    arm_path = mode_root / 'arm-report.json'
                    rows[mode] = seed.pin(_pin(arm_path))
                    if (rows[mode].get('shared_context_sha256') != shared_sha
                            or rows[mode].get('run_ids') != launch['run_ids']):
                        raise ValueError('arm changed shared seed/entropy/deployment identity')
                    receipts[mode]['arm_report'] = _pin(arm_path)
                    receipts[mode]['transaction_metrics'] = rows[mode]['transaction_metrics']
                    outers[mode] = outer
                except (ValueError, OSError, KeyError, TypeError) as error:
                    reason = type(error).__name__ + ': mode failed/censored or evidence rejected'
                    abort = not _clean_outer(outer)
                    break
            if reason is None:
                try:
                    pair = validate_pair(rows['full'], rows['anchor'], outers['full'], outers['anchor'],
                                         repeat=repeat, order=order)
                    common = allocation['equal_common_seconds_per_mode_action']
                    pair['allocated_common_seconds_per_action'] = common
                    pair['anchor_allocated_total_wall_savings_fraction'] = (
                        pair['full_direct_wall_seconds'] - pair['anchor_direct_wall_seconds']) / (
                            pair['full_direct_wall_seconds'] + common)
                    pair['allocated_total_wall_setup_qualification'] = setup_evidence['qualification']
                    pair['allocated_total_wall_current_setup_qualified'] = setup_evidence['current_session_schema_qualified']
                except (ValueError, KeyError, TypeError):
                    pair = {'repeat': repeat, 'status': 'excluded', 'reason': 'exact pair matching rejected'}
            else:
                pair = {'repeat': repeat, 'status': 'excluded', 'reason': reason}
            pairs.append(pair)
            arm_refs.append({'repeat': repeat, 'arms': receipts})
            direct._write_new(output_root / f'pair-{repeat}-report.json', pair)
        report = {'schema': CAMPAIGN_SCHEMA, 'variant': 0, 'update_count': 1,
            'runtime_feature_profile': seed.LOCAL_COMPATIBILITY_PROFILE,
            'run_manifest': run_ref, 'measurement_sources': measurement_sources,
            'registered_order': [list(registered_order(i)) for i in range(4)],
            'pairs': pairs, 'summary': summarize(pairs), 'arms': arm_refs,
            'shared_cost_allocation': allocation, 'shared_seed_creation': creation,
            'prerequisite_receipt': prerequisite_ref, 'blank_seed_manifest_sha256': blank_ref['sha256'],
            'fixed_entropy_sha256': entropy_ref['sha256'],
            'measurement_scope': 'direct outer whole-session initial application preparation through finalized Execute and owned cleanup',
            'timing_notes': ['only immutable blank-chain seed creation and random entropy precede mode timers',
                'replay derivation, both control/main blank imports and ELF deployments, source/witness/relation work, selected proof and ordinary verification, transition, persisted ledger clone/reload, finalized Execute and owned cleanup are charged',
                'nested stage times are attribution only; no component sum substitutes for the outer wall',
                'monitor setup and final outer report writes are excluded by session_runner',
                'failed/censored/mismatched pairs are retained and excluded without replacement',
                'CPU is unqualified; RSS/storage are sampled and may miss brief spikes',
                'private proof-state serialization/reload is not used; application ledger persistence/reload is measured',
                'issuer enrollment and certificate issuance are common prerequisites disclosed in the pinned receipt']}
        require_freeze(manifest)
        path = output_root / 'whole-session-campaign-report.json'
        digest = direct._write_pair_report(path, report)
        return {'report': report, 'report_path': str(path), 'report_sha256': digest}
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output-root', type=Path, required=True)
    parser.add_argument('--seed-only', action='store_true',
                        help='credential-independent blank-chain pilot; no heldout result')
    parser.add_argument('--seed-config', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--seed-config-sha256', help=argparse.SUPPRESS)
    parser.add_argument('--_create-seed', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--deployment-inputs', type=Path)
    parser.add_argument('--deployment-inputs-sha256')
    parser.add_argument('--prerequisites', type=Path)
    parser.add_argument('--prerequisites-sha256')
    parser.add_argument('--launch', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--launch-sha256', help=argparse.SUPPRESS)
    parser.add_argument('--_mode', choices=('full', 'anchor'), help=argparse.SUPPRESS)
    parser.add_argument('--repeat', type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args._create_seed:
            status = _create_seed_worker(args.manifest, args.output_root,
                {'path': str(args.seed_config), 'sha256': args.seed_config_sha256})
            if status['status'] != 'passed':
                raise SystemExit(1)
            print(json.dumps({'schema': seed.CREATE_SCOPE, 'status': 'passed'}))
        elif args._mode:
            row = _mode_worker(args.manifest, args.output_root,
                {'path': str(args.launch), 'sha256': args.launch_sha256}, args._mode, args.repeat)
            print(json.dumps({'schema': ARM_SCHEMA, 'mode': row['mode'], 'repeat': row['repeat']}))
        elif args.seed_only:
            report = run_seed_pilot(args.manifest, args.output_root)
            print(json.dumps({'schema': report['schema'], 'blank_seed': report['blank_seed']}))
        else:
            result = run_campaign(args.manifest, args.output_root,
                {'path': str(args.deployment_inputs), 'sha256': args.deployment_inputs_sha256},
                {'path': str(args.prerequisites), 'sha256': args.prerequisites_sha256})
            print(json.dumps({'schema': CAMPAIGN_SCHEMA, 'report': result['report_path'],
                              'report_sha256': result['report_sha256']}))
    except Exception as error:
        raise SystemExit(f'whole-session measurement rejected: {type(error).__name__}: {str(error)[:180]}') from None


if __name__ == '__main__':
    main()
