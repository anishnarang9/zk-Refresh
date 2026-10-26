#!/usr/bin/env python3
"""Read-only, post-exit finalization of a bounded expired-status candidate.

The caller supplies independently retained SHA-256 pins in a manifest. These pins
are not signatures or authenticated provenance. No RPC, verifier, validator,
process cleanup, proof creation, or build is performed. A 705 rejection and an
ordinary-verification assertion in a proof receipt do not prove validity. The
only supported validity bridge is a separately pinned, independently supervised
loaded Full success with the identical complete wire and exact staged config and
request. Other positive formats fail closed until an adapter is implemented.

Successful output is a binding receipt containing the strict evidence report.
Failures return a blocker without either successful schema or full_wire_valid.
The receipt establishes consistency of retained loaded-run evidence, never
heldout acceptance, source-to-binary build provenance, or unsampled resource peaks.
"""
import argparse
import copy
import hashlib
import json
import math
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from harness.tests import queue_v3_local_expired_status_negative as supervisor
from tools.part5 import heldout_expired_status_evidence as evidence

MANIFEST_SCHEMA = 'part5-v3-expired-status-finalizer-input-v1'
FINAL_SCHEMA = 'part5-v3-expired-status-finalization-v1'
BLOCKED_SCHEMA = 'part5-v3-expired-status-finalization-blocked-v1'
REF_ROLES = ('config', 'candidate', 'supervisor_status', 'monitor', 'monitor_invocation')
POSITIVE_ROLES = ('config', 'report', 'status', 'monitor', 'monitor_invocation', 'monitor_owner')
SOURCE_PATHS = (
    'harness/src/solana/queue_v3.rs',
    'harness/src/solana/queue_v3/expired_status_negative.rs',
    'harness/tests/queue_v3.rs',
    'harness/tests/queue_v3_local_expired_status_negative.py',
    'harness/tests/queue_v3_local_execute.py',
    'harness/tests/queue_v3_local_stage.py',
    'harness/tests/queue_v3_local_prepare.py',
    'harness/tests/queue_v3_build_prep.py',
    'harness/tests/queue_v3_clone_ledger.py',
    'harness/tests/queue_v3_loaded_negative_checks.py',
    'results/dynark/part5/session_runner.py',
    'tools/part5/heldout_expired_status_evidence.py',
    'tools/part5/finalize_v3_expired_status_negative.py',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def number(value, integer=False, positive=False):
    return evidence._number(value, integer=integer, positive=positive)


class Inputs:
    """Bounded nonsymlink reads, with every consumed byte rechecked before return."""
    def __init__(self):
        self.reads = []

    def raw(self, ref, cap=2 * 1024 * 1024):
        raw = evidence._snapshot(ref, cap)
        self.reads.append((copy.deepcopy(ref), cap, raw))
        return raw

    def doc(self, ref, cap=1024 * 1024):
        raw = self.raw(ref, cap)
        value = supervisor.execute.base.decode_json(raw)
        def finite(item):
            if type(item) is float:
                require(math.isfinite(item), 'finite JSON numbers required')
            elif type(item) is dict:
                for child in item.values():
                    finite(child)
            elif type(item) is list:
                for child in item:
                    finite(child)
        finite(value)
        require(type(value) is dict, 'JSON object required')
        return value

    def recheck(self):
        for ref, cap, raw in self.reads:
            require(evidence._snapshot(ref, cap) == raw, 'input changed during finalization')


def config_ref(config, path, digest):
    return {'path': config[path], 'sha256': config[digest]}


def check_monitor(monitor, invocation, owner, command_path, config_pin,
                  storage_required, cwd, *, private_output, expected_exit=0):
    """Check the existing session_runner report, including all sample maxima."""
    require({'schema', 'measurement', 'owner', 'passed', 'censored', 'exit_code',
             'stop_reason', 'runner_error_type', 'cleanup_remaining_owned_processes',
             'cleanup_status_unknown'} <= set(monitor), 'complete external cleanup fields required')
    require(monitor.get('schema') == 1
            and monitor.get('measurement') == 'bounded_complete_session'
            and monitor.get('owner') == owner and invocation.get('owner') == owner
            and monitor.get('passed') is (expected_exit == 0) and monitor.get('censored') is False
            and type(monitor.get('exit_code')) is int and monitor['exit_code'] == expected_exit
            and monitor.get('stop_reason') is None and monitor.get('runner_error_type') is None
            and type(monitor.get('cleanup_remaining_owned_processes')) is int
            and monitor['cleanup_remaining_owned_processes'] == 0
            and monitor.get('cleanup_status_unknown') is False,
            'successful external post-exit whole-tree cleanup required')
    argv = invocation.get('argv')
    require(type(argv) is list and len(argv) == 6
            and type(argv[0]) is str and Path(argv[0]).is_absolute()
            and argv[1:] == [str(command_path), '--config', config_pin['path'],
                             '--config-sha256', config_pin['sha256']]
            and invocation.get('cwd') == str(cwd),
            'external monitor must own the exact pinned supervisor invocation')
    roots = invocation.get('storage_roots')
    require(type(roots) is list and roots and all(type(p) is str for p in roots),
            'external storage roots required')
    roots = [Path(p) for p in roots]
    require(all(p.is_absolute() and p.resolve() == p for p in roots),
            'canonical external storage roots required')
    private_output = Path(private_output)
    require(private_output.is_absolute() and private_output.resolve() == private_output
            and roots[0] == private_output,
            'external monitor must measure its private_output as first storage root')
    require(all(not (p == q or p in q.parents or q in p.parents)
                for i, p in enumerate(roots) for q in roots[i + 1:]),
            'disjoint external storage roots required')
    require(all(any(Path(p) == root or root in Path(p).parents for root in roots)
                for p in storage_required), 'external monitor omitted mutable storage root')
    limits = monitor.get('limits')
    evidence._fields(limits, ('runtime_seconds', 'owned_tree_rss_bytes',
                              'storage_growth_bytes', 'poll_seconds'))
    expected = supervisor.LIMITS
    for key, expected_key in (('runtime_seconds', 'runtime_seconds'),
                              ('owned_tree_rss_bytes', 'rss_bytes'),
                              ('storage_growth_bytes', 'storage_growth_bytes')):
        value = number(limits[key], positive=True, integer=key != 'runtime_seconds')
        require(value == expected[expected_key], 'external owner limits differ from pinned bounds')
    require(number(limits['poll_seconds'], positive=True) <= 0.2,
            'external sampling interval exceeds bounded runner default')
    duration = number(monitor.get('duration_seconds'), positive=True)
    require(duration <= limits['runtime_seconds'], 'owner wall bound exceeded after cleanup')
    samples = monitor.get('samples')
    require(type(samples) is list and samples
            and type(monitor.get('sample_count')) is int
            and monitor['sample_count'] == len(samples), 'external samples required')
    previous = -1
    for row in samples:
        evidence._fields(row, ('elapsed_seconds', 'owned_process_count',
            'sampled_tree_self_cpu_seconds_lower_bound', 'owned_tree_rss_bytes', 'storage_growth_bytes'))
        elapsed = number(row['elapsed_seconds'])
        require(previous <= elapsed <= duration, 'external sample chronology required')
        previous = elapsed
        for key in ('owned_process_count', 'owned_tree_rss_bytes', 'storage_growth_bytes'):
            number(row[key], integer=True)
        number(row['sampled_tree_self_cpu_seconds_lower_bound'])
    require(any(row['owned_process_count'] > 0 for row in samples),
            'external monitor must observe the owned execution tree')
    for key, maximum, bound in (
            ('owned_tree_rss_bytes', 'sampled_peak_owned_tree_rss_bytes', 'owned_tree_rss_bytes'),
            ('storage_growth_bytes', 'sampled_peak_storage_growth_bytes', 'storage_growth_bytes')):
        peak = number(monitor.get(maximum), integer=True)
        require(peak == max(row[key] for row in samples) and peak <= limits[bound],
                'external resource peak inconsistent or out of bounds')
    return duration


def monitor_pair(inputs, monitor_ref, invocation_ref):
    monitor = inputs.doc(monitor_ref)
    invocation = inputs.doc(invocation_ref)
    # session_runner writes identical report bytes next to its private invocation
    # and at the external report path, after it has reaped the leader and tree.
    require(Path(invocation_ref['path']).name == 'invocation.json',
            'external monitor private invocation path required')
    private_report = {'path': str(Path(invocation_ref['path']).parent / 'report.json'),
                      'sha256': monitor_ref['sha256']}
    require(inputs.raw(private_report) == inputs.raw(monitor_ref),
            'external and private post-exit report bytes differ')
    return monitor, invocation


def positive_full(inputs, refs, config, negative, negative_status):
    """Use retained loaded Full success; no proof assertion is used as a verifier."""
    require(type(refs) is dict and set(refs) == set(POSITIVE_ROLES),
            'same-wire positive loaded Full evidence required; receipt assertions are insufficient')
    positive = inputs.doc(refs['config'])
    # Replay the stable admission contract after exit. Full execute.admit cannot
    # be called here: it requires fresh output paths and a pre-run clone inventory.
    require(type(positive.get('schema')) is int and positive['schema'] == 1
            and positive.get('scope') == 'part5-v3-local-execute',
            'positive actual bounded Execute config contract required')
    supervisor._same_json(positive.get('outer_limits_required'), supervisor.execute.LIMITS,
                         'positive Execute limits must match exact admission LIMITS')
    for key in ('ledger', 'stage_root', 'execute_output', 'control_output'):
        value = positive.get(key)
        require(type(value) is str and Path(value).is_absolute() and Path(value).resolve() == Path(value),
                'positive canonical configured storage paths required')
    supervisor.execute.stage.validate_stage_paths(Path(positive['execute_output']),
        Path(positive['control_output']), REPO / 'artifacts/dynark/part5')
    report, status = inputs.doc(refs['report']), inputs.doc(refs['status'])
    monitor, invocation = monitor_pair(inputs, refs['monitor'], refs['monitor_invocation'])
    for key in ('stage_root', 'stage_report_sha256', 'stage_plan_sha256', 'full_wire_sha256',
                'expected_genesis'):
        require(positive.get(key) == config[key], 'positive Full uses a different stage, root, request, or wire')
    require(status.get('schema') == 1 and status.get('scope') == 'part5-v3-local-execute'
            and status.get('config_sha256') == refs['config']['sha256']
            and status.get('effect_verified') is True and status.get('application_effect') is True
            and status.get('effect_outcome') == 'verified'
            and type(status.get('effect_count')) is int and status['effect_count'] == 1
            and status.get('error_type') is None
            and status.get('execute_report_sha256') == refs['report']['sha256'],
            'independently supervised positive Full effect required')
    require(status.get('execute_output') == positive['execute_output']
            and refs['report']['path'] == str(Path(positive['execute_output']) / 'execute-report.json')
            and refs['status']['path'] == str(Path(positive['control_output']) / 'status.json'),
            'positive report and status must bind configured Execute output paths')
    supervisor.execute.same_loaded(negative_status['loaded_program'], status.get('loaded_program', {}))
    loaded = report.get('loaded_program', {})
    require(loaded.get('elf_match') is True and loaded.get('elf_sha256') == config['expected_elf_sha256'],
            'positive Full loaded ELF mismatch')
    original = {'program': config['expected_program']}
    number(report.get('finalized_slot'), integer=True, positive=True)
    require(type(report.get('effect_count')) is int, 'positive integer effect count required')
    supervisor.execute.check_effect_report(report, positive, original)
    require(number(status.get('finalized_slot'), integer=True, positive=True) >= report['finalized_slot'],
            'positive independent finalized account slot required')
    positive_wire = inputs.raw(config_ref(positive, 'full_wire', 'full_wire_sha256'), 448)
    require(len(positive_wire) == 448 and positive_wire == inputs.raw(negative['source_refs']['full_wire'], 448),
            'positive Full must use the identical complete statement and proof wire')
    stage_report = inputs.doc(config_ref(config, 'stage_report', 'stage_report_sha256'))
    before, after = [], []
    for index, name in enumerate(supervisor.ACCOUNT_NAMES):
        ref = {'path': str(Path(config['stage_root']) / (name + '.bin')),
               'sha256': stage_report['account_sha256'][index]}
        before.append(inputs.raw(ref, 4096))
        post_ref = {'path': str(Path(positive['execute_output']) / (name + '.bin')),
                    'sha256': report['account_sha256'][index]}
        after.append(inputs.raw(post_ref, 4096))
    supervisor.execute.check_effect_bytes(before, after, stage_report)
    for index in (0, 3, 4):
        require(before[index] == inputs.raw(negative['snapshots'][index]['before'], 4096),
                'positive Full exact config/root, request/action, and queue mismatch')
    require(stage_report.get('program') == config['expected_program']
            and stage_report.get('genesis') == config['expected_genesis'],
            'positive staged program/genesis mismatch')
    require(type(refs['monitor_owner']) is str and refs['monitor_owner'], 'positive monitor owner required')
    runner_cleanup, validator_cleanup = status.get('runner_cleanup', {}), status.get('validator_cleanup', {})
    require(runner_cleanup.get('reaped') is True
            and type(runner_cleanup.get('exit_code')) is int and runner_cleanup['exit_code'] == 0
            and validator_cleanup.get('reaped') is True
            and type(validator_cleanup.get('exit_code')) is int, 'positive direct child cleanup required')
    if status.get('status') == 'passed':
        require(validator_cleanup.get('graceful') is True and validator_cleanup['exit_code'] == 0,
                'positive passed status cleanup mismatch')
        expected_exit = 0
    else:
        require(status.get('status') == 'failed' and validator_cleanup.get('graceful') is False
                and validator_cleanup['exit_code'] == -2, 'positive reviewed SIGINT cleanup required')
        expected_exit = 1
    check_monitor(monitor, invocation, refs['monitor_owner'],
                  REPO / 'harness/tests/queue_v3_local_execute.py', refs['config'],
                  [positive['ledger'], positive['execute_output'], positive['control_output']], REPO,
                  private_output=Path(refs['monitor_invocation']['path']).parent,
                  expected_exit=expected_exit)
    return {'method': 'identical-wire-loaded-full-effect', 'wire_sha256': config['full_wire_sha256'],
            'statement_sha256': hashlib.sha256(positive_wire[:192]).hexdigest(),
            'proof_wire_sha256': hashlib.sha256(positive_wire[192:]).hexdigest(),
            'positive_report_sha256': refs['report']['sha256'],
            'positive_supervisor_status_sha256': refs['status']['sha256'],
            'positive_outer_monitor_sha256': refs['monitor']['sha256'],
            'positive_config_sha256': refs['config']['sha256'],
            'full_proof_receipt_sha256': config['full_proof_receipt_sha256']}


def finalize(manifest):
    """Raise on any missing gate; return a bound report only after all gates pass."""
    evidence._fields(manifest, ('schema', 'refs', 'source_pins', 'positive_full'))
    require(manifest['schema'] == MANIFEST_SCHEMA, 'finalizer manifest schema mismatch')
    refs = manifest['refs']
    evidence._fields(refs, REF_ROLES)
    inputs = Inputs()
    pins = manifest['source_pins']
    evidence._fields(pins, SOURCE_PATHS)
    for relative, digest in pins.items():
        inputs.raw({'path': str(REPO / relative), 'sha256': evidence._hash(digest)})
    config = inputs.doc(refs['config'], 65536)
    supervisor._validate_config(config)
    # The cloned ledger changes during execution. Reopen immutable inputs, never
    # reuse the pre-run clone inventory equality test on a post-run ledger.
    for path, digest, cap in supervisor.INPUT_ARTIFACTS:
        inputs.raw(config_ref(config, path, digest), cap)
    inputs.raw(config_ref(config, 'runner', 'runner_sha256'), 128 * 1024 * 1024)
    proof = inputs.doc(config_ref(config, 'full_proof_receipt', 'full_proof_receipt_sha256'))
    require(proof.get('schema') == 'credential-v3-heldout-proof-evidence-v1'
            and proof.get('mode') == 'full' and proof.get('proof_created') is True
            and type(proof.get('target_variant')) is int and proof['target_variant'] == config['variant']
            and proof.get('freeze_sha256') == config['freeze_sha256']
            and proof.get('stage_report_sha256') == config['stage_report_sha256']
            and proof.get('stage_plan_sha256') == config['stage_plan_sha256']
            and proof.get('source_receipts', {}).get('R0')
                == config_ref(config, 'source_receipt', 'source_receipt_sha256')
            and proof.get('wires', {}).get('r0_full_wire')
                == config_ref(config, 'full_wire', 'full_wire_sha256')
            and type(proof.get('artifacts')) is dict
            and config_ref(config, 'full_proof', 'full_proof_sha256') in proof['artifacts'].values(),
            'Full proof receipt must bind the exact source, stage, wire and proof bytes')
    genesis_ref = {'path': str(Path(config['ledger']) / 'genesis.bin'),
                   'sha256': config['expected_genesis_sha256']}
    inputs.raw(genesis_ref, 16 * 1024 * 1024)
    candidate, status = inputs.doc(refs['candidate'], 65536), inputs.doc(refs['supervisor_status'], 65536)
    require(refs['candidate']['path'] == str(Path(config['output_dir']) / supervisor.REPORT_NAME)
            and refs['supervisor_status']['path'] == str(Path(config['control_output']) / 'status.json'),
            'exact candidate and supervisor output paths required')
    require(status.get('schema') == 1 and status.get('scope') == supervisor.SCOPE
            and status.get('status') == 'candidate_verified_pending_external_finalization'
            and status.get('candidate_verified') is True and 'error_type' in status
            and status['error_type'] is None
            and status.get('candidate_path') == refs['candidate']['path']
            and status.get('candidate_sha256') == refs['candidate']['sha256']
            and status.get('candidate_schema') == supervisor.CANDIDATE_SCHEMA
            and status.get('config_path') == refs['config']['path']
            and status.get('config_sha256') == refs['config']['sha256']
            and status.get('owner') == config['owner']
            and status.get('output_dir') == config['output_dir']
            and status.get('application_effect') is False
            and status.get('external_finalization_required') is True,
            'supervisor must bind exact verified candidate and config bytes')
    for role, exit_code in (('runner', 0), ('validator', -2)):
        cleanup = status.get(role + '_cleanup', {})
        require(cleanup.get('spawned') is True and cleanup.get('reaped') is True
                and type(cleanup.get('exit_code')) is int and cleanup['exit_code'] == exit_code,
                'supervisor direct child reaping required')
    require(status['validator_cleanup'].get('graceful') is False,
            'negative validator reviewed SIGINT cleanup required')
    require(status.get('validator_alive_before_cleanup') is True,
            'validator must survive all final RPC checks')
    loaded = status.get('loaded_program', {})
    require(type(loaded) is dict and loaded.get('program') == config['expected_program']
            and loaded.get('genesis') == config['expected_genesis']
            and loaded.get('elf_match') is True and loaded.get('elf_sha256') == config['expected_elf_sha256'],
            'supervisor loaded identity mismatch')
    supervisor._validate_candidate(candidate, config, refs['config']['path'], refs['config']['sha256'],
        Path(config['output_dir']), loaded, candidate['runner_observations']['pid'])
    require(number(status.get('live_rechecked_finalized_slot'), integer=True, positive=True)
            >= candidate['account_slots']['after'], 'independent post-candidate finality required')
    monitor, invocation = monitor_pair(inputs, refs['monitor'], refs['monitor_invocation'])
    wall = check_monitor(monitor, invocation, config['owner'],
        REPO / 'harness/tests/queue_v3_local_expired_status_negative.py', refs['config'],
        [config['ledger'], config['output_dir'], config['control_output']], REPO,
        private_output=Path(refs['monitor_invocation']['path']).parent)
    require(candidate['runner_observations']['elapsed_seconds']
            <= number(status.get('elapsed_seconds')) <= wall,
            'runner and supervisor durations must fit externally measured owner wall')
    proof_binding = positive_full(inputs, manifest['positive_full'], config, candidate, status)
    report = {key: copy.deepcopy(candidate[key]) for key in (
        'identities', 'clock', 'transaction', 'source_refs', 'snapshots', 'application_effect')}
    report.update({'schema': evidence.SCHEMA,
        'preconditions': {key: True for key in ('status_active', 'issuer_active', 'head_bound',
                                               'request_live', 'full_wire_valid')},
        'limits': {'owner_wall_seconds': supervisor.LIMITS['runtime_seconds'],
                   'rss_bytes': supervisor.LIMITS['rss_bytes'],
                   'storage_growth_bytes': supervisor.LIMITS['storage_growth_bytes'],
                   'clock_wait_seconds': config['wait_deadline_seconds']},
        'measured': {'owner_wall_seconds': wall,
                     'clock_wait_seconds': candidate['runner_observations']['clock_wait_seconds'],
                     'peak_owned_rss_bytes': monitor['sampled_peak_owned_tree_rss_bytes'],
                     'storage_growth_bytes': monitor['sampled_peak_storage_growth_bytes']},
        'cleanup': {'remaining_owned_processes': 0, 'status_unknown': False,
                    'runner_reaped': True, 'validator_reaped': True, 'censored': False,
                    'stop_reason': None, 'runner_error_type': None}})
    facts = evidence.validate_report(report, supervisor._expected_identities(config))
    inputs.recheck()
    return {'schema': FINAL_SCHEMA, 'bindings': copy.deepcopy(manifest),
            'proof_validity_binding': proof_binding, 'evidence': report, 'facts': facts,
            'heldout_acceptance_established': False,
            'resource_accounting': 'sampled RSS and logical storage; external owner wall includes cleanup'}


def finalize_or_block(manifest):
    try:
        return finalize(manifest)
    except (ValueError, KeyError, TypeError, AttributeError, IndexError, OverflowError,
            OSError, RuntimeError, RecursionError) as error:
        return {'schema': BLOCKED_SCHEMA, 'status': 'blocked', 'blocker': str(error)[:256],
                'error_type': type(error).__name__, 'evidence_emitted': False,
                'proof_validity_established': False, 'heldout_acceptance_established': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    inputs = Inputs()
    try:
        manifest = inputs.doc({'path': str(args.manifest), 'sha256': args.manifest_sha256})
        result = finalize_or_block(manifest)
        inputs.recheck()
    except (ValueError, OSError, RuntimeError, RecursionError) as error:
        result = {'schema': BLOCKED_SCHEMA, 'status': 'blocked', 'blocker': str(error)[:256],
                  'evidence_emitted': False, 'proof_validity_established': False}
    supervisor.execute.base.write_new(args.output, result)
    print(json.dumps({'schema': result['schema'], 'evidence_emitted': result['schema'] == FINAL_SCHEMA}))
    return 0 if result['schema'] == FINAL_SCHEMA else 2


if __name__ == '__main__':
    sys.exit(main())
