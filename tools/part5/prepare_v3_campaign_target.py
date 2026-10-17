#!/usr/bin/env python3
"""Build private Rj training inputs from pinned R0 and signed R0..Rk evidence.

Requires fresh owner0700 output and owner0600 evidence. No proof, validator,
submission, or live-state authentication is performed. Generation is in 1..10.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import types

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from tools.part5.prepare_v3_matched_training_source import digest, private_dir
from tools.part5.prepare_v3_campaign_context import derive, encoded
from tools.part5 import prepare_v3_request_fixture as bridge
from tools.part5.credential_profile import admit_certificate, public_bindings
from harness.tests.queue_v3_local_campaign_transition import checked_history, check_finalized_chain

SUPPORT = REPO / 'crates/dynark-native-client/tests/support'
PREPARER_SHA = 'de37e94a4319c34439fe656aba702a05a1469fc08940113b4012289a8f8bfe19'
SOURCE_BOUNDS = {'credential.der': 952, 'holder.pem': 4096, 'issuer-modulus.bin': 256,
                 'config.bin': 381, 'membership.json': 16384, 'parameters.json': 8192}
ARTIFACT_BOUNDS = {'request.bin': 1918, 'summary.bin': 459, 'input.json': 65536,
                   'public.json': 1024, 'input-coordinates.bin': 4096,
                   'internal-coordinate.bin': 4}
PUBLIC_NAMES = ('root', 'issuerHash', 'notBefore', 'notAfter', 'actionHash', 'policyHash')


def load_preparer():
    raw = (SUPPORT / 'prepare_v3_request_bound_training.py').read_bytes()
    if digest(raw) != PREPARER_SHA:
        raise ValueError('frozen training helper changed')
    module = types.ModuleType('campaign_base_preparer')
    module.__file__ = str(SUPPORT / 'prepare_v3_request_bound_training.py')
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    module._read(REPO / 'tools/part5/prepare_v3_request_fixture.py', 131072,
                 private=False, expected=module.BRIDGE_SHA)
    return module


def decode_worker(worker, response, expected, fr):
    if type(response) is not bytes or len(response) != 24495 or response[:4] != b'V3I1':
        raise ValueError('complete worker response required')
    fields = [int.from_bytes(response[i:i + 32], 'little') for i in range(463, 24495, 32)]
    if len(fields) != 751 or fields[:6] != expected or any(value >= fr for value in fields):
        raise ValueError('six public and 751 canonical input fields required')
    inputs, cursor = {}, 0
    for name, count in worker.INPUT_FIELDS:
        values = [str(value) for value in fields[cursor:cursor + count]]
        inputs[name] = values[0] if count == 1 else values
        cursor += count
    if cursor != 751 or [inputs[name] for name in PUBLIC_NAMES] != [str(v) for v in expected]:
        raise ValueError('frozen input layout required')
    return inputs


def one_sibling_delta(base, target):
    if (type(base) is not dict or type(target) is not dict or set(base) != set(target)
            or base.get('root') == target.get('root')
            or any(base[key] != target[key] for key in base if key not in ('root', 'siblings'))
            or type(base.get('siblings')) is not list or type(target.get('siblings')) is not list
            or len(base['siblings']) != 10 or len(target['siblings']) != 10
            or [i for i, (a, b) in enumerate(zip(base['siblings'], target['siblings'])) if a != b] != [4]):
        raise ValueError('same action with only root and sibling level 4 changed required')


def prepare(source, base, stage_root, transition_root, cohort_root, context_path,
            generation, output, source_receipt_sha256, base_receipt_sha256,
            transition_report_sha256):
    if type(generation) is not int or not 1 <= generation <= 10:
        raise ValueError('generation must be in 1..10')
    helper = load_preparer()
    directories = [private_dir(path) for path in (source, base, stage_root, transition_root, cohort_root)]
    source, base, stage_root, transition_root, cohort_root = directories
    output = private_dir(output, empty=True)
    context_path = Path(context_path)
    private_dir(context_path.parent)
    if output in directories or output == context_path.parent:
        raise ValueError('separate fresh output required')
    identities = {path: helper._identity(helper._directory(path)) for path in set(directories + [output, context_path.parent])}
    snapshots = {}

    def read(path, cap, expected=None):
        raw = helper._read(path, cap, expected=expected)
        snapshots[path] = (raw, cap)
        return raw

    def document(path, cap, expected=None):
        return helper._json(read(path, cap, expected))

    for pin in (source_receipt_sha256, base_receipt_sha256, transition_report_sha256):
        helper._hex(pin, 32)
    src = document(source / 'source-receipt.json', 8192, source_receipt_sha256)
    receipt = document(base / 'training-receipt.json', 8192, base_receipt_sha256)
    report = document(transition_root / 'transition-report.json', 65536, transition_report_sha256)
    context_raw = read(context_path, 8192, src['context_sha256'])
    context = helper._json(context_raw)
    cohort_receipt = read(cohort_root / 'cohort-receipt.json', 65536, src['cohort_receipt_sha256'])
    member_raw = read(cohort_root / 'membership.json', 65536, src['cohort_membership_sha256'])
    member = helper._json(member_raw)
    # Capture every admitted certificate, not only the holder's, for the final recheck.
    for i in range(11):
        read(cohort_root / f'credential-{i}.der', 952)
    read(cohort_root / 'issuer-modulus.bin', 256)
    if encoded(derive(cohort_root, digest(cohort_receipt), digest(member_raw))) != context_raw:
        raise ValueError('independently derived frozen eleven-certificate context required')
    raw = {name: read(source / name, cap, src['source_sha256'][name]) for name, cap in SOURCE_BOUNDS.items()}
    params, membership = helper._json(raw['parameters.json']), helper._json(raw['membership.json'])
    staged_raw = read(stage_root / 'stage-report.json', 65536, src['stage_report_sha256'])
    staged = helper._json(staged_raw)
    plan_raw = read(stage_root / 'plan.json', 8192, src['stage_plan_sha256'])
    plan = helper._json(plan_raw)
    stage_history_raw = read(stage_root / 'signed-history.json', 1024 * 1024, src['signed_history_sha256'])
    allocation_raw = read(stage_root / 'initial-allocations.json', 8192, src['initial_allocations_sha256'])
    history_raw = read(transition_root / 'signed-history.json', 1024 * 1024, report['signed_history_sha256'])
    history = helper._json(history_raw)
    count = report.get('target_count')
    if (src.get('schema') != 'part5-v3-campaign-training-source-v1'
            or src.get('training_only') is not True or src.get('application_effect') is not False
            or src.get('proof_created') is not False or src.get('live_state_authenticated') is not False
            or src.get('root_sequence_sha256') != context['initial_allocations']['root_sequence_sha256']
            or staged.get('schema') != 'part5-v3-campaign-stage-v1'
            or any(staged.get(k) is not True for k in ('passed', 'training_only', 'registry_history_authenticated',
                       'allocation_history_authenticated', 'upstream_source_authentication', 'upstream_publisher_authentication'))
            or staged.get('application_effect') is not False or staged.get('proof_created') is not False
            or staged.get('plan_sha256') != digest(plan_raw)
            or staged.get('signed_history_sha256') != digest(stage_history_raw)
            or staged.get('initial_allocations_sha256') != digest(allocation_raw)
            or helper._json(allocation_raw) != context['initial_allocations']
            or report.get('schema') != 'part5-v3-campaign-transition-v1'
            or type(count) is not int or not generation <= count <= 10
            or any(report.get(k) is not True for k in ('passed', 'registry_history_authenticated',
                                                      'allocation_history_authenticated', 'request_unconsumed'))
            or report.get('application_effect') is not False
            or report.get('stage_report_sha256') != digest(staged_raw)
            or report.get('stage_plan_sha256') != digest(plan_raw)
            or report.get('context_sha256') != digest(context_raw)
            or report.get('base_root') != context['root_sequence'][0]
            or report.get('current_root') != context['root_sequence'][count]
            or report.get('root_sequence_sha256') != src['root_sequence_sha256']
            or any(report.get(k) != staged.get(k) for k in ('program', 'genesis', 'request', 'queue', 'config', 'issuer', 'head'))
            or len(report.get('checkpoints', [])) != count
            or len(report.get('transactions', [])) != 3 * count
            or any(row.get('err') is not None for row in report['transactions'])):
        raise ValueError('pinned signed campaign stage and transition required')
    commitments = checked_history(history, context, plan, report, staged)
    stage_history = helper._json(stage_history_raw)
    checked_history(stage_history, context, plan, {'target_count': 0}, staged)
    if stage_history['checkpoints'][0] != history['checkpoints'][0]:
        raise ValueError('transition must preserve signed R0 history')
    before, after = [], []
    for directory, row, accounts in ((stage_root, staged, before), (transition_root, report, after)):
        hashes = row.get('account_sha256')
        if type(hashes) is not list or len(hashes) != 5:
            raise ValueError('five pinned campaign accounts required')
        for name, pin in zip(('config', 'issuer', 'head', 'request', 'queue'), hashes):
            accounts.append(read(directory / (name + '.bin'), 4096, pin))
    expected_config = bytearray(before[0])
    expected_config[332:364] = bytes.fromhex(context['root_sequence'][count])
    expected_config[364:372] = count.to_bytes(8, 'big')
    if (len(before[0]) != 381 or before[0][:8] != b'DYNCONF3'
            or before[0][332:364].hex() != context['root_sequence'][0]
            or before[0] != raw['config.bin'] or after[0] != expected_config
            or before[3:] != after[3:]):
        raise ValueError('only campaign config root/version may change; request and queue preserved')
    check_finalized_chain(before, after, plan, context, history, commitments)
    parsed = admit_certificate(raw['credential.der'], int.from_bytes(raw['issuer-modulus.bin'], 'big'))
    issuer, policy = public_bindings(parsed, int.from_bytes(raw['issuer-modulus.bin'], 'big'))
    expected_member = dict(slot=0, issuer_hash=issuer, policy_hash=policy,
                           active_root=member['roots'][0], active_siblings=member['holder_siblings'][0])
    expected_params = {k: bytes(plan[k]).hex() for k in ('genesis', 'creator', 'nonce', 'recipient')}
    last = next(row for row in reversed(staged['transactions']) if row['scenario'] == 'v3-bind-head')
    expected_params.update(program_id=bytes(plan['program']).hex(), payload=bytes(plan['payload']).hex(),
                           request_type=1, deadline=plan['deadline'], now=last['blockTime'],
                           exporter_sha256=src['exporter_sha256'])
    if (membership != expected_member or params != expected_params
            or type(params['now']) is not int or not 0 < params['now'] < params['deadline']
            or raw['credential.der'] != snapshots[cohort_root / 'credential-0.der'][0]
            or raw['issuer-modulus.bin'] != snapshots[cohort_root / 'issuer-modulus.bin'][0]
            or context['issuer_hash'] != f'{issuer:064x}' or context['policy_id'] != f'{policy:064x}'
            or bytes(plan['root']).hex() != context['root_sequence'][0]
            or bytes(plan['issuer_hash']) != issuer.to_bytes(32, 'big')
            or bytes(plan['policy_id']) != policy.to_bytes(32, 'big')
            or raw['config.bin'][104:136] != bytes(plan['genesis'])):
        raise ValueError('R0 holder, membership and action parameters must remain exact')
    if (receipt.get('schema') != 'v3-request-bound-training-input-v1'
            or receipt.get('training_only') is not True or receipt.get('proof_created') is not False
            or receipt.get('bridge_sha256') != helper.BRIDGE_SHA or receipt.get('worker_sha256') != helper.WORKER_SHA
            or receipt.get('exporter_sha256') != src['exporter_sha256']
            or any(receipt.get(key + '_sha256') != digest(raw[name]) for key, name in
                   (('membership', 'membership.json'), ('parameters', 'parameters.json'), ('config', 'config.bin')))):
        raise ValueError('pinned complete R0 training fixture required')
    artifacts = {name: read(base / name, cap, receipt['artifact_sha256'].get(name))
                 for name, cap in ARTIFACT_BOUNDS.items()}
    q0 = artifacts['request.bin']
    if len(q0) != 1918 or q0[:4] != b'V3Q1':
        raise ValueError('complete R0 V3Q1 required')
    action = q0[1212:1244]
    modulus = int.from_bytes(raw['issuer-modulus.bin'], 'big')
    if bridge.build_v3q1(raw['credential.der'], modulus, source / 'holder.pem', action, membership) != q0:
        raise ValueError('R0 credential, holder signature and membership differ')
    expected = [member['roots'][0], issuer, parsed['not_before'], parsed['not_after'], int.from_bytes(action, 'big'), policy]
    worker = helper.load_worker()
    response0 = worker.build(q0)
    input0 = decode_worker(worker, response0, expected, helper.FR)
    if (helper._json(artifacts['input.json']) != input0
            or helper._json(artifacts['public.json']) != [str(x) for x in expected]
            or response0[4:463] != artifacts['summary.bin']):
        raise ValueError('R0 complete worker input or public mismatch')
    relation = helper._module(SUPPORT / 'prepare_v3_relation.py', helper.RELATION_HELPER_SHA)
    coordinates, internal = relation.coordinates(types.SimpleNamespace(FIELDS=worker.INPUT_FIELDS))
    if coordinates != artifacts['input-coordinates.bin'] or internal != artifacts['internal-coordinate.bin']:
        raise ValueError('frozen coordinate artifacts required')
    target_member = dict(expected_member, active_root=member['roots'][generation],
                         active_siblings=member['holder_siblings'][generation])
    q1 = bridge.build_v3q1(raw['credential.der'], modulus, source / 'holder.pem', action, target_member)
    # DER, issuer, action, deterministic holder signature, slot and issuer/policy bytes stay exact.
    if q1[:1502] != q0[:1502] or q1[1854:] != q0[1854:]:
        raise ValueError('target changed holder/action/signature/slot/issuer/policy')
    expected[0] = member['roots'][generation]
    response = worker.build(q1)
    inputs = decode_worker(worker, response, expected, helper.FR)
    one_sibling_delta(input0, inputs)
    if response[4:463] != response0[4:463]:
        raise ValueError('target changed credential summary')
    outputs = {'request.bin': q1, 'summary.bin': response[4:463], 'input.json': encoded(inputs),
               'public.json': encoded([str(x) for x in expected]),
               'input-coordinates.bin': coordinates, 'internal-coordinate.bin': internal}
    result = dict(schema='v3-request-bound-campaign-training-input-v1', training_only=True,
        registry_history_authenticated=True, live_state_authenticated=False, application_effect=False,
        proof_created=False, complete_relation_checked=False, generation=generation, signed_target_count=count,
        source_receipt_sha256=source_receipt_sha256, base_receipt_sha256=base_receipt_sha256,
        transition_report_sha256=transition_report_sha256, signed_history_sha256=digest(history_raw),
        stage_report_sha256=digest(staged_raw), context_sha256=digest(context_raw),
        root_sequence_sha256=src['root_sequence_sha256'], bridge_sha256=helper.BRIDGE_SHA,
        worker_sha256=helper.WORKER_SHA, training_helper_sha256=PREPARER_SHA,
        relation_helper_sha256=helper.RELATION_HELPER_SHA, public_fields=6, input_scalars=751,
        action_hash=str(expected[4]), source_sha256={str(path): digest(data) for path, (data, _) in snapshots.items()},
        artifact_sha256={name: digest(data) for name, data in outputs.items()})
    outputs['training-receipt.json'] = encoded(result)
    for path, (data, cap) in snapshots.items():
        if helper._read(path, cap) != data:
            raise ValueError('campaign source changed')
    for path, identity in identities.items():
        if helper._identity(helper._directory(path)) != identity:
            raise ValueError('campaign directory changed')
    # Recheck the exact helper/worker sources before publishing any private output.
    load_preparer().load_worker()
    helper._module(SUPPORT / 'prepare_v3_relation.py', helper.RELATION_HELPER_SHA)
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    created = []
    try:
        if helper._identity(os.fstat(fd)) != identities[output] or os.listdir(fd):
            raise ValueError('output changed')
        for name, data in outputs.items():
            handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            created.append(name)
            with os.fdopen(handle, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        os.fsync(fd)
        current = helper._directory(output)
        original = identities[output]
        if (current.st_dev, current.st_ino) != original[:2]:
            raise ValueError('output directory replaced during publication')
    except Exception:
        for name in created:
            os.unlink(name, dir_fd=fd)
        raise
    finally:
        os.close(fd)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'base', 'stage_root', 'transition_root', 'cohort_root', 'context_path', 'output'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    parser.add_argument('--generation', type=int, required=True)
    for name in ('source_receipt_sha256', 'base_receipt_sha256', 'transition_report_sha256'):
        parser.add_argument('--' + name.replace('_', '-'), required=True)
    args = parser.parse_args()
    try:
        result = prepare(**vars(args))
    except Exception:
        raise SystemExit('campaign target preparation rejected') from None
    print(json.dumps({key: result[key] for key in
          ('schema', 'generation', 'transition_report_sha256', 'public_fields', 'input_scalars')}))


if __name__ == '__main__':
    main()
