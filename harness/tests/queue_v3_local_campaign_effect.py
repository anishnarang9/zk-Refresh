#!/usr/bin/env python3
"""Supervise a finalized campaign proof check on a stopped Rk ledger clone."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
from harness.tests import queue_v3_clone_ledger as ledgers
from harness.tests import queue_v3_local_campaign_transition as transition
from harness.tests import queue_v3_local_execute as execute
from harness.tests import queue_v3_local_stage as stage
from tools.part5.prepare_v3_campaign_context import derive, encoded
from tools.part5.registry_v3_vectors import rebuild

base = stage.base
LIMITS = {'runtime_seconds': 180, 'rss_bytes': 4294967296,
          'storage_growth_bytes': 268435456}
COUNTS = (0, 1, 2, 5, 10)
MODES = ('full', 'anchor', 'coalesced-full', 'own-revocation')
RUNNER_CLEANUP_RESERVE_SECONDS = 60


def pinned(path, digest, cap=65536):
    return base.decode_json(base.checked(path, digest, cap))


def reviewed_monitor(monitor, owner, limits):
    observed = monitor.get('limits', {})
    if (not owner or monitor.get('owner') != owner
            or monitor.get('exit_code') != 1
            or monitor.get('stop_reason') is not None
            or monitor.get('runner_error_type') is not None
            or monitor.get('cleanup_remaining_owned_processes') != 0
            or monitor.get('cleanup_status_unknown') is not False
            or observed.get('runtime_seconds') != limits['runtime_seconds']
            or observed.get('owned_tree_rss_bytes') != limits['rss_bytes']
            or observed.get('storage_growth_bytes') != limits['storage_growth_bytes']
            or not isinstance(observed.get('poll_seconds'), (int, float))
            or not 0 < observed['poll_seconds'] <= 1):
        raise ValueError('reviewed bounded campaign cleanup evidence required')


def account_artifacts(root, report):
    hashes = report.get('account_sha256')
    if not isinstance(hashes, list) or len(hashes) != 5:
        raise ValueError('five pinned campaign accounts required')
    accounts = []
    for name, digest in zip(execute.ACCOUNT_NAMES, hashes):
        raw, observed = stage.snapshot_generated(Path(root) / (name + '.bin'), 4096)
        if not raw or observed != digest:
            raise ValueError('campaign account artifact changed')
        accounts.append(raw)
    return accounts


def check_proof(config, packet, proof, staged, changed, context, original, wires, history_sha):
    count = config['target_count']
    mode = config['mode']
    proof_mode = config.get('proof_mode', mode)
    if (proof_mode not in ('full', 'anchor', 'coalesced-full')
            or (mode == 'own-revocation' and proof_mode == 'coalesced-full')
            or (mode != 'own-revocation' and proof_mode != mode)):
        raise ValueError('pinned campaign proof mode required')
    expected_packet_schema = ('credential-v3-cumulative-coalesced-request-v1'
                              if proof_mode == 'coalesced-full'
                              else 'credential-v3-cumulative-request-v1')
    stage_pins = packet.get('application_stage', {})
    expected = {
        'program_id': original['program'], 'genesis_hash': config['expected_genesis'],
        'loaded_elf_sha256': original['elf_sha256'],
        'base_stage_report_sha256': config['stage_report_sha256'],
        'base_config_sha256': staged['account_sha256'][0],
        'finalized_request_sha256': staged['account_sha256'][3],
        'request_address': staged['request'],
        'base_finalized_slot': staged['finalized_slot'],
        'near_state_report_sha256': (config['transition_report_sha256'] if count
                                     else config['stage_report_sha256']),
        'near_config_sha256': changed['account_sha256'][0],
        'near_finalized_slot': changed['finalized_slot'],
        'base_root': str(int(context['root_sequence'][0], 16)),
        'near_root': str(int(context['root_sequence'][count], 16)),
        'action_hash': str(int.from_bytes(wires['current'][128:160], 'big')),
    }
    expected_counts = ({'proofs': 1, 'positive_checks': 1,
                        'altered_public_checks': 6, 'cross_root_checks': 0,
                        'ordinary_checks': 7}
                       if proof_mode == 'coalesced-full'
                       else {'proofs': count + 1, 'positive_checks': count + 1,
                             'altered_public_checks': 6 * (count + 1),
                             'cross_root_checks': 2 * count,
                             'ordinary_checks': 9 * count + 7})
    if (packet.get('schema') != expected_packet_schema
            or packet.get('update_count') != count
            or packet.get('synthetic_only') is not False
            or packet.get('application_verified') is not False
            or stage_pins != expected
            or packet.get('history_receipt_sha256') != history_sha
            or packet.get('root_schedule_sha256')
               != context['initial_allocations']['root_sequence_sha256']
            or proof.get('schema') != 'credential-v3-cumulative-proof-v1'
            or proof.get('passed') is not True
            or proof.get('mode') != f'campaign-{proof_mode}-k{count}'
            or proof.get('update_count') != count
            or proof.get('packet_sha256') != config['proof_packet_sha256']
            or proof.get('counts') != expected_counts
            or proof.get('application_verified') is not False
            or proof.get('admitted') is not False
            or proof.get('setup_executed') is not False
            or proof.get('private_cache_persisted') is not False
            or proof.get('application_stage_pins') != stage_pins
            or proof.get('history_receipt_sha256') != history_sha
            or proof.get('root_schedule_sha256') != packet['root_schedule_sha256']
            or proof.get('freeze_receipt_sha256') != packet['freeze_receipt_sha256']):
        raise ValueError('exact cumulative proof and finalized application pins required')
    if (len(wires['current']) != 448
            or wires['current'][:32] != bytes.fromhex(context['root_sequence'][count])
            or wires['current'][128:160]
               != int(stage_pins['action_hash']).to_bytes(32, 'big')):
        raise ValueError('base/current proof wires differ from campaign root/action')
    if proof_mode == 'coalesced-full':
        if wires['base'] is not None:
            raise ValueError('coalesced control must carry only final proof wire')
    elif (wires['base'] is None or len(wires['base']) != 448
          or wires['base'][:32] != bytes.fromhex(context['root_sequence'][0])
          or wires['base'][32:192] != wires['current'][32:192]
          or (count > 0 and wires['base'][:32] == wires['current'][:32])):
        raise ValueError('cumulative proof wire pair changed root or request')


def check_transactions(transactions, mode, count):
    expected = [('v3-campaign-refresh-active-source', None),
                ('v3-campaign-bind-current-head', None)]
    if count and mode != 'coalesced-full':
        expected.append(('v3-campaign-stale-R0', 713))
    expected.extend([('v3-campaign-wrong-action', 712),
                     ('v3-campaign-invalid-proof', 714),
                     (f'v3-campaign-valid-{mode}', None),
                     (f'v3-campaign-replay-{mode}', 707)])
    if (not isinstance(transactions, list) or len(transactions) != len(expected)
            or any(row.get('scenario') != name or row.get('customError') != code
                   or (row.get('err') is None) != (code is None)
                   for row, (name, code) in zip(transactions, expected))):
        raise ValueError('exact campaign effect transaction outcomes required')


def own_revocation_root(context, count):
    allocations = context.get('initial_allocations', {})
    encoded_digests = allocations.get('tbs_digests')
    if (type(count) is not int or count not in COUNTS
            or not isinstance(encoded_digests, list) or len(encoded_digests) != 11):
        raise ValueError('eleven pinned campaign allocations required for own revocation')
    try:
        digests = [bytes.fromhex(value) for value in encoded_digests]
    except (TypeError, ValueError) as error:
        raise ValueError('canonical campaign TBS digests required') from error
    if any(len(value) != 32 or value == bytes(32) for value in digests):
        raise ValueError('canonical campaign TBS digests required')
    unrelated = [(15 + index, digest, index > count)
                 for index, digest in enumerate(digests[1:], 1)]
    current = f'{rebuild([(0, digests[0], True)] + unrelated)[-1][0]:064x}'
    if current != context['root_sequence'][count]:
        raise ValueError('campaign active-root schedule differs from allocations')
    return f'{rebuild([(0, digests[0], False)] + unrelated)[-1][0]:064x}'


def check_own_revocation_transactions(transactions):
    expected = [('v3-campaign-publish-own-revocation', None),
                ('v3-campaign-observe-own-revocation', None),
                ('v3-campaign-bind-own-revocation-head', None),
                ('v3-campaign-own-revoked-old-root', 713),
                ('v3-campaign-own-revoked-pre-revoke-current-root', 713)]
    if (not isinstance(transactions, list) or len(transactions) != len(expected)
            or any(row.get('scenario') != name or row.get('customError') != code
                   or (row.get('err') is None) != (code is None)
                   for row, (name, code) in zip(transactions, expected))):
        raise ValueError('exact own-revocation rejection transaction outcomes required')


def check_own_revocation_report(report, config, original, staged, changed,
                                context, history_sha):
    count = config['target_count']
    revoked_root = own_revocation_root(context, count)
    if (report.get('schema') != 'part5-v3-campaign-own-revocation-v1'
            or report.get('passed') is not True
            or report.get('mode') != 'own-revocation'
            or report.get('target_count') != count
            or report.get('training_only') is not True
            or report.get('devnet') is not False
            or report.get('application_effect') is not False
            or type(report.get('effect_count')) is not int
            or report.get('effect_count') != 0
            or report.get('request_consumed') is not False
            or report.get('registry_history_authenticated') is not True
            or report.get('allocation_history_authenticated') is not True
            or report.get('upstream_source_authentication') is not True
            or report.get('upstream_publisher_authentication') is not True
            or report.get('own_revocation_applied') is not True
            or report.get('active_leaf_absent') is not True
            or report.get('old_root_rejected') is not True
            or report.get('pre_revocation_current_root_rejected') is not True
            or report.get('stage_report_sha256') != config['stage_report_sha256']
            or report.get('stage_plan_sha256') != config['stage_plan_sha256']
            or report.get('transition_report_sha256') != config['transition_report_sha256']
            or report.get('context_sha256') != config['context_sha256']
            or report.get('signed_history_sha256') != history_sha
            or report.get('base_wire_sha256') != config['base_wire_sha256']
            or report.get('current_wire_sha256') != config['current_wire_sha256']
            or report.get('base_root') != context['root_sequence'][0]
            or report.get('pre_revocation_root') != context['root_sequence'][count]
            or report.get('own_revoked_root') != revoked_root
            or report.get('program') != original['program']
            or report.get('genesis') != config['expected_genesis']
            or report.get('source_sequence') != count + 2
            or report.get('publication_sequence') != count + 2
            or type(report.get('previous_finalized_slot')) is not int
            or report['previous_finalized_slot'] < changed['finalized_slot']
            or type(report.get('bound_finalized_slot')) is not int
            or report['bound_finalized_slot'] < report['previous_finalized_slot']
            or type(report.get('finalized_slot')) is not int
            or report['finalized_slot'] < report['bound_finalized_slot']
            or not isinstance(report.get('account_sha256'), list)
            or len(report['account_sha256']) != 5):
        raise ValueError('exact finalized own-revocation report required')
    for digest in report['account_sha256']:
        base.prep.canonical_sha(digest)
    check_own_revocation_transactions(report.get('transactions'))
    execute.report_loaded(report, original)
    return revoked_root


def signed_successor(output, stage_root, report, plan, history, context, count,
                     own_revoked_root=None):
    if (own_revoked_root is not None
            and report.get('own_revoked_root') != own_revoked_root):
        raise ValueError('signed own-revocation root differs from report')
    source_raw, source_sha = stage.snapshot_generated(output / 'effect-signed-source.json', 65536)
    publisher_raw, publisher_sha = stage.snapshot_generated(output / 'effect-signed-publisher.json', 65536)
    enrolled_raw, enrolled_sha = stage.snapshot_generated(output / 'effect-enrolled-source.json', 65536)
    if (report.get('effect_signed_source_sha256') != source_sha
            or report.get('effect_signed_publisher_sha256') != publisher_sha
            or report.get('effect_enrolled_source_sha256') != enrolled_sha):
        raise ValueError('campaign effect signed artifacts differ from report')
    signed = base.decode_json(source_raw)
    publisher = base.decode_json(publisher_raw)
    enrolled = base.decode_json(enrolled_raw)
    staged_enrolled_raw, _ = stage.snapshot_generated(
        Path(stage_root) / 'enrolled-source.json', 65536)
    if enrolled != base.decode_json(staged_enrolled_raw):
        raise ValueError('effect enrollment differs from signed R0 stage')
    previous = history['checkpoints'][-1]
    prior_source = previous['source']
    prior_publisher = previous['publisher']
    source_key = bytes(plan['source'])
    publisher_key = bytes(plan['publisher'])
    observation = signed['observation']
    binding = publisher
    source_wire = b'DYNARK-V3-SOURCE-WIRE-v1\0' + json.dumps(
        signed, separators=(',', ':'), ensure_ascii=False).encode()
    source_digest = hashlib.sha256(source_wire).digest()
    publisher_wire = b'DYNARK-V3-PUBLISHER-WIRE-v1\0' + json.dumps(
        binding, separators=(',', ':'), ensure_ascii=False).encode()
    publisher_digest = hashlib.sha256(publisher_wire).digest()
    prior_source_wire = b'DYNARK-V3-SOURCE-WIRE-v1\0' + json.dumps(
        prior_source, separators=(',', ':'), ensure_ascii=False).encode()
    prior_publisher_wire = b'DYNARK-V3-PUBLISHER-WIRE-v1\0' + json.dumps(
        prior_publisher, separators=(',', ':'), ensure_ascii=False).encode()
    expected_changes = ([] if own_revoked_root is None else [{
        'Revoke': {'tbs_digest': list(bytes.fromhex(
            context['initial_allocations']['tbs_digests'][0]))}}])
    expected_root = (context['root_sequence'][count]
                     if own_revoked_root is None else own_revoked_root)
    expected_root_version = count + (own_revoked_root is not None)
    if (enrolled['scope'] != observation['scope']
            or enrolled['issuer'] != observation['issuer']
            or bytes(enrolled['issuer']['source_key']) != source_key
            or observation['issuer_status_active'] is not True
            or observation['changes'] != expected_changes
            or observation['sequence'] != count + 2
            or bytes(observation['previous_digest']) != hashlib.sha256(prior_source_wire).digest()
            or type(observation['observed_at']) is not int
            or type(observation['valid_until']) is not int
            or observation['observed_at'] <= prior_source['observation']['observed_at']
            or not 0 <= observation['valid_until'] - observation['observed_at'] <= 180
            or binding['scope'] != observation['scope']
            or binding['issuer'] != observation['issuer']
            or bytes(binding['publisher_key']) != publisher_key
            or binding['publication_sequence'] != count + 2
            or bytes(binding['previous_publication_digest'])
               != hashlib.sha256(prior_publisher_wire).digest()
            or binding['root_version'] != expected_root_version
            or bytes(binding['root']).hex() != expected_root
            or binding['source_head']['sequence'] != count + 2
            or bytes(binding['source_head']['digest']) != source_digest
            or report.get('source_head_digest') != source_digest.hex()
            or report.get('publisher_envelope_digest') != publisher_digest.hex()):
        raise ValueError('exact signed current-root successor required')
    source_message = b'DYNARK-V3-SOURCE-STATUS-v1\0' + json.dumps(
        observation, separators=(',', ':'), ensure_ascii=False).encode()
    Ed25519PublicKey.from_public_bytes(source_key).verify(
        bytes(signed['signature']), source_message)
    body = {name: binding[name] for name in (
        'scope', 'issuer', 'source_head', 'root', 'root_version',
        'publisher_key', 'publication_sequence', 'previous_publication_digest')}
    publisher_message = b'DYNARK-V3-PUBLISHER-BINDING-v1\0' + json.dumps(
        body, separators=(',', ':'), ensure_ascii=False).encode()
    Ed25519PublicKey.from_public_bytes(publisher_key).verify(
        bytes(binding['signature']), publisher_message)
    return signed, binding, source_digest, publisher_digest


def check_successor_accounts(before, after, staged, context, count, signed, binding,
                             source_digest, publisher_digest,
                             own_revoked_root=None):
    if own_revoked_root is None:
        execute.check_effect_bytes(before, after, staged)
    else:
        config_key = base.key(staged['config'])
        expected_config = bytearray(before[0]) if len(before) == 5 else bytearray()
        if len(expected_config) == 381:
            expected_config[332:364] = bytes.fromhex(own_revoked_root)
            expected_config[364:372] = (count + 1).to_bytes(8, 'big')
        if (len(before) != 5 or len(after) != 5
                or len(before[0]) != 381 or before[0][:8] != b'DYNCONF3'
                or before[0][332:364] != bytes.fromhex(context['root_sequence'][count])
                or before[0][364:372] != count.to_bytes(8, 'big')
                or len(before[3]) != 2249 or before[3][:8] != b'DYNREQ03'
                or before[3][8:40] != config_key or before[3][183] != 1
                or len(before[4]) != 2090 or before[4][:8] != b'DYNQUE03'
                or before[4][8:40] != config_key or any(before[4][40:])
                or after[3] != before[3] or after[4] != before[4]
                or after[0] != bytes(expected_config)):
            raise ValueError('own revocation must preserve finalized request and empty queue')
    issuer, head = after[1], after[2]
    prior_issuer, prior_head = before[1], before[2]
    observation = signed['observation']
    sequence = (count + 2).to_bytes(8, 'big')
    root = bytes.fromhex(context['root_sequence'][count]
                         if own_revoked_root is None else own_revoked_root)
    root_version = count + (own_revoked_root is not None)
    prior_envelope = prior_head[112:144]
    if (len(issuer) != 374 or len(head) != 280
            or issuer[:8] != b'DYNISS03' or head[:8] != b'DYNHEAD3'
            or issuer[:173] != prior_issuer[:173]
            or issuer[309:] != prior_issuer[309:]
            or issuer[173:181] != sequence
            or issuer[181:213] != source_digest
            or issuer[213:221] != observation['observed_at'].to_bytes(8, 'big', signed=True)
            or issuer[221:229] != observation['valid_until'].to_bytes(8, 'big', signed=True)
            or issuer[229:261] != root
            or issuer[261:269] != root_version.to_bytes(8, 'big')
            or issuer[269:277] != sequence or issuer[277:309] != source_digest
            or head[:104] != prior_head[:104]
            or head[104:112] != sequence
            or head[112:144] != publisher_digest
            or head[144:176] != prior_envelope
            or head[176:208] != root
            or head[208:216] != root_version.to_bytes(8, 'big')
            or head[216:224] != sequence or head[224:256] != source_digest
            or head[256:272] != prior_head[256:272]
            or int.from_bytes(head[272:280], 'big', signed=True) < 0
            or binding['source_head']['sequence'] != count + 2):
        raise ValueError('effect issuer/head differ from signed successor')


def admit(config):
    count = config.get('target_count')
    proof_mode = config.get('proof_mode', config.get('mode'))
    if (config.get('schema') != 1 or config.get('scope') != 'part5-v3-campaign-effect'
            or config.get('mode') not in MODES or count not in COUNTS
            or proof_mode not in ('full', 'anchor', 'coalesced-full')
            or (config.get('mode') == 'own-revocation'
                and proof_mode == 'coalesced-full')
            or (config.get('mode') != 'own-revocation'
                and proof_mode != config.get('mode'))
            or (config.get('mode') == 'own-revocation'
                and (config.get('base_wire') is None
                     or config.get('base_wire_sha256') is None))
            or config.get('outer_limits_required') != LIMITS):
        raise ValueError('explicit bounded campaign effect contract required')
    stage_config = pinned(config['stage_config'], config['stage_config_sha256'])
    stage_status = pinned(config['stage_status'], config['stage_status_sha256'])
    stage_monitor = pinned(config['stage_monitor'], config['stage_monitor_sha256'])
    staged = pinned(Path(config['stage_root']) / 'stage-report.json',
                    config['stage_report_sha256'])
    plan = pinned(Path(config['stage_root']) / 'plan.json', config['stage_plan_sha256'], 8192)
    if (stage_config.get('scope') != 'part5-v3-campaign-stage'
            or stage_config.get('stage_output') != config['stage_root']
            or stage_config.get('context') != config['context']
            or stage_config.get('context_sha256') != config['context_sha256']
            or stage_status.get('scope') != 'part5-v3-campaign-stage'
            or stage_status.get('stage_verified') is not True
            or stage_status.get('config_sha256') != config['stage_config_sha256']
            or stage_status.get('stage_report_sha256') != config['stage_report_sha256']
            or stage_status.get('application_effect') is not False
            or stage_status.get('status') != 'failed'
            or stage_status.get('error_type') is not None
            or stage_status.get('ledger_reuse_requires_review') is not True
            or stage_status.get('validator_cleanup', {}).get('reaped') is not True
            or stage_status.get('validator_cleanup', {}).get('exit_code') != -signal.SIGINT
            or stage_status.get('runner_cleanup', {}).get('reaped') is not True
            or stage_status.get('runner_cleanup', {}).get('exit_code') != 0
            or staged.get('schema') != 'part5-v3-campaign-stage-v1'
            or staged.get('passed') is not True
            or staged.get('registry_history_authenticated') is not True
            or staged.get('allocation_history_authenticated') is not True
            or staged.get('application_effect') is not False
            or staged.get('proof_created') is not False
            or staged.get('plan_sha256') != config['stage_plan_sha256']
            or staged.get('program') is None
            or staged.get('genesis') != config['expected_genesis']):
        raise ValueError('reviewed signed campaign R0 stage required')
    reviewed_monitor(stage_monitor, config['stage_monitor_owner'], stage.LIMITS)
    original = pinned(stage_config['prior_config'], stage_config['prior_config_sha256'])
    build = pinned(original['build_plan'], original['build_plan_sha256'])
    base.prep.check_manifest(REPO, build['source_manifest'])
    if base.prep.external_config_pins(REPO) != build['external_cargo_config_pins']:
        raise ValueError('reviewed Cargo configuration changed')
    base.checked(build['argv'][0], build['builder_sha256'], 128 * 1024 * 1024)
    elf = base.checked(original['elf'], original['elf_sha256'], 4 * 1024 * 1024)
    base.prep.compare_elf_payload(elf, elf, original['elf_sha256'])
    base.checked(original['validator'], original['validator_sha256'], 128 * 1024 * 1024)
    base.checked(config['runner'], config['runner_sha256'], 128 * 1024 * 1024)
    report_loaded(staged, original, stage_status['loaded_program'])
    if staged['program'] != original['program']:
        raise ValueError('campaign stage program identity changed')
    context_raw = base.checked(config['context'], config['context_sha256'], 8192)
    context = base.decode_json(context_raw)
    if (context.get('schema') != 'part5-v3-campaign-context-v1'
            or encoded(derive(Path(config['cohort_root']),
                              context['initial_allocations']['cohort_receipt_sha256'],
                              context['initial_allocations']['membership_sha256'])) != context_raw
            or bytes(plan['root']).hex() != context['root_sequence'][0]):
        raise ValueError('admitted signed campaign certificate context required')
    initial = account_artifacts(config['stage_root'], staged)
    if count:
        transition_config = pinned(config['transition_config'],
                                   config['transition_config_sha256'])
        transition_status = pinned(config['transition_status'],
                                   config['transition_status_sha256'])
        transition_monitor = pinned(config['transition_monitor'],
                                    config['transition_monitor_sha256'])
        changed = pinned(Path(config['transition_root']) / 'transition-report.json',
                         config['transition_report_sha256'])
        if (transition_config.get('scope') != 'part5-v3-campaign-transition'
                or transition_config.get('target_count') != count
                or transition_config.get('stage_config_sha256') != config['stage_config_sha256']
                or transition_config.get('stage_status_sha256') != config['stage_status_sha256']
                or transition_config.get('stage_monitor_sha256') != config['stage_monitor_sha256']
                or transition_config.get('stage_root') != config['stage_root']
                or transition_config.get('transition_output') != config['transition_root']
                or transition_config.get('context_sha256') != config['context_sha256']
                or transition_status.get('scope') != 'part5-v3-campaign-transition'
                or transition_status.get('target_count') != count
                or transition_status.get('transition_verified') is not True
                or transition_status.get('status') != 'failed'
                or transition_status.get('application_effect') is not False
                or transition_status.get('ledger_reuse_requires_review') is not True
                or transition_status.get('config_sha256') != config['transition_config_sha256']
                or transition_status.get('transition_report_sha256')
                   != config['transition_report_sha256']
                or transition_status.get('validator_cleanup', {}).get('reaped') is not True
                or transition_status.get('validator_cleanup', {}).get('exit_code')
                   != -signal.SIGINT
                or transition_status.get('runner_cleanup', {}).get('reaped') is not True
                or transition_status.get('runner_cleanup', {}).get('exit_code') != 0
                or changed.get('schema') != 'part5-v3-campaign-transition-v1'
                or changed.get('passed') is not True
                or changed.get('target_count') != count
                or changed.get('registry_history_authenticated') is not True
                or changed.get('allocation_history_authenticated') is not True
                or changed.get('request_unconsumed') is not True
                or changed.get('application_effect') is not False
                or changed.get('stage_report_sha256') != config['stage_report_sha256']
                or changed.get('stage_plan_sha256') != config['stage_plan_sha256']
                or changed.get('context_sha256') != config['context_sha256']
                or changed.get('current_root') != context['root_sequence'][count]
                or changed.get('base_root') != context['root_sequence'][0]
                or changed.get('program') != original['program']
                or changed.get('genesis') != config['expected_genesis']):
            raise ValueError('reviewed signed R0-to-Rk campaign transition required')
        reviewed_monitor(transition_monitor, config['transition_monitor_owner'],
                         transition.LIMITS)
        report_loaded(changed, original, transition_status['loaded_program'])
        history_root = Path(config['transition_root'])
        current = account_artifacts(history_root, changed)
    else:
        transition_status = stage_status
        changed = staged
        history_root = Path(config['stage_root'])
        current = initial
    history_raw, history_sha = stage.snapshot_generated(
        history_root / 'signed-history.json', 1024 * 1024)
    if history_sha != changed['signed_history_sha256']:
        raise ValueError('campaign signed history changed')
    history = base.decode_json(history_raw)
    commitments = transition.checked_history(history, context, plan,
                                             {'target_count': count, **changed}, staged)
    transition.check_finalized_chain(initial, current, plan, context, history, commitments)
    if (current[3] != initial[3] or current[4] != initial[4]
            or current[0][332:364] != bytes.fromhex(context['root_sequence'][count])
            or current[0][364:372] != count.to_bytes(8, 'big')):
        raise ValueError('current campaign root or unconsumed request differs')
    clone = pinned(config['clone_report'], config['clone_report_sha256'])
    ledger = execute.private_directory(config['ledger'])
    if (clone.get('copy_identical') is not True
            or clone.get('source_stable') is not True
            or clone.get('destination') != str(ledger)
            or Path(config['clone_report']).parent != ledger.parent
            or clone.get('source') != (transition_config['ledger'] if count
                                      else stage_config['ledger'])
            or (count and (clone.get('schema') != 'part5-v3-campaign-final-ledger-clone-v1'
                           or clone.get('target_count') != count
                           or clone.get('current_root') != changed['current_root']
                           or clone.get('transition_config_sha256')
                              != config['transition_config_sha256']
                           or clone.get('transition_report_sha256')
                              != config['transition_report_sha256']
                           or clone.get('transition_status_sha256')
                              != config['transition_status_sha256']
                           or clone.get('transition_monitor_sha256')
                              != config['transition_monitor_sha256']))
            or (not count and (
                clone.get('schema') != 'part5-v3-campaign-r0-ledger-clone-v1'
                or clone.get('stage_report_sha256') != config['stage_report_sha256']
                or clone.get('stage_status_sha256') != config['stage_status_sha256']
                or clone.get('stage_monitor_sha256') != config['stage_monitor_sha256']))):
        raise ValueError('byte-identical stopped Rk clone required')
    rows = ledgers.inventory(ledger)
    if hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode()).hexdigest() != clone['tree_sha256']:
        raise ValueError('campaign clone changed before restart')
    proof_packet = pinned(config['proof_packet'], config['proof_packet_sha256'], 262144)
    proof_report = pinned(config['proof_report'], config['proof_report_sha256'], 65536)
    wires = {'base': None}
    for role in ('base', 'current'):
        if role == 'base' and config['mode'] == 'coalesced-full':
            if (config.get('base_wire') is not None
                    or config.get('base_wire_sha256') is not None):
                raise ValueError('coalesced effect cannot claim R0 proof wire')
            continue
        path = Path(config[role + '_wire'])
        execute.private_directory(path.parent)
        raw, digest = stage.snapshot_generated(path, 448)
        if digest != config[role + '_wire_sha256']:
            raise ValueError('pinned campaign proof wire changed')
        wires[role] = raw
    check_proof(config, proof_packet, proof_report, staged, changed, context,
                original, wires, history_sha)
    output = base.fresh_child(config['effect_output'], REPO / 'artifacts/dynark/part5')
    control = base.fresh_child(config['control_output'], REPO / 'artifacts/dynark/part5')
    stage.validate_stage_paths(output, control, REPO / 'artifacts/dynark/part5')
    return original, transition_status, staged, changed, plan, context, history, elf, current, ledger, output, control


def check_effect_report(report, config, original, staged, changed, context, history_sha):
    if config['mode'] == 'own-revocation':
        return check_own_revocation_report(report, config, original, staged,
                                           changed, context, history_sha)
    count = config['target_count']
    if (report.get('schema') != 'part5-v3-campaign-effect-v1'
            or report.get('passed') is not True
            or report.get('mode') != config['mode']
            or report.get('target_count') != count
            or report.get('training_only') is not True
            or report.get('devnet') is not False
            or report.get('application_effect') is not True
            or report.get('effect_count') != 1
            or report.get('request_consumed') is not True
            or report.get('stale_r0_rejected') is not (count > 0 and config['mode'] != 'coalesced-full')
            or report.get('registry_history_authenticated') is not True
            or report.get('allocation_history_authenticated') is not True
            or report.get('upstream_source_authentication') is not True
            or report.get('upstream_publisher_authentication') is not True
            or report.get('stage_report_sha256') != config['stage_report_sha256']
            or report.get('stage_plan_sha256') != config['stage_plan_sha256']
            or report.get('transition_report_sha256') != config['transition_report_sha256']
            or report.get('context_sha256') != config['context_sha256']
            or report.get('signed_history_sha256') != history_sha
            or report.get('base_wire_sha256') != config['base_wire_sha256']
            or report.get('current_wire_sha256') != config['current_wire_sha256']
            or report.get('base_root') != context['root_sequence'][0]
            or report.get('current_root') != context['root_sequence'][count]
            or report.get('program') != original['program']
            or report.get('genesis') != config['expected_genesis']
            or report.get('source_sequence') != count + 2
            or report.get('publication_sequence') != count + 2
            or type(report.get('previous_finalized_slot')) is not int
            or report['previous_finalized_slot'] < changed['finalized_slot']
            or type(report.get('bound_finalized_slot')) is not int
            or report['bound_finalized_slot'] < report['previous_finalized_slot']
            or type(report.get('finalized_slot')) is not int
            or report['finalized_slot'] < report['bound_finalized_slot']
            or not isinstance(report.get('account_sha256'), list)
            or len(report['account_sha256']) != 5):
        raise ValueError('exact finalized campaign effect report required')
    for digest in report['account_sha256']:
        base.prep.canonical_sha(digest)
    check_transactions(report.get('transactions'), config['mode'], count)
    execute.report_loaded(report, original)


def report_loaded(report, original, loaded):
    """Bind Rust's compact report identity to the supervisor's full identity."""
    execute.report_loaded(report, original)
    reported = report.get('loaded_program', {})
    if (not isinstance(loaded.get('loader'), str) or not loaded['loader']
            or type(loaded.get('elf_bytes')) is not int or loaded['elf_bytes'] <= 0
            or reported.get('loader') != loaded.get('loader')
            or type(reported.get('local_bytes')) is not int
            or type(reported.get('remote_bytes')) is not int
            or reported.get('local_bytes') != loaded.get('elf_bytes')
            or reported.get('remote_bytes') != loaded.get('elf_bytes')):
        raise ValueError('report loaded program size or loader mismatch')


def wait_current_finality(rpc, staged, changed, program, sizes):
    return execute.wait_staged_finality(
        rpc, staged, program, changed['account_sha256'], sizes,
        minimum_slot=changed['finalized_slot'])


def run(config, config_sha256):
    if os.environ.get('P5_V3_CAMPAIGN_EFFECT_SUPERVISOR') != 'reviewed-campaign-clone':
        raise ValueError('explicit external bounded campaign effect scope required')
    original, previous, staged, changed, plan, context, history, elf, before, ledger, output, control = admit(config)
    started = time.monotonic()
    validator = runner = None
    logs = []
    handlers = {}
    old_umask = os.umask(0o077)
    status = {'schema': 1, 'scope': 'part5-v3-campaign-effect',
              'status': 'failed', 'effect_verified': False,
              'application_effect': False, 'effect_outcome': 'not_submitted',
              'target_count': config['target_count'], 'mode': config['mode'],
              'ledger_reuse_requires_review': True,
              'config_sha256': config_sha256, 'training_only': True, 'devnet': False,
              'outer_limits_required': LIMITS,
              'whole_tree_cleanup_authority': 'external bounded_runner'}

    def interrupted(signum, frame):
        raise InterruptedError('campaign effect supervisor interrupted')

    try:
        control.mkdir(mode=0o700)
        output.mkdir(mode=0o700)
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, interrupted)
        base.ports_free()
        argv = stage.resume_argv(original['validator'], str(ledger))
        base.write_new(control / 'invocation.json', {
            'validator_argv': argv, 'runner': config['runner'],
            'runner_sha256': config['runner_sha256'],
            'stage_report_sha256': config['stage_report_sha256'],
            'transition_report_sha256': config['transition_report_sha256'],
            'proof_report_sha256': config['proof_report_sha256'],
            'base_wire_sha256': config['base_wire_sha256'],
            'current_wire_sha256': config['current_wire_sha256'],
            'outer_limits_required': LIMITS})
        for name in ('validator.stdout.log', 'validator.stderr.log',
                     'runner.stdout.log', 'runner.stderr.log'):
            fd = os.open(control / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            logs.append(os.fdopen(fd, 'wb'))
        env = os.environ.copy()
        for name in ('LD_PRELOAD', 'DYLD_INSERT_LIBRARIES'):
            env.pop(name, None)
        validator = subprocess.Popen(argv, cwd=REPO, env=env,
                                     stdin=subprocess.DEVNULL,
                                     stdout=logs[0], stderr=logs[1],
                                     start_new_session=False)
        rpc = base.LocalRpc()
        loaded = execute.wait_loaded_after_start(
            rpc, validator, original['program'], elf, original['elf_sha256'])
        execute.same_loaded(previous['loaded_program'], loaded)
        sizes = [len(raw) for raw in before]
        pre_slot, finalized_before = wait_current_finality(
            rpc, staged, changed, original['program'], sizes)
        if finalized_before != before:
            raise ValueError('restarted finalized accounts differ from Rk artifacts')
        env.update({
            'P5_V3_CAMPAIGN_EFFECT_SCOPE': 'part5-v3-campaign-effect',
            'P5_V3_CAMPAIGN_EFFECT_MODE': config['mode'],
            'P5_V3_CAMPAIGN_COUNT': str(config['target_count']),
            'P5_V3_STAGE_ROOT': config['stage_root'],
            'P5_V3_STAGE_REPORT_SHA256': config['stage_report_sha256'],
            'P5_V3_STAGE_PLAN_SHA256': config['stage_plan_sha256'],
            'P5_V3_CONTEXT': config['context'],
            'P5_V3_CONTEXT_SHA256': config['context_sha256'],
            'P5_V3_CURRENT_WIRE': config['current_wire'],
            'P5_V3_CURRENT_WIRE_SHA256': config['current_wire_sha256'],
            'P5_QUEUE_RPC': base.RPC.rstrip('/'),
            'P5_QUEUE_PROGRAM': original['program'],
            'P5_QUEUE_GENESIS': loaded['genesis'],
            'P5_QUEUE_ELF': original['elf'],
            'P5_QUEUE_ELF_SHA256': original['elf_sha256'],
            'P5_QUEUE_OUTPUT': str(output)})
        if config['base_wire'] is not None:
            env.update({'P5_V3_BASE_WIRE': config['base_wire'],
                        'P5_V3_BASE_WIRE_SHA256': config['base_wire_sha256']})
        if config['target_count']:
            env.update({'P5_V3_TRANSITION_ROOT': config['transition_root'],
                        'P5_V3_TRANSITION_REPORT_SHA256':
                            config['transition_report_sha256']})
        runner_argv = [config['runner'], 'root_pinned_queue_v3_campaign_effect',
                       '--exact', '--ignored', '--test-threads=1']
        status.update({'application_effect': None,
                       'effect_outcome': 'requires_reconciliation'})
        runner = subprocess.Popen(runner_argv, cwd=REPO, env=env,
                                  stdin=subprocess.DEVNULL,
                                  stdout=logs[2], stderr=logs[3],
                                  start_new_session=False)
        deadline = started + LIMITS['runtime_seconds'] - RUNNER_CLEANUP_RESERVE_SECONDS
        while runner.poll() is None:
            if validator.poll() is not None:
                raise RuntimeError('validator exited during campaign effect')
            if time.monotonic() >= deadline:
                raise TimeoutError('campaign effect runner deadline')
            time.sleep(0.1)
        if runner.wait() != 0:
            raise RuntimeError('campaign effect runner rejected; reconcile ledger')
        raw, report_sha = stage.snapshot_generated(output / 'effect-report.json', 65536)
        report = base.decode_json(raw)
        history_root = Path(config['transition_root'] if config['target_count']
                            else config['stage_root'])
        history_sha = stage.snapshot_generated(history_root / 'signed-history.json',
                                               1024 * 1024)[1]
        own_root = check_effect_report(report, config, original, staged, changed,
                                       context, history_sha)
        report_loaded(report, original, loaded)
        signed, binding, source_digest, publisher_digest = signed_successor(
            output, config['stage_root'], report, plan, history, context,
            config['target_count'], own_revoked_root=own_root)
        post_slot, after = execute.finalized_accounts(
            rpc, staged, max(pre_slot, report['finalized_slot']),
            original['program'], report['account_sha256'], sizes)
        check_successor_accounts(before, after, staged, context, config['target_count'],
                                 signed, binding, source_digest, publisher_digest,
                                 own_revoked_root=own_root)
        for name, data in zip(execute.ACCOUNT_NAMES, after):
            artifact, _ = stage.snapshot_generated(output / (name + '.bin'), 4096)
            if artifact != data:
                raise ValueError('effect artifact differs from finalized account')
        latest = base.wait_loaded(rpc, validator, original['program'], elf,
                                  original['elf_sha256'])
        execute.same_loaded(loaded, latest)
        base.prep.check_manifest(REPO, pinned(original['build_plan'],
                                               original['build_plan_sha256'])['source_manifest'])
        own_revocation = config['mode'] == 'own-revocation'
        status.update({'effect_verified': True,
                       'application_effect': not own_revocation,
                       'effect_outcome': ('verified_rejection' if own_revocation
                                          else 'verified'),
                       'effect_count': 0 if own_revocation else 1,
                       'effect_report_sha256': report_sha, 'finalized_slot': post_slot,
                       'loaded_program': latest, 'effect_output': str(output)})
    except Exception as error:
        status['error_type'] = type(error).__name__
        status['error_message'] = str(error)[:256]
    finally:
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        for name, proc in (('runner', runner), ('validator', validator)):
            try:
                status[name + '_cleanup'] = base.cleanup(proc)
            except Exception as error:
                status[name + '_cleanup'] = {'reaped': False, 'graceful': False,
                                             'error_type': type(error).__name__}
        if (status['effect_verified']
                and status['validator_cleanup'].get('graceful') is True
                and status['validator_cleanup'].get('reaped') is True
                and status['validator_cleanup'].get('exit_code') == 0
                and status['runner_cleanup'].get('reaped') is True
                and status['runner_cleanup'].get('exit_code') == 0):
            status['status'] = 'passed'
            status['ledger_reuse_requires_review'] = False
        status['elapsed_seconds'] = time.monotonic() - started
        for stream in logs:
            stream.close()
        try:
            if control.is_dir():
                base.write_new(control / 'status.json', status)
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
            os.umask(old_umask)
    print(json.dumps({'status': status['status'],
                      'effect_verified': status['effect_verified'],
                      'report': str(control / 'status.json')}))
    return 0 if status['status'] == 'passed' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--config-sha256', required=True)
    args = parser.parse_args()
    return run(pinned(args.config, args.config_sha256), args.config_sha256)


if __name__ == '__main__':
    sys.exit(main())
