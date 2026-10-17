import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from harness.tests import queue_v3_local_campaign_effect as effect


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def wire(root, action=3):
    data = bytearray(448)
    data[:32] = bytes.fromhex(root)
    data[128:160] = action.to_bytes(32, 'big')
    return bytes(data)


class CampaignEffectChecks(unittest.TestCase):
    def test_bounded_monitor_requires_clean_owned_tree(self):
        monitor = {'owner': 'campaign-effect', 'exit_code': 1,
                   'stop_reason': None, 'runner_error_type': None,
                   'cleanup_remaining_owned_processes': 0,
                   'cleanup_status_unknown': False,
                   'limits': {'runtime_seconds': 180,
                              'owned_tree_rss_bytes': 4294967296,
                              'storage_growth_bytes': 268435456,
                              'poll_seconds': 0.25}}
        effect.reviewed_monitor(monitor, 'campaign-effect', effect.LIMITS)
        with self.assertRaises(ValueError):
            effect.reviewed_monitor(dict(monitor, cleanup_remaining_owned_processes=1),
                                    'campaign-effect', effect.LIMITS)
        with self.assertRaises(ValueError):
            effect.reviewed_monitor(monitor, 'wrong-owner', effect.LIMITS)

    def test_exact_transaction_codes_and_coalesced_without_stale_proof(self):
        scenarios = [('v3-campaign-refresh-active-source', None),
                     ('v3-campaign-bind-current-head', None),
                     ('v3-campaign-stale-R0', 713),
                     ('v3-campaign-wrong-action', 712),
                     ('v3-campaign-invalid-proof', 714),
                     ('v3-campaign-valid-anchor', None),
                     ('v3-campaign-replay-anchor', 707)]
        rows = [{'scenario': name, 'customError': code,
                 'err': None if code is None else {'Custom': code}}
                for name, code in scenarios]
        effect.check_transactions(rows, 'anchor', 2)
        rows[2]['customError'] = 714
        with self.assertRaises(ValueError):
            effect.check_transactions(rows, 'anchor', 2)
        coalesced = [row for row in rows if row['scenario'] != 'v3-campaign-stale-R0']
        coalesced[-2]['scenario'] = 'v3-campaign-valid-coalesced-full'
        coalesced[-1]['scenario'] = 'v3-campaign-replay-coalesced-full'
        effect.check_transactions(coalesced, 'coalesced-full', 2)

    def proof_fixture(self, mode='anchor', count=2):
        roots = ['01' * 32, '02' * 32, '03' * 32]
        config = {'mode': mode, 'target_count': count,
                  'expected_genesis': 'genesis', 'stage_report_sha256': 'stage',
                  'transition_report_sha256': 'changed' if count else None,
                  'proof_packet_sha256': 'packet'}
        staged = {'account_sha256': ['a', 'b', 'c', 'request', 'queue'],
                  'request': 'request-address', 'finalized_slot': 10}
        changed = {'account_sha256': ['near', 'b', 'c', 'request', 'queue'],
                   'finalized_slot': 20}
        context = {'root_sequence': roots, 'initial_allocations': {
            'root_sequence_sha256': 'schedule'}}
        original = {'program': 'program', 'elf_sha256': 'elf'}
        current = wire(roots[count])
        base = None if mode == 'coalesced-full' else wire(roots[0])
        wires = {'base': base, 'current': current}
        pins = {'program_id': 'program', 'genesis_hash': 'genesis',
                'loaded_elf_sha256': 'elf', 'base_stage_report_sha256': 'stage',
                'base_config_sha256': 'a', 'finalized_request_sha256': 'request',
                'request_address': 'request-address', 'base_finalized_slot': 10,
                'near_state_report_sha256': 'changed' if count else 'stage',
                'near_config_sha256': 'near', 'near_finalized_slot': 20,
                'base_root': str(int(roots[0], 16)),
                'near_root': str(int(roots[count], 16)), 'action_hash': '3'}
        packet = {'schema': ('credential-v3-cumulative-coalesced-request-v1'
                             if mode == 'coalesced-full'
                             else 'credential-v3-cumulative-request-v1'),
                  'update_count': count, 'synthetic_only': False,
                  'application_verified': False, 'application_stage': pins,
                  'history_receipt_sha256': 'history',
                  'root_schedule_sha256': 'schedule',
                  'freeze_receipt_sha256': 'freeze'}
        counts = ({'proofs': 1, 'positive_checks': 1,
                   'altered_public_checks': 6, 'cross_root_checks': 0,
                   'ordinary_checks': 7} if mode == 'coalesced-full'
                  else {'proofs': count + 1, 'positive_checks': count + 1,
                        'altered_public_checks': 6 * (count + 1),
                        'cross_root_checks': 2 * count,
                        'ordinary_checks': 9 * count + 7})
        proof = {'schema': 'credential-v3-cumulative-proof-v1', 'passed': True,
                 'mode': f'campaign-{mode}-k{count}', 'update_count': count,
                 'packet_sha256': 'packet', 'counts': counts,
                 'application_verified': False, 'admitted': False,
                 'setup_executed': False, 'private_cache_persisted': False,
                 'application_stage_pins': pins,
                 'history_receipt_sha256': 'history',
                 'root_schedule_sha256': 'schedule',
                 'freeze_receipt_sha256': 'freeze'}
        return config, packet, proof, staged, changed, context, original, wires

    def test_proof_stage_and_wire_pins(self):
        values = self.proof_fixture()
        effect.check_proof(*values, 'history')
        altered = list(values)
        altered[7] = dict(values[7], current=wire('ff' * 32))
        with self.assertRaises(ValueError):
            effect.check_proof(*altered, 'history')
        altered = list(values)
        altered[2] = dict(values[2], counts={**values[2]['counts'], 'proofs': 2})
        with self.assertRaises(ValueError):
            effect.check_proof(*altered, 'history')
        effect.check_proof(*self.proof_fixture('coalesced-full'), 'history')

    def test_effect_report_requires_one_finalized_effect(self):
        config, _, _, staged, changed, context, original, _ = self.proof_fixture()
        config.update({'stage_plan_sha256': 'plan', 'context_sha256': 'context',
                       'base_wire_sha256': 'base', 'current_wire_sha256': 'current'})
        rows = [{'scenario': name, 'customError': code,
                 'err': None if code is None else {'Custom': code}}
                for name, code in [
                    ('v3-campaign-refresh-active-source', None),
                    ('v3-campaign-bind-current-head', None),
                    ('v3-campaign-stale-R0', 713),
                    ('v3-campaign-wrong-action', 712),
                    ('v3-campaign-invalid-proof', 714),
                    ('v3-campaign-valid-anchor', None),
                    ('v3-campaign-replay-anchor', 707)]]
        report = {'schema': 'part5-v3-campaign-effect-v1', 'passed': True,
                  'mode': 'anchor', 'target_count': 2, 'training_only': True,
                  'devnet': False,
                  'application_effect': True, 'effect_count': 1,
                  'request_consumed': True, 'registry_history_authenticated': True,
                  'stale_r0_rejected': True,
                  'allocation_history_authenticated': True,
                  'upstream_source_authentication': True,
                  'upstream_publisher_authentication': True,
                  'stage_report_sha256': 'stage', 'stage_plan_sha256': 'plan',
                  'transition_report_sha256': 'changed',
                  'context_sha256': 'context', 'signed_history_sha256': 'history',
                  'base_wire_sha256': 'base', 'current_wire_sha256': 'current',
                  'base_root': context['root_sequence'][0],
                  'current_root': context['root_sequence'][2],
                  'program': 'program', 'genesis': 'genesis',
                  'source_sequence': 4, 'publication_sequence': 4,
                  'previous_finalized_slot': 20, 'bound_finalized_slot': 21,
                  'finalized_slot': 22, 'account_sha256': ['00' * 32] * 5,
                  'transactions': rows, 'loaded_program': {
                      'elf_match': True, 'elf_sha256': 'elf'}}
        effect.check_effect_report(report, config, original, staged, changed, context, 'history')
        report['request_consumed'] = False
        with self.assertRaises(ValueError):
            effect.check_effect_report(report, config, original, staged, changed, context, 'history')

    def test_minimal_report_loaded_identity_matches_full_status(self):
        original = {'elf_sha256': 'a' * 64}
        full = {'elf_match': True, 'elf_sha256': 'a' * 64, 'elf_bytes': 4096,
                'loader': 'BPFLoaderUpgradeab1e11111111111111111111111'}
        report = {'loaded_program': {'elf_match': True, 'elf_sha256': 'a' * 64,
                    'loader': full['loader'], 'local_bytes': 4096, 'remote_bytes': 4096}}
        effect.report_loaded(report, original, full)
        for key, value in (('elf_sha256', 'f' * 64), ('loader', 'other-loader'),
                           ('local_bytes', 4095), ('remote_bytes', 4095)):
            with self.subTest(key=key):
                report['loaded_program'][key] = value
                with self.assertRaises(ValueError):
                    effect.report_loaded(report, original, full)
                report['loaded_program'][key] = {
                    'elf_sha256': 'a' * 64, 'loader': full['loader'],
                    'local_bytes': 4096, 'remote_bytes': 4096}[key]

    def test_signed_no_change_successor_and_account_binding(self):
        source_key = Ed25519PrivateKey.generate()
        publisher_key = Ed25519PrivateKey.generate()
        source_public = list(source_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        publisher_public = list(publisher_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        plan = {'source': source_public, 'publisher': publisher_public}
        issuer = {'source_key': source_public}
        scope = {'id': 1}
        prior_source = {'observation': {'sequence': 2, 'observed_at': 99},
                        'signature': []}
        prior_publisher = {'publication_sequence': 2}
        source_prior_digest = hashlib.sha256(
            b'DYNARK-V3-SOURCE-WIRE-v1\0' + json.dumps(
                prior_source, separators=(',', ':')).encode()).digest()
        publisher_prior_digest = hashlib.sha256(
            b'DYNARK-V3-PUBLISHER-WIRE-v1\0' + json.dumps(
                prior_publisher, separators=(',', ':')).encode()).digest()
        obs = {'scope': scope, 'issuer': issuer, 'issuer_status_active': True,
               'sequence': 3, 'previous_digest': list(source_prior_digest),
               'observed_at': 100, 'valid_until': 280, 'changes': []}
        source_message = b'DYNARK-V3-SOURCE-STATUS-v1\0' + json.dumps(
            obs, separators=(',', ':')).encode()
        signed = {'observation': obs, 'signature': list(source_key.sign(source_message))}
        source_digest = hashlib.sha256(b'DYNARK-V3-SOURCE-WIRE-v1\0' +
            json.dumps(signed, separators=(',', ':')).encode()).digest()
        binding = {'scope': scope, 'issuer': issuer,
                   'source_head': {'sequence': 3, 'digest': list(source_digest)},
                   'root': list(bytes.fromhex('02' * 32)), 'root_version': 1,
                   'publisher_key': publisher_public, 'publication_sequence': 3,
                   'previous_publication_digest': list(publisher_prior_digest)}
        body = dict(binding)
        publisher_message = b'DYNARK-V3-PUBLISHER-BINDING-v1\0' + json.dumps(
            body, separators=(',', ':')).encode()
        binding['signature'] = list(publisher_key.sign(publisher_message))
        publisher_digest = hashlib.sha256(b'DYNARK-V3-PUBLISHER-WIRE-v1\0' +
            json.dumps(binding, separators=(',', ':')).encode()).digest()
        report = {'source_head_digest': source_digest.hex(),
                  'publisher_envelope_digest': publisher_digest.hex()}
        history = {'checkpoints': [{'source': prior_source,
                                    'publisher': prior_publisher}]}
        context = {'root_sequence': ['01' * 32, '02' * 32]}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve()
            stage_root = output / 'stage'
            stage_root.mkdir(mode=0o700)
            def write(name, value):
                raw = json.dumps(value, separators=(',', ':')).encode()
                fd = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw)
                return sha(raw)
            report['effect_signed_source_sha256'] = write('effect-signed-source.json', signed)
            report['effect_signed_publisher_sha256'] = write('effect-signed-publisher.json', binding)
            report['effect_enrolled_source_sha256'] = write('effect-enrolled-source.json',
                                                            {'scope': scope, 'issuer': issuer})
            stage_enrolled = output / 'effect-enrolled-source.json'
            (stage_root / 'enrolled-source.json').write_bytes(stage_enrolled.read_bytes())
            (stage_root / 'enrolled-source.json').chmod(0o600)
            parsed = effect.signed_successor(output, stage_root, report, plan,
                                             history, context, 1)
            self.assertEqual(parsed[2], source_digest)
            wrong = dict(report, source_head_digest='ff' * 32)
            with self.assertRaises(ValueError):
                effect.signed_successor(output, stage_root, wrong, plan,
                                        history, context, 1)
            wrong = dict(signed)
            wrong['observation'] = dict(obs, changes=[{'Revoke': {}}])
            (output / 'effect-signed-source.json').write_bytes(
                json.dumps(wrong, separators=(',', ':')).encode())
            report['effect_signed_source_sha256'] = sha((output / 'effect-signed-source.json').read_bytes())
            with self.assertRaises(ValueError):
                effect.signed_successor(output, stage_root, report, plan,
                                        history, context, 1)

    def test_finalized_successor_may_change_only_signed_status_and_one_queue_effect(self):
        config_key = bytes([1] * 32)
        request_key = bytes([2] * 32)
        staged = {'config': effect.base.b58(config_key),
                  'request': effect.base.b58(request_key)}
        config = bytearray(381)
        config[:8] = b'DYNCONF3'
        issuer = bytearray(374)
        issuer[:8] = b'DYNISS03'
        head = bytearray(280)
        head[:8] = b'DYNHEAD3'
        head[112:144] = bytes([7] * 32)
        request = bytearray(2249)
        request[:8] = b'DYNREQ03'
        request[8:40] = config_key
        request[183] = 1
        queue = bytearray(2090)
        queue[:8] = b'DYNQUE03'
        queue[8:40] = config_key
        before = [bytes(value) for value in (config, issuer, head, request, queue)]
        source_digest = bytes([8] * 32)
        publisher_digest = bytes([9] * 32)
        issuer[173:181] = (3).to_bytes(8, 'big')
        issuer[181:213] = source_digest
        issuer[213:221] = (100).to_bytes(8, 'big', signed=True)
        issuer[221:229] = (280).to_bytes(8, 'big', signed=True)
        issuer[229:261] = bytes([2] * 32)
        issuer[261:269] = (1).to_bytes(8, 'big')
        issuer[269:277] = (3).to_bytes(8, 'big')
        issuer[277:309] = source_digest
        head[104:112] = (3).to_bytes(8, 'big')
        head[112:144] = publisher_digest
        head[144:176] = bytes([7] * 32)
        head[176:208] = bytes([2] * 32)
        head[208:216] = (1).to_bytes(8, 'big')
        head[216:224] = (3).to_bytes(8, 'big')
        head[224:256] = source_digest
        head[272:280] = (101).to_bytes(8, 'big', signed=True)
        request[183] = 2
        queue[40:42] = (1).to_bytes(2, 'big')
        queue[42:74] = request_key
        after = [bytes(value) for value in (config, issuer, head, request, queue)]
        context = {'root_sequence': ['01' * 32, '02' * 32]}
        signed = {'observation': {'observed_at': 100, 'valid_until': 280}}
        binding = {'source_head': {'sequence': 3}}
        effect.check_successor_accounts(before, after, staged, context, 1, signed,
                                        binding, source_digest, publisher_digest)
        wrong = list(after)
        changed = bytearray(wrong[1])
        changed[229] ^= 1
        wrong[1] = bytes(changed)
        with self.assertRaises(ValueError):
            effect.check_successor_accounts(before, wrong, staged, context, 1,
                                            signed, binding, source_digest,
                                            publisher_digest)


if __name__ == '__main__':
    unittest.main()
