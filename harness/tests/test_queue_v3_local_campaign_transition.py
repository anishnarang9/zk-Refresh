import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from harness.tests import queue_v3_clone_campaign_r0 as clone
from harness.tests import queue_v3_local_campaign_transition as transition

checked_history = transition.checked_history


def compact(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


def pinned_json(path, value):
    raw = (json.dumps(value, sort_keys=True) + '\n').encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


class CampaignHistoryTests(unittest.TestCase):
    def signed_chain(self, target_count=1):
        source = Ed25519PrivateKey.generate()
        publisher = Ed25519PrivateKey.generate()
        public = lambda key: key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        source_key, publisher_key = public(source), public(publisher)
        digests = [bytes([index + 1]) * 32 for index in range(11)]
        roots = [bytes([21 + index]) * 32 for index in range(11)]
        scope = {'network': [7] * 32}
        issuer = {'source_key': list(source_key)}
        checkpoints, source_digests, publisher_digests = [], [], []
        old_source, old_publisher = bytes(32), bytes(32)
        for index in range(target_count + 1):
            changes = ([{'Issue': {'tbs_digest': list(digest),
                                   'slot': 0 if j == 0 else j + 15,
                                   'allocation_epoch': 1}}
                        for j, digest in enumerate(digests)] if index == 0
                       else [{'Revoke': {'tbs_digest': list(digests[index])}}])
            observation = {'scope': scope, 'issuer': issuer,
                           'sequence': index + 1,
                           'previous_digest': list(old_source),
                           'observed_at': 100 + index,
                           'valid_until': 200 + index,
                           'issuer_status_active': True, 'changes': changes}
            signed = {'observation': observation,
                      'signature': list(source.sign(
                          b'DYNARK-V3-SOURCE-STATUS-v1\0' + compact(observation)))}
            source_digest = hashlib.sha256(
                b'DYNARK-V3-SOURCE-WIRE-v1\0' + compact(signed)).digest()
            body = {'scope': scope, 'issuer': issuer,
                    'source_head': {'sequence': index + 1,
                                    'digest': list(source_digest)},
                    'root': list(roots[index]), 'root_version': index,
                    'publisher_key': list(publisher_key),
                    'publication_sequence': index + 1,
                    'previous_publication_digest': list(old_publisher)}
            binding = {**body, 'signature': list(publisher.sign(
                b'DYNARK-V3-PUBLISHER-BINDING-v1\0' + compact(body)))}
            publisher_digest = hashlib.sha256(
                b'DYNARK-V3-PUBLISHER-WIRE-v1\0' + compact(binding)).digest()
            checkpoints.append({'source': signed, 'publisher': binding,
                                'checked_at': 100 + index})
            source_digests.append(source_digest)
            publisher_digests.append(publisher_digest)
            old_source, old_publisher = source_digest, publisher_digest
        history = {'schema': 'part5-v3-eleven-leaf-signed-history-v1',
                   'checkpoints': checkpoints}
        context = {'initial_allocations': {'tbs_digests': [d.hex() for d in digests]},
                   'root_sequence': [r.hex() for r in roots]}
        plan = {'source': list(source_key), 'publisher': list(publisher_key)}
        report = {'target_count': target_count, 'checkpoints': [{
            'root_version': index, 'root': roots[index].hex(),
            'source_sequence': index + 1, 'source_head_digest': source_digests[index].hex(),
            'publication_sequence': index + 1,
            'publisher_envelope_digest': publisher_digests[index].hex()}
            for index in range(1, target_count + 1)]}
        staged = {'source_head_digest': source_digests[0].hex(),
                  'publisher_envelope_digest': publisher_digests[0].hex()}
        return history, context, plan, report, staged

    def test_verifies_signed_chain_and_rejects_changed_revocation_or_root(self):
        inputs = self.signed_chain()
        checked_history(*inputs)
        for name, mutate in (
            ('revocation', lambda x: x[0]['checkpoints'][1]['source']['observation']
             ['changes'][0]['Revoke']['tbs_digest'].__setitem__(0, 99)),
            ('root', lambda x: x[0]['checkpoints'][1]['publisher']['root'].__setitem__(0, 99)),
            ('predecessor', lambda x: x[0]['checkpoints'][1]['source']['observation']
             ['previous_digest'].__setitem__(0, 99)),
        ):
            altered = copy.deepcopy(inputs)
            mutate(altered)
            with self.subTest(name=name), self.assertRaises(ValueError):
                checked_history(*altered)

    def test_finalized_accounts_commit_to_signed_r0_and_rk(self):
        for count in (1, 2, 5, 10):
            with self.subTest(count=count):
                history, context, plan, report, staged = self.signed_chain(count)
                commitments = checked_history(history, context, plan, report, staged)
                self.assertEqual(len(commitments), count + 1)

                def accounts(index):
                    source_digest, publisher_digest = commitments[index]
                    observation = history['checkpoints'][index]['source']['observation']
                    root = bytes.fromhex(context['root_sequence'][index])
                    issuer, head = bytearray(374), bytearray(280)
                    issuer[:8], head[:8] = b'DYNISS03', b'DYNHEAD3'
                    issuer[140:172] = bytes(plan['source'])
                    issuer[172], issuer[357] = 1, 1
                    issuer[173:181] = (index + 1).to_bytes(8, 'big')
                    issuer[181:213] = source_digest
                    issuer[213:221] = observation['observed_at'].to_bytes(8, 'big', signed=True)
                    issuer[221:229] = observation['valid_until'].to_bytes(8, 'big', signed=True)
                    issuer[229:261] = root
                    issuer[261:269] = index.to_bytes(8, 'big')
                    issuer[269:277] = (index + 1).to_bytes(8, 'big')
                    issuer[277:309] = source_digest
                    head[72:104] = bytes(plan['publisher'])
                    head[104:112] = (index + 1).to_bytes(8, 'big')
                    head[112:144] = publisher_digest
                    head[144:176] = commitments[index - 1][1] if index else bytes(32)
                    head[176:208] = root
                    head[208:216] = index.to_bytes(8, 'big')
                    head[216:224] = (index + 1).to_bytes(8, 'big')
                    head[224:256] = source_digest
                    return [b'', bytes(issuer), bytes(head), b'', b'']

                before, after = accounts(0), accounts(count)
                transition.check_finalized_chain(before, after, plan, context, history, commitments)
                for name, original, account, offset in (
                    ('final publisher', after, 2, 112),
                    ('final source', after, 1, 181),
                    ('R0 publisher', before, 2, 112),
                    ('R0 source', before, 1, 181),
                ):
                    altered = original.copy()
                    altered[account] = bytearray(original[account])
                    altered[account][offset] ^= 1
                    with self.subTest(name=name), self.assertRaises(ValueError):
                        transition.check_finalized_chain(
                            altered if original is before else before,
                            altered if original is after else after,
                            plan, context, history, commitments)

    def test_clone_rejects_stage_monitor_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / 'source' / 'ledger'
            source.mkdir(parents=True, mode=0o700)
            (root / 'clone').mkdir(mode=0o700)
            (source / 'genesis.bin').write_bytes(b'R0')
            (source / 'genesis.bin').chmod(0o600)
            stage = root / 'stage'
            stage.mkdir()
            config_path, report_path = root / 'config.json', stage / 'stage-report.json'
            status_path, monitor_path = root / 'status.json', root / 'monitor.json'
            config_sha = pinned_json(config_path, {'scope': 'part5-v3-campaign-stage',
                                                   'stage_output': str(stage), 'ledger': str(source)})
            report_sha = pinned_json(report_path, {'schema': 'part5-v3-campaign-stage-v1',
                'passed': True, 'registry_history_authenticated': True,
                'allocation_history_authenticated': True, 'application_effect': False,
                'loaded_program': {'elf_match': True}})
            status_sha = pinned_json(status_path, {'scope': 'part5-v3-campaign-stage',
                'config_sha256': config_sha, 'stage_report_sha256': report_sha,
                'stage_verified': True, 'stage_output': str(stage),
                'application_effect': False, 'ledger_reuse_requires_review': True,
                'validator_cleanup': {'exit_code': -2, 'reaped': True},
                'runner_cleanup': {'exit_code': 0, 'reaped': True}})
            monitor_sha = pinned_json(monitor_path, {'owner': 'campaign-stage',
                'stop_reason': None, 'runner_error_type': 'MonitorError',
                'cleanup_remaining_owned_processes': 0,
                'cleanup_status_unknown': False})
            with mock.patch.object(clone, 'ports_free'), self.assertRaisesRegex(
                    ValueError, 'reviewed stopped signed campaign R0 ledger'):
                clone.clone(str(config_path), config_sha, str(report_path), report_sha,
                            str(status_path), status_sha, str(monitor_path), monitor_sha,
                            'campaign-stage', str(root / 'clone' / 'ledger'))

    def test_transition_admission_rejects_stage_monitor_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            stage = root / 'stage'
            stage.mkdir()
            report_sha = pinned_json(stage / 'stage-report.json', {})
            plan_sha = pinned_json(stage / 'plan.json', {})
            config_path, status_path, monitor_path = (root / name for name in
                ('config.json', 'status.json', 'monitor.json'))
            config_sha = pinned_json(config_path, {'scope': 'part5-v3-campaign-stage',
                'stage_output': str(stage), 'context': 'context', 'context_sha256': 'digest'})
            status_sha = pinned_json(status_path, {'scope': 'part5-v3-campaign-stage',
                'config_sha256': config_sha, 'stage_report_sha256': report_sha,
                'stage_verified': True, 'ledger_reuse_requires_review': True,
                'validator_cleanup': {'exit_code': -2}, 'runner_cleanup': {'exit_code': 0}})
            monitor_sha = pinned_json(monitor_path, {'owner': 'campaign-stage',
                'stop_reason': None, 'runner_error_type': 'MonitorError',
                'cleanup_remaining_owned_processes': 0,
                'cleanup_status_unknown': False})
            config = {'schema': 1, 'scope': 'part5-v3-campaign-transition',
                'target_count': 1, 'outer_limits_required': transition.LIMITS,
                'stage_config': str(config_path), 'stage_config_sha256': config_sha,
                'stage_status': str(status_path), 'stage_status_sha256': status_sha,
                'stage_monitor': str(monitor_path), 'stage_monitor_sha256': monitor_sha,
                'stage_root': str(stage), 'stage_report_sha256': report_sha,
                'stage_plan_sha256': plan_sha, 'stage_monitor_owner': 'campaign-stage',
                'context': 'context', 'context_sha256': 'digest'}
            with self.assertRaisesRegex(ValueError, 'reviewed signed campaign R0 stage'):
                transition.admit(config)

    def test_runner_deadline_reserves_cleanup_time(self):
        self.assertTrue(hasattr(transition, 'runner_deadline'))
        started = 100.0
        deadline = transition.runner_deadline(started)
        self.assertLessEqual(deadline, started + transition.LIMITS['runtime_seconds'] - 45)


if __name__ == '__main__':
    unittest.main()
