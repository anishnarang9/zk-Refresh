import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.part5 import prepare_v3_queue_capacity_fixture as fixture


class CapacityProducerTests(unittest.TestCase):
    def stage_case(self):
        address = fixture.capacity.execute.base.b58
        stage = {name: address(bytes([index]) * 32)
                 for index, name in enumerate(('config', 'issuer', 'queue'), 1)}
        program = address(bytes([4]) * 32)
        genesis = address(bytes([5]) * 32)
        baseline = {'program': [4] * 32, 'genesis': [5] * 32,
                    'creator': [6] * 32, 'nonce': [0] * 32,
                    'issuer_hash': [7] * 32, 'recipient': [8] * 32,
                    'payload': [9] * 513, 'deadline': 1000}
        seed = bytes([10]) * 32
        rust = {'schema': 'part5-v3-queue-capacity-stage-config-v1',
                'scope': 'part5-v3-queue-capacity-stage',
                'plan': {'path': '/private/baseline-plan.json', 'sha256': 'b' * 64},
                'stage_report': {'path': '/private/stage.json', 'sha256': 'c' * 64},
                'creator': {'public_key': address(bytes([6]) * 32)},
                'nonce_seed': seed.hex(), 'program': program, 'genesis': genesis}
        config = {'rust_config_path': '/private/rust.json', 'rust_config_sha256': 'a' * 64,
                  'baseline_stage_report': rust['stage_report'], 'expected_program': program,
                  'expected_genesis': genesis, 'request_deadline': 2000,
                  'credential_not_after': 3000}
        rows, plans, requests = [], {}, {}
        for index in range(65):
            nonce = hashlib.sha256(b'part5-v3-capacity-nonce-v1' + seed
                                   + index.to_bytes(8, 'big')).digest()
            plan = {**baseline, 'nonce': list(nonce), 'deadline': 2000}
            request_address = address(index.to_bytes(2, 'big') + bytes([11]) * 30)
            request_path = f'/private/request-{index:02}.bin'
            plan_path = f'/private/plan-{index:02}.json'
            raw = bytearray(2249)
            raw[:8] = b'DYNREQ03'
            raw[8:40] = fixture.capacity.execute.base.key(stage['config'])
            raw[40:72] = bytes(plan['creator'])
            raw[72:104] = nonce
            raw[104:136] = bytes(plan['issuer_hash'])
            raw[136:168] = bytes(plan['recipient'])
            raw[168:170] = (1).to_bytes(2, 'big')
            raw[170:178] = (2000).to_bytes(8, 'big')
            raw[178:182] = (513).to_bytes(2, 'big') * 2
            raw[182:185] = b'\x02\x01\x02'
            raw[1225:1738] = bytes(plan['payload'])
            requests[request_path] = bytes(raw)
            plans[plan_path] = plan
            transactions = [dict(signature=f'signature-{index}-{part}', slot=10 + index * 5 + part,
                                 finalized=True, rpc_error=None, block_time=1500)
                            for part in range(5)]
            rows.append({'request_address': request_address, 'request_account': request_path,
                         'request_sha256': hashlib.sha256(raw).hexdigest(),
                         'plan': {'path': plan_path, 'sha256': 'd' * 64},
                         'action_sha256': 'e' * 64, 'finalization': transactions[-1],
                         'transactions': transactions, 'finalized_account_slot': transactions[-1]['slot']})
        report = {'schema': fixture.PREPARATION_SCHEMA, 'passed': True,
                  'config_ref': {'path': config['rust_config_path'],
                                 'sha256': config['rust_config_sha256']},
                  'stage_report_sha256': config['baseline_stage_report']['sha256'],
                  'request_count': 65, 'queue_empty': True,
                  'request_preparation_effect': True, 'application_effect': False,
                  'loaded_program': {'loaded': True}, 'request_deadline': 2000,
                  'credential_not_after': 3000, 'program': program, 'genesis': genesis,
                  'inputs': rows, 'finalized_slot': rows[-1]['finalized_account_slot']}
        docs = {config['rust_config_path']: rust,
                config['baseline_stage_report']['path']: stage,
                rust['plan']['path']: baseline, **plans}
        return config, report, docs, requests

    def test_stage_transaction_specs_bind_create_upload_metas_finalize(self):
        plan = {'nonce': [1]*32, 'issuer_hash': [2]*32, 'recipient': [3]*32,
                'deadline': 1234, 'payload': list(range(256))*3, 'creator': [4]*32}
        stage = {'config': 'config', 'issuer': 'issuer', 'queue': 'queue'}
        with patch.object(fixture.capacity.execute.base, 'b58', return_value='creator'), \
             patch.object(fixture.capacity.execute.base, 'key', return_value=b'\x05'*32):
            specs = fixture.stage_transaction_specs(plan, stage, 'request', 'program')
        self.assertEqual([name for name, _, _ in specs],
                         ['create', 'upload', 'upload', 'upload-metas', 'finalize'])
        self.assertEqual(specs[0][1][:2], b'\x51\x04')
        self.assertEqual(specs[0][1][2:34], bytes([1])*32)
        self.assertEqual(specs[1][1][:6], b'\x51\x06\x00\x00\x02\x00')
        self.assertEqual(specs[2][1][:6], b'\x51\x06\x02\x00\x01\x00')
        self.assertEqual(specs[-1][1], b'\x51\x05')
        self.assertEqual(specs[0][2][0], ('creator', True, True))
        self.assertEqual(specs[-1][2][0], ('creator', True, False))

    def test_stage_replays_every_normal_signed_transaction(self):
        config, report, docs, requests = self.stage_case()
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(fixture, 'doc', side_effect=lambda ref, cap=1048576: docs[ref['path']]), \
             patch.object(fixture, 'read', side_effect=lambda ref, cap=1048576: requests[ref['path']]), \
             patch('harness.tests.queue_v3_capacity_runtime.rpc_transaction') as replay:
            replay.side_effect = lambda rpc, row, program, data, metas, output, index: {
                **row, 'transaction': {'path': f'rpc/transaction-{index:03}.bin', 'sha256': 'f' * 64}}
            result = fixture.verify_stage(object(), report, config, Path(directory),
                                          {'loaded': True}, 123)
            self.assertEqual(replay.call_count, 65 * 5)
            self.assertEqual(replay.call_args_list[0].args[3][:2], b'\x51\x04')
            self.assertEqual(replay.call_args_list[1].args[3][:6], b'\x51\x06\x00\x00\x02\x00')
            self.assertEqual(replay.call_args_list[3].args[3][:2], b'\x51\x08')
            self.assertEqual(replay.call_args_list[-1].args[3], b'\x51\x05')
            self.assertEqual(result['transaction_count'], 325)
            self.assertTrue((Path(directory) / 'stage-rpc-replay.json').exists())

    def test_stage_rejects_missing_or_failed_normal_transaction(self):
        config, report, docs, requests = self.stage_case()
        with patch.object(fixture, 'doc', side_effect=lambda ref, cap=1048576: docs[ref['path']]), \
             patch.object(fixture, 'read', side_effect=lambda ref, cap=1048576: requests[ref['path']]), \
             patch('harness.tests.queue_v3_capacity_runtime.rpc_transaction') as replay:
            replay.side_effect = lambda rpc, row, program, data, metas, output, index: {
                **row, 'transaction': {'path': f'rpc/transaction-{index:03}.bin', 'sha256': 'f' * 64}}
            for mutation in ('missing', 'failed'):
                with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                    replay.reset_mock()
                    changed = {**report, 'inputs': [dict(row) for row in report['inputs']]}
                    changed['inputs'][0]['transactions'] = list(changed['inputs'][0]['transactions'])
                    if mutation == 'missing':
                        changed['inputs'][0]['transactions'].pop(1)
                    else:
                        changed['inputs'][0]['transactions'][1] = {
                            **changed['inputs'][0]['transactions'][1], 'rpc_error': {'Custom': 1}}
                    with self.assertRaises(ValueError):
                        fixture.verify_stage(object(), changed, config, Path(directory),
                                             {'loaded': True}, 123)
                    self.assertFalse((Path(directory) / 'stage-rpc-replay.json').exists())
                    self.assertEqual(replay.call_count, 0 if mutation == 'missing' else 1)

    def test_stage_rejects_noncanonical_nonce_seed_before_rpc(self):
        config, report, docs, requests = self.stage_case()
        docs[config['rust_config_path']] = {
            **docs[config['rust_config_path']], 'nonce_seed': '0A' * 32}
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(fixture, 'doc', side_effect=lambda ref, cap=1048576: docs[ref['path']]), \
             patch.object(fixture, 'read', side_effect=lambda ref, cap=1048576: requests[ref['path']]), \
             patch('harness.tests.queue_v3_capacity_runtime.rpc_transaction') as replay:
            with self.assertRaisesRegex(ValueError, 'canonical capacity nonce seed'):
                fixture.verify_stage(object(), report, config, Path(directory),
                                     {'loaded': True}, 123)
        replay.assert_not_called()

    def test_stage_rpc_replay_failure_does_not_publish_receipt(self):
        config, report, docs, requests = self.stage_case()
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(fixture, 'doc', side_effect=lambda ref, cap=1048576: docs[ref['path']]), \
             patch.object(fixture, 'read', side_effect=lambda ref, cap=1048576: requests[ref['path']]), \
             patch('harness.tests.queue_v3_capacity_runtime.rpc_transaction',
                   side_effect=ValueError('signed transaction mismatch')) as replay:
            with self.assertRaisesRegex(ValueError, 'signed transaction mismatch'):
                fixture.verify_stage(object(), report, config, Path(directory),
                                     {'loaded': True}, 123)
            self.assertFalse((Path(directory) / 'stage-rpc-replay.json').exists())
        replay.assert_called_once()

    def test_one_proof_cannot_publish_full_fixture(self):
        with patch.object(fixture, 'write') as writer:
            with self.assertRaisesRegex(ValueError, '65 complete proofs'):
                fixture.publish_full_fixture(Path('/private/output'), {}, {},
                                             {'inputs': [{}] * 65}, {}, {}, [{}], [{}], 0, 3600)
        writer.assert_not_called()

    def test_repeated_pilot_proof_cannot_fill_65_proof_slots(self):
        one = {'path': '/private/one-proof.json', 'sha256': 'a' * 64}
        inputs = [{'proof_receipt': one['path'], 'proof_receipt_sha256': one['sha256'],
                   'request_address': f'request-{index}'} for index in range(65)]
        prepared = {'inputs': [{'request_address': f'request-{index}',
                                'finalization': {'signature': f'sig-{index}', 'slot': index + 1}}
                               for index in range(65)], 'program': 'program', 'genesis': 'genesis',
                    'loaded_program': {'elf_sha256': 'b' * 64}, 'request_deadline': 1234}
        config = {'genesis_sha256': 'c' * 64, 'baseline_stage_report': {}, 'signers': {},
                  'preparation_report': {}, 'stage_config': {}, 'stage_status': {},
                  'stage_monitor': {}, 'stage_invocation': {}, 'freeze': {}}
        with patch.object(fixture, 'write') as writer, \
             patch.object(fixture, 'doc', return_value={'duration_seconds': 1}):
            with self.assertRaisesRegex(ValueError, '65 distinct proofs'):
                fixture.publish_full_fixture(Path('/private/output'), config, {},
                                             prepared, {'ledger': '/private/ledger'}, {},
                                             [one] * 65, inputs, 0, 3600)
        writer.assert_not_called()

    def test_pilot_receipt_cannot_authorize_full_fixture_clone(self):
        config = {'stage_config': {'path': '/private/stage-config', 'sha256': 'a' * 64},
                  'stage_status': {'path': '/private/stage-status', 'sha256': 'b' * 64},
                  'preparation_report': {'path': '/private/prepared', 'sha256': 'c' * 64},
                  'stage_monitor': {'path': '/private/stage-monitor', 'sha256': 'd' * 64},
                  'stage_invocation': {'path': '/private/stage-invocation', 'sha256': 'e' * 64},
                  'preparation_receipt': {'path': '/private/pilot', 'sha256': 'f' * 64}}
        docs = {'/private/stage-config': {},
                '/private/stage-status': {'status': 'candidate_verified_pending_external_finalization',
                                          'candidate': config['preparation_report'],
                                          'config_ref': config['stage_config']},
                '/private/prepared': {'schema': fixture.PREPARATION_SCHEMA,
                                      'request_count': 65, 'queue_empty': True},
                '/private/stage-monitor': {}, '/private/stage-invocation': {},
                '/private/pilot': {'schema': 'part5-v3-queue-capacity-one-proof-pilot-v1',
                                   'preparation_report': config['preparation_report'],
                                   'proof_receipts': [{}] * 65}}
        with patch.object(fixture, 'doc', side_effect=lambda ref, cap=1048576: docs[ref['path']]), \
             patch('tools.part5.finalize_v3_queue_capacity_negative.check_monitor'), \
             patch.object(fixture, 'inventory') as inventory:
            with self.assertRaisesRegex(ValueError, 'completed offline proof owner'):
                fixture.clone_prepared(config, {})
        inventory.assert_not_called()

    def clone_case(self, directory):
        root = Path(directory).resolve()
        source = root / 'source' / 'ledger'
        destination = root / 'target' / 'ledger'
        source.mkdir(parents=True, mode=0o700)
        destination.parent.mkdir(mode=0o700)
        (source / 'data').write_bytes(b'prepared ledger')
        (source / 'data').chmod(0o600)
        pin = lambda name: {'path': str(root / name), 'sha256': 'a' * 64}
        config = {name: pin(name) for name in (
            'stage_config', 'stage_status', 'preparation_report', 'stage_monitor',
            'stage_invocation', 'preparation_receipt', 'proof_monitor', 'proof_invocation',
            'baseline_stage_report')}
        tree = fixture.inventory(source)
        import json
        config.update(phase='clone', ledger=str(destination), output_dir=str(destination.parent),
                      source_tree_sha256=hashlib.sha256(
                          json.dumps(tree, separators=(',', ':')).encode()).hexdigest())
        proof_config = pin('proof-config')
        docs = {config['stage_config']['path']: {'ledger': str(source)},
                config['stage_status']['path']: {
                    'status': 'candidate_verified_pending_external_finalization',
                    'candidate': config['preparation_report'], 'config_ref': config['stage_config']},
                config['preparation_report']['path']: {
                    'schema': fixture.PREPARATION_SCHEMA, 'request_count': 65, 'queue_empty': True},
                config['preparation_receipt']['path']: {
                    'schema': 'part5-v3-queue-capacity-prepared-fixture-v1',
                    'fixture_manifest': pin('fixture'), 'preparation_report': config['preparation_report'],
                    'proof_receipts': [{}] * 65, 'config_ref': proof_config},
                proof_config['path']: {'phase': 'proofs'}}
        return config, pin('clone-config'), docs, destination

    def test_clone_receipt_binds_owner_config_and_exact_source_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            config, config_pin, docs, destination = self.clone_case(directory)
            with patch.object(fixture, 'doc', side_effect=lambda pin: docs.get(pin['path'], {})), \
                 patch('tools.part5.finalize_v3_queue_capacity_negative.check_monitor'):
                result = fixture.clone_prepared(config, config_pin)
            self.assertEqual(result.get('config_ref'), config_pin)
            self.assertEqual(result['tree_sha256'], config['source_tree_sha256'])
            self.assertEqual(result['destination'], str(destination))
            self.assertTrue(result['clone_owner_required'])
            self.assertFalse(result['cost_included'])
            self.assertEqual(result['owner_limits']['runtime_seconds'], 3600)
            self.assertEqual(result['owner_limits']['storage_growth_bytes'], 17179869184)
            self.assertTrue((destination.parent / 'clone-report.json').exists())

    def test_clone_rejects_missing_or_changed_source_pin_before_copy(self):
        for invalid in (None, 'b' * 64):
            with self.subTest(pin=invalid), tempfile.TemporaryDirectory() as directory:
                config, config_pin, docs, destination = self.clone_case(directory)
                config['source_tree_sha256'] = invalid
                with patch.object(fixture, 'doc', side_effect=lambda pin: docs.get(pin['path'], {})), \
                     patch('tools.part5.finalize_v3_queue_capacity_negative.check_monitor'), \
                     patch.object(fixture.shutil, 'copytree', wraps=fixture.shutil.copytree) as copy:
                    with self.assertRaisesRegex(ValueError, 'pinned prepared source tree'):
                        fixture.clone_prepared(config, config_pin)
                copy.assert_not_called()
                self.assertFalse((destination.parent / 'clone-report.json').exists())

    def test_clone_rejects_existing_report_or_wrong_output_root_before_copy(self):
        for invalid in ('existing', 'wrong-root'):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as directory:
                config, config_pin, docs, destination = self.clone_case(directory)
                if invalid == 'existing':
                    (destination.parent / 'clone-report.json').write_text('{}')
                else:
                    config['output_dir'] = str(destination.parent.parent)
                with patch.object(fixture, 'doc', side_effect=lambda pin: docs.get(pin['path'], {})), \
                     patch('tools.part5.finalize_v3_queue_capacity_negative.check_monitor'), \
                     patch.object(fixture.shutil, 'copytree') as copy:
                    with self.assertRaisesRegex(ValueError, 'fresh rooted clone report'):
                        fixture.clone_prepared(config, config_pin)
                copy.assert_not_called()

    def test_proof_and_clone_dispatch_are_separate(self):
        pin = {'path': '/private/config.json', 'sha256': 'c'*64}
        with patch.object(fixture, 'prepare_proofs', return_value={'schema': 'pilot'}) as proofs, \
             patch.object(fixture, 'clone_prepared', return_value={'schema': 'clone'}) as clone:
            self.assertEqual(fixture.run({'phase': 'proofs', 'proof_count': 1}, pin), 0)
            proofs.assert_called_once_with({'phase': 'proofs', 'proof_count': 1}, pin)
            clone.assert_not_called()
            self.assertEqual(fixture.run({'phase': 'clone'}, pin), 0)
            clone.assert_called_once_with({'phase': 'clone'}, pin)

    def test_stage_launches_exact_staging_callback(self):
        config = {'phase': 'stage', 'rust_config_path': '/private/rust.json',
                  'rust_config_sha256': 'a'*64, 'request_deadline': 20000,
                  'credential_not_after': 30000, 'proof_owner_limit_seconds': 3600,
                  'cohort_manifest': {'path': '/private/cohort.json', 'sha256': 'd'*64},
                  'expected_program': 'program', 'expected_genesis': 'genesis',
                  'baseline_stage_report': {'path': '/private/stage.json', 'sha256': 'b'*64}}
        rust = {'credential_not_after': 30000, 'request_deadline': 20000,
                'stage_report': config['baseline_stage_report'], 'proof_owner_limit_seconds': 3600,
                'plan': {'path': '/private/plan.json', 'sha256': 'e'*64}}
        baseline = {'schema': 'part5-v3-local-stage-v1', 'passed': True,
                    'plan_sha256': 'e'*64, 'program': 'program', 'genesis': 'genesis'}
        pin = {'path': '/private/config.json', 'sha256': 'c'*64}
        with patch.object(fixture, 'doc', side_effect=[rust, baseline, {}]), \
             patch.object(fixture, 'signed_validity', return_value=30000), \
             patch.object(fixture.time, 'time', return_value=100), \
             patch('harness.tests.queue_v3_capacity_runtime.supervise', return_value=0) as launch:
            self.assertEqual(fixture.run(config, pin), 0)
        launch.assert_called_once_with(config, pin, 'capacity-preparation-report.json',
                                       fixture.verify_stage, staging=True)

    def test_stage_rejects_uncovered_owner_window_before_launch(self):
        config = {'phase': 'stage', 'rust_config_path': '/private/rust.json',
                  'rust_config_sha256': 'a'*64, 'request_deadline': 100,
                  'credential_not_after': 200, 'proof_owner_limit_seconds': 3600,
                  'cohort_manifest': {'path': '/private/cohort.json', 'sha256': 'd'*64},
                  'expected_program': 'program', 'expected_genesis': 'genesis',
                  'baseline_stage_report': {'path': '/private/stage.json', 'sha256': 'b'*64}}
        rust = {'credential_not_after': 200, 'request_deadline': 100,
                'stage_report': config['baseline_stage_report'], 'proof_owner_limit_seconds': 3600,
                'plan': {'path': '/private/plan.json', 'sha256': 'e'*64}}
        baseline = {'schema': 'part5-v3-local-stage-v1', 'passed': True,
                    'plan_sha256': 'e'*64, 'program': 'program', 'genesis': 'genesis'}
        with patch.object(fixture, 'doc', side_effect=[rust, baseline, {}]), \
             patch.object(fixture, 'signed_validity', return_value=200), \
             patch('harness.tests.queue_v3_capacity_runtime.supervise') as launch:
            with self.assertRaisesRegex(ValueError, 'signed validity'):
                fixture.run(config, {'path': '/private/config.json', 'sha256': 'c'*64})
        launch.assert_not_called()

    def test_signed_validity_rejects_deadline_past_der(self):
        config = {'credential_source': {'credential': {'path': '/private/credential.der', 'sha256': 'a'*64},
                                        'issuer_modulus': {'path': '/private/issuer.bin', 'sha256': 'b'*64}}}
        with patch.object(fixture, 'read', side_effect=[b'der', b'\x01'*256]), \
             patch.object(fixture, 'admit_certificate', return_value={'not_after': 100}):
            with self.assertRaisesRegex(ValueError, 'signed credential validity'):
                fixture.signed_validity(config, 101)

    def test_signed_validity_uses_pinned_der_and_modulus(self):
        config = {'credential_source': {'credential': {'path': '/private/credential.der', 'sha256': 'a'*64},
                                        'issuer_modulus': {'path': '/private/issuer.bin', 'sha256': 'b'*64}}}
        with patch.object(fixture, 'read', side_effect=[b'der', b'\x01'*256]) as reader, \
             patch.object(fixture, 'admit_certificate', return_value={'not_after': 200}) as admit:
            self.assertEqual(fixture.signed_validity(config, 199), 200)
        self.assertEqual(reader.call_count, 2)
        admit.assert_called_once_with(b'der', int.from_bytes(b'\x01'*256, 'big'))


if __name__ == '__main__':
    unittest.main()
