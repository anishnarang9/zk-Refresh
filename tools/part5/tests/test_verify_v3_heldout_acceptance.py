import ast
import hashlib
import inspect
import json
from pathlib import Path
import tempfile
import unittest

from tools.part5 import verify_v3_heldout_acceptance as verifier
from tools.part5.generate_v3_heldout_keys import FREEZE_SCHEMA, IDENTITY_ROLES
from tools.part5.prepare_v3_heldout_context import COHORT_SCHEMA
from tools.part5.prepare_v3_revocation_cohort import membership_for_pair


class HeldoutAcceptanceVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def _cohort_provenance_artifacts(self):
        def write(path, value):
            raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o600)
            return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}

        freeze_path = self.root / 'freeze' / 'freeze.json'
        cohort_path = self.root / 'cohort' / 'cohort-receipt.json'
        identities = {role: f'{index + 1:064x}' for index, role in
                      enumerate(sorted(IDENTITY_ROLES))}
        freeze = {
            'schema': FREEZE_SCHEMA, 'frozen_at_unix_ns': 1000,
            'issuance_tool_sha256': 'a' * 64,
            'key_generation_tool_sha256': 'b' * 64,
            'identities': identities,
            'forbidden_public_key_sha256': ['c' * 64, 'd' * 64],
        }
        freeze_ref = write(freeze_path, freeze)
        inventory = {
            'schema': 'credential-v3-prior-public-key-inventory-v1',
            'observed_at_unix_ns': 900, 'freeze_sha256': freeze_ref['sha256'],
            'public_key_sha256': list(freeze['forbidden_public_key_sha256']),
        }
        inventory_ref = write(freeze_path.parent / 'prior-key-inventory.json', inventory)

        key_rows = []
        key_by_role_index = {}
        for role, count in (('issuer', 4), ('holder', 8)):
            for index in range(count):
                key_row = {
                    'role': role, 'index': index,
                    'public_key_sha256': f'{100 + len(key_rows):064x}',
                    'generation_started_unix_ns': 2011 + 2 * len(key_rows),
                    'generation_completed_unix_ns': 2012 + 2 * len(key_rows),
                }
                key_rows.append(key_row)
                key_by_role_index[(role, index)] = key_row
        key_receipt = {
            'schema': 'credential-v3-heldout-key-generation-v1',
            'freeze_receipt_sha256': freeze_ref['sha256'],
            'frozen_at_unix_ns': freeze['frozen_at_unix_ns'],
            'identities': identities,
            'issuance_tool_sha256': freeze['issuance_tool_sha256'],
            'key_generation_tool_sha256': freeze['key_generation_tool_sha256'],
            'generation_started_unix_ns': 2010,
            'generation_completed_unix_ns': 2040,
            'counts': {'issuers': 4, 'holders': 8}, 'keys': key_rows,
            'prior_public_key_count': 2,
            'provenance': {'implementation': 'cryptography.rsa.generate_private_key',
                           'cryptography_version': 'test-version', 'backend': 'test-backend',
                           'key_size': 2048, 'public_exponent': 65537,
                           'imported_keys': False, 'certificates_issued': False,
                           'reuse_scope': 'supplied earlier-key inventory and complete new cohort'},
        }
        key_receipt_ref = write(
            cohort_path.parent / 'keys' / 'key-generation-receipt.json', key_receipt)
        rows = []
        for variant in range(8):
            issuer_index, holder_index = variant % 4, variant
            rows.append({
                'variant': variant, 'issuer_index': issuer_index,
                'holder_index': holder_index,
                'issuer_public_key_sha256': key_by_role_index[
                    ('issuer', issuer_index)]['public_key_sha256'],
                'holder_public_key_sha256': key_by_role_index[
                    ('holder', holder_index)]['public_key_sha256'],
                'serial_hex': ((1 << 120) + variant + 1).to_bytes(16, 'big').hex(),
                'issuance_started_unix_ns': 2050 + 20 * variant,
                'issuance_completed_unix_ns': 2060 + 20 * variant,
            })
        cohort = {
            'generation_started_unix_ns': 2000,
            'generation_completed_unix_ns': 2300,
            'prior_key_inventory_sha256': inventory_ref['sha256'],
            'key_generation_receipt_sha256': key_receipt_ref['sha256'],
            'prior_public_key_count': 2, 'certificates': rows,
        }
        cohort_ref = write(cohort_path, cohort)
        return freeze, freeze_ref, cohort, cohort_ref, {
            variant: row for variant, row in enumerate(rows)}, key_receipt, inventory

    def test_fresh_full_replay_requires_same_statement_and_distinct_proof(self):
        first = self.root / 'first-wire.bin'
        second = self.root / 'replay-wire.bin'
        original = b'a' * 192 + b'b' * 256
        replay = b'a' * 192 + b'c' * 256
        first.write_bytes(original)
        second.write_bytes(replay)
        first.chmod(0o600)
        second.chmod(0o600)
        ref = lambda path: {'path': str(path),
                            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        verifier._verify_fresh_replay_wires(ref(first), ref(second))
        second.write_bytes(original)
        with self.assertRaisesRegex(ValueError, 'distinct randomized proof'):
            verifier._verify_fresh_replay_wires(ref(first), ref(second))
        second.write_bytes(b'z' * 192 + b'c' * 256)
        with self.assertRaisesRegex(ValueError, 'identical six public'):
            verifier._verify_fresh_replay_wires(ref(first), ref(second))

    def test_case_run_manifest_and_journal_must_join_frozen_evidence(self):
        globals_ = {name: {'pinned': name} for name in (
            'frozen_files', 'frozen_bundles', 'source_files', 'proof_inputs',
            'application_source_manifest', 'application_source_files')}
        runner_path = str(verifier.ROOT /
            'artifacts/dynark/part5/v3-heldout-queue-runner-001')
        globals_['frozen_bundles'] = {'registry': [{
            'path': 'artifacts/dynark/part5/v3-heldout-queue-runner-001',
            'artifact': {'path': runner_path, 'sha256': 'd' * 64}}],
            'client': []}
        run = {'schema': 'credential-v3-heldout-case-run-v1', 'variant': 2,
               'freeze_sha256': 'a' * 64, 'cohort_sha256': 'b' * 64,
               'runner': runner_path, 'runner_sha256': 'd' * 64, **globals_}
        run_path = self.root / 'case-02.json'
        run_raw = (json.dumps(run, sort_keys=True, indent=2) + '\n').encode()
        run_path.write_bytes(run_raw)
        run_path.chmod(0o600)
        canonical = hashlib.sha256((json.dumps(run, sort_keys=True,
            separators=(',', ':')) + '\n').encode()).hexdigest()
        journal_path = self.root / 'run-journal.json'
        journal = {'schema': 'credential-v3-heldout-case-run-journal-v1',
                   'manifest_sha256': canonical, 'steps': {
                       'positive_full:proof-full-fresh-replay': {'status': 'passed'}}}
        journal_raw = (json.dumps(journal, sort_keys=True) + '\n').encode()
        journal_path.write_bytes(journal_raw)
        journal_path.chmod(0o600)
        ref = lambda path: {'path': str(path),
                            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        case = {'run_manifest': ref(run_path), 'run_journal': ref(journal_path)}
        verifier._verify_case_run_provenance(case, 2, globals_, 'a' * 64, 'b' * 64)
        altered = dict(run, runner_sha256='e' * 64)
        run_path.write_bytes((json.dumps(altered, sort_keys=True, indent=2) + '\n').encode())
        case['run_manifest'] = ref(run_path)
        with self.assertRaisesRegex(ValueError, 'queue runner'):
            verifier._verify_case_run_provenance(case, 2, globals_, 'a' * 64, 'b' * 64)
        run_path.write_bytes(run_raw)
        case['run_manifest'] = ref(run_path)
        journal['manifest_sha256'] = 'c' * 64
        journal_path.write_bytes((json.dumps(journal, sort_keys=True) + '\n').encode())
        case['run_journal'] = ref(journal_path)
        with self.assertRaisesRegex(ValueError, 'journal.*manifest'):
            verifier._verify_case_run_provenance(case, 2, globals_, 'a' * 64, 'b' * 64)

    def test_manifest_reader_returns_exact_input_digest(self):
        raw = b'{"schema":"input"}\n'
        path = self.root / 'manifest.json'
        path.write_bytes(raw)
        manifest, digest = verifier._read_json_path(path)
        self.assertEqual(manifest, {'schema': 'input'})
        self.assertEqual(digest, hashlib.sha256(raw).hexdigest())

    def test_missing_case_evidence_fails_closed(self):
        manifest = {
            'schema': verifier.MANIFEST_SCHEMA,
            'freeze_receipt': {'path': str(self.root / 'missing-freeze.json'),
                               'sha256': 'a' * 64},
            'cohort_receipt': {'path': str(self.root / 'missing-cohort.json'),
                               'sha256': 'b' * 64},
            'frozen_files': {},
            'source_files': {},
            'cases': [],
        }
        manifest_path = self.root / 'manifest.json'
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'eight heldout cases'):
            verifier.verify_manifest(manifest_path)

    def test_offline_context_and_pair_receipts_cannot_claim_authentication(self):
        context = {'heldout_acceptance': False,
                   'authenticated': {'registry_history': False,
                                     'live_state': False,
                                     'current_head': False,
                                     'finalized_account_batch': False}}
        pair = {'heldout_acceptance': False, 'allocation_authorized': False,
                'registry_history_authenticated': False,
                'live_state_authenticated': False}
        verifier._verify_offline_provenance_flags(context, pair)
        context['authenticated']['current_head'] = True
        with self.assertRaisesRegex(ValueError, 'offline context'):
            verifier._verify_offline_provenance_flags(context, pair)
        context['authenticated']['current_head'] = False
        pair['allocation_authorized'] = True
        with self.assertRaisesRegex(ValueError, 'pair receipt'):
            verifier._verify_offline_provenance_flags(context, pair)

    def test_branch_passes_globals_and_slot_data_to_proof_validator(self):
        tree = ast.parse(inspect.getsource(verifier._verify_branch))
        calls = [node for node in ast.walk(tree)
                 if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name)
                 and node.func.id == '_validate_proof_bundle']
        self.assertEqual(len(calls), 1)
        self.assertEqual([ast.unparse(arg) for arg in calls[0].args], [
            "bundle['proof']", 'branch', 'case', 'globals_', 'slot_data',
            "result_bundle['wires']"])

    def test_proof_case_label_matches_heldout_runner_prefix(self):
        self.assertEqual(verifier._proof_case_label({'variant': 3}, 'unrelated_compare'),
                         'heldout_v03_unrelated_compare')

    def test_proof_supervisor_caps_accept_helper_poll_interval(self):
        limits = {'runtime_seconds': 600, 'rss_bytes': 4 * 1024**3,
                  'storage_bytes': 512 * 1024**2}
        outer = {'limits': {'runtime_seconds': 600,
                            'owned_tree_rss_bytes': 4 * 1024**3,
                            'storage_growth_bytes': 512 * 1024**2,
                            'poll_seconds': 0.25}}
        self.assertTrue(verifier._proof_outer_limits_match(outer, limits))
        outer['limits']['poll_seconds'] = 0.2
        self.assertFalse(verifier._proof_outer_limits_match(outer, limits))

    def test_reviewed_execute_status_accepts_verified_sigint_stop(self):
        status = {'scope': 'part5-v3-local-execute', 'status': 'failed',
                  'error_type': None, 'effect_verified': True,
                  'application_effect': True, 'effect_count': 1,
                  'execute_report_sha256': 'a' * 64,
                  'validator_cleanup': {'spawned': True, 'reaped': True,
                                        'graceful': False, 'exit_code': -2},
                  'runner_cleanup': {'spawned': True, 'reaped': True,
                                     'exit_code': 0}}
        verifier._verify_reviewed_local_status(
            status, scope='part5-v3-local-execute', verified_field='effect_verified',
            report_field='execute_report_sha256', report_sha256='a' * 64,
            application_effect=True, effect_count=1)
        status['validator_cleanup']['exit_code'] = 0
        with self.assertRaisesRegex(ValueError, 'reviewed stop'):
            verifier._verify_reviewed_local_status(
                status, scope='part5-v3-local-execute', verified_field='effect_verified',
                report_field='execute_report_sha256', report_sha256='a' * 64,
                application_effect=True, effect_count=1)

    def test_report_identity_joins_producer_report_summary_to_status_runtime(self):
        elf_sha256 = 'a' * 64
        program = 'program-address'
        genesis = 'genesis-hash'
        report = {
            'program': program,
            'genesis': genesis,
            'loaded_program': {
                'elf_match': True, 'elf_sha256': elf_sha256,
                'loader': 'BPFLoaderUpgradeab1e11111111111111111111111',
                'local_bytes': 123, 'remote_bytes': 123,
            },
        }
        status = {'loaded_program': {
            'elf_match': True, 'elf_sha256': elf_sha256,
            'program': program, 'programdata': 'programdata-address',
            'loader': 'BPFLoaderUpgradeab1e11111111111111111111111',
            'elf_bytes': 123,
            'program_account_sha256': 'b' * 64,
            'programdata_account_sha256': 'c' * 64,
            'genesis': genesis,
        }}

        identity_verifier = getattr(verifier, '_verify_report_runtime_identity', None)
        self.assertIsNotNone(identity_verifier,
                             'runtime identity join must be independently testable')
        config = {'expected_genesis': genesis}
        identity = identity_verifier(
            report, status, config, elf_sha256,
            expected_program=program, expected_genesis=genesis)

        self.assertEqual(identity['program'], program)
        self.assertEqual(identity['genesis'], genesis)
        with self.assertRaisesRegex(ValueError, 'runtime identity'):
            identity_verifier(
                report, status, config, elf_sha256,
                expected_program=program, expected_genesis='other-genesis')
        status['loaded_program']['program'] = 'other-program'
        with self.assertRaisesRegex(ValueError, 'runtime identity'):
            identity_verifier(
                report, status, config, elf_sha256,
                expected_program=program, expected_genesis=genesis)

    def test_exporter_source_and_ordinary_adapter_have_distinct_role_pins(self):
        source_hashes = {'exporter': 'd' * 64}
        proof_hashes = {'exporter': 'd' * 64, 'adapter_binary': '5' * 64}
        frozen_hashes = {'ordinary_adapter': '5' * 64}
        verifier._verify_exporter_adapter_roles(source_hashes, proof_hashes,
                                                frozen_hashes)
        proof_hashes['exporter'] = 'e' * 64
        with self.assertRaisesRegex(ValueError, 'exporter'):
            verifier._verify_exporter_adapter_roles(source_hashes, proof_hashes,
                                                    frozen_hashes)

    def test_proof_packet_and_report_must_share_exact_application_stage_pins(self):
        stage_pins = {name: f'{index + 1:064x}' for index, name in enumerate(
            verifier.PROOF_STAGE_PIN_FIELDS)}
        packet = {
            'schema': 'credential-v3-request-bound-anchor-v1',
            'synthetic_only': False, 'application_verified': False,
            'cohort': 'request-bound-training-v1',
            'proof_source_identity': 'f' * 64,
            'application_stage': stage_pins,
            'pairs': [{'name': 'request_bound_training',
                       'base': {'input_path': '/tmp/base/input.json',
                                'input_sha256': 'a' * 64,
                                'public_path': '/tmp/base/public.json',
                                'public_sha256': 'b' * 64,
                                'wtns_path': '/tmp/base/output.wtns',
                                'wtns_sha256': 'c' * 64,
                                'issuer_version': 1, 'policy_version': 1,
                                'allocation_epoch': 1, 'root_version': 0},
                       'near': {'input_path': '/tmp/near/input.json',
                                'input_sha256': 'd' * 64,
                                'public_path': '/tmp/near/public.json',
                                'public_sha256': 'e' * 64,
                                'wtns_path': '/tmp/near/output.wtns',
                                'wtns_sha256': 'f' * 64,
                                'issuer_version': 1, 'policy_version': 1,
                                'allocation_epoch': 1, 'root_version': 1}}],
        }
        packet.update({name: f'{index + 100:064x}' for index, name in enumerate(
            verifier.PACKET_IDENTITY_FIELDS)})
        report = {
            'schema': 'credential-v3-matched-k1-proof-v1', 'passed': True,
            'application_verified': False, 'setup_executed': False,
            'private_cache_persisted': False, 'qualification_extras_executed': False,
            'old_base_full_rejected_at_near_publics': True,
            'application_stage_pins_authority':
                'caller-supplied; external finalized-state verification required',
            'application_stage_pins': stage_pins,
            'package_digest': packet['package_digest'],
            'proof_binary_sha256': '1' * 64,
            'ordinary_vk_file_sha256': '2' * 64,
            'setup_manifest_sha256': '3' * 64,
            'proof_source_identity': packet['proof_source_identity'],
            'packet_sha256': '4' * 64,
            'mode': 'matched-full-k1',
            'counts': {'proofs': 2, 'positive_checks': 2,
                       'altered_public_checks': 12, 'cross_root_checks': 2,
                       'ordinary_checks': 16},
        }
        packet_fields = {name: packet[name] for name in verifier.PACKET_IDENTITY_FIELDS}
        packet_kinds = {'input.json': 'input', 'public.json': 'public',
                        'output.wtns': 'wtns'}
        artifact_refs = {
            f'{side}/{kind}': {'path': value[f'{packet_kind}_path'],
                               'sha256': value[f'{packet_kind}_sha256']}
            for side, value in (('base', packet['pairs'][0]['base']),
                                ('near', packet['pairs'][0]['near']))
            for kind, packet_kind in packet_kinds.items()
        }
        report_identities = {name: report[name] for name in (
            'package_digest', 'proof_binary_sha256', 'ordinary_vk_file_sha256',
            'setup_manifest_sha256', 'proof_source_identity')}
        verifier._validate_packet_and_proof_report(
            packet, report, packet_sha256='4' * 64, proof_mode='matched-full-k1',
            stage_pins=stage_pins, packet_fields=packet_fields,
            artifact_refs=artifact_refs,
            report_identities=report_identities,
            proof_counts=report['counts'])
        report['application_stage_pins'] = dict(stage_pins, base_root='e' * 64)
        with self.assertRaisesRegex(ValueError, 'stage pins'):
            verifier._validate_packet_and_proof_report(
                packet, report, packet_sha256='4' * 64, proof_mode='matched-full-k1',
                stage_pins=stage_pins, packet_fields=packet_fields,
                artifact_refs=artifact_refs,
                report_identities=report_identities,
                proof_counts=report['counts'])

    def test_cohort_requires_four_issuers_eight_layouts_and_exactly_four_openssl(self):
        freeze = {
            'schema': FREEZE_SCHEMA,
            'frozen_at_unix_ns': 100,
            'identities': {role: f'{index + 1:064x}'
                           for index, role in enumerate(sorted(IDENTITY_ROLES))},
        }
        rows = [{
            'variant': variant,
            'issuer_index': variant % 4,
            'holder_index': variant,
            'credential_sha256': f'{variant + 101:064x}',
            'tbs_sha256': f'{variant + 201:064x}',
            'issuer_public_key_sha256': f'{variant % 4 + 301:064x}',
            'holder_public_key_sha256': f'{variant + 401:064x}',
            'aki_sha256': f'{variant % 4 + 501:064x}',
            'issuer_hash': str(1000 + variant % 4),
            'policy_hash': str(2000 + variant // 4),
            'encoder': 'openssl' if variant < 4 else 'cryptography',
            'not_before_unix': 1_700_000_000,
            'not_after_unix': 1_800_000_000,
        } for variant in range(8)]
        cohort = {
            'schema': COHORT_SCHEMA,
            'status': 'cohort_issued_pending_application_gate',
            'keys_generated_after_freeze': True,
            'freeze_sha256': 'a' * 64,
            'frozen_at_unix_ns': 100,
            'generation_started_unix_ns': 101,
            'generation_completed_unix_ns': 102,
            'counts': {'issuers': 4, 'holders': 8, 'certificates': 8,
                       'openssl_issuances': 4, 'policies': 2},
            'policy_hashes': ['2000', '2001'],
            'issuer_aki_sha256': sorted({row['aki_sha256'] for row in rows}),
            'identities': freeze['identities'],
            'certificates': rows,
        }
        accepted = verifier._case_cohort(freeze, 'a' * 64, cohort, 'b' * 64)
        self.assertEqual(set(accepted), set(range(8)))
        cohort['certificates'][4]['encoder'] = 'openssl'
        with self.assertRaisesRegex(ValueError, 'OpenSSL'):
            verifier._case_cohort(freeze, 'a' * 64, cohort, 'b' * 64)

    def test_cohort_generation_provenance_joins_inventory_keys_times_and_serials(self):
        (freeze, freeze_ref, cohort, cohort_ref, by_variant,
         key_receipt, inventory) = self._cohort_provenance_artifacts()
        result = verifier._verify_cohort_generation_provenance(
            freeze, freeze_ref['sha256'], cohort, by_variant,
            freeze_ref, cohort_ref)
        self.assertEqual(result['prior_key_inventory_sha256'],
                         cohort['prior_key_inventory_sha256'])
        self.assertEqual(result['key_generation_receipt_sha256'],
                         cohort['key_generation_receipt_sha256'])

        by_variant[3]['serial_hex'] = (1 << 120).to_bytes(16, 'big').hex()
        with self.assertRaisesRegex(ValueError, 'serial sequence'):
            verifier._verify_cohort_generation_provenance(
                freeze, freeze_ref['sha256'], cohort, by_variant,
                freeze_ref, cohort_ref)
        by_variant[3]['serial_hex'] = ((1 << 120) + 4).to_bytes(16, 'big').hex()
        by_variant[2]['issuance_started_unix_ns'] = 2039
        with self.assertRaisesRegex(ValueError, 'issuance must follow key generation'):
            verifier._verify_cohort_generation_provenance(
                freeze, freeze_ref['sha256'], cohort, by_variant,
                freeze_ref, cohort_ref)

        by_variant[2]['issuance_started_unix_ns'] = 2090
        original_issuer_key = by_variant[0]['issuer_public_key_sha256']
        by_variant[0]['issuer_public_key_sha256'] = 'e' * 64
        with self.assertRaisesRegex(ValueError, 'match the pinned key-generation receipt'):
            verifier._verify_cohort_generation_provenance(
                freeze, freeze_ref['sha256'], cohort, by_variant,
                freeze_ref, cohort_ref)
        by_variant[0]['issuer_public_key_sha256'] = original_issuer_key

        key_receipt['keys'][0]['public_key_sha256'] = inventory['public_key_sha256'][0]
        key_path = Path(cohort_ref['path']).parent / 'keys' / 'key-generation-receipt.json'
        key_raw = json.dumps(key_receipt, sort_keys=True, separators=(',', ':')).encode()
        key_path.write_bytes(key_raw)
        key_path.chmod(0o600)
        cohort['key_generation_receipt_sha256'] = hashlib.sha256(key_raw).hexdigest()
        cohort_path = Path(cohort_ref['path'])
        cohort_raw = json.dumps(cohort, sort_keys=True, separators=(',', ':')).encode()
        cohort_path.write_bytes(cohort_raw)
        cohort_path.chmod(0o600)
        cohort_ref['sha256'] = hashlib.sha256(cohort_raw).hexdigest()
        with self.assertRaisesRegex(ValueError, 'absent from prior inventory'):
            verifier._verify_cohort_generation_provenance(
                freeze, freeze_ref['sha256'], cohort, by_variant,
                freeze_ref, cohort_ref)

    def test_anchor_transaction_receipt_must_show_stale_r0_rejection(self):
        rows = [
            {'scenario': 'v3-observe-signed-current-status', 'customError': None,
             'err': None},
            {'scenario': 'v3-bind-current-branch-head', 'customError': None,
             'err': None},
            {'scenario': 'v3-stale-R0-full', 'customError': 713,
             'err': {'InstructionError': [1, {'Custom': 713}]}},
            {'scenario': 'v3-anchor-wrong-action', 'customError': 712,
             'err': {'InstructionError': [1, {'Custom': 712}]}},
            {'scenario': 'v3-anchor-invalid-proof', 'customError': 714,
             'err': {'InstructionError': [1, {'Custom': 714}]}},
            {'scenario': 'v3-valid-anchor-R1', 'customError': None, 'err': None},
            {'scenario': 'v3-anchor-replay', 'customError': 707,
             'err': {'InstructionError': [1, {'Custom': 707}]}},
        ]
        expected = [(row['scenario'], row['customError']) for row in rows]
        verifier._txs(rows, expected, 'Anchor')
        rows[2] = dict(rows[2], customError=None, err=None)
        with self.assertRaisesRegex(ValueError, 'transaction outcome mismatch'):
            verifier._txs(rows, expected, 'Anchor')

    def test_full_a_transaction_receipt_matches_execute_report_order_and_codes(self):
        rows = [
            {'scenario': 'v3-refresh-active-source', 'customError': None,
             'err': None},
            {'scenario': 'v3-bind-refreshed-head', 'customError': None,
             'err': None},
            {'scenario': 'v3-wrong-issuer', 'customError': 713,
             'err': {'InstructionError': [1, {'Custom': 713}]}},
            {'scenario': 'v3-wrong-policy', 'customError': 713,
             'err': {'InstructionError': [1, {'Custom': 713}]}},
            {'scenario': 'v3-wrong-action', 'customError': 712,
             'err': {'InstructionError': [1, {'Custom': 712}]}},
            {'scenario': 'v3-invalid-proof', 'customError': 714,
             'err': {'InstructionError': [1, {'Custom': 714}]}},
            {'scenario': 'v3-valid-full-execute', 'customError': None,
             'err': None},
            {'scenario': 'v3-replay-new-transaction', 'customError': 707,
             'err': {'InstructionError': [1, {'Custom': 707}]}},
        ]
        snapshots = {'before_sha256': [f'{n:064x}' for n in range(1, 6)],
                     'after_sha256': [f'{n:064x}' for n in range(1, 6)]}
        verifier._verify_full_transactions(rows, snapshots)
        with self.assertRaisesRegex(ValueError, 'transaction outcome mismatch'):
            verifier._verify_full_transactions(rows[1:] + rows[:1], snapshots)
        rows[2]['err'] = {'InstructionError': [1, {'Custom': 714}]}
        with self.assertRaisesRegex(ValueError, 'Full A transaction error mismatch'):
            verifier._verify_full_transactions(rows, snapshots)
        rows[2]['err'] = {'InstructionError': [1, {'Custom': 713}]}
        snapshots['after_sha256'][0] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'preserve all five accounts'):
            verifier._verify_full_transactions(rows, snapshots)

    def test_full_a_rejection_hashes_must_match_pinned_account_bytes(self):
        finalized = {name: f'final-{name}'.encode()
                     for name in ('config', 'issuer', 'head', 'request', 'queue')}
        staged = {name: f'stage-{name}'.encode()
                  for name in ('config', 'issuer', 'head', 'request', 'queue')}
        expected = [hashlib.sha256(finalized[name]).hexdigest()
                    for name in ('config', 'issuer', 'head')]
        expected.extend(hashlib.sha256(staged[name]).hexdigest()
                        for name in ('request', 'queue'))
        report = {'before_sha256': expected[:], 'after_sha256': expected[:]}

        verifier._verify_full_rejection_account_hashes(report, finalized, staged)

        report['before_sha256'][0] = hashlib.sha256(b'tampered').hexdigest()
        report['after_sha256'][0] = report['before_sha256'][0]
        with self.assertRaisesRegex(ValueError, 'pinned finalized/staged account bytes'):
            verifier._verify_full_rejection_account_hashes(report, finalized, staged)

    def test_stage_receipt_requires_pre_enrollment_create_rejection_before_enrollment(self):
        rows = [
            {'scenario': 'v3-initialize', 'customError': None, 'err': None},
            {'scenario': 'v3-pre-enrollment-create', 'customError': 710,
             'err': {'InstructionError': [1, {'Custom': 710}]}},
            {'scenario': 'v3-enroll', 'customError': None, 'err': None},
            {'scenario': 'v3-create', 'customError': None, 'err': None},
        ]
        verifier._verify_pre_enrollment_create(rows, True)
        reordered = rows[:]
        reordered[1], reordered[2] = reordered[2], reordered[1]
        with self.assertRaisesRegex(ValueError, 'pre-enrollment Create must fail before enrollment'):
            verifier._verify_pre_enrollment_create(reordered, True)
        with self.assertRaisesRegex(ValueError, 'request PDA absent'):
            verifier._verify_pre_enrollment_create(rows, False)
        rows[1]['customError'] = 713
        rows[1]['err'] = {'InstructionError': [1, {'Custom': 713}]}
        with self.assertRaisesRegex(ValueError, 'pre-enrollment Create error mismatch'):
            verifier._verify_pre_enrollment_create(rows, True)

    def test_own_leaf_absence_is_rebuilt_from_pair_membership(self):
        own, unrelated = b't' * 32, b'u' * 32
        slot = 73
        membership = membership_for_pair(own, unrelated, slot)
        membership.update(issuer_hash=1200, policy_hash=2300)
        case = {
            'target': {'tbs_sha256': own.hex(), 'issuer_hash': '1200',
                       'policy_hash': '2300'},
            'unrelated': {'tbs_sha256': unrelated.hex()},
            'membership': membership,
            'roots': {'R0': f"{membership['active_root']:064x}",
                      'R1': f"{membership['unrelated_root']:064x}",
                      'R2': f"{membership['own_revoked_root']:064x}"},
        }
        verifier._verify_leaf_absent(case)
        case['roots']['R2'] = case['roots']['R1']
        with self.assertRaisesRegex(ValueError, 'active from finalized R2'):
            verifier._verify_leaf_absent(case)

    def test_four_outcomes_map_to_three_request_identities(self):
        branches = {
            'full': {'finalized_request_sha256': 'a' * 64,
                     'request_account_sha256': '1' * 64,
                     'action_hash': '1' * 64},
            'unrelated_full': {'finalized_request_sha256': 'b' * 64,
                               'request_account_sha256': '2' * 64,
                               'action_hash': '2' * 64,
                               'current_root': 'R1'},
            'anchor': {'finalized_request_sha256': 'b' * 64,
                       'request_account_sha256': '2' * 64,
                       'action_hash': '2' * 64,
                       'current_root': 'R1'},
            'own_revocation': {'finalized_request_sha256': 'd' * 64,
                               'request_account_sha256': '3' * 64,
                               'action_hash': '3' * 64},
        }
        finalized, accounts = set(), set()
        result = verifier._validate_request_triads(branches, finalized, accounts)
        self.assertEqual(result, {'A': 'a' * 64, 'B': 'b' * 64, 'C': 'd' * 64})
        self.assertEqual(len(finalized), 3)
        self.assertEqual(len(accounts), 3)
        branches['anchor'] = dict(branches['anchor'], finalized_request_sha256='e' * 64)
        with self.assertRaisesRegex(ValueError, 'share exact request B'):
            verifier._validate_request_triads(branches, set(), set())
        branches['anchor'] = dict(branches['unrelated_full'])
        branches['full']['action_hash'] = '2' * 64
        with self.assertRaisesRegex(ValueError, 'distinct action hashes'):
            verifier._validate_request_triads(branches, set(), set())

    def test_outer_allows_only_uncensored_expected_sigint_exit(self):
        path = self.root / 'outer.json'
        outer = {
            'schema': 1, 'passed': False, 'exit_code': 1,
            'stop_reason': None, 'runner_error_type': None,
            'cleanup_remaining_owned_processes': 0,
            'cleanup_status_unknown': False,
            'duration_seconds': 1.0, 'sample_count': 2,
        }
        path.write_text(json.dumps(outer))
        path.chmod(0o600)
        ref = {'path': str(path), 'sha256': verifier._sha(path.read_bytes())}
        self.assertEqual(verifier._outer(ref, 'transition')['exit_code'], 1)
        outer['stop_reason'] = 'runtime_limit'
        path.write_text(json.dumps(outer))
        ref['sha256'] = verifier._sha(path.read_bytes())
        with self.assertRaisesRegex(ValueError, 'complete uncensored outer session'):
            verifier._outer(ref, 'transition')




if __name__ == '__main__':
    unittest.main()
