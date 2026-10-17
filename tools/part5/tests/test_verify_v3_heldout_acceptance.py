import ast
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
