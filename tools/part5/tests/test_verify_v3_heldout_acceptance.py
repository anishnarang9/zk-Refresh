import ast
import hashlib
import inspect
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tools.part5 import verify_v3_heldout_acceptance as verifier
from tools.part5 import build_v3_heldout_cohort as cohort_builder
from tools.part5.issue_v3_heldout_certificate import issue_certificate
from tools.part5.generate_v3_heldout_keys import FREEZE_SCHEMA, IDENTITY_ROLES
from tools.part5.prepare_v3_heldout_context import COHORT_SCHEMA
from tools.part5.prepare_v3_revocation_cohort import membership_for_pair
from tools.part5.credential_profile import admit_certificate, public_bindings


class HeldoutAcceptanceVerifierTests(unittest.TestCase):
    def test_anchor_effect_bytes_require_one_request_consume_and_exact_pda_append(self):
        before_request = bytearray(2249)
        before_request[:8] = b'DYNREQ03'
        before_request[183] = 1
        before_queue = bytearray(2090)
        before_queue[:8] = b'DYNQUE03'
        before_queue[8:40] = bytes([3]) * 32
        before_queue[40:42] = (1).to_bytes(2, 'big')
        before_queue[42:74] = bytes([4]) * 32
        request_key = bytes([5]) * 32
        after_request = bytearray(before_request)
        after_request[183] = 2
        after_queue = bytearray(before_queue)
        after_queue[40:42] = (2).to_bytes(2, 'big')
        after_queue[74:106] = request_key

        verifier._verify_single_effect_bytes(
            bytes(before_request), bytes(before_queue), bytes(after_request),
            bytes(after_queue), request_key)

        extra_request_change = bytearray(after_request)
        extra_request_change[200] ^= 1
        with self.assertRaisesRegex(ValueError, 'exactly consume the request'):
            verifier._verify_single_effect_bytes(
                bytes(before_request), bytes(before_queue), bytes(extra_request_change),
                bytes(after_queue), request_key)

        extra_queue_change = bytearray(after_queue)
        extra_queue_change[110] ^= 1
        with self.assertRaisesRegex(ValueError, 'append the request PDA exactly once'):
            verifier._verify_single_effect_bytes(
                bytes(before_request), bytes(before_queue), bytes(after_request),
                bytes(extra_queue_change), request_key)

    def test_anchor_effect_bytes_reject_wrong_or_duplicate_request_pda(self):
        before_request = bytearray(2249)
        before_request[:8] = b'DYNREQ03'
        before_request[183] = 1
        before_queue = bytearray(2090)
        before_queue[:8] = b'DYNQUE03'
        before_queue[40:42] = (1).to_bytes(2, 'big')
        before_queue[42:74] = bytes([4]) * 32
        request_key = bytes([5]) * 32
        after_request = bytearray(before_request)
        after_request[183] = 2
        after_queue = bytearray(before_queue)
        after_queue[40:42] = (2).to_bytes(2, 'big')
        after_queue[74:106] = bytes([6]) * 32
        with self.assertRaisesRegex(ValueError, 'append the request PDA exactly once'):
            verifier._verify_single_effect_bytes(
                bytes(before_request), bytes(before_queue), bytes(after_request),
                bytes(after_queue), request_key)

        duplicate_before_queue = bytearray(before_queue)
        duplicate_before_queue[40:42] = (1).to_bytes(2, 'big')
        duplicate_before_queue[42:74] = request_key
        duplicate_after_queue = bytearray(duplicate_before_queue)
        duplicate_after_queue[40:42] = (2).to_bytes(2, 'big')
        duplicate_after_queue[74:106] = request_key
        with self.assertRaisesRegex(ValueError, 'must not already be present'):
            verifier._verify_single_effect_bytes(
                bytes(before_request), bytes(duplicate_before_queue),
                bytes(after_request), bytes(duplicate_after_queue), request_key)

        duplicate_other_queue = bytearray(before_queue)
        duplicate_other_queue[40:42] = (2).to_bytes(2, 'big')
        duplicate_other_queue[74:106] = duplicate_other_queue[42:74]
        duplicate_other_after = bytearray(duplicate_other_queue)
        duplicate_other_after[40:42] = (3).to_bytes(2, 'big')
        duplicate_other_after[106:138] = request_key
        with self.assertRaisesRegex(ValueError, 'canonical bounded encoding'):
            verifier._verify_single_effect_bytes(
                bytes(before_request), bytes(duplicate_other_queue),
                bytes(after_request), bytes(duplicate_other_after), request_key)

    def test_config_root_version_uses_program_big_endian_encoding(self):
        config = bytearray(381)
        config[:8] = b'DYNCONF3'
        for version in (0, 1, 2):
            config[364:372] = version.to_bytes(8, 'big')
            self.assertEqual(verifier._config_root_version(bytes(config)), version)
        config[364:372] = (1).to_bytes(8, 'little')
        self.assertNotEqual(verifier._config_root_version(bytes(config)), 1)

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

        cohort_root, imported_rows, imported_key_rows, _, _ = self._real_import_fixture('cohort')
        self.assertEqual(cohort_path.parent, cohort_root)
        key_rows = []
        key_by_role_index = {}
        for role, count in (('issuer', 4), ('holder', 8)):
            for index in range(count):
                key_row = {
                    'role': role, 'index': index,
                    'public_key_sha256': imported_key_rows[(role, index)]['public_key_sha256'],
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
            row = dict(imported_rows[variant])
            row.update(issuance_started_unix_ns=2050 + 20 * variant,
                       issuance_completed_unix_ns=2060 + 20 * variant)
            rows.append(row)
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

    def _real_import_fixture(self, name='import-cohort'):
        cohort_root = self.root / name
        keys_root = cohort_root / 'keys'
        keys_root.mkdir(parents=True, mode=0o700)
        issuer_keys = [rsa.generate_private_key(public_exponent=65537, key_size=2048)
                       for _ in range(4)]
        holder_keys = [rsa.generate_private_key(public_exponent=65537, key_size=2048)
                       for _ in range(8)]
        key_map, rows = {}, {}
        for role, keys in (('issuer', issuer_keys), ('holder', holder_keys)):
            for index, key in enumerate(keys):
                key_map[(role, index)] = key
                path = keys_root / f'{role}-{index}.pem'
                path.write_bytes(key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()))
                path.chmod(0o600)
        for variant in range(8):
            issuer_index, holder_index = variant % 4, variant
            issuer, holder = issuer_keys[issuer_index], holder_keys[holder_index]
            issuer_digest = self._spki_digest(issuer.public_key())
            params = cohort_builder._certificate_parameters(variant, issuer_digest)
            der = issue_certificate(issuer, holder, params, 'cryptography')
            cert_dir = cohort_root / f'certificate-{variant:02d}'
            cert_dir.mkdir(mode=0o700)
            cert_path = cert_dir / 'credential.der'
            cert_path.write_bytes(der)
            cert_path.chmod(0o600)
            parsed = admit_certificate(der, issuer.public_key().public_numbers().n)
            issuer_hash, policy_hash = public_bindings(
                parsed, issuer.public_key().public_numbers().n)
            rows[variant] = {
                'variant': variant, 'issuer_index': issuer_index,
                'holder_index': holder_index,
                'encoder': 'openssl' if variant < 4 else 'cryptography',
                'credential_sha256': hashlib.sha256(der).hexdigest(),
                'tbs_sha256': hashlib.sha256(parsed['tbs']).hexdigest(),
                'issuer_public_key_sha256': self._spki_digest(issuer.public_key()),
                'holder_public_key_sha256': self._spki_digest(holder.public_key()),
                'issuer_hash': str(issuer_hash), 'policy_hash': str(policy_hash),
                'aki_sha256': hashlib.sha256(parsed['aki']).hexdigest(),
                'organization_sha256': hashlib.sha256(parsed['organization']).hexdigest(),
                'group_sha256': hashlib.sha256(parsed['group']).hexdigest(),
                'serial_hex': parsed['serial'].hex(),
                'not_before_unix': parsed['not_before'],
                'not_after_unix': parsed['not_after'],
            }
        key_rows = {key: {
            'public_key_sha256': self._spki_digest(value.public_key())}
            for key, value in key_map.items()}
        return cohort_root, rows, key_rows, issuer_keys, holder_keys

    @staticmethod
    def _spki_digest(public_key):
        return hashlib.sha256(public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()

    def test_independent_cohort_import_parses_all_der_and_imports_all_keys(self):
        cohort_root, rows, key_rows, _, _ = self._real_import_fixture()
        evidence = verifier._verify_cohort_import(
            cohort_root, rows, key_rows, set(), 'a' * 64, 'b' * 64,
            frozen_at_unix_ns=100)
        self.assertEqual(evidence['counts'], {
            'issuer_keys': 4, 'holder_keys': 8, 'certificates': 8})
        self.assertEqual([row['variant'] for row in evidence['certificates']], list(range(8)))
        self.assertTrue(all(row['issuer_signature_verified'] for row in evidence['certificates']))
        self.assertEqual(evidence['creation_time_basis'], 'cohort and key-generation receipt claims only')
        self.assertEqual(evidence['openssl_route_basis'],
                         'freeze-pinned source and receipt encoder labels; invocation not independently observed')
        negative = evidence['local_negative_admission']
        self.assertEqual(negative['scope'], 'local_admission_only')
        self.assertFalse(negative['loaded_execute_observed'])
        self.assertFalse(negative['changed_policy_allowlist_tested'])
        self.assertEqual(negative['counts'], {
            'certificates': 8,
            'malformed_der_rejections': 8,
            'wrong_issuer_key_rejections': 8,
            'tampered_signed_organization_rejections': 8,
        })
        self.assertEqual([row['variant'] for row in negative['certificates']], list(range(8)))
        for row in negative['certificates']:
            self.assertEqual(row['malformed_der']['error_category'], 'der_content_exceeds_parent')
            self.assertIn(row['wrong_issuer_key']['error_category'], {
                'rsa_signature_verification_failed', 'noncanonical_rsa_signature'})
            self.assertEqual(row['tampered_signed_organization']['error_category'],
                             'rsa_signature_verification_failed')
            self.assertTrue(row['tampered_signed_organization']['structurally_parseable'])
            self.assertNotEqual(row['malformed_der']['der_sha256'], row['credential_sha256'])
            self.assertNotEqual(row['tampered_signed_organization']['der_sha256'],
                                row['credential_sha256'])
            for case in row.values():
                if isinstance(case, dict):
                    for key, value in case.items():
                        if key.endswith('_sha256'):
                            self.assertRegex(value, r'^[0-9a-f]{64}$')
        serialized = json.dumps(evidence)
        for path in cohort_root.rglob('*'):
            if path.is_file() and path.suffix == '.pem':
                self.assertNotIn(path.read_text(), serialized)
            if path.is_file() and path.suffix == '.der':
                self.assertNotIn(path.read_bytes().hex(), serialized)

    def test_independent_cohort_import_rejects_der_and_key_receipt_mismatch(self):
        cohort_root, rows, key_rows, issuer_keys, _ = self._real_import_fixture('key-mismatch')
        cert_path = cohort_root / 'certificate-03' / 'credential.der'
        cert_path.write_bytes(cert_path.read_bytes()[:-1] + b'\x00')
        with self.assertRaisesRegex(ValueError, 'artifact SHA-256 pin mismatch'):
            verifier._verify_cohort_import(
                cohort_root, rows, key_rows, set(), 'a' * 64, 'b' * 64,
                frozen_at_unix_ns=100)

        cohort_root, rows, key_rows, issuer_keys, _ = self._real_import_fixture('prior-key')
        with self.assertRaisesRegex(ValueError, 'absent from prior inventory'):
            verifier._verify_cohort_import(
                cohort_root, rows, key_rows,
                {key_rows[('issuer', 0)]['public_key_sha256']},
                'a' * 64, 'b' * 64, frozen_at_unix_ns=100)

        cohort_root, rows, key_rows, issuer_keys, _ = self._real_import_fixture('key-mismatch-2')
        pem_path = cohort_root / 'keys' / 'issuer-0.pem'
        pem_path.write_bytes(issuer_keys[1].private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        pem_path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'imported key differs from pinned generation receipt'):
            verifier._verify_cohort_import(
                cohort_root, rows, key_rows, set(), 'a' * 64, 'b' * 64,
                frozen_at_unix_ns=100)

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
        runner_path = str(verifier.ROOT / verifier.QUEUE_RUNNER_REL)
        globals_['frozen_bundles'] = {'registry': [{
            'path': verifier.QUEUE_RUNNER_REL,
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

    def test_current_head_evidence_is_derived_from_signed_history_and_finalized_bytes(self):
        root = '11' * 32
        source_digest = '22' * 32
        publisher_digest = '33' * 32
        history_sha = '44' * 32
        report_sha = '55' * 32
        history = {'checkpoints': [{'source': {'observation': {'sequence': 2}},
                                    'publisher': {
                                        'root': list(bytes.fromhex(root)),
                                        'root_version': 1,
                                        'source_head': {'sequence': 2,
                                                        'digest': list(bytes.fromhex(source_digest))},
                                        'publication_sequence': 2,
                                        'publisher_key': list(bytes([0x66]) * 32),
                                        'previous_publication_digest': list(bytes(32))}}]}
        chain = {'source_sha256': source_digest,
                 'publisher_sha256': publisher_digest}
        head = bytearray(280)
        head[:8] = b'DYNHEAD3'
        head[72:104] = bytes([0x66]) * 32
        head[104:112] = (2).to_bytes(8, 'big')
        head[112:144] = bytes.fromhex(publisher_digest)
        head[144:176] = bytes(32)
        head[176:208] = bytes.fromhex(root)
        head[208:216] = (1).to_bytes(8, 'big')
        head[216:224] = (2).to_bytes(8, 'big')
        head[224:256] = bytes.fromhex(source_digest)
        config = bytearray(381)
        config[:8] = b'DYNCONF3'
        config[332:364] = bytes.fromhex(root)
        config[364:372] = (1).to_bytes(8, 'big')
        accounts = {'head': bytes(head), 'config': bytes(config)}
        report = {'source_head_digest': source_digest,
                  'publisher_envelope_digest': publisher_digest}

        evidence = verifier._derive_current_head_evidence(
            history=history, history_sha256=history_sha, chain=chain,
            accounts=accounts, expected_root=root, report=report,
            report_sha256=report_sha, label='R1')

        self.assertEqual(evidence['root'], root)
        self.assertEqual(evidence['root_version'], 1)
        self.assertEqual(evidence['source_sequence'], 2)
        self.assertEqual(evidence['source_digest'], source_digest)
        self.assertEqual(evidence['publisher_sequence'], 2)
        self.assertEqual(evidence['publisher_digest'], publisher_digest)
        self.assertEqual(evidence['history_sha256'], history_sha)
        self.assertEqual(evidence['report_sha256'], report_sha)
        self.assertEqual(evidence['finalized_head_account_sha256'],
                         hashlib.sha256(bytes(head)).hexdigest())
        self.assertFalse(evidence['independent_production_freshness'])

    def test_current_head_evidence_rejects_mutated_finalized_head_fields(self):
        root = '11' * 32
        source_digest = '22' * 32
        publisher_digest = '33' * 32
        history = {'checkpoints': [{'source': {'observation': {'sequence': 2}},
                                    'publisher': {
                                        'root': list(bytes.fromhex(root)),
                                        'root_version': 1,
                                        'source_head': {'sequence': 2,
                                                        'digest': list(bytes.fromhex(source_digest))},
                                        'publication_sequence': 2,
                                        'publisher_key': list(bytes([0x66]) * 32),
                                        'previous_publication_digest': list(bytes(32))}}]}
        chain = {'source_sha256': source_digest,
                 'publisher_sha256': publisher_digest}
        head = bytearray(280)
        head[:8] = b'DYNHEAD3'
        head[72:104] = bytes([0x66]) * 32
        head[104:112] = (2).to_bytes(8, 'big')
        head[112:144] = bytes.fromhex(publisher_digest)
        head[144:176] = bytes(32)
        head[176:208] = bytes.fromhex(root)
        head[208:216] = (1).to_bytes(8, 'big')
        head[216:224] = (2).to_bytes(8, 'big')
        head[224:256] = bytes.fromhex(source_digest)
        config = bytearray(381)
        config[:8] = b'DYNCONF3'
        config[332:364] = bytes.fromhex(root)
        config[364:372] = (1).to_bytes(8, 'big')
        report = {'source_head_digest': source_digest,
                  'publisher_envelope_digest': publisher_digest}

        mutations = (
            ('head root version', 'head', 208, b'\x02'),
            ('head publisher sequence', 'head', 104, b'\x03'),
            ('head source sequence', 'head', 216, b'\x03'),
            ('head source digest', 'head', 224, b'\x99'),
            ('head publisher digest', 'head', 112, b'\x99'),
            ('head publisher identity', 'head', 72, b'\x99'),
            ('config root version', 'config', 364, b'\x02'),
            ('config root', 'config', 332, b'\x99'),
        )
        for label, account_name, offset, replacement in mutations:
            with self.subTest(field=label):
                mutated = bytearray(head if account_name == 'head' else config)
                mutated[offset:offset + len(replacement)] = replacement
                accounts = {'head': bytes(head), 'config': bytes(config)}
                accounts[account_name] = bytes(mutated)
                with self.assertRaises(ValueError):
                    verifier._derive_current_head_evidence(
                        history=history, history_sha256='44' * 32, chain=chain,
                        accounts=accounts,
                        expected_root=root, report=report,
                        report_sha256='55' * 32, label='R1')

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
        evidence = result['cohort_import_evidence']
        self.assertEqual(evidence['cohort_receipt_sha256'], cohort_ref['sha256'])
        self.assertEqual(evidence['counts']['certificates'], 8)
        self.assertEqual(evidence['creation_time_basis'],
                         'cohort and key-generation receipt claims only')

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
            {'scenario': 'v3-execute-readonly-request', 'customError': 711,
             'err': {'InstructionError': [1, {'Custom': 711}]}},
            {'scenario': 'v3-execute-missing-final-account', 'customError': 709,
             'err': {'InstructionError': [1, {'Custom': 709}]}},
            {'scenario': 'v3-execute-system-program-as-issuer', 'customError': 710,
             'err': {'InstructionError': [1, {'Custom': 710}]}},
            {'scenario': 'v3-execute-wrong-account-order', 'customError': 701,
             'err': {'InstructionError': [1, {'Custom': 701}]}},
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
        rows[6]['err'] = {'InstructionError': [1, {'Custom': 710}]}
        with self.assertRaisesRegex(ValueError, 'Full A transaction error mismatch'):
            verifier._verify_full_transactions(rows, snapshots)
        rows[6]['err'] = {'InstructionError': [1, {'Custom': 711}]}
        rows[2]['err'] = {'InstructionError': [1, {'Custom': 714}]}
        with self.assertRaisesRegex(ValueError, 'Full A transaction error mismatch'):
            verifier._verify_full_transactions(rows, snapshots)
        rows[2]['err'] = {'InstructionError': [1, {'Custom': 713}]}
        rows[7]['err'] = {'InstructionError': [1, {'Custom': 710}]}
        with self.assertRaisesRegex(ValueError, 'Full A transaction error mismatch'):
            verifier._verify_full_transactions(rows, snapshots)
        rows[7]['err'] = {'InstructionError': [1, {'Custom': 709}]}
        rows[8]['err'] = {'InstructionError': [1, {'Custom': 709}]}
        with self.assertRaisesRegex(ValueError, 'Full A transaction error mismatch'):
            verifier._verify_full_transactions(rows, snapshots)
        rows[8]['err'] = {'InstructionError': [1, {'Custom': 710}]}
        rows[9]['err'] = {'InstructionError': [1, {'Custom': 709}]}
        with self.assertRaisesRegex(ValueError, 'Full A transaction error mismatch'):
            verifier._verify_full_transactions(rows, snapshots)
        rows[9]['err'] = {'InstructionError': [1, {'Custom': 701}]}
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

    def test_current_r2_witness_receipt_rejects_generic_failure(self):
        receipt = {'schema': 'part5-v3-r2-active-witness-rejection-v1',
                   'outcome': 'generator_failed'}
        with mock.patch.object(verifier, '_json', return_value=(receipt, 'a' * 64)):
            with self.assertRaisesRegex(ValueError, 'separate generator and R1CS outcomes'):
                verifier._verify_current_r2_witness_rejection(
                    {'path': '/unused/receipt.json', 'sha256': 'a' * 64}, {}, {}, {}, {})

    def test_current_r2_witness_receipt_rejects_old_r1_proof_rejection_only(self):
        receipt = {'schema': 'part5-v3-r2-active-witness-rejection-v1',
                   'outcome': 'old_r1_proof_rejected_at_r2'}
        with mock.patch.object(verifier, '_json', return_value=(receipt, 'b' * 64)):
            with self.assertRaisesRegex(ValueError, 'separate generator and R1CS outcomes'):
                verifier._verify_current_r2_witness_rejection(
                    {'path': '/unused/receipt.json', 'sha256': 'b' * 64}, {}, {}, {}, {})

    def test_current_r2_receipt_requires_independent_generator_and_relation_supervisors(self):
        receipt = {'schema': 'part5-v3-r2-active-witness-rejection-v1',
                   'outcome': 'generator_rejected_plus_counterfactual_r1cs_unsatisfied',
                   'generator_attempt': {'exit_code': 1}}
        with mock.patch.object(verifier, '_json', return_value=(receipt, 'c' * 64)):
            with self.assertRaisesRegex(ValueError, 'separate generator and R1CS outcomes'):
                verifier._verify_current_r2_witness_rejection(
                    {'path': '/unused/receipt.json', 'sha256': 'c' * 64}, {}, {}, {}, {})

    def test_current_r2_receipt_accepts_only_cross_pinned_counterfactual_row(self):
        def write(path, raw):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o600)
            return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}

        def json_ref(name, value):
            return write(self.root / name, verifier._canonical_json(value))

        r1_root, r2_root = f'{1:064x}', f'{2:064x}'
        action_hash = f'{8:064x}'
        own_siblings = [40 + index for index in range(10)]
        base_input = {'root': str(int(r1_root, 16)),
                      'siblings': [str(3 + index) for index in range(10)],
                      'issuerHash': '4', 'notBefore': '5', 'notAfter': '6',
                      'actionHash': str(int(action_hash, 16)), 'policyHash': '9'}
        candidate_input = dict(base_input, root=str(int(r2_root, 16)),
                               siblings=[str(value) for value in own_siblings])
        base_input_ref = json_ref('base-input.json', base_input)
        candidate_input_ref = json_ref('candidate-input.json', candidate_input)

        coordinates = list(range(1, 752))
        coordinates_raw = b''.join(value.to_bytes(4, 'little') for value in coordinates)
        coordinates_ref = write(self.root / 'input-coordinates.bin', coordinates_raw)
        values = [0] * 784796
        values[0] = 1
        values[1:7] = [int(base_input[name]) for name in (
            'root', 'issuerHash', 'notBefore', 'notAfter', 'actionHash', 'policyHash')]
        for index, wire in enumerate(coordinates[731:741]):
            values[wire] = int(base_input['siblings'][index])

        def wtns_bytes(assignment):
            fr = 21888242871839275222246405745257275088548364400416034343698204186575808495617
            header = ((32).to_bytes(4, 'little') + fr.to_bytes(32, 'little')
                      + len(assignment).to_bytes(4, 'little'))
            section1 = (1).to_bytes(4, 'little') + len(header).to_bytes(8, 'little') + header
            data = b''.join(value.to_bytes(32, 'little') for value in assignment)
            section2 = (2).to_bytes(4, 'little') + len(data).to_bytes(8, 'little') + data
            return b'wtns' + (2).to_bytes(4, 'little') + (2).to_bytes(4, 'little') + section1 + section2

        base_witness_ref = write(self.root / 'base.wtns', wtns_bytes(values))
        patched_values = list(values)
        patched_values[1] = int(r2_root, 16)
        for index, wire in enumerate(coordinates[731:741]):
            patched_values[wire] = own_siblings[index]
        patched_witness_ref = write(self.root / 'patched.wtns', wtns_bytes(patched_values))
        receipt_hashes = {
            'candidate_input_sha256': candidate_input_ref['sha256'],
            'witness_sha256': patched_witness_ref['sha256'],
            'base_r1_witness_sha256': base_witness_ref['sha256'],
            'r1cs_sha256': 'e' * 64,
            'relation_checker_sha256': 'd' * 64,
        }
        relation_result = {
            'schema': 'part5-v3-r2-active-witness-r1cs-result-v1',
            'status': 'unsatisfied', 'scan': 'first_unsatisfied_row',
            'constraint_row': 73,
            'expected_public': [candidate_input[name] for name in (
                'root', 'issuerHash', 'notBefore', 'notAfter', 'actionHash', 'policyHash')],
            **receipt_hashes,
        }
        result_ref = json_ref('r1cs-result.json', relation_result)
        witness_limits = {'runtime_seconds': 300, 'rss_bytes': 4 * 1024**3,
                          'storage_bytes': 512 * 1024**2}
        relation_limits = {'runtime_seconds': 600, 'rss_bytes': 4 * 1024**3,
                           'storage_bytes': 512 * 1024**2}

        def outer_ref(name, exit_code, limits):
            outer = {'schema': 1, 'passed': exit_code == 0, 'exit_code': exit_code,
                     'stop_reason': None, 'runner_error_type': None,
                     'cleanup_remaining_owned_processes': 0,
                     'cleanup_status_unknown': False,
                     'duration_seconds': 1.0, 'sample_count': 1,
                     'limits': {'runtime_seconds': limits['runtime_seconds'],
                                'owned_tree_rss_bytes': limits['rss_bytes'],
                                'storage_growth_bytes': limits['storage_bytes'],
                                'poll_seconds': verifier.PROOF_POLL_SECONDS}}
            outer['owner'] = name.replace('.json', '-owner')
            return json_ref(name, outer)

        generator_ref = outer_ref('generator-outer.json', 2, witness_limits)
        relation_ref = outer_ref('relation-outer.json', 0, relation_limits)
        candidate_dir = self.root / 'candidate'
        candidate_dir.mkdir()
        # Move the candidate artifact into its actual generator input directory.
        candidate_input_ref = write(candidate_dir / 'input.json',
                                    verifier._canonical_json(candidate_input))
        candidate_input_ref['sha256'] = hashlib.sha256(
            verifier._canonical_json(candidate_input)).hexdigest()
        relation_dir = self.root / 'relation'
        relation_dir.mkdir()
        result_ref = json_ref('relation/r1cs-result.json', relation_result)
        generator_monitor = self.root / 'generator-monitor'
        relation_monitor = self.root / 'relation-monitor'
        generator_monitor.mkdir()
        relation_monitor.mkdir()
        generator_argv = ['/frozen/node', '/frozen/witness.cjs', str(candidate_dir)]
        relation_argv = [sys.executable, '-B',
                         str(verifier.ROOT / 'tools/part5/check_v3_r2_counterfactual.py'),
                         '--candidate-input', candidate_input_ref['path'],
                         '--candidate-input-sha256', candidate_input_ref['sha256'],
                         '--witness', str(self.root / 'patched.wtns'),
                         '--witness-sha256', patched_witness_ref['sha256'],
                         '--base-r1-witness', str(self.root / 'base.wtns'),
                         '--base-r1-witness-sha256', base_witness_ref['sha256'],
                         '--r1cs', '/frozen/r1cs', '--r1cs-sha256', 'e' * 64,
                         '--relation-checker', '/frozen/relation.py',
                         '--relation-checker-sha256', 'd' * 64,
                         '--output', result_ref['path']]

        def invocation_ref(path, owner, argv, roots):
            return json_ref(path, {'owner': owner, 'argv': argv, 'cwd': str(verifier.ROOT),
                                   'started_at_utc': '2026-10-17T12:00:00Z',
                                   'storage_roots': roots})

        generator_invocation_ref = invocation_ref(
            'generator-monitor/invocation.json', 'generator-outer-owner', generator_argv,
            [str(generator_monitor), str(candidate_dir)])
        relation_invocation_ref = invocation_ref(
            'relation-monitor/invocation.json', 'relation-outer-owner', relation_argv,
            [str(relation_monitor), str(relation_dir)])
        receipt = {
            'schema': 'part5-v3-r2-active-witness-rejection-v1',
            'outcome': 'generator_rejected_plus_counterfactual_r1cs_unsatisfied',
            'r2_root': r2_root, 'base_r1_root': r1_root,
            'own_revoked_siblings_sha256': verifier._sha(verifier._canonical_json(own_siblings)),
            'base_r1_input_sha256': base_input_ref['sha256'],
            'candidate_input_sha256': candidate_input_ref['sha256'],
            'base_r1_input_ref': base_input_ref,
            'candidate_input_ref': candidate_input_ref,
            'generator_invocation_ref': generator_invocation_ref,
            'relation_invocation_ref': relation_invocation_ref,
            'input_coordinates_ref': coordinates_ref,
            'input_coordinates_sha256': coordinates_ref['sha256'],
            'target_credential_sha256': 'a' * 64, 'target_tbs_sha256': 'b' * 64,
            'action_hash': action_hash, 'witness_generator_sha256': 'g' * 64,
            'relation_checker_sha256': 'd' * 64, 'r1cs_sha256': 'e' * 64,
            'bounded_supervisor_sha256': 'f' * 64,
            'generator_attempt': {'exit_code': 2, 'output_wtns_present': False,
                                  'input_sha256': candidate_input_ref['sha256'],
                                  'supervisor_ref': generator_ref,
                                  'supervisor_limits': witness_limits},
            'counterfactual_assignment': {
                'label': 'counterfactual_r1_wtns_with_r2_public_root_and_revoked_siblings',
                'base_r1_witness_ref': base_witness_ref,
                'base_r1_witness_sha256': base_witness_ref['sha256'],
                'patched_witness_ref': patched_witness_ref,
                'patched_witness_sha256': patched_witness_ref['sha256']},
            'r1cs_result': relation_result, 'r1cs_result_ref': result_ref,
            'relation_supervisor': {'ref': relation_ref, 'limits': relation_limits,
                                    'exit_code': 0},
        }
        receipt_ref = json_ref('receipt.json', receipt)
        case = {'roots': {'R1': r1_root, 'R2': r2_root},
                'membership': {'own_revoked_siblings': own_siblings},
                'target': {'credential_sha256': 'a' * 64, 'tbs_sha256': 'b' * 64}}
        slot_data = {'r1_input': base_input,
                     'r1_input_sha256': base_input_ref['sha256'],
                     'r1': {'action_hash': action_hash}}
        globals_ = {
            'freeze': {'identities': {'witness_executable': 'c' * 64, 'r1cs': 'e' * 64}},
            'proof_inputs': {'witness_js': 'g' * 64, 'relation_checker': 'd' * 64,
                             'bounded_supervisor': 'f' * 64},
            'proof_input_paths': {'node': Path('/frozen/node'),
                                  'witness_js': Path('/frozen/witness.cjs'),
                                  'relation_checker': Path('/frozen/relation.py')},
            'frozen_paths': {'r1cs': Path('/frozen/r1cs')},
            'packet_template': {'input_map_sha256': coordinates_ref['sha256']},
        }
        result = verifier._verify_current_r2_witness_rejection(
            receipt_ref, case, globals_, slot_data,
            {'artifacts': {'near/output.wtns': base_witness_ref}})
        self.assertEqual(result['r1cs_constraint_row'], 73)
        self.assertEqual(result['generator_output_absence_scope'],
                         'present-time only; not historical proof')

        bad_invocation = {'owner': 'generator-outer-owner', 'argv': generator_argv[:-1]
                          + ['/wrong/candidate'], 'cwd': str(verifier.ROOT),
                          'started_at_utc': '2026-10-17T12:00:00Z',
                          'storage_roots': [str(generator_monitor), str(candidate_dir)]}
        receipt['generator_invocation_ref'] = json_ref(
            'generator-monitor/invocation.json', bad_invocation)
        receipt_ref = json_ref('receipt.json', receipt)
        with self.assertRaisesRegex(ValueError, 'exact argv, cwd, owner, and storage roots'):
            verifier._verify_current_r2_witness_rejection(
                receipt_ref, case, globals_, slot_data,
                {'artifacts': {'near/output.wtns': base_witness_ref}})

        receipt['r2_root'] = r1_root
        receipt['generator_invocation_ref'] = generator_invocation_ref
        receipt_ref = json_ref('receipt.json', receipt)
        with self.assertRaisesRegex(ValueError, 'membership, target, and C action'):
            verifier._verify_current_r2_witness_rejection(
                receipt_ref, case, globals_, slot_data,
                {'artifacts': {'near/output.wtns': base_witness_ref}})

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
