import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.part5 import prepare_v3_heldout_proof as tool


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


class HeldoutProofTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.r0 = self.root / 'r0'
        self.r1 = self.root / 'r1'
        for path in (self.r0, self.r1):
            path.mkdir(mode=0o700)
        self.freeze_sha = 'f' * 64
        self.stage_sha = 'a' * 64
        self.plan_sha = 'b' * 64
        self.cohort_sha = 'c' * 64
        self.case_sha = 'd' * 64
        self.pair_sha = 'e' * 64
        self.roots = {'R0': '1' * 64, 'R1': '2' * 64, 'R2': '3' * 64}
        self.action = '4' * 64
        self.request = b'DYNREQ03' + b'r' * 2241
        self.f1 = {name: b'V3F1' + bytes([index]) * (2870)
                   for index, name in enumerate(('R0', 'R1'), start=1)}
        self.f1['R0'] = self.f1['R0'][:625] + self.request
        self.f1['R1'] = self.f1['R1'][:625] + self.request
        self.f2 = b'V3F2' + bytes(160) + bytes.fromhex(self.action) + bytes(365)
        self.r0_receipt, self.r0_sha = self.source(self.r0, 'R0')
        self.r1_receipt, self.r1_sha = self.source(self.r1, 'R1', self.r0_sha)

    @staticmethod
    def write(path, raw):
        path.write_bytes(raw)
        path.chmod(0o600)
        return raw

    def source(self, root, variant, r0_sha=None):
        helper_artifacts = {
            'request.bin': b'V3Q1' + b'q' * 1914,
            'summary.bin': b's' * 459,
            'input.json': encoded({'root': str(int(self.roots[variant], 16)),
                                   'actionHash': str(int(self.action, 16))}),
            'public.json': encoded([str(int(self.roots[variant], 16)), '10', '20', '30',
                                    str(int(self.action, 16)), '40']),
            'input-coordinates.bin': b'c' * 3004,
            'internal-coordinate.bin': b'i' * 4,
        }
        training = {
            'schema': 'v3-request-bound-training-input-v1', 'training_only': True,
            'live_state_authenticated': False, 'proof_created': False,
            'artifact_sha256': {name: sha(raw) for name, raw in helper_artifacts.items()
                                if name in ('request.bin', 'input.json', 'public.json')},
        }
        training_raw = encoded(training)
        artifacts = {**helper_artifacts, 'training-receipt.json': training_raw,
                     'staged-request.bin': self.request,
                     'finalized-request.bin': self.f1[variant],
                     'action-transport.bin': self.f2}
        artifact_hashes = {}
        for name, raw in artifacts.items():
            self.write(root / name, raw)
            artifact_hashes[name] = sha(raw)
        receipt = {
            'schema': 'credential-v3-heldout-request-source-v1',
            'freeze_sha256': self.freeze_sha, 'cohort_receipt_sha256': self.cohort_sha,
            'case_context_sha256': self.case_sha, 'pair_receipt_sha256': self.pair_sha,
            'target_variant': 2, 'issuer_index': 0, 'holder_index': 2,
            'case_index': 2, 'unrelated_variant': 3,
            'target_der_sha256': '5' * 64, 'target_tbs_sha256': '6' * 64,
            'unrelated_der_sha256': '7' * 64,
            'issuer_public_key_sha256': '8' * 64, 'holder_public_key_sha256': '9' * 64,
            'variant': variant, 'stage_report_sha256': self.stage_sha,
            'stage_plan_sha256': self.plan_sha,
            'transition_report_sha256': None if variant == 'R0' else 'a' * 64,
            'transition_context_sha256': None if variant == 'R0' else 'b' * 64,
            'context_sha256': self.case_sha, 'stage_context_sha256': 'b' * 64,
            'membership_sha256': self.pair_sha, 'membership_roots': self.roots,
            'selected_root': self.roots[variant],
            'staged_request_sha256': sha(self.request),
            'finalized_request_sha256': sha(self.f1[variant]),
            'finalized_action_transport_sha256': sha(self.f2),
            'action_hash': self.action, 'exporter_sha256': 'a' * 64,
            'training_helper_sha256': 'b' * 64,
            'training_receipt_sha256': sha(training_raw),
            'artifacts_sha256': artifact_hashes,
            'proof_created': False, 'application_effect': False,
            'live_state_authenticated': False,
        }
        if variant == 'R1':
            receipt['r0_source_receipt_sha256'] = r0_sha
        receipt_raw = encoded(receipt)
        self.write(root / 'source-receipt.json', receipt_raw)
        return receipt, sha(receipt_raw)

    def test_validates_cross_pinned_r0_r1_source_pair(self):
        pair = tool.validate_source_pair(
            self.r0, self.r0_sha, self.r1, self.r1_sha, self.freeze_sha)
        self.assertEqual(pair['R0']['receipt']['selected_root'], self.roots['R0'])
        self.assertEqual(pair['R1']['receipt']['selected_root'], self.roots['R1'])
        self.assertEqual(pair['R0']['receipt']['action_hash'], pair['R1']['receipt']['action_hash'])

    def test_rejects_source_artifact_drift(self):
        (self.r1 / 'action-transport.bin').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'artifact'):
            tool.validate_source_pair(
                self.r0, self.r0_sha, self.r1, self.r1_sha, self.freeze_sha)

    def test_input_directory_guard_allows_output_writes_and_rejects_input_mutation(self):
        stage = self.root / 'stage'
        transition = self.root / 'transition'
        stage.mkdir(mode=0o700)
        transition.mkdir(mode=0o700)
        output = self.root / 'output'
        output.mkdir(mode=0o700)
        inputs = (stage, transition, self.r0, self.r1)
        identities = {path: tool._identity(path.lstat()) for path in inputs}

        (output / 'work').mkdir(mode=0o700)
        (output / 'supervisor').mkdir(mode=0o700)
        tool._assert_input_directories_unchanged(identities)

        (stage / 'unexpected-input').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'input directory changed'):
            tool._assert_input_directories_unchanged(identities)

    def test_requires_exact_proof_counts_and_mode(self):
        stage_pins = {
            'program_id': 'program', 'genesis_hash': 'genesis',
            'loaded_elf_sha256': 'a' * 64, 'base_stage_report_sha256': 'b' * 64,
            'base_config_sha256': 'c' * 64, 'finalized_request_sha256': 'd' * 64,
            'request_address': 'request', 'base_finalized_slot': 40,
            'near_state_report_sha256': 'e' * 64, 'near_config_sha256': 'f' * 64,
            'near_finalized_slot': 50, 'base_root': str(int(self.roots['R0'], 16)),
            'near_root': str(int(self.roots['R1'], 16)),
            'action_hash': str(int(self.action, 16)),
        }
        identities = {'package_digest': 'a' * 64, 'proof_binary_sha256': 'b' * 64,
                      'ordinary_vk_file_sha256': 'c' * 64, 'setup_manifest_sha256': 'd' * 64,
                      'proof_source_identity': 'e' * 64}
        report = {
            'schema': 'credential-v3-matched-k1-proof-v1', 'passed': True,
            'mode': 'matched-full-k1', 'packet_sha256': 'f' * 64,
            'counts': {'proofs': 2, 'positive_checks': 2, 'altered_public_checks': 12,
                       'cross_root_checks': 2, 'ordinary_checks': 16},
            'application_verified': False, 'setup_executed': False,
            'private_cache_persisted': False, 'qualification_extras_executed': False,
            'old_base_full_rejected_at_near_publics': True,
            'application_stage_pins_authority':
                'caller-supplied; external finalized-state verification required',
            'application_stage_pins': stage_pins,
            **identities,
        }
        checked = tool.validate_proof_report(
            report, 'full', 'f' * 64, stage_pins, identities)
        self.assertTrue(checked['passed'])
        report['counts']['ordinary_checks'] = 15
        with self.assertRaisesRegex(ValueError, 'counts'):
            tool.validate_proof_report(report, 'full', 'f' * 64, stage_pins, identities)

    def test_report_binds_all_application_pins_and_frozen_identities(self):
        stage_pins = {'program_id': 'program', 'genesis_hash': 'genesis',
                      'loaded_elf_sha256': 'a' * 64,
                      'base_stage_report_sha256': 'b' * 64,
                      'base_config_sha256': 'c' * 64,
                      'finalized_request_sha256': 'd' * 64,
                      'request_address': 'request', 'base_finalized_slot': 40,
                      'near_state_report_sha256': 'e' * 64, 'near_config_sha256': 'f' * 64,
                      'near_finalized_slot': 50,
                      'base_root': str(int(self.roots['R0'], 16)),
                      'near_root': str(int(self.roots['R1'], 16)),
                      'action_hash': str(int(self.action, 16))}
        identities = {'package_digest': 'a' * 64, 'proof_binary_sha256': 'b' * 64,
                      'ordinary_vk_file_sha256': 'c' * 64, 'setup_manifest_sha256': 'd' * 64,
                      'proof_source_identity': 'e' * 64}
        report = {'schema': 'credential-v3-matched-k1-proof-v1', 'passed': True,
                  'mode': 'matched-anchor-k1', 'packet_sha256': 'f' * 64,
                  'counts': tool.PROOF_COUNTS, 'application_verified': False,
                  'setup_executed': False, 'private_cache_persisted': False,
                  'qualification_extras_executed': False,
                  'old_base_full_rejected_at_near_publics': True,
                  'application_stage_pins_authority':
                      'caller-supplied; external finalized-state verification required',
                  'application_stage_pins': dict(stage_pins), **identities}
        tool.validate_proof_report(report, 'anchor', 'f' * 64, stage_pins, identities)
        report['application_stage_pins']['loaded_elf_sha256'] = '9' * 64
        with self.assertRaisesRegex(ValueError, 'report'):
            tool.validate_proof_report(report, 'anchor', 'f' * 64, stage_pins, identities)

    def test_near_copy_skips_receipt_before_replacement(self):
        pair = tool.validate_source_pair(
            self.r0, self.r0_sha, self.r1, self.r1_sha, self.freeze_sha)
        near = self.root / 'near-copy'
        tool._source_inputs(pair['R1'], near, skip=('training-receipt.json',))
        near_receipt = tool._near_receipt(pair['R0'], pair['R1'])
        tool._write(near / 'training-receipt.json', near_receipt)
        self.assertEqual((near / 'training-receipt.json').read_bytes(), near_receipt)
        self.assertEqual((near / 'request.bin').read_bytes(), pair['R1']['artifacts']['request.bin'])

    def test_matched_proof_names_match_packet_pair_name(self):
        self.assertEqual(tool.matched_proof_names('full'), (
            'request_bound_training_full_base', 'request_bound_training_full_near'))
        self.assertEqual(tool.matched_proof_names('anchor'), (
            'request_bound_training_full_base', 'request_bound_training_anchor_near'))

    def test_node_sha_pin_is_required(self):
        node = self.root / 'node'
        self.write(node, b'node-runtime')
        node.chmod(0o700)
        with self.assertRaisesRegex(ValueError, 'artifact'):
            tool.validate_node_pin(node, '0' * 64)
        self.assertEqual(tool.validate_node_pin(node, sha(b'node-runtime')), node)

    def test_receipt_proof_tool_hash_map_matches_frozen_roles(self):
        product = {name: (str(index) * 64) for index, name in enumerate((
            'packet_template_sha256', 'witness_sha256', 'relation_sha256',
            'node_sha256', 'proof_runner_sha256', 'adapter_sha256',
            'packet_builder_sha256'), start=1)}
        observed = tool.proof_tool_hashes(product, '8' * 64, '9' * 64, 'a' * 64)
        self.assertEqual(set(observed), {
            'packet_template', 'witness_js', 'relation_checker', 'node',
            'proof_runner', 'adapter_binary', 'bounded_supervisor', 'exporter',
            'packet_builder', 'proof_helper'})
        self.assertEqual(observed['node'], product['node_sha256'])

    def test_wire_pins_root_and_action(self):
        wire = bytearray(448)
        wire[:32] = bytes.fromhex(self.roots['R1'])
        wire[128:160] = bytes.fromhex(self.action)
        tool.validate_wire(bytes(wire), self.roots['R1'], self.action)
        with self.assertRaisesRegex(ValueError, 'wire'):
            tool.validate_wire(bytes(wire), self.roots['R0'], self.action)


if __name__ == '__main__':
    unittest.main()
