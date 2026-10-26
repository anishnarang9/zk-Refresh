import unittest

from tools.part5 import prepare_v3_heldout_proof as proof


class R2ActiveWitnessRejectionTests(unittest.TestCase):
    def setUp(self):
        self.action_hash = f'{42:064x}'
        self.base = {
            'root': '2', 'issuerHash': '3', 'notBefore': '4', 'notAfter': '5',
            'actionHash': '42', 'policyHash': '6', 'layout': '0',
            'tbs': ['7'] * 672, 'issuerModulus': ['8'] * 17,
            'issuerSignature': ['9'] * 17, 'holderSignature': ['10'] * 17,
            'slot': '11', 'siblings': [str(x) for x in range(10)],
            'pathIndices': ['0'] * 10,
        }
        self.r2_root = f'{7:064x}'
        self.siblings = list(range(10, 20))
        self.candidate = proof.build_r2_active_witness_input(
            self.base, self.r2_root, self.siblings)
        self.coords = b''.join(i.to_bytes(4, 'little') for i in range(1, 752))
        self.pins = {
            'action_hash': self.action_hash,
            'target_credential_sha256': 'a' * 64,
            'target_tbs_sha256': 'b' * 64,
            'witness_generator_sha256': 'c' * 64,
            'relation_checker_sha256': 'd' * 64,
            'r1cs_sha256': 'e' * 64,
            'bounded_supervisor_sha256': 'f' * 64,
            'generator_supervisor_ref': {'path': '/private/generator-supervisor.json',
                                         'sha256': '1' * 64},
            'generator_invocation_ref': {'path': '/private/generator-monitor/invocation.json',
                                         'sha256': '5' * 64},
            'generator_supervisor_limits': dict(proof.WITNESS_LIMITS),
            'generator_exit_code': 2, 'generated_wtns_present': False,
            'base_input_ref': {'path': '/private/r1-input.json',
                               'sha256': proof.digest(proof.encoded(self.base))},
            'candidate_input_ref': {'path': '/private/r2-input.json',
                                    'sha256': proof.digest(proof.encoded(self.candidate))},
            'input_coordinates_ref': {'path': '/private/input-coordinates.bin',
                                      'sha256': proof.digest(self.coords)},
            'r1_witness_ref': {'path': '/private/r1.wtns', 'sha256': '2' * 64},
            'counterfactual_witness_ref': {'path': '/private/r2-counterfactual.wtns',
                                           'sha256': '3' * 64},
            'relation_supervisor_ref': {'path': '/private/relation-supervisor.json',
                                        'sha256': '4' * 64},
            'relation_invocation_ref': {'path': '/private/relation-monitor/invocation.json',
                                        'sha256': '6' * 64},
            'relation_supervisor_limits': dict(proof.RELATION_LIMITS),
            'relation_exit_code': 0,
        }

    def relation_result(self):
        return {
            'schema': 'part5-v3-r2-active-witness-r1cs-result-v1',
            'status': 'unsatisfied', 'scan': 'first_unsatisfied_row',
            'constraint_row': 793680,
            'expected_public': ['7', '3', '4', '5', '42', '6'],
            'candidate_input_sha256': proof.digest(proof.encoded(self.candidate)),
            'base_r1_witness_sha256': self.pins['r1_witness_ref']['sha256'],
            'witness_sha256': self.pins['counterfactual_witness_ref']['sha256'],
            'r1cs_sha256': self.pins['r1cs_sha256'],
            'relation_checker_sha256': self.pins['relation_checker_sha256'],
        }

    def receipt(self):
        relation_result = self.relation_result()
        return proof.r2_active_witness_rejection_receipt(
            base_input=self.base, candidate_input=self.candidate,
            r2_root=self.r2_root, own_revoked_siblings=self.siblings,
            relation_result=relation_result,
            relation_result_ref={'path': '/private/r1cs-result.json',
                                 'sha256': proof.digest(proof.encoded(relation_result))},
            **self.pins,
        )

    def test_candidate_changes_only_current_root_and_revoked_path(self):
        self.assertEqual(self.candidate['root'], '7')
        self.assertEqual(self.candidate['siblings'], [str(x) for x in self.siblings])
        self.assertEqual({key: value for key, value in self.candidate.items()
                          if key not in ('root', 'siblings')},
                         {key: value for key, value in self.base.items()
                          if key not in ('root', 'siblings')})

    def test_wtns_patch_changes_only_public_root_and_ten_sibling_wires(self):
        header = (b'wtns' + (2).to_bytes(4, 'little') + (2).to_bytes(4, 'little')
                  + (1).to_bytes(4, 'little') + (40).to_bytes(8, 'little')
                  + (32).to_bytes(4, 'little') + proof.FR.to_bytes(32, 'little')
                  + (784796).to_bytes(4, 'little')
                  + (2).to_bytes(4, 'little') + (784796 * 32).to_bytes(8, 'little'))
        assignments = bytearray(784796 * 32)
        assignments[:32] = (1).to_bytes(32, 'little')
        for i in range(1, 7):
            assignments[i * 32:(i + 1) * 32] = (i + 1).to_bytes(32, 'little')
        original = header + bytes(assignments)
        patched = proof.patch_r1_wtns_for_r2_counterfactual(
            original, self.coords, self.r2_root, self.siblings)
        self.assertEqual(len(patched), 25113548)
        self.assertNotEqual(patched, original)
        self.assertEqual(int.from_bytes(patched[header.__len__() + 32:header.__len__() + 64],
                                        'little'), 7)
        wire_start = len(header)
        for coordinate, expected in zip(range(732, 742), self.siblings):
            self.assertEqual(int.from_bytes(patched[wire_start + coordinate * 32:
                                                    wire_start + (coordinate + 1) * 32],
                                            'little'), expected)

    def test_receipt_labels_counterfactual_and_pins_both_bounded_runs(self):
        receipt = self.receipt()
        self.assertEqual(receipt['outcome'],
                         'generator_rejected_plus_counterfactual_r1cs_unsatisfied')
        self.assertEqual(receipt['generator_attempt']['exit_code'], 2)
        self.assertFalse(receipt['generator_attempt']['output_wtns_present'])
        self.assertEqual(receipt['counterfactual_assignment']['label'],
                         'counterfactual_r1_wtns_with_r2_public_root_and_revoked_siblings')
        self.assertEqual(receipt['r1cs_result']['constraint_row'], 793680)
        self.assertEqual(receipt['bounded_supervisor_sha256'], 'f' * 64)

    def test_rejects_generic_failure_or_invalid_r1cs_row(self):
        for change in (
                {'generator_exit_code': 1},
                {'generated_wtns_present': True},
                {'relation_exit_code': 1},
                {'generator_supervisor_limits': {'runtime_seconds': 1}},
        ):
            with self.subTest(change=change):
                kwargs = dict(self.pins)
                kwargs.update(change)
                result = self.relation_result()
                try:
                    proof.r2_active_witness_rejection_receipt(
                        base_input=self.base, candidate_input=self.candidate,
                        r2_root=self.r2_root, own_revoked_siblings=self.siblings,
                        relation_result=result,
                        relation_result_ref={'path': '/private/r1cs-result.json',
                                             'sha256': proof.digest(proof.encoded(result))},
                        **kwargs)
                except ValueError:
                    pass
                else:
                    self.fail('invalid generator or relation outcome was accepted')
        result = self.relation_result()
        result['constraint_row'] = 793681
        kwargs = dict(self.pins)
        with self.assertRaisesRegex(ValueError, 'counterfactual unsatisfied'):
            proof.r2_active_witness_rejection_receipt(
                base_input=self.base, candidate_input=self.candidate,
                r2_root=self.r2_root, own_revoked_siblings=self.siblings,
                relation_result=result,
                relation_result_ref={'path': '/private/r1cs-result.json',
                                     'sha256': proof.digest(proof.encoded(result))},
                **kwargs)


if __name__ == '__main__':
    unittest.main()
