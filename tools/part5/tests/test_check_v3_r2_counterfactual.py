import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.part5 import check_v3_r2_counterfactual as tool


class R2CounterfactualCheckTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()
        os.chmod(self.directory, 0o700)
        self.candidate = self.directory / 'input.json'
        self.witness = self.directory / 'candidate.wtns'
        self.base_r1_witness = self.directory / 'base.wtns'
        self.r1cs = self.directory / 'relation.r1cs'
        public = ['1', '2', '3', '4', '5', '6']
        self.candidate.write_text(json.dumps(dict(zip(tool.PUBLIC_FIELDS, public))))
        self.witness.write_bytes(b'counterfactual fixture')
        self.base_r1_witness.write_bytes(b'base fixture')
        self.r1cs.write_bytes(b'relation fixture')
        for path in (self.candidate, self.witness, self.base_r1_witness):
            os.chmod(path, 0o600)
        self.checker = tool.ROOT / 'crates/dynark-native-client/tests/support/prepare_v3_relation.py'
        self.output = self.directory / 'result.json'

    @staticmethod
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def call(self):
        return tool.check(
            self.candidate, self.digest(self.candidate), self.witness,
            self.digest(self.witness), self.base_r1_witness,
            self.digest(self.base_r1_witness), self.r1cs, self.digest(self.r1cs),
            self.checker, self.digest(self.checker), self.output)

    def test_records_only_a_specific_unsatisfied_relation_row(self):
        with mock.patch.object(tool.witness_check, 'check_witness',
                               side_effect=ValueError('unsatisfied relation row 123')) as check:
            result = self.call()
        check.assert_called_once_with(self.r1cs, self.witness, [1, 2, 3, 4, 5, 6])
        self.assertEqual(result['constraint_row'], 123)
        self.assertEqual(result['scan'], 'first_unsatisfied_row')
        self.assertEqual(json.loads(self.output.read_text()), result)

    def test_generic_failure_and_satisfied_witness_do_not_publish(self):
        for result in (ValueError('WTNS public statement'), None):
            with self.subTest(result=result):
                with mock.patch.object(tool.witness_check, 'check_witness',
                                       side_effect=result):
                    with self.assertRaises(ValueError):
                        self.call()
                self.assertFalse(self.output.exists())

    def test_tampered_witness_pin_does_not_run_checker_or_publish(self):
        with mock.patch.object(tool.witness_check, 'check_witness') as check:
            with self.assertRaisesRegex(ValueError, 'hash or identity differs'):
                tool.check(self.candidate, self.digest(self.candidate),
                           self.witness, '0' * 64,
                           self.base_r1_witness, self.digest(self.base_r1_witness),
                           self.r1cs, self.digest(self.r1cs),
                           self.checker, self.digest(self.checker), self.output)
        check.assert_not_called()
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
