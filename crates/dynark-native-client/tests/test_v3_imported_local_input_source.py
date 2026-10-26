"""Cheap source-boundary checks only; Rust behavior tests require a later build slot."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ImportedLocalInputSourceTests(unittest.TestCase):
    def test_builder_requires_imported_credential_setup_and_explicit_untrusted_path(self):
        source = (ROOT / 'src/v3_input_worker.rs').read_text()
        self.assertTrue('pub fn from_imported_local(' in source, 'pub fn from_imported_local(')
        self.assertTrue('credential: &ImportedV3Credential' in source, 'credential: &ImportedV3Credential')
        self.assertTrue('setup: &V3SharedSetup' in source, 'setup: &V3SharedSetup')
        self.assertTrue('path: &V3UntrustedLocalPath' in source, 'path: &V3UntrustedLocalPath')
        self.assertTrue('setup.manifest().check_identity(' in source, 'setup.manifest().check_identity(')
        self.assertTrue('credential.certificate_der()' in source, 'credential.certificate_der()')
        self.assertTrue('accounts.check(' in source, 'accounts.check(')
        self.assertTrue('V3InputWorkerRequest::from_wire(&wire, summary)' in source, 'V3InputWorkerRequest::from_wire(&wire, summary)')

    def test_builder_does_not_open_the_authority_or_proof_gate(self):
        source = (ROOT / 'src/v3_input_worker.rs').read_text()
        self.assertNotRegex(source, r'impl\s+AuthenticatedV3State\s+for')
        self.assertNotIn('ValidatedAssignment', source)
        self.assertNotIn('dynark_bn254::prove(', source)
        admission = (ROOT / 'src/v3_admission.rs').read_text()
        self.assertTrue(re.search(r'pub\(crate\) fn certificate_der\(&self\) -> &\[u8\]', admission), 'DER accessor must be crate-private')


if __name__ == '__main__':
    unittest.main()
