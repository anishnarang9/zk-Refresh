"""Source contract only; Rust behavior verification needs the serialized build slot."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ConstructorSourceTests(unittest.TestCase):
    def test_public_constructor_uses_only_fixed_private_factory(self):
        source = (ROOT / "src/lib.rs").read_text()
        self.assertTrue("pub fn new(pins: DeploymentPins)" in source, "configured constructor missing")
        self.assertTrue("loopback_http::configured_transport(&pins.endpoint)?" in source,
                        "constructor must select the fixed loopback transport")
        self.assertNotRegex(source, r"pub (?:trait Transport|struct FinalizedBatch|struct Account)")

    def test_private_factory_preserves_private_type_and_exact_endpoint_validation(self):
        source = (ROOT / "src/loopback_http.rs").read_text()
        self.assertTrue("pub(super) fn configured_transport(" in source, "parent-private factory missing")
        self.assertTrue("Box::new(LoopbackRpc::new(endpoint)?)" in source, "fixed implementation required")
        self.assertNotRegex(source, r"pub(?:\([^)]*\))? struct LoopbackRpc")
        self.assertTrue('strip_prefix("http://127.0.0.1:")' in source)
        self.assertTrue("text!=port.to_string()" in source)
        self.assertTrue(".no_proxy()" in source)
        self.assertTrue(".redirect(reqwest::redirect::Policy::none())" in source)


if __name__ == "__main__":
    unittest.main()
