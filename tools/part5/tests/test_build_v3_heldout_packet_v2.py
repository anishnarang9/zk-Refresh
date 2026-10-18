import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.part5 import build_v3_heldout_packet_v2 as tool


class HeldoutPacketV2Tests(unittest.TestCase):
    def test_source_identity_matches_the_rust_v2_closure(self):
        files = [
            ('main.rs', 'src/main.rs'),
            ('artifacts.rs', 'src/artifacts.rs'),
            ('context.rs', 'src/context.rs'),
            ('ordinary.rs', 'src/ordinary.rs'),
            ('pins.rs', 'src/pins.rs'),
            ('Cargo.lock', 'Cargo.lock'),
            ('Cargo.toml', 'Cargo.toml'),
        ]
        repo = Path(__file__).resolve().parents[3]
        runner = repo / 'circuits/credential-v3-bounded/qualification/proof-runner-v2'
        digest = hashlib.sha256(b'dynark-v3-proof/source-closure/v2')
        for name, relative in files:
            data = (runner / relative).read_bytes()
            digest.update(len(name).to_bytes(4, 'big'))
            digest.update(name.encode())
            digest.update(len(data).to_bytes(8, 'big'))
            digest.update(data)
        self.assertEqual(tool.SOURCE_FILES, files)
        self.assertEqual(tool.proof_source_identity(repo), digest.hexdigest())

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.root.chmod(0o700)
        self.source = self.root / tool.SOURCE
        self.source.mkdir(parents=True)
        for name, relative in tool.SOURCE_FILES:
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((name + "\n").encode())
        self.expected_source = self.independent_source_identity()
        self.package_dir = self.root / "docs/dynark/part5"
        self.package_dir.mkdir(parents=True)
        self.package_path = self.package_dir / Path(tool.PACKAGE_PINS_RELATIVE).name
        self.setup_path = self.root / "artifacts/setup/setup-manifest.json"
        self.check_path = self.root / "artifacts/package/package-check-report.json"
        self.input_map_path = self.root / "private/input-map.json"
        self.template_path = self.root / "private/template.json"
        self.template_path.parent.mkdir(mode=0o700)
        self.template = {
            "package_digest": "a" * 64,
            "setup_manifest_path": str(self.setup_path),
            "setup_manifest_sha256": "b" * 64,
            "package_check_path": str(self.check_path),
            "package_check_sha256": "c" * 64,
            "r1cs_path": str(self.root / "compiled/credential.r1cs"),
            "wasm_path": str(self.root / "compiled/credential_js/credential.wasm"),
            "profile_path": str(self.root / "circuits/profile.json"),
            "input_map_path": str(self.input_map_path),
            "input_map_sha256": "d" * 64,
        }
        self.save(self.template_path, self.template)
        self.package_record = {
            "schema": "part5-v3-fresh-package-output-pins-v2",
            "source_commit": "0" * 40,
            "input_pins": {},
            "ordinary_vk": {},
            "proving_key": {},
            "setup_launcher": {},
            "semantic_hashes": {},
            "census": {},
            "ordered_public_inputs": [],
            "package_identity": {
                "matrix": "1" * 64, "circuit": "2" * 64,
                "pk": "3" * 64, "engine_extended_vk": "4" * 64,
                "package": self.template["package_digest"],
            },
            "setup_manifest": {"path": "artifacts/setup/setup-manifest.json",
                                "sha256": self.template["setup_manifest_sha256"]},
            "package_check_report": {"path": "artifacts/package/package-check-report.json",
                                      "sha256": self.template["package_check_sha256"]},
        }
        self.save(self.package_path, self.package_record)
        self.preparer_path = self.root / "tools/prepare_inputs.py"
        self.preparer_path.parent.mkdir()
        self.preparer_path.write_text("# pinned preparer source\n")
        self.preparer_sha = self.sha(self.preparer_path)
        self.freeze_path = self.root / "private/freeze.json"
        self.cases = [self.make_pair("holdout_0")]
        self.freeze = {
            "schema": "credential-v3-frozen-holdout-boundary-v1",
            "frozen_at_unix_ns": 1,
            "setup_manifest_sha256": self.template["setup_manifest_sha256"],
            "package_digest": self.template["package_digest"],
            "proof_binary_sha256": "e" * 64,
            "proof_source_identity": self.expected_source,
            "input_preparer_sha256": self.preparer_sha,
            "client_sha256": "1" * 64,
            "adapter_sha256": "2" * 64,
            "application_source_sha256": "3" * 64,
            "application_elf_sha256": "4" * 64,
        }
        self.save(self.freeze_path, self.freeze)

    def independent_source_identity(self):
        digest = hashlib.sha256(b"dynark-v3-proof/source-closure/v2")
        for name, relative in tool.SOURCE_FILES:
            data = (self.source / relative).read_bytes()
            digest.update(len(name).to_bytes(4, "big"))
            digest.update(name.encode())
            digest.update(len(data).to_bytes(8, "big"))
            digest.update(data)
        return digest.hexdigest()

    def save(self, path, value):
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        path.chmod(0o600)

    @staticmethod
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def make_pair(self, name):
        pair = {"name": name}
        for role in ("base", "near"):
            directory = self.root / "private" / name / role
            directory.mkdir(parents=True, mode=0o700)
            for filename, data in (("output.wtns", b"witness-" + role.encode()),
                                   ("public.json", b'["1","2","3","4","5","6"]'),
                                   ("input.json", b'{"root":"1"}')):
                path = directory / filename
                path.write_bytes(data)
                path.chmod(0o600)
            pair[role] = directory
        return pair

    def build(self):
        return tool.build(
            self.template_path, self.sha(self.template_path),
            self.freeze_path, self.sha(self.freeze_path), self.cases,
            self.package_path, self.sha(self.package_path), "e" * 64,
            self.preparer_path, self.preparer_sha,
        )

    def test_builds_runner_v2_heldout_packet_from_exact_pins(self):
        with mock.patch.object(tool, "ROOT", self.root):
            packet = self.build()
        self.assertEqual(packet["schema"], "credential-v3-bounded-proof-contexts-v1")
        self.assertEqual(packet["cohort"], "heldout-v1")
        self.assertEqual(packet["proof_source_identity"], self.expected_source)
        self.assertEqual(packet["proof_binary_sha256"], "e" * 64)
        self.assertEqual(packet["package_pins_sha256"], self.sha(self.package_path))
        self.assertEqual(packet["input_preparer_sha256"], self.preparer_sha)
        self.assertEqual(packet["setup_manifest_path"], self.template["setup_manifest_path"])
        self.assertEqual(packet["setup_manifest_sha256"], self.template["setup_manifest_sha256"])
        self.assertEqual(packet["pairs"][0]["name"], "holdout_0")
        self.assertEqual(packet["pairs"][0]["base"]["root_version"], 1)
        self.assertEqual(packet["pairs"][0]["near"]["root_version"], 2)
        self.assertEqual(packet["pairs"][0]["base"]["input_sha256"],
                         self.sha(self.cases[0]["base"] / "input.json"))

    def test_rejects_freeze_from_a_different_v2_source_closure(self):
        self.freeze["proof_source_identity"] = "f" * 64
        self.save(self.freeze_path, self.freeze)
        with mock.patch.object(tool, "ROOT", self.root):
            with self.assertRaisesRegex(ValueError, "freeze identity"):
                self.build()

    def test_rejects_setup_pin_that_differs_from_external_package_record(self):
        self.template["setup_manifest_sha256"] = "f" * 64
        self.save(self.template_path, self.template)
        with mock.patch.object(tool, "ROOT", self.root):
            with self.assertRaisesRegex(ValueError, "differs from packet setup_manifest"):
                self.build()

    def test_rejects_case_inputs_that_postdate_the_freeze_boundary(self):
        self.freeze["frozen_at_unix_ns"] = max(
            (self.cases[0][role] / "input.json").stat().st_ctime_ns
            for role in ("base", "near")) + 1
        self.save(self.freeze_path, self.freeze)
        with mock.patch.object(tool, "ROOT", self.root):
            with self.assertRaisesRegex(ValueError, "follow freeze"):
                self.build()

    def test_rejects_incomplete_or_out_of_range_runner_freeze(self):
        del self.freeze["application_elf_sha256"]
        self.save(self.freeze_path, self.freeze)
        with mock.patch.object(tool, "ROOT", self.root):
            with self.assertRaisesRegex(ValueError, "freeze identity"):
                self.build()
        self.freeze["application_elf_sha256"] = "4" * 64
        self.freeze["frozen_at_unix_ns"] = 2**64
        self.save(self.freeze_path, self.freeze)
        with mock.patch.object(tool, "ROOT", self.root):
            with self.assertRaisesRegex(ValueError, "freeze identity"):
                self.build()

    def test_rejects_external_package_record_mode_runner_would_reject(self):
        self.package_path.chmod(0o640)
        with mock.patch.object(tool, "ROOT", self.root):
            with self.assertRaisesRegex(ValueError, "package-pins record"):
                self.build()


if __name__ == "__main__":
    unittest.main()
