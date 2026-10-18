import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from tools.part5 import heldout_queue_capacity_evidence as evidence


SUPERVISOR_PATH = Path(__file__).with_name("queue_v3_local_queue_capacity_negative.py")
spec = importlib.util.spec_from_file_location(
    "queue_v3_local_queue_capacity_negative", SUPERVISOR_PATH)
supervisor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(supervisor)


class QueueCapacitySupervisorTests(unittest.TestCase):
    def test_cli_failure_does_not_echo_private_paths(self):
        argv = ['capacity', '--config', '/PRIVATE/config.json', '--config-sha256', 'a' * 64]
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(
                supervisor, '_decode_pinned_config', side_effect=ValueError('/PRIVATE/key')):
            with self.assertRaises(SystemExit) as caught:
                supervisor.main()
        self.assertNotIn('PRIVATE', str(caught.exception))

    def make_catalog(self, root):
        rows = []
        for index in range(supervisor.QUEUE_CAPACITY + 1):
            stem = f"request-{index:02d}"
            request = root / f"{stem}.request"
            proof = root / f"{stem}.proof-receipt.json"
            wire = root / f"{stem}.wire"
            request.write_bytes(f"request-bytes-{index}".encode())
            proof.write_text(json.dumps({"receipt": stem}), encoding="utf-8")
            wire.write_bytes(f"wire-bytes-{index}".encode())
            for path in (request, proof, wire):
                path.chmod(0o600)
            rows.append({
                "request_address": stem,
                "action_sha256": hashlib.sha256(f"action-{index}".encode()).hexdigest(),
                "request_account": str(request),
                "request_sha256": hashlib.sha256(request.read_bytes()).hexdigest(),
                "proof_receipt": str(proof),
                "proof_receipt_sha256": hashlib.sha256(proof.read_bytes()).hexdigest(),
                "full_wire": str(wire),
                "full_wire_sha256": hashlib.sha256(wire.read_bytes()).hexdigest(),
            })
        return rows

    def test_input_catalog_requires_65_distinct_pinned_request_proof_wire_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            rows = self.make_catalog(root)
            checked = supervisor._validate_inputs(rows)
            self.assertEqual(len(checked), 65)
            self.assertEqual(len({row["request_address"] for row in checked}), 65)
            self.assertEqual(len({row["action_sha256"] for row in checked}), 65)

            duplicate = json.loads(json.dumps(rows))
            duplicate[64]["request_address"] = duplicate[0]["request_address"]
            with self.assertRaisesRegex(ValueError, "distinct"):
                supervisor._validate_inputs(duplicate)

            bad_wire = json.loads(json.dumps(rows))
            bad_wire[0]["full_wire_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "Full wire.*pin"):
                supervisor._validate_inputs(bad_wire)

    def test_missing_rust_capacity_entrypoint_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            test_source = root / "queue_v3.rs"
            module_source = root / "queue_v3_module.rs"
            test_source.write_text("// unrelated test selector\n", encoding="utf-8")
            module_source.write_text("// no capacity supervisor\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "Rust queue-capacity entrypoint is not integrated"):
                supervisor._require_rust_entrypoint((test_source, module_source))

    def test_integration_failure_status_records_zero_started_processes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            control = root / "control"
            with mock.patch.object(supervisor, "_canonical_child", return_value=control):
                status = supervisor._write_integration_failure(
                    {"control_output": str(control)}, "a" * 64, root / "config.json",
                    RuntimeError("Rust queue-capacity entrypoint is not integrated"))
            persisted = json.loads((control / "status.json").read_text(encoding="utf-8"))
            self.assertEqual(status["status"], "failed")
            self.assertIs(persisted["validator_started"], False)
            self.assertIs(persisted["runner_started"], False)
            self.assertIs(persisted["loaded_execution_established"], False)
            self.assertEqual(persisted["remaining_owned_processes"], 0)

    def test_run_accepts_raw_byte_pinned_config_without_canonical_json_serialization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = root / "config.json"
            raw = (b'{\n  "scope" : "part5-v3-loaded-queue-capacity-negative", '
                   b'"schema": "part5-v3-queue-capacity-negative-supervisor-v1", '
                   b'"control_output": "/tmp/not-used"\n}\n')
            path.write_bytes(raw)
            path.chmod(0o600)
            parsed = {"scope": supervisor.SCOPE, "schema": supervisor.CONFIG_SCHEMA,
                      "control_output": "/tmp/not-used"}
            with (mock.patch.dict(os.environ, {
                    "P5_V3_QUEUE_CAPACITY_NEGATIVE_SCOPE": supervisor.SCOPE}),
                  mock.patch.object(supervisor, "_validate_config") as validate,
                  mock.patch.object(supervisor, "_require_rust_entrypoint",
                                    side_effect=RuntimeError("Rust queue-capacity entrypoint is not integrated")),
                  mock.patch.object(supervisor, "_write_integration_failure")):
                result = supervisor.run(parsed, hashlib.sha256(raw).hexdigest(), path)
            self.assertEqual(result, 2)
            validate.assert_called_once_with(parsed)

    def test_genesis_identity_uses_externally_supplied_genesis_byte_pin(self):
        config = {'cohort_freeze_sha256': 'a' * 64, 'expected_genesis': 'base58-genesis',
                  'expected_genesis_sha256': 'b' * 64, 'expected_elf_sha256': 'c' * 64,
                  'stage_report_sha256': 'd' * 64, 'clone_receipt_sha256': 'e' * 64,
                  'inputs': []}
        self.assertEqual(supervisor._expected_identities(config)['genesis_sha256'], 'b' * 64)

    def test_established_capacity_report_validates_through_both_layers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            inputs = self.make_catalog(root)
            report, config = make_report(root, inputs)
            first = evidence.validate_report(
                report, root / "evidence", supervisor._expected_identities(config))
            second = supervisor._validate_report(report, config, root / "evidence")
            self.assertIs(first["report_consistent"], True)
            self.assertIs(first["loaded_run_established"], False)
            self.assertIs(second["report_consistent"], True)
            self.assertIs(second["loaded_run_established"], False)
            self.assertEqual(second["successful_fill_count"], 64)

    def test_report_owner_limits_must_match_supervisor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            report, config = make_report(root, self.make_catalog(root))
            for key, larger in (("wall_limit_seconds", 3601),
                                ("rss_limit_bytes", 4294967297),
                                ("storage_limit_bytes", 1073741825)):
                changed = json.loads(json.dumps(report))
                changed["owner"][key] = larger
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, "supervisor limit"):
                    supervisor._validate_report(changed, config, root / "evidence")

    def test_capacity_report_rejects_wrong_error_duplicate_fill_and_changed_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            inputs = self.make_catalog(root)

            report, config = make_report(root, inputs)
            bad_error = json.loads(json.dumps(report))
            bad_error["rejected_request"]["rpc_error"] = {
                "InstructionError": [1, {"Custom": 705}]}
            with self.assertRaisesRegex(ValueError, "exact instruction/custom error"):
                supervisor._validate_report(bad_error, config, root / "evidence")

            duplicate = json.loads(json.dumps(report))
            duplicate["fill_history"][1]["request_address"] = duplicate["fill_history"][0]["request_address"]
            duplicate["fill_history"][1]["queue_after_addresses"][-1] = duplicate["fill_history"][0]["request_address"]
            with self.assertRaisesRegex(ValueError, "distinct"):
                supervisor._validate_report(duplicate, config, root / "evidence")

            incomplete_cleanup = json.loads(json.dumps(report))
            incomplete_cleanup["owner"]["cleanup_complete"] = False
            with self.assertRaisesRegex(ValueError, "required evidence precondition"):
                supervisor._validate_report(incomplete_cleanup, config, root / "evidence")

            (root / "evidence" / "after" / "issuer.bin").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "snapshot digest mismatch"):
                supervisor._validate_report(report, config, root / "evidence")


def make_report(root, inputs):
    evidence_dir = root / "evidence"
    before_dir, after_dir = evidence_dir / "before", evidence_dir / "after"
    before_dir.mkdir(parents=True)
    after_dir.mkdir()
    evidence_dir.chmod(0o700)
    before_dir.chmod(0o700)
    after_dir.chmod(0o700)
    snapshots = []
    queue_bytes = b"queue-full-account-bytes"
    for name in supervisor.ACCOUNT_NAMES:
        raw = (Path(inputs[-1]["request_account"]).read_bytes()
               if name == "request" else queue_bytes if name == "queue"
               else ("snapshot-" + name).encode())
        before_path, after_path = before_dir / f"{name}.bin", after_dir / f"{name}.bin"
        before_path.write_bytes(raw)
        after_path.write_bytes(raw)
        before_path.chmod(0o600)
        after_path.chmod(0o600)
        digest = hashlib.sha256(raw).hexdigest()
        snapshots.append({
            "name": name,
            "before": {"path": f"before/{name}.bin", "sha256": digest},
            "after": {"path": f"after/{name}.bin", "sha256": digest},
        })

    queue = []
    queue_hash = hashlib.sha256(b"empty queue").hexdigest()
    fills = []
    for index, request in enumerate(inputs[:supervisor.QUEUE_CAPACITY]):
        queue.append(request["request_address"])
        next_queue_hash = hashlib.sha256(f"queue-state-{index}".encode()).hexdigest()
        fills.append({
            "request_address": request["request_address"],
            "signature": f"fill-signature-{index}", "slot": index + 1,
            "finalized": True, "consumed": True,
            "queue_after_addresses": list(queue),
            "request_before_sha256": hashlib.sha256(f"request-before-{index}".encode()).hexdigest(),
            "request_after_sha256": hashlib.sha256(f"request-after-{index}".encode()).hexdigest(),
            "queue_before_sha256": queue_hash,
            "queue_after_sha256": next_queue_hash,
        })
        queue_hash = next_queue_hash
    fills[-1]["queue_after_sha256"] = hashlib.sha256(queue_bytes).hexdigest()

    config = {
        "scope": supervisor.SCOPE,
        "cohort_freeze_sha256": "a" * 64,
        "expected_genesis": "genesis-id",
        "expected_genesis_sha256": "e" * 64,
        "expected_elf_sha256": "b" * 64,
        "stage_report_sha256": "c" * 64,
        "clone_receipt_sha256": "d" * 64,
        "inputs": inputs,
    }
    report = {
        "schema": evidence.SCHEMA,
        "identities": supervisor._expected_identities(config),
        "fill_history": fills,
        "before_queue_addresses": list(queue),
        "after_queue_addresses": list(queue),
        "rejected_request": {
            "request_address": inputs[-1]["request_address"],
            "signature": "capacity-rejection-signature", "slot": 65,
            "finalized": True, "consumed": False,
            "rpc_error": {"InstructionError": [1, {"Custom": 708}]},
        },
        "preconditions": {
            "status_active": True, "issuer_active": True, "head_bound": True,
            "request_live": True, "full_wire_valid": True,
            "observed_at": 100, "expires_at": 200, "now": 150,
            "request_deadline": 250,
        },
        "snapshots": snapshots,
        "owner": {
            "wall_limit_seconds": supervisor.LIMITS["runtime_seconds"],
            "rss_limit_bytes": supervisor.LIMITS["rss_bytes"],
            "storage_limit_bytes": supervisor.LIMITS["storage_growth_bytes"],
            "wall_seconds": 12.5, "peak_owned_rss_bytes": 1024,
            "storage_growth_bytes": 4096, "ownership_known": True,
            "cleanup_complete": True, "remaining_owned_processes": 0,
        },
    }
    return report, config


if __name__ == "__main__":
    unittest.main()
