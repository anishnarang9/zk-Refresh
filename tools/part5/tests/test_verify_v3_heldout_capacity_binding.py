"""Focused final-acceptance binding checks for the shared loaded capacity run."""

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from harness.tests import queue_v3_local_queue_capacity_negative as supervisor
from tools.part5 import finalize_v3_queue_capacity_negative as finalizer
from tools.part5 import heldout_queue_capacity_evidence as capacity_evidence
from tools.part5 import verify_v3_heldout_acceptance as verifier


def pinned(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    path.write_bytes(raw)
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}


class CapacityBindingTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.freeze = {"identities": {"loaded_elf": "e" * 64}}
        self.freeze_ref = pinned(self.root / "freeze.json", self.freeze)
        self.cohort_ref = pinned(
            self.root / "cohort.json", {"freeze_sha256": self.freeze_ref["sha256"]}
        )
        self.runner = verifier.ROOT / verifier.QUEUE_RUNNER_REL
        self.runner_sha = hashlib.sha256(self.runner.read_bytes()).hexdigest()
        self.elf = (
            verifier.ROOT
            / "artifacts/dynark/part5/application-v3-sbf-build-002"
            / "elf/zk_fresh_program.so"
        )
        self.config = {
            "cohort_id": "test-cohort",
            "cohort_freeze": self.freeze_ref["path"],
            "cohort_freeze_sha256": self.freeze_ref["sha256"],
            "cohort_manifest": self.cohort_ref["path"],
            "cohort_manifest_sha256": self.cohort_ref["sha256"],
            "expected_elf": str(self.elf),
            "expected_elf_sha256": "e" * 64,
            "expected_program": "test-program",
            "expected_genesis": "test-genesis",
            "runner": str(self.runner),
            "runner_sha256": self.runner_sha,
        }
        self.refs = {"config": pinned(self.root / "config.json", self.config)}
        for role in (
            "candidate",
            "supervisor_status",
            "monitor",
            "monitor_invocation",
            "proof_monitor",
            "proof_invocation",
        ):
            self.refs[role] = pinned(self.root / f"{role}.json", {"role": role})
        self.consistency = {
            "schema": "part5-v3-heldout-queue-capacity-evidence-v1",
            "report_consistent": True,
            "scope": capacity_evidence.SCOPE,
            "successful_fill_count": 64,
            "queue_capacity": 64,
            "rejected_request_unconsumed": True,
            "execute_instruction_index": 1,
            "custom_error": 708,
            "unchanged_application_account_count": 5,
            "cleanup_known": True,
            "loaded_run_established": False,
            "heldout_acceptance_established": False,
        }
        self.finalized = {
            "schema": finalizer.SCHEMA,
            "passed": True,
            "scope": supervisor.SCOPE,
            **self.refs,
            "fixture_manifest": {"path": "fixture", "sha256": "f" * 64},
            "preparation_receipt": {"path": "preparation", "sha256": "p" * 64},
            "evidence_report": {
                "rejected_request": {
                    "rpc_error": {"InstructionError": [1, {"Custom": 708}]}
                },
                "fill_history": [
                    {"request_address": f"request-{i}"} for i in range(64)
                ],
                "snapshots": [{"name": name} for name in verifier.ACCOUNT_NAMES],
            },
            "evidence_dir": str(self.root / "capacity-output"),
            "report_consistency": self.consistency,
            "setup_cost_seconds": 7.0,
            "loaded_owner_seconds": 13.0,
            "loaded_run_established": True,
            "heldout_acceptance_established": False,
        }
        self.finalization_ref = pinned(self.root / "finalization.json", self.finalized)
        paths = (
            "tools/part5/finalize_v3_queue_capacity_negative.py",
            "tools/part5/prepare_v3_queue_capacity_fixture.py",
            "tools/part5/heldout_queue_capacity_evidence.py",
            "harness/tests/queue_v3_capacity_runtime.py",
            "harness/tests/queue_v3_local_queue_capacity_negative.py",
        )
        client = []
        for name in paths:
            source = verifier.ROOT / name
            client.append(
                {
                    "path": name,
                    "artifact": {
                        "path": str(source),
                        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                    },
                }
            )
        registry = [
            {
                "path": verifier.QUEUE_RUNNER_REL,
                "artifact": {"path": str(self.runner), "sha256": self.runner_sha},
            }
        ]
        self.manifest = {
            "schema": verifier.MANIFEST_SCHEMA,
            "evidence_scope": "final-acceptance",
            "queue_capacity_negative": self.finalization_ref,
            "queue_capacity_negative_wall_seconds": 20.0,
            "freeze_receipt": self.freeze_ref,
            "cohort_receipt": self.cohort_ref,
            "frozen_files": {"loaded_elf": {"path": str(self.elf), "sha256": "e" * 64}},
            "frozen_bundles": {"client": client, "registry": registry},
        }
        self.runtime = {
            "program": "test-program",
            "genesis": "test-genesis",
            "elf_sha256": "e" * 64,
        }

    def verify(self):
        return verifier._verify_queue_capacity_negative(self.manifest, self.runtime)

    def test_replays_exact_retained_finalization_against_shared_cohort(self):
        with patch.object(finalizer, "finalize", return_value=self.finalized) as replay:
            result = self.verify()
        replay.assert_called_once_with(
            {"schema": finalizer.MANIFEST_SCHEMA, **self.refs}
        )
        self.assertEqual(result["finalization_sha256"], self.finalization_ref["sha256"])
        self.assertEqual(result["successful_fill_count"], 64)
        self.assertEqual(result["custom_error"], 708)

    def test_rejects_other_cohort_even_when_finalizer_replays(self):
        self.config["cohort_manifest_sha256"] = "0" * 64
        self.refs["config"] = pinned(self.root / "config.json", self.config)
        self.finalized["config"] = self.refs["config"]
        self.manifest["queue_capacity_negative"] = pinned(
            self.root / "finalization.json", self.finalized
        )
        with patch.object(finalizer, "finalize", return_value=self.finalized):
            with self.assertRaisesRegex(ValueError, "cohort"):
                self.verify()

    def test_rejects_unreproduced_finalization(self):
        with patch.object(
            finalizer, "finalize", return_value={**self.finalized, "passed": False}
        ):
            with self.assertRaisesRegex(ValueError, "replay|reproduce"):
                self.verify()

    def test_rejects_supplied_only_capacity_report(self):
        self.manifest["queue_capacity_negative"] = pinned(
            self.root / "finalization.json",
            {"schema": "part5-v3-heldout-queue-capacity-evidence-v1"},
        )
        with patch.object(finalizer, "finalize", return_value=self.finalized):
            with self.assertRaisesRegex(ValueError, "finalization"):
                self.verify()

    def test_rejects_unaccounted_setup_cost(self):
        self.manifest["queue_capacity_negative_wall_seconds"] = 13.0
        with patch.object(finalizer, "finalize", return_value=self.finalized):
            with self.assertRaisesRegex(ValueError, "wall|cost"):
                self.verify()

    def test_accepts_capacity_supervisor_pinned_in_registry_bundle(self):
        moved = {
            "harness/tests/queue_v3_capacity_runtime.py",
            "harness/tests/queue_v3_local_queue_capacity_negative.py",
        }
        client = self.manifest["frozen_bundles"]["client"]
        self.manifest["frozen_bundles"]["registry"].extend(
            row for row in client if row["path"] in moved
        )
        self.manifest["frozen_bundles"]["client"] = [
            row for row in client if row["path"] not in moved
        ]
        with patch.object(finalizer, "finalize", return_value=self.finalized):
            self.assertEqual(self.verify()["successful_fill_count"], 64)

    def test_rejects_core_only_scope_under_final_schema(self):
        self.manifest["evidence_scope"] = "legacy-core-path-only"
        with patch.object(finalizer, "finalize", return_value=self.finalized):
            with self.assertRaisesRegex(ValueError, "final acceptance|core"):
                self.verify()


if __name__ == "__main__":
    unittest.main()
