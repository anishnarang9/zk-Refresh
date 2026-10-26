import importlib.util
import hashlib
from pathlib import Path
import copy
import unittest


spec = importlib.util.spec_from_file_location(
    "queue_v3_loaded_negative_checks",
    Path(__file__).with_name("queue_v3_loaded_negative_checks.py"))
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


class LoadedNegativeCheckTests(unittest.TestCase):
    def test_expired_status_accepts_expiry_at_now_and_age_at_limit(self):
        self.assertIsNone(checks.check_expired_status(
            observed_at=100, expires_at=200, now=400,
            status_active=True, issuer_active=True, head_bound=True,
            request_live=True, full_wire_valid=True))

    def test_expired_status_rejects_unexpired_or_overage_status(self):
        base = dict(observed_at=100, expires_at=200, now=199,
                    status_active=True, issuer_active=True, head_bound=True,
                    request_live=True, full_wire_valid=True)
        with self.assertRaisesRegex(ValueError, "has not expired"):
            checks.check_expired_status(**base)
        base["now"] = 401
        with self.assertRaisesRegex(ValueError, "too old"):
            checks.check_expired_status(**base)

    def test_expired_status_requires_all_other_preconditions(self):
        for field in ("status_active", "issuer_active", "head_bound",
                      "request_live", "full_wire_valid"):
            values = dict(observed_at=100, expires_at=200, now=201,
                          status_active=True, issuer_active=True, head_bound=True,
                          request_live=True, full_wire_valid=True)
            values[field] = False
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                checks.check_expired_status(**values)

    def test_expired_status_rejects_boolean_timestamps_and_long_lifetime(self):
        values = dict(observed_at=100, expires_at=200, now=200,
                      status_active=True, issuer_active=True, head_bound=True,
                      request_live=True, full_wire_valid=True)
        values["now"] = True
        with self.assertRaisesRegex(ValueError, "timestamp"):
            checks.check_expired_status(**values)
        values.update(now=401, expires_at=401)
        with self.assertRaisesRegex(ValueError, "lifetime"):
            checks.check_expired_status(**values)

    def test_execute_error_accepts_exact_status_and_capacity_errors(self):
        for custom in (705, 708):
            with self.subTest(custom=custom):
                error = {"InstructionError": [1, {"Custom": custom}]}
                self.assertIsNone(checks.check_execute_error(error, custom))

    def test_execute_error_rejects_wrong_shape_index_or_code(self):
        for error, custom in (
                ({"InstructionError": [0, {"Custom": 705}]}, 705),
                ({"InstructionError": [1, {"Custom": 713}]}, 705),
                ({"InstructionError": [1, {"Custom": 705}], "other": None}, 705),
                ({"InstructionError": [1, {"Custom": 705}]}, 708)):
            with self.subTest(error=error, custom=custom), self.assertRaises(ValueError):
                checks.check_execute_error(error, custom)
        with self.assertRaises(ValueError):
            checks.check_execute_error({"InstructionError": [1, {"Custom": 709}]}, 709)

    @staticmethod
    def snapshots():
        return {name: (name.encode() + b"\x00") for name in checks.ACCOUNT_NAMES}

    def test_application_accounts_accepts_identical_five_ordered_bytes(self):
        before = self.snapshots()
        self.assertIsNone(checks.check_application_accounts_unchanged(
            before, dict(before)))

    def test_application_accounts_rejects_changed_missing_reordered_and_nonbytes(self):
        before = self.snapshots()
        changed = dict(before)
        changed["queue"] += b"x"
        with self.assertRaisesRegex(ValueError, "queue application account changed"):
            checks.check_application_accounts_unchanged(before, changed)
        with self.assertRaisesRegex(ValueError, "five ordered"):
            checks.check_application_accounts_unchanged(before, dict(reversed(list(before.items()))))
        malformed = dict(before)
        del malformed["head"]
        with self.assertRaisesRegex(ValueError, "five ordered"):
            checks.check_application_accounts_unchanged(before, malformed)
        malformed = dict(before)
        malformed["head"] = bytearray(b"head")
        with self.assertRaisesRegex(ValueError, "must be bytes"):
            checks.check_application_accounts_unchanged(before, malformed)

    @staticmethod
    def full_addresses():
        return ["request-" + str(index) for index in range(64)]

    def test_full_queue_accepts_64_distinct_stable_addresses_and_absent_65th(self):
        before = self.full_addresses()
        self.assertIsNone(checks.check_full_queue(before, list(before), "request-64"))

    def test_full_queue_rejects_wrong_size_duplicates_65th_and_membership_change(self):
        before = self.full_addresses()
        cases = (
            (before[:-1], before[:-1], "request-64", "exactly 64"),
            (before[:-1] + [before[0]], before[:-1] + [before[0]], "request-64", "distinct"),
            (before + ["request-64"], before + ["request-64"], "request-65", "exactly 64"),
            (before, before[:-1] + ["new-request"], "request-64", "membership changed"),
            (before, before, "request-0", "65th request"),
        )
        for pre, post, request65, reason in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                checks.check_full_queue(pre, post, request65)

    @staticmethod
    def fill_history():
        rows = []
        queue = []
        queue_hash = hashlib.sha256(b"initial-empty-queue").hexdigest()
        for index in range(64):
            request = "fill-request-" + str(index)
            queue = queue + [request]
            next_queue_hash = (hashlib.sha256(b"pre-submit-queue").hexdigest()
                               if index == 63 else hashlib.sha256(f"queue-state-{index}".encode()).hexdigest())
            rows.append({
                "request_address": request,
                "signature": "fill-signature-" + str(index),
                "slot": index + 1,
                "finalized": True,
                "consumed": True,
                "queue_after_addresses": list(queue),
                "request_before_sha256": hashlib.sha256(f"request-before-{index}".encode()).hexdigest(),
                "request_after_sha256": hashlib.sha256(f"request-after-{index}".encode()).hexdigest(),
                "queue_before_sha256": queue_hash,
                "queue_after_sha256": next_queue_hash,
            })
            queue_hash = next_queue_hash
        return rows, queue, queue_hash

    def test_finalized_fill_history_accepts_ordered_successful_fills(self):
        rows, queue, queue_hash = self.fill_history()
        self.assertIsNone(checks.check_finalized_fill_history(
            rows, queue, "request-65", queue_hash))

    def test_finalized_fill_history_rejects_duplicate_nonfinalized_and_reordered(self):
        rows, queue, queue_hash = self.fill_history()
        duplicate = copy.deepcopy(rows)
        duplicate[1]["request_address"] = duplicate[0]["request_address"]
        duplicate[1]["queue_after_addresses"][-1] = duplicate[0]["request_address"]
        with self.assertRaisesRegex(ValueError, "distinct"):
            checks.check_finalized_fill_history(duplicate, queue, "request-65", queue_hash)

        nonfinalized = copy.deepcopy(rows)
        nonfinalized[7]["finalized"] = False
        with self.assertRaisesRegex(ValueError, "finalized"):
            checks.check_finalized_fill_history(nonfinalized, queue, "request-65", queue_hash)

        reordered = copy.deepcopy(rows)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        with self.assertRaisesRegex(ValueError, "append exactly"):
            checks.check_finalized_fill_history(reordered, queue, "request-65", queue_hash)

    def test_finalized_fill_history_rejects_bad_append_or_unconsumed_request(self):
        rows, queue, queue_hash = self.fill_history()
        bad_append = copy.deepcopy(rows)
        bad_append[5]["queue_after_addresses"][-1] = "wrong-request"
        with self.assertRaisesRegex(ValueError, "append exactly"):
            checks.check_finalized_fill_history(bad_append, queue, "request-65", queue_hash)

        unconsumed = copy.deepcopy(rows)
        unconsumed[5]["consumed"] = False
        with self.assertRaisesRegex(ValueError, "must be consumed"):
            checks.check_finalized_fill_history(unconsumed, queue, "request-65", queue_hash)

        wrong_final = list(queue)
        wrong_final[-1] = "different-request"
        with self.assertRaisesRegex(ValueError, "pre-submit queue"):
            checks.check_finalized_fill_history(rows, wrong_final, "request-65", queue_hash)

    def test_finalized_fill_history_rejects_bad_signature_slot_and_row_schema(self):
        rows, queue, queue_hash = self.fill_history()
        for field, value, message in (
                ("signature", "", "signature"),
                ("signature", 12, "signature"),
                ("slot", 0, "positive integer"),
                ("slot", True, "positive integer"),
                ("extra", "private", "unknown or missing field")):
            mutated = copy.deepcopy(rows)
            mutated[0][field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, message):
                checks.check_finalized_fill_history(mutated, queue, "request-65", queue_hash)

        with self.assertRaisesRegex(ValueError, "65th request"):
            checks.check_finalized_fill_history(rows, queue, rows[10]["request_address"], queue_hash)

    def test_finalized_fill_history_rejects_bad_hash_transitions_and_chain(self):
        rows, queue, queue_hash = self.fill_history()
        for index, field, value, message in (
                (0, "request_after_sha256", rows[0]["request_before_sha256"], "request account hash must change"),
                (0, "queue_after_sha256", rows[0]["queue_before_sha256"], "queue account hash must change"),
                (1, "queue_before_sha256", "f" * 64, "queue account hash chain is broken"),
                (0, "request_before_sha256", "F" * 64, "SHA-256 is invalid")):
            mutated = copy.deepcopy(rows)
            mutated[index][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, message):
                checks.check_finalized_fill_history(mutated, queue, "request-65", queue_hash)

        with self.assertRaisesRegex(ValueError, "pre-submit queue snapshot"):
            checks.check_finalized_fill_history(rows, queue, "request-65", "a" * 64)


if __name__ == "__main__":
    unittest.main()
