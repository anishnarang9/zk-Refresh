from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.part5 import render_v3_campaign_public_report as renderer
from tools.part5 import verify_v3_campaign_public_metrics as verifier


def _result():
    rows = []
    for count in (0, 1, 2, 5, 10):
        rows.append({
            "target_count": count,
            "median_full_total_seconds": 100.0 + count,
            "median_anchor_total_seconds": 80.0 + count,
            "median_delta_seconds": 20.0,
            "median_savings_fraction": 0.2,
            "paired_fraction_at_least_20_percent": True,
        })
    return {
        "status": "verified",
        "campaign_id": "training-011",
        "slot_count": 60,
        "matched_pair_count": 20,
        "per_target_count": rows,
        "median_sampled_break_even": {
            "first_positive_target_count": 1,
            "preceding_sampled_target_count": 0,
            "not_crossed_through_k10": False,
        },
        "one_time_costs": {
            "development_setup_seconds": 123.5,
            "cohort_preparation_seconds": 67.25,
        },
    }


class RenderPublicCampaignReportTests(unittest.TestCase):
    def test_render_includes_verified_coverage_medians_break_even_and_scope(self):
        report = renderer.render_report(_result())
        for expected in (
                "Campaign: `training-011`", "60/60 registered slots",
                "20/20 matched Full/Anchor pair groups", "| 0 | 100 | 80 | 20 | 20.00% | Yes |",
                "First positive median delta at 1 requests (previous sampled count: 0).",
                "Development setup: 123.5 s", "Cohort preparation: 67.25 s",
                "derived sums of measured components",
                "Withheld private report truth and matched identity are not independently verifiable offline",
                "does not claim a directly timed whole-application benefit",
                "Heldout results are not covered"):
            with self.subTest(expected=expected):
                self.assertIn(expected, report)

    def test_render_reports_uncrossed_break_even_and_rejects_unverified_results(self):
        result = _result()
        result["median_sampled_break_even"] = {
            "first_positive_target_count": None,
            "preceding_sampled_target_count": None,
            "not_crossed_through_k10": True,
        }
        self.assertIn("Not crossed through 10 requests", renderer.render_report(result))
        result["status"] = "rejected"
        with self.assertRaisesRegex(ValueError, "verified metrics"):
            renderer.render_report(result)

    def test_cli_calls_verifier_and_creates_fresh_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.md"
            args = ["projection-dir", "receipt-dir", "metrics.json",
                    "--expected-sha256", "a" * 64,
                    "--clock-audit", "clock.json", "--output", str(output)]
            with mock.patch.object(renderer.verifier, "verify_metrics", return_value=_result()) as verify:
                renderer.main(args)
            verify.assert_called_once_with(Path("projection-dir"), Path("receipt-dir"),
                                           Path("metrics.json"), "a" * 64,
                                           Path("clock.json"))
            content = output.read_text()
            self.assertIn("Training-011 public campaign metrics", content)
            self.assertNotIn("projection-dir", content)

            with mock.patch.object(renderer.verifier, "verify_metrics", return_value=_result()):
                with self.assertRaises(SystemExit) as raised:
                    renderer.main(args)
            self.assertEqual(str(raised.exception), "public metrics report rejected (FileExistsError)")

    def test_cli_fails_closed_without_output_and_suppresses_error_details(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "secret-private-report.md"
            args = ["projection", "receipts", "metrics", "--expected-sha256", "b" * 64,
                    "--clock-audit", "clock", "--output", str(output)]
            with mock.patch.object(renderer.verifier, "verify_metrics",
                                   side_effect=ValueError("private source at /secret/TOKEN")):
                with self.assertRaises(SystemExit) as raised:
                    renderer.main(args)
            self.assertEqual(str(raised.exception), "public metrics report rejected (ValueError)")
            self.assertFalse(output.exists())
            self.assertNotIn("TOKEN", str(raised.exception))
            self.assertNotIn(tmp, str(raised.exception))

    def test_direct_verifier_rejects_missing_public_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises((ValueError, OSError)):
                verifier.verify_metrics(root / "projection", root / "receipts",
                                        root / "metrics.json", "c" * 64,
                                        root / "clock.json")

    def test_report_cannot_invalidate_a_verified_public_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            projection = root / "projection"
            receipts = root / "receipts"
            projection.mkdir()
            receipts.mkdir()
            for directory in (projection, receipts):
                output = directory / "report.md"
                args = [str(projection), str(receipts), "metrics.json",
                        "--expected-sha256", "a" * 64,
                        "--clock-audit", "clock.json", "--output", str(output)]
                with mock.patch.object(renderer.verifier, "verify_metrics", return_value=_result()):
                    with self.assertRaisesRegex(SystemExit, "ValueError"):
                        renderer.main(args)
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
