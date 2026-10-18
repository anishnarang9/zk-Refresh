#!/usr/bin/env python3
"""Verify a public Training-011 metrics capsule and render a Markdown report."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.part5 import verify_v3_campaign_public_metrics as verifier


def _number(value):
    return format(value, ".6g")


def render_report(result):
    """Render only values returned by the independent public metrics verifier."""
    if result.get("status") != "verified":
        raise ValueError("verified metrics result required")
    rows = result.get("per_target_count")
    if type(rows) is not list or len(rows) != 5:
        raise ValueError("five verified target-count summaries required")
    lines = [
        "# Training-011 public campaign metrics",
        "",
        f"Campaign: `{result['campaign_id']}`",
        "",
        f"Coverage: {result['slot_count']}/60 registered slots; "
        f"{result['matched_pair_count']}/20 matched Full/Anchor pair groups.",
        "",
        "## Paired medians",
        "",
        "Savings fraction is median paired `(Full - Anchor) / Full`; the indicator "
        "checks whether that median is at least 20%.",
        "",
        "| Requests | Median Full (s) | Median Anchor (s) | Median delta (s) | Median savings | At least 20% |",
        "| ---: | ---: | ---: | ---: | ---: | :---: |",
    ]
    for row in rows:
        indicator = "Yes" if row["paired_fraction_at_least_20_percent"] else "No"
        lines.append(
            f"| {row['target_count']} | {_number(row['median_full_total_seconds'])} "
            f"| {_number(row['median_anchor_total_seconds'])} "
            f"| {_number(row['median_delta_seconds'])} "
            f"| {row['median_savings_fraction']:.2%} | {indicator} |"
        )
    crossing = result["median_sampled_break_even"]
    if crossing["not_crossed_through_k10"]:
        break_even = "Not crossed through 10 requests in the sampled counts."
    else:
        first = crossing["first_positive_target_count"]
        previous = crossing["preceding_sampled_target_count"]
        break_even = f"First positive median delta at {first} requests"
        if previous is not None:
            break_even += f" (previous sampled count: {previous})"
        break_even += "."
    one_time = result["one_time_costs"]
    lines.extend([
        "",
        "Sampled median break-even: " + break_even,
        "",
        "## One-time costs",
        "",
        f"- Development setup: {_number(one_time['development_setup_seconds'])} s",
        f"- Cohort preparation: {_number(one_time['cohort_preparation_seconds'])} s",
        "",
        "## Scope",
        "",
        "Totals are derived sums of measured components. Withheld private report truth "
        "and matched identity are not independently verifiable offline. This report "
        "does not claim a directly timed whole-application benefit. Heldout results "
        "are not covered.",
        "",
    ])
    return "\n".join(lines)


def write_fresh_report(path, contents, protected_dirs=()):
    path = Path(path).absolute()
    parent = path.parent.resolve(strict=True)
    if path.exists() or path.is_symlink():
        raise FileExistsError("fresh Markdown output required")
    target = parent / path.name
    if any(target.is_relative_to(Path(directory).resolve()) for directory in protected_dirs):
        raise ValueError("report output must be separate from verified public bundles")
    with target.open("x", encoding="utf-8", newline="\n") as output:
        output.write(contents)
    return target


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("projection", type=Path)
    parser.add_argument("receipts", type=Path)
    parser.add_argument("metrics", type=Path)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--clock-audit", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = verifier.verify_metrics(args.projection, args.receipts, args.metrics,
                                         args.expected_sha256, args.clock_audit)
        contents = render_report(result)
        write_fresh_report(args.output, contents, (args.projection, args.receipts))
    except Exception as error:
        raise SystemExit(f"public metrics report rejected ({type(error).__name__})") from None


if __name__ == "__main__":
    main()
