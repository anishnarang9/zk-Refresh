# Training-011 public release runbook

This is a post-completion publication procedure for the registered Training-011 campaign. It does not start or resume the matrix. Run it from the repository root only after the existing [completion runbook](v3-campaign-training-011-runbook.md) has passed all three gates: all 60 ordered slots and the final sequence receipt, a passing clock-drift audit, and recomputed economics, reconciliation, and the complete 20-pair summary. Require the matrix driver to have exited successfully and cleanup to have passed. An incomplete, interrupted, failed-clock, or mismatched campaign stops here. Run all seven shell blocks in one Bash session so the pinned variables and helper function remain defined; `set -u` intentionally fails if a block is run without that setup.

The release remains training-only. Its totals are derived sums of measured components. They do not establish a directly timed whole-application benefit, heldout acceptance, deployment, or production readiness.

## 1. Pin the registered campaign and prepare fresh outputs

The only accepted manifest is `results/dynark/part5/v3-campaign-matrix-training-011.json`, with raw and canonical SHA-256 `0b7f6340a34d43e1c1680c1f306a993b36a409e13fc427d24e207df4fa676a96`. Its generated 60-slot plan is pinned at `e2b93eaaf756332da274f6407acb4f0d65af63ccab6608ae964a2529663b66ee`. The existing input projection is the already-published `v3-training-011-public-projection-001`; verify it as-is and do not replace it.

Set the paths and check the identity and gate artifacts. The `CLOCK_REPORT`, economics report, reconciliation report, and total summary must be the passing outputs created by the completion runbook.

```bash
set -euo pipefail
umask 077

ROOT=/Users/anishnarang/Zk-refresh
cd "$ROOT"
RESULTS="$ROOT/results/dynark/part5"
PART5="$ROOT/artifacts/dynark/part5"
CAMPAIGN_PY="$PART5/v3-campaign-python-002"
MATRIX="$RESULTS/v3-campaign-matrix-training-011.json"
MATRIX_OUTPUT="$PART5/v3-matrix-training-011"
PRIVATE_INPUT="$MATRIX_OUTPUT/input-manifest.json"
ECONOMICS_INPUT="$MATRIX_OUTPUT/economics-input-manifest.json"
CLOCK_REPORT="$RESULTS/v3-campaign-clock-drift-training-011.json"
ECONOMICS_REPORT="$RESULTS/v3-campaign-economics-training-011.json"
RECONCILIATION_REPORT="$RESULTS/v3-campaign-cost-reconciliation-training-011.json"
TOTAL_SUMMARY="$RESULTS/v3-campaign-total-cost-training-011.json"
QUALIFICATION="$RESULTS/v3-campaign-completion-training-011.json"
PROJECTION_DIR="$RESULTS/v3-training-011-public-projection-001"
RECEIPT_DIR="$RESULTS/v3-training-011-public-receipts-001"
METRICS_DIR="$RESULTS/v3-training-011-public-metrics-001"
METRICS_CAPSULE="$METRICS_DIR/metrics.json"
METRICS_SHA_FILE="$METRICS_DIR/metrics.sha256"
PUBLIC_REPORT="$METRICS_DIR/report.md"

sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
test "$(git rev-parse --show-toplevel)" = "$ROOT"
test "$(sha256_file "$MATRIX")" = \
  0b7f6340a34d43e1c1680c1f306a993b36a409e13fc427d24e207df4fa676a96
test "$(sha256_file "$PRIVATE_INPUT")" = \
  0b7f6340a34d43e1c1680c1f306a993b36a409e13fc427d24e207df4fa676a96
test "$(sha256_file "$MATRIX_OUTPUT/matrix-plan.json")" = \
  e2b93eaaf756332da274f6407acb4f0d65af63ccab6608ae964a2529663b66ee
test "$(sha256_file "$PROJECTION_DIR/index.json")" = \
  57def2c1f1c2cb540226153899f055d8853824791456a24598df80f45bf0dd5c
test -s "$MATRIX_OUTPUT/sequence-receipt.json"
test -s "$ECONOMICS_INPUT"
test -s "$CLOCK_REPORT"
test -s "$ECONOMICS_REPORT"
test -s "$RECONCILIATION_REPORT"
test -s "$TOTAL_SUMMARY"
test ! -e "$QUALIFICATION" && test ! -L "$QUALIFICATION"
test ! -e "$RECEIPT_DIR" && test ! -L "$RECEIPT_DIR"
test ! -e "$METRICS_DIR" && test ! -L "$METRICS_DIR"
mkdir -m 700 "$METRICS_DIR"
```

These path/hash checks do not replace campaign verification. The qualification command below independently rechecks the registered manifest, completed sequence, clock report, economics inputs and reports, reconciliation, and 20-pair summary. If it fails, preserve its evidence and do not publish the capsule.

## 2. Qualify the completed Training-011 evidence

The binder's CLI takes the registered manifest, passing clock report, economics report, reconciliation report, total summary, and a fresh output path:

```bash
"$CAMPAIGN_PY" -B tools/part5/bind_v3_campaign_completion.py \
  --matrix-manifest "$MATRIX" \
  --clock-report "$CLOCK_REPORT" \
  --economics-report "$ECONOMICS_REPORT" \
  --reconciliation-report "$RECONCILIATION_REPORT" \
  --total-summary "$TOTAL_SUMMARY" \
  --output "$QUALIFICATION"
test -s "$QUALIFICATION"
```

This qualification binds completion and arithmetic for the training matrix. It does not certify a whole-application session benefit or heldout credentials.

## 3. Verify the existing public projection and export receipts

Verify the existing path-free public projection, then export the separate public receipt bundle to its fresh directory. Verify both the receipt chain and the cross-binding between the projection and receipt bundle.

```bash
"$CAMPAIGN_PY" -B tools/part5/verify_v3_campaign_public_projection.py \
  "$PROJECTION_DIR"

"$CAMPAIGN_PY" -B tools/part5/export_v3_campaign_public_receipts.py \
  --matrix-manifest "$MATRIX" \
  --output-dir "$RECEIPT_DIR"

"$CAMPAIGN_PY" -B tools/part5/verify_v3_campaign_public_receipts.py \
  "$RECEIPT_DIR"
"$CAMPAIGN_PY" -B tools/part5/verify_v3_campaign_public_bundle_bindings.py \
  "$PROJECTION_DIR" "$RECEIPT_DIR"
```

The projection verifier covers the public registered inputs. The receipt verifier and binding verifier cover the exported slot receipt chain and its link to that projection; they do not open or independently establish the truth of the private session/effect reports.

## 4. Verify the public clock report

The passing clock report from the completion gate is the bounded clock-audit report used by the metrics capsule. Verify it with the public clock verifier before export:

```bash
"$CAMPAIGN_PY" -B tools/part5/verify_v3_campaign_public_clock_audit.py \
  "$CLOCK_REPORT"
```

Clock agreement is a timing consistency check. It does not establish CPU accounting or prove that the host was never suspended.

## 5. Export the metrics capsule into its separate directory

The metrics exporter independently revalidates the private completion/economics inputs, the clock audit, the unchanged public projection, and the receipt bundle. It writes only `metrics.json` into `METRICS_DIR`, which is separate from `RECEIPT_DIR`.

```bash
"$CAMPAIGN_PY" -B tools/part5/export_v3_campaign_public_metrics.py \
  --matrix-manifest "$MATRIX" \
  --economics-manifest "$ECONOMICS_INPUT" \
  --economics-report "$ECONOMICS_REPORT" \
  --reconciliation-report "$RECONCILIATION_REPORT" \
  --total-report "$TOTAL_SUMMARY" \
  --clock-report "$CLOCK_REPORT" \
  --projection-dir "$PROJECTION_DIR" \
  --receipt-dir "$RECEIPT_DIR" \
  --output "$METRICS_CAPSULE"
test -s "$METRICS_CAPSULE"
```

## 6. Pin the capsule digest and verify offline

Record the capsule's raw-byte SHA-256 in a separate one-line file. Keep or publish this digest independently of `metrics.json`; it is the trusted expected digest for offline verification. The check below confirms the sidecar matches the capsule before passing the pin to the verifier.

```bash
test ! -e "$METRICS_SHA_FILE" && test ! -L "$METRICS_SHA_FILE"
METRICS_SHA="$(sha256_file "$METRICS_CAPSULE")"
python3 - "$METRICS_SHA_FILE" "$METRICS_SHA" <<'PY'
from pathlib import Path
import sys

with Path(sys.argv[1]).open("x", encoding="ascii", newline="\n") as output:
    output.write(sys.argv[2] + "\n")
PY
test "$(cat "$METRICS_SHA_FILE")" = "$METRICS_SHA"
test "$(sha256_file "$METRICS_CAPSULE")" = "$METRICS_SHA"

"$CAMPAIGN_PY" -B tools/part5/verify_v3_campaign_public_metrics.py \
  "$PROJECTION_DIR" "$RECEIPT_DIR" "$METRICS_CAPSULE" \
  --expected-sha256 "$METRICS_SHA" \
  --clock-audit "$CLOCK_REPORT"
```

An offline verifier checks public receipt linkage, capsule arithmetic, and the pinned public clock report. It cannot prove withheld report truth or publisher-asserted matched identity from those source hashes alone.

## 7. Render the Markdown report

Render only after offline verification passes. The renderer calls `verify_metrics` itself and creates a new Markdown file exclusively:

```bash
"$CAMPAIGN_PY" -B tools/part5/render_v3_campaign_public_report.py \
  "$PROJECTION_DIR" "$RECEIPT_DIR" "$METRICS_CAPSULE" \
  --expected-sha256 "$METRICS_SHA" \
  --clock-audit "$CLOCK_REPORT" \
  --output "$PUBLIC_REPORT"
test -s "$PUBLIC_REPORT"
```

The report presents measured-component sums and sampled Full/Anchor medians. It is training-only: do not describe it as a directly timed whole-application benefit, an end-to-end deployment result, or heldout evidence.
