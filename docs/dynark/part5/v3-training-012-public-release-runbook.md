# Training-012 prospective public release runbook

This is a prospective post-completion publication procedure for Training-012. It does not start, resume, or qualify the matrix, and no Training-012 metrics capsule or result digest is asserted here. Begin only after the [Training-012 completion runbook](v3-campaign-training-012-runbook.md) passes every gate: 60 ordered slot receipts plus the final sequence receipt, a passing clock-drift audit, and recomputed economics, reconciliation, and the complete 20-pair summary. The matrix driver must have exited successfully and cleanup must have passed. An interrupted, incomplete, clock-failed, or mismatched campaign stops here.

The public release remains training-only. Component sums do not establish a directly timed whole-application benefit, heldout acceptance, deployment, or production readiness. Do not publish any metrics unless all completion gates above are independently revalidated by a Training-012-capable publisher. Do not put private filesystem paths, `current_root`, raw reports, configs, identifiers, or unrestricted source maps in the public capsule.

## 1. Pin Training-012 and prepare fresh outputs

The accepted registered manifest is `results/dynark/part5/v3-campaign-matrix-training-012.json`, with raw and canonical SHA-256 `21612a6451c00b7a46d9abaa3445e5acecec3c14583317884800b49b2614ff53`. Its generated 60-slot plan is pinned at `e1cd1b9eb1c08fed70cd7544b0286af82422eb50a49a63875be267b57907f467`. Verify the existing public projection as-is; its `index.json` SHA-256 is `d846e56347d3a244837426bf08f9358e7c0b0cc6aff62666ed5440090967e340`. Do not replace it.

Run after the completion runbook has passed all gates. Keep these commands in one Bash session so the pinned variables remain defined. The clock, economics, reconciliation, and total-summary files must be the passing outputs from that runbook. The receipt and metrics output directories below must be fresh; the pinned projection already exists and must remain unchanged.

```bash
set -euo pipefail
umask 077

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
RESULTS="$ROOT/results/dynark/part5"
PART5="$ROOT/artifacts/dynark/part5"
CAMPAIGN_PY="$PART5/v3-campaign-python-002"
MATRIX="$RESULTS/v3-campaign-matrix-training-012.json"
MATRIX_OUTPUT="$PART5/v3-matrix-training-012"
PRIVATE_INPUT="$MATRIX_OUTPUT/input-manifest.json"
ECONOMICS_INPUT="$MATRIX_OUTPUT/economics-input-manifest.json"
CLOCK_REPORT="$RESULTS/v3-campaign-clock-drift-training-012.json"
ECONOMICS_REPORT="$RESULTS/v3-campaign-economics-training-012.json"
RECONCILIATION_REPORT="$RESULTS/v3-campaign-cost-reconciliation-training-012.json"
TOTAL_SUMMARY="$RESULTS/v3-campaign-total-cost-training-012.json"
QUALIFICATION="$RESULTS/v3-campaign-completion-training-012.json"
PROJECTION_DIR="$RESULTS/v3-training-012-public-projection-001"
RECEIPT_DIR="$RESULTS/v3-training-012-public-receipts-001"
METRICS_DIR="$RESULTS/v3-training-012-public-metrics-001"
METRICS_CAPSULE="$METRICS_DIR/metrics.json"
METRICS_SHA_FILE="$METRICS_DIR/metrics.sha256"
PUBLIC_REPORT="$METRICS_DIR/report.md"

sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
test "$(git rev-parse --show-toplevel)" = "$ROOT"
test "$(sha256_file "$MATRIX")" = \
  21612a6451c00b7a46d9abaa3445e5acecec3c14583317884800b49b2614ff53
test "$(sha256_file "$PRIVATE_INPUT")" = \
  21612a6451c00b7a46d9abaa3445e5acecec3c14583317884800b49b2614ff53
test "$(sha256_file "$MATRIX_OUTPUT/matrix-plan.json")" = \
  e1cd1b9eb1c08fed70cd7544b0286af82422eb50a49a63875be267b57907f467
test "$(sha256_file "$PROJECTION_DIR/index.json")" = \
  d846e56347d3a244837426bf08f9358e7c0b0cc6aff62666ed5440090967e340
test -s "$MATRIX_OUTPUT/sequence-receipt.json"
test -s "$ECONOMICS_INPUT"
test -s "$CLOCK_REPORT"
test -s "$ECONOMICS_REPORT"
test -s "$RECONCILIATION_REPORT"
test -s "$TOTAL_SUMMARY"
test ! -e "$QUALIFICATION" && test ! -L "$QUALIFICATION"
test ! -e "$RECEIPT_DIR" && test ! -L "$RECEIPT_DIR"
test ! -e "$METRICS_DIR" && test ! -L "$METRICS_DIR"
```

These identity and presence checks do not qualify completion. The completion runbook's validation must have passed first; the publisher must independently recheck all 60 receipts, the sequence, clock, economics, reconciliation, and total summary before it writes any capsule.

## 2. Verify the registered public projection

The projection verifier checks the scrubbed registered design and pinned public inputs. Its result does not establish private slot receipts, application effects, clock agreement, or campaign costs.

```bash
"$CAMPAIGN_PY" -B tools/part5/verify_v3_campaign_public_projection.py \
  "$PROJECTION_DIR"
```

## 3. Export and verify the public receipt bundle

After completion is qualified, export the 60-slot receipt bundle to its fresh directory. Verify its receipt chain and its binding to the unchanged public projection.

```bash
"$CAMPAIGN_PY" -B tools/part5/export_v3_campaign_public_receipts.py \
  --matrix-manifest "$MATRIX" \
  --output-dir "$RECEIPT_DIR"

"$CAMPAIGN_PY" -B tools/part5/verify_v3_campaign_public_receipts.py \
  "$RECEIPT_DIR"
"$CAMPAIGN_PY" -B tools/part5/verify_v3_campaign_public_bundle_bindings.py \
  "$PROJECTION_DIR" "$RECEIPT_DIR"
```

Receipt verification covers the public receipt chain and its projection link. It does not independently establish the truth of private session/effect reports or the economics.

## 4. Verify the passing public clock report

Use the clock report produced by the completion runbook. Clock agreement is a bounded timing-consistency check; it does not establish CPU accounting or prove that the host was never suspended.

```bash
"$CAMPAIGN_PY" -B tools/part5/verify_v3_campaign_public_clock_audit.py \
  "$CLOCK_REPORT"
```

## 5. Bind the completed private evidence

The binder independently rechecks the exact registered Training-012 manifest, all 60 slot reports and final sequence, the clock audit, the economics report, reconciliation, and all 20 matched pairs. Its fresh qualification receipt is a publisher-side result, not a substitute for the public verifier or the private reports.

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

## 6. Export the narrowly scrubbed metrics capsule

The publisher rechecks the private completion chain and exact source identities, joins the same registered Full/Anchor requests, and emits an allowlisted `metrics.json` with no private paths. It publishes component sums; it does not convert them to direct complete-arm measurements.

```bash
mkdir -m 700 "$METRICS_DIR"
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
test ! -e "$METRICS_DIR/clock-audit.json"
cp "$CLOCK_REPORT" "$METRICS_DIR/clock-audit.json"
test "$(sha256_file "$METRICS_DIR/clock-audit.json")" = "$(sha256_file "$CLOCK_REPORT")"
METRICS_SHA="$(sha256_file "$METRICS_CAPSULE")"
printf '%s\n' "$METRICS_SHA" > "$METRICS_SHA_FILE"
```

## 7. Verify offline and render the public report

The public verifier reads only the public projection, public receipts, the capsule, the published clock audit, and the separately pinned capsule byte hash. It independently recomputes the 20 paired component-sum totals, savings, and sampled strict-positive break-even. It cannot independently recover withheld private reports or prove the publisher's private identity equality claim. The renderer accepts only a verified capsule and keeps that limitation in the report.

```bash
"$CAMPAIGN_PY" -B tools/part5/verify_v3_campaign_public_clock_audit.py \
  "$METRICS_DIR/clock-audit.json"
"$CAMPAIGN_PY" -B tools/part5/verify_v3_campaign_public_metrics.py \
  "$PROJECTION_DIR" "$RECEIPT_DIR" "$METRICS_CAPSULE" \
  --expected-sha256 "$METRICS_SHA" \
  --clock-audit "$METRICS_DIR/clock-audit.json"
"$CAMPAIGN_PY" -B tools/part5/render_v3_campaign_public_report.py \
  "$PROJECTION_DIR" "$RECEIPT_DIR" "$METRICS_CAPSULE" \
  --expected-sha256 "$METRICS_SHA" \
  --clock-audit "$METRICS_DIR/clock-audit.json" \
  --output "$PUBLIC_REPORT"
test -s "$PUBLIC_REPORT"
```

Inspect each public file before staging it. Publish only the verified projection, 60-receipt bundle, metrics capsule, capsule digest, clock audit, report, and a scrubbed interpretation note. Stage their exact paths; keep the raw manifest, keys, witnesses, proofs, private effects, full reports, and other untracked files outside Git. No Training-012 metric or benefit is asserted by this prospective procedure before the complete run and these commands pass.
