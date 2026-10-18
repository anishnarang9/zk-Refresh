# Training-012 campaign completion runbook

This is the post-run procedure for the fresh Training-012 matrix. Training-010 stopped after host sleep and Training-011 stopped at its storage limit; both partial attempts remain historical evidence and are excluded from Training-012 economics. Training-012 launched under `caffeinate -is`; this runbook does not claim completion. Do not relaunch or resume it from a second process. Run the shell blocks from the repository root in one Bash session so the checked paths and pins remain in scope.

## Registered paths and pins

The registered matrix manifest is `results/dynark/part5/v3-campaign-matrix-training-012.json` (SHA-256 `21612a6451c00b7a46d9abaa3445e5acecec3c14583317884800b49b2614ff53`). The campaign's private copy is `artifacts/dynark/part5/v3-matrix-training-012/input-manifest.json`; it has the same byte hash. The output root is `artifacts/dynark/part5/v3-matrix-training-012`, and its generated 60-slot plan is `matrix-plan.json` (SHA-256 `e1cd1b9eb1c08fed70cd7544b0286af82422eb50a49a63875be267b57907f467`). The registered design is four repetitions × update counts `{0, 1, 2, 5, 10}` × Full, Anchor, and coalesced Full.

| Pinned item | Path | SHA-256 |
|---|---|---|
| Campaign Python | `artifacts/dynark/part5/v3-campaign-python-002` | `4fce274f0e60574ada0b53f17bceb49bbd804125ddae972c7674b8eb13d9e49d` |
| Training-011 source manifest used for registration | `results/dynark/part5/v3-campaign-matrix-training-011.json` | `0b7f6340a34d43e1c1680c1f306a993b36a409e13fc427d24e207df4fa676a96` |
| Matrix driver | `tools/part5/run_v3_campaign_matrix.py` | `dee858b687dcb657814d98d376c9510136e3d16a4a38bd5c40d320933e0781ba` |
| Frozen source/setup boundary | `results/dynark/part5/v3-campaign-freeze-003/freeze.json` | `3aa9c34057a44db5d040777c6e8ad94bf9fa567bf12f9260742b08ef5428c203` |
| Freeze identity manifest | `results/dynark/part5/v3-campaign-freeze-003/identity-manifest.json` | `e8f09c2fd84d9f2c69696b8d382e95d7498c7f2b9489e382b6cf8fc240db9ae7` |
| Isolated proof runner | `artifacts/dynark/part5/v3-proof-runner-training-010` | `093659cec842945fd3db15e9e51087b5717d71dcb375fdf60ced58279a5ad19a` |
| v3 setup manifest | `artifacts/dynark/part5/v3-development-setup-001/setup-manifest.json` | `d31f82e3f147e31b30074b3a570a9d7945c5e1f5d3f3dd74172801abbe984918` |
| Ordinary VK | `artifacts/dynark/part5/v3-development-setup-001/ordinary.vk` | `87edb4608c2140f3c7fddc8503e49b68931cda973711ce2c831bd44f1b98a875` |
| Profile | `circuits/credential-v3-bounded/profile.json` | `2e5d26564fb055e70cff924c4cb6e296509030b8c0062130f86ad5af783f7918` |
| R1CS | `artifacts/dynark/part5/v3-compile-001/credential.r1cs` | `976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888` |

The freeze identity manifest pins the remaining application source, client, registry, adapter, ELF, signer interface, and witness executable identities. Keep that manifest and the Training-010 proof runner unchanged; the matrix and later cost reports are not replacements for these source/setup pins.

## 1. Wait for and verify the complete matrix

Run from the repository root after the existing serial matrix process exits. Do not run economics before the clock audit in Step 2. These checks read the registered and private manifests but do not print their contents.

```bash
set -euo pipefail
umask 077

ROOT=/Users/anishnarang/Zk-refresh
cd "$ROOT"
RESULTS="$ROOT/results/dynark/part5"
PART5="$ROOT/artifacts/dynark/part5"
CAMPAIGN_PY="$PART5/v3-campaign-python-002"
MATRIX="$RESULTS/v3-campaign-matrix-training-012.json"
MATRIX_OUTPUT="$PART5/v3-matrix-training-012"
PRIVATE_INPUT="$MATRIX_OUTPUT/input-manifest.json"
ECONOMICS_INPUT="$MATRIX_OUTPUT/economics-input-manifest.json"
CLOCK_REPORT="$RESULTS/v3-campaign-clock-drift-training-012.json"

sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
test "$(git rev-parse --show-toplevel)" = "$ROOT"
test "$(sha256_file "$MATRIX")" = \
  21612a6451c00b7a46d9abaa3445e5acecec3c14583317884800b49b2614ff53
test "$(sha256_file "$PRIVATE_INPUT")" = \
  21612a6451c00b7a46d9abaa3445e5acecec3c14583317884800b49b2614ff53
test "$(sha256_file "$MATRIX_OUTPUT/matrix-plan.json")" = \
  e1cd1b9eb1c08fed70cd7544b0286af82422eb50a49a63875be267b57907f467
test "$(sha256_file "$ROOT/tools/part5/run_v3_campaign_matrix.py")" = \
  dee858b687dcb657814d98d376c9510136e3d16a4a38bd5c40d320933e0781ba
test "$(sha256_file "$CAMPAIGN_PY")" = \
  4fce274f0e60574ada0b53f17bceb49bbd804125ddae972c7674b8eb13d9e49d
test "$(sha256_file "$PART5/v3-proof-runner-training-010")" = \
  093659cec842945fd3db15e9e51087b5717d71dcb375fdf60ced58279a5ad19a
test "$(sha256_file "$RESULTS/v3-campaign-freeze-003/freeze.json")" = \
  3aa9c34057a44db5d040777c6e8ad94bf9fa567bf12f9260742b08ef5428c203
test "$(sha256_file "$RESULTS/v3-campaign-freeze-003/identity-manifest.json")" = \
  e8f09c2fd84d9f2c69696b8d382e95d7498c7f2b9489e382b6cf8fc240db9ae7

test -s "$MATRIX_OUTPUT/economics-input-manifest.json"

"$CAMPAIGN_PY" -B - "$ROOT" "$MATRIX" "$MATRIX_OUTPUT" "$ECONOMICS_INPUT" <<'PY'
import pathlib, sys
root, matrix_path, output_root, economics_input = map(pathlib.Path, sys.argv[1:])
sys.path.insert(0, str(root))
from tools.part5 import run_v3_campaign_matrix as matrix
from tools.part5 import reconcile_v3_campaign_costs as costs

validated = matrix.validate_manifest(matrix_path)
assert validated['campaign_id'] == 'training-012'
assert pathlib.Path(validated['output_root']).resolve(strict=True) == output_root.resolve(strict=True)
planned = matrix.plan_slots(validated)
assert len(planned) == 60
sequence_sha = costs.verify_completed_matrix(validated)
sequence = matrix.read_json(output_root / 'sequence-receipt.json')['sequence']
assert len(sequence) == 60
assert matrix.read_json(economics_input) == matrix.economics_input_manifest(planned)
print(f'Training-012 has 60 verified slots and a final sequence receipt ({sequence_sha}).')
PY
```

If the matrix driver did not exit successfully, any slot or sequence receipt is missing, or the identity checks fail, stop. Preserve the receipts and failure evidence; do not pool Training-010 or Training-011 partial slots or make replacement outputs.

## 2. Mandatory clock-drift audit

After all 60 contiguous slot receipts and the final sequence receipt validate, run the clock audit with the matrix-pinned Python. This must pass before creating or reading any Training-012 economics result. The audit compares each slot's UTC elapsed time with its bounded monotonic duration at a maximum five-second tolerance. A mismatch detects a timing discrepancy but does not identify its cause; matching clocks do not prove absence of suspension or establish CPU accounting.

```bash
test ! -e "$CLOCK_REPORT" && test ! -L "$CLOCK_REPORT"

"$CAMPAIGN_PY" -B tools/part5/audit_v3_campaign_clock_drift.py \
  --matrix-manifest "$MATRIX" \
  --output "$CLOCK_REPORT"

"$CAMPAIGN_PY" -B - "$CLOCK_REPORT" "$MATRIX" <<'PY'
import hashlib, json, pathlib, sys
report_path, matrix_path = map(pathlib.Path, sys.argv[1:])
report = json.loads(report_path.read_bytes())
matrix_value = json.loads(matrix_path.read_bytes())
canonical_matrix = (json.dumps(matrix_value, sort_keys=True, separators=(',', ':')) + '\n').encode()
assert report['schema'] == 'part5-v3-campaign-clock-drift-v1'
assert report['passed'] is True and report['slot_count'] == 60
assert report['tolerance_seconds'] <= 5.0
assert report['matrix_manifest_sha256'] == hashlib.sha256(canonical_matrix).hexdigest()
print('Training-012 clock-drift audit passed for all 60 slots.')
PY
```

If the audit exits nonzero or its report fails these checks, preserve the report and stop. Do not remove or replace Training-012 evidence, resume that matrix, reconcile its costs, or claim savings from it. A new attempt requires a separately registered fresh campaign.

## 3. Economics, only after a passing clock report

The following commands create fresh reports only after Steps 1 and 2 pass. They use the pinned campaign interpreter and keep the measured matrix, clock report, economics, reconciliation, and total summary separate.

```bash
ECONOMICS_REPORT="$RESULTS/v3-campaign-economics-training-012.json"
RECONCILIATION_REPORT="$RESULTS/v3-campaign-cost-reconciliation-training-012.json"
TOTAL_SUMMARY="$RESULTS/v3-campaign-total-cost-training-012.json"

for report in "$ECONOMICS_REPORT" "$RECONCILIATION_REPORT" "$TOTAL_SUMMARY"; do
  test ! -e "$report" && test ! -L "$report"
done

"$CAMPAIGN_PY" -B \
  tools/part5/analyze_v3_campaign_economics.py \
  --manifest "$ECONOMICS_INPUT" --output "$ECONOMICS_REPORT"
"$CAMPAIGN_PY" -B \
  tools/part5/reconcile_v3_campaign_costs.py \
  --matrix-manifest "$MATRIX" --economics-report "$ECONOMICS_REPORT" \
  --output "$RECONCILIATION_REPORT"
"$CAMPAIGN_PY" -B \
  tools/part5/summarize_v3_campaign_total.py \
  --reconciliation-report "$RECONCILIATION_REPORT" \
  --matrix-manifest "$MATRIX" --economics-report "$ECONOMICS_REPORT" \
  --output "$TOTAL_SUMMARY"
test -s "$ECONOMICS_REPORT" && test -s "$RECONCILIATION_REPORT" && test -s "$TOTAL_SUMMARY"

"$CAMPAIGN_PY" -B - "$ROOT" "$MATRIX" "$MATRIX_OUTPUT" "$ECONOMICS_INPUT" \
  "$CLOCK_REPORT" "$ECONOMICS_REPORT" "$RECONCILIATION_REPORT" "$TOTAL_SUMMARY" <<'PY'
import json, pathlib, sys
root, matrix_path, output_root, economics_input, clock_path, economics_path, reconciliation_path, total_path = map(pathlib.Path, sys.argv[1:])
sys.path.insert(0, str(root))
from tools.part5 import run_v3_campaign_matrix as matrix
from tools.part5 import reconcile_v3_campaign_costs as costs
from tools.part5 import summarize_v3_campaign_total as total

validated = matrix.validate_manifest(matrix_path)
assert validated['campaign_id'] == 'training-012'
assert pathlib.Path(validated['output_root']).resolve(strict=True) == output_root.resolve(strict=True)
planned = matrix.plan_slots(validated)
sequence_sha = costs.verify_completed_matrix(validated)
assert len(planned) == 60
assert matrix.read_json(economics_input) == matrix.economics_input_manifest(planned)
clock = matrix.read_json(clock_path)
assert clock['schema'] == 'part5-v3-campaign-clock-drift-v1'
assert clock['passed'] is True and clock['slot_count'] == 60
assert clock['matrix_manifest_sha256'] == validated['manifest_sha256']
economics = matrix.read_json(economics_path)
expected = costs.reconcile(validated, economics)
expected['economics_report_sha256'] = matrix.sha256(economics_path)
assert matrix.read_json(reconciliation_path) == expected
summary = total.load_and_summarize(reconciliation_path, matrix_path, economics_path)
assert json.loads(total_path.read_bytes()) == summary
assert summary['matrix_grid_complete'] is True
assert summary['matched_pairs'] == 20 and summary['expected_pairs'] == 20
assert summary['source_hashes']['sequence_receipt_sha256'] == sequence_sha
print('Training-012 matrix, clock audit, economics, reconciliation, and 20-pair summary validate.')
PY
```

Interpret the result against the registered application-benefit plan: report strict-positive Full-minus-Anchor savings, sampled break-even, spread, resource/storage costs, and whether the 20% total-savings target was met. Report a loss or an unestablished result plainly. The campaign is training measurement only; heldout freeze, fresh issuance, case acceptance, and heldout economics are separate gates. Earlier heldout runbooks have campaign-specific paths and are not a Training-012 heldout protocol. Separately timed component sums do not establish direct complete-arm timing.
