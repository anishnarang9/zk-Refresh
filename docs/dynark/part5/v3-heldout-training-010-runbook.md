# Heldout Training-010 runbook

This is a prospective run recipe, not a record that heldout work has run. It keeps the Training-009 and Training-010 campaign artifacts separate from the new heldout issuance and cases. Run each numbered block from the repository root in one Bash session. Run only one cohort or case job at a time, stop at the first failed gate, and never delete or replace an existing output to make a command fit.

## Observed prerequisites

- Training-010 campaign freeze: `results/dynark/part5/v3-campaign-freeze-003/freeze.json`, SHA-256 `3aa9c34057a44db5d040777c6e8ad94bf9fa567bf12f9260742b08ef5428c203`. Its identity manifest pins the isolated corrected proof executable at `artifacts/dynark/part5/v3-proof-runner-training-010`, SHA-256 `093659cec842945fd3db15e9e51087b5717d71dcb375fdf60ced58279a5ad19a`.
- The campaign identity manifest is `results/dynark/part5/v3-campaign-freeze-003/identity-manifest.json`, SHA-256 `e8f09c2fd84d9f2c69696b8d382e95d7498c7f2b9489e382b6cf8fc240db9ae7`; its `freeze_sha256` matches freeze-003.
- The Training-010 campaign cohort monitor at `artifacts/dynark/part5/v3-campaign-cohort-training-010-monitor-report.json` passed with exit 0, no stop or runner error, zero remaining owned processes, and known cleanup. Its eleven-leaf campaign cohort already exists. The heldout freeze must follow it so the earlier-key census includes those keys.
- The heldout queue runner exists at `artifacts/dynark/part5/v3-heldout-queue-runner-002`, SHA-256 `f82401e93c506eb1bdd8e2787a18bdbdbd5d948fc42a8f04a0cbeefe9ebe002c`, mode 0700. The heldout freeze and all eight case manifests must pin this exact runner path.
- The existing bootstrap status `artifacts/dynark/part5/application-v3-campaign-prepare-control-002/status.json` is failed with reviewed SIGINT cleanup, with `application_effect=false`, child reaped, and ledger review true. It is an input accepted by the heldout freeze's source and cleanup checks; it does not establish successful preparation or application acceptance. Recompute its source-manifest comparison immediately before freezing.
- At this preflight, these heldout outputs were absent: `results/dynark/part5/v3-heldout-freeze-training-010`, `artifacts/dynark/part5/v3-heldout-private-training-010`, `artifacts/dynark/part5/v3-heldout-run-manifests-training-010`, and the eight `artifacts/dynark/part5/v3-heldout-case-training-010-00` through `-07` directories. The commands below require them to remain absent until their creation step.

The campaign freeze and its stage, transition, or matrix evidence are not heldout inputs. The heldout boundary uses the prepare-002 status, the frozen product and application sources, the adapter, the explicit Training-010 proof executable, and the heldout runner-002. A fresh heldout freeze inventories all earlier public keys; no Training-009 heldout or campaign receipts are substituted.

## 0. Set paths and check the observed pins

```bash
set -euo pipefail
umask 077

ROOT=/Users/anishnarang/Zk-refresh
cd "$ROOT"
RESULTS="$ROOT/results/dynark/part5"
PART5="$ROOT/artifacts/dynark/part5"
CAMPAIGN_PY="$PART5/v3-campaign-python-002"
PREPARE_STATUS="$PART5/application-v3-campaign-prepare-control-002/status.json"
ADAPTER="$ROOT/crates/dynark-solana-adapter/target/debug/build/dynark-solana-adapter/3a4659842a713e9a/out/v3_request_bound_host-3a4659842a713e9a"
PROOF_BINARY="$PART5/v3-proof-runner-training-010"
RUNNER="$PART5/v3-heldout-queue-runner-002"
BASE_PREPARE_CONFIG="$PART5/application-v3-campaign-prepare-config-002.json"
PACKET_TEMPLATE="$PART5/v3-full-r1-proof-training-001/packet-003.json"
SUPERVISOR="$RESULTS/session_runner.py"
NODE=/Users/anishnarang/.nvm/versions/node/v24.10.0/bin/node
EXPORTER="$ROOT/program/target/debug/examples/export_v3_request_fixture"

sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
require_absent() {
  if [ -e "$1" ] || [ -L "$1" ]; then
    printf 'Expected fresh path is already present: %s\n' "$1" >&2
    return 1
  fi
}

test "$(git rev-parse --show-toplevel)" = "$ROOT"
test "$(sha256_file "$RESULTS/v3-campaign-freeze-003/freeze.json")" = \
  3aa9c34057a44db5d040777c6e8ad94bf9fa567bf12f9260742b08ef5428c203
test "$(sha256_file "$PROOF_BINARY")" = \
  093659cec842945fd3db15e9e51087b5717d71dcb375fdf60ced58279a5ad19a
test "$(sha256_file "$RUNNER")" = \
  f82401e93c506eb1bdd8e2787a18bdbdbd5d948fc42a8f04a0cbeefe9ebe002c
for f in "$CAMPAIGN_PY" "$PREPARE_STATUS" "$ADAPTER" "$PROOF_BINARY" "$RUNNER" \
         "$BASE_PREPARE_CONFIG" "$PACKET_TEMPLATE" "$SUPERVISOR" "$NODE" "$EXPORTER"; do
  test -f "$f"
done
test "$(sha256_file "$RESULTS/v3-campaign-freeze-003/identity-manifest.json")" = \
  e8f09c2fd84d9f2c69696b8d382e95d7498c7f2b9489e382b6cf8fc240db9ae7
for p in "$RESULTS/v3-heldout-freeze-training-010" \
         "$PART5/v3-heldout-private-training-010" \
         "$PART5/v3-heldout-run-manifests-training-010"; do
  require_absent "$p"
done
for V in 00 01 02 03 04 05 06 07; do
  require_absent "$PART5/v3-heldout-case-training-010-$V"
done

python3 -B - "$ROOT" "$PREPARE_STATUS" \
  "$PART5/v3-campaign-cohort-training-010-monitor-report.json" \
  "$RESULTS/v3-campaign-freeze-003/freeze.json" \
  "$RESULTS/v3-campaign-freeze-003/identity-manifest.json" \
  "$PART5/application-v3-campaign-cohort-training-010/cohort/cohort-receipt.json" <<'PY'
import hashlib, json, pathlib, sys
root, status_path, monitor_path, freeze_path, identity_path, cohort_path = map(pathlib.Path, sys.argv[1:])
sys.path.insert(0, str(root))
from harness.tests import queue_v3_build_prep

status = json.loads(status_path.read_bytes())
monitor = json.loads(monitor_path.read_bytes())
freeze = json.loads(freeze_path.read_bytes())
identity = json.loads(identity_path.read_bytes())
cohort = json.loads(cohort_path.read_bytes())
freeze_sha = hashlib.sha256(freeze_path.read_bytes()).hexdigest()
assert status.get('scope') == 'part5-v3-local-prepare'
assert status.get('status') == 'failed' and status.get('application_effect') is False
assert status.get('ledger_reuse_requires_review') is True
assert status.get('cleanup', {}).get('reaped') is True
current = queue_v3_build_prep.source_manifest(root)
current_sha = hashlib.sha256(json.dumps(current, sort_keys=True).encode()).hexdigest()
assert status.get('source_manifest_sha256') == current_sha
assert monitor.get('owner') == 'part5-v3-campaign-cohort-training-010'
assert monitor.get('passed') is True and monitor.get('exit_code') == 0
assert monitor.get('stop_reason') is None and monitor.get('runner_error_type') is None
assert monitor.get('cleanup_remaining_owned_processes') == 0
assert monitor.get('cleanup_status_unknown') is False
assert identity.get('freeze_sha256') == freeze_sha
assert cohort.get('schema') == 'v3-eleven-signed-training-credentials-v1'
assert cohort.get('training_only') is True and cohort.get('heldout_acceptance') is False
assert cohort.get('freeze_receipt_sha256') == freeze_sha
assert cohort.get('counts') == {
    'issuers': 1, 'holders': 11, 'certificates': 11, 'roots': 11}
assert identity['identity_inputs']['proof_runner'] == {
    'path': 'artifacts/dynark/part5/v3-proof-runner-training-010',
    'sha256': '093659cec842945fd3db15e9e51087b5717d71dcb375fdf60ced58279a5ad19a'}
print('Observed Training-010 prerequisites pass; prepare status remains failed with reviewed SIGINT cleanup.')
PY
```

The freeze includes current heldout registry/client and shared queue/transition sources. Let all related source edits settle before Step 1; any frozen source change afterward requires a new fresh freeze and cohort. Do not overwrite the campaign proof executable or use the canonical Training-009 proof path.

## 0.5. Gate on the completed Training-010 matrix and total-cost summary

This is a required pre-freeze gate, not a claim that the matrix or summary has passed. Wait until the serial matrix driver exits 0 and publishes its final sequence receipt. The freeze tool does not enforce matrix completion. The commands below use the registered Training-010 manifest and output root; the read-only audit revalidates all 60 slot receipts and the sequence, checks the economics input against the registered plan, and recomputes the reconciliation and summary from their pinned inputs.

After matrix completion, run this gate immediately before Step 1 with the
interpreter pinned in the matrix manifest. Its validator rejects `python3` if
that resolves to a different executable. The gate creates each missing report
in dependency order and preserves existing reports, so a later report can be
retried if an earlier command succeeded before a failure. The read-only audit
at the end validates the full chain.

```bash
MATRIX="$RESULTS/v3-campaign-matrix-training-010.json"
MATRIX_OUTPUT="$PART5/v3-matrix-training-010"
ECONOMICS_INPUT="$MATRIX_OUTPUT/economics-input-manifest.json"
ECONOMICS_REPORT="$RESULTS/v3-campaign-economics-training-010.json"
RECONCILIATION_REPORT="$RESULTS/v3-campaign-cost-reconciliation-training-010.json"
TOTAL_SUMMARY="$RESULTS/v3-campaign-total-cost-training-010.json"

test -s "$ECONOMICS_INPUT"
ensure_report() {
  local path="$1"
  shift
  if [ -L "$path" ]; then
    printf 'Refusing symlink report path: %s\n' "$path" >&2
    return 1
  elif [ -e "$path" ]; then
    test -f "$path" && test -s "$path"
  else
    "$@"
    test -f "$path" && test -s "$path"
  fi
}
ensure_report "$ECONOMICS_REPORT" "$CAMPAIGN_PY" -B tools/part5/analyze_v3_campaign_economics.py \
  --manifest "$ECONOMICS_INPUT" --output "$ECONOMICS_REPORT"
ensure_report "$RECONCILIATION_REPORT" "$CAMPAIGN_PY" -B tools/part5/reconcile_v3_campaign_costs.py \
  --matrix-manifest "$MATRIX" --economics-report "$ECONOMICS_REPORT" \
  --output "$RECONCILIATION_REPORT"
ensure_report "$TOTAL_SUMMARY" "$CAMPAIGN_PY" -B tools/part5/summarize_v3_campaign_total.py \
  --reconciliation-report "$RECONCILIATION_REPORT" \
  --matrix-manifest "$MATRIX" --economics-report "$ECONOMICS_REPORT" \
  --output "$TOTAL_SUMMARY"

"$CAMPAIGN_PY" -B - "$ROOT" "$MATRIX" "$MATRIX_OUTPUT" "$ECONOMICS_INPUT" \
  "$ECONOMICS_REPORT" "$RECONCILIATION_REPORT" "$TOTAL_SUMMARY" <<'PY'
import json, pathlib, sys
root, matrix_path, output_root, economics_input, economics_report, reconciliation_report, total_summary = map(pathlib.Path, sys.argv[1:])
sys.path.insert(0, str(root))
from tools.part5 import run_v3_campaign_matrix as matrix
from tools.part5 import reconcile_v3_campaign_costs as costs
from tools.part5 import summarize_v3_campaign_total as total

validated = matrix.validate_manifest(matrix_path)
assert validated['campaign_id'] == 'training-010'
assert pathlib.Path(validated['output_root']).resolve(strict=True) == output_root.resolve(strict=True)
sequence_sha = costs.verify_completed_matrix(validated)
planned = matrix.plan_slots(validated)
assert len(planned) == 60
assert matrix.read_json(economics_input) == matrix.economics_input_manifest(planned)

economics = matrix.read_json(economics_report)
expected_reconciliation = costs.reconcile(validated, economics)
expected_reconciliation['economics_report_sha256'] = matrix.sha256(economics_report)
assert matrix.read_json(reconciliation_report) == expected_reconciliation
summary = total.load_and_summarize(reconciliation_report, matrix_path, economics_report)
assert json.loads(total_summary.read_bytes()) == summary
assert summary['matrix_grid_complete'] is True
assert summary['matched_pairs'] == 20 and summary['expected_pairs'] == 20
assert summary['source_hashes']['sequence_receipt_sha256'] == sequence_sha
print('Training-010 matrix receipts, economics inputs, reconciliation, and 20-pair total-cost summary validate.')
PY
```

## 1. Freeze the heldout boundary and prior-key inventory

The freeze command itself checks the current prepare source manifest and frozen product identities. Its output directory must be a fresh direct child of `results/dynark/part5`; the tool publishes `freeze.json` and its paired `prior-key-inventory.json` as owner-only files.

```bash
FREEZE_DIR="$RESULTS/v3-heldout-freeze-training-010"
require_absent "$FREEZE_DIR"
python3 -B tools/part5/freeze_v3_heldout_cohort.py \
  --prepare-status "$PREPARE_STATUS" \
  --adapter-binary "$ADAPTER" \
  --proof-binary "$PROOF_BINARY" \
  --output-dir "$FREEZE_DIR"

FREEZE="$FREEZE_DIR/freeze.json"
INVENTORY="$FREEZE_DIR/prior-key-inventory.json"
FREEZE_SHA="$(sha256_file "$FREEZE")"
INVENTORY_SHA="$(sha256_file "$INVENTORY")"
python3 -B - "$FREEZE" "$INVENTORY" "$PROOF_BINARY" "$FREEZE_SHA" <<'PY'
import hashlib, json, pathlib, sys
freeze_path, inventory_path, proof_path = map(pathlib.Path, sys.argv[1:4])
freeze = json.loads(freeze_path.read_bytes())
inventory = json.loads(inventory_path.read_bytes())
freeze_sha = hashlib.sha256(freeze_path.read_bytes()).hexdigest()
proof_sha = hashlib.sha256(proof_path.read_bytes()).hexdigest()
assert freeze_sha == sys.argv[4]
assert freeze['schema'] == 'credential-v3-frozen-holdout-boundary-v1'
assert freeze['identities']['proof_runner'] == proof_sha
assert inventory['freeze_sha256'] == freeze_sha
assert inventory['schema'] == 'credential-v3-prior-public-key-inventory-v1'
print('Heldout freeze and prior-key inventory pins pass.')
PY
```

Do not edit any frozen source or add earlier-key material after this point. The cohort command below validates both receipt hashes and creates keys/certificates strictly after the recorded freeze.

## 2. Create the cohort through the parent observer

The observer launches `build_v3_heldout_cohort` and checks the resulting scrubbed receipt. Do not call the builder separately. It expects a fresh ignored owner-only parent directly under `artifacts/dynark/part5`, with sibling cohort and observation destinations. It has a fixed 900-second child timeout. The external session-runner owner below adds a 1,020-second whole-tree limit, 4 GiB RSS cap, and 256 MiB storage-growth cap, and saves an outer cleanup receipt. Its private monitor output is a sibling of the cohort private root so monitored storage roots remain disjoint. The observer receipt records local process chronology; it does not observe OpenSSL internals or establish application acceptance.

```bash
PRIVATE_ROOT="$PART5/v3-heldout-private-training-010"
COHORT_ROOT="$PRIVATE_ROOT/v3-heldout-cohort"
OBSERVATION="$PRIVATE_ROOT/v3-heldout-cohort-observation.json"
COHORT_MONITOR_HOME="$PART5/v3-heldout-cohort-training-010-monitor"
COHORT_OUTER_REPORT="$RESULTS/v3-heldout-cohort-training-010-bounded.json"
COHORT_OWNER=part5-v3-heldout-cohort-training-010
require_absent "$COHORT_MONITOR_HOME"
require_absent "$COHORT_OUTER_REPORT"
require_absent "$PRIVATE_ROOT"
git check-ignore -q "$PRIVATE_ROOT"
mkdir -m 700 "$PRIVATE_ROOT"
python3 -B "$SUPERVISOR" \
  --owner "$COHORT_OWNER" --cwd "$ROOT" \
  --private-output "$COHORT_MONITOR_HOME" --report "$COHORT_OUTER_REPORT" \
  --runtime-seconds 1020 --rss-bytes 4294967296 --storage-bytes 268435456 \
  --storage-path "$PRIVATE_ROOT" --poll-seconds 0.2 -- \
  python3 -B tools/part5/observe_v3_heldout_cohort.py \
  --freeze "$FREEZE" --freeze-sha256 "$FREEZE_SHA" \
  --prior-key-inventory "$INVENTORY" \
  --prior-key-inventory-sha256 "$INVENTORY_SHA" \
  --output "$COHORT_ROOT" --observation "$OBSERVATION"

python3 -B - "$COHORT_OUTER_REPORT" "$COHORT_OWNER" <<'PY'
import json, pathlib, sys
report = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
assert report['schema'] == 1 and report['owner'] == sys.argv[2]
assert report['measurement'] == 'bounded_complete_session'
assert report['passed'] is True and report['exit_code'] == 0
assert report['censored'] is False
assert report['stop_reason'] is None and report['runner_error_type'] is None
assert report['cleanup_remaining_owned_processes'] == 0
assert report['cleanup_status_unknown'] is False
assert report['limits'] == {'runtime_seconds': 1020.0,
    'owned_tree_rss_bytes': 4294967296, 'storage_growth_bytes': 268435456,
    'poll_seconds': 0.2}
print('Heldout cohort outer owner, resource caps, and cleanup gate pass.')
PY
```

Gate the new cohort before manifest creation: require `cohort-receipt.json` to have schema `credential-v3-heldout-issuance-cohort-v1`, eight certificates, eight holders, four issuers, four OpenSSL issuances, complete variants 0–7, identities equal to the freeze, and matching freeze/inventory SHA-256s. Require the observation to pin that receipt and show child exit 0 with post-freeze parent-started chronology. Keep all private cohort material under the ignored 0700 root.

## 3. Build eight manifests with the same isolated proof binary

This step is lightweight manifest construction. It validates the freeze, cohort observation, current source identities, and all executable pins before writing a fresh direct child of `artifacts/dynark/part5`.

```bash
RUN_MANIFESTS="$PART5/v3-heldout-run-manifests-training-010"
require_absent "$RUN_MANIFESTS"
git check-ignore -q "$RUN_MANIFESTS"
python3 -B tools/part5/build_v3_heldout_run_manifest.py \
  --freeze-receipt "$FREEZE" \
  --cohort-root "$COHORT_ROOT" \
  --cohort-observation "$OBSERVATION" \
  --base-prepare-config "$BASE_PREPARE_CONFIG" \
  --packet-template "$PACKET_TEMPLATE" \
  --adapter-binary "$ADAPTER" \
  --bounded-supervisor "$SUPERVISOR" \
  --node "$NODE" --exporter "$EXPORTER" \
  --runner "$RUNNER" --proof-binary "$PROOF_BINARY" \
  --output-dir "$RUN_MANIFESTS"
```

Before running cases, verify `case-00.json` through `case-07.json` exist and each pins both `frozen_files.proof_runner` and `proof_inputs.proof_runner` to the same Training-010 executable path and hash as the heldout freeze. The manifest builder enforces the runner-002 path and byte hash.

## 4. Run cases serially

Each case runs one certificate through the local application gate and records a resumable journal and acceptance fragment. Within one case, validator, clone, and application sessions run serially under 180-second owners with 4 GiB RSS and 256 MiB storage-growth caps. Proof preparation has separate bounded owners: each witness generation has 300 seconds, each relation check 600 seconds, and each adapter job 600 seconds; each has 4 GiB RSS and 512 MiB storage-growth caps. Full proof jobs have 1,800 seconds and Anchor proof jobs 3,600 seconds, each with 4 GiB RSS and 512 MiB storage-growth caps. These are per-child ceilings, not predicted runtime or a whole-case deadline.

The direct case command has no whole-case global deadline or cross-case/global heavy-job lock. Its journal lock serializes cooperating invocations for that same output root only. Run exactly one case command at a time, with no campaign, validator, build, or other heavy job running concurrently; do not background the loop or launch another variant from another session. Validator port guards detect occupied ports but do not reserve a global execution lease. Wait for the preceding owner to finish and prove cleanup before starting the observer or a case. There is no observed heldout case duration yet. The loop below is fresh-run only because it requires each case root to be absent. If a case fails, stop the loop, inspect its journal and saved inputs, and after review retry only that case directly against the same manifest and existing output root; do not rerun the loop or create a replacement root.

```bash
for V in 00 01 02 03 04 05 06 07; do
  CASE_ROOT="$PART5/v3-heldout-case-training-010-$V"
  require_absent "$CASE_ROOT"
  git check-ignore -q "$CASE_ROOT"
  python3 -B tools/part5/run_v3_heldout_case.py \
    --manifest "$RUN_MANIFESTS/case-$V.json" \
    --output-root "$CASE_ROOT"
done
```

For a reviewed retry of an existing case journal, replace `03` with the failed case number and use the same manifest/root directly, omitting the loop's `require_absent` guard:

```bash
V=03
python3 -B tools/part5/run_v3_heldout_case.py \
  --manifest "$RUN_MANIFESTS/case-$V.json" \
  --output-root "$PART5/v3-heldout-case-training-010-$V"
```

Proceed only after all eight commands exit successfully and produce one `acceptance-case-fragment.json` each. Confirm fragment variants cover 0–7 and every case journal is complete before acceptance work.

## 5. Acceptance verification, cost analysis, and reporting

These are post-case gates. Do not assemble acceptance inputs, verify acceptance,
analyze costs, or write a heldout result report until all eight cases pass. The
assembler requires eight distinct, explicitly hash-pinned fragments. The
independent verifier must pass before cost analysis. The cost analyzer reports
matched heldout request-B wall costs; it does not infer CPU savings or choose
an economic winner. The final model combines those direct `k = 1` heldout
deltas with the sampled Training-010 update-count deltas. Its other heldout
counts are conditional estimates, not new heldout runs or a measured heldout
break-even. Final reporting must preserve the verifier outcome and cost
limitations and must not claim acceptance or economics from
freeze/cohort/manifests alone.

```bash
ASSEMBLED_DIR="$PART5/v3-heldout-assembled-training-010"
ASSEMBLED_MANIFEST="$ASSEMBLED_DIR/heldout-acceptance-manifest.json"
ACCEPTANCE_REPORT="$RESULTS/v3-heldout-acceptance-training-010.json"
COST_REPORT="$RESULTS/v3-heldout-cost-analysis-training-010.json"
MODEL_REPORT="$RESULTS/v3-heldout-conditional-break-even-training-010.json"
require_absent "$ASSEMBLED_DIR"
require_absent "$ACCEPTANCE_REPORT"
require_absent "$COST_REPORT"
require_absent "$MODEL_REPORT"
git check-ignore -q "$ASSEMBLED_DIR"

FRAGMENTS=()
for V in 00 01 02 03 04 05 06 07; do
  FRAGMENT="$PART5/v3-heldout-case-training-010-$V/acceptance-case-fragment.json"
  test -f "$FRAGMENT"
  FRAGMENT_SHA="$(sha256_file "$FRAGMENT")"
  FRAGMENTS+=(--fragment "$FRAGMENT:$FRAGMENT_SHA")
done
python3 -B tools/part5/assemble_v3_heldout_acceptance.py \
  "${FRAGMENTS[@]}" --output-dir "$ASSEMBLED_DIR"

ASSEMBLED_SHA="$(sha256_file "$ASSEMBLED_MANIFEST")"
python3 -B tools/part5/verify_v3_heldout_acceptance.py \
  --manifest "$ASSEMBLED_MANIFEST" --output "$ACCEPTANCE_REPORT"
ACCEPTANCE_SHA="$(sha256_file "$ACCEPTANCE_REPORT")"
python3 -B tools/part5/analyze_v3_heldout_costs.py \
  --manifest "$ASSEMBLED_MANIFEST:$ASSEMBLED_SHA" \
  --acceptance-report "$ACCEPTANCE_REPORT:$ACCEPTANCE_SHA" \
  --output "$COST_REPORT"
COST_SHA="$(sha256_file "$COST_REPORT")"
TOTAL_SHA="$(sha256_file "$TOTAL_SUMMARY")"
python3 -B tools/part5/model_v3_heldout_break_even.py \
  --heldout-cost-report "$COST_REPORT:$COST_SHA" \
  --training-total-summary "$TOTAL_SUMMARY:$TOTAL_SHA" \
  --output "$MODEL_REPORT"
test -s "$MODEL_REPORT"
```

No command in this runbook has been executed for heldout freeze, issuance,
manifests, cases, acceptance, direct costs, or the conditional model. Those
results remain prospective until their output gates pass.
