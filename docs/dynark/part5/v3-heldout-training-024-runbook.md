# Heldout Training-024 recovery runbook

Training-023 case 00 failed at pre-stop ambiguous-restart reconciliation after 48.3 seconds: the supervisor interpreted config account data bytes as the config account public key when checking the finalized request and queue. Preserve every Training-023 root and report; do not continue Training-023 cases 01–07 or retry its private case root. Training-024 requires a fresh source freeze, cohort, manifests, and case roots after review of the staged-config-public-key fix. No Training-023 output can be reused as Training-024 acceptance evidence. The registered 60-slot economics comparison remains Training-012. See the preserved [Training-023 runbook](v3-heldout-training-023-runbook.md).

The commands below are a prospective serial execution plan. Run the numbered blocks in one Bash session so later blocks retain the paths and hashes set earlier. Stop at the first failed gate, preserve every failed root, and run only one proof, validator, build, or case job at a time under the stable heavy-job lock. The Step 0 source pins include the finality-before-shutdown repair and the staged-config-public-key correction; source pins alone do not establish a passing case.

## Shared prerequisites and prospective outputs

- Training-010 campaign freeze: `results/dynark/part5/v3-campaign-freeze-003/freeze.json`, SHA-256 `3aa9c34057a44db5d040777c6e8ad94bf9fa567bf12f9260742b08ef5428c203`. Its identity manifest pins the isolated corrected proof executable at `artifacts/dynark/part5/v3-proof-runner-training-010`, SHA-256 `093659cec842945fd3db15e9e51087b5717d71dcb375fdf60ced58279a5ad19a`.
- The campaign identity manifest is `results/dynark/part5/v3-campaign-freeze-003/identity-manifest.json`, SHA-256 `e8f09c2fd84d9f2c69696b8d382e95d7498c7f2b9489e382b6cf8fc240db9ae7`; its `freeze_sha256` matches freeze-003.
- The Training-010 campaign cohort monitor at `artifacts/dynark/part5/v3-campaign-cohort-training-010-monitor-report.json` passed with exit 0, no stop or runner error, zero remaining owned processes, and known cleanup. Its eleven-leaf campaign cohort already exists. The heldout freeze must follow it so the earlier-key census includes those keys.
- The heldout queue runner exists at `artifacts/dynark/part5/v3-heldout-queue-runner-002`, SHA-256 `f82401e93c506eb1bdd8e2787a18bdbdbd5d948fc42a8f04a0cbeefe9ebe002c`, mode 0700. The heldout freeze and all eight case manifests must pin this exact runner path.
- The existing bootstrap status `artifacts/dynark/part5/application-v3-campaign-prepare-control-002/status.json` is failed with reviewed SIGINT cleanup, with `application_effect=false`, child reaped, and ledger review true. It is an input accepted by the heldout freeze's source and cleanup checks; it does not establish successful preparation or application acceptance. Recompute its source-manifest comparison immediately before freezing.
- These new heldout output paths must be absent: `results/dynark/part5/v3-heldout-freeze-training-024`, `artifacts/dynark/part5/v3-heldout-private-training-024`, `artifacts/dynark/part5/v3-heldout-run-manifests-training-024`, and the eight `artifacts/dynark/part5/v3-heldout-case-training-024-00` through `-07` directories. The commands below require them to be absent until their creation step; their absence is checked at execution time.
- Preserve all historical Training-017 through Training-023 roots and reports, including failed cases and the Training-022 cloned-ledger diagnostic. They are preserved history, not fresh Training-024 destinations.

Heldout acceptance retains the existing Training-010 v1 proof/setup path: the shared setup at `artifacts/dynark/part5/v3-development-setup-001` and explicit proof executable at `artifacts/dynark/part5/v3-proof-runner-training-010`. This runbook does not claim clean-checkout v2 reproduction. The shared campaign source/setup freeze remains freeze-003. Campaign stage, transition, and matrix receipts are not heldout issuance inputs. Training-012 completion and its clock/economics chain are mandatory procedural pre-freeze gates; the freeze CLI does not enforce them. The heldout boundary uses the prepare-002 status, the frozen product and application sources, the adapter, the explicit Training-010 proof executable, and the heldout runner-002. The fresh Training-024 heldout freeze inventories all earlier public keys, including the public keys retained by preserved heldout attempts through Training-023; no Training-009 heldout or campaign receipts are substituted.

## 0. Set paths and check the observed pins

```bash
set -euo pipefail
umask 077

ROOT="$(git rev-parse --show-toplevel)"
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
NODE="$(command -v node)"
EXPORTER="$ROOT/program/target/debug/examples/export_v3_request_fixture"

sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
require_absent() {
  if [ -e "$1" ] || [ -L "$1" ]; then
    printf 'Expected fresh path is already present: %s\n' "$1" >&2
    return 1
  fi
}

test "$(git rev-parse --show-toplevel)" = "$ROOT"
test "$("$NODE" --version)" = v24.10.0
test "$(sha256_file "$ROOT/tools/part5/prepare_v3_heldout_source.py")" = \
  2e6bb1e4f6ffd5fee2ed7a66bacd966554b53ab5464fd8b3f20e46d71717fcdc
test "$(sha256_file "$ROOT/tools/part5/prepare_v3_heldout_proof.py")" = \
  5a811fb37f39b5218186fe62e7d5c6b38503d6b5558e5ed3c1c17666a82b3034
test "$(sha256_file "$ROOT/harness/tests/queue_v3_local_disabled_config_negative.py")" = \
  dd8e1991e271cbe5c729171d057ba9cf88276dcbc483e3902f6625181ae518f6
test "$(sha256_file "$ROOT/tools/part5/run_v3_heldout_case.py")" = \
  2bb15b8c2413d229863f7923cf0095a95719f72122c1a70bab19232e643771f5
test "$(sha256_file "$ROOT/harness/tests/queue_v3_local_ambiguous_restart.py")" = \
  8f8e64aa83b4397d7fdc0d5236237b13992f03bc0fb4df13e867262f0dcf1780
test "$(sha256_file "$ROOT/tools/part5/verify_v3_heldout_acceptance.py")" = \
  69a35f42662bf3da85a89ecdc0f63fd12678b3f95565836c40103b6e2135f3c4
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
for p in "$RESULTS/v3-heldout-freeze-training-024" \
         "$PART5/v3-heldout-private-training-024" \
         "$PART5/v3-heldout-run-manifests-training-024"; do
  require_absent "$p"
done
for V in 00 01 02 03 04 05 06 07; do
  require_absent "$PART5/v3-heldout-case-training-024-$V"
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
for role, pin in identity['identity_inputs'].items():
    path = root / pin['path']
    assert hashlib.sha256(path.read_bytes()).hexdigest() == pin['sha256'], role
for group in ('registry_members', 'client_members'):
    for pin in identity[group]:
        assert hashlib.sha256((root / pin['path']).read_bytes()).hexdigest() == pin['sha256'], group
assert identity['application_manifest'] == current
assert cohort.get('schema') == 'v3-eleven-signed-training-credentials-v1'
assert cohort.get('training_only') is True and cohort.get('heldout_acceptance') is False
assert cohort.get('freeze_receipt_sha256') == freeze_sha
assert cohort.get('counts') == {
    'issuers': 1, 'holders': 11, 'certificates': 11, 'roots': 11}
assert identity['identity_inputs']['proof_runner'] == {
    'path': 'artifacts/dynark/part5/v3-proof-runner-training-010',
    'sha256': '093659cec842945fd3db15e9e51087b5717d71dcb375fdf60ced58279a5ad19a'}
print('Shared Training-010 product/cohort prerequisites pass; prepare status remains failed with reviewed SIGINT cleanup.')
PY
python3 -B -m unittest tools.part5.tests.test_prepare_v3_heldout_proof
python3 -B -m unittest harness.tests.test_queue_v3_local_disabled_config_negative
python3 -B -m unittest harness.tests.test_queue_v3_local_ambiguous_restart
ruff check --select F821 tools/part5/prepare_v3_heldout_proof.py \
  harness/tests/queue_v3_local_ambiguous_restart.py
python3 -B -m pytest -q tools/part5/tests/test_prepare_v3_heldout_source.py \
  tools/part5/tests/test_prepare_v3_heldout_context.py \
  harness/tests/test_queue_v3_local_transition.py
python3 -B -m pytest -q tools/part5/tests/test_run_v3_heldout_case.py \
  tools/part5/tests/test_verify_v3_heldout_acceptance.py \
  tools/part5/tests/test_analyze_v3_heldout_costs.py
ruff check --select F821 tools/part5/run_v3_heldout_case.py \
  tools/part5/verify_v3_heldout_acceptance.py
```

The freeze includes current heldout registry/client and shared queue/transition sources. Let all related source edits settle before Step 1; any frozen source change afterward requires a new fresh freeze and cohort. Do not overwrite the campaign proof executable or use the canonical Training-009 proof path.

## 0.5. Require the completed Training-012 matrix, clock audit, and audited total-cost chain

The Training-012 matrix completed 60 contiguous slots and its clock, economics, reconciliation, and total-cost chain passed before the first heldout attempt. Revalidate that existing chain read-only immediately before Step 1; do not relaunch the matrix. The heldout freeze CLI does not enforce campaign completion, clock passage, or cost reconciliation.

This gate creates no campaign or heldout reports, keys, or freeze. Missing matrix receipts or reports are inputs still to be produced by the campaign runbook; do not invent hashes or results. It revalidates all 60 receipts, the sequence, and the planned economics input; recomputes the clock audit at its recorded tolerance (at most five seconds); and recomputes economics, reconciliation, and the 20-pair summary. Any incomplete or mismatched item stops heldout work. Preserve failure evidence. A passing clock audit does not establish CPU accounting or absence of suspension. A measured loss or no established benefit may proceed to heldout evaluation; do not require or claim a profitable result.

```bash
MATRIX="$RESULTS/v3-campaign-matrix-training-012.json"
MATRIX_OUTPUT="$PART5/v3-matrix-training-012"
ECONOMICS_INPUT="$MATRIX_OUTPUT/economics-input-manifest.json"
CLOCK_REPORT="$RESULTS/v3-campaign-clock-drift-training-012.json"
ECONOMICS_REPORT="$RESULTS/v3-campaign-economics-training-012.json"
RECONCILIATION_REPORT="$RESULTS/v3-campaign-cost-reconciliation-training-012.json"
TOTAL_SUMMARY="$RESULTS/v3-campaign-total-cost-training-012.json"

test "$(sha256_file "$CAMPAIGN_PY")" = \
  4fce274f0e60574ada0b53f17bceb49bbd804125ddae972c7674b8eb13d9e49d
test "$(sha256_file "$MATRIX")" = \
  21612a6451c00b7a46d9abaa3445e5acecec3c14583317884800b49b2614ff53
test "$(sha256_file "$MATRIX_OUTPUT/input-manifest.json")" = \
  21612a6451c00b7a46d9abaa3445e5acecec3c14583317884800b49b2614ff53
test "$(sha256_file "$MATRIX_OUTPUT/matrix-plan.json")" = \
  e1cd1b9eb1c08fed70cd7544b0286af82422eb50a49a63875be267b57907f467
test "$(sha256_file "$ROOT/tools/part5/run_v3_campaign_matrix.py")" = \
  dee858b687dcb657814d98d376c9510136e3d16a4a38bd5c40d320933e0781ba
for f in "$ECONOMICS_INPUT" "$CLOCK_REPORT" "$ECONOMICS_REPORT" \
         "$RECONCILIATION_REPORT" "$TOTAL_SUMMARY"; do
  test ! -L "$f" && test -f "$f" && test -s "$f"
done

"$CAMPAIGN_PY" -B - "$ROOT" "$MATRIX" "$MATRIX_OUTPUT" "$ECONOMICS_INPUT" \
  "$CLOCK_REPORT" "$ECONOMICS_REPORT" "$RECONCILIATION_REPORT" "$TOTAL_SUMMARY" <<'PY_GATE'
import json, pathlib, sys
root, matrix_path, output_root, economics_input, clock_path, economics_path, reconciliation_path, total_path = map(pathlib.Path, sys.argv[1:])
sys.path.insert(0, str(root))
from tools.part5 import run_v3_campaign_matrix as matrix
from tools.part5 import audit_v3_campaign_clock_drift as clock_audit
from tools.part5 import analyze_v3_campaign_economics as economics_analysis
from tools.part5 import reconcile_v3_campaign_costs as costs
from tools.part5 import summarize_v3_campaign_total as total

validated = matrix.validate_manifest(matrix_path)
assert validated['campaign_id'] == 'training-012'
assert pathlib.Path(validated['output_root']).resolve(strict=True) == output_root.resolve(strict=True)
sequence_sha = costs.verify_completed_matrix(validated)
planned = matrix.plan_slots(validated)
assert len(planned) == 60
assert len(matrix.read_json(output_root / 'sequence-receipt.json')['sequence']) == 60
assert matrix.read_json(economics_input) == matrix.economics_input_manifest(planned)
clock = matrix.read_json(clock_path)
assert clock['schema'] == 'part5-v3-campaign-clock-drift-v1'
assert clock['passed'] is True and clock['slot_count'] == 60
assert clock['tolerance_seconds'] <= 5.0
assert clock['matrix_manifest_sha256'] == validated['manifest_sha256']
assert clock['sequence_receipt_sha256'] == sequence_sha
assert clock == clock_audit.audit(matrix_path, clock['tolerance_seconds'])
economics = matrix.read_json(economics_path)
expected_economics = economics_analysis.aggregate(matrix.read_json(economics_input), economics_input.parent)
expected_economics['input_manifest_sha256'] = matrix.sha256(economics_input)
assert economics == expected_economics
expected = costs.reconcile(validated, economics)
expected['economics_report_sha256'] = matrix.sha256(economics_path)
assert matrix.read_json(reconciliation_path) == json.loads(json.dumps(expected))
summary = total.load_and_summarize(reconciliation_path, matrix_path, economics_path)
assert json.loads(total_path.read_bytes()) == summary
assert summary['matrix_grid_complete'] is True
assert summary['matched_pairs'] == 20 and summary['expected_pairs'] == 20
assert summary['source_hashes']['sequence_receipt_sha256'] == sequence_sha
print('Training-012 60 receipts, passing clock audit, economics, reconciliation, and total summary validate.')
PY_GATE
```

## 1. Freeze the heldout boundary and prior-key inventory

The freeze command itself checks the current prepare source manifest and frozen product identities. Its output directory must be a fresh direct child of `results/dynark/part5`; the tool publishes `freeze.json` and its paired `prior-key-inventory.json` as owner-only files.

```bash
FREEZE_DIR="$RESULTS/v3-heldout-freeze-training-024"
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
PRIVATE_ROOT="$PART5/v3-heldout-private-training-024"
COHORT_ROOT="$PRIVATE_ROOT/v3-heldout-cohort"
OBSERVATION="$PRIVATE_ROOT/v3-heldout-cohort-observation.json"
COHORT_MONITOR_HOME="$PART5/v3-heldout-cohort-training-024-monitor"
COHORT_OUTER_REPORT="$RESULTS/v3-heldout-cohort-training-024-bounded.json"
COHORT_OWNER=part5-v3-heldout-cohort-training-024
LOCKFILE="$PART5/.v3-heldout-heavy.lock"
require_absent "$COHORT_MONITOR_HOME"
require_absent "$COHORT_OUTER_REPORT"
require_absent "$PRIVATE_ROOT"
git check-ignore -q "$PRIVATE_ROOT"
test ! -L "$LOCKFILE"
if test ! -e "$LOCKFILE"; then
  (umask 077; : > "$LOCKFILE")
fi
test -f "$LOCKFILE"
/usr/bin/lockf -t 0 -k "$LOCKFILE" /bin/bash -c '
set -euo pipefail
umask 077
PRIVATE_ROOT="$1"; COHORT_MONITOR_HOME="$2"; COHORT_OUTER_REPORT="$3"
if test -e "$PRIVATE_ROOT" || test -L "$PRIVATE_ROOT" ||
   test -e "$COHORT_MONITOR_HOME" || test -L "$COHORT_MONITOR_HOME" ||
   test -e "$COHORT_OUTER_REPORT" || test -L "$COHORT_OUTER_REPORT"; then
  printf "Cohort output appeared before lock acquisition.\n" >&2
  exit 1
fi
mkdir -m 700 "$PRIVATE_ROOT"
exec python3 -B "$4" \
  --owner "$5" --cwd "$6" \
  --private-output "$COHORT_MONITOR_HOME" --report "$COHORT_OUTER_REPORT" \
  --runtime-seconds 1020 --rss-bytes 4294967296 --storage-bytes 268435456 \
  --storage-path "$PRIVATE_ROOT" --poll-seconds 0.2 -- \
  python3 -B tools/part5/observe_v3_heldout_cohort.py \
  --freeze "$7" --freeze-sha256 "$8" \
  --prior-key-inventory "$9" \
  --prior-key-inventory-sha256 "${10}" \
  --output "${11}" --observation "${12}"
' cohort-owner "$PRIVATE_ROOT" "$COHORT_MONITOR_HOME" "$COHORT_OUTER_REPORT" \
  "$SUPERVISOR" "$COHORT_OWNER" "$ROOT" "$FREEZE" "$FREEZE_SHA" \
  "$INVENTORY" "$INVENTORY_SHA" "$COHORT_ROOT" "$OBSERVATION"

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
RUN_MANIFESTS="$PART5/v3-heldout-run-manifests-training-024"
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

Each case runs one certificate through the local application gate and records a resumable journal and acceptance fragment. Within one case, validator, clone, and application-session children other than the disabled-config negative run serially under 180-second owners with 4 GiB RSS and 256 MiB storage-growth caps. The disabled-config negative has a 270-second outer owner cap with the same 4 GiB RSS and 256 MiB storage-growth caps; inside it, the supervisor budget is 255 seconds and the Rust runner deadline is 210 seconds. These are nested ceilings, not additive time allowances. Proof preparation has separate bounded owners: each witness generation has 300 seconds, each relation check 600 seconds, and each adapter job 600 seconds; each has 4 GiB RSS and 512 MiB storage-growth caps. Full proof jobs have 1,800 seconds and Anchor proof jobs 3,600 seconds, each with 4 GiB RSS and 512 MiB storage-growth caps. These are per-child ceilings, not predicted runtime or a whole-case deadline.

The current runner records `positive_full:stage`, then completes `positive_full:r0-clone`, `positive_full:disabled-config-clone`, and `positive_full:ambiguous-restart-clone`, before starting `positive_full:transition`; the acceptance verifier rejects a journal that does not show this chronology. This preserves all three R0 ledgers before the transition mutates the shared original ledger. The direct case command has no whole-case global deadline or cross-case/global heavy-job lock. Its journal lock serializes cooperating invocations for that same output root only. Run exactly one case command at a time, with no campaign, validator, build, or other heavy job running concurrently; do not background the unguarded loop or launch another variant from another session. Validator port guards detect occupied ports but do not reserve a global execution lease. Wait for the preceding owner to finish and prove cleanup before starting the observer or a case. The loop below is fresh-run only because it requires each case root to be absent. If a case fails, stop the loop and inspect its journal, status, outer monitor, and saved inputs. Resume the same manifest/root only when the recorded partial outputs satisfy the runner's reuse checks. A step left `running` with unknown work time, as in Training-021, is not resumable. Never remove or replace failed output to force a retry.

```bash
for V in 00 01 02 03 04 05 06 07; do
  CASE_ROOT="$PART5/v3-heldout-case-training-024-$V"
  require_absent "$CASE_ROOT"
  git check-ignore -q "$CASE_ROOT"
  python3 -B -m tools.part5.run_v3_heldout_case \
    --manifest "$RUN_MANIFESTS/case-$V.json" \
    --output-root "$CASE_ROOT"
done
```

For a long run owned by an interactive tool session, launch **one** fresh case in a detached `tmux` session instead of running the loop above. The private owner keeps its logs and atomic exit code outside the case root. The stable `lockf` inode prevents another cooperating heldout case from starting concurrently. This is an operational owner around the same case command; it does not replace any bounded child monitor or add a whole-case measurement. Set `V` to the next case only after the prior case's exit, journal, fragment, and child cleanup have been reviewed.

```bash
V=00
SESSION="v3-heldout-training-024-$V"
CASE_ROOT="$PART5/v3-heldout-case-training-024-$V"
MANIFEST="$RUN_MANIFESTS/case-$V.json"
LAUNCH="$PART5/v3-heldout-launch-training-024-$V"
LOCKFILE="$PART5/.v3-heldout-heavy.lock"
require_absent "$CASE_ROOT"
require_absent "$LAUNCH"
git check-ignore -q "$LAUNCH"
test -f "$MANIFEST" && test ! -L "$MANIFEST"
if tmux has-session -t "$SESSION" 2>/dev/null; then
  printf 'Case owner is already active: %s\n' "$SESSION" >&2
  exit 1
fi
test ! -L "$LOCKFILE"
if test ! -e "$LOCKFILE"; then
  (umask 077; : > "$LOCKFILE")
fi
test -f "$LOCKFILE"
mkdir -m 700 "$LAUNCH"
cat > "$LAUNCH/worker.sh" <<'SH'
#!/bin/bash
set -euo pipefail
umask 077
ROOT="$1"; MANIFEST="$2"; CASE_ROOT="$3"
cd "$ROOT"
if test -e "$CASE_ROOT" || test -L "$CASE_ROOT"; then
  printf 'Case root is no longer fresh: %s\n' "$CASE_ROOT" >&2
  exit 1
fi
exec /usr/bin/caffeinate -is python3 -B -m tools.part5.run_v3_heldout_case \
  --manifest "$MANIFEST" --output-root "$CASE_ROOT"
SH
cat > "$LAUNCH/owner.sh" <<'SH'
#!/bin/bash
set -euo pipefail
umask 077
ROOT="$1"; MANIFEST="$2"; CASE_ROOT="$3"; LAUNCH="$4"; LOCKFILE="$5"
printf '%s\n' "$$" > "$LAUNCH/owner.pid"
trap 'rc=$?; printf "%s\n" "$rc" > "$LAUNCH/exit.tmp"; mv "$LAUNCH/exit.tmp" "$LAUNCH/exit-code"' EXIT
/usr/bin/lockf -t 0 -k "$LOCKFILE" /bin/bash "$LAUNCH/worker.sh" \
  "$ROOT" "$MANIFEST" "$CASE_ROOT" > "$LAUNCH/stdout.log" 2> "$LAUNCH/stderr.log"
SH
chmod 600 "$LAUNCH/worker.sh" "$LAUNCH/owner.sh"
tmux new-session -d -s "$SESSION" -c "$ROOT" /bin/bash "$LAUNCH/owner.sh" \
  "$ROOT" "$MANIFEST" "$CASE_ROOT" "$LAUNCH" "$LOCKFILE"
```

`tmux new-session` only confirms launch. While it is active, inspect the single case journal and child monitors read-only. Completion requires the session to end, an `exit-code` file containing `0`, a complete passed journal and hash-pinned case fragment, and reviewed bounded-child cleanup. An absent exit file with no live owner is an interrupted attempt, not a success. Keep the private launch directory and the stable lock file.

For a reviewed resumable journal, replace `03` with the stopped case number and use the same manifest/root directly, omitting the loop's `require_absent` guard. This command is invalid for an incomplete stage/control/monitor set such as Training-012 case 00:

```bash
V=03
python3 -B -m tools.part5.run_v3_heldout_case \
  --manifest "$RUN_MANIFESTS/case-$V.json" \
  --output-root "$PART5/v3-heldout-case-training-024-$V"
```

Proceed only after all eight commands exit successfully and produce one `acceptance-case-fragment.json` each. Confirm fragment variants cover 0–7 and every case journal is complete before acceptance work.

## 5. Acceptance verification, cost analysis, and reporting

These are post-case gates. Do not assemble acceptance inputs, verify acceptance,
analyze costs, or write a heldout result report until all eight cases pass. The
assembler requires eight distinct, explicitly hash-pinned fragments. The
independent verifier must pass before cost analysis. The cost analyzer reports
matched heldout request-B proof, clone, and effect component-sum wall costs;
it does not infer CPU savings or choose an economic winner. The final model
combines those separately timed `k = 1` heldout deltas with the sampled
Training-012 update-count deltas. Its other heldout
counts are conditional estimates, not new heldout runs or a measured heldout
break-even. A directly timed complete arm still needs a separate loaded run.
Final reporting must preserve the verifier outcome and cost
limitations and must not claim acceptance or economics from
freeze/cohort/manifests alone.

**Binding-plan limitation and report gate:** the current case assembler and
verifier do not cover the loaded expired-status negative for each heldout case
or the loaded full-queue capacity negative required by the [binding heldout
acceptance plan](v3-heldout-acceptance-plan.md). The existing commands below
remain usable for the eight-case core heldout path, but even a passing verifier
only establishes that implemented path; it is not a pass of the full binding
plan. Before publishing a full-plan acceptance result, require eight
independently verified loaded expired-status negatives and one independently
verified loaded queue-capacity negative, with the source bundle, freeze,
cohort, manifests, assembler, verifier, and cost analyzer updated to pin and
validate them as specified in the [negative-evidence
checklist](v3-heldout-negative-evidence-checklist.md). Until that gate passes,
report the two loaded-negative categories as missing and label the result
core-path only. The current output chain does not create or validate those
negative reports.

```bash
ASSEMBLED_DIR="$PART5/v3-heldout-assembled-training-024"
ASSEMBLED_MANIFEST="$ASSEMBLED_DIR/heldout-acceptance-manifest.json"
ACCEPTANCE_REPORT="$RESULTS/v3-heldout-acceptance-training-024.json"
COST_REPORT="$RESULTS/v3-heldout-cost-analysis-training-024.json"
MODEL_REPORT="$RESULTS/v3-heldout-conditional-break-even-training-024.json"
require_absent "$ASSEMBLED_DIR"
require_absent "$ACCEPTANCE_REPORT"
require_absent "$COST_REPORT"
require_absent "$MODEL_REPORT"
git check-ignore -q "$ASSEMBLED_DIR"

FRAGMENTS=()
for V in 00 01 02 03 04 05 06 07; do
  FRAGMENT="$PART5/v3-heldout-case-training-024-$V/acceptance-case-fragment.json"
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

Training-012 matrix evidence and the Training-012 through Training-023 heldout attempts are preserved separately. These Training-024 outputs are prospective until each command and validation gate passes. The 35-second validator-port wait applies only to transient `EADDRINUSE` during validator-port preflight and is charged to its owning child budget; it does not reserve sockets or apply to the proxy. The ambiguous-restart proxy port `19500 + variant` is a separate one-shot endpoint and receives no retry. Report failed attempts separately from matched successful-case costs.

## 6. Publish and verify the scrubbed public bundle

Only after Step 5 passes, publish the allowlisted projection. Inspect the four output files before committing them; do not add private case roots, raw reports, proofs, witnesses, credentials, keys, or ledgers. The separately recorded `SHA256SUMS` digest is the offline verifier's trust input.

```bash
PUBLIC_DIR="$RESULTS/v3-heldout-public-training-024"
require_absent "$PUBLIC_DIR"
MODEL_SHA="$(sha256_file "$MODEL_REPORT")"
python3 -B tools/part5/publish_v3_heldout_public.py \
  --acceptance-report "$ACCEPTANCE_REPORT:$ACCEPTANCE_SHA" \
  --cost-report "$COST_REPORT:$COST_SHA" \
  --conditional-model-report "$MODEL_REPORT:$MODEL_SHA" \
  --training-total-summary "$TOTAL_SUMMARY:$TOTAL_SHA" \
  --output-dir "$PUBLIC_DIR"
SHA256SUMS_SHA="$(sha256_file "$PUBLIC_DIR/SHA256SUMS")"
python3 -B tools/part5/verify_v3_heldout_public.py \
  "$PUBLIC_DIR" --expected-sha256sums "$SHA256SUMS_SHA"
```

This projection reports the implemented eight-case core path and its exact gaps. It cannot upgrade the missing loaded expired-status or full-queue negatives into full binding-plan acceptance, and the conditional `k > 1` model is not a directly measured heldout break-even.
