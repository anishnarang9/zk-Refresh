# Training-010 recovery runbook

This runbook records the completed Training-010 build/freeze/cohort prerequisites and the remaining command plan; it is not a matrix-completion record. It replaces the failed Training-009 matrix with a fresh, serial Training-010 campaign after the proof-runner checkpoint guard fix in commit `362d598`. Do not reuse Training-009 stage, transition, smoke, or matrix receipts. The existing prepare-002 status/ledger is only a bootstrap input: freeze and stage-supervisor admission recheck its source manifest and ELF/setup identity; stage-config creation checks the stopped monitor and ledger review conditions and binds the ledger to the new campaign context.

Training-009 slot 10 (`r1-k5-full`) failed in proof with `registered update count`; slots 1–9 passed. The current Training-009 manifest pins proof binary SHA `b564fc5d9159aa5d96589221a73cf0c1fba6d3cf91439e05a842f36e380c0305`. Keep the canonical Training-009 executable unchanged; Training-010 uses its own installed proof binary. The runbook below requires one heavy job at a time. Stop at each report gate on failure; never continue with a partial artifact.

## 0. Paths and fresh-output guard

Run from the repository root in one Bash session. The helper variables below match the paths used by `results/dynark/part5/v3-campaign-matrix-training-009.json` and its stage/transition configs. The proof build, freeze, cohort, and context already exist and are verified below. Subsequent stage, transition, smoke, and matrix creation outputs must be absent before their corresponding command; do not remove or overwrite existing outputs to make a command fit.

```bash
set -euo pipefail
umask 077

ROOT=/Users/anishnarang/Zk-refresh
RESULTS="$ROOT/results/dynark/part5"
PART5="$ROOT/artifacts/dynark/part5"
PYTHON="$PART5/v3-campaign-python-002"
BOUNDED="$ROOT/results/dynark/phase-2/bootstrap/bounded_runner.py"
SESSION_RUNNER="$RESULTS/session_runner.py"
CARGO=/Users/anishnarang/.cargo/bin/cargo
PROOF_DIR="$ROOT/circuits/credential-v3-bounded/qualification/proof-runner-v1"
PROOF_MANIFEST="$PROOF_DIR/Cargo.toml"
PROOF_NAME=credential-v3-bounded-proof-qualification-v1
BUILD010="$PART5/v3-proof-runner-training-010-build"
PROOF_BINARY="$PART5/v3-proof-runner-training-010"

ADAPTER="$ROOT/crates/dynark-solana-adapter/target/debug/build/dynark-solana-adapter/3a4659842a713e9a/out/v3_request_bound_host-3a4659842a713e9a"
EFFECT_RUNNER="$ROOT/harness/target/debug/build/zk-fresh-benchmark/0d22d099108927cf/out/queue_v3-0d22d099108927cf"
EXPORTER="$ROOT/program/target/debug/examples/export_v3_request_fixture"
NODE=/Users/anishnarang/.nvm/versions/node/v24.10.0/bin/node
OLD_PACKET="$PART5/v3-full-r1-proof-training-001/packet-003.json"
SESSION_SCRIPT="$ROOT/tools/part5/run_v3_campaign_session.py"
EFFECT_CONFIG="$ROOT/tools/part5/create_v3_campaign_effect_config.py"
EFFECT_SUPERVISOR="$ROOT/harness/tests/queue_v3_local_campaign_effect.py"
EFFECT_EXECUTE="$ROOT/harness/tests/queue_v3_local_execute.py"
CLONE_R0="$ROOT/harness/tests/queue_v3_clone_campaign_r0.py"
CLONE_FINAL="$ROOT/harness/tests/queue_v3_clone_campaign_final.py"

sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
check_bounded_success() {
  "$PYTHON" -B - "$1" "$2" <<'PY'
import json, pathlib, sys
report = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
assert report['schema'] == 1 and report['owner'] == sys.argv[2]
assert report['passed'] is True and report['exit_code'] == 0
assert report['stop_reason'] is None and report['runner_error_type'] is None
assert report['cleanup_remaining_owned_processes'] == 0
assert report['cleanup_status_unknown'] is False
print(f"bounded run passed: {report['owner']}")
PY
}
require_absent() {
  if [ -e "$1" ] || [ -L "$1" ]; then
    printf 'Expected fresh path is already present: %s\n' "$1" >&2
    return 1
  fi
}
```

Confirm the pinned Python and input tools exist and the matrix output does not:

```bash
for f in "$PYTHON" "$BOUNDED" "$SESSION_RUNNER" "$ADAPTER" "$EFFECT_RUNNER" \
         "$EXPORTER" "$NODE" "$OLD_PACKET" "$EFFECT_CONFIG" "$EFFECT_SUPERVISOR" \
         "$EFFECT_EXECUTE" "$CLONE_R0" "$CLONE_FINAL"; do
  test -f "$f"
done
require_absent "$PART5/v3-matrix-training-010"
```

The fixed `OLD_PACKET` is a stable baseline tool input already required by the matrix schema; it is not a Training-009 campaign receipt. Rehash it when building the new manifest.

## 1. Verify the completed proof build and current source closure

The isolated Training-010 unit and release builds already completed. Their saved bounded reports passed, and the unit log records **24 passed, 0 failed, 0 ignored**. Reuse the installed executable only after these gates; do not rebuild or reinstall over the protected outputs. A missing or changed artifact is a blocker requiring review, not permission to overwrite it.

```bash
check_bounded_success "$PART5/v3-proof-runner-training-010-tests-report.json" \
  part5-v3-proof-runner-training-010-tests
check_bounded_success "$PART5/v3-proof-runner-training-010-release-report.json" \
  part5-v3-proof-runner-training-010-release
grep -Fq 'test result: ok. 24 passed; 0 failed; 0 ignored;' \
  "$PART5/v3-proof-runner-training-010-tests-monitor/stdout.log"

NEW_PROOF_BINARY="$BUILD010/release/$PROOF_NAME"
CANONICAL009="$PROOF_DIR/target/release/$PROOF_NAME"
OLD_PROOF_SHA=b564fc5d9159aa5d96589221a73cf0c1fba6d3cf91439e05a842f36e380c0305
NEW_PROOF_SHA=093659cec842945fd3db15e9e51087b5717d71dcb375fdf60ced58279a5ad19a
test -x "$PROOF_BINARY"
test "$(sha256_file "$CANONICAL009")" = "$OLD_PROOF_SHA"
test "$(sha256_file "$PROOF_BINARY")" = "$NEW_PROOF_SHA"
test "$(sha256_file "$NEW_PROOF_BINARY")" = "$NEW_PROOF_SHA"
```

Record or revalidate the current reviewed source closure before smoke execution. This observation is made after the completed build; it is not represented as a historical pre-build freeze. The smoke report must later match it to the executable's embedded source identity. Use the exact Rust convention: labels `main.rs`, `artifacts.rs`, `context.rs`, `ordinary.rs`, `Cargo.lock`, `Cargo.toml`, with no terminator after domain `dynark-v3-proof/source-closure/v1`; frame each label length as big-endian u32 and content length as big-endian u64. Resolve Rust files under `src/` without including `src/` in the hashed labels. Older GREEN review file hashes do not substitute for the current observation.

```bash
SOURCE_FREEZE="$RESULTS/v3-proof-runner-v1-training-010-source-freeze.json"
"$PYTHON" -B - "$ROOT" "$SOURCE_FREEZE" <<'PYCODE'
import hashlib, json, os, pathlib, struct, subprocess, sys
root, output = map(pathlib.Path, sys.argv[1:])
base = root / 'circuits/credential-v3-bounded/qualification/proof-runner-v1'
names = ['main.rs', 'artifacts.rs', 'context.rs', 'ordinary.rs', 'Cargo.lock', 'Cargo.toml']
h = hashlib.sha256(b'dynark-v3-proof/source-closure/v1')
files = {}
for name in names:
    path = base / ('src/' + name if name.endswith('.rs') else name)
    raw, label = path.read_bytes(), name.encode()
    files[name] = hashlib.sha256(raw).hexdigest()
    h.update(struct.pack('>I', len(label))); h.update(label)
    h.update(struct.pack('>Q', len(raw))); h.update(raw)
head = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
value = {'git_head': head, 'source_files_sha256': files,
         'source_closure_sha256': h.hexdigest()}
if output.exists() or output.is_symlink():
    assert not output.is_symlink() and output.resolve(strict=True) == output
    prior = json.loads(output.read_bytes())
    assert prior['source_files_sha256'] == files
    assert prior['source_closure_sha256'] == value['source_closure_sha256']
else:
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
print(json.dumps(value, sort_keys=True, indent=2))
PYCODE
```

## 2. Verify the recorded Training-010 freeze, cohort, and context

The freeze is already recorded at `results/dynark/part5/v3-campaign-freeze-003/freeze.json`. It pins the isolated corrected proof binary. The fresh eleven-leaf Training-010 cohort completed under owner `part5-v3-campaign-cohort-training-010`: its bounded report passed with exit 0 in 1.169 seconds and zero remaining owned processes. This is training preparation, not a completed matrix or held-out result. Preserve these outputs; do not rerun freeze or key generation at their existing paths.

```bash
FREEZE_HOME="$RESULTS/v3-campaign-freeze-003"
FREEZE="$FREEZE_HOME/freeze.json"
IDENTITY="$FREEZE_HOME/identity-manifest.json"
COHORT_HOME="$PART5/application-v3-campaign-cohort-training-010"
COHORT_ROOT="$COHORT_HOME/cohort"
CONTEXT="$COHORT_HOME/context.json"
COHORT_MONITOR="$PART5/v3-campaign-cohort-training-010-monitor-report.json"
COHORT_RECEIPT="$COHORT_ROOT/cohort-receipt.json"
MEMBERSHIP="$COHORT_ROOT/membership.json"

check_bounded_success "$COHORT_MONITOR" part5-v3-campaign-cohort-training-010
FREEZE_SHA=$(sha256_file "$FREEZE")
COHORT_SHA=$(sha256_file "$COHORT_RECEIPT")
MEMBERSHIP_SHA=$(sha256_file "$MEMBERSHIP")
"$PYTHON" -B - "$FREEZE" "$IDENTITY" "$COHORT_ROOT" "$CONTEXT" "$NEW_PROOF_SHA" <<'PYCODE'
import hashlib, json, pathlib, sys
from tools.part5.prepare_v3_campaign_context import derive, encoded
freeze_path, identity_path, cohort, context_path = map(pathlib.Path, sys.argv[1:5])
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
freeze, identity = [json.loads(path.read_bytes()) for path in (freeze_path, identity_path)]
receipt = json.loads((cohort / 'cohort-receipt.json').read_bytes())
membership = json.loads((cohort / 'membership.json').read_bytes())
assert freeze['schema'] == 'credential-v3-training-campaign-cohort-freeze-v1'
assert freeze['identities']['proof_runner'] == sys.argv[5]
assert identity['freeze_sha256'] == sha(freeze_path)
assert receipt['schema'] == 'v3-eleven-signed-training-credentials-v1'
assert receipt['training_only'] is True and receipt['heldout_acceptance'] is False
assert receipt['freeze_receipt_sha256'] == sha(freeze_path)
assert receipt['identities'] == freeze['identities']
assert receipt['counts'] == {'issuers': 1, 'holders': 11, 'certificates': 11, 'roots': 11}
assert membership['schema'] == 'v3-eleven-leaf-training-membership-v1'
assert len(membership['roots']) == 11
expected = derive(cohort, sha(cohort / 'cohort-receipt.json'), sha(cohort / 'membership.json'))
assert context_path.read_bytes() == encoded(expected)
print('Recorded Training-010 freeze, cohort, and context gate pass')
PYCODE
CONTEXT_SHA=$(sha256_file "$CONTEXT")
```

## 3. Create the new R0 stage and four transitions

These paths are fresh, direct children of `$PART5`, as required by the config creators and stage/transition scripts. Training-009 stage and transition paths are not inputs here.

```bash
STAGE_ROOT="$PART5/application-v3-campaign-stage-training-010"
STAGE_CONTROL="$PART5/application-v3-campaign-stage-control-training-010"
STAGE_CONFIG="$PART5/application-v3-campaign-stage-config-training-010.json"
STAGE_MONITOR="$PART5/application-v3-campaign-stage-monitor-training-010.json"
STAGE_MONITOR_PRIVATE="$PART5/application-v3-campaign-stage-monitor-private-training-010"
STAGE_OWNER=part5-v3-campaign-stage-training-010
RUNNER="$EFFECT_RUNNER"
PREP_CONFIG="$PART5/application-v3-campaign-prepare-config-002.json"
PREP_STATUS="$PART5/application-v3-campaign-prepare-control-002/status.json"
PREP_MONITOR="$PART5/application-v3-campaign-prepare-bounded-002.json"

for p in "$STAGE_ROOT" "$STAGE_CONTROL" "$STAGE_CONFIG" "$STAGE_MONITOR" "$STAGE_MONITOR_PRIVATE"; do require_absent "$p"; done

"$PYTHON" -B -m tools.part5.create_v3_campaign_stage_config \
  --prior-config "$PREP_CONFIG" --prior-status "$PREP_STATUS" \
  --prior-monitor "$PREP_MONITOR" \
  --prior-monitor-owner part5-v3-campaign-prepare-002 \
  --context "$CONTEXT" --campaign-cohort "$COHORT_ROOT" --runner "$RUNNER" \
  --stage-output "$STAGE_ROOT" --control-output "$STAGE_CONTROL" \
  --output "$STAGE_CONFIG"
STAGE_CONFIG_SHA=$(sha256_file "$STAGE_CONFIG")

STAGE_EXIT=0
"$PYTHON" -B "$BOUNDED" \
  --owner "$STAGE_OWNER" --cwd "$ROOT" \
  --private-output "$STAGE_MONITOR_PRIVATE" --report "$STAGE_MONITOR" \
  --runtime-seconds 180 --rss-bytes 4294967296 --storage-bytes 268435456 \
  --storage-path "$STAGE_ROOT" --storage-path "$STAGE_CONTROL" --poll-seconds 0.2 -- \
  env P5_V3_STAGE_SUPERVISOR=local-ledger-review-and-stage \
  "$PYTHON" -B "$ROOT/harness/tests/queue_v3_local_stage.py" \
  --config "$STAGE_CONFIG" --config-sha256 "$STAGE_CONFIG_SHA" || STAGE_EXIT=$?
test "$STAGE_EXIT" -eq 1
STAGE_REPORT="$STAGE_ROOT/stage-report.json"
STAGE_PLAN="$STAGE_ROOT/plan.json"
STAGE_STATUS="$STAGE_CONTROL/status.json"

"$PYTHON" -B - "$STAGE_REPORT" "$STAGE_STATUS" "$STAGE_MONITOR" "$STAGE_OWNER" <<'PY'
import json, pathlib, sys
report_path, status_path, monitor_path = map(pathlib.Path, sys.argv[1:4])
owner = sys.argv[4]
report, status, monitor = [json.loads(path.read_bytes()) for path in
                           (report_path, status_path, monitor_path)]
assert report['schema'] == 'part5-v3-campaign-stage-v1' and report['passed'] is True
assert report['registry_history_authenticated'] is True
assert report['allocation_history_authenticated'] is True
assert report['application_effect'] is False and report['training_only'] is True
assert status['stage_verified'] is True and status['application_effect'] is False
assert status['status'] == 'failed' and status.get('error_type') is None
assert monitor['passed'] is False and monitor['exit_code'] == 1
assert status['ledger_reuse_requires_review'] is True
assert status['validator_cleanup']['reaped'] is True
assert status['validator_cleanup']['exit_code'] == -2
assert status['runner_cleanup']['reaped'] is True and status['runner_cleanup']['exit_code'] == 0
assert monitor['owner'] == owner and monitor['stop_reason'] is None
assert monitor['runner_error_type'] is None
assert monitor['cleanup_remaining_owned_processes'] == 0
assert monitor['cleanup_status_unknown'] is False
print('Training-010 stage report, status, and cleanup gate pass')
PY
```

The expected bounded exit 1 is the reviewed validator SIGINT path, not a successful outer process. The report gate requires the verified finalized stage, no supervisor error, exact cleanup, and outer exit 1 before continuing. Do not start any transition unless that machine gate exits 0.

Run the following loop serially. For each registered k, it creates an independent R0 ledger clone, pins it in a transition config, then runs one local validator transition under a bounded owner. Do not run these four validators in parallel.

After supervisor SIGINT, the localhost port guard may briefly reject a bind even when no process owner is visible. The first Training-010 k=1 clone observed `OSError 48` on `127.0.0.1:18999`; the port became free and the unchanged clone command then passed. Wait and confirm port freedom using the clone's active port guard before retrying. Retry only the clone command, and only after confirming that neither its ledger destination nor `clone-report.json` was written; a partial destination/receipt requires review. Do not rerun the whole fresh-output block or replace any generated artifact.

```bash
for K in 1 2 5 10; do
  OWNER="part5-v3-campaign-r${K}-transition-training-010"
  CLONE_HOME="$PART5/application-v3-campaign-r0-k${K}-training-010"
  CLONE_LEDGER="$CLONE_HOME/ledger"
  CLONE_REPORT="$CLONE_HOME/clone-report.json"
  TRANSITION_ROOT="$PART5/application-v3-campaign-r${K}-transition-training-010"
  TRANSITION_CONTROL="$PART5/application-v3-campaign-r${K}-transition-control-training-010"
  TRANSITION_CONFIG="$PART5/application-v3-campaign-r${K}-transition-config-training-010.json"
  TRANSITION_MONITOR="$PART5/application-v3-campaign-r${K}-transition-monitor-training-010.json"
  TRANSITION_PRIVATE="$PART5/application-v3-campaign-r${K}-transition-monitor-private-training-010"

  for p in "$CLONE_HOME" "$TRANSITION_ROOT" "$TRANSITION_CONTROL" "$TRANSITION_CONFIG" "$TRANSITION_MONITOR" "$TRANSITION_PRIVATE"; do require_absent "$p"; done
  mkdir -m 700 "$CLONE_HOME"
  "$PYTHON" -B "$CLONE_R0" \
    --stage-config "$STAGE_CONFIG" --config-sha "$STAGE_CONFIG_SHA" \
    --stage-report "$STAGE_REPORT" --report-sha "$(sha256_file "$STAGE_REPORT")" \
    --stage-status "$STAGE_STATUS" --status-sha "$(sha256_file "$STAGE_STATUS")" \
    --stage-monitor "$STAGE_MONITOR" --monitor-sha "$(sha256_file "$STAGE_MONITOR")" \
    --monitor-owner "$STAGE_OWNER" --destination "$CLONE_LEDGER"

  "$PYTHON" -B -m tools.part5.create_v3_campaign_transition_config \
    --target-count "$K" --stage-config "$STAGE_CONFIG" --stage-status "$STAGE_STATUS" \
    --stage-monitor "$STAGE_MONITOR" --stage-monitor-owner "$STAGE_OWNER" \
    --clone-report "$CLONE_REPORT" --cohort-root "$COHORT_ROOT" --runner "$RUNNER" \
    --transition-output "$TRANSITION_ROOT" --control-output "$TRANSITION_CONTROL" \
    --output "$TRANSITION_CONFIG"
  TRANSITION_CONFIG_SHA=$(sha256_file "$TRANSITION_CONFIG")

  TRANSITION_EXIT=0
  "$PYTHON" -B "$BOUNDED" \
    --owner "$OWNER" --cwd "$ROOT" \
    --private-output "$TRANSITION_PRIVATE" --report "$TRANSITION_MONITOR" \
    --runtime-seconds 420 --rss-bytes 4294967296 --storage-bytes 268435456 \
    --storage-path "$TRANSITION_ROOT" --storage-path "$TRANSITION_CONTROL" --poll-seconds 0.2 -- \
    env P5_V3_CAMPAIGN_TRANSITION_SUPERVISOR=reviewed-r0-campaign-clone \
    "$PYTHON" -B "$ROOT/harness/tests/queue_v3_local_campaign_transition.py" \
    --config "$TRANSITION_CONFIG" --config-sha256 "$TRANSITION_CONFIG_SHA" || TRANSITION_EXIT=$?
  test "$TRANSITION_EXIT" -eq 1

  "$PYTHON" -B - "$TRANSITION_ROOT" "$TRANSITION_CONTROL" "$TRANSITION_MONITOR" "$OWNER" "$K" <<'PY'
import json, pathlib, sys
root, control, monitor_path = map(pathlib.Path, sys.argv[1:4])
owner, count = sys.argv[4], int(sys.argv[5])
report = json.loads((root / 'transition-report.json').read_bytes())
status = json.loads((control / 'status.json').read_bytes())
monitor = json.loads(monitor_path.read_bytes())
assert report['schema'] == 'part5-v3-campaign-transition-v1' and report['passed'] is True
assert report['target_count'] == count
assert report['registry_history_authenticated'] is True
assert report['allocation_history_authenticated'] is True
assert report['request_unconsumed'] is True and report['application_effect'] is False
assert status['transition_verified'] is True and status['target_count'] == count
assert status.get('error_type') is None
assert monitor['passed'] is False and monitor['exit_code'] == 1
assert status['status'] == 'failed' and status['application_effect'] is False
assert status['ledger_reuse_requires_review'] is True
assert status['validator_cleanup']['reaped'] is True
assert status['validator_cleanup']['exit_code'] == -2
assert status['runner_cleanup']['reaped'] is True and status['runner_cleanup']['exit_code'] == 0
assert monitor['owner'] == owner and monitor['stop_reason'] is None
assert monitor['runner_error_type'] is None
assert monitor['cleanup_remaining_owned_processes'] == 0
assert monitor['cleanup_status_unknown'] is False
print(f'Training-010 k={count} transition report, status, and cleanup gate pass')
PY
done
```

For each k, the expected report/status files are `$PART5/application-v3-campaign-r${K}-transition-training-010/transition-report.json` and `$PART5/application-v3-campaign-r${K}-transition-control-training-010/status.json`. Retain each config, report, status, monitor, clone report, and their measured SHA-256 values.

## 4. Fresh k=5 Full smoke

The first attempt used clone home `$PART5/application-v3-campaign-training-010-smoke-k5-clone`, smoke home `$PART5/v3-training-010-smoke-k5-full`, effect output `$PART5/application-v3-training-010-smoke-k5-full-effect`, and control output `$PART5/application-v3-training-010-smoke-k5-full-control`. Preserve those as the failed smoke-001 record; its proof report passed, but the application admission failed because the 65,536-byte monitor reader rejected the 99,130-byte k=5 transition monitor. See [the smoke-001 failure note](v3-training-010-smoke-failure-001.md) for report hashes and the source trace. The session submitted no protected effect and was not a matrix run.

The scoped fix raises only the transition-monitor read cap to 1 MiB at `harness/tests/queue_v3_local_campaign_effect.py:451`. Its current source SHA-256 is `01f27ef23626b235605fca823a0af55e120169885ef7583b79bb8913524fbf39`; this fix is pending smoke verification. Keep the isolated Training-010 proof binary and source-closure checks below unchanged (`NEW_PROOF_SHA=093659cec842945fd3db15e9e51087b5717d71dcb375fdf60ced58279a5ad19a`). The retry uses the already-created `-002` final-ledger clone, checks its receipt against the current k=5 transition pins, and writes only to fresh `-002` smoke outputs. It is not one of the 60 matrix slots. The full session proof gate still requires `campaign-full-k5`, `update_count: 5`, six proofs, and 52 ordinary checks; matrix creation and execution remain gated on the complete smoke gate passing.

```bash
K=5
TRANSITION_ROOT="$PART5/application-v3-campaign-r5-transition-training-010"
TRANSITION_CONTROL="$PART5/application-v3-campaign-r5-transition-control-training-010"
TRANSITION_CONFIG="$PART5/application-v3-campaign-r5-transition-config-training-010.json"
TRANSITION_MONITOR="$PART5/application-v3-campaign-r5-transition-monitor-training-010.json"
TRANSITION_PRIVATE="$PART5/application-v3-campaign-r5-transition-monitor-private-training-010"
TRANSITION_OWNER=part5-v3-campaign-r5-transition-training-010
TRANSITION_REPORT="$TRANSITION_ROOT/transition-report.json"
TRANSITION_STATUS="$TRANSITION_CONTROL/status.json"
TRANSITION_CONFIG_SHA=$(sha256_file "$TRANSITION_CONFIG")

SMOKE_CLONE_HOME="$PART5/application-v3-campaign-training-010-smoke-k5-clone-002"
SMOKE_CLONE_LEDGER="$SMOKE_CLONE_HOME/ledger"
SMOKE_CLONE_REPORT="$SMOKE_CLONE_HOME/clone-report.json"
SMOKE_HOME="$PART5/v3-training-010-smoke-k5-full-002"
SMOKE_WORK="$SMOKE_HOME/work"
SMOKE_EFFECT="$PART5/application-v3-training-010-smoke-k5-full-effect-002"
SMOKE_CONTROL="$PART5/application-v3-training-010-smoke-k5-full-control-002"
SMOKE_PRIVATE="$SMOKE_HOME/outer-private"
SMOKE_OUTER="$SMOKE_HOME/outer-report.json"

for p in "$SMOKE_HOME" "$SMOKE_EFFECT" "$SMOKE_CONTROL"; do require_absent "$p"; done
test -d "$SMOKE_CLONE_HOME" && test ! -L "$SMOKE_CLONE_HOME"
test -d "$SMOKE_CLONE_LEDGER" && test ! -L "$SMOKE_CLONE_LEDGER"
test -f "$SMOKE_CLONE_REPORT" && test ! -L "$SMOKE_CLONE_REPORT"
"$PYTHON" -B - "$SMOKE_CLONE_HOME" "$SMOKE_CLONE_LEDGER" "$SMOKE_CLONE_REPORT" \
  "$TRANSITION_CONFIG" "$TRANSITION_REPORT" "$TRANSITION_STATUS" "$TRANSITION_MONITOR" <<'PY'
import hashlib, json, pathlib, sys
home, ledger, receipt, config_path, report_path, status_path, monitor_path = map(pathlib.Path, sys.argv[1:])
load = lambda path: json.loads(path.read_bytes())
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
clone, config, report = load(receipt), load(config_path), load(report_path)
assert clone['schema'] == 'part5-v3-campaign-final-ledger-clone-v1'
assert clone['training_only'] is True and clone['target_count'] == 5
assert clone['copy_identical'] is True and clone['source_stable'] is True
assert clone['application_effect'] is False
assert clone['destination'] == str(ledger) and ledger.is_dir()
assert clone['source'] == config['ledger']
assert clone['current_root'] == report['current_root']
assert clone['signed_history_sha256'] == report['signed_history_sha256']
assert clone['monitor_owner'] == 'part5-v3-campaign-r5-transition-training-010'
assert clone['transition_config_sha256'] == sha(config_path)
assert clone['transition_report_sha256'] == sha(report_path)
assert clone['transition_status_sha256'] == sha(status_path)
assert clone['transition_monitor_sha256'] == sha(monitor_path)
print(f'verified existing smoke clone-002 receipt sha256={sha(receipt)}')
PY
test "$(sha256_file "$EFFECT_SUPERVISOR")" = 01f27ef23626b235605fca823a0af55e120169885ef7583b79bb8913524fbf39
test "$(sha256_file "$PROOF_BINARY")" = "$NEW_PROOF_SHA"
mkdir -m 700 "$SMOKE_HOME" "$SMOKE_WORK"

PINS=(--exporter-sha256 "$(sha256_file "$EXPORTER")"
      --node-sha256 "$(sha256_file "$NODE")"
      --old-packet-sha256 "$(sha256_file "$OLD_PACKET")"
      --effect-config-sha256 "$(sha256_file "$EFFECT_CONFIG")"
      --effect-supervisor-sha256 "$(sha256_file "$EFFECT_SUPERVISOR")"
      --bounded-runner-sha256 "$(sha256_file "$SESSION_RUNNER")"
      --effect-execute "$EFFECT_EXECUTE"
      --effect-execute-sha256 "$(sha256_file "$EFFECT_EXECUTE")")

P5_V3_CAMPAIGN_SESSION_SUPERVISOR=bounded-complete-session \
  "$PYTHON" -B "$SESSION_RUNNER" \
  --owner v3-campaign-full-k5-training-010-smoke-002 --cwd "$ROOT" \
  --private-output "$SMOKE_PRIVATE" --report "$SMOKE_OUTER" \
  --runtime-seconds 1800 --rss-bytes 4294967296 --storage-bytes 536870912 \
  --storage-path "$SMOKE_EFFECT" --storage-path "$SMOKE_CONTROL" \
  --storage-path "$SMOKE_WORK" --storage-path "$SMOKE_CLONE_HOME" -- \
  "$PYTHON" -B "$SESSION_SCRIPT" \
  --mode full --target-count 5 --repetition 1 \
  --freeze "$FREEZE" --cohort-root "$COHORT_ROOT" --context "$CONTEXT" \
  --stage-root "$STAGE_ROOT" --clone-report "$SMOKE_CLONE_REPORT" \
  --work-root "$SMOKE_WORK" --effect-output "$SMOKE_EFFECT" --control-output "$SMOKE_CONTROL" \
  --proof-binary "$PROOF_BINARY" --adapter-binary "$ADAPTER" \
  --exporter "$EXPORTER" --node "$NODE" --old-packet "$OLD_PACKET" \
  --effect-runner "$EFFECT_RUNNER" "${PINS[@]}" \
  --transition-root "$TRANSITION_ROOT" --transition-config "$TRANSITION_CONFIG" \
  --transition-report "$TRANSITION_REPORT" --transition-status "$TRANSITION_STATUS" \
  --transition-monitor "$TRANSITION_MONITOR" --transition-monitor-owner "$TRANSITION_OWNER"
```

Smoke gate: outer report exit 0, passed, no stop reason or owned-process residue; session report `passed: true`, mode `full`, count 5; proof stage exit 0; proof report mode `campaign-full-k5`, `update_count: 5`, `counts.proofs: 6`, `counts.ordinary_checks: 52`, and `passed: true`. Stop before manifest/run if any condition fails. Keep the smoke clone and outputs out of the matrix output root.

Use this read-only gate to check the session, proof report, installed binary, and source freeze together:

```bash
"$PYTHON" -B - "$SMOKE_OUTER" "$SMOKE_WORK/session-report.json" \
  "$SMOKE_WORK/proof/proof-report.json" "$PROOF_BINARY" "$SOURCE_FREEZE" <<'PY'
import hashlib, json, pathlib, sys
outer_path, session_path, proof_path, binary_path, source_path = map(pathlib.Path, sys.argv[1:])
load = lambda path: json.loads(path.read_bytes())
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
outer, session, proof, source = map(load, (outer_path, session_path, proof_path, source_path))
assert outer['owner'] == 'v3-campaign-full-k5-training-010-smoke-002'
assert outer['passed'] is True and outer['exit_code'] == 0 and outer['stop_reason'] is None
assert outer['runner_error_type'] is None and outer['cleanup_remaining_owned_processes'] == 0
assert outer['cleanup_status_unknown'] is False
assert session['schema'] == 'part5-v3-campaign-session-v1'
assert session['passed'] is True and session['mode'] == 'full' and session['target_count'] == 5
assert session['effect_verified'] is True
assert any(row.get('stage') == 'proof' and row.get('exit_code') == 0 for row in session['stages'])
assert proof['passed'] is True and proof['mode'] == 'campaign-full-k5' and proof['update_count'] == 5
assert proof['counts']['proofs'] == 6 and proof['counts']['ordinary_checks'] == 52
assert proof['proof_binary_sha256'] == sha(binary_path)
assert proof['proof_source_identity'] == source['source_closure_sha256']
assert session['proof_report_sha256'] == sha(proof_path)
print('Training-010 k5 Full smoke reports and binary/source pins pass')
PY
```

## 5. Generate a fresh pinned manifest, plan it, then run serially

The matrix schema has no manifest generator. This block copies the Training-009 JSON only as a limits/tool-path template, replaces every evidence reference with fresh Training-010 evidence, rehashes every tool file, and creates the new manifest exclusively. It does not copy Training-009 receipts. The old packet remains an explicitly pinned baseline input.

```bash
MATRIX="$RESULTS/v3-campaign-matrix-training-010.json"
MATRIX_TEMPLATE="$RESULTS/v3-campaign-matrix-training-009.json"
MATRIX_OUTPUT="$PART5/v3-matrix-training-010"
require_absent "$MATRIX"
require_absent "$MATRIX_OUTPUT"
require_absent "$RESULTS/v3-campaign-matrix-training-010-plan.json"

export ROOT RESULTS PART5 PYTHON PROOF_BINARY ADAPTER EFFECT_RUNNER EXPORTER NODE OLD_PACKET
export SESSION_SCRIPT SESSION_RUNNER EFFECT_CONFIG EFFECT_SUPERVISOR EFFECT_EXECUTE CLONE_R0 CLONE_FINAL
export FREEZE COHORT_ROOT CONTEXT STAGE_ROOT STAGE_CONFIG STAGE_CONTROL STAGE_MONITOR STAGE_OWNER
export MATRIX MATRIX_TEMPLATE MATRIX_OUTPUT

"$PYTHON" -B - <<'PY'
import hashlib, json, os, pathlib, stat

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

root = pathlib.Path(os.environ['ROOT'])
part5 = pathlib.Path(os.environ['PART5'])
matrix_path = pathlib.Path(os.environ['MATRIX'])
data = json.loads(pathlib.Path(os.environ['MATRIX_TEMPLATE']).read_bytes())
data['campaign_id'] = 'training-010'
data['campaign_runtime_seconds'] = 129600
data['output_root'] = os.environ['MATRIX_OUTPUT']
data['tools']['proof_binary']['path'] = os.environ['PROOF_BINARY']

freeze = pathlib.Path(os.environ['FREEZE'])
cohort = pathlib.Path(os.environ['COHORT_ROOT'])
context = pathlib.Path(os.environ['CONTEXT'])
stage_root = pathlib.Path(os.environ['STAGE_ROOT'])
stage_control = pathlib.Path(os.environ['STAGE_CONTROL'])
stage_config = pathlib.Path(os.environ['STAGE_CONFIG'])
stage_monitor = pathlib.Path(os.environ['STAGE_MONITOR'])
stage_owner = os.environ['STAGE_OWNER']

def pin(path):
    path = pathlib.Path(path).resolve(strict=True)
    return {'path': str(path), 'sha256': sha(path)}

evidence = {
    'freeze': pin(freeze), 'cohort_root': str(cohort.resolve(strict=True)),
    'cohort_receipt': pin(cohort / 'cohort-receipt.json'),
    'context': pin(context), 'stage_root': str(stage_root.resolve(strict=True)),
    'stage_config': pin(stage_config),
    'stage_report': pin(stage_root / 'stage-report.json'),
    'stage_plan': pin(stage_root / 'plan.json'),
    'stage_status': pin(stage_control / 'status.json'),
    'stage_monitor': pin(stage_monitor), 'stage_monitor_owner': stage_owner,
    'transitions': {}
}
for count in (1, 2, 5, 10):
    r = part5 / f'application-v3-campaign-r{count}-transition-training-010'
    c = part5 / f'application-v3-campaign-r{count}-transition-control-training-010'
    config = part5 / f'application-v3-campaign-r{count}-transition-config-training-010.json'
    monitor = part5 / f'application-v3-campaign-r{count}-transition-monitor-training-010.json'
    evidence['transitions'][str(count)] = {
        'root': str(r.resolve(strict=True)), 'config': pin(config),
        'report': pin(r / 'transition-report.json'),
        'status': pin(c / 'status.json'), 'monitor': pin(monitor),
        'monitor_owner': f'part5-v3-campaign-r{count}-transition-training-010'
    }
data['evidence'] = evidence
for row in data['tools'].values():
    row['sha256'] = sha(row['path'])
raw = (json.dumps(data, sort_keys=True, indent=2) + '\n').encode()
fd = os.open(matrix_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'wb') as stream:
    stream.write(raw); stream.flush(); os.fsync(stream.fileno())
print(f'created {matrix_path} sha256={hashlib.sha256(raw).hexdigest()}')
PY
```

Review the generated manifest and exact 60-slot argv plan. `--plan` validates all pins without creating campaign outputs or launching sessions:

```bash
"$PYTHON" -B -m tools.part5.run_v3_campaign_matrix "$MATRIX" --plan \
  > "$RESULTS/v3-campaign-matrix-training-010-plan.json"
```

Gate: plan has `campaign_id: training-010`, `slot_count: 60`, fresh `v3-matrix-training-010` output root, current proof binary pin equal to `$NEW_PROOF_SHA`, all fresh Training-010 evidence pins, and no Training-009 stage/transition/freeze/cohort/matrix receipt references. Check again that the matrix root is absent and that the smoke passed. Then start the serial run, with no `--resume`:

```bash
require_absent "$MATRIX_OUTPUT"
"$PYTHON" -B -m tools.part5.run_v3_campaign_matrix "$MATRIX"
```

Completion gate: command exits 0; `$MATRIX_OUTPUT/sequence-receipt.json` has `campaign_id: training-010`, `passed: true`, `sequence_count: 60`, and `cross_session_order_verified: true`; every sequence row links the preceding slot receipt, and all 60 slot reports pass. The driver itself validates the receipt chain and non-overlapping session timestamps before publishing the final receipt. Resume only the same Training-010 manifest after an interruption when the existing slots form a contiguous prefix of verified passed receipts; a partial failed slot requires a new campaign ID/output root.

After exit 0, run a read-only receipt/report audit:

```bash
"$PYTHON" -B - "$MATRIX_OUTPUT" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
load = lambda path: json.loads(path.read_bytes())
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
final = load(root / 'sequence-receipt.json')
plan = load(root / 'matrix-plan.json')
assert final['campaign_id'] == 'training-010' and final['passed'] is True
assert final['sequence_count'] == 60 and final['cross_session_order_verified'] is True
assert plan['campaign_id'] == 'training-010' and plan['slot_count'] == 60
previous = None
for row in final['sequence']:
    name = f"slot-r{row['repetition']}-k{row['target_count']}-{row['mode']}"
    slot = root / name
    receipt = load(slot / 'slot-receipt.json')
    outer = load(slot / 'outer-report.json')
    session = load(slot / 'work/session-report.json')
    assert sha(slot / 'slot-receipt.json') == row['slot_receipt_sha256']
    assert receipt['previous_slot_receipt_sha256'] == previous
    assert outer['passed'] is True and outer['exit_code'] == 0
    assert outer['stop_reason'] is None and outer['cleanup_remaining_owned_processes'] == 0
    assert session['passed'] is True and session['mode'] == row['mode']
    assert session['target_count'] == row['target_count']
    previous = row['slot_receipt_sha256']
assert previous == final['final_slot_receipt_sha256']
print('All 60 Training-010 slot receipts and reports pass')
PY
```

## Reported timing limits

The unit/release build and cohort jobs above already completed; their recorded bounded receipts govern their actual limits. The remaining stage, transition, and smoke ceilings are 180 s, 420 s per transition, and 1800 s. Run sequentially. The matrix has a 129600-second (36-hour) envelope. These are ceilings, not runtime predictions.
