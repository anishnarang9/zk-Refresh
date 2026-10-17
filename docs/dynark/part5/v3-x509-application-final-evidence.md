# v3 bounded X.509 application evidence (draft)

**Evidence snapshot:** 2026-10-17 23:31 UTC
**Source revision:** `14c7bbc` (`codex/engine-focus-oct14`; same as `origin/codex/engine-focus-oct14` at this snapshot)
**Status:** training correctness demonstrated; training-004 was censored during slot 10 and training-005 failed in slot 5 after its Anchor proof passed but before application submission. Training-006 is running: its first Full slot has a passing proof and completed slot receipt, and its second slot is in progress without a receipt. Exactly one of 60 receipts exists at this snapshot. No full matrix, final economics, or held-out acceptance result is established. This is a draft, not a campaign-completion report.

## What the application demonstrates

The experiment covers the declared bounded X.509/RSA profile and an exact, finalized action-v2 request. The v3 application checks the current authenticated registry state and uses a program-owned queue append with request consumption as its protected effect. This is development evidence for the declared profile; it does not establish arbitrary X.509 support, production issuer operations, production setup, or devnet deployment.

The signed-history training check exercised two controlled demo-issued credentials. Both Full and Anchor used the same finalized request, source history, witnesses, setup, ordinary verification key, proof runner, loaded application, and cloned pre-execution ledger. Each finalized one queue append and consumed the request; replay failed. A stale R0 Full proof failed under current R1 state. After an own-leaf revocation at R2, both the old Full proof and the R1 Anchor proof were rejected, with no request consumption or queue append. See [signed-history training evidence](v3-signed-history-k1-training-effect-2026-10-17.md) and the scrubbed pair and own-revocation receipts it links.

This closes the signed-history **training correctness check** for that fixture. It does not pass the independent held-out gate.

## Acceptance checklist and evidence status

The plan has two independent success gates: protected-action correctness for an
unseen in-profile credential, and an honest whole-session economic result. A
pass in the training correctness check cannot stand in for held-out acceptance;
one completed training pair cannot stand in for the registered matrix.

| Plan gate | Exact acceptance condition | Status in this report |
| --- | --- | --- |
| Request-bound Full path (plan Gate 1) | A newly issued training credential signs the Rust-finalized canonical action; authenticated `open_full` checks the exact package, profile, setup, current state and request; the complete witness matches all 751 inputs and six public fields, passes every R1CS row, and yields a randomized proof accepted by the ordinary verifier. | Training application sessions are recorded below, but this report does not independently claim each native-client predicate from the matrix receipts. Reuse the source gate evidence; do not infer it from the effect alone. |
| Protected effect and revocation behavior (plan Gate 2) | On separate pre-execution ledger clones: one exact queue append and request consumption; replay fails; an old R0 proof fails after unrelated R1 revocation; same-action Anchor refresh succeeds for a distinct unconsumed request; own-leaf revocation rejects old/current attempts without effect. | **Training correctness passed** for the two controlled demo-issued credentials cited below. Held-out behavior remains pending. |
| Matched whole-session economics (plan Gate 3) | Four matched repetitions at each `k = 0, 1, 2, 5, 10` for Full, Anchor, and coalesced Full; complete cost accounting and valid sequence/order receipts; report per-pair spread, measured break-even, the registered ≥20% target, and resource costs. | **Incomplete.** Training-004 was storage-censored and training-005 failed. Training-006 is running with one of 60 slot receipts at this snapshot. No break-even or savings conclusion is established. |
| Bounded repair cycle (plan Gate 4) | Only if the valid comparison shows no benefit: quantify the bottleneck, make one evidence-ranked change, and repeat the same comparison with correctness preserved. | **Not triggered or evaluated.** The training-006 comparison is incomplete, so no optimization result is claimed. |
| Frozen held-out acceptance and cost analysis (plan Gate 5) | After identity freeze, admit eight unseen profile credentials without per-certificate code/setup; pass each Full, unrelated-revocation Anchor, own-revocation and replay case plus negatives; run the frozen cost method and independently verify assembled receipts. | **Pending.** R2 own-revocation receipt and total-cost verifier code is pushed in `14c7bbc`, and the stable Rust runner is built and pinned. No held-out freeze, cohort, run, assembled manifest, verifier report, or cost report exists. |

## Whole-session economics: in progress

The registered `training-004` matrix contains 60 slots: four repetitions at each of `k = 0, 1, 2, 5, 10` root changes, for Full, Anchor, and coalesced Full. Nine slots completed: all three modes at `k = 0`, `k = 1`, and `k = 2`. Slot 10 (`k = 5`, Full) was stopped after 32.46 seconds when the bounded supervisor reached its 256 MiB storage-growth cap; the outer report records `censored: true`, `stop_reason: storage_growth_bytes`, and exit code `-15`. The remaining 51 slots did not complete, so training-004 is a censored run, not a complete matrix.

The partial six-slot training-004 snapshot derives these matched total-session estimates by adding the shared stage cost and slot clone preparation to both modes. These are the six-slot snapshot only; they are training evidence, not the result of all nine completed slots or the full matrix:

| Distinct root changes (`k`) | Full | Anchor | Anchor minus Full |
| ---: | ---: | ---: | ---: |
| 0 | 146.52 s | 1,355.97 s | +1,209.45 s |
| 1 | 212.63 s | 1,375.92 s | +1,163.29 s |

These preliminary pairs show no total-work benefit at `k = 0` or `k = 1` in that partial sample. They do not establish a campaign-wide conclusion. Training-004's storage-censored outcome prevents final matrix economics; no pooled break-even, distribution, or 20% savings result is reported.

Training-005 was the replacement 60-slot training run, registered with a uniform 512 MiB storage-growth cap. The historical 22:31 UTC snapshot below captured four completed receipts and slot 5 running. The run later failed in slot 5, repetition 1, `k = 1` Anchor: the proof report passed, but the application stage stopped before submission with `ValueError: finalized exact account bytes mismatch`. The outer bounded run ended with exit code 2 and `passed: false`; there is no application effect receipt and no `slot-receipt.json` for this slot. The failed slot's proof, work, clone, outer and monitor artifacts remain preserved under `artifacts/dynark/part5/v3-matrix-training-005/slot-r1-k1-anchor/`. A read-only fresh-clone diagnostic matched all five account hashes, but did not observe the original failure role, so the cause remains unknown. The matrix driver's `--resume` refuses this partial slot; preserve it and do not treat it as completed or resumable. The first four receipts remain valid prior slot records, but the ordered campaign is incomplete. Their `cross_session_order_verified: false` fields also leave CPU accounting unqualified. No paired economics, full matrix, or final result is established.

### Training-006 current status (2026-10-17 23:31 UTC)

Training-006 is the current 60-slot replacement matrix. Its checked-in input is `results/dynark/part5/v3-campaign-matrix-training-006.json` (SHA-256 `c2415bf7fedc8b2119c946bad83462f38f95a2a58bfff9e52bbbb83c06fadf86`); the materialized input manifest is `artifacts/dynark/part5/v3-matrix-training-006/input-manifest.json` (SHA-256 `0a9c9cfee26093a7a719b8ae9a5bcb8d4ffe067633f16fa3f170c9449ce0567a`), and its plan is `artifacts/dynark/part5/v3-matrix-training-006/matrix-plan.json` (SHA-256 `bfcd079e37314b9d40751c83ab851e435d1e44ebd5def0277945bc6ddcec0d42`). The plan has four repetitions at each `k = 0, 1, 2, 5, 10` for Full, Anchor, and coalesced Full (60 slots total), with a uniform 512 MiB per-slot storage-growth cap. The pinned campaign helper is `harness/tests/queue_v3_local_execute.py` (SHA-256 `dc9ab5dcb3bb086e73fb7e995f990ca5eddf14cba71fdb88d93942928cc3463c`), added and pinned by `cbf1f07`; the source revision when launched is `14c7bbc`. Its matrix Python artifact is `artifacts/dynark/part5/v3-campaign-python-002` (SHA-256 `4fce274f0e60574ada0b53f17bceb49bbd804125ddae972c7674b8eb13d9e49d`). The actual launch command was:

```sh
artifacts/dynark/part5/v3-campaign-python-002 \
  -B -m tools.part5.run_v3_campaign_matrix \
  results/dynark/part5/v3-campaign-matrix-training-006.json
```

The campaign state records start `2026-10-17T23:28:34.166072Z` and deadline `2026-10-19T11:28:34.166072Z`; the driver process was still running at this snapshot. Slot `r1-k0-full` has `proof-report.json` with `passed: true`, a passing session and outer report (exit code 0, no stop reason), and its `slot-receipt.json` (sequence 1) exists. The matrix had advanced to the second slot, `r1-k0-anchor`; its ledger clone report and proof-stage work files existed, but no slot receipt had been written. Exactly 1 of 60 receipts existed at this snapshot. This is progress evidence only: no complete matrix, paired economics, held-out result, or economic benefit is established.

A prior single-pair engineering run measured Full at 115.326 seconds and Anchor at 1,244.766 seconds of bounded whole-session wall time. Anchor's public and private preparation cost 447.573 and 682.496 seconds; refresh plus ordinary verification was 0.982 seconds. Both modes produced the protected effect. This is one training pair, excluded from the amended matrix: Full paid an Anchor-only preflight, and the run did not establish pooled economics or complete-tree CPU savings. The warm refresh time is not a session-level benefit. See [the matched-session method amendment](v3-matched-session-protocol-amendment-2026-10-17.md) and [the signed-history training check](v3-signed-history-k1-training-effect-2026-10-17.md).

The current matrix uses the amended comparator: Full and coalesced Full omit Anchor-only delta/support preparation; all modes authenticate the same history and validate complete witnesses. Count `k` is the number of distinct authenticated root changes for one still-unconsumed exact request. The chosen update pattern is controlled synthetic training history, not observed issuer churn or user action-lifetime data.

### Cost interpretation rules

The primary unit is one complete authorization of one exact, still-unconsumed
request, from its mode-specific preparation through a finalized application
effect (or a recorded failure/retry). For each matched clone, compare the same
credential, request, authenticated source history, root sequence, software
identities and effect. Do not consume the request twice in one ledger; Full,
Anchor and coalesced Full start from separate clones of the same pre-execution
state.

Report at least these two wall-cost views separately:

1. **Request/action cost:** costs attributable to that request, including
   complete witness generation and validation, mode-specific private
   preparation, delta/support work where applicable, proving or refresh,
   ordinary verification, state catch-up, serialization/reload, submission,
   effect, and failed/retried work.
2. **Shared-setup allocation:** the same request/action cost plus the explicitly
   allocated one-time public setup/material cost. State the amortization rule;
   do not charge it to only one mode or silently omit it from both when making
   an end-to-end claim.

Keep public setup cost distinct from private credential/action preparation.
Also distinguish one-time circuit setup from any per-run or per-credential
public Anchor preparation: allocate each cost where the application actually
pays it, and amortize it only when the measured reuse justifies that rule.
The campaign's eager Anchor preparation is paid even at `k = 0`, when both
modes make a Full proof. The coalesced Full control waits for the final state
and proves once; report its idle time separately from active work. The
amended protocol excludes Anchor-only delta, support and updating-material
preflight from Full and coalesced Full, while retaining common history
authentication and complete-witness validation.

For each repetition, show paired costs and the difference
`Anchor - Full`; summarize all repetitions and censored/failed slots. Define
the measured break-even as the smallest tested `k` where the registered paired
comparison favors Anchor under the stated accounting basis, and show the
distribution rather than extrapolating a single pair. The registered target
is at least 20% total savings at the selected workload. For each paired trial,
show `(Full total - Anchor total) / Full total` against the Full complete-session
cost, then show the spread before any aggregate. Identify any model beyond
tested `k` values as a model with synthetic update-pattern assumptions. CPU
savings remain unqualified unless the cross-session ordering receipt verifies
the CPU accounting. Report peak RSS and retained/storage growth, plus
transaction size and compute where present; wall time alone does not establish
a resource or deployment benefit.

## Held-out acceptance: pending

The independent gate remains pending; no held-out pass is claimed. Before issuance, freeze the source and artifact identities. Generate eight unseen in-profile certificates using four fresh issuer keys and eight fresh holder keys, with no training-key reuse; cover all eight DER layouts, distinct positive 16-byte serials and validity periods, at least two signed organization/group policies, varied AKIs, and at least four independent OpenSSL issuances. Preserve an independent post-freeze issuance/import receipt, use the same frozen public VK/setup, and admit the credentials without source/offset edits or a new setup.

For every credential, verify issuer/AKI and exact-policy enrollment (including pre-enrollment and wrong-policy rejection), fresh authenticated source/current-head evidence, and three distinct signed action-v2 requests. Request A must produce one Full effect; replay, including with a fresh proof, must fail without a second effect. Request B must reject its stale R0 proof after an unrelated R1 revocation, then allow same-action Anchor refresh/effect from a separate unconsumed R1 clone. Request C must reject old-root and current-root active-leaf attempts after own-leaf revocation at R2, without queue append or request consumption. Also cover malformed/ineligible DER, wrong issuer, changed policy, stale status, disabled issuer/config, wrong account order/privileges/owners, modified action, malformed proof, queue capacity, and ambiguous submission/restart. Record preparation and complete-refresh time, per-credential memory, and paid public/private Anchor preparation; verify setup reuse, private-cache isolation, holder/action separation, and no source/setup drift. See the [binding held-out acceptance plan](v3-heldout-acceptance-plan.md) for the complete predicates.

| Evidence item | Observed state at this snapshot | Evidence required to close it |
| --- | --- | --- |
| Request-bound Full plus protected effect | The cited signed-history run passed its training fixture; the four receipt-bearing training-005 sessions each have an effect receipt. The fifth slot failed before application submission. | Preserve the exact Full/native-client and loaded-ELF identity evidence; held-out cases must independently exercise the complete predicate. |
| Current-root and own-revocation safety | Passed for the two controlled training credentials in the signed-history report. | Repeat for all eight post-freeze credentials, with separate unconsumed requests and no effect/consumption on rejection. |
| Training-004 | Nine of 60 slots completed; slot 10 was censored at the 256 MiB storage-growth cap. | Do not use as a completed matrix. Training-006 is the current registered replacement; training-005 failed before completion. |
| Training-005 | Four ordered receipts exist: `r1-k0-full`, `r1-k0-anchor`, `r1-k0-coalesced-full`, `r1-k1-full`. The fifth slot `r1-k1-anchor` generated a passing proof report, then failed before submission with `ValueError: finalized exact account bytes mismatch`; outer exit is 2, `passed` is false, and no fifth receipt exists. A read-only fresh-clone diagnostic matched all five account hashes but did not observe the original failure role, leaving cause unknown. | Preserve the failed slot artifacts. `--resume` refuses the partial slot. No full matrix, pooled distribution, CPU result, measured break-even, or 20% target result is available. |
| Training-006 | At the 23:31 UTC snapshot, `r1-k0-full` had a passing proof and completed slot receipt. The second slot `r1-k0-anchor` had started but had no receipt. One of 60 receipts existed and the matrix driver remained active. | Continue to record ordered receipts and failures. No full matrix, paired distribution, CPU result, measured break-even, or 20% target result is available. |
| Training-005 reproducibility inputs | Input, materialized manifest and plan hashes are recorded below; the freeze identities are in the registered input. | Check the exact digests and inspect the generated plan before interpreting results. A plan-only invocation does not execute or validate a campaign. |
| Held-out freeze and cohort | No held-out freeze, cohort, or held-out run exists. The R2 own-revocation receipt and total-cost verifier implementation is pushed in `14c7bbc`; the stable Rust runner has been built and pinned, and its seven-test list inspected, but no test bodies were run. | Complete the required training matrix gate before freezing source/artifacts and creating the fresh cohort. |
| Held-out cases and analysis | No manifests, fragments, assembled manifest, verifier report or cost report exist. | Run all eight frozen cases serially; assemble with fragment hashes; independently verify; then compute the matched cost report. |
| Final conclusion | **Not established.** | Valid training matrix, held-out acceptance, and a bounded application-level cost report with explicit assumptions and limitations. |

## Reproducibility and evidence boundary

The scrubbed evidence is under `results/dynark/part5/`; raw credentials, keys, witnesses, proofs, signed envelopes, and ledger clones remain in protected ignored artifacts. The checked-in training campaign inputs are `results/dynark/part5/v3-campaign-matrix-training-004.json` and `results/dynark/part5/v3-campaign-matrix-training-005.json`. The matrix driver and session runner expose their CLI surfaces with:

```sh
python3 -B -m tools.part5.run_v3_campaign_matrix --help
python3 -B tools/part5/run_v3_campaign_session.py --help
```

To reproduce the **historical 22:31 UTC snapshot inspection** from the
repository root, verify the registered training-005 input, materialized input
manifest, plan, and four receipts present at that time, then list currently
available receipts and ask the matrix driver to render (not execute) its plan.
The four receipt hashes remain the same, while the current tree also contains
the preserved failed fifth-slot artifacts described below:

```sh
set -euo pipefail
shasum -a 256 \
  results/dynark/part5/v3-campaign-matrix-training-005.json \
  artifacts/dynark/part5/v3-matrix-training-005/input-manifest.json \
  artifacts/dynark/part5/v3-matrix-training-005/matrix-plan.json \
  artifacts/dynark/part5/v3-matrix-training-005/slot-r1-k0-full/slot-receipt.json \
  artifacts/dynark/part5/v3-matrix-training-005/slot-r1-k0-anchor/slot-receipt.json \
  artifacts/dynark/part5/v3-matrix-training-005/slot-r1-k0-coalesced-full/slot-receipt.json \
  artifacts/dynark/part5/v3-matrix-training-005/slot-r1-k1-full/slot-receipt.json
find artifacts/dynark/part5/v3-matrix-training-005 -maxdepth 3 \
  -type f -name slot-receipt.json -print | sort
python3 -B -m tools.part5.run_v3_campaign_matrix \
  "$PWD/results/dynark/part5/v3-campaign-matrix-training-005.json" --plan
```

Compare the digest output with the pins below before interpreting the
historical snapshot. The plan command is intentionally non-executing; it does
not wait for, resume, or certify the campaign. For the 22:50 UTC state, inspect
all four ordered receipts and the failed fifth slot's proof, outer, session,
effect-monitor and clone reports. The failed slot directory has no slot receipt.
The matrix driver's `--resume` refuses this partial slot; retain the failure
artifacts and do not carry the old “slot 5 active” status forward.

The failure is not attributed to a root cause. The read-only fresh-clone check
matched all five account hashes, but did not observe the role that produced the
original failure. Do not infer that matching clone hashes explain or repair the
original submission path. Inspect
`artifacts/dynark/part5/application-v3-matrix-training-005-r1-k1-anchor-control/status.json`
for the `ValueError`, and the preserved `outer-report.json`,
`work/session-report.json`, `work/proof/proof-report.json`,
`clone/clone-report.json`, and `work/effect-monitor-private/report.json` under
`artifacts/dynark/part5/v3-matrix-training-005/slot-r1-k1-anchor/` for the outer
run, proof, session, clone, and monitor evidence.

Training-004's checked-in campaign input SHA-256 is `244e4f73bc898a1c36bc671314da3dc4e0ed147e0d35318b172228dd64f5fd57`. Its materialized input manifest is `artifacts/dynark/part5/v3-matrix-training-004/input-manifest.json` (SHA-256 `e0bd25765037702ee442b1243c95440c7a19e8698ed4b531f701fbfcdcf86816`) and its 60-slot plan is `artifacts/dynark/part5/v3-matrix-training-004/matrix-plan.json` (SHA-256 `ec694f1c6777667e538f423a055fd40613e86231ba755f49e5254c06ceba3fe3`). The run produced nine complete slot receipts and a censored slot-10 report at the storage-growth limit.

Training-005's checked-in campaign input SHA-256 is `7f3ddade5f647ac9dfb94e8ff46759134f493d5f3fadbd0d25be5d66ea5248f0`. Its materialized input manifest is `artifacts/dynark/part5/v3-matrix-training-005/input-manifest.json` (SHA-256 `4882b76277934f234f03c8a05d43209f8024111d69544055220d8d9614ee3001`) and its 60-slot plan is `artifacts/dynark/part5/v3-matrix-training-005/matrix-plan.json` (SHA-256 `649a6dcc4109d19ac390b4c4032c50377c8bcb9b8ad0be2faba3a0d1e87865ea`). The uniform per-slot storage-growth cap is 536,870,912 bytes (512 MiB). Commit `f21be84` registered this run. At the 2026-10-17 22:31 UTC snapshot, the first slot receipt and its pinned artifacts were:

- `artifacts/dynark/part5/v3-matrix-training-005/slot-r1-k0-full/slot-receipt.json` — SHA-256 `00744cfb592b3c32ebdee42e3112d4a2a41e88c1f1b6c2d8f944c19a80182fd3`
- `artifacts/dynark/part5/v3-matrix-training-005/slot-r1-k0-full/outer-report.json` — SHA-256 `96da45dc8407981de673f5faefbc4424bdadfc5a3209f08e47bc58d143c6b758`
- `artifacts/dynark/part5/v3-matrix-training-005/slot-r1-k0-full/work/session-report.json` — SHA-256 `b49878a078d93fd9b63acc178311de5beccb50702fec3e6854df16b2e738b265`
- `artifacts/dynark/part5/v3-matrix-training-005/slot-r1-k0-full/clone/clone-report.json` — SHA-256 `115c1d8c6faf84400d606a57dba548f4051db9df6cad269e522be84c7b729742`

The next three receipts in the completed chain were:

- `artifacts/dynark/part5/v3-matrix-training-005/slot-r1-k0-anchor/slot-receipt.json` — SHA-256 `f766d86ffda7d9da810d73878730191630970061d6613535aea9525906de887f`; outer report SHA-256 `ab1434002f01c682140c78803bf4ee961ba320da73cf667f6a86d69d168b6183`
- `artifacts/dynark/part5/v3-matrix-training-005/slot-r1-k0-coalesced-full/slot-receipt.json` — SHA-256 `c5d8bcea765282f7af4511aaf6a6e23e526928b93d203e7d11ccf6cbdc822aa6`; outer report SHA-256 `6668aa9965eb962f83cdbbe493a8a9ba47655bbae3fc9fd175a0de2ed7523a25`
- `artifacts/dynark/part5/v3-matrix-training-005/slot-r1-k1-full/slot-receipt.json` — SHA-256 `a635dbc0c5a805f83db13ad0eba4d88163888be7a2ecb4a49c1de84199f82936`; outer report SHA-256 `500ee7faa23cdbbfa86fa5fc17195cee0423d7e26517ef25870f1f7c89596e67`

The first slot's outer report records 473 samples, peak sampled RSS 1,392,771,072 bytes, peak sampled storage growth 194,224,002 bytes, exit code 0, and no censoring. The campaign state records a 129,600-second envelope starting `2026-10-17T21:52:18.230397Z`, with deadline `2026-10-19T09:52:18.230397Z`. At this snapshot, slot 5 (`k = 1`, Anchor) was active. These hashes and a non-executing plan inspection do not establish completion:

```sh
set -euo pipefail
python3 -B -m tools.part5.run_v3_campaign_matrix \
  "$PWD/results/dynark/part5/v3-campaign-matrix-training-005.json" --plan
```

The held-out commands below document reproducible inputs and a future run sequence; they do not indicate that the held-out run has occurred. The freeze input, prepare config, packet template and executable inputs listed below exist. The stable held-out Rust runner is built at `artifacts/dynark/part5/v3-heldout-queue-runner-001`, mode `700`, SHA-256 `2f289b4eb920593a06f86a2b806e12a62b7adad8920b79eaa4d8f6682c8bf2a1`. Its `--list` output contained the seven named tests below; no test bodies were run. The freeze, cohort, run manifests, case outputs, assembled manifest, verifier report and cost report do not exist. The output paths below are reserved names and each creation command requires its output path to be fresh. Run the blocks in order from the repository root; each block defines its own path variables. The freeze receipt and prior-key inventory go in the owner-only `results/dynark/part5/v3-heldout-freeze-001/` directory. Keep the cohort, case manifests, and case outputs under owner-only ignored paths in `artifacts/dynark/part5/`. Do not put raw credentials, keys, witnesses, proofs, signed envelopes or ledger clones in tracked prose or files.

The following records the held-out Rust runner build recipe. It was completed before the current snapshot: the stable copy is `artifacts/dynark/part5/v3-heldout-queue-runner-001`. A clean rebuild requires a fresh build target and an empty destination; do not overwrite the pinned stable copy. The Python campaign interpreter and raw Cargo output path are not valid `--runner` inputs.

```sh
set -euo pipefail
ROOT="$PWD"
PART5="$ROOT/artifacts/dynark/part5"
BUILD_TARGET="$(mktemp -d "$PART5/v3-heldout-queue-runner-build-XXXXXX")"
RUNNER="$PART5/v3-heldout-queue-runner-001"

test ! -e "$RUNNER"
CARGO_TARGET_DIR="$BUILD_TARGET" CARGO_BUILD_JOBS=1 /Users/anishnarang/.cargo/bin/cargo test \
  --offline --locked --manifest-path "$ROOT/harness/Cargo.toml" \
  --test queue_v3 --no-run

RUNNER_CANDIDATES="$(find "$BUILD_TARGET/debug" -maxdepth 4 -type f \
  -perm -111 -name 'queue_v3-*' -print)"
test -n "$RUNNER_CANDIDATES"
test "$(printf '%s\n' "$RUNNER_CANDIDATES" | wc -l | tr -d ' ')" -eq 1
RUNNER_BIN="$RUNNER_CANDIDATES"
LISTING="$BUILD_TARGET/queue-v3-tests.txt"
"$RUNNER_BIN" --list > "$LISTING"
for TEST in \
  root_pinned_queue_v3_stage \
  root_pinned_queue_v3_campaign_stage \
  root_pinned_queue_v3_campaign_transition \
  root_pinned_queue_v3_campaign_effect \
  root_pinned_queue_v3_execute \
  root_pinned_queue_v3_unrelated_transition \
  root_pinned_queue_v3_branch; do
  grep -Fqx "$TEST: test" "$LISTING"
done

install -m 700 "$RUNNER_BIN" "$RUNNER"
shasum -a 256 "$RUNNER"
```

Run these commands from the repository root. The freeze input is the existing status report `artifacts/dynark/part5/application-v3-campaign-prepare-control-002/status.json` (SHA-256 `b56d7def28b50c183ddd62d5b944119fa33f6a20140c10db6c0d28f3a11c231f`). It records a failed bounded prepare (`exit_code: -2`), a reaped process, no application effect, a loaded-ELF match, and `ledger_reuse_requires_review: true`. The freeze validator explicitly accepts this failed status only with that cleanup and review evidence; this is not evidence that preparation passed or that the application ran. Freeze output must be a fresh direct child of `results/dynark/part5/`. The adapter path and digest are pinned by the current training matrix input (`tools` → `adapter_binary`):

```sh
set -euo pipefail
ROOT="$PWD"
PREPARE_STATUS="$ROOT/artifacts/dynark/part5/application-v3-campaign-prepare-control-002/status.json"
ADAPTER="$ROOT/crates/dynark-solana-adapter/target/debug/build/dynark-solana-adapter/3a4659842a713e9a/out/v3_request_bound_host-3a4659842a713e9a"
FREEZE_DIR="$ROOT/results/dynark/part5/v3-heldout-freeze-001"

python3 -B tools/part5/freeze_v3_heldout_cohort.py \
  --prepare-status "$PREPARE_STATUS" \
  --adapter-binary "$ADAPTER" \
  --output-dir "$FREEZE_DIR"
```

After the freeze exists, issue the eight-certificate cohort using the tool that checks the freeze and prior-key inventory together. This builder generates the cohort; individual `issue_v3_heldout_certificate.py` invocations are not a substitute for its cohort-level freshness and coverage receipt. The resulting cohort directory is private and ignored:

```sh
set -euo pipefail
ROOT="$PWD"
FREEZE_DIR="$ROOT/results/dynark/part5/v3-heldout-freeze-001"
FREEZE="$FREEZE_DIR/freeze.json"
INVENTORY="$FREEZE_DIR/prior-key-inventory.json"
COHORT_ROOT="$ROOT/artifacts/dynark/part5/v3-heldout-cohort-001"
FREEZE_SHA="$(shasum -a 256 "$FREEZE" | awk '{print $1}')"
INVENTORY_SHA="$(shasum -a 256 "$INVENTORY" | awk '{print $1}')"

python3 -B tools/part5/build_v3_heldout_cohort.py \
  --freeze "$FREEZE" --freeze-sha256 "$FREEZE_SHA" \
  --prior-key-inventory "$INVENTORY" \
  --prior-key-inventory-sha256 "$INVENTORY_SHA" \
  --output "$COHORT_ROOT"
```

Build the eight run manifests from the existing base prepare config `artifacts/dynark/part5/application-v3-campaign-prepare-config-002.json` (SHA-256 `b5bb168545a3dfef91fa2b0430bf19912ffbbe6080c6b94041315256934d2853`) and packet template `artifacts/dynark/part5/v3-full-r1-proof-training-001/packet-003.json` (SHA-256 `f74da66ef9a12c03a028ed52bee8cb4de2ddf0958abbecb0b7e528b22065512b`). These are pinned construction inputs, not held-out run evidence. The manifest builder requires `--runner` to resolve exactly to the stable Rust executable `artifacts/dynark/part5/v3-heldout-queue-runner-001` described above; the build step must run before freezing because this file is included in the frozen registry bundle. The builder verifies the file and embeds its path and SHA-256 in each manifest. Other pinned inputs are the bounded supervisor `results/dynark/part5/session_runner.py` (`77fc4107089d14039af8726051e174a9b6508e09c13b07e2ac1bcc083eec5429`), Node `/Users/anishnarang/.nvm/versions/node/v24.10.0/bin/node` (`9e759d34d97af8a71b75854d20af297794611155406997f06d796b5e0f6d573b`), exporter `program/target/debug/examples/export_v3_request_fixture` (`d5b10820153334b5cb5996ad2f26aad95a033741e0883f69019ebf79fb051700`), and the adapter above (`5e364d7ea4d2321a1135e697ed7cf3233abaa832d371bff2f4dfdf2ea5ff6521`). The builder verifies and embeds their hashes and emits `case-00.json` through `case-07.json`:

```sh
set -euo pipefail
ROOT="$PWD"
FREEZE_DIR="$ROOT/results/dynark/part5/v3-heldout-freeze-001"
ADAPTER="$ROOT/crates/dynark-solana-adapter/target/debug/build/dynark-solana-adapter/3a4659842a713e9a/out/v3_request_bound_host-3a4659842a713e9a"
FREEZE="$FREEZE_DIR/freeze.json"
COHORT_ROOT="$ROOT/artifacts/dynark/part5/v3-heldout-cohort-001"
BASE_PREPARE_CONFIG="$ROOT/artifacts/dynark/part5/application-v3-campaign-prepare-config-002.json"
PACKET_TEMPLATE="$ROOT/artifacts/dynark/part5/v3-full-r1-proof-training-001/packet-003.json"
# Set after the held-out Rust queue_v3 runner has been built and pinned.
RUNNER="$ROOT/artifacts/dynark/part5/v3-heldout-queue-runner-001"
SUPERVISOR="$ROOT/results/dynark/part5/session_runner.py"
NODE="/Users/anishnarang/.nvm/versions/node/v24.10.0/bin/node"
EXPORTER="$ROOT/program/target/debug/examples/export_v3_request_fixture"
RUN_MANIFESTS="$ROOT/artifacts/dynark/part5/v3-heldout-run-manifests-001"

python3 -B tools/part5/build_v3_heldout_run_manifest.py \
  --freeze-receipt "$FREEZE" \
  --cohort-root "$COHORT_ROOT" \
  --base-prepare-config "$BASE_PREPARE_CONFIG" \
  --packet-template "$PACKET_TEMPLATE" \
  --adapter-binary "$ADAPTER" \
  --bounded-supervisor "$SUPERVISOR" \
  --node "$NODE" --exporter "$EXPORTER" --runner "$RUNNER" \
  --output-dir "$RUN_MANIFESTS"
```

Run cases serially, one manifest per declared DER variant. Each case output root is private and ignored; a completed run writes `acceptance-case-fragment.json` there. The runner accepts only a pinned manifest and output root:

```sh
set -euo pipefail
ROOT="$PWD"
RUN_MANIFESTS="$ROOT/artifacts/dynark/part5/v3-heldout-run-manifests-001"
for V in 00 01 02 03 04 05 06 07; do
  python3 -B tools/part5/run_v3_heldout_case.py \
    --manifest "$RUN_MANIFESTS/case-$V.json" \
    --output-root "$ROOT/artifacts/dynark/part5/v3-heldout-case-$V"
done
```

After all eight fragments exist, pin each fragment's SHA-256 at assembly time. The assembler requires exactly eight distinct fragments covering variants 0–7 and writes a scrubbed-reference manifest to a fresh ignored directory:

```sh
set -euo pipefail
ROOT="$PWD"
ASSEMBLED_DIR="$ROOT/artifacts/dynark/part5/v3-heldout-assembled-001"
FRAGMENTS=()
for V in 00 01 02 03 04 05 06 07; do
  FRAGMENT="$ROOT/artifacts/dynark/part5/v3-heldout-case-$V/acceptance-case-fragment.json"
  FRAGMENT_SHA="$(shasum -a 256 "$FRAGMENT" | awk '{print $1}')"
  FRAGMENTS+=(--fragment "$FRAGMENT:$FRAGMENT_SHA")
done
python3 -B tools/part5/assemble_v3_heldout_acceptance.py \
  "${FRAGMENTS[@]}" --output-dir "$ASSEMBLED_DIR"
```

Run the independent verifier against the assembled manifest. Then run the cost analyzer against that manifest and verifier report, computing their digests after each output exists. The verifier accepts a manifest path; the analyzer requires `PATH:SHA256` references. Both output paths must be fresh:

```sh
set -euo pipefail
ROOT="$PWD"
ASSEMBLED_DIR="$ROOT/artifacts/dynark/part5/v3-heldout-assembled-001"
ASSEMBLED_MANIFEST="$ASSEMBLED_DIR/heldout-acceptance-manifest.json"
ASSEMBLED_SHA="$(shasum -a 256 "$ASSEMBLED_MANIFEST" | awk '{print $1}')"
ACCEPTANCE_REPORT="$ROOT/results/dynark/part5/v3-heldout-acceptance-001.json"
COST_REPORT="$ROOT/results/dynark/part5/v3-heldout-cost-analysis-001.json"

python3 -B tools/part5/verify_v3_heldout_acceptance.py \
  --manifest "$ASSEMBLED_MANIFEST" --output "$ACCEPTANCE_REPORT"
ACCEPTANCE_SHA="$(shasum -a 256 "$ACCEPTANCE_REPORT" | awk '{print $1}')"
python3 -B tools/part5/analyze_v3_heldout_costs.py \
  --manifest "$ASSEMBLED_MANIFEST:$ASSEMBLED_SHA" \
  --acceptance-report "$ACCEPTANCE_REPORT:$ACCEPTANCE_SHA" \
  --output "$COST_REPORT"
```

The verifier report and cost analysis are not present yet. No static input path is left as a placeholder; the remaining dependencies are outputs to be generated in order: the freeze/inventory pair, cohort receipt, eight run manifests, eight case fragments, assembled manifest, and verifier report. The digest commands compute pins from those output bytes. The cost analyzer reports request-B wall costs both without and with the one-time shared credential preparation charged to each mode, with a corresponding wall-savings fraction for each basis. It does not infer CPU savings or classify an economic winner. Training-005 has a preserved failed partial slot and is not a completed matrix; it does not constitute held-out issuance or acceptance. No held-out acceptance or final economics result is claimed here.

The current campaign freeze records the development circuit, profile, setup, ordinary VK, proof runner, client, adapter, application source, and loaded ELF identities in `results/dynark/part5/v3-campaign-freeze-002/`. This training freeze is not a held-out freeze. Completion still requires a validated full matrix, independent held-out acceptance, and a report that answers whether total application work improves for a justified update pattern. Until then, the economic conclusion is **not established**.
