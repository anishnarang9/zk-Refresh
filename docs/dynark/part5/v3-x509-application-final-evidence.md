# v3 bounded X.509 application evidence (draft)

**Evidence snapshot:** 2026-10-17 23:31 UTC
**Source revision:** `14c7bbc` (`codex/engine-focus-oct14`; same as `origin/codex/engine-focus-oct14` at this snapshot)
**Status:** training correctness demonstrated; training-004 was censored during slot 10 and training-005 failed in slot 5 after its Anchor proof passed but before application submission. Training-006 is running: its first Full slot has a passing proof and completed slot receipt, and its second slot is in progress without a receipt. Exactly one of 60 receipts exists at this snapshot. No full matrix, final economics, or held-out acceptance result is established. This is a draft, not a campaign-completion report.

**Post-snapshot implementation status (after 23:31 UTC; additions do not revise the snapshot above):** The independent all-eight key/DER import verifier was added in pushed commit `551a980`; its 27 focused tests passed, but no held-out data or cohort exists. The economics analyzer's nested monitor revalidation was added in pushed commit `152036b`; its 12 focused tests passed. The lightweight held-out validation suite also passed 87 unittest checks and 18 case-level pytest checks; these are code/fixture checks, not held-out acceptance results. These checks establish no complete matrix or full-matrix economics; subsequent dated updates below record Training-006 and Training-007.

Pushed commit `1fd7f53` adds held-out effect-transaction and pinned proof-artifact byte accounting in `tools/part5/analyze_v3_heldout_costs.py`; focused regression cases cover successful pinned transaction fields and artifact presence with unknown retention lifecycle. Pushed commit `9c06d11` adds campaign Execute transaction metrics in `tools/part5/analyze_v3_campaign_economics.py`; its tests require the session-pinned, successful, mode-matched effect report. A read-only extraction of the actual Training-006 repetition-1, `k = 1`, Full effect report records the successful application transaction as 825 bytes, 185,532 compute units, and 5,000 lamports, confirmed at slot 186; the effect is separately finalized at slot 187. The held-out analyzer verifies receipt-pinned artifact bytes are present during analysis, but their retained lifetime is unknown. No held-out receipts exist, so there is no held-out artifact total, acceptance result, or economic result. This update leaves the historical snapshots above unchanged and establishes no full-matrix economics.

**2026-10-17 post-snapshot implementation update (workspace checked 2026-10-18 01:02 UTC):** Pushed commits `2cf92da`, `30b983b`, and `7597d54` update the training total summary to carry available transaction/compute/fee metrics, add direct campaign-cost reconciliation CLI support, and strengthen held-out verification of Anchor's exact request consumption and single queue append while adding the loaded wrong-account-order negative to the harness/verifier path. Commits `f029b58`, `04d542e`, and corrective `71dcb2c` charge measured caught failed attempts in held-out retries and reject hard interruptions whose work time cannot be separated from idle downtime. The related lightweight Python suite passed 76 tests and 37 subtests; the new loaded negative and held-out path have not run. At this check, Training-007 had three of 60 verified ordered slot receipts: repetition 1, `k = 0`, Full, Anchor, and coalesced Full. Each chains to the preceding receipt and records a passed, effect-verified, uncensored session. The matrix remains incomplete; `v3-heldout-queue-runner-002` was absent at the documented build path. No held-out receipt, acceptance, or full-matrix economics result is established.

**Cost-model correction (2026-10-18 01:00 UTC):** Pushed commit `72a43e7` charges each matched `k` pair for its exact measured R0-to-Rk transition, rather than summing independent transitions to smaller target counts. The matrix clones only the exact target transition for each slot. Thirty focused economics tests pass, including a new exact-transition regression. No Training-007 cost report has been produced yet.

**2026-10-18 post-snapshot update (01:06 UTC):** Pushed `4323f65` to apply the registered median strict-positive break-even rule, carry confirmed transaction-byte/compute/fee samples, and expose matrix-grid completeness; pushed `ef2506e` to require the 60-slot grid for the held-out model. The related Python suite passed 41 tests and 4 subtests. Training-007 remains live and incomplete; the last verified ordered receipt sequence has four receipts, ending at repetition 1, `k = 1`, Full (`r1-k1-full`). No full-matrix or held-out result is established.

**2026-10-18 implementation and run update (01:20 UTC):** Pushed `c255ccf`, `699963d`, `210736b`, and `9e1e897` so cost reconciliation requires and revalidates the completed 60-slot receipt chain, the total summary and held-out model carry its SHA-256 pin, and sequence timings match each current slot report. The related focused suite passed 28 tests. Training-007 still has four independently verified ordered receipts; `r1-k1-anchor` is running without a fifth receipt. The held-out runner-002, held-out cohort, full-matrix reports, and final benefit result do not yet exist.

**2026-10-18 implementation update (01:25 UTC):** Pushed commit `3912f01` updates the local acceptance verifier to construct matching-issuer, signed, out-of-profile DER with `notBefore` in 1999 for each of the eight variants and reject it at the UTCTime profile bound. The 32 focused tests pass. The new DER check is local admission only; no held-out cohort, case run, or held-out loaded-ELF negative has executed. Loaded config/status, queue-capacity, and ambiguous-restart cases remain limitations; this does not complete the acceptance matrix.

**2026-10-18 current implementation and Training-009 update:** Pushed source-only commits `b952269` (one-shot response-drop proxy), `470f0b9` (opt-in Rust finalized pre-submit snapshot), `5172aa2` (same-ledger restart supervisor and source tests), `c15a71e` (freeze inventory), and `9e958be` (reviewed SIGINT stop path). No live ambiguous-restart or held-out acceptance run has occurred. Training-009 has 8 of 60 ordered verified slot receipts; slot 8 (`r1-k2-anchor`) has receipt SHA-256 `a2b729e7a51bc68be8d1c0066ccdeb9ef9a510614661838a97f1ec892fd71789`. Its outer run was uncensored and exited 0, with `effect_verified=true`; the nested effect supervisor failed, the application stage exited 1, and whole-tree CPU remains unqualified. The matrix is incomplete: there is no held-out freeze, `v3-heldout-queue-runner-002`, held-out measurement, or break-even result. Uncommitted held-out runner, verifier, and cost integration is source under review, not established evidence.

**Training-009 stop and recovery decision (2026-10-18):** The driver exited at sequence 10 (`r1-k5-full`) after nine contiguous verified receipts; sequence 9 (`r1-k2-coalesced-full`) has receipt SHA-256 `2ff981622b5ac92bac840d7c9ee13cd2f1b3594c6b38862b29477999943f705f`. The slot-10 packet has the registered terminal `update_count = 5` and checkpoints 1 through 5. The pinned proof runner passed checkpoints 1 and 2, then rejected checkpoint generation 3 because its per-checkpoint admission call uses the terminal-count allowlist `{0, 1, 2, 5, 10}`. The proof stage exited 1; the bounded outer report exited 2 after 93.819 seconds without censoring or a resource stop and found no remaining owned processes. No slot-10 receipt or protected effect exists. The partial slot also makes `--resume` reject the output root. A corrected proof runner changes the pinned tool identity, so the nine Training-009 receipts and failed-attempt cost remain separate historical evidence; a corrected 60-slot measurement requires a fresh registered campaign. Pushed source commit `8f867eb` separately keeps the ambiguous proxy's exact target wire for the opt-in positive Execute, with the account-metadata negatives using a distinct validated Full wire. This is a source fix only; no held-out ambiguous-restart run has occurred.

**Training-010 preparation snapshot (2026-10-18 03:56 UTC):** Fresh freeze `results/dynark/part5/v3-campaign-freeze-003/freeze.json` has SHA-256 `3aa9c34057a44db5d040777c6e8ad94bf9fa567bf12f9260742b08ef5428c203` and pins isolated proof runner `artifacts/dynark/part5/v3-proof-runner-training-010` at `093659cec842945fd3db15e9e51087b5717d71dcb375fdf60ced58279a5ad19a`. The bounded cohort monitor passed (report SHA `f11952abcf3c66c41e2b1a73c5a50b738f65fa943f7617b8ef034261dbb52610`); its signed 11-credential training receipt is `eaa8421800d162bd4fd5ee48e74b42ee5858ea31e29748e1f289822ea9fcf849`, and context SHA is `399c8a04446ea8f774142c105e9fbdafd41250b0a432eda99dc293ac6ac13e1b`. The R0 stage report passed as training-only, with no proof or application effect (SHA `f43fa88fe770a666ef4f7dc72a53fb139ee9b91b4ed2ec2917f2b13ae7ff0355`); R0 k=1,2,5 ledger clones were byte-identical and stable, with clone report SHAs `1ee79b8468b4339614ae3c9d43b2d7aec1f5b591535e0cdc56d620a3ee75efb3`, `b8283773ab84b045062e6d377786ed410ab12209f8b4213cc13f267ecac33019`, and `6c236b41cc7e64c9d904b37db586a4d89587d15806d3a9bdaaca04ff6af9e202`. The k=1,2,5 transition reports each passed their training-only authenticated-history checks, preserved the unconsumed request, and recorded no application effect; report SHAs are `31ed3e60a53abfbf4dcf07f8dd8389373cfd777ede5a398c8b7b86b5da44990b`, `1f81c9fb5035163d424298885d1f0ed21b99ecfe9c5c1360bff1d40b6648d500`, and `b1d3adf72658c663dee9257fab90350d613c0a386a0a8c031062bf4695f17494`. The outer bounded monitors are uncensored, report no resource stop or runner error, and find zero remaining owned processes, but exit 1 because each control status records the validator's SIGINT shutdown as non-graceful (`-2`); each campaign runner was reaped with exit 0. These are not outer-monitor passes, and complete descendant CPU accounting remains unqualified. At this snapshot the k=10 transition report is not present; neither the k=5 whole-session smoke nor the 60-slot matrix, economics reconciliation/summary, held-out freeze/cases/acceptance/cost report exists. The 20% threshold, break-even, and whole-session benefit are therefore unresolved.

**Separate development-attempt cost disclosure (Training-004 through Training-009):** These incomplete runs are historical development attempts excluded from matched savings. Counts below inventory saved completed slot receipts; the measured seconds and storage refer only to the failed slot, not the preceding successful slots or total development expenditure.

| Attempt | Completed slots; last completed | Failed slot | Outer seconds | Stop/failure | Sampled peak storage growth (bytes) | Proof/effect evidence |
|---|---|---|---:|---|---:|---|
| 004 | 9; `r1-k2-coalesced-full` | `r1-k5-full` | 32.455 | Storage-growth limit; censored, exit -15 | 269,710,052 | No proof/effect evidence |
| 005 | 4; `r1-k1-full` | `r1-k1-anchor` | 1,240.862 | Uncensored exit 2; finalized account bytes mismatch | 219,371,095 | Proof passed; application runner not spawned, no effect |
| 006 | 5; `r1-k1-anchor` | `r1-k1-coalesced-full` | 75.881 | Uncensored exit 2; finalized config bytes mismatch | 194,247,579 | Proof passed; application runner not spawned, no effect |
| 007 | 5; `r1-k1-anchor` | `r1-k1-coalesced-full` | 0.288 | Uncensored exit 2; preregistered cohort freeze rejected | 5,349 | Zero session stages; no proof/effect |
| 008 | 3; `r1-k0-coalesced-full` | No failed-slot report saved | Unknown | No failed-slot outer observation | Unknown | Subsequent failed-slot proof/effect work unknown |
| 009 | 9; `r1-k2-coalesced-full` | `r1-k5-full` | 93.819 | Uncensored exit 2; proof rejected registered update count | 319,958,096 | Proof failed after partial work; no application stage/effect |

The failed-slot sources are `artifacts/dynark/part5/v3-matrix-training-NNN/slot-SLOT/outer-report.json`, with `NNN` and `SLOT` from the table; session stage evidence, where saved, is in the same slot's `work/session-report.json`. Training-005 and Training-006 also record an unspawned application runner in their corresponding `application-v3-matrix-training-NNN-r1-k1-MODE-control/status.json`. Training-004's censored duration measures work before termination, not completion time. Storage values are sampled peaks, not cumulative writes. Training-008 has no failed-slot duration/storage measurement to impute. These rows do not sum incompatible attempts into a matched mode result and do not establish campaign completion.


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
| Frozen held-out acceptance and cost analysis (plan Gate 5) | After identity freeze, admit eight unseen profile credentials without per-certificate code/setup; pass each Full, unrelated-revocation Anchor, own-revocation and replay case plus negatives; run the frozen cost method and independently verify assembled receipts. | **Pending.** R2 own-revocation receipt and total-cost verifier code is pushed in `14c7bbc`; the older `queue-runner-001` is built and pinned but stale; the required `queue-runner-002` is not built. No held-out freeze, cohort, run, assembled manifest, verifier report, or cost report exists. |

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

At the 2026-10-17 23:31 UTC snapshot, Training-006 was the current 60-slot replacement matrix. Its checked-in input is `results/dynark/part5/v3-campaign-matrix-training-006.json` (SHA-256 `c2415bf7fedc8b2119c946bad83462f38f95a2a58bfff9e52bbbb83c06fadf86`); the materialized input manifest is `artifacts/dynark/part5/v3-matrix-training-006/input-manifest.json` (SHA-256 `0a9c9cfee26093a7a719b8ae9a5bcb8d4ffe067633f16fa3f170c9449ce0567a`), and its plan is `artifacts/dynark/part5/v3-matrix-training-006/matrix-plan.json` (SHA-256 `bfcd079e37314b9d40751c83ab851e435d1e44ebd5def0277945bc6ddcec0d42`). The plan has four repetitions at each `k = 0, 1, 2, 5, 10` for Full, Anchor, and coalesced Full (60 slots total), with a uniform 512 MiB per-slot storage-growth cap. The pinned campaign helper is `harness/tests/queue_v3_local_execute.py` (SHA-256 `dc9ab5dcb3bb086e73fb7e995f990ca5eddf14cba71fdb88d93942928cc3463c`), added and pinned by `cbf1f07`; the source revision when launched is `14c7bbc`. Its matrix Python artifact is `artifacts/dynark/part5/v3-campaign-python-002` (SHA-256 `4fce274f0e60574ada0b53f17bceb49bbd804125ddae972c7674b8eb13d9e49d`). The actual launch command was:

```sh
artifacts/dynark/part5/v3-campaign-python-002 \
  -B -m tools.part5.run_v3_campaign_matrix \
  results/dynark/part5/v3-campaign-matrix-training-006.json
```

The campaign state records start `2026-10-17T23:28:34.166072Z` and deadline `2026-10-19T11:28:34.166072Z`; the driver process was still running at this snapshot. Slot `r1-k0-full` has a passing proof, a finalized and verified application effect, and a passing session and outer report (outer exit code 0, no stop reason); its `slot-receipt.json` (sequence 1) exists. The nested effect supervisor exited 1 after validator cleanup ended on SIGINT (`-2`), with `ledger_reuse_requires_review: true`. The session gate explicitly accepts this reviewed shutdown because the effect is verified; this does not establish clean ledger reuse. The matrix had advanced to the second slot, `r1-k0-anchor`; its ledger clone report and proof-stage work files existed, but no slot receipt had been written. Exactly 1 of 60 receipts existed at this snapshot. This is progress evidence only: no complete matrix, paired economics, held-out result, or economic benefit is established.

### Training-006 progress update (2026-10-17 23:53 UTC)

The `r1-k0-anchor` slot has now completed and produced its ordered sequence-2 receipt, `artifacts/dynark/part5/v3-matrix-training-006/slot-r1-k0-anchor/slot-receipt.json` (SHA-256 `33c4e243f1e805c57e83ca059e3e49269748144c64b447ec4a676c69e0a163dc`). The outer bounded run passed uncensored with exit code 0 and duration 1,296.850 seconds. The session records `effect_verified: true` and passed. Its nested effect supervisor is marked failed because validator cleanup ended on SIGINT (`-2`); cleanup was reaped, and the session records `ledger_reuse_requires_review: true`. This is a reviewed cleanup outcome, not evidence of clean ledger reuse. The receipt also records `cross_session_order_verified: false` and `complete_tree_cpu_qualified: false`, so CPU accounting remains unqualified. Exactly 2 of 60 slot receipts existed at this update: `r1-k0-full` and `r1-k0-anchor`. This is one completed training `k = 0` Full/Anchor pair only; it establishes no full-matrix economics, break-even, or savings result.

Commits `7631209` (read-only request denial path) and `7761a32` (local DER admission negatives) were made after the 23:31 snapshot. These changes were not loaded into held-out evidence: a runner rebuilt with the updated code identity and a held-out cohort run are still required. The 23:31 evidence snapshot above remains unchanged.

### Training-006 progress update (2026-10-18 00:02 UTC)

The ordered `r1-k0-coalesced-full` and `r1-k1-full` receipts have completed, bringing the matrix to 4 of 60 receipts. The `r1-k1-full` receipt is `artifacts/dynark/part5/v3-matrix-training-006/slot-r1-k1-full/slot-receipt.json` (SHA-256 `f7c8610c089c33c541ad7b5062d27639e438518bd9323968c972797b849ea2c0`). Its outer bounded run passed uncensored, and its session and finalized application effect were verified. The proof-stage report's `application_verified: false` describes only the proof stage. The nested effect supervisor recorded reviewed SIGINT validator cleanup, so this receipt does not establish clean ledger reuse or complete-tree CPU accounting. Slot `r1-k1-anchor` is proving; no fifth receipt or matched `k = 1` pair exists yet.

Pushed commits `22e387c` and `f069733` make the held-out freeze and verifier require the replacement `queue-runner-002`, and require branch request-consumption evidence to agree with the reported effect. The replacement binary has not been built while the matrix owns the heavy-job slot. The freeze script itself does not enforce training-matrix completion, so the complete 60-slot matrix and its validated summary must be checked before the held-out freeze command is run. The table rows above retain their explicitly dated 23:31 snapshot and are not current held-out results.

### Training-006 progress update (2026-10-18 00:27 UTC)

Five ordered receipts now exist, through `r1-k1-anchor`. That Anchor receipt is `artifacts/dynark/part5/v3-matrix-training-006/slot-r1-k1-anchor/slot-receipt.json` (SHA-256 `43dc3102943979a98b6d9b497e9a6281e267cb1cc07f0c6f74f1e0c2bde51a52`); its outer run passed uncensored in 1,307.214 seconds. The exact protected-account hashes recorded for the `k = 1` Full and Anchor effects match. The next slot, `r1-k1-coalesced-full`, completed proof generation but stopped before application submission: its pre-submit finalized config was at context slot 62 while the transition report was finalized at slot 83. The uncensored outer run failed with exit code 2 after 75.881 seconds; no protected effect occurred and no slot receipt was produced. The matrix driver `--resume` refuses this existing failed partial slot. Training-006 remains incomplete; no full-matrix economics or held-out result is established. The early-replay guard is under investigation; no fix or replacement run is verified here.

### Training-007 registration and launch update (2026-10-18 00:34 UTC)

Pushed commit `ebca62d` changes the campaign effect supervisor to request finalized protected-account bytes with `minContextSlot` set to the transition's finalized slot for `k > 0` (and the staged slot at `k = 0`). In a fresh diagnostic copy of the same stopped Training-006 `k = 1` ledger, the first minimum-slot-83 RPC attempt returned a readiness error; a subsequent read reached the exact Rk account bytes at finalized slot 84. Diagnostic shutdown still used reviewed SIGINT cleanup and remains review-required for ledger reuse; this does not establish clean reuse or itself create a matrix receipt.

Pushed commit `2ba67a9` registers Training-007. Compared with the Training-006 input, its manifest changes exactly four fields: `campaign_id` (`training-006` to `training-007`), `output_root` (Training-006 to Training-007), `tools.effect_execute.sha256` (`dc9ab5dcb3bb086e73fb7e995f990ca5eddf14cba71fdb88d93942928cc3463c` to `df6fd4ff07bab02fffc8f05c3c58e2e744432a37b23c0ee25bb4addcc2fd430e`), and `tools.effect_supervisor.sha256` (`f70d2e868a197d45d2406a7d5199d5f32299bde5590efef8bcfa702de4da0dc5` to `2851442797c8daff367138646e6f6f4020cbee9eb0ec9de66dbe350b35d53ac0`). The registered 60-slot plan has 20 slots per mode, 12 per `k` value (`0, 1, 2, 5, 10`), and four repetitions. Its materialized input-manifest SHA-256 is `950aed2abbbcfb7cd903d045ec348fbbae2be8db697ae0106425c6c0a8bc04f1`; the plan SHA-256 is `4c8e9c1508221012106c4708d2a14b22f338c56c6647acaa67a0cfb2598f5da2`.

Training-007 launched at `2026-10-18T00:33:21Z` with a 36-hour campaign envelope. At the 00:34 UTC inspection, the matrix driver was running in `r1-k0-full`; no slot receipt, economics summary, or complete-matrix result existed. Training-007 therefore establishes no full-matrix economics or held-out acceptance result.

### Training-007 progress update (2026-10-18 00:38 UTC)

The first ordered receipt, `r1-k0-full`, is present at `artifacts/dynark/part5/v3-matrix-training-007/slot-r1-k0-full/slot-receipt.json` (SHA-256 `c69adf7705dc24505f7e17b84f1e92f251217989bfbe3931a7b4fc61ae38b44c`). The uncensored outer run passed with exit code 0 in 110.626 seconds; the session passed and the protected effect was verified. The nested effect supervisor's validator cleanup ended by SIGINT (`-2`) and was reaped; the session marks ledger reuse as requiring review. This remains a reviewed cleanup outcome, not clean ledger reuse. Exactly 1 of 60 slot receipts existed at this update; no campaign economics summary is available.

Pushed commit `b706919` adds controlled local signed-current-head evidence for R0/R1/R2 and corrects the verifier's config root-version byte order. Its focused verifier suite passed 30 tests. Pushed commit `cd6e5cd` makes held-out cost analysis require complete, mutually consistent R0/R1/R2 head evidence; its focused analyzer suite passed 22 tests. These are verifier/analyzer code checks only: no held-out credential data, acceptance receipt, or held-out result exists.

A prior single-pair engineering run measured Full at 115.326 seconds and Anchor at 1,244.766 seconds of bounded whole-session wall time. Anchor's public and private preparation cost 447.573 and 682.496 seconds; refresh plus ordinary verification was 0.982 seconds. Both modes produced the protected effect. This is one training pair, excluded from the amended matrix: Full paid an Anchor-only preflight, and the run did not establish pooled economics or complete-tree CPU savings. The warm refresh time is not a session-level benefit. See [the matched-session method amendment](v3-matched-session-protocol-amendment-2026-10-17.md) and [the signed-history training check](v3-signed-history-k1-training-effect-2026-10-17.md).

The current matrix uses the amended comparator: Full and coalesced Full omit Anchor-only delta/support preparation; all modes authenticate the same history and validate complete witnesses. Count `k` is the number of distinct authenticated root changes for one still-unconsumed exact request. The chosen update pattern is controlled synthetic training history, not observed issuer churn or user action-lifetime data.

### Training-007 stop and Training-008 launch update (2026-10-18 01:32 UTC)

Training-007 ended in slot 6, `r1-k1-coalesced-full`, before the application stages. Its five valid ordered receipts end at sequence 5, `r1-k1-anchor` (receipt SHA-256 `7d3a7060ff596bab05fa376eb7fc913bc448feaf83337d28cef4d54468b8c129`). The slot's session failed with `ValueError: exact preregistered campaign cohort freeze required`; the outer run exited 2 after 0.287883916 seconds. No slot-6 receipt or protected effect exists. The campaign is incomplete and has no full-matrix economics result.

The failure was traced to the issuance source SHA changing from the frozen `619908b599cb7a90359f714101500fce58b8dce711a31fb6ae4c6e5b367b203c` to `02b7b54d15672f3ea578522c11799da03af02262748f940b7bf00435546fe999` in pushed hardening commit `786bd0a`. The exact frozen source was restored in pushed commit `512c181`. Training-008 was registered in pushed commit `a039cb4`; relative to Training-007, its manifest changes only `campaign_id` and `output_root`. Its raw input SHA-256 is `577be58dd02a27560f6502bfef6d3c1b5e3e6574b6706f833115011968e7c712`, and its canonical manifest SHA-256 is `02a6ea58c47a99496d4107d06d0565c4d54c1a65aae628ef9d97fb84518bae4c`. Preflight validated the 60-slot plan, frozen pins, and ports. Training-008 has launched and its first clone has started; no Training-008 slot receipt is verified yet. These launch checks do not establish any matrix outcome, economics, or held-out result.

### Training-008 first receipt (2026-10-18 01:34 UTC)

The ordered sequence-1 `r1-k0-full` receipt is present at `artifacts/dynark/part5/v3-matrix-training-008/slot-r1-k0-full/slot-receipt.json` (SHA-256 `407dcabf3db6fe1e97fcfd2e56e0900da18e845324f5783ba7b5dfb4c710c325`). The uncensored outer run passed in 110.484 seconds with exit code 0; the session passed and verified the protected effect. Validator cleanup remains review-required for ledger reuse. The 60-slot campaign is still running; this single receipt does not establish paired economics, break-even, or held-out acceptance.

### Training-008 stop and Training-009 launch (2026-10-18 02:02 UTC)

Training-008 stopped after exactly three ordered receipts, all for repetition 1 at `k = 0`: sequence 1 `r1-k0-full` (SHA-256 `407dcabf3db6fe1e97fcfd2e56e0900da18e845324f5783ba7b5dfb4c710c325`), sequence 2 `r1-k0-anchor` (SHA-256 `b82a8984246851ed50630f68c26c50f6b904d3fd3def660bb507d3462601f869`), and sequence 3 `r1-k0-coalesced-full` (SHA-256 `1990708a1e492052076c3d2759fc35c3c4f8d5061e403adcc1cbb810b15be83c`). The campaign matrix driver's `tool_names_for_campaign` omitted `effect_execute` even though the Training-008 manifest pinned it, so the session argv omitted the helper pin. No slot-4 (`r1-k1-full`) clone was created. The run is incomplete: no complete matrix, paired economics, break-even, or application-level benefit result is established.

Training-009 replaces the incomplete Training-008 run. Its manifest was added and pushed in commit `499a82f2c5b49af79cfd00a73881a9586cd3e99f`, and the remote branch matched that commit when checked. The same commit includes the matrix-driver fix that forwards `effect_execute` in every session argv; the pinned driver source SHA-256 is `a24b7035bbc73032a96a38358a3e68fd0ef9eaa9d7381be781300317faa13ce8`. Relative to Training-008, the manifest changes only `campaign_id` and `output_root`. The Training-009 input's raw SHA-256 is `f5ff9b2ec6faa81da5a46e289f7174b0b7d73d4eb9e5713159a74120d0e679b4`; its canonical JSON and materialized input manifest have SHA-256 `75e2a9e22211d1ccc5899975cf60ff9c60db2cb8e0c3819785789e7b47688d5d`, and the materialized plan SHA-256 is `d281ba8efd59a43e3db2882bb53dd60d3b2bd7aff90864cd7a00454a27380ba9`. Pinned-interpreter preflight validated the 60-slot plan, with `effect_execute` SHA-256 `df6fd4ff07bab02fffc8f05c3c58e2e744432a37b23c0ee25bb4addcc2fd430e` forwarded in all session argv. The campaign started at `2026-10-18T02:02:25.635344+00:00` with a 36-hour envelope. PID `47786` was live at the latest check; its first `r1-k0-full` session had begun and displayed the helper arguments. No Training-009 slot receipt exists yet. This confirms registration, pinned preflight, and launch only; no matrix outcome, economics, or held-out result is established.

**Training-009 progress snapshot (2026-10-18 02:29 UTC):** The manifest-pinned slot verifier passed the contiguous first three receipts, all at repetition 1 and `k = 0`: Full sequence 1 SHA-256 `0e407c1590f20583dbad829d4b0cb838d0ebee0e0617835a004cd88233a7ce6d` (outer 108.575 seconds), Anchor sequence 2 SHA-256 `e4f461feec2171ca3c7ec9daa77b5fde2acb52d58d35f4e89fdddaeb5aa77d95` (outer 1267.729 seconds), and coalesced Full sequence 3 SHA-256 `403db0f706442f62ca34777540a26a3732757a347e4201c3024a5f4d94168511` (outer 109.867 seconds). Each outer report records exit 0 without censoring or a stop reason, and each session records `effect_verified=true`. The nested effect supervisor status is `failed` with application-stage exit 1 after reviewed validator SIGINT cleanup; the complete-tree CPU metric remains unqualified. The driver had advanced beyond the three receipts. A read-only pin audit found all 38 materialized input refs and all 38 freeze-identity file pins matched current bytes, including the four cohort source hashes. Three of 60 slots do not establish the registered economics, a break-even point, or held-out acceptance.

### Post-snapshot negative-coverage status (source revision `2a79c60`)

This inventory describes source and planned coverage after the dated evidence snapshots above; it does not record execution. Planned loaded-ELF held-out case A covers wrong issuer/policy public words, wrong action, malformed proof, read-only request, missing final account, System Program in the issuer slot, and replay. The planned loaded B and C branches reject old-root proofs after unrelated and own revocation, respectively; C's attempted active-current-root witness is rejected by the witness/relation checks before submission. The loaded harness and held-out verifier source include the missing-final-account and System-Program-as-issuer scenarios, but this does not establish a runner build or a held-out case run. The report's earlier signed-history receipts are local training evidence for stale-root and own-revocation behavior, not held-out evidence.

Local DER admission negatives have source/fixture validation coverage only; they are not loaded application transactions. Disabled issuer/config, expired status, queue-capacity (fixture available), account-order, and ambiguous-restart cases remain host-only or test/mock coverage at this revision, not demonstrated loaded-ELF held-out rejections. **Held-out negative execution: none established.** The required `v3-heldout-queue-runner-002` is absent; no held-out freeze, cohort, case fragment, assembled manifest, or verifier report exists. Do not infer case execution, a build, or a freeze from this inventory.

**Source-only follow-up (2026-10-18):** A separate held-out A R0 clone, loaded-ELF disabled-config Execute negative, three five-account finalized snapshots, and independent sidecar/verifier checks are now wired into the case runner. The negative's clone and session wall time are recorded outside the matched Full/Anchor branch totals. Focused Python tests and Rust formatting checks passed, but the Rust runner has not been compiled and this negative has not run against a validator. Training-009 owns the sole heavyweight-job slot; no held-out acceptance claim follows from this source change.

**Source-only follow-up (2026-10-18 02:55 UTC):** The same held-out A R0 clone session now also re-enables config, refreshes issuer source and rebinds the head, disables the issuer, then submits the same valid Full wire expecting Policy 713. Source pins three additional five-account finalized snapshots for this sequence. This is wiring only: no Rust build, validator run, held-out freeze or cases, or economics result exists. Training-009 still owns the heavy slot. Account the combined negative cost once, not once per rejection step; no issuer rejection is claimed as executed.

**Bounded held-out runner build update (2026-10-18):** Build monitor-002 failed with JSON macro recursion, and monitor-003 failed because a local `source_digest` binding shadowed the helper. After the fixes in pushed commit `5ba9e37`, monitor-004 passed with exit 0 in 7.665 seconds and zero remaining owned processes. The bounded reports are `artifacts/dynark/part5/v3-heldout-queue-runner-build-report-002.json`, `-003.json`, and `-004.json`; these are build outcomes, not loaded application results. The installed stable `artifacts/dynark/part5/v3-heldout-queue-runner-002` has SHA-256 `f82401e93c506eb1bdd8e2787a18bdbdbd5d948fc42a8f04a0cbeefe9ebe002c`. Its saved `--list` output at `artifacts/dynark/part5/v3-heldout-queue-runner-build-002/queue-v3-tests.txt` contains all eight required names shown in the recipe below. No held-out freeze, cohort, cases, or acceptance result exists. Earlier dated statements that runner-002 was absent remain historical snapshots.

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

### Conditional post-matrix Training-009 reports (not yet eligible)

Run this only if Training-009 has all 60 ordered slot receipts and its verified
sequence receipt; the matrix runner publishes
`economics-input-manifest.json` only after that gate. The preflight and
reconciler below recheck the receipt chain. These commands describe a future
report sequence; the campaign is registered and launched, but no economics
input or report exists at this update. Run from the repository root, with fresh
output paths:

```sh
set -euo pipefail
ROOT="$PWD"
PY="$ROOT/artifacts/dynark/part5/v3-campaign-python-002"
MATRIX="$ROOT/results/dynark/part5/v3-campaign-matrix-training-009.json"
OUTPUT_ROOT="$ROOT/artifacts/dynark/part5/v3-matrix-training-009"
ECONOMICS_INPUT="$OUTPUT_ROOT/economics-input-manifest.json"
ECONOMICS_REPORT="$ROOT/results/dynark/part5/v3-campaign-economics-training-009.json"
RECONCILIATION_REPORT="$ROOT/results/dynark/part5/v3-campaign-cost-reconciliation-training-009.json"
TOTAL_SUMMARY="$ROOT/results/dynark/part5/v3-campaign-total-cost-training-009.json"

test -s "$ECONOMICS_INPUT"
for OUTPUT in "$ECONOMICS_REPORT" "$RECONCILIATION_REPORT" \
  "$TOTAL_SUMMARY"; do
  test ! -e "$OUTPUT" && test ! -L "$OUTPUT"
done

"$PY" -B -c '
import sys
from pathlib import Path
from tools.part5 import run_v3_campaign_matrix as matrix
from tools.part5.reconcile_v3_campaign_costs import verify_completed_matrix

matrix_path, output_root = map(Path, sys.argv[1:])
validated = matrix.validate_manifest(matrix_path)
if validated["campaign_id"] != "training-009":
    raise ValueError("wrong training campaign")
if validated["output_root"] != output_root:
    raise ValueError("wrong matrix output root")
if (matrix.read_json(output_root / "economics-input-manifest.json") !=
        matrix.economics_input_manifest(matrix.plan_slots(validated))):
    raise ValueError("economics input differs from registered plan")
verify_completed_matrix(validated)
' "$MATRIX" "$OUTPUT_ROOT"

"$PY" -B tools/part5/analyze_v3_campaign_economics.py \
  --manifest "$ECONOMICS_INPUT" --output "$ECONOMICS_REPORT"
"$PY" -B tools/part5/reconcile_v3_campaign_costs.py \
  --matrix-manifest "$MATRIX" --economics-report "$ECONOMICS_REPORT" \
  --output "$RECONCILIATION_REPORT"
"$PY" -B tools/part5/summarize_v3_campaign_total.py \
  --reconciliation-report "$RECONCILIATION_REPORT" \
  --matrix-manifest "$MATRIX" --economics-report "$ECONOMICS_REPORT" \
  --output "$TOTAL_SUMMARY"
```

## Held-out acceptance: pending

The independent gate remains pending; no held-out pass is claimed. Before issuance, freeze the source and artifact identities. Generate eight unseen in-profile certificates using four fresh issuer keys and eight fresh holder keys, with no training-key reuse; cover all eight DER layouts, distinct positive 16-byte serials and validity periods, at least two signed organization/group policies, varied AKIs, and at least four independent OpenSSL issuances. Preserve an independent post-freeze issuance/import receipt, use the same frozen public VK/setup, and admit the credentials without source/offset edits or a new setup.

For every credential, verify issuer/AKI and exact-policy enrollment (including pre-enrollment and wrong-policy rejection), controlled local signed-publisher current-head evidence (`independent_production_freshness: false`), and three distinct signed action-v2 requests. Request A must produce one Full effect; replay, including with a fresh proof, must fail without a second effect. Request B must reject its stale R0 proof after an unrelated R1 revocation, then allow same-action Anchor refresh/effect from a separate unconsumed R1 clone. Request C must reject old-root and current-root active-leaf attempts after own-leaf revocation at R2, without queue append or request consumption. Also cover malformed/ineligible DER, wrong issuer, changed policy, stale status, disabled issuer/config, wrong account order/privileges/owners, modified action, malformed proof, queue capacity, and ambiguous submission/restart. Record preparation and complete-refresh time, per-credential memory, and paid public/private Anchor preparation; verify setup reuse, private-cache isolation, holder/action separation, and no source/setup drift. See the [binding held-out acceptance plan](v3-heldout-acceptance-plan.md) for the complete predicates.

| Evidence item | Observed state at this snapshot | Evidence required to close it |
| --- | --- | --- |
| Request-bound Full plus protected effect | The cited signed-history run passed its training fixture; the four receipt-bearing training-005 sessions each have an effect receipt. The fifth slot failed before application submission. | Preserve the exact Full/native-client and loaded-ELF identity evidence; held-out cases must independently exercise the complete predicate. |
| Current-root and own-revocation safety | Passed for the two controlled training credentials in the signed-history report. | Repeat for all eight post-freeze credentials, with separate unconsumed requests and no effect/consumption on rejection. |
| Training-004 | Nine of 60 slots completed; slot 10 was censored at the 256 MiB storage-growth cap. | Do not use as a completed matrix. Training-005 through Training-009 remain incomplete; Training-009 has launched but has no verified slot receipt yet. |
| Training-005 | Four ordered receipts exist: `r1-k0-full`, `r1-k0-anchor`, `r1-k0-coalesced-full`, `r1-k1-full`. The fifth slot `r1-k1-anchor` generated a passing proof report, then failed before submission with `ValueError: finalized exact account bytes mismatch`; outer exit is 2, `passed` is false, and no fifth receipt exists. A read-only fresh-clone diagnostic matched all five account hashes but did not observe the original failure role, leaving cause unknown. | Preserve the failed slot artifacts. `--resume` refuses the partial slot. No full matrix, pooled distribution, CPU result, measured break-even, or 20% target result is available. |
| Training-006 | At the 23:31 UTC snapshot, `r1-k0-full` had a passing proof, finalized and verified effect, and completed slot receipt. Its nested effect supervisor exited 1 during SIGINT validator cleanup (`-2`); `ledger_reuse_requires_review: true`, which the session gate explicitly accepts as a reviewed shutdown, not clean ledger reuse. The second slot `r1-k0-anchor` had started but had no receipt. One of 60 receipts existed and the matrix driver remained active. | Continue to record ordered receipts and failures. No full matrix, paired distribution, CPU result, measured break-even, or 20% target result is available. |
| Training-005 reproducibility inputs | Input, materialized manifest and plan hashes are recorded below; the freeze identities are in the registered input. | Check the exact digests and inspect the generated plan before interpreting results. A plan-only invocation does not execute or validate a campaign. |
| Held-out freeze and cohort | No held-out freeze, cohort, or held-out run exists. The R2 own-revocation receipt and total-cost verifier implementation is pushed in `14c7bbc`. The older `queue-runner-001` is stale; the required `queue-runner-002` has not been built. | Complete the required training matrix gate before freezing source/artifacts and creating the fresh cohort. |
| Held-out cases and analysis | No manifests, fragments, assembled manifest, verifier report or cost report exist. | Run all eight frozen cases serially; assemble with fragment hashes; independently verify; then compute the matched cost report. |
| Final conclusion | **Not established.** | Valid training matrix, held-out acceptance, and a bounded application-level cost report with explicit assumptions and limitations. |

## Reproducibility and evidence boundary

The scrubbed evidence is under `results/dynark/part5/`; raw credentials, keys, witnesses, proofs, signed envelopes, and ledger clones remain in protected ignored artifacts. The checked-in training campaign inputs are `results/dynark/part5/v3-campaign-matrix-training-004.json` through `v3-campaign-matrix-training-009.json`. Training-009's raw and canonical JSON hashes and pinned driver/helper identities are recorded in the launch update above. The matrix driver and session runner expose their CLI surfaces with:

```sh
python3 -B -m tools.part5.run_v3_campaign_matrix --help
python3 -B tools/part5/run_v3_campaign_session.py --help
```

### Conditional held-out break-even method (not run at this snapshot)

The post-snapshot analyzer `tools/part5/model_v3_heldout_break_even.py` (introduced in commit `5ed86a7`) requires eight directly measured held-out request-B cost pairs at `k = 1` and a complete sampled training summary with 20 matched pairs across four repetitions and `k = 0, 1, 2, 5, 10`. For held-out variant `v` and training repetition `r`, it computes `D_vrk = D_v1 + (D_rk - D_r1)`, where `D_v1` is the measured held-out Anchor-minus-Full delta at `k = 1` and `D_rk` is the sampled training delta. Only `k = 1` is a direct held-out comparison; other counts are labeled conditional model/inference, using a transfer assumption from the training cohort without interpolation or extrapolation across the sampled `k` values. Pair-view one-time cost is reported separately and excluded from the deltas. This method does not use observed issuer-churn weights and makes no CPU-savings claim. At the 23:31 UTC snapshot, its required held-out and complete-training inputs did not exist, so no model output or held-out result is established.

When both source reports exist, reproduce the conditional analysis with their SHA-256 pins and a fresh absolute output path:

```sh
python3 -B tools/part5/model_v3_heldout_break_even.py \
  --heldout-cost-report /ABS/PATH/HELDOUT-COST.json:SHA256 \
  --training-total-summary /ABS/PATH/TRAINING-TOTAL-SUMMARY.json:SHA256 \
  --output /ABS/PATH/NEW-CONDITIONAL-BREAK-EVEN.json
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

The held-out commands below document reproducible inputs and a future run sequence; they do not indicate that the held-out run has occurred. The freeze input, prepare config, packet template and executable inputs listed below exist. The previously built `artifacts/dynark/part5/v3-heldout-queue-runner-001` reflects the older queue source and is stale for the current source. At this historical pre-build snapshot, the replacement stable runner at `artifacts/dynark/part5/v3-heldout-queue-runner-002` had not been built or listed; the dated build update above records its subsequent installed hash and confirmed listing. The freeze, cohort, run manifests, case outputs, assembled manifest, verifier report and cost report do not exist. The output paths below are reserved names and each creation command requires its output path to be fresh. Run the blocks in order from the repository root; each block defines its own path variables. The freeze receipt and prior-key inventory go in the owner-only `results/dynark/part5/v3-heldout-freeze-001/` directory. Keep the cohort, case manifests, and case outputs under owner-only ignored paths in `artifacts/dynark/part5/`. Do not put raw credentials, keys, witnesses, proofs, signed envelopes or ledger clones in tracked prose or files.

The following retains the held-out Rust runner build recipe used before the installed build recorded above. It must create the replacement stable copy at `artifacts/dynark/part5/v3-heldout-queue-runner-002`. Use a fresh build target and an empty destination; preserve the older runner-001. The Python campaign interpreter and raw Cargo output path are not valid `--runner` inputs. The executable search uses depth 8 because the generated binary is nested under `debug/build/.../out`.

```sh
set -euo pipefail
ROOT="$PWD"
PART5="$ROOT/artifacts/dynark/part5"
BUILD_TARGET="$(mktemp -d "$PART5/v3-heldout-queue-runner-build-XXXXXX")"
RUNNER="$PART5/v3-heldout-queue-runner-002"

test ! -e "$RUNNER"
CARGO_TARGET_DIR="$BUILD_TARGET" CARGO_BUILD_JOBS=1 /Users/anishnarang/.cargo/bin/cargo test \
  --offline --locked --manifest-path "$ROOT/harness/Cargo.toml" \
  --test queue_v3 --no-run

RUNNER_CANDIDATES="$(find "$BUILD_TARGET/debug" -maxdepth 8 -type f \
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
  root_pinned_queue_v3_branch \
  root_pinned_queue_v3_disabled_config_negative; do
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
PRIVATE_ROOT="$ROOT/artifacts/dynark/part5/v3-heldout-private-001"
COHORT_ROOT="$PRIVATE_ROOT/v3-heldout-cohort-001"
OBSERVATION="$PRIVATE_ROOT/v3-heldout-cohort-observation-001.json"
FREEZE_SHA="$(shasum -a 256 "$FREEZE" | awk '{print $1}')"
INVENTORY_SHA="$(shasum -a 256 "$INVENTORY" | awk '{print $1}')"

test ! -e "$PRIVATE_ROOT" && test ! -L "$PRIVATE_ROOT"
git check-ignore -q "$PRIVATE_ROOT"
mkdir -m 700 "$PRIVATE_ROOT"
python3 -B tools/part5/observe_v3_heldout_cohort.py \
  --freeze "$FREEZE" --freeze-sha256 "$FREEZE_SHA" \
  --prior-key-inventory "$INVENTORY" \
  --prior-key-inventory-sha256 "$INVENTORY_SHA" \
  --output "$COHORT_ROOT" \
  --observation "$OBSERVATION"
```

The observer requires the ignored, owner-only 0700 private root and writes the
cohort plus a 0600 sibling observation there. It gives local parent-process
chronology: the parent starts the builder after the recorded freeze boundary,
then checks the builder's receipt and records its own interval. It does not
directly observe OpenSSL invocations or provide an external timestamp. The
observer uses an owner-only temporary directory for the builder's temporary
files and removes it on normal exit. A hard interruption can leave a partial
private cohort requiring inspection before choosing fresh output paths.

Build the eight run manifests from the existing base prepare config `artifacts/dynark/part5/application-v3-campaign-prepare-config-002.json` (SHA-256 `b5bb168545a3dfef91fa2b0430bf19912ffbbe6080c6b94041315256934d2853`) and packet template `artifacts/dynark/part5/v3-full-r1-proof-training-001/packet-003.json` (SHA-256 `f74da66ef9a12c03a028ed52bee8cb4de2ddf0958abbecb0b7e528b22065512b`). These are pinned construction inputs, not held-out run evidence. The manifest builder requires `--runner` to resolve exactly to the replacement stable Rust executable `artifacts/dynark/part5/v3-heldout-queue-runner-002` described above; the build step must run before freezing because this file is included in the frozen registry bundle. The builder verifies the file and embeds its path and SHA-256 in each manifest. Other pinned inputs are the bounded supervisor `results/dynark/part5/session_runner.py` (`77fc4107089d14039af8726051e174a9b6508e09c13b07e2ac1bcc083eec5429`), Node `/Users/anishnarang/.nvm/versions/node/v24.10.0/bin/node` (`9e759d34d97af8a71b75854d20af297794611155406997f06d796b5e0f6d573b`), exporter `program/target/debug/examples/export_v3_request_fixture` (`d5b10820153334b5cb5996ad2f26aad95a033741e0883f69019ebf79fb051700`), and the adapter above (`5e364d7ea4d2321a1135e697ed7cf3233abaa832d371bff2f4dfdf2ea5ff6521`). The builder verifies and embeds their hashes and emits `case-00.json` through `case-07.json`:

```sh
set -euo pipefail
ROOT="$PWD"
FREEZE_DIR="$ROOT/results/dynark/part5/v3-heldout-freeze-001"
ADAPTER="$ROOT/crates/dynark-solana-adapter/target/debug/build/dynark-solana-adapter/3a4659842a713e9a/out/v3_request_bound_host-3a4659842a713e9a"
FREEZE="$FREEZE_DIR/freeze.json"
COHORT_ROOT="$ROOT/artifacts/dynark/part5/v3-heldout-private-001/v3-heldout-cohort-001"
OBSERVATION="$ROOT/artifacts/dynark/part5/v3-heldout-private-001/v3-heldout-cohort-observation-001.json"
BASE_PREPARE_CONFIG="$ROOT/artifacts/dynark/part5/application-v3-campaign-prepare-config-002.json"
PACKET_TEMPLATE="$ROOT/artifacts/dynark/part5/v3-full-r1-proof-training-001/packet-003.json"
# Set after the held-out Rust queue_v3 runner has been built and pinned.
RUNNER="$ROOT/artifacts/dynark/part5/v3-heldout-queue-runner-002"
SUPERVISOR="$ROOT/results/dynark/part5/session_runner.py"
NODE="/Users/anishnarang/.nvm/versions/node/v24.10.0/bin/node"
EXPORTER="$ROOT/program/target/debug/examples/export_v3_request_fixture"
RUN_MANIFESTS="$ROOT/artifacts/dynark/part5/v3-heldout-run-manifests-001"

python3 -B tools/part5/build_v3_heldout_run_manifest.py \
  --freeze-receipt "$FREEZE" \
  --cohort-root "$COHORT_ROOT" \
  --cohort-observation "$OBSERVATION" \
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
