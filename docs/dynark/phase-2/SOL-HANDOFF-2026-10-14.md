# DYNARK Phase 2 handoff to the next Sol agent

Prepared October 14, 2026, late evening EDT. This is the current resume document. Earlier chronological status paragraphs may describe gates that have since passed; use the linked final evidence and this checkpoint.

## Status and objective

**Phase 2 is incomplete. The core engine has passed its required small-shape and credential-scale functional qualification. Session economics, mode-selection evaluation and final closure remain unfinished.** Do not spend another run re-establishing completed credential-scale qualification. The immediate blocker is the session measurement harness's conservative work accounting, not a failed ordinary proof in the accepted credential run.

The objective is a general fixed-R1CS BN254/Groth16 engine supporting validated full proving, immutable-anchor updates, fully dynamic reconstruction, public-input changes, authenticated persistence and recovery, with honest preparation/memory/session economics. Early incremental witness work was additionally authorized. Complete product/Solana integration was deferred. The user now prioritizes closing the remaining work; **start no new optimization experiments**.

## Workspace and execution rules

- Authoritative checkout: `/Users/anishnarang/Zk-refresh`, branch `codex/engine-focus-oct14`. The environment's `/Users/anishnarang/Zk-fresh` path is historical; do not work in the wrong directory.
- Latest accepted product implementation: `54523c1` (bounded reconstruction batches), following `4bf635a` (anchored parallel query/projection sums). Subsequent commits are evidence/documentation. Recent records: `04f5e34` credential acceptance, `a83093b` projection experiment, `b04e1b0` session failure and repair decision.
- Preserve the pinned reference `experiments/dynark/vendor/DYNARK_/` at `c73a380df86d8f5d195f1e20c8a1d86a7dce084b`, fixtures, keys and large untracked/ignored baseline. Inspect Git status; stage exact files only. Do not edit the unrelated root-level `HANDOFF.md`.
- User's division of work: Astra owns architecture, mathematics/review, evidence and documents; GPT-6.1 Sol owns implementation/tests/helpers. High reasoning for cryptographic/dependency work, medium for systems/measurement. At most two disjoint coding owners, explicit shared-file transfer, no worker delegation, one named heavy execution owner.
- Fixed policy `dynark-fixed-budget-v1`: 4 GiB sampled owned-workload-tree RSS, four Rayon workers, one test thread, one heavy job. Builds are offline/locked with one Cargo job. Eight live owned processes and 64 tracked live births. Smaller tests retain their smaller limits. Warning pressure is telemetry; critical/unknown pressure remains an interruption. This is not a hard cap on the entire laptop and not an average-laptop benchmark.
- Preserve original arithmetic/runtime/storage caps and every failed run. Do not automatically retry, expand budgets, repeat expensive preparation, or refund failed work. Use fresh numbered outputs and exact source/binary grants. All grant CLI paths must be absolute.
- Protected artifact directories/files/executables use 700/600/700. Do not publish witnesses, projections, blinders or private caches. No push, PR, deployment, real credentials or production setup is authorized here.

## Completed Phase 2 work

| Package | Achieved | Boundary / unfinished work |
|---|---|---|
| T0: contracts and derivations | Circuit/setup/reduction identities, sparse-delta rules, randomness, reconstruction and security contracts reviewed | Verification tests do not establish a new security proof, adaptive security or side-channel resistance |
| T1: full prover/public package/RNG | Validated ordinary full comparator, constant-one preservation, shared immutable public material, fallible caller CSPRNG; 12 product conformance and 14 preserved probe tests; parent reran all 12 | Exact compatible setup/reduction required; original `.zkey` interoperability remains unestablished |
| T2: transitions/anchors | Canonical duplicate/zero delta handling, public/private changes, immutable bindings, exact sparse/dense/component comparisons; 23 independent tests and complete credential replay | No approved cross-action credential reuse; changed action invalidates reuse and full-proves |
| T3: sharing/allocation | Public sharing/private disjointness verified for zero, one and two states; separate structural, allocator and RSS measurements | Ten states were not admitted because the preregistered smaller-case RSS condition failed; do not extrapolate |
| T4: cross terms | Independent fast candidate matched exact oracles and was measured; actual credential supports also matched | Fast lost by 13.20/25.05/84.28x near/middle/far. Retain Quadratic. The paper's advertised fast complexity has not been achieved by the selected implementation |
| T5: fully dynamic engine | FFT/shape/progress repairs, frozen snapshots, exactly-once corrections, overshoot handling, atomic promotions, rollback, dense/action/reverse/no-op cases; 1,000 transitions and 533 real promotions; credential sequence now passed | Credential result is one ten-update synthetic trace. Final builder is intentionally partial. No general pause/SLA or cheap dense/new-action claim |
| T6: persistence | Bounded authenticated codec, context binding, nonce/key checks, trusted-receipt publication, adversarial recovery/invalidation tests; 911 checkpoint positions; actual credential save/drop/recover passed | Trusted provider survives within one process. Durable provider restart, whole-store anti-rollback operations and production key service remain open |
| T7: selective preparation/economics | Dependency argument and bounded selective engine; 19 tests passed in worker and parent; current-engine measurement builds and finite checks passed | Audit incomplete; TRAIN, HOLDOUT, allocation diagnostics and final default policy have not run |

Primary navigation: [status](README.md), [conformance](conformance.md), [architecture](architecture.md), [claims and limits](claims-and-limits.md), [decisions](decisions.md), [engine work/evidence](engine-focus-oct14.md).

## Accepted credential-scale milestone

Runtime003, isolated source007, completed **10 distinct-root updates, two real promotions at targets05/09, target05 authenticated save/drop/recovery and 154 ordinary Groth16 checks**. The 154 checks include positives and altered-public/cross-generation rejection checks, not 154 distinct proofs. The resumed state continued through target10. ROOT and an independent reviewer reconciled all 26,686 maintenance records, 53,060,793 cross pairs, 218,575,669 actions, 114,766,642 G1 calls and 92,274,688 field multiplications. All 93 external pins and fixture authentication matched; cleanup was known-zero.

Sampled peak workload RSS was **1,646,690,304 bytes (about 1.53 GiB)**. Cold package import cost 102.973 monotonic seconds; fresh anchor preparation/commit 785.677. Instrumented checkpoint save/drop/recover cost 50.433 seconds, including 31.406 recovery; equality covered 11,133,149 installed values/placement checks. Maintenance recorded 1,528.300 monotonic seconds and 4,501.536 all-thread CPU seconds, with maximum observed call pause 1.080714 seconds. These costs remain paid.

**Timing caveat:** runner elapsed was 2,510.552 monotonic seconds, but `/usr/bin/time` real was 4,300.99 and UTC endpoints span 4,301.175. Cause unknown. Preserve all clocks; do not call 41.8 minutes calendar elapsed, infer sleep, claim CPU efficiency or use this as a clean latency comparison. Functional/work-accounting acceptance stands.

[Final acceptance](evidence/credential-dynamic-runtime003-results.md), [aggregate](../../../results/dynark/phase-2/credential/dynamic-runtime-003-scrubbed-aggregate-acceptance-001.json). Aggregate SHA256 `b9e8b7ee5072f90997744eb220affc6934a5dbd111e9c24bf7b3b2368026115f`; primary/duplicate `c4b2a5627536a3715a0dc8d13e2e96d8b3467a17a5d92510394a9dcb7e9042e4`; source007 `90acae63c4bd8a09df5c744ecc494e425eccc71e9397a7b334bb5d9fd6c70fad`; executable `c1ce520ac6aed4a922af3da249933bbcd1727e9e7fc5834588276d134cc28b5a`.

Earlier dynamic001 was interrupted before checkpoint; source006's 18/20 focused-test failure was repaired in007, which passed all20. Those originals remain failures; do not relabel them or rerun the completed large sequence.

## Measured improvements and losses

| Measurement | Observed result | Interpretation |
|---|---|---|
| Historical Phase 1 proof stage | 2.221 s full vs 0.389 s anchored | Real historical proof-only measurement; old complete refresh was 5.417 vs 3.587 s with a roughly 3.128 s witness stage |
| Validated Phase 2 replay004 | Supplied-witness medians 2.254241 s full / 1.710784 anchored, 30 pairs; complete-refresh 5.584775 / 5.067440 s, 10 pairs | Earlier complete pipeline measurement, before the later optimizations; preparation/import excluded and reported separately |
| Anchored parallel query/projection sums | 1.635991 → 0.871564 s warm API median, five pairs | Includes target validation and fresh entropy; excludes witness, import/preparation and final verification. Product adoption passed separate checks |
| One eligible reconstruction batch | 0.369258 → 0.099390 s API median, five pairs | Product patch passed 27 selected correctness methods. Not a whole credential reconstruction speedup |
| Incremental witness generation | Full near/middle/far 3.169/3.121/3.187 s → 0.202/0.197/0.199 s warm medians, five pairs each | All48 complete WTNS outputs byte-identical. Shared context startup 103.133 s remains paid. Not integrated end-to-end with the optimized prover |
| Final projection arithmetic candidate | Dense 721.167 → 192.571 ms; one-in-eight 108.999 → 29.705 ms; five pairs each | 98,304 exact raw-point comparisons; arithmetic-only candidate outside product. No full-preparation/CPU gain claim |
| Public-twiddle decomposition cache | Construction-inclusive low-reuse comparisons lost | Rejected for tested workloads despite fewer warm allocations |
| Fast cross kernel | All primary measured comparisons lost | Retain weighted Quadratic; no measured crossover |

**Do not add separately measured witness/proof medians and present the sum as measured end-to-end latency.** Incremental witness generation also accelerates the full-proving comparator. Full proving remains the conservative default for short/unknown reuse until complete economics support another choice. The old approximately271-refresh crossover was a conditional estimate, not a measured product workload.

New actions change over104,000 witness coordinates; the actual support census implied about10.31 billion naive pairs. Reuse was rejected within budget and full fallback verified. Fully dynamic support does not make this workload cheap.

## Early witness work completed beyond the original engine slice

The fixed circuit's ten-level dependency mapping, evaluator and compiler-alias handling were reviewed. Near/middle/far candidates matched **all643,563 fields**, including unchanged values and intermediate aliases, and emitted **5,081/2,541/509** sparse deltas. Relation checks covered648,156 rows; fresh ordinary original/decoded proofs and all five wrong-public negatives passed. Mapping/evaluator support suites and the matched full-output pilot passed. [Witness evidence](evidence/witness-suffix-oct14.md).

This is an unchanged synthetic credential circuit: padded N=1,048,576, six instances including constant one, public order `[root, issuerHash, notBefore, notAfter, actionHash]`. It is not arbitrary-circuit incremental generation or real X.509 qualification.

## Exact unfinished session work

The original ledger007 contains234 groups: PREPARE1, AUDIT9, TRAIN36, HOLDOUT180 and allocation diagnostics8. It uses N=256, so it cannot measure the new8192-operation batch acceleration or establish credential-scale selective economics. All234 original envelopes must remain unchanged. Ledger SHA256: `2ea68dbfcf8d237c5c743f3e6ad3484cbd7235244d19f924dad93c732a9e9575`.

Current accepted measurement source003 freeze manifest: `4f2a5f9a3594aa1d0cc7275fb98e8a12036d9810d6686ff9e27a53320e298241`; launcher005: `b1f6e8443cfa924012ebf93982db223f3c3eb14ce6df480eb3ab7d77c62601d6`; normal003 binary: `cbb1696d221269a8fcbd143d86e30525ffa84d6bc505fb772ab7bd640d49e8f9`; diagnostic004: `d16b81356dbbef5b5ee48cc0463b46114f458d96daef74c2dabc49db160388c6`. Both builds, 27 launcher checks, five normal invariants, diagnostic startup/list and five diagnostic invariants passed. Reuse the original paid public preparation exactly once; do not repeat setup.

Audit output roots are `artifacts/dynark/phase-2/fixed-budget/oct14-preflight/session-rebind-audit-pilot-001` and sibling `session-rebind-audit-pilot-001-runner`. **Groups000–005 passed.** Group000 common-r/s audit passed8 proof operations/48checks. Group005 is the old-source Full/cold10 pilot. **Group006 Anchor/cold10 failed** at its final output reservation: requested13,806 G1 versus13,801 allowance, exit101, no surviving processes. Groups007 Dynamic/cold10 and008 Selective/cold10 did not run. The aborted ledger retains the full phase reservation; no refund is permitted.

Two source-reviewed accounting corrections are approved, but are **not yet implemented or tested**:

1. **Anchor:** the planner fails to update anchor-relative row support after cold reload at9. Correct that census. Use a separate conservative G1 ticket `7+3d+4R+P`: queries≤3d, fixed products7, cross/projection linear terms≤4R, diagonals≤P. The existing generic5R ticket over-reserves. Correct cold10 becomes13,800≤13,801; cold100 four-sample bound69,960≤70,144. Keep dynamic tickets and every verification unchanged.
2. **Selective:** current harness uses `2+max(current,anchor_coordinates)` G2 while its planner sometimes uses anchor coordinates only. Cold10 would ask30 against26. Actual product correction uses exactly1+anchor-delta length. Separate conservative ticket `1+max(current,anchor_coordinates)` gives21≤26. Keep G1, field/admission/entry work and full fallback tickets unchanged. Cancellation remains charged for both attempts. This also applies to Known-mode selective corrections.

Pending private copies are `artifacts/dynark/phase-2/fixed-budget/session-source-004/crates/dynark-bn254` and `artifacts/dynark/phase-2/sessions/tooling-source-003`. They contain tests-first work, **not a runnable accepted successor**. Six new Rust and eleven new Python tests were authored; none were executed. Only `tests/private/session_invariants.rs` differs from source003, and tooling003 contains five unchanged copies plus `test_anchor_reservations.py`. The Rust tests reference two helpers that do not exist yet. Product files, old snapshots, ledger007, allocator and launcher005 are unchanged. There is no new source freeze, executable, runtime grant or passing repair test yet. The worker has released ownership.

Read the [approved design002](../../../results/dynark/phase-2/sessions/current-engine-rebind-repair-continuation-design-002.md), [exact transfer inventory and file pins](../../../results/dynark/phase-2/sessions/current-engine-rebind-accounting-handoff-state-001.json), and [tests-first receipt002](../../../results/dynark/phase-2/sessions/current-engine-rebind-accounting-repair-tests-first-002.json) before editing. Their SHA256 values are respectively `6d95349fbcfab6f441fd338eb8eb506699f53eb12d3f79b780dacdfcbf491fa7`, `2e6e57dc3e6bf53dc3c4b354950c70b3a3155fd51f630fca6cc6862c0d744e82`, and `5ffdbd812b6d6cfeaca69e68d97dd11d48deaa238379bbb45d14994aec9b174b`. Preserve the partial source trees; they are local artifact files and must accompany a transfer to another checkout or device.

Failure evidence: [postflight](../../../results/dynark/phase-2/sessions/current-engine-rebind-audit-pilot-failure-postflight-001.json), [Anchor diagnosis/headroom](../../../results/dynark/phase-2/sessions/current-engine-rebind-audit-failure-counter-diagnosis-001.json). The latter predates the additional Selective finding; do not treat it as the complete repair specification.

## Resume sequence and exit gates

1. Read the worker transfer record; establish sole file/queue ownership and inspect processes. Finish only the two accounting helpers, planner correspondence and focused tests. Test cold9→10, both old failures, unchanged cryptographic work, cancellation/fallback, and all234 envelopes. Distinguish conservative reservations from actual primitive operations. No cap expansion or category transfer.
2. Independently review/freeze source and exact diffs. Run bounded finite tests, then offline single-job normal/diagnostic builds, actual emitted-binary binding and invariants. Preserve unexecuted tests-first records accurately; do not invent a red/green result.
3. Implement/review only the approved narrow continuation. Reuse old groups0–5 with original source labels; run only6–8 with the new accepted binary and their original envelopes. Carry the full aborted paid ledger once, then separately add all three original envelopes as additional paid work. Global headroom is sufficient by the recorded derivation; verify again. Never use failed/unused reservations as a refund.
4. Continuation design uses a tighter120-second successor active deadline, unchanged4-GiB RSS, and a combined128-MiB growth budget with old growth/side reserves debited. Exact source equivalence, old ledger/vector/completed set, new source, order and one-time carry must be bound. Old Full/cold10 pilot may contribute only its exact registered overhead through a narrowly reviewed provenance association; no generic source-compatibility bypass. **No continuation grant exists yet.**
5. After complete audit acceptance, run TRAIN:24 forced groups, freeze actual fit/policy/conditional ledger, then12 selector groups. Fit only authorized TRAIN data plus the exact Full/Selective pilot overhead inputs. Missing inputs fail; an unprofitable fit may choose Full. Run180 HOLDOUT groups with that frozen policy, then8 allocation diagnostics. No tuning on HOLDOUT. Templates and required artifacts are in [later-phase readiness](../../../results/dynark/phase-2/sessions/current-engine-rebind-later-phase-readiness-001.md); old template bindings must be updated to actual accepted evidence.
6. Report paid preparation, misses, abandonment, reload, maintenance, failed work and memory residence for0/1/2/5/10/100-update sessions. Keep N=256 results separate from credential results. Update defaults, evidence index and final handoff. Only then assess Phase2 exit; negative optimization findings are valid, missing required evaluation is not completion.

## Not delivered in this scope

Real organization-issued X.509/RSA profile qualification, constrained DER parsing/authenticated attributes, chain/extension/key-usage/expiration/issuer-rotation rules; persistent authenticated registry streams and client lifecycle; durable trusted-key/receipt operations; original `.zkey` compatibility; Solana encoding/deployed-key acceptance and atomic protected action; revocation-race integration; a sound split-proof comparator; combined optimized witness/proof end-to-end workloads; production ceremony, external security review, reproducible release/dependency/license gates, SDK/application integration and a consenting pilot are **not complete**. See the bounded [Phase3 plan](phase-3-plan.md). Do not claim full product or production readiness from Phase2 proof verification.

The existing two-hour `dynark-engine-progress` follow-up is configured in this chat. Establish one execution owner during transfer so an automatic follow-up cannot duplicate a new agent's benchmark. At handoff, all workers have completed and released ownership, and no matching benchmark/build process is running. No new work was launched for this status report.
