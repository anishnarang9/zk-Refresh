# DYNARK fixed resource budget implementation plan

October 11, 2026. User-directed amendment to the Phase 2 experiment policy.

**Goal:** Compare every proving method under a fixed workload allowance that does not change with background application memory use.

**Architecture:** Preserve all earlier sources, manifests, reports and failed attempts. Add a successor launch profile using the existing bounded runner and process cleanup machinery. Host observations describe the environment; warning pressure and ordinary swap activity do not determine the benchmark allowance.

**Tech stack:** Existing Python launch controls and one population experiment's Rust admission check. Astra owns policy, source review and documentation; GPT-6.1 Sol medium owns the narrow implementation and finite tests. No cryptographic implementation or workload change is authorized by this amendment.

## Fixed standard

- Workload process-tree sampled RSS: 4,294,967,296 bytes (4 GiB), including the measured command and its descendants. The runner samples every 0.2 seconds. This is a stop threshold, not an OS allocation quota or reserved RAM; brief overshoot remains possible. RSS does not bound total virtual/allocated memory or compressed/swapped pages.
- Monitoring and reporting: at most 192 MiB additional **planning allowance**, using the existing finite report/schema limits. This allowance is not an independently enforced or measured RSS guarantee. Do not describe the complete system as hard-capped at 4 GiB.
- Four Rayon compute workers, one Rust test thread, and exactly one heavy experiment at a time. Compiler jobs remain two. These settings do not reserve CPU cores or eliminate competition from other apps.
- Existing finite arithmetic, storage and elapsed-time budgets remain unchanged, declared before each workload. Comparators executing the same workload receive the same limits. Different workloads may have different fixed time/storage allowances; limits never expand after failure or based on free RAM.
- Replay: 2,100 seconds / 2 GiB core output growth. Credential dynamic sequence: 14,400 seconds / 4 GiB core output growth. Population case: 1,200 seconds / 2 GiB core output growth. Session phases: 300 seconds preparation; 300 seconds audit/pilot; 1,800 seconds TRAIN; 1,800 seconds HOLDOUT; 900 seconds diagnostic; 128 MiB total output per phase including pre-reserved side evidence. Previously bounded side evidence remains separately charged where specified.
- Small correctness tests and builds retain their smaller existing caps. They are validation tasks, not competing benchmark measurements.

## Host observations and outcomes

Admission requires one valid noncritical host observation, not a 30-second normal-pressure/quiet-swap window. Normal and warning pressure permit execution. Warning and swap changes are recorded as context; they do not shrink the memory cap or automatically invalidate a completed everyday-use measurement. Critical pressure or unusable host telemetry still triggers existing cleanup, recorded as a **host interruption**, distinct from exceeding the workload budget. No automatic retry loop or intentional pressure generation.

A memory/time/storage/work-limit stop is **unable to complete within the fixed budget**, retaining its partial cost and evidence. A host interruption is incomplete and does not establish an algorithm's memory requirement. Preserve interrupted runs and historical policy identities; never pool them silently with new-profile completed measurements. Counterbalance comparator order and retain repeated raw samples and spread. The profile does not establish average-laptop representativeness or isolate timings from background load.

Ten-state population admission must use observed one/two-state results against the fixed 4 GiB workload ceiling, including its existing conservative margins. It must never use current free memory or the previous 6 GiB ceiling. An unadmitted case is reported as unmeasured, not extrapolated into a result.

## Implementation and verification

- [x] Create a protected successor bundle under `artifacts/dynark/phase-2/fixed-budget/source-001/`, with results under `results/dynark/phase-2/fixed-budget/`. Original frozen files remain read-only. New files0600/directories0700.
- [x] Reuse the accepted shared supervisor, guard ownership/cleanup routines, and replay/dynamic/population/session launcher logic. Change only policy, fixed workload limits, successor pins/paths, and fresh output identities. Preserve binary/source admission gates, work ledgers, cryptography, sample counts and proof acceptance.
- [x] Preserve and copy the frozen population source into the successor bundle. In `src/bin/phase2-population.rs` only, replace the normal-only per-addition pressure check with normal-or-warning acceptance and the 6 GiB reserve boundary with 4 GiB. Preserve the finite query, transient margins, structural measurements and all cryptographic source. Record this binary as requiring a fresh build; an old executable cannot satisfy its source manifest.
- [x] Cover warning admission/continued warning, critical/unknown pressure, fixed RSS/thread arguments in all four launch paths, fixed population admission, retained resource-limit cleanup, and evidence policy identity with meaningful finite tests. Reuse the existing bounded runner; no pressure-generating tests.
- [x] Freeze sources and explicit diffs; report all changed identities and an exact bounded smoke command. Worker passed 15 tests within 120 seconds / 512 MiB RSS / 32 MiB output and released the small-test queue. No Rust builds, credential imports or heavy benchmarks ran.
- [x] Astra read complete changed logic/diffs, verified pins, and independently passed the 15-test suite in fresh protected outputs. Limitations, active successor entry points and superseding policy are recorded in [the review](../../dynark/phase-2/evidence/fixed-budget-review.md).

The user's instruction to use fixed caps authorizes this policy amendment and its narrow implementation. It does not authorize larger caps, deployment, real credentials, publishing, or declaring the unfinished Phase 2 measurements complete.
