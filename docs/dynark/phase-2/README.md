# Phase 2 status and evidence

Started October 10, 2026 in `/Users/anishnarang/Zk-refresh`. **Phase 2 is in progress, not complete.** The corrected [Phase 1 handoff](../phase-1/HANDOFF.md) and [approved bounded plan](../phase-1/phase-2-plan.md) govern this work. Historical paths remain provenance. Root starting commit: `0365566`.

The orchestrator owns architecture, algebra review, evidence review and documents only. All implementation, tests, measurements and helpers belong to explicitly dispatched GPT-6.1 Sol workers. At most two coding workers; no worker delegation. The orchestrator is the heavyweight queue coordinator; ownership of an execution slot is explicitly recorded before each run. Initially there is no authorized credential-scale run.

| Task | Dependencies | Owner | Status | Evidence / remaining gates |
|---|---|---|---|---|
| T0 contracts and derivations | Corrected Phase 1 | Orchestrator; Sol high review | Specification gate complete | [Conformance](conformance.md), [architecture](architecture.md), [independent review](evidence/t0-review.md); implementation/tests remain open |
| T1 full prover / public package / RNG | T0 full contract | `t1_full`, Sol high; parent acceptance | Complete for small conformance | [Independent review](evidence/t1-review.md), [fresh identities](../../../results/dynark/phase-2/t1/identities.json); 12 product and 14 unchanged probe tests passed; parent independently reran all 12 product tests |
| T2 imports / transitions / anchors | Reviewed T1 | Unassigned, Sol high | Pending | Exact raw component/dense equality and immutable state |
| T3 allocation / sharing | Stable T1/T2 API | Unassigned, Sol medium | Pending | E4-directed ablation; measured live memory and fair comparator |
| T4 cross kernel | T0 kernel review, T2 | Unassigned, Sol high | Pending | Product/remainder tree, exact oracle, observed crossover |
| T5 full dynamics | T0 scheduler, T1/T2 | Unassigned, Sol high | Pending | FFT/progress; 1,000 transitions; separately budgeted credential swaps |
| T6 persistence | Frozen state schema | Unassigned, Sol medium + high review | Pending | Authenticated confidential envelope, trusted generation, crash/recovery |
| T7 preparation/economics | Dependency review, measured engine | Unassigned, Sol high then medium | Pending | Selective hypothesis, measured sessions and held-out policy |

Records: [experiments and queue](experiments.md), [decisions](decisions.md). Worker returns and primary aggregate evidence belong under `results/dynark/phase-2/`; sensitive runtime artifacts belong under ignored `artifacts/dynark/phase-2/` with directory mode 700 and file mode 600.

Initial secondary assignments: `t0_review` (Sol high) owns only `evidence/t0-review.md` and is read-only outside that document; `evidence_steward` (Sol medium) owns only bootstrap preservation/runner evidence under `results/dynark/phase-2/bootstrap/`, its protected runtime directory and `evidence/bootstrap.md`. The latter is the second coding worker. It has no cryptographic execution slot. Shared crate/manifests/product fork remain exclusively owned by `t1_full`.

The workspace contains untracked original circuits, probes, reference vendor, fixtures and reports. Preserve them. Work directly in the user-specified isolated crate, not a new worktree that omits the untracked/ignored baseline. No repository migration. Stage reviewed task paths explicitly; no push, PR, deployment or production ceremony.

T1 acceptance: the parent inspected the product boundary, randomness sampler and discriminating fixtures, verified final source hashes against the independent review, and independently ran `full_conformance` through the bounded runner. All 12 tests passed in 1.06 seconds (runner 1.409 seconds; sampled tree RSS 54,738,944 bytes; no limit or cleanup failure). This is correctness evidence, not a performance benchmark. The unchanged probe's 14 passing tests were inspected from its protected logs. The source/lock/executable identities and failed development trials are retained in the T1 reports. Trusted setup provenance and fresh caller entropy remain explicit external obligations. No anchored, dynamic, persistence or credential-scale gate is closed by T1.
