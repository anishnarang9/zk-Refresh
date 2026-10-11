# Phase 2 status and evidence

Started October 10, 2026 in `/Users/anishnarang/Zk-refresh`. **Phase 2 is in progress, not complete.** The corrected [Phase 1 handoff](../phase-1/HANDOFF.md) and [approved bounded plan](../phase-1/phase-2-plan.md) govern this work. Historical paths remain provenance. Root starting commit: `0365566`.

The orchestrator owns architecture, algebra review, evidence review and documents only. All implementation, tests, measurements and helpers belong to explicitly dispatched GPT-6.1 Sol workers. At most two coding workers; no worker delegation. The orchestrator is the heavyweight queue coordinator; ownership of an execution slot is explicitly recorded before each run. Initially there is no authorized credential-scale run.

| Task | Dependencies | Owner | Status | Evidence / remaining gates |
|---|---|---|---|---|
| T0 contracts and derivations | Corrected Phase 1 | Orchestrator; Sol high review | In progress | [Conformance](conformance.md), [architecture](architecture.md); independent scheduler/kernel review pending |
| T1 full prover / public package / RNG | T0 full contract | `t1_full`, Sol high | Ready to dispatch | Small conformance and unchanged probe suite; no credential preparation |
| T2 imports / transitions / anchors | Reviewed T1 | Unassigned, Sol high | Pending | Exact raw component/dense equality and immutable state |
| T3 allocation / sharing | Stable T1/T2 API | Unassigned, Sol medium | Pending | E4-directed ablation; measured live memory and fair comparator |
| T4 cross kernel | T0 kernel review, T2 | Unassigned, Sol high | Pending | Product/remainder tree, exact oracle, observed crossover |
| T5 full dynamics | T0 scheduler, T1/T2 | Unassigned, Sol high | Pending | FFT/progress; 1,000 transitions; separately budgeted credential swaps |
| T6 persistence | Frozen state schema | Unassigned, Sol medium + high review | Pending | Authenticated confidential envelope, trusted generation, crash/recovery |
| T7 preparation/economics | Dependency review, measured engine | Unassigned, Sol high then medium | Pending | Selective hypothesis, measured sessions and held-out policy |

Records: [experiments and queue](experiments.md), [decisions](decisions.md). Worker returns and primary aggregate evidence belong under `results/dynark/phase-2/`; sensitive runtime artifacts belong under ignored `artifacts/dynark/phase-2/` with directory mode 700 and file mode 600.

The workspace contains untracked original circuits, probes, reference vendor, fixtures and reports. Preserve them. Work directly in the user-specified isolated crate, not a new worktree that omits the untracked/ignored baseline. No repository migration. Stage reviewed task paths explicitly; no push, PR, deployment or production ceremony.
