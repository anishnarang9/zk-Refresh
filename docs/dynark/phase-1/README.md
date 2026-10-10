# DYNARK Phase 1 — corrected research and specification

October10,2026. **Status: full-paper research, baseline validation, E4 profiling and the engineering specification are complete.** The previous completion claim was too broad; this package corrects it with all30 pages read by the parent and independent GPT-6.1 Sol reviewers, directly measured diagnostics, and an independent derivation review. The earlier package is preserved under `archive/pre-full-paper/`. Phase2 can begin with T0/T1, then T2/T3 under their dependencies; production, full-dynamic and integration gates remain explicit. This chat stops at the Phase1 handoff.

## Goal-by-goal status

| Requested goal | Current result | Completion boundary |
|---|---|---|
| Read/map complete paper | All30 pages read; source hashed; equations/algorithms/security/evaluation mapped to reference code | Supplied file has no appendix and itself defers selected proofs/algorithms. Those omissions are precisely recorded, not silently treated as supplied |
| Audit current implementation/results | Fresh proof/test evidence, historical provenance, RNG/domain/index/state defects and corrected QAP analysis | Valid proof acceptance does not certify ZK, cache safety or original-key interoperability |
| Trustworthy baselines/profiling | E1–E4 complete; same-key no-cache full comparator; direct complete-refresh trials; allocation counters,13 preparation sampling windows and witness-child memory | E4 diagnostics do not replace E2 timing. Public-UK internal profiling, exact per-kernel allocation attribution, cold load and real workloads remain scoped limits |
| Product requirements | Native desktop, controlled CA/narrow RSA profile, signed authorization fields, pause-on-stale issuer status, exactly bound work-request queue accepted | Concrete issuer encodings/device/freshness/workload qualification still needed; current product advantage not demonstrated |
| Decisions/experiments/Phase2 tasks | Ranked falsifiable hypotheses, bounded owned tasks, corrected handoff and next-chat prompt; independent review findings resolved | Source omissions and implementation/security gates have named owners and resolution paths; see final validation record |

## Findings that change the earlier handoff

- **The paper is now fully read.** [Research map](research-and-gaps.md) identifies each section/theorem/algorithm and the supplied-file omissions. Its SHA256 is `f851f11ed8ae8a6876dafe09373650098aa792b9f886019eea4d98060fa7b259`.
- **Quadratic cross terms were intentional.** Paper §5.1 says they were faster at tested supports. Keep a measured oracle/fallback; evaluate the fast method at our actual supports.
- **Different QAP augmentation is not automatically unsoundness.** Separate ordinary soundness, stronger properties and exact key/basis interoperability.
- **Ordinary proving still has optimization room.** The fair no-cache comparator has seven quotient transforms; the paper's four-FFT proposal is not supplied as an algorithm or present in these routines.
- **Warm speedup does not establish product economics.** Full/update complete local medians5.417/3.587s show1.51× for one fixed synthetic transition;510.323s private preparation requires271 comparable refreshes even under ideal shared-public/no-I/O assumptions. No pilot reuse distribution was measured.
- **Memory and preparation work are now directly profiled.** E4 requested-heap peak2.512GB includes the original cache kept as an equality oracle; private preparation creates50.329GB allocation traffic. The67.1MB compressed cache retains201.3MB of projection data in memory. Both regenerated projection vectors match exactly, proofs verify, and the witness child peaks at222.3MB RSS. These are diagnostic observations with explicit boundaries.
- **Known defects remain explicit Phase2 work:** exported deterministic test randomness, constant-one matrix wrapper mismatch,32/80 custom FFT mismatches and a partial-batch reconstruction timeout. No fully dynamic credential sequence or original-zkey/Solana integration was established.

## Read in this order

1. [Research and conformance](research-and-gaps.md), [algorithm evidence](evidence/paper-algorithms.md), [security evidence](evidence/paper-security.md).
2. [Baseline audit](baseline-audit.md), [baseline worker record](evidence/baseline-worker.md), [reopened coverage/profiling](evidence/research-coverage.md).
3. [Product specification](product-spec.md), [primary product research](evidence/product-research.md), [decisions](decisions.md).
4. [Phase2 bounded plan](phase-2-plan.md), [handoff](HANDOFF.md), [next-chat prompt](phase-2-launch-prompt.md), and [independent revision review](evidence/revision-review.md).

## Ownership and evidence

Parent: personally reads paper, reviews algebra/source/evidence and writes synthesis; no implementation code. `paper_algorithms`, `paper_security` and `revision_review`: explicit GPT-6.1 Sol high, source/algebra review and owned reports. `research_coverage`: explicit GPT-6.1 Sol medium, audit and E4 instrumentation. It completed the sole heavyweight run in878.370s within900s; no owned heavyweight job remains. No setup/public-UK regeneration occurred; one private-preparation repeat closed missing attribution. [Experiment contracts](experiments.md) record resources/stops.

Prior E1–E3 owners and results remain preserved. Original code/fixtures/keys/reference stay frozen. Root Git was initially absent and was initialized after the user's explicit request for small local commits; no push is authorized. All public aggregates are under `results/dynark/phase-1/`; private witness/cache/blinders stay in protected local artifacts. Historical [code audit](evidence/crypto-code-audit.md) predates supplied-paper review; its source observations remain useful, while current research/security reports supersede its paper-access and QAP-scope limitations.

Evidence index: [165-entry freeze](../../../results/dynark/phase-1/baseline-freeze.json), [E2 build identity](../../../results/dynark/phase-1/e2-build-manifest.json), [raw E2 trials](../../../results/dynark/phase-1/e2-report.json), [summary/session estimates](../../../results/dynark/phase-1/e2-summary.json), [independent replays](../../../results/dynark/phase-1/e2-proof-replays.json), [watchdog](../../../results/dynark/phase-1/e2-watchdog.json), [E3 failures](../../../results/dynark/phase-1/fft-smoke/run-v1/report.json), [release RNG evidence](../../../results/dynark/phase-1/ark-std-release-fingerprint.json), [E4 profile](../../../results/dynark/phase-1/profile-v1/summary.json), [revised validation](../../../results/dynark/phase-1/revised-validation.json). Old `final-validation.json` applies only to the pre-reopening package and remains preserved.

A valid old-root proof remains valid for its original statement but cannot authorize against a newer execution root. All performance targets remain provisional; no deployment, spending, private real-key access or Phase2 implementation occurred.
