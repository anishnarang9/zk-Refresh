# DYNARK Phase 1

Date: October 10, 2026 (America/New_York). **Status: Phase 1 complete with explicit research gaps. Phase 2 may start its ungated hardening/representation tasks; paper-complete and fully dynamic promotion are not ready.**

Scope: audit the paper and existing BN254 prototype, establish fair baseline methodology, specify the credential product, and hand off a bounded Phase 2 plan. This phase does not implement the production engine or deploy anything.

## Executive findings

- Fresh verification:55 tests pass; six retained-proof replays and five new E2 fresh-process replays have expected outcomes. Correct no-cache full proving works on the unchanged real circuit with the same development key/reduction as anchored updates.
- Measured medians: no-cache full proof2.221s versus anchored update0.389s (30 measured pairs); complete local refresh5.417s versus3.587s (10 measured pairs), about1.51×. Full witness computation remains about3.13s on every refresh.
- Preparation remains costly: public UK382.969s, private projections510.323s; package serialization12.991s and validated warm-filesystem reload63.453s. Conditional crossover is515 comparable refreshes including all preparation/I/O, or271 in an ideal shared-public/no-I/O scenario. These are derived fixed-transition estimates, not measured pilot behavior.
- Negative findings: deterministic test randomness in the unused exported dynamic path; constant-one mismatch in the reference's ordinary matrix wrapper;32/80 custom FFT vector mismatches and one toy reconstruction timeout. These are preserved defects, not fixed in Phase 1. No fully dynamic credential sequence was run.
- Complete revised paper access remains unresolved. The matrix is availability-qualified; exact algorithms/security appendices and the reference's QAP/public-input obligations block specific Phase 2 promotions.
- The user accepted native desktop, controlled organization CA/narrow profile, dedicated signed authorization fields, pause-on-stale issuer status and permissioned work-request queue. Exact profile/issuer/device/freshness parameters need qualification; no top-level requirement question remains pending.

## Work and ownership

| Track | Owner / requested configuration | Files / authority | Status |
|---|---|---|---|
| Paper, algebra review, synthesis, decisions | Parent orchestrator | Top-level Phase 1 documents; public source retrieval | Complete within stated access limits; consequential algebra personally reviewed |
| Cryptographic source audit | `crypto_audit`, GPT-6.1 Sol high; parent synthesis | Source inspection and E3 diagnostic source | Worker halted by repeated model rate limits; parent reviews/persists findings |
| Baseline provenance and bounded validation | `baseline_audit`, GPT-6.1 Sol medium | Phase 1 results and E1/E2 code; routine E3 execution transferred here | E1/E2/E3 finished; source/evidence verification recorded |
| Credential/product sources | `product_research`, GPT-6.1 Sol medium | `evidence/product-research.md`; read-only source inspection | Complete; independent consistency/measurement-boundary review returned |

Workers were dispatched with explicit fresh-context model/reasoning overrides. The parent does not independently expose its model identity; the requested Astra orchestration role does not constitute verification of that identity.

Heavyweight queue owner: `baseline_audit`. No other worker may start proof/setup/memory-intensive work. [E1/E2/E3 experiment records](experiments.md) specify the approved scope and limits. E3 source was written by the high-reasoning worker; routine execution transferred to the medium-reasoning baseline worker after repeated model rate-limit failures. No baseline fixtures, keys, circuits or reports may change.

## Evidence rules

Claims are labeled primary source, inspected code, freshly measured, historical artifact, derived estimate, hypothesis, or unresolved. An ordinary verifier accepting a proof establishes neither cache safety nor zero knowledge of repeated proofs. A stale-root proof can remain valid for its original statement while failing execution-current-root policy.

The master roadmap is [here](../../superpowers/plans/2026-10-10-dynark-product-roadmap.md). The old split-proof proposal is historical context. Existing reports remain preserved.

## Completion checklist

- [x] Full-paper availability/version and conformance matrix, with explicit missing-full-text gate.
- [x] Current source and historical evidence audit.
- [x] Representative fresh verification and bounded fair-baseline measurements.
- [x] Product statement, trust/privacy boundaries and accepted D06–D10 decisions.
- [x] Ranked, falsifiable optimization hypotheses.
- [x] Bounded Phase 2 plan and consistency review.
- [x] Durable handoff and next-chat launch prompt.

## Reading order and evidence index

1. [Handoff](HANDOFF.md), then [decisions](decisions.md): accepted choices, boundaries and next ownership.
2. [Baseline audit](baseline-audit.md) and [worker evidence](evidence/baseline-worker.md): fresh/historical distinction, fair comparator, complete refresh and session economics.
3. [Research and gaps](research-and-gaps.md) and [crypto evidence](evidence/crypto-code-audit.md): availability-qualified matrix, algebra, defects and ranked experiments.
4. [Product specification](product-spec.md) and [primary-source research](evidence/product-research.md): signed eligibility, issuer/publisher trust, privacy and qualification.
5. [Phase 2 plan](phase-2-plan.md) and [pasteable launch prompt](phase-2-launch-prompt.md): exact files, gates, bounded tasks and acceptance.

Primary aggregates: [165-entry preservation freeze](../../../results/dynark/phase-1/baseline-freeze.json), [E2 build identity](../../../results/dynark/phase-1/e2-build-manifest.json), [six retained-proof replays](../../../results/dynark/phase-1/retained-proof-replays.json), [E3 vector/timeout results](../../../results/dynark/phase-1/fft-smoke/run-v1/report.json), [E3 execution identity](../../../results/dynark/phase-1/fft-smoke/execution-v1.json), [release RNG feature evidence](../../../results/dynark/phase-1/ark-std-release-fingerprint.json), and [archived probe identities](../../../results/dynark/phase-1/historical-probe-source-identity.json). Fresh test logs and sensitive runtime package paths are named in the worker evidence; private witness/cache/blinders are not part of the public aggregate package.

Fresh E2 evidence: [raw trials](../../../results/dynark/phase-1/e2-report.json), [summary and session estimates](../../../results/dynark/phase-1/e2-summary.json), [separate-process verification](../../../results/dynark/phase-1/e2-proof-replays.json), [resource watchdog](../../../results/dynark/phase-1/e2-watchdog.json), and [final link/preservation validation](../../../results/dynark/phase-1/final-validation.json).

Queue closed: E2 PID75943 exited0; its protected run directory is `artifacts/dynark/phase-1/near-e2-v1/`, and logs/watchdog are under `artifacts/dynark/phase-1/baseline-audit/`. No heavyweight job remains active. New-phase workers must recheck identities and current jobs before using saved development artifacts. The final consistency review resolved accepted-vs-pending decisions, the T5/G3 correction dependency, exported-method reachability wording and package-I/O accounting. No Phase 2 work was launched.
