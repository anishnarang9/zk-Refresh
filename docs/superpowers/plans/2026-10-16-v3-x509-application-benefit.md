# V3 X.509 Application Benefit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking. This entire document is the continuation prompt for the lead agent.

**Goal:** Demonstrate that DYNARK correctly refreshes a proof for the bounded X.509/RSA credential application and determine, with complete matched measurements, whether it reduces total authorization work for a plausible workload.

**Architecture:** Preserve the accepted v2 and v3 work. Complete the v3 request-bound native client and local Solana queue effect, then compare Full Groth16 reproving with DYNARK refresh for the same finalized, unconsumed request under the same changing authenticated registry state. Charge shared and private preparation, witness generation, proof work, verification, persistence and application execution. Full proving remains the fallback when refresh is unsupported or uneconomic.

**Tech Stack:** Rust, Circom 2.2.3, BN254/Groth16, the pinned DYNARK engine, Python 3 profile/fixture tooling, Solana local validator/SBF, bounded experiment runner.

---

## Agent mandate and scope

You are continuing the repository at `/Users/anishnarang/Zk-refresh` on its existing `codex/engine-focus-oct14` work branch. The user's present objective is **one working bounded X.509 credential application plus an honest whole-application DYNARK-versus-Full result**. Do not build a generic circuit-conversion service, add a second credential family, or pursue cryptographic novelty. Solana is the current application verifier/effect path, not the research claim. Use a controlled demo issuer; the user has no organization-issued credential/key. No production PKIX, real-issuer, privacy/anonymity, devnet, or arbitrary-X.509 claim follows from this work.

The original protected effect is a finalized work-request append to the program-owned queue with atomic nonce/request consumption. Keep the existing exact-action design for this experiment. A short-lived or reusable service session is only a separate future design option; the untracked `docs/dynark/paper-to-application-map-2026-10-16.md` is a proposal, not an approved replacement for the queue application. Do not silently turn the current action into a session capability.

Success has two independent gates:

1. **Correctness/application:** A previously unseen in-profile certificate, admitted without a certificate-specific source/offset edit or individual setup, signs a finalized request. Its Full proof produces exactly one protected effect. For a *different unconsumed request*, an unrelated revocation makes the old-root proof fail, while a DYNARK-refreshed proof under the current root succeeds exactly once. Revoking that holder blocks current-root authorization. Full and refreshed proofs verify under the same ordinary Groth16 VK and identical application policy.
2. **Economic benefit:** A matched, directly timed complete-session comparison shows a material reduction in total wall time and/or CPU for an explicitly justified number and pattern of updates per prepared request, after charging all extra DYNARK work and reporting memory/storage. Register a target of at least 20% total savings at the selected workload, with the observed spread reported rather than hidden, before tuning. State the measured break-even point and workload assumptions. Do not equate warm update latency, a synthetic root sequence, or an assumed high update rate with a real-world net win. If the current exact-request lifecycle does not cross over under a plausible workload, report that result and the measured bottleneck; do not manufacture a favorable workload or claim success.

## Preserve and reuse accepted work

Read these before changing code:

- `docs/dynark/part5/submission-readiness-2026-10-16.md` and the user-supplied Part 5 handoff at `/Users/anishnarang/.codex/attachments/20b974a0-11a3-4c67-ada9-001a2cd2430c/Pasted text.txt`.
- `docs/dynark/part5/implementation-plan.md`, `v3-standard-client-plan.md`, `v3-request-bound-full-proof-gate.md`, `v3-heldout-acceptance-plan.md`, `supported-profile.md`, `v3-full-corpus-gate.md`, `v3-anchor-pilot-gate.md`, `v3-private-queue-effect-gate.md`, and `application-v2-local-full-execute-gate.md`.
- `docs/dynark/phase-2/claims-and-limits.md`, `performance.md`, and `docs/dynark/pre-part5/component-contracts.md` for the accepted engine, witness, identity and accounting boundaries.

Do not rerun Phase 1 qualification, the nine-credential v3 Full corpus, the one accepted v3 Anchor correctness pilot, the v2 local effect, or the separate blocked Phase 2 TRAIN/HOLDOUT campaign merely to recreate evidence. Reuse their frozen source and artifact identities where appropriate. New measurements must be labeled as new, on the current versioned v3 path. Preserve the pinned vendor oracle and quadratic cross-term fallback. Keep circuit, profile, R1CS, witness generator, setup, ordinary VK, adapter and ELF identities versioned together.

Known starting facts to verify at intake rather than assume current forever: v3 has nine training credential pairs, 27 randomized Full proofs and 207 ordinary checks under one development setup, one OpenSSL-issued Anchor refresh, but no request-bound positive v3 Execute or loaded-v3-ELF effect. `V3BoundWitness::open_full` returns `Unsupported`; v3 `Execute` returns `Unavailable` after proof preflight. Public/private preparation in the single Anchor pilot was 732.500/704.394 seconds; refresh plus ordinary verification was 0.922 seconds. Complete v3 witness generation is still required. These figures are stage evidence, not net-session evidence.

## Team and execution control

Use up to **five lower- or medium-reasoning subagent workstreams**, assigning small independent tasks in waves. Prefer the available GPT-6.1 Sol model at low reasoning for bounded fixtures, tests and documentation; use medium reasoning for integration or correctness review. The current team has four concurrency slots including the lead, so run no more than **three active subagents beside the lead**. Do not spend a high-reasoning worker on routine work. The lead owns architecture, shared contracts, final integration, experiment registration, evidence review, resource scheduling, commits and pushes. Delegate only disjoint file ownership, and transfer ownership explicitly before another worker edits a shared file.

Suggested initial lanes, adapted after verifying the checkout:

| Lane | Owner files / result | Can start alongside |
| --- | --- | --- |
| A: exact request bridge | `program/examples/export_v3_request_fixture.rs`, `tools/part5/prepare_v3_request_fixture.py`, their focused tests; public plan to finalized V3F1/V3F2 action to private V3Q1 signer | B and C |
| B: native client | `crates/dynark-native-client/src/v3_binding.rs`, `v3.rs`, `v3_relation.rs`, `v3_setup.rs`, focused v3 tests; authenticated state, safe `open_full`, complete witness and ordinary Full proof | A and C, after locking shared wire contract |
| C: application tests/policy | `program/tests/application_v3_execute.rs`, `application_v3_preflight.rs`, `program/src/application_runtime_v3.rs`; tests-first positive and negative Execute then reviewed queue-effect connection | A and B, but one owner for program runtime edits |
| D: measurement design | Read-only at first; register matched Full/Anchor session protocol, cost fields, stopping criteria and scrubbed report schema under `docs/dynark/part5/` | Any lane; no heavy run |
| E: heldout/evidence | Read-only at first; prepare freeze checklist and independent certificate acceptance runner using `v3-heldout-acceptance-plan.md` | Any lane; generate heldout keys only after freeze |

Keep **one serialized heavyweight job** across all lanes. Use the existing bounded runner, finite wall/RSS/storage caps, offline/locked single-job Cargo where applicable, four Rayon workers, and the repository's accepted cleanup/receipt pattern. Small source inspections and isolated unit tests may proceed in parallel when they do not compete for memory or file ownership. Never launch duplicate full setup, witness, proof or local-validator runs. Protect signer keys, DER, raw witnesses, proofs and private caches in fresh owner-only ignored paths. Git reports must contain only scrubbed counters, hashes and evidence.

Before each edit, inspect targeted `git status` and diff. This checkout has extensive unrelated untracked files. Stage exact task paths only; never `git add -A`, `git clean`, a destructive reset, or a force push. Commit each reviewed, test-passing small slice and push after every one or two accepted commits, at minimum at every completed gate. Verify the upstream/remote before the first push, handle any remote divergence without discarding work, and record the commit hash and evidence link in the current gate report. Do not create a PR or deploy merely to satisfy a cadence. Keep the user updated with accepted result, remaining uncertainty and next gate.

## Ordered work, with parallel slices inside each gate

### Gate 0: Intake and reproducible baseline

**Files:** read-only source/docs above; update only the new current-status/evidence note under `docs/dynark/part5/` if a recorded fact has drifted.

- [ ] Check branch, upstream, tracked diff, relevant untracked paths, active heavy processes and pinned artifact hashes. Do not touch unrelated user work.
- [ ] Build a source/identity map for v3 action transport, current-state authority, witness, proof, ordinary adapter, program runtime, local validator and benchmark entry points. Confirm ownership boundaries for lanes A–E.
- [ ] Name the exact Full baseline and Anchor variant, using the same circuit/setup/VK, credential, finalized request, root sequence, hardware, and application effect. Execute the two modes in separate cloned pre-execution ledger states so the same request is never consumed twice in one state. Record which costs are shared and which are extra per credential/action. Freeze a measurement protocol before performance tuning.
- [ ] Commit and push the small intake/protocol note; avoid a new heavy qualification run.

### Gate 1: One genuine request-bound v3 Full proof

**Files:** `program/examples/export_v3_request_fixture.rs`, `tools/part5/prepare_v3_request_fixture.py`, `crates/dynark-native-client/src/v3_binding.rs`, `v3.rs`, `v3_relation.rs`, `v3_setup.rs`, targeted tests in `program/tests/`, `tools/part5/tests/`, `crates/dynark-native-client/tests/`.

- [ ] Lane A writes failing focused tests for a fresh supported demo-issued certificate whose signed issuer/policy/validity populate a public request plan without hard-coded certificate bytes. The Rust builder finalizes that plan, exports the canonical action, and the holder signer in the private V3Q1 bridge signs exactly that action. Reject altered nonce, payload, account order, issuer/policy, wrong signer and mismatched public fields.
- [ ] Lane B completes only the safe authenticated native `open_full` path after independently verifying the exact package/profile/setup and current config/issuer/status/registry/request record. Compare all 751 input scalars and all six public fields, generate the complete 784,796-field WTNS, validate every R1CS row, use fresh secure randomness for Full proving and ordinary-verify the result. The relation checker remains non-authorizing. Keep the current fail-closed behavior until the full binding exists.
- [ ] Join A and B on one newly issued **training** credential with retained private signer outside Git. Use its actual Rust-finalized request action, not a synthetic caller-selected digest. Pass the ordinary proof and six ordered public fields through the existing v3 adapter and host verifier. Do not treat a standalone proof as application authorization.
- [ ] Run focused failures first, then bounded relevant regressions. Review the exact hashes and private-output hygiene; commit/push the bridge and native slices separately.

### Gate 2: Actual v3 protected effect and refresh correctness

**Files:** `program/src/application_runtime_v3.rs`, its existing private effect helper, `program/tests/application_v3_execute.rs`, focused local-validator harness files found at Gate 0, `crates/dynark-native-client/` refresh/submit boundary.

- [ ] Lane C first demonstrates a tests-first positive Execute that passes exact request/current-state/proof preflight but reaches the current `Unavailable` effect gate. Connect only the already reviewed atomic queue append/request-consumption helper. Verify one append, one consumption, replay rejection and unchanged bytes on a failed effect.
- [ ] Build and load the actual v3 ELF in a bounded local validator. Pin program/source, ordinary VK, setup/profile and ELF hashes separately. Read the exact request and queue bytes at finalized commitment. Reuse the v2 local-validator procedure, but do not reuse its five-field key or proof.
- [ ] For a **different finalized and still unconsumed request**, establish a Full base under root R0, publish an authenticated unrelated revocation to R1, and show the old proof fails current-root policy. Produce a complete R1 witness, a DYNARK Anchor refresh for the same credential/action, independently ordinary-verify it, and execute that request once under R1. A consumed Full request is never recycled as the refresh case.
- [ ] Revoke the tested credential itself and reject old-root authorization and any purported current active-leaf witness. Include wrong action/account metadata, disabled or stale issuer, changed policy, malformed proof, cache-context substitution, request replay and failure rollback. Commit/push focused passing gates before broad integration.

### Gate 3: Matched application economics

**Files:** a new focused measurement harness in the existing Part 5 tooling/harness location identified at Gate 0, scrubbed `results/dynark/part5/` reports, and one interpretation note under `docs/dynark/part5/`.

- [ ] Run Full and Anchor modes over identical, authenticated, distinct-root sequences for one fixed credential and one unconsumed exact action. Counterbalance mode order and retain raw per-trial stage times. Include 0, 1, 2, 5 and 10 root changes first; extend to 100+ only if the registered resource and relevance gates justify it. Exercise unrelated-root, own-revocation, new-action, abandonment, cold/restart and superseded-target cases separately.
- [ ] Charge public setup/material once per matching circuit and declare how it is shared; charge private preparation to the exact credential/action. Measure complete witness generation, import and full relation validation, delta construction, proving/refresh, ordinary verification, local state catch-up, serialization/reload, application submission/effect and failed/retried work. Record wall time, CPU, peak RSS, retained bytes, transaction size/compute and proof success. Do not add medians from separate runs and call them a session result.
- [ ] Give a directly measured break-even distribution and a clearly marked model for additional update counts. Use observed issuer/operator update and action-lifetime data only if actually available; otherwise label churn assumptions as synthetic and report conditional benefit. The Full comparator gets the same legitimate witness or backend improvements as Anchor when applicable.
- [ ] Publish both wins and losses. Warm proof-stage speedup alone, the v1 ~16x incremental-witness stage result, and the old v3 0.922-second pilot are not the required v3 application result. Commit/push measurement harness, protocol and scrubbed results in reviewable slices.

### Gate 4: One evidence-ranked repair cycle if total benefit is absent

**Files:** only the measured bottleneck's existing module and focused tests; update the registered comparison and report.

- [ ] Quantify the observed gap first. The present v3 private preparation cost is roughly 704 seconds while one warm update saves only a small amount against Full proving; a few same-action retries cannot repay this as-is. Shared-public preparation alone does not solve per-action private preparation. Do not assume that faster v3 witness generation improves the *difference* between modes if the same improvement also speeds Full.
- [ ] Choose one bounded, already-supported engineering candidate from accepted work, such as selective/on-demand private preparation **only after its paid-work evidence supports it**, or v3 incremental witness generation using a newly derived v3 dependency map with exact complete-output equality. State the predicted total-session effect before editing. Preserve the correct quadratic cross-term oracle and full fallback; do not reopen previously losing Fast/GLV/twiddle campaigns or start multiple optimization tracks.
- [ ] Run exact-output, full-relation, ordinary-proof and application-effect regressions, then rerun the same registered matched comparison. If the result still cannot beat Full in a plausible exact-request lifecycle, stop the speedup claim and deliver a concise decision memo. A longer-lived X.509 authorization is a separate application-semantics design requiring review before implementation.

### Gate 5: Frozen unseen-credential acceptance and final report

**Files:** `docs/dynark/part5/v3-heldout-acceptance-plan.md` as the binding test plan; new frozen identity/evidence and final report under `docs/dynark/part5/` and `results/dynark/part5/`.

- [ ] Freeze source, circuit/profile, setup, proof runner, client, adapter and loaded ELF identities. Then generate the already specified eight new certificates with four new issuer keys, eight holder keys, all eight supported layouts and at least four independent OpenSSL issuances. Keep all keys and raw material protected/ignored.
- [ ] For each heldout credential, establish issuer enrollment/policy and authenticated state; test Full protected effect, a separate unrelated-root Anchor refresh/effect, own-revocation rejection and replay. Require no source, manual DER-offset or per-certificate trusted-setup change. Check shared public material and isolated private state.
- [ ] Apply the registered performance method to the heldout cohort without tuning on its outcomes. Report variability, preparation distribution, break-even, memory, effect/transaction costs and limitations. Distinguish training, frozen heldout, synthetic workload assumptions and any observed operator data.
- [ ] Deliver a reproducible artifact: exact commands, pinned identities, code/result locations, proof and application checks, scrubbed raw-trial summaries, and a plain-language answer to **“Did DYNARK save total work for this X.509 authorization application, and under what update pattern?”** State “not established” or “no” if that is what the evidence supports. Commit/push each accepted report and the final evidence index.

## Completion and stop conditions

Do not mark the objective complete on a local proof check, one warm refresh, host-only program test, or synthetic engine trace. Completion requires the v3 protected effect, current-root/own-revocation safety, frozen unseen-credential acceptance and the matched whole-application economics report. If measured benefit is conditional, state the exact condition and whether it occurs in the demonstrated workflow. If no plausible net benefit exists after the bounded repair cycle, provide the negative result and the smallest next design decision; preserve all accepted work and do not expand into a generic toolkit or another application to hide it.

Devnet deployment, PR/merge and production issuer enrollment are outside this plan. Continue local work autonomously; prepare any later deployment package for review without treating it as part of the performance result.
