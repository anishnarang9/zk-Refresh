# BN254 engine and cache implementation plan

> **For agentic workers:** Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` for the next authorized phase. This plan specifies interfaces, tests and acceptance without providing implementation code: the user reserves implementation for GPT-6.1 Sol workers. Do not execute Phase 2 in this Phase 1 chat.

**Goal:** Deliver a validated BN254 full/anchored/fully dynamic engine with explicit artifact and cache boundaries, then measure preparation/memory optimizations against the same-key no-cache full baseline.

**Architecture:** Immutable shared public package; holder/action-private versioned state; fallible normalized transitions; CSPRNG-driven complete ordinary Groth16 proofs; atomic reconstruction generations. Preserve the existing credential relation and historical reference/probes as differential evidence.

**Tech stack:** Rust, existing pinned arkworks 0.5 BN254 and Circom R1CS/WTNS, reference commit `c73a380df86d8f5d195f1e20c8a1d86a7dce084b` with explicit patches. No dependency upgrade, new credential circuit or deployment in this plan.

## Entry gates and permitted start

Read [HANDOFF](HANDOFF.md), [decisions](decisions.md), [research matrix](research-and-gaps.md), [baseline audit](baseline-audit.md), all evidence reports and the master roadmap. Workspace is now `/Users/anishnarang/Zk-refresh`. Recheck source/artifact identities, Git status and queue state. Root Git was initialized after the user's explicit request for small local commits; preserve historical manifests and make concise commits as meaningful small groups of files change. No push was authorized.

| Gate | Blocks | Owner and exact resolution |
|---|---|---|
| G1: supplied30-page paper fully read/mapped; authors defer selected details | Claim of checked complete author proofs or author-exact omitted pseudocode; approval of an unreviewed derived kernel/scheduler | Reading/hash/parameter/locator work is closed in Phase1. Astra uses the omission register and independent derivations; T0 reviews chosen equations/invariants before T4/T5 |
| G2: exported deterministic fully dynamic RNG | Any production-reachable fully dynamic proving | Sol high proof owner accepts caller cryptographic RNG on all paths, propagates entropy failure, reviews transcript independence; Astra reviews resulting algebra |
| G3: custom reconstruction shape/progress defects | Fully dynamic actual-circuit trials and reconstruction promotion | Sol high dynamics owner uses E3 evidence, implements validated dimensions/budgets and differential tests before heavy runs |
| G4: claim scope and exact reduction/key compatibility | Stronger simulation/adaptive properties beyond reviewed argument; original-zkey interoperability | Unaugmented construction matches paper; augmentation difference is not inherently unsound. Use Phase1 security analysis and exact relation identity. Public H-basis conversion is derived, not an executed original-key adapter; P4 validates it |
| G5: profile scope | Optimization claims outside measured E4 stages, especially public UK internal attribution | Read E4 final evidence and residual limits. T3 profiles an unmeasured kernel only when a proposed optimization requires it; no blanket deferral/repetition of Phase1 profiling |
| G6: exact profile/device/freshness parameters and real corpus unqualified | Final profile/availability limits and changed statement | D06–D10 are accepted: native, controlled CA, signed authorization fields, pause on stale issuer status, work-request queue. Product lead qualifies issuer OIDs/encoding, size limits, signer support, request schema, device budget and timeout; consent still required before real private data. Unchanged-circuit engine tasks do not depend on this |
| G7: original `.zkey` and Solana encoding/execution unestablished | Existing deployed key or dynamic Solana claims | Separate reduction/key mapping and local ordinary-verifier adapter; deployment requires user approval in Phase 4 |

Phase2 may begin T0–T2 and T3 after the final Phase1 handoff. Source reading is complete. T4/T5 require approval of specific derived algorithms and corrected invariants, not another generic request to find/read the paper. Full paper conformance, production security and original-key/Solana claims remain distinct from implementation readiness.

## Interfaces to freeze before workers edit

| Contract | Required fields / behavior |
|---|---|
| Circuit identity | SHA-256 R1CS + witness executable + profile + public-schema; curve/reduction/domain/serialization versions; no filename-only identity |
| Public package | Immutable PK/VK/UK/matrix index references and setup identity; single ownership of each large allocation; no witness-derived state |
| Validated assignment | Exactly v canonical field values; coordinate0=one; expected public vector; correct package; full or documented incremental satisfaction validation |
| Transition | Base and target generations, normalized full-index additive deltas, exact expected new public vector. Combine duplicate coordinates in field, remove zero sums, reject out-of-bounds and constant mutation before group work |
| Anchor | Immutable z0 identity, projections, proof/blinders and domain/key binding. All updates refer to this same base; no silent rebasing |
| Dynamic state | Active/rebuilding generation identifiers, snapshot, pending corrections, scheduler progress, proof/public metadata and bounded memory budget; atomic swap only after complete reconstruction |
| Prove/update result | Ordinary complete proof, exact public statement, resulting committed generation or typed failure; no partially exposed successful state |
| Persistence | Authenticated bounded envelope with version, package, credential/action and root generation, lengths and checksum/authentication; secret data protected locally; recover-or-rebuild on interruption |

Proposed module paths below are new and must not reorganize the harness. Reference algebra changes use an isolated product fork at `crates/dynark-bn254/vendor/ark-groth16/`; its initial snapshot/hash and each patch must be recorded. Do not overwrite `experiments/dynark/vendor/DYNARK_`, which remains the Phase 1 oracle. No Git/worktree assumption is made.

## T0 — close evidence and security definitions

**Owner:** Astra high reasoning, assisted by one Sol high read-only worker. **Files:** update `docs/dynark/phase-1/research-and-gaps.md` only through a clearly dated addendum or create `docs/dynark/phase-2/conformance.md`; new source manifest under `results/dynark/phase-2/`. No implementation ownership.

- [ ] Consume the completed30-page review, exact hash, source-omission register and corrected formula/code map; do not repeat Phase1 reading as unfinished work.
- [ ] Freeze the implementation contract using Phase1's parameter/quotient derivation and candidate Trummer algorithm. Resolve fast-kernel/scheduler choices and overshoot behavior before code.
- [ ] Carry forward reviewed ordinary-QAP and transcript-randomization scope, including Groth's benign relation/auxiliary-input generator assumption; limit stronger claims explicitly. Review BN254 assumptions and any reduction/key-basis adapter before promotion. Freeze the C-only public-input and equal-padded-domain reduction fixtures below as discriminating acceptance cases.
- [ ] Define invariant checks and accepted domains. Distinguish static derivation, vector smoke evidence and ordinary proof acceptance.
- [ ] Review the complete resulting conformance table personally before opening gated algorithm tasks.

**Acceptance:** every consequential algebraic choice has primary-source location plus reviewed code/derivation mapping; unresolved gates remain visibly closed. No benchmark required.

## T1 — minimal crate, immutable public package, and RNG boundary

**Owner:** Sol high proof engineer. **Ownership:** create `crates/dynark-bn254/{Cargo.toml,Cargo.lock,src/lib.rs,src/artifact.rs,src/full.rs,src/randomness.rs,tests/full_conformance.rs}`; initial isolated vendor fork and `PATCHES.md`. Another worker may read but not mutate this shared boundary until ownership transfer.

- [ ] Before copying, record source/lockfile identities and expected new paths. Retain same dependency versions and licenses; no workspace-wide migration.
- [ ] Wrap the independently verified no-cache full path with fallible dimensions/public schema, preserving constant one. Keep the known-bad matrix wrapper outside exported product API.
- [ ] Make public package immutable and share PK rather than embedding clones. Define its content identity before persistence.
- [ ] Route randomness through a caller cryptographic RNG with explicit failure behavior; no exported test RNG, fixed seed or hidden zero-blinding production path. Tests use isolated deterministic fixtures only where identified as tests.
- [ ] Add meaningful conformance cases: five public inputs, variables greater/less than domain, non-power-of-two constraints, public/private/zero deltas, invalid assignments, altered each public input, incorrect key, and entropy-source failure.
- [ ] Include `w*w=x`, with public x appearing only in C: accept satisfying assignments, reject altered x and unsatisfied assignments, and preserve coordinate one. Compare original-row and A-augmented reductions at the same padded N using matching keys for each; show that equal N does not make their QAP queries interchangeable. Original-zkey H-basis interoperability remains a separate P4/G7 task.
- [ ] Run `cargo test --locked --manifest-path crates/dynark-bn254/Cargo.toml --test full_conformance` and the unchanged probe test suite. Record source/binary/lock hashes.

**Acceptance:** ordinary crates.io ark-groth16 accepts all valid full proofs and rejects altered statements with explicit false; malformed/entropy failure returns typed error without panic. Same relation/setup/reduction as the comparator. G4 remains a separately reviewed security requirement, not inferred from tests. Budget: small tests ≤5 minutes/1 GiB; no actual-circuit preparation yet.

## T2 — validated sparse transitions and anchored state

**Owner:** Sol high proof engineer after T1. **Ownership:** `crates/dynark-bn254/src/{import.rs,delta.rs,anchored.rs}`, `tests/{delta_contract.rs,anchored_conformance.rs}`, necessary isolated vendor patch under exclusive proof ownership.

- [ ] Import canonical R1CS/WTNS with file/section/allocation bounds. Check exact counts and index ranges before arithmetic. Preserve original relation; no silent field reduction.
- [ ] Normalize additive deltas by full coordinate; combine duplicates, drop zeros/cancellations, reject coordinate0 mutation and wrong instance/auxiliary split. Track touched matrix entries separately from nonzero row changes.
- [ ] Bind immutable anchors to circuit/setup/domain/credential/action/witness generation. Reject target transitions against another anchor or mismatched expected public statement.
- [ ] Differentially compare raw quotient/proof components on small satisfying pairs; verify randomized proofs independently. Cover overlapping/diagonal/disjoint A/B supports, repeated indices, public-root/action changes, reversals and no-ops.
- [ ] Run `cargo test --locked --manifest-path crates/dynark-bn254/Cargo.toml --test delta_contract --test anchored_conformance`.
- [ ] Replay the actual near/middle/far witnesses with matching private artifacts when identity permits. Do not pair separate-before trees with the near anchor without first constructing the exact full-index delta.

**Acceptance:** malformed transitions fail before group work; normalized updates agree with dense evaluation; anchor is unchanged on success and failure; every resulting proof verifies for exact public values. Budget: small randomized tests ≤10 minutes/1 GiB; actual-circuit run requires a recorded ≤35-minute/4-GiB experiment with sole queue owner. G1 restricts claims about absent author proofs and unimplemented algorithms; the complete supplied-paper reading is closed.

## T3 — public/cache allocation profile and first representation ablation

**Owner:** Sol medium performance engineer after T1 API handoff; at most the second coding worker. **Ownership:** `crates/dynark-bn254/benches/phase2_stages.rs`, `results/dynark/phase-2/representation/`, `docs/dynark/phase-2/performance.md`. Mutations to `artifact.rs` require explicit transfer from proof owner.

- [ ] Reuse E4's allocation/call-stack evidence and profile only missing attribution needed by the selected change. Distinguish requested heap, current RSS, high-water RSS and structural bytes; diagnostic timing is separate from E2 latency.
- [ ] Keep the seven-transform no-cache full baseline and count every full-prover transform/MSM. The paper's four-FFT proposal is not supplied in text/code. A lower-transform candidate needs a separate reviewed derivation, exact quotient oracle and same-key proof checks; report its effect on both full cost and the dynamic comparison.
- [ ] Compare duplicate versus shared public package with 1/2/10 private states under equal inputs/threads; measure current live memory, peak, serialized bytes, load/decompression, total CPU and wall.
- [ ] Try only the first supported buffer-ownership change, retaining arithmetic and key representation. Validate against T1/T2 oracles before timing.
- [ ] Repeat E2 method with source identity and counterbalanced order; report full/no-cache, preparation, refresh, reload and total sessions. Include negative regions.

**Acceptance:** positive memory result measured live and not explained solely by compression; ordinary proof acceptance unchanged; total session effect includes any load penalty. Reject a change that violates memory/latency budgets or only hides work. No 16-MiB/512-MiB target claim unless directly observed. One full preparation per compatible package, no repeated preparation for minor inspections.

## T4 — reviewed fast cross-term kernel and crossover

**Owner:** Sol high algebra engineer after G1/T0 and T2; proof owner reviews. **Ownership:** `src/cross_term.rs`, `tests/cross_term_oracle.rs`, `benches/cross_term.rs`, corresponding isolated vendor patch. Do not combine with cache restructuring.

- [ ] Write the exact primary-source equations, field/domain preconditions and diagonal rule in a design record before code.
- [ ] Implement the independently reviewed Trummer/product-tree candidate in the Phase1 algorithm report, or an equivalent fully documented method. The PDF defers its pseudocode. Retain quadratic as oracle/small-support fallback; the authors intentionally use it in their benchmarks.
- [ ] Exercise zero, single, overlapping, full diagonal, disjoint, canceled and uneven supports; deterministic equality of group result under common inputs is required, not only proof verification.
- [ ] Measure conversion/interpolation/allocation/field/group time over actual near/far/new-action supports, including tiny supports. In full-dynamic correction calls, distinguish accumulated support b from current d: a fast transform over their union does not establish O(dlog²d) field work. Review the call-site strategy and report both complexity terms.
- [ ] Run `cargo test --locked --manifest-path crates/dynark-bn254/Cargo.toml --test cross_term_oracle`; run release kernel benchmark with fixed threads and raw samples.

**Acceptance:** exact oracle equality and independently valid proofs; choose fallback below measured crossover. Unreviewed derivation blocks implementation; full supplied-paper access no longer does. Kernel tests ≤10 minutes/1 GiB; new-action real proof experiments need a finite pair-work budget before launch.

## T5 — fully dynamic reconstruction and transactional state

**Owner:** Sol high dynamics engineer after T2 and T1's RNG boundary. The bounded dimension/progress corrections below are authorized work to close G3; they do not depend on G3 already being closed. Full algorithm approval and security acceptance require T0/G1/G4; heavy actual-circuit reconstruction additionally requires G2/G3 closed. **Ownership:** `src/{dynamic.rs,reconstruction.rs}`, `tests/{fft_domains.rs,dynamic_sequences.rs}`, isolated vendor `dynamic_cache.rs`/`fft_handler.rs` exclusively. Do not overlap T4 mutations to the same fork; transfer ownership explicitly.

- [ ] Replace caller ambiguity between m,v,N with validated dimensions. Support declared power-of-two padded domains and explicitly reject unsupported shapes until implemented.
- [ ] Resolve E3 even/odd-log and partial-batch behavior. Positive step budgets must make bounded progress; zero-budget calls must be specified no-ops. Validate forward/inverse vectors against arkworks for both fields and groups.
- [ ] Implement active/rebuilding generation invariants, frozen snapshot, accumulated cross corrections and atomic swap. Each update applies exactly once. Specify t+d=b, t+d>b and d>b behavior; Protocol3's exact-equality pseudocode is insufficient for arbitrary steps. Count all fallback/rebuild work.
- [ ] Use current independent proof randomness on every emitted proof. Validate full assignment/public input correspondence through sequences.
- [ ] Run at least 1,000 small scalable transitions, multiple completed reconstruction/swap cycles, dense/new-action/no-op/revert/batch changes and failure injection at every phase; compare checkpoints to fresh full calculation.
- [ ] Run `cargo test --locked --manifest-path crates/dynark-bn254/Cargo.toml --test fft_domains --test dynamic_sequences` before a separately budgeted actual-circuit sequence.

**Acceptance:** no stalled positive-budget scheduler, no mixed-generation proof/cache, exact vector/raw-state agreement, ordinary verifier success at every valid transition and precise rejection. Report all maintenance/background CPU/memory and maximum observed pause. Small tests ≤15 minutes/2 GiB; actual-circuit resource bounds are derived from profile first, not silently inherited from anchored mode.

## T6 — authenticated persistence, reload and invalidation

**Owner:** Sol medium systems engineer; high-reasoning review of binding. **Ownership:** `src/{cache.rs,encoding.rs}`, `tests/{cache_roundtrip.rs,cache_adversarial.rs}` after dynamic schema freeze. No independent wire-format edits by other workers.

- [ ] Specify bounded versioned envelope, authenticated identity and lengths, local secret protection and atomic write/commit strategy. Preserve private cache and public package separation.
- [ ] Reject cross-key/circuit/reduction/action/holder swaps, corrupt/truncated/oversized input, stale generation rollback and unknown versions before allocation/group work.
- [ ] Inject interruption at each reconstruction/write phase; restore a complete committed generation or explicitly rebuild. Own revocation/issuer disable/action completion cancels use and invalidates relevant state.
- [ ] Run `cargo test --locked --manifest-path crates/dynark-bn254/Cargo.toml --test cache_roundtrip --test cache_adversarial`; measure cold reload including authentication/deserialization and peak memory.

**Acceptance:** reload equivalence with uninterrupted proof sequence, no unauthenticated/mixed private state, correct permissions and bounded allocations. File-permission tests alone do not satisfy authentication. No real holder keys required.

## T7 — selective/lazy preparation and adaptive economics

**Owner:** Sol high for reuse derivation, Sol medium for benchmark plumbing sequentially. **Ownership:** `src/{preparation.rs,selection.rs}`, `tests/preparation_equivalence.rs`, `benches/session_cost.rs`; shared anchored/cache modules only after transfer.

- [ ] Pick one hypothesis from research ranks 7–9 with a written exact dependency argument and falsifiable target. Do not implement all at once.
- [ ] Test materializing selected projection entries including cold miss and fallback; count global transforms and all background work.
- [ ] Treat cross-action reuse as a separate gate: derive complete stable/action decomposition with signature intermediates and cross terms, then adversarially test holder/action mixing. If unjustified, invalidate and full-prove.
- [ ] Evaluate 0/1/2/5/10/100+ updates, new actions, abandonment, eviction/reload and shared public package population. Charge reconstruction, wasted prep and resident byte-seconds.
- [ ] Tune full/anchor/dynamic choice on one workload set and assess on a held-out set; reject negative denominator break-even claims and threshold oscillation.

**Acceptance:** exact proof/state equivalence, bounded miss behavior, documented positive and negative cost regions. Keep full proving when cache economics lose. No claim of practical improvement without pilot workload evidence; no changes to current-root policy.

## Exit and orchestration

Use GPT-6.1 Sol medium for routine implementation/instrumentation and high for proof/algebra/dependency work; always `fork_turns="none"` with self-contained task brief and explicit model override. Maximum two coding agents, non-overlapping ownership, one named heavyweight queue owner. Every experiment records hypothesis, resources, stop condition and evidence path before running. All workers return the nine-part evidence contract from the Phase 1 brief. Astra reads source and primary logs, independently reviews consequential invariants, and uses targeted separate verification for important claims.

Before finishing Phase2, confirm gates, tests, identities, boundaries and measurements agree; write aggregate reports locally, never include witnesses/cache/blinders/keys. External publication requires approval. Update handoff and rejected approaches. Phases3–5 retain DER/incremental witnesses, application integration, deployment, pilot, audit and production setup. Do not claim full implementation conformance or production readiness while their gates remain unresolved; source-reading completion is a separate achieved Phase1 result.
