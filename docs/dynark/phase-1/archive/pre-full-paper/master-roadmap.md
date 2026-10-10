# DYNARK BN254 Credential Product Implementation Roadmap

> **For agentic workers:** Use `superpowers:executing-plans` for approved work packages, or `superpowers:subagent-driven-development` if parallel agent execution is requested. Track the checkboxes below. This is a program-level research and engineering roadmap; derive a bounded implementation plan for each package after its prerequisites resolve the relevant algorithm and interface choices.

**Goal:** Deliver a complete, independently verified DYNARK implementation over BN254/Groth16 and an X.509/RSA authorization product on Solana, with measured reductions in preparation cost, private cache storage, and total authorization work under realistic registry changes.

**Architecture:** A native Rust client retains private credential computation, maintains an authenticated revocation witness, and chooses full, semi-dynamic, or fully dynamic proving according to measured cost. Circuit-wide public artifacts are shared; private credential/action state stays with the holder. Solana verifies one ordinary Groth16 proof and enforces current-root, issuer, time, policy, action, and replay rules when the protected action executes.

**Tech stack:** Existing Circom R1CS and witness artifacts; Rust/arkworks 0.5 BN254; the pinned DYNARK reference with a documented patch set; the existing Rust harness and Solana verifier; explicit adapters for snarkjs artifacts. Upgrade dependencies only through measured, separately reviewed changes.

**Date:** October 10, 2026. **Status:** Proposed roadmap, not implementation approval or new benchmark results. **Confirmed first credential target:** X.509/RSA. **Planning assumption:** Native local proving first; browser/mobile qualification follows measured memory and latency results.

---

## 1. What the project already establishes

The current evidence is in [the feasibility report](../../../results/dynark/feasibility.md), [witness census](../../../results/dynark/witness-census.md), [probe documentation](../../../experiments/dynark/proof-probe/README.md), and [baseline README](../../../README.md). These reports were inspected for this roadmap; the benchmarks were not rerun.

| Item | Observed result | Limit on interpretation |
|---|---|---|
| Combined credential circuit | 648,156 constraints; 643,563 witness values; five public signals; BN254 | Synthetic 439-byte X.509 profile, two RSA-2048 checks, depth-10 tree |
| Same-backend full proof | 2.353 s median | Includes the reference's base-cache construction; add a proof-only full comparator |
| Semi-dynamic proof update | 0.411 s median; 5.73x proof-stage speedup | Five updates from the same original cache for the same near-revocation transition |
| Witness generation | 3.054 s median, measured separately | Entire witness recomputed; no incremental witness engine |
| Derived local compute | 5.408 s full vs 3.580 s updated | Sum of stage medians, not measured complete authorization trials |
| Circuit-wide updating-key preparation | 403.46 s | Shareable for the exact circuit, setup, and representation |
| Witness-specific preparation | 551.61 s | Tied to private witness state; reuse across holders/actions is not established |
| Retained serialized cache | 64.00 MiB | Semi-dynamic cache only; does not include all live state or fully dynamic buffers |
| Updating/proving key representations | 407.79 / 130.20 MiB | Updating key includes a proving-key clone; updating-key size was estimated through serialization sizing |
| Process memory | 1.50 GiB lifetime peak RSS; 2.66 GiB macOS footprint | Different metrics; neither is a stage allocation profile |
| Existing interoperability | Ordinary arkworks verification accepts updated proofs | Separate development setup; no original-zkey or dynamic Solana integration |
| Changed witness footprint | 509 / 2,541 / 5,081 values for far/middle/near cases | Only near was proof-benchmarked |
| New action | 104,175 changed values | Witness census only; no proof-update timing |

Using the derived 1.828 s saving, preparation currently takes approximately 526 comparable refreshes to repay, or 305 if the updating key is already shared. These are arithmetic estimates, not observed user behavior. A pending action may have only zero, one, or a few retries. A long-lived credential is not automatically a long-lived reusable action cache.

The reference pin is `c73a380df86d8f5d195f1e20c8a1d86a7dce084b`. Inspection confirms quadratic cross-term loops in both `dynark_prover.rs` and `dynamic_cache.rs`, and `test_rng()` in the unused fully dynamic proof randomization path. Fully dynamic cache reconstruction also has custom FFT scheduling and multiple working buffers that need independent validation.

## 2. Scope, alternatives, and success definition

Recommended approach: implement the complete fixed-circuit DYNARK engine and put a workload-aware credential client above it. This preserves a reusable research contribution while allowing the product to select the cheapest correct proving mode.

The alternatives are useful comparisons, not the primary direction:

| Approach | Advantage | Why it is insufficient as the full project |
|---|---|---|
| Optimize only the current anchored updater | Fastest route to another measured improvement | Does not establish fully dynamic behavior, long sequences, or paper completeness |
| Complete engine plus credential-specific optimizations | Covers the requested paper implementation and product economics | Requires separate algorithm, witness, cache, and integration work; recommended |
| Redesign the credential proof around splitting/recursion first | Could reduce the dynamic footprint | Changes the statement, keys, and verifier costs before the DYNARK result is understood; retain a split design as a comparator |

“Full DYNARK” means both semi-dynamic and fully dynamic updates, their required preprocessing and reconstruction, correct public/private input updates, fresh zero-knowledge randomization, and ordinary Groth16 verification. It does not mean arbitrary circuit mutation: changed circuits, depths, credential profiles, or public-input layouts need matching keys and invalidate affected artifacts. Full paper coverage is distinct from supporting all of X.509 or proving every update faster than a full proof.

The product must succeed at three levels:

1. **Correctness:** The complete credential statement and execution policy hold for every accepted action.
2. **Efficiency:** Total paid work improves on an optimized same-backend full prover for an identified workload, accounting for preparation, cache maintenance, misses, and canceled actions.
3. **Usability:** Supported credentials, devices, issuer operations, witness delivery, recovery, and actual application execution work together.

Keep strict execution-current-root semantics throughout the primary evaluation. Internal prover cache snapshots are not historical-root acceptance or a change to revocation policy.

## 3. System boundaries and artifact lifetimes

| Component | Responsibility | Lifetime / trust |
|---|---|---|
| Circuit package | R1CS, witness executable, signal/dependency metadata, profile, public-input schema | Immutable version; public artifact hashes and verified setup provenance |
| Public proving package | Proving key, updating key, matrix indexes, supported domains and encodings | Shared per exact circuit/setup; no private witness values or toxic waste |
| Credential state | Certificate bytes, holder signing access, reusable witness data | Holder-private; expires on credential/trust/profile changes |
| Action state | Bound action, signature, witness, proof, chosen DYNARK cache | Holder-private; isolated by credential/action/policy and deleted according to retention policy |
| Dynamic engine | Full proving, anchored updates, sequential updates, reconstruction, serialization | Must not silently accept incompatible state or caller-supplied malformed deltas |
| Registry publisher | Authorized issuance/revocation transitions and root publication | Explicit trusted authority in the current model; versioned, auditable operations |
| Witness client/service | Authenticated snapshots/deltas, catch-up, reconnect, path reconstruction | Treat service responses as untrusted; verify against a chain-confirmed root |
| Submission client | Bound action submission, stale-root classification, retry, cancellation | Retries only while action remains eligible and unconsumed |
| Solana program / application | Verify proof and policy; execute protected effect atomically | Current root and current execution clock remain authoritative |

Private cache identity must cover the circuit/setup hashes, credential identity inside private storage, action digest, issuer/policy version, witness/root version, curve, and serialization format. Reject or rebuild on mismatch. Cache identity is local metadata; do not expose a stable credential identifier in transactions or telemetry.

Default to local proving. Public updating keys can be distributed through ordinary artifact hosting. Outsourcing private preparation to an operator changes who learns credential/witness data and is not a free optimization.

## 4. Work package 0 — Freeze evidence and map the paper

**Owner:** Proof engineer, with cryptographic review. **Dependencies:** None.

- [ ] Preserve baseline circuit, setup, source pins, compiler settings, raw samples, and negative cases using immutable manifests. The project currently has no root Git repository; decide version-control ownership before implementation and preserve existing artifacts.
- [ ] Acquire and pin the complete revised DYNARK paper. Build an algorithm-to-code checklist covering setup-derived artifacts, projection preprocessing, sparse correction, rerandomization, semi-dynamic updates, fully dynamic reconstruction, and security assumptions.
- [ ] Reconcile the theoretical parameters with the actual imported R1CS. Record padded domain size, assignment support, nonzero supports of A/B/C assignment changes, touched matrix entries, cancellations, and matrix sparsity. Do not equate one revoked leaf with the paper's distance parameter.
- [ ] Reproduce author-style controlled examples as conformance checks, then establish BN254 equivalents. Keep the existing real circuit as the product baseline.
- [ ] Add ordinary full Groth16 proving without unnecessary DYNARK cache work as a comparator. Preserve the current comparator too, explaining the distinction.
- [ ] Randomize full/update trial order, measure complete trials, and profile CPU, allocations, I/O, serialization, FFTs, scalar multiplication, and memory by stage. Benchmark lightweight cryptographic kernels separately from importer diagnostics.

**Acceptance:** Every advertised paper capability maps to an implementation/test or an explicit open work item; both current and optimized full baselines verify independently; reports can be reproduced without modifying old evidence.

**Source limitation for this roadmap:** The authors' IACR and publisher pages were accessible and the pinned reference code was inspected. The full ePrint PDF returned HTTP 403 in this session. The algorithm-by-algorithm full-text audit therefore remains an explicit prerequisite, rather than a claim already completed.

## 5. Work package 1 — Complete and harden the BN254 engine

**Owner:** Proof engineer. **Dependencies:** Package 0 algorithm inventory.

- [ ] Separate imports, sparse deltas, proof generation, cache state, and benchmarks into a maintainable crate while retaining the pinned reference as a differential oracle.
- [ ] Expose explicit full, semi-dynamic, and fully dynamic operations; accept cryptographically secure caller randomness on every production path. Remove production reachability of test RNGs; audit rejection and entropy-failure behavior.
- [ ] Normalize sparse updates: bounds check indices, preserve constant-one semantics, combine duplicates, remove zero/canceled entries, distinguish instance from auxiliary indices, and enforce field canonicality.
- [ ] Implement the paper's fast sparse cross-term method after the derivation audit. The existing quadratic implementation remains the small-case oracle. Validate overlap/diagonal terms, signs, domain indexing, zero deltas, and repeated indices. Use a measured crossover to choose the fast or simple algorithm for small supports.
- [ ] Implement the fully dynamic state machine with active and rebuilding caches, bounded reconstruction work, accumulated corrections, and an atomic state swap. A changed public root must follow the same statement-binding rules as full proving.
- [ ] Validate FFT domain sizing, padding, odd/even log sizes, reconstruction step budgets, and thread assumptions on non-toy matrices. Do not copy the synthetic example's equality between constraint count and domain size into the credential adapter.
- [ ] Support long update sequences, dense changes, batched changes, no-ops, and new actions. Dense cases may choose full proving; engine completeness is a correctness requirement, not a universal speed guarantee.
- [ ] Define fallible, versioned serialization for fully dynamic state. Recover after interruption at every reconstruction phase. Commit cache, root version, public statement, and proof metadata together; never combine half-written generations.
- [ ] Test stale snapshots, corruption, cross-circuit cache substitution, mismatched credentials/actions, repeated updates, and restore/restart behavior.

**Acceptance:** For randomized small circuits and real credential sequences, each updated proof verifies through unmodified ordinary arkworks; sampled states agree with full reproving. Run at least 1,000 sequential transitions in a scalable test registry and multiple complete reconstruction/swap cycles. Preserve valid authorization and own-revocation rejection across restarts. Report worst observed reconstruction pauses, not just average update time.

## 6. Work package 2 — Reduce public and private preparation costs

**Owner:** Proof/performance engineer. **Dependencies:** Profiling from 0; reference correctness from 1. Safe representation experiments can begin earlier.

Preparation has three different budgets: public circuit/setup preparation, private credential/action preparation, and ongoing maintenance. Optimize and report each separately.

| Experiment | Concrete change / hypothesis | Required measurement and stopping rule |
|---|---|---|
| Share immutable public state | Remove proving-key duplication; share matrix indexes and FFT metadata; load one public package per process | Live and serialized bytes, cold load, concurrent users; keep only if total memory improves without harmful load latency |
| Allocation and representation | Reuse scratch buffers, reduce clones, batch normalization, compare affine/projective retention and validated memory mapping | Wall time, allocations, RSS, peak footprint, decompression; compressed storage alone is not a RAM result |
| FFT and group operations | Optimize the measured projection/update hotspots; compare batch inversion, MSM, data layout, thread counts, and scratch reuse | Correctness against reference and complete preparation/update timing on ARM64 and x86-64 |
| Selective projections | Materialize only projections needed by a proven allowed update support, with explicit miss handling | Build time, cache bytes, first miss, warm hits, miss rate, dense fallback; a single requested projection can still depend on the whole original witness |
| Lazy preparation | Create entries only when demanded; bound work and retain an eviction policy | Total cost over sessions with 0/1/2/5/10/100 updates, including canceled sessions and misses |
| Stable credential contribution | Investigate exact reuse of linear projection contributions across actions while retaining all required cross terms | Algebraic equivalence plus adversarial cross-action tests; do not count reuse as achieved before proof and measurements |
| Adaptive rebuilding | Select anchored updates, fully dynamic updates, or rebase/full proof from current support, cache coverage, queue, and memory | Total time/CPU for real sequences; bound tail stalls and avoid oscillation |
| Acceleration | Evaluate GPU or other acceleration only after profiling identifies sufficiently large kernels | Transfers, startup, energy, hardware availability, and full-path gains; CPU fallback remains supported |

Background preparation can improve responsiveness, but report its CPU, memory, energy, and unfinished/canceled work. Do not remove it from cost accounting.

For K private states sharing one public package, a preliminary break-even calculation is:

`N_break_even = ceil((P_private + P_public / K + extra_load_cost) / (T_full - T_dynamic - maintenance_per_update))`

Use consistent units, incrementally charged costs, and only a positive denominator. Real traces replace this constant-cost approximation when costs grow with support or reconstruction. Count memory residency separately in byte-seconds and capacity per device/worker. Private setup cannot be divided across K users unless it is actually shared safely.

**Acceptance:** Publish a Pareto frontier of preparation time, retained/live memory, warm and cold refresh time, and session total cost. Identify where each cache mode pays back. Select a default that wins for the pilot workload, not for an assumed 300 retries of a single action. Retain full proving when no private cache mode pays back.

## 7. Work package 3 — Incremental witness generation

**Owner:** Circuit/witness engineer. **Dependencies:** Frozen circuit metadata from 0; delta interface from 1.

The existing three-second witness calculation remains on every retry and can dominate after proof updates are optimized.

- [ ] Build a dependency map from the compiled witness computation and compiler metadata. R1CS constraints and symbol names alone do not necessarily provide an executable witness schedule; compiler optimization aliases must be handled explicitly.
- [ ] For the unchanged initial circuit, first implement a narrowly scoped refresh evaluator for changed Merkle siblings, affected Poseidon nodes, root, and every affected compiled intermediate. Reuse certificate hashing, issuer verification, and holder-signature computation only when their dependencies are unchanged.
- [ ] Produce sparse witness/public deltas directly rather than recomputing two complete witnesses and scanning them. Preserve canonical wire ordering and alias mapping.
- [ ] Maintain A/B/C row-evaluation changes from column adjacency; count true nonzero changes after cancellation. Establish that every affected constraint is included before replacing full validation with incremental validation in the production path.
- [ ] Keep full witness generation as the correctness oracle and recovery path. Differentially compare every field element over randomized paths, slot positions, certificate inputs, mixed batches, and sequence histories; check full R1CS satisfaction in CI/research runs.
- [ ] Add invalidation for changed certificate bytes, holder signature/action, issuer, policy, circuit, expired credential, and revoked holder. Add new-action incremental evaluation only after its larger dependency graph is measured.
- [ ] Test long chains of updates, catch-up from missed versions, repeated touches of one subtree, and updates while a refresh is running.

**Acceptance:** Exact equality with the full witness for accepted cases, exact policy failure for rejected cases, verified final proofs, and measured complete refresh latency. A useful research target is at least a 10x reduction in same-action witness refresh time on the baseline host; this is a target, not a predicted result.

## 8. Work package 4 — Real X.509/RSA credentials and circuit optimization

**Owner:** Credential/circuit engineer with security review. **Dependencies:** Starts with 0; optimized versions feed back into 1–3.

- [ ] Select one concrete pilot use case: an organization-issued RSA client credential authorizing a protected application action. Establish what possession and organization eligibility mean, how the holder can sign, and which issuer/trust anchor is accepted. A public website certificate without holder signing access is not a complete authorization fixture.
- [ ] Assemble a consented corpus with real encodings and owned signing keys, plus publicly shareable synthetic equivalents. Inventory TBS lengths, issuer/subject structures, extensions, certificate chains, signature schemes, exponents, and key sizes before defining the supported profile.
- [ ] Replace fixed byte positions with sound bounded DER parsing and extraction. Constrain lengths, tags, offsets, padding, relevant algorithm identifiers, signed attributes, subject public key, signature bytes, and rejection of malformed/ambiguous encodings. Values asserted by a local parser must be proved from signed bytes or explicitly covered by a declared trusted authority.
- [ ] Retain RSA-2048/65537 and PKCS#1 v1.5/SHA-256 as the initial allowed suite when the corpus permits. Measure and separately version RSA-3072/4096 or RSA-PSS support if needed. Unsupported credentials get explicit errors.
- [ ] Specify trust-path scope. Start with accepted issuing CA keys for a controlled enterprise profile if appropriate; independently verified chain enrollment can be an explicit trust boundary. Broad PKIX support requires enforced chain signatures, CA/basic constraints, path length, critical-extension behavior, key usage/EKU, name/policy constraints where relevant, validity, and trust-anchor management. Do not label a host-side parser check as a proved chain.
- [ ] Add GeneralizedTime and boundary-date handling for supported certificates; tie eligibility predicates to authenticated fields. Define issuer/intermediate revocation and rotation in addition to individual holder revocation.
- [ ] Map issuer revocation sources into the registry and document detection/publication delay. If CRL/OCSP adapters are used, authenticate and validate them, define stale-feed behavior, and record the last effective update. Onchain current-root enforcement begins after an authorized revocation is published; it does not eliminate the preceding delay.
- [ ] Preserve holder action authorization with correct signature padding, message/domain encoding, and key binding. Provide local signer adapters so keys need not be uploaded or unnecessarily exported.
- [ ] Profile constraint count, domain rounding, memory, full proof time, incremental support, and preparation after each circuit optimization. Compare appropriate SHA/RSA gadget improvements, fixed public exponents, reuse of existing intermediate computations, profile size buckets, and tree depth. Do not weaken signature or parsing checks for a benchmark.
- [ ] Review privacy of public issuer and exact certificate dates, action/recipient, update timing, and witness delivery. If stronger anonymity needs private dates plus proved validity bounds, specify and measure the resulting circuit/public-input changes explicitly.

**Acceptance:** Supported real credentials authorize valid actions; invalid signatures, malformed certificates, wrong organization/usage, untrusted issuers, expiry, and relevant revocations fail. Document the exact supported profile and trust model. Rebuild and rebenchmark keys after circuit changes; freeze the release circuit before production ceremony work.

## 9. Work package 5 — Registry, witness delivery, and client lifecycle

**Owner:** Systems engineer. **Dependencies:** Statement/profile from 4; can prototype with the existing circuit.

- [ ] Replace full-tree rebuilding on every revocation with incremental path updates and a persistent authenticated registry store. Define issuance, revocation, renewal, slot reuse, and migration semantics; protect against an old credential inheriting a recycled active slot.
- [ ] Evaluate depth 10, 16, 20, and 24 as capacity/workload points. Depth increases require compatible circuit packages. Separate registry population from update frequency.
- [ ] Publish versioned authenticated root changes and enough data for local path updates. Support snapshot bootstrap, deltas, bounded retention, gap detection, and catch-up after outages. Verify final reconstructed paths against chain state.
- [ ] Measure public broadcasts/full-download baselines versus per-slot queries. A public update feed can hide which path a user requests but still expose certificate/slot associations through its contents; record that leakage. Treat stronger private retrieval as a separately evaluated product feature.
- [ ] Implement a client state machine for credential import, action creation, initial proof, stale-root retry, cancellation, expiry, revocation, accepted receipt, and cleanup. Root changes arriving during preparation must be reconciled before proof submission.
- [ ] Coalesce redundant client refresh work to the newest authenticated state without delaying the authority's publication of revocations. Add bounded retries, deadlines, cancellation, resource budgets, and informative failures under sustained churn.
- [ ] Handle RPC rate limits, reconnect, stale endpoints, skipped versions, transaction expiry, duplicate submissions, and ambiguous confirmation. Resolve action receipt state before replaying an action with uncertain execution status.
- [ ] Bound worker concurrency and total cache memory. Separate public shared memory from per-holder private memory. Keep credential slots, witnesses, keys, and detailed dependency fingerprints out of ordinary telemetry.

**Acceptance:** Restart/reconnect and missed-update tests recover correctly; forged data never creates accepted authorization; long-running sessions have bounded memory; revoked and canceled actions stop; action effects occur once. Report feed bandwidth and propagation delays with proving results.

## 10. Work package 6 — Keys, Solana interoperability, and actual application execution

**Owner:** Solana/proof integration engineer. **Dependencies:** Begin compatibility checks early; final release depends on the frozen circuit from 4.

- [ ] Test the existing development proof against the Solana verifier with its matching exported verification key in an isolated local program. This exposes encoding and integration errors before building the entire product.
- [ ] Implement a canonical BN254 adapter: field bounds, curve/subgroup checks as appropriate, exact endianness, Fq2 component ordering, A negation expected by the existing verifier, and public-input order. The current Solana proof payload is 256 bytes; the 128-byte compressed arkworks artifact is a different encoding.
- [ ] Implement and test existing `.zkey` interoperability as a separate capability. Reconcile QAP reduction, public-input augmentation, padded domain, H-query basis/scaling, and group generators. Importing the same R1CS alone does not establish key compatibility. Derive updating artifacts from public proving/setup data without toxic waste.
- [ ] Cross-check ordinary arkworks, snarkjs, and the Solana verifier using shared compatible artifacts. Do not require randomized full and refreshed proofs to be byte-identical; require the same statement/key acceptance and correct rejection.
- [ ] Use deliberate versioned verification-key deployments for changed credential circuits; preserve the baseline program and evidence. Define key/circuit/policy rotation, issuer migration, old-version disablement, and private cache invalidation.
- [ ] Enforce chain/program/registry/policy/action/recipient binding, current-root equality, allowed issuer, execution-time validity, and replay rules in the actual protected instruction. Eliminate ambiguity about network/domain separation.
- [ ] Replace a receipt-only demo with one concrete protected application effect in the same transaction, such as a permissioned instruction. Bind the exact effect and account parameters; test CPI/account substitution and failed-effect rollback.
- [ ] Exercise unrelated revocation before/after proof generation and before execution, own revocation at each boundary, altered root/action, expiry during retries, unauthorized root publication, and duplicate submissions. A failed attempt must not consume the action; a successful one must.
- [ ] Measure proof verification and whole-transaction CU, bytes, fees, inclusion/confirmation delay, and registry-account contention. Prover speed does not automatically reduce onchain compute.

**Acceptance:** Updated BN254 proofs execute valid actions locally and on devnet with transaction/receipt evidence; stale or revoked statements cannot execute. Existing-key compatibility is claimed only after its own tests pass. Release deployments are tied to source/build/key hashes.

## 11. Work package 7 — Evaluation and adaptive mode selection

**Owner:** Performance/research lead. **Dependencies:** Baselines begin in 0; full evaluation integrates 1–6.

| Dimension | Minimum study scope |
|---|---|
| Proving modes | Optimized ordinary Rust full prover; original snarkjs baseline for migration context; current reference semi-dynamic; optimized semi-dynamic; fully dynamic; adaptive policy |
| Architectural comparison | A sound split-proof baseline with credential/action binding, both verification costs, and transaction overhead; historical policy shown separately with its changed revocation semantics |
| Credentials | Original fixture, representative real supported profiles, certificate size/chain variants; no inflated circuit to manufacture a win |
| Changes | Near/middle/far, random slots, batches, repeated subtrees, own revocation, new action, issuer/policy changes, offline catch-up |
| Cache lifetime | 0/1/2/5/10/100+ refreshes, cancel/abandon, cold start, warm start, eviction/reload, multiple actions and credentials |
| Scale | Population/depth, observed pilot update rates, bursty and adversarial churn, submission delays, concurrent authorizations |
| Platforms | Existing M3 Pro; Linux x86-64 target; a constrained target device before browser/mobile support claims |
| Resource limits | Fixed threads/cores, CPU contention, memory caps, public-package cold download, network/RPC delays |

Use pilot measurements for primary claims and label synthetic stress sweeps. Authorization request rate is not registry root-update rate. Include issuance and any other operation that actually changes the root.

Record per trial: artifact/source hashes, hardware/build flags, RNG policy, thread count, warm/cold state, root history, true delta supports, all stage timestamps, memory, bandwidth, CPU, cache hits/misses, reconstruction, outcome, retries, and transaction data. Publish scrubbed raw samples and commands.

Measure complete elapsed trials directly:

`T_retry = T_path_acquisition + T_witness_refresh + T_delta + T_proof_update + T_synchronous_maintenance + T_encoding + T_submission_and_confirmation`

Also report first-use latency, successful-action latency including all failed attempts, total CPU including background work, preparation wasted on abandoned actions, byte-seconds retained, throughput, success-before-deadline, and tail stalls. Overlapped stages require actual wall time rather than a sum of medians.

For intuition only, under independent Poisson root updates with rate lambda and a fixed vulnerable interval T, the probability of no update is `exp(-lambda*T)`. Actual traces must include retries, correlations, queued work, and network time; shorter proving cannot eliminate races or guarantee progress under unbounded churn.

Use multiple independent sessions and at least 30 trials for ordinary stage comparisons; use hundreds/thousands of workload events for tail analysis, report confidence intervals, and do not infer p99 from five runs. Sweep a manageable matrix with focused ablations rather than an uncontrolled full Cartesian product.

**Proposed engineering targets, to ratify against pilot needs:**

- Same-action local refresh, including witness/delta/update and required maintenance: p95 below one second on the baseline class of machine, measured after public package availability and with private-cache preparation reported separately.
- At least 3x warm local-refresh improvement versus the optimized full pipeline for the designated retry workload, plus positive total session savings over its actual lifetime.
- Private preparation pays back within the observed expected reuse count; for a short-lived action workload, explicitly test whether 1–5 retries suffice. A 300-update requirement fails that product case even if a different long-lived workload succeeds.
- Explore a 16 MiB retained private-cache target and sub-512 MiB total live-client target as stretch goals. They are not paper guarantees or claims about the unmeasured fully dynamic state. Benchmark on the target device before adopting hard device limits.
- Equal authorization guarantees and no unexplained loss of supported credential correctness. Publish workloads where full proving wins.

**Acceptance:** Results separate backend improvements from DYNARK improvements, cover cold and warm sessions, and demonstrate the chosen policy's net benefit. Train/tune mode thresholds on one workload set and test them on another. If a target fails, keep the complete engine result and identify the exact workload or resource limit that prevents a product claim.

## 12. Work package 8 — Security review and production release

**Owner:** Security reviewer plus engineering owners. **Dependencies:** Threat modeling begins in 0; final audit follows circuit and interface freeze.

- [ ] Review the DYNARK security assumptions, BN254 security margin, adaptive update use, rerandomization, malformed deltas, cache-state sensitivity, and timing/access-pattern leakage. Proof verification alone does not establish zero knowledge or safe cache handling.
- [ ] Audit DER parsing, RSA checks, witness completeness, issuer/policy trust, public-input binding, replay handling, and execution-order semantics. Fuzz importers, certificate parsers, cache deserializers, and transaction decoders with bounded allocation.
- [ ] Document cache disclosure consequences. Encrypt persisted private state with an OS-protected key where persistent storage is needed; restrict access, authenticate state, handle version rollback, clear state on revocation/logout according to policy, and avoid secret-bearing crash reports. Do not promise perfect secure deletion on ordinary storage.
- [ ] Run a verified production setup for the frozen circuit. Verify the complete phase-one transcript and use an appropriate multi-contributor circuit-specific phase two with published verification artifacts. Existing single-contributor development setup remains a development artifact.
- [ ] Separate setup, issuance, root publication, deployment, and upgrade authority. Establish signer protection, rotation, recovery, compromise response, and an emergency pause policy with explicit availability consequences.
- [ ] Complete dependency/license review of reference and circuit libraries, pinned reproducible builds, CI conformance/fuzz/regression checks, resource-limit tests, and an external cryptographic/application audit. Resolve critical/high findings before production release.
- [ ] Package a documented local SDK/CLI and one working application integration: supported credential errors, action lifecycle, cancellation, cache controls, progress, and recovery. Add browser/mobile bindings only after platform qualification.
- [ ] Run a private pilot with consenting holders and an issuer operator. Collect privacy-preserving service/error metrics, validate deployment hashes, test rollback/version migration, and publish a supported-profile/security-limit document.

**Acceptance:** Security findings are resolved or explicitly accepted by the appropriate owner, setup and release provenance verify, the pilot satisfies its latency/resource budget, and documented recovery/rotation procedures have been exercised. Mainnet readiness is a separate decision from a devnet demo or positive benchmark.

## 13. Proposed code organization

Preserve the current experiment and baseline. Introduce product modules incrementally after their interfaces are approved; these are proposed paths, not files created by this roadmap.

| Existing starting point | Proposed product boundary | Responsibility |
|---|---|---|
| `experiments/dynark/proof-probe/src/lib.rs` | `crates/dynark-bn254/src/{import,delta,engine,cache,encoding}.rs` | Validated artifacts, sparse changes, proving modes, state lifecycle, serialization |
| `experiments/dynark/vendor/DYNARK_/ark-groth16/src/` | Pinned fork plus documented patches | Core paper algorithms, efficient cross terms, reconstruction, cryptographic RNG |
| `experiments/dynark/witness-probe/` and compiled witness artifacts | `crates/credential-witness/src/{dependencies,refresh,validate}.rs` | Exact compiled witness reuse and differential checks |
| `harness/src/fixtures.rs`, `circuits/credential.circom`, `circuits/profile.json` | `crates/credential-profile/` and versioned `circuits/profiles/` | Real supported DER/RSA profiles, corpus, policy-to-signed-field binding |
| `harness/src/registry.rs` | `crates/registry-client/` and `services/registry/` | Persistent incremental tree, publisher, authenticated updates, catch-up |
| `harness/src/prover.rs`, `harness/src/policy.rs` | `crates/credential-client/` | Action lifecycle, mode selection, resource budgets, local signing/cache |
| `harness/src/setup.rs`, `harness/src/solana.rs` | Small adapters in existing harness first | Key import/export, Solana proof encoding, transaction evidence |
| `program/src/lib.rs`, `program/src/generated_vk.rs` | Versioned verifier/application integration | Execution policy, current keys, atomic protected action |
| Existing `results/dynark/` | `benchmarks/` and new versioned reports | Workload replay, ablations, raw sample schema, reproducibility |

Do not simultaneously reorganize the entire harness. Start with isolated modules and migrate only what each accepted package needs. Define binary/schema versions before caches become persistent.

## 14. Sequence, effort, and decision gates

1. **Evidence and conformance gate:** Complete 0; begin credential corpus/profile and early Solana adapter work. Exit with trustworthy baselines and the full paper inventory.
2. **Complete engine gate:** Implement 1, including secure randomness and sequence/reconstruction correctness. Begin 2 profiling-driven changes and 3 witness refresh in parallel when interfaces stabilize.
3. **Economic gate:** Finish the first 2/3 ablations. Demonstrate preparation/retention/latency tradeoffs over short and long sessions. Choose default modes without disabling engine capabilities.
4. **Real credential gate:** Complete the selected profile in 4, re-run engine/witness tests for the new circuit, and freeze the intended release statement.
5. **Integrated beta gate:** Complete 5/6 and full evaluation from 7. Demonstrate a real supported credential executing an application action while unrelated revocations cause successful bounded refresh/retry.
6. **Release gate:** Complete 8, external review, verified setup, pilot, and operational acceptance.

Budget approximately **20–32 focused engineering person-weeks for an integrated research beta**, assuming two engineers covering proofs/performance and credentials/systems, with cryptographic review available. Dependencies and research uncertainty make **roughly 12–20 elapsed weeks** a planning range for that team, not a delivery promise. A solo effort takes longer; broad PKIX, constrained-device support, and difficult key interoperability can extend the range. External audit, setup coordination, and production pilot are additional release work and require separate scheduling. Re-estimate after the first two weeks of profiling and paper conformance.

The first two weeks should produce the complete paper/code coverage matrix, a corrected full baseline, stage allocation profiles, secure fully dynamic BN254 smoke/sequence tests, the real credential corpus inventory, and an independently verified incremental-witness prototype for the unchanged circuit. These are the earliest inputs needed to make later implementation estimates credible.

## 15. Risks and response rules

| Risk | Response |
|---|---|
| Private preprocessing still needs hundreds of retries | Evaluate selective/lazy/stable-contribution reuse; default to full proving for uneconomic sessions; do not hide costs off the foreground path |
| Fully dynamic buffers or reconstruction exceed device limits | Bound memory and queueing; compare anchored/rebase mode; retain fully dynamic capability for suitable hosts |
| New-action footprint remains large | Treat first/new-action latency separately; benchmark full proof/rebase; only claim cross-action reuse after exact equivalence and cost evidence |
| Real DER/chain support expands constraints/domain dramatically | Use explicit supported profiles and measured size buckets; preserve cryptographic/semantic checks |
| Root churn exceeds completion capacity | Bound retries and expose failure/deadline behavior; do not silently accept stale roots |
| Root publisher delays or omits revocation | Monitor feed age and publication delay; define fail-closed/pause behavior and authority recovery; document the trust boundary |
| Old zkey cannot be mapped directly | Resolve the reduction mismatch; use an explicit matching-key development deployment in the meantime; withhold existing-key compatibility claims |
| Optimization changes algebra or privacy behavior | Differential tests, independent verifier, derivation review, and external audit before promotion |
| Speedup disappears against optimized full prover | Publish the negative region; assess net workload savings and avoid conflating a Rust backend migration with DYNARK |

## 16. Final deliverables

- [ ] Complete BN254 DYNARK engine with both update modes, independent verification, documented paper coverage, and reproducible conformance tests.
- [ ] Validated incremental witness generator and measured cache/preparation strategies, including explicit non-winning cases.
- [ ] Supported real X.509/RSA credential profile, signer interface, trust/revocation policy, and positive/adversarial corpus.
- [ ] Registry publisher, authenticated witness delivery/catch-up, and resilient local client with cost-aware proving selection.
- [ ] Ordinary Groth16 key/encoding interoperability evidence and a Solana integration executing an actual protected action.
- [ ] Full benchmark suite and research report with raw scrubbed evidence, ablations, uncertainty, resource budgets, and fair baselines.
- [ ] Verified release setup, security review/audit outcomes, SDK documentation, operational runbooks, and pilot acceptance evidence.

## 17. Sources

- [DYNARK authors' IACR entry](https://eprint.iacr.org/2025/1897): revised May 11, 2026; semi/fully dynamic definitions and stated Groth16 compatibility.
- [EUROCRYPT 2026 publisher entry](https://link.springer.com/chapter/10.1007/978-3-032-25336-1_7): published statement and complexity claims. Full text still needs the package-0 audit.
- [Authors' reference implementation](https://github.com/OYJason08/DYNARK_): project uses the pinned local copy noted above; relevant code was inspected directly.
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) and its applicable updates: certificate, extension, trust-path, and revocation semantics to map into the supported profile.
- [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017): RSA signature encodings and verification requirements.
- [groth16-solana](https://github.com/Lightprotocol/groth16-solana): ordinary BN254/Solana verification adapter reference; actual project costs must be measured.
- Local sources: `README.md`, `HANDOFF.md`, `results/dynark/feasibility.{md,json}`, `results/dynark/witness-census.md`, probe source/documentation, `circuits/credential.circom`, `harness/src/{registry,setup,solana}.rs`, and `program/src/lib.rs`.
