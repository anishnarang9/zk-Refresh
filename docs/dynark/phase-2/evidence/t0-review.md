# T0 independent algebra and bounded scheduler review

October 10, 2026. Worker `t0_review`, parent-requested GPT-6.1 Sol/high. This is an internal read-only derivation and architecture review, not an external cryptographic audit, an executed algorithm, or a new measurement. **T4's finite-part algebra is approved for implementation subject to the tests and bounds below. T5's grouped algebra is approved; the concrete scheduler below is an independently derived candidate requiring the parent's personal review before implementation.** The existing reference coordinator is not an accepted production scheduler.

## 1. Scope and deviations

Reviewed `phase-2/{conformance,architecture,decisions,experiments}.md`, corrected `phase-1/evidence/{paper-algorithms,paper-security,crypto-code-audit}.md`, `phase-1/phase-2-plan.md`, the relevant frozen reference methods, E4's aggregate/source-stack evidence, and protected paper extraction around pp20–23. The supplied 30-page paper was fully reviewed in Phase 1; no generic reading gate was reopened. The historical availability/rank concerns in `crypto-code-audit.md:5,38,63` are superseded by `paper-security.md:79–93` and the corrected plan, rather than treated as current conclusions.

Only this report is written. No implementation, helper, test, benchmark, build, proof, setup, baseline edit, subagent, heavy queue slot, deployment, publication, or real credential access. The parent's later scoped request added only the concise public-twiddle GLV assessment in section 6. This is within the read-only scope.

Retain the accepted native desktop, controlled CA, signed fields, issuer-staleness pause, work-request queue, and execution-current-root decisions (`phase-1/phase-2-plan.md:21–23`). No circuit or product redesign is proposed.

## 2. Changed files

- Added only `docs/dynark/phase-2/evidence/t0-review.md`.
- Parent owns conformance, architecture, decisions and experiments. Recommendations here do not silently amend those contracts or open gates.

## 3. Identities and exact source mapping

| Source | Freshly inspected identity / locator |
|---|---|
| Supplied PDF | `/Users/anishnarang/Downloads/2025-1897.pdf`, SHA-256 `f851f11ed8ae8a6876dafe09373650098aa792b9f886019eea4d98060fa7b259` |
| Protected extraction | `artifacts/dynark/phase-1/paper-review/paper-layout.txt`, SHA-256 `1a3f5673805b3c70d78fc160009434bd2c5405d56aa593fe30e519bf2a0feb3f`; lines 1144–1287, pp20–23 |
| Reference | `experiments/dynark/vendor/DYNARK_` HEAD `c73a380df86d8f5d195f1e20c8a1d86a7dce084b`; observed diff remains generator/prover pre-existing patches only |
| `dynamic_cache.rs` | SHA-256 `fecd160dd22b705326db22fb9b125d8d5ed82e2765f34179feedf665fdff5823`; FullCache vectors 97–130, constructor 137–169, phases 192–355, cross 459–504, update 508–560, append/randomization/copy 636–666 |
| `fft_handler.rs` | SHA-256 `a278d4e66f2b34f37380f0537e9560fe818f9bf65a099d1f045f24928ddf3a7e`; public tables 29–114; known square-half kernels mapped by `crypto-code-audit.md:31,53` |
| Author coordinator | `ark-groth16/examples/fully_dynamic.rs:78–80,113–157`; drives work, copies raw proof, swaps, freezes, appends current delta, then updates active |
| Pinned arkworks GLV | `ark-ec-0.5.0/src/scalar_mul/glv.rs`, SHA-256 `5809156073c036613032fb992bffdfe522a3be41f15f369f474dd2815742d612`; BN254 `curves/g1.rs`, SHA-256 `d524540d74248d7fa6cfe7e141959b1b6ba04eda7c1265b32f981bed636e5e95` |

Reference source paths in this report are beneath `experiments/dynark/vendor/DYNARK_/ark-groth16/`. Artifact checksums identify bytes; they do not authenticate their producer or a setup ceremony.

### T4: finite-part kernel

Paper pp15–17 Eq(4)–(8) defines both off-diagonal orientations, N normalization, truncated H-derived L basis, and separate diagonal p. Its p16 fast algorithm is omitted. The candidate is therefore independently derived, as already labeled in `paper-algorithms.md:191–219`, rather than an author-exact implementation.

For distinct `x_i=omega^i`, normalized support union I, and `c_j=a_j*x_j`, define

`D(X)=product_j(X-x_j)` and `P_a(X)=sum_j c_j D(X)/(X-x_j)`.

Factor `D=(X-x_i)D_i` and `P_a=c_i D_i+(X-x_i)R_i`. Then `D'(x_i)=D_i(x_i)`, `D''(x_i)=2D_i'(x_i)` and `P_a'(x_i)=c_i D_i'(x_i)+R_i(x_i)`. Consequently

`[P_a'(x_i)/D'(x_i) - c_i D''(x_i)/(2D'(x_i))]/N`

`= sum_(j!=i) a_j*x_j/[N(x_i-x_j)] = sum_(j!=i) a_j*w'_(i-j)`.

This approves the formula, orientation and self-pole removal. It does **not** remove the actual diagonal group contribution. The complete cross quotient remains

`sum_i (da_i*conv(db)_i + db_i*conv(da)_i)*L_i + sum_i da_i*db_i*p_i`.

Empty and singleton unions have zero off-diagonal result; a singleton overlap still has its diagonal p term. Repeated indices must first be combined in the field and zeros removed. Distinct indices of the exact validated domain give distinct nodes; silently interpreting an out-of-range index modulo N is prohibited. N and 2 must be invertible, and every D' evaluation must be nonzero before batch inversion. Handle degenerate tiny domains explicitly instead of underflowing N-2.

Approve balanced denominator/numerator trees with leaf `(X-x_i)` / `c_i` and merge `P_left*D_right+P_right*D_left`. Differentiate D and both numerators; evaluate D', D'', P_a', P_b' with the same fast remainder tree. Non-power-of-two support lengths are valid: use an uneven balanced tree or neutral padding leaves with D=1/P=0, never duplicate domain nodes. Fast remainders require reviewed reversed-polynomial inversion/division, not a quadratic long division hidden behind a fast multiplication interface.

The field bound is `O(M(s) log s)`, hence `O(s log²s)` only with supported fast multiplication and division; straightforward retained trees have `O(s log s)` coefficients. N-point group basis work is not involved in this kernel: output group work is linear in union support. All tree construction, normalization, node generation, derivatives, inversions, conversions, allocations and group summation belong in crossover accounting.

**Required bounds:** preflight all checked polynomial lengths, padded convolution lengths, actual field-domain support, node/union cardinality, scratch bytes, and quadratic pair count. An original N-point domain does not imply that an intermediate degree-s product's s+1 coefficients or Newton-division products fit a supported transform. Root products at s=N can already need a larger convolution than N. Ask the field/domain API for each required size; reject unsupported shapes or take only a predeclared bounded fallback. Never launch an unbounded quadratic new-action calculation. A denominator tree can be reused only for the exact same support/node ordering.

**Unexecuted acceptance:** exact finite-part vectors against nested loops; complete group quotient against the frozen reference and an independently expressed polynomial quotient; empty/singleton, overlap/diagonal, disjoint, uneven, wraparound 0/N-1, dense, cancellation and random fixtures; unsupported transform/scratch/pair-budget negatives; common-r/s exact target components plus ordinary independently randomized proof verification. Tiny-case crossover may favor the oracle. No local speed or asymptotic implementation result exists yet.

### T5: grouped correction and reference distinction

Let a0,b0 belong to the active projection anchor, alpha,beta be the exact row differences to the current base witness, and da,db the current accepted transition. Quotient linearity gives

`Quo(a0*db+b0*da) + Quo((alpha+da)*db) + Quo(da*beta)`

`= Quo((a0+alpha)*db+(b0+beta)*da+da*db)`.

This contains da*db exactly once. Reference `update_from:539–555` reads complete anchor projections, appends da before reading alpha+da, reads old beta, then appends db. That local order is correct. `trivial_append` updates the rebuilding deltas only; `copy_proof_from` copies only raw proof components, not projections or accumulators. Arbitrarily replacing a semi-dynamic blinded anchor proof while retaining unrelated projections is not equivalent.

C's polynomial difference has degree below N and no quotient, but old/new satisfaction and the remainder are required. The correction's anchored/randomized signs follow p13, not the printed Protocol 2 plus-sign mistake. UK must keep Eq(6)'s 1/N and w0=0, and use truncated H-derived basis with diagonal p. `phase-2/conformance.md:17–20,34–36` is approved on these points.

The reference grouped strategy is **not direct partial-K**. Paper p22 gives `q_i(current)=q_i(anchor)+sum_j alpha_j*phi_ij` for the current requested rows. Directly materializing those entries has accumulated-by-current group cost, then permits a current-only fast cross kernel. Replacing grouped reference cross calls with a union tree costs `O(s_union log²s_union)` fields with accumulated support in s_union. A current d=1 update does not make that tree size 1. Retain this honest bound; no claim of the paper's current-only `O(d log²d)` follows.

## 4. Commands and actions

Read-only `pwd`, `rg --files`, `rg -n`, `cat`, `wc -l`, `nl -ba`/`sed -n`; root `git status --short`; reference `git rev-parse HEAD` and `git diff --stat`; `shasum -a 256` on the supplied PDF, protected extraction and four relevant source files. Read the using-superpowers entry point, which directs dispatched subagents to skip its process. No other workflow skill, runtime command, network request, PDF extraction/render or delegated work was used.

One `wc` lookup incorrectly placed `baseline-audit.md` inside `evidence/`, returned status 1, and was corrected by `rg --files` to the authoritative Phase 1 root document. Some aggregate output exceeded the tool display budget; targeted source/document ranges were read subsequently. No ignored failure is treated as a pass. `apply_patch` wrote this report only.

## 5. Outcomes, actionable issues and concrete T5 scheduler candidate

No tests were run. These are review outcomes and proposed tests.

| Priority | Issue / action |
|---|---|
| P1 before T4 integration | Enforce fast polynomial domain/scratch bounds and finite fallback pair budget; retain exact full quotient/diagonal oracles |
| P1 before T5 promotion | Replace ambiguous work steps with resumable bounded actions; fix/reject odd-log and tail cases; implement the exact generation/transaction protocol below |
| P1 before all exported dynamic proofs | Caller fallible independent r/s, no production test RNG or raw-proof success result; same package/reduction/key identity |
| P1 before imported/persisted trust | Expected manifest must come from a trusted channel; external trusted generation is required for rollback rejection |
| P2 claim boundary | Current and accumulated support costs, full validation, paid fallback/reconstruction and peak memory must all appear in comparisons |

### State representation

Keep one authoritative `Current` record: validated assignment reference, public statement, raw A/B1/B2/C, credential/action/package identity and committed generation g. Active owns **complete immutable** q_a/q_b at projection anchor ga, anchor a0/b0 and normalized alpha/beta satisfying `a(g)=a0+alpha`, `b(g)=b0+beta`.

Builder owns frozen snapshot generation gs, its immutable snapshot assignment identity and a/b inputs, separate output/scratch arrays, explicit phase/stream/index cursors, and normalized post-snapshot eta/theta satisfying `a(g)=a(gs)+eta`, `b(g)=b(gs)+theta`. Partial q is never active. Pending correction state can be coalesced maps plus a `last_applied_generation`; it need not retain an unbounded transition log. A transition must name base g and the next unique accepted target identity; reject replay, gaps, conflicting generation reuse and mismatch before arithmetic.

### Bounded reconstruction actions, including odd/even logs

Use a standard in-place radix-two Cooley–Tukey transform with explicit cursors, instead of the reference's equal square-half decomposition. For N=2^k this handles every supported k, including odd k. Each field/group stream records direction, bit-reversal cursor, stage length L, block index, j, twiddle cursor and inverse-normalization cursor. For each stage L, with `v=twiddle*buffer[base+j+L/2]` and `u=buffer[base+j]`, write u+v/u-v. Forward twiddle is `omega^(j*N/L)`; inverse uses omega^-1 and applies N^-1 exactly once afterward. Stage barriers prevent reading a half-completed prior stage.

One work unit is one documented bounded cursor action: a single field/group butterfly, one bit-reversal index visit/swap, one scalar inverse-normalization element, one prepared/integrated row tuple, or a fixed-size allocation/page-copy action. A row tuple has a fixed maximum of four group scalar multiplications during preparation; integration has two. Count four streams separately, not one unit for four parallel FFTs. Bound any page length and parallel batch explicitly; do not make one row transform of length sqrt(N) a constant-cost unit. Advancing empty phases/cursors is bounded and does not consume the budget indefinitely.

Twiddle-table creation, zeroing, freezing/copying a/b input vectors and buffer allocation must be either already-paid immutable public setup or explicit resumable phases. Avoid an uncharged O(N) clone at every reconstruction start. A frozen sparse overlay on immutable anchor a/b can be materialized into builder snapshot rows in bounded chunks; subsequent accepted deltas never alter that frozen overlay. If root exponentiation is used rather than a table, charge its bounded field work instead of hiding it inside a butterfly count.

Reconstruction follows actual persisted partial work: snapshot/materialize -> prepare `(a*L,b*L)` group streams and `(a,b)` field streams plus `(a*p,b*p)` q -> forward FFTs -> multiply by public Fourier(w) / Fourier(w_reverse) -> inverse FFTs -> integrate. Two group streams each run forward and inverse, so their butterfly count is `2*N*log2(N)`; two field streams have the same count, plus permutations, normalization and vector phases. This is an operation count, not a measured time. q must equal eager Theorem 2 after arbitrary budget partitioning. Normal update calls must not repeatedly invoke full K and call that dynamic maintenance.

`advance(0)` is an exact maintenance no-op, including cursors and generation. `advance(B>0)` consumes at most B actions and either consumes at least one, reports already complete, or returns a typed error. Tail work uses `min(remaining,bounded_chunk)`, never floor division that stalls. Ready is a terminal state; repeated polling cannot restart K accidentally. A maximum unit wall pause still requires measurement on the chosen implementation/device; bounded 256-bit arithmetic does not imply a stated millisecond deadline.

### Thresholds, carried overshoot and indivisible transitions

Let b be the configured positive cumulative **normalized assignment-distance** threshold; d is this transition's nonzero assignment support after combining its own duplicates. Let lifetime accepted distance C never decrease. Maintain a separate cycle credit t in `[0,b)` and actual accepted distance from each snapshot. Cancellations across transitions can reduce alpha/eta support but never refund C, t or completed work. Matrix row fanout is separately capped; d<=b alone does not bound row correction support.

For a builder requiring a precomputed exact finite action count W, use the cumulative quota `F(u)=floor(W*u/b)` for `0<=u<=b`. If optional background work has already advanced farther, grant only `max(0,F(u)-completed_actions)`; do not charge completed actions twice. Quota arithmetic and additions are checked for overflow. Extra background work is charged explicitly. A ready builder may wait for the logical threshold; it is never promoted while partial.

For a validated transition with `0<d<=b`, stage the target raw proof and active alpha/beta, append da/db exactly once to the builder's post-snapshot eta/theta, and sample the proof's fresh r/s before mutation. Then:

| Case | Required staged effect |
|---|---|
| t+d<b | Advance the same builder up to F(t+d); preserve its frozen snapshot; commit t+d and target generation together |
| t+d=b | Complete to W, promote complete q with its gs anchor and eta/theta **through the target**, install the target raw proof/public state, freeze a new builder at the target, and set t=0 |
| t+d>b | Complete/promote as above; let e=t+d-b; freeze the next builder at the actual target witness, grant F(e) to that next builder, and commit t=e. The update is not applied again to this new snapshot's pending maps |
| d>b, or row/pair/memory cap exceeded | Use the explicitly charged validated full/rebase route or return a typed bounded error. If full/rebase succeeds, replace both generations consistently and reset the cycle origin/t=0; retain absolute C. A full-only state with deferred preparation must be labeled as such, not ready dynamic state |
| d=0 | Fresh proof randomizers; no invented distance or implicit maintenance. Separately requested positive maintenance remains available |

At most one logical crossing occurs for t<b and d<=b. The overshoot e is **prepaid schedule credit**, not actual distance since the newly frozen target snapshot. Record these counters separately. This is an independent policy extension to Protocol 3's exact-equality case (`paper-layout.txt:1281–1286`), not a claim to copy its omitted scheduler.

This delayed-boundary policy preserves whole satisfying witnesses but does not preserve the paper's literal ideal 2b anchor-distance argument. A snapshot is frozen only at accepted witnesses; for d<=b, actual distance between adjacent snapshot freezes is below 2b. Conservatively cap correction distance from the active previous snapshot by 4b (and cap actual normalized row support separately). This constant-factor bound must be in the chosen design/complexity contract; a literal 2b claim needs a different reviewed schedule. It is acceptable to choose the explicit error/full route when that bound would exceed supported resources. Large transitions do not create fake intermediate witnesses or repeated redundant full rebuilds.

### Exactly-once promotion and transactional failure

At promotion the complete q belongs to gs, while eta/theta describes gs -> target. Install those maps as the new active alpha/beta. The target raw proof/public assignment is copied by identity, not updated again. New builder inputs describe the target itself and its pending maps start empty. An arriving transition and completion are serialized under one owner and one atomic committed root; do not allow another update to read between swaps. Retain old immutable references until the new root is committed.

Validate target satisfaction/public values, bounds/identities, kernel availability, allocation cap, required randomness and all other fallible proof obligations first. Stage raw proof/maps/cursors and builder changes under a transaction. For strict rollback, use bounded copy-on-write pages or a bounded undo representation for the touched scratch; a full naive `FullCache::clone` is not a free transaction. Page copies and dirty-page memory must be charged. If a large operation must continue in multiple chunks, keep a private pending transaction and the old committed root; expose no partial target success and serialize further proof updates until it commits or is discarded. Cancellation discards candidate work and records wasted work. Any entropy/proof/update/reconstruction error leaves the old committed generation coherent; no consumed transition ID, partial pending correction, advanced public root or half-swap escapes.

Arithmetic reversals such as +v then -v remove zero net coefficients but still count two accepted distances. User/job cancellation is distinct: cancel staged work; own revocation, issuer disable/staleness or completed action blocks use according to the external policy and invalidates relevant state. Recovery must return one complete committed generation or explicit rebuild.

**Unexecuted T5 acceptance:** exact field/group FFT and inverse at N=1 if supported, 2, 16,32,64,128,256 plus varied raw shapes; partitions 0/1/tails/oversized budgets; every positive budget progresses or completes. At least 1,000 small valid transitions, d=0/1/b/>b, t+d=b/>b, cancellations, repeats, public changes, dense/fanout cap, simultaneous completion/update, multiple swaps, and entropy/proof/cancellation failure at every phase. Compare full q, accumulated row evaluations, raw proof and target public vector to eager full calculation; ordinary independent verifier accepts every emitted target and rejects altered statements. Also check exact transition replay rejection and committed root identity after every injected failure.

## 6. Observations versus unmeasured costs

E4 is existing diagnostic evidence, not this worker's result: `phase-1/baseline-audit.md:103–124` reports anchored projections retaining 201,326,592 requested bytes (two N-element projective G1 vectors, 96 bytes each); private preparation's one instrumented call has 50,328,625,677 bytes allocation traffic, 1,467,151,506 allocation calls, 2,511,531,089 peak requested live bytes and 1,583,857,664 lifetime RSS. These metrics differ. E4 retained an original projection oracle and did not execute fully dynamic reconstruction. They cannot be substituted for a dynamic peak, steady state, or scheduler-pause measurement.

**Reference structural count:** each `FullCache` explicitly retains six N-length group vectors (q_a/q_b, fl_a/fl_b, mem_fl_a/mem_fl_b), six ordinary N-length field vectors (acc_a/acc_b, fw_a/fw_b, mem_fw_a/mem_fw_b), and two additional N-length field value arrays in the SparseRecords. Thus two cloned checkpoints retain **12N projective groups and 16N scalar fields** before their public root/index tables, SparseRecord index capacities, assignments, PK/UK, temporary updates and allocator overhead. At E4's observed representation, the group vectors alone imply 1,207,959,552 structural bytes at N=2^20; this is arithmetic from vector count, **not measured RSS**. `CustomParaFFT` adds two N root tables and bit-reversal arrays per checkpoint plus half-domain tables (`fft_handler.rs:29–114`).

**Proposed in-place representation:** active q plus builder q/FFT group streams requires 6N projective groups; active and frozen-builder a/b plus two builder field FFT streams requires 6N scalar fields, before sparse maps, public tables, assignment snapshots and transactions. This is a candidate vector budget, not a saving already implemented. Extra frozen sparse overlays, materialization cursors, imported current/anchor/snapshot assignment references must be counted by ownership/aliasing. Atomic swap can temporarily retain old active plus the next builder; copy-on-write rollback adds touched page copies, potentially all builder arrays if the transaction is broad. Set caps against this **peak**, not merely the six-vector steady representation, before any actual-circuit queue request. Sharing PK/UK does not remove private per-action state.

### Scoped T3 public-twiddle GLV hypothesis

Pinned BN254 `curves/g1.rs:43–48` routes projective multiplication to GLV. `ark-ec glv.rs:27–83` constructs BigInt/BigUint decomposition objects; its joint point multiplication is separately expressed at 90–123. Protected E4 `private-preparation-0-sample.txt:183–207` observes those decomposition/allocation paths. This supports a concrete allocation hypothesis, not attribution of the complete traffic or a speed result.

For each repeated **public** FFT twiddle k, cache the exact signed pair returned by the unchanged BN254 `GLVConfig::scalar_decomposition(k)`, then use unchanged endomorphism/sign/joint multiplication semantics on each point. Algebra requires signed `k1+lambda*k2=k` in Fr and the same endomorphism relation. Preserve exact zero-sign, limb and iterator behavior when splitting the existing method; do not fix/rewrite the scalar loop incidentally. Cache identity binds curve/config/dependency/domain/root/direction/version. Entries are public scalars, so this introduces no new secret decomposition table, but it establishes no constant-time or side-channel claim and must not expand to witness-dependent multipliers without separate review.

Bound distinct twiddles rather than caching every butterfly. A simple cache of two Fr values plus two signs per twiddle is at least 66 logical payload bytes per entry before layout/padding/index overhead; actual `size_of`/allocation and cardinality must be recorded. Forward/inverse sets and N^-1 normalization may share entries only by exact scalar identity. Include construction, cold load, retained bytes, byte-seconds and eviction in economics; no per-action duplicate immutable table. It trades allocation traffic for retained public memory and may lose for a short/cold session.

Exact oracles before timing: compare signed decomposition with unchanged Config, equality of cached and existing multiplication on identity, generator, random subgroup/projectively rescaled points, k=0/1/-1, all used public twiddles/directions/normalizers and boundary scalars; then full FFT/projection vectors and same-key raw proof/components, with independent ordinary verification. Keep one ablation at a time; do not combine this with a transform, scalar algorithm, scheduler or representation rewrite. No measured speed claim is approved.

## 7. Evidence path

This report: `docs/dynark/phase-2/evidence/t0-review.md`. Authoritative parent contracts remain `phase-2/conformance.md`, `architecture.md`, `decisions.md`, `experiments.md`. Corrected derivations: `phase-1/evidence/paper-algorithms.md:197–259` and `paper-security.md:30–120`. E3 failures remain preserved at `crypto-code-audit.md:49–55`; E4 limits are in `phase-1/baseline-audit.md:101–124` and protected stack artifacts. No new runtime evidence directory was created.

## 8. Security limits and contract approval

Approve the ordinary fixed indexed-relation scope, valid old/new assignment requirement, same CRS/key/reduction/domain, public-CRS-derived UK, fresh independent caller r/s and conditional component-equality argument (`paper-security.md:38–45`). Retain Groth's benign relation/auxiliary-input generator assumption (`:83–85`). This is not arbitrary-auxiliary-input security, a supplied formal adaptive theorem, simulation extractability, compromised-cache privacy, forward security, timing privacy, production setup or quantitative BN254 security.

Approve discriminating `w*w=x` public-C-only and equal-N=8 original/augmented fixtures (`conformance.md:44`; `paper-security.md:150–161`). Original unaugmented u_x=0 is not inherently a soundness defect. Same padded N does not authenticate or equate reduction queries. The ordinary verifier must receive the exact target public vector and the matching VK. Full assignment satisfaction validation and its matrix-wide cost remain charged; synthetic action-coordinate tests do not authorize cross-action reuse.

Approve trusted expected manifest/provenance distinction (`architecture.md:7–11`): matching checksums are insufficient for an arbitrary caller-supplied setup, witness executable or R1CS. Validation cannot prove a toxic-waste ceremony honest. Imported identities need an expected authenticated source/provenance policy, canonical decoding/subgroup checks and all dimension/index/domain checks before arithmetic.

Approve persistence's external trusted-generation boundary (`architecture.md:33–37`). AEAD protects confidentiality/integrity under its key but cannot reject a complete valid old encrypted store without trusted expected state outside it or authority revalidation/rebuild. Bind exact package/reduction/setup, holder/action, generation/commit, public statement, lengths/version and reconstruction cursor namespace. Nonces must remain unique across crash/rollback attempts, not merely increment a counter in the rollbackable file. Local invalidation and current-root/issuer freshness are independent external obligations; an internal anchor never authorizes a stale execution root.

No secret scalar, witness, private raw state, holder key or credential value is copied into this report. Security claims remain conditional on valid state and no private-state leakage. User accepted product decisions are preserved.

## 9. Next gate and prerequisites

Parent must personally review this finite-part derivation, grouped-current ordering, exact quota/overshoot policy, conservative 4b cap, rollback staging and structural memory count, then amend its contracts around the selected scheduler. **No substantive algebra blocker remains for the bounded T4 candidate. T5 implementation is not yet validated: specific dimension/progress fixes are authorized by the plan, while promotion needs the concrete policy accepted and tested.**

T4 requires T2 normalized-transition/anchor handoff, exact oracle tests, domain/scratch/fallback caps and call-site complexity accounting. T5 requires T1 randomness/package boundary, T2 identities and valid transition semantics, field/group differential progress tests, transactional sequences and peak-memory preflight. No actual-circuit dynamic trial until G2/G3 close and the parent records its sole queue owner, finite resource budget and stop conditions. Persistence, original-zkey/Solana and production qualification retain their separate gates. Optional GLV exact-reuse work is a single T3 hypothesis after ownership handoff, not a reason to postpone the core correctness gates or repeat all E4 profiling.
