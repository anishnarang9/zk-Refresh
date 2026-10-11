# T7 dependency brief: bounded direct on-demand anchor projections

October 10, 2026. Worker `t0_review`, parent-requested GPT-6.1 Sol/high. **One candidate is selected:** stream exact requested projection entries from a fixed validated anchor, retain a tiny bounded private cache, and full-prove when demand or work exceeds its limits. This is an independently derived dependency/design brief for later implementation after T2/T5 interfaces freeze. It is not an implemented selective engine, new measurement, or claim of a practical win.

## 1. Scope and deviations

Read the parent's `phase-2/performance.md:22–30`, Phase 1 T7 plan (`phase-2-plan.md:129–139`), current package/anchor/persistence contracts, corrected Theorem 2 mapping, actual projection/correction source, and protected extraction of paper pp17–18. The parent accepted T0's separate bounded dynamic scheduler; this brief does not revise it.

No subagents, source/product boundary edits, helpers, builds, proofs, tests, benchmarks, setup, new extraction/renders or heavy queue slot. No real credential/key access. The unchanged credential R1CS remains the product relation. Small public engine fixtures proposed below test mathematics only. No cross-action reuse or dynamic selective projection representation is proposed.

## 2. Changed files

- Added only `docs/dynark/phase-2/evidence/t7-dependency.md`.
- Implementation ownership remains with the later assigned Sol worker; package/anchor/dynamic boundary changes require their existing ownership transfer and parent approval. No other document is amended here.

## 3. Source identities and exact dependency argument

Reference pin remains `c73a380df86d8f5d195f1e20c8a1d86a7dce084b`; supplied PDF identity is `f851f11ed8ae8a6876dafe09373650098aa792b9f886019eea4d98060fa7b259`, previously freshly checked by this worker in T0. No new version or hash claim is inferred from a filename.

Primary formulas: DYNARK p15 Theorem 1/Eq(4)–(6), p17 Theorem 2/Eq(9), p18 encoded projection formulas and sparse projection contribution. Protected extraction `artifacts/dynark/phase-1/paper-review/paper-layout.txt:930–1007` was inspected for this task. Corrected orientation/truncation derivation is `phase-1/evidence/paper-algorithms.md:91–123`; reference `ark-groth16/src/dynark_prover.rs:37–73` computes eager projections, `:234–245` binds them to the supplied anchor, and `:304–348` consumes q_b on A-row changes and q_a on B-row changes. No deferred fast or step-K algorithm is needed for the selected direct calculation.

Let `Z=X^N-1`, `x_i=omega^i`, a be the **entire anchor A-row evaluation vector**, and `A(X)=sum_j a_j*ell_j(X)`. Theorem 2 defines

`A(X)*ell_i(X)=q_i^A(X)*Z(X)+a_i*ell_i(X)`.

Quotient linearity gives `q_i^A=sum_j a_j*phi_ij`. Using the reviewed off-diagonal identity `phi_ij=w_(j-i)*ell_i+w_(i-j)*ell_j` and separate diagonal phi_ii, the exact encoded entry is

`[q_i^A] = sum_(j!=i) (a_j*w_(i-j))*L_j`

`          + (sum_(j!=i) a_j*w_(j-i))*L_i + a_i*p_i`.

All subscripts are modulo the **validated domain** after bounds checks. `w_0=0`; nonzero w keeps Eq(6)'s N^-1. L is the truncated H-derived public basis and p the encoded diagonal. The omitted leading Lagrange coefficients cancel in each phi quotient; replacing L by an unreviewed full Lagrange commitment is not allowed. The analogous B entry replaces a by the full anchor b vector.

Thus an exact streaming calculation needs immutable public L/p/w, exact full anchor a/b and package/domain identity. One entry visits N rows, computes at most `2(N-1)` field multiplications for the two orientations, accumulates one scalar and one group, and finishes with two group scalar multiplications. Its conservative logical count is **N+1 group scalar multiplications**, plus group additions and indexing. This counts calls to scalar multiplication, not the internal curve-operation count of GLV or an elapsed-time claim. Zero anchor rows may skip a multiplication but do not remove the dense traversal or its charge. Use a bounded streaming block; do not materialize an unbounded MSM coefficient vector to hide peak memory. No FFT or eager N-entry private projection preparation occurs in this candidate.

### Which rows must actually be requested

The selected mode is an **immutable anchored** update from z0 to target z', even if the caller arrived at z' via several current transitions. Normalize the full anchor-to-target assignment delta e and calculate row differences da/db against anchor a/b. Its quotient correction is

`Quo(A0*db+B0*da+da*db)`.

Projection demand is therefore typed records

`D={(A,i): db_i!=0} union {(B,i): da_i!=0}`.

One row that needs both q_A and q_B counts as two entries. It is not sufficient to demand only the current transition's row supports: anchor-relative support can accumulate, and a small current change can require many anchor projection entries. Public/auxiliary assignment-query corrections also use the entire anchor-to-target e. All those sizes, touched matrix entries and normalization work are charged and capped independently.

`deg(dC)<N` makes C's quotient zero, but C's remainder still participates in satisfaction. Both anchor and target must satisfy the same original relation and exact public statement. A C-only public change cannot bypass validation simply because no C projection is requested. Full validation remains the initial policy; this hypothesis introduces no incremental-satisfaction assumption.

Cross quotient retains both orientations and the p overlap term. With the small demand cap below, a bounded quadratic cross oracle is sufficient for this ablation; it must not silently switch backend, relation, or T4 kernel between comparators. Selected exact q values plus the existing reviewed anchored linear/randomization/cross correction yield exactly the eager anchored target proof components under common explicit test r/s. That equality, followed by independent randomized verification, is the relevant correctness obligation.

## 4. Commands and actions

Read-only `nl -ba`/`sed -n` on the named documents, protected extraction and `dynark_prover.rs`; `rg -n` on research/baseline evidence; `git status --short -- docs/dynark/phase-2/evidence`. `apply_patch` adds this brief. Existing T0 source/PDF identities are reused with that status explicit; no build/test/runtime identity is newly created.

No command failed in this task. No experiment was run, so proposed test outcomes below are unobserved.

## 5. Chosen bounded contract, outcomes and planned tests

### One conservative evaluable candidate

Use a fixed private **four-entry LRU cache** for typed `(A/B,row)` values at one frozen anchor. Allow at most **two cold entry calculations per accepted update** and at most **eight started entry-calculation attempts per holder/action evaluation session**, including evicted/recomputed entries and canceled attempts. These are experimental hard ceilings, not tuned performance constants. The two-entry allowance permits a single A/B changed row; four retained entries permit limited repeated two-row demand. Zero-demand/no-op still emits a freshly randomized ordinary proof without projection work.

Additionally require configured ceilings for row visits, logical group scalar multiplications, field operations, full anchor-relative assignment support, touched matrix entries, cross pair count, retained/scratch/transaction bytes, per-call chunk work, and total session work. For m new entries, reserve at least m*N row visits and m*(N+1) logical group scalar multiplications; field/addition/finish work is reserved separately. Across eight attempts, dense projection work cannot exceed the corresponding eight-entry worst case. Checked arithmetic rejects overflow. A configured work ceiling may reduce the allowed entry count to zero for a large N. None of these operation ceilings asserts a millisecond deadline.

At the credential N=2^20, even one dense entry may require roughly a million scalar multiplications. Two allowed entries are not automatically an affordable desktop operation. An actual-circuit experiment needs a pre-recorded operation/resource budget from measured smaller cases. Thousands of demanded near/new-action rows fail the four-entry guard **before any direct scan**; they cannot trigger thousands of N-row calculations. Existing E4 support counts are not a selective performance result.

No hidden eager preparation is allowed: initializer captures exact frozen anchor assignment/a/b, ordinary proof/raw components and identity from the validated full/anchor interface, with its measured cost; it does not call `process_dynark`/eager K, compute all q, start T5 reconstruction or allocate N group outputs. If the boundary cannot retain the required anchor state without extra calculation, charge that calculation. Public UK derivation/load is still required and charged; the public matrices/basis/package remain shared rather than duplicated in each private cache.

### Miss, eviction, full fallback and transaction behavior

1. Fully validate/normalize the named transition and target, derive anchor-relative demand D, and preflight all required work/shape/memory/randomness boundaries. Public/auxiliary split, coordinate one and same package/action/holder checks precede group arithmetic.
2. If `|D|>4`, more than two records are missing, the eight-attempt/session work budget would be exceeded, or any inherited T2 correction cap fails, choose the validated no-cache full proof **before starting a missing entry**. Return an explicit Full result/mode and charged reason. On successful fallback, retire the lazy anchor/cache and latch FullOnly for the rest of this bounded session. Do not silently perform eager K, rebase selective state or reopen it on every later call.
3. For admissible demand, pin needed existing entries and compute misses in bounded chunks using the streamed formula. One elementary row visit performs at most one group scalar multiplication, fixed field/index work and accumulator additions. A chunk has a recorded fixed maximum number of row visits; positive chunk budgets progress or complete, and zero budget does not mutate the cursor. Long calculation may yield a private pending operation with the old committed generation still usable; no partial target proof is reported.
4. Stage completed new entries and the entire target correction/proof. Evict least-recently-used **unrequested** records only at successful commit. If all four are requested, they remain pinned and the final cache is still at most four. Old plus at most two staged entries gives a six-value peak before constant scratch/metadata. Do not mutate cache LRU/generation or consume a transition ID on entropy/proof failure.
5. Fresh independent caller r/s, exact target public values and complete ordinary output remain mandatory. Cancellation discards partial results; attempted work and consumed attempt tickets remain in the external resource/cost ledger without modifying the committed proof generation. Reverts can remove anchor-relative demand but do not refund prior computation, preparation, or residence.

The four/eight-entry counts bound this hypothesis only. Full proving has its own measured validation/proving resource limits; fallback is not a promise to finish an unsupported proof shape. If the approved full budget is unavailable, return a typed error rather than launching an unrecorded job.

Eviction saves the value's future residence but not its sunk computation. If a needed record was evicted, it is a real cold miss and spends another attempt. Authenticated cold reload may restore exact entries and anchor inputs only after package/anchor/action/generation/length validation and the external trusted-generation check. Charge AEAD, I/O, decoding, allocations, required authority validation and public-package load. A missing/invalid/old anchor requires full proof/rebuild; a MAC cannot make it fresh. Cold reload does not reset the declared session work budget in an evaluation. Absence of a trusted cross-reload resource ledger is explicitly a new evaluated session with new cold costs, not a claim to have preserved a previous eight-attempt bound.

### Exact tests and finite correctness budget, not executed

Later owner first records a small public fixture experiment, with at most 5 minutes/1 GiB, pinned source/dependencies and no credential-scale preparation. Proposed shapes N=8/16/32/64/128/256, varied assignment-vs-domain counts, public/private split and sparse/dense rows. Reduce case count rather than silently exceed the cap. No separate large setup is needed per policy variant: all modes for a fixture use the same PK/VK/UK/reduction/assignment sequence.

Required discriminating checks:

- Each selected A/B entry equals the eager Theorem 2 vector element **exactly**, including dense anchors, zero rows, row0/N-1, overlap/diagonal, uneven demand and public-C-only fixtures. An independently expressed small polynomial quotient checks orientation and remainder subtraction. Merely passing a pairing check is insufficient.
- Cross/private/public linear and complete raw target components equal eager anchored and fresh full calculation under common test r/s. Separately randomized ordinary proofs verify for exact public values and reject changed public values/invalid assignments.
- Cache key mismatch across anchor/setup/domain/reduction/action/holder/type is rejected; wrong requested-row association is detected. Canonical delta cancellation and anchor-relative accumulation are tested across valid sequences.
- Exact cache hits, one/two misses, third miss, fifth demanded typed entry, eighth/ninth attempts, LRU eviction/recomputation, zero/positive chunks, failed entropy before work, failure after a computed miss, cancellation midway, reload and malformed envelopes. Guard tests assert no eager K/FFT, no full N-group projection allocation and no dense scan on preflight fallback.
- A sequence with tiny current d but growing anchor-relative demand must trip the correct accumulated-demand cap. A no-op rerandomizes but performs no miss work. FullOnly fallback produces the same accepted target as fresh full and does not reuse retired entries later in the same session.

The later bounded session benchmark requires its own resource/stop record and begins only after these oracles pass. T5 dynamic remains a separate comparator only after its own conformance/sequence gates pass; an unavailable comparator is reported unmeasured, never simulated by repeatedly calling full.

## 6. Observations, unmeasured costs and actual session evaluation

Only source/formula/architecture observations are established here. E4's two full private q vectors retain 201,326,592 requested bytes at N=2^20 (`phase-2/performance.md:5`; `phase-1/baseline-audit.md:116`). Four projective q values would have 384 structural payload bytes in that observed 96-byte representation; six staged/committed values would have 576. Neither is a measured cache file or complete private state. Exact anchor a/b still require 2N scalar fields, an anchor assignment may require v scalar fields, and current assignment/transition/persistence scratch may coexist. Public UK/PK/indexes and load costs remain substantial. This candidate reduces projection retention, not the entire private/public footprint to a few hundred bytes.

No selective timing, allocation, cold load, gain, crossover, pilot churn distribution or dynamic sequence cost is newly measured. Existing repeated-near E2 savings are not projected onto cold direct scans, distinct-root sequences or long sessions.

### Named training and held-out workloads

**T7-TRAIN-dense-anchor-repeat:** deterministic small valid public engine relations with dense nonzero anchor A/B rows and one selected row repeatedly changed/reverted. One concrete correctness fixture is `z=(1,x,w0,...,w_(N-1))`, rows `w_j*w_j=x`, x=1, w_j in {1,-1}. Sign flips give genuine satisfying sequential assignments and dense anchors. They exercise mathematical proof generation only, not the credential product or root authorization. Training selects admission/hysteresis thresholds and chunk size under the fixed four/two/eight caps; no change to the curve/relation/backend comparators.

**T7-HOLDOUT-rotate4-cold-evict:** separate deterministic seeds, row positions not used for tuning, and valid transitions rotating through four rows with reversions; alternate one/two simultaneous affected rows, then include a three-row anchor-relative demand. Add declared cold reload points, cancellation during a miss, early action abandonment, action/holder invalidation and an abrupt dense/fanout transition. This exposes LRU misses, exhausted attempts, cumulative demand, full fallback and false predictions. Freeze this set before tuning finishes and report every loss. Toy reversions are algebra tests, not measured real revocation churn.

**T7-HOLDOUT-credential-replay:** when T2 has authenticated exact preserved credential assignments/transitions and identity-compatible same-key packages, use the unchanged near/middle/far and new-action traces as held-out inputs. Validate each full target separately; do not splice arbitrary witness coordinates into fictional valid intermediates. Near/far demands may all fall back under these caps, which is a legitimate scoped negative result. No original-zkey or execution-current-root claim follows from an engine replay. A lack of a valid 100-update credential trace is reported missing; never duplicate one measured pair and label it an actual distinct-root sequence.

### Session cost contract

For each workload, run **actual sequential sessions** at k=0,1,2,5,10,100 and one predeclared k>100 if the work/resource bound permits. Every mode uses the same key, relation, reduction, witness/public sequence, cryptographic randomness policy, backend and thread/concurrency limits. Counterbalance execution order; record raw sessions/sample counts/spread. Measure wall and total CPU directly, with a separate diagnostic allocation run if instrumentation would perturb timing. No per-session cost is derived by multiplying the E2 near median.

Let F_j be the complete actual full refresh cost; U_j the actual selected hit-path cost excluding separately accounted misses; m_j the actual miss/canceled-scan cost charged once; K_A eager anchor prep; K_D dynamic initial/reconstruction preparation. Let J be each mode's measured public-package generation/share/load, L reload/persistence, E failed/abandoned/cleanup work not already charged elsewhere, and I each mode's actual initial full proof/state capture. All modes separately charge witness generation, full validation, deltas they actually perform, proving/randomization/encoding/verification, writes, and maintenance. Common costs cancel only after equality is checked.

`T_F(k)=I_F+J_F+sum_(j=1..k) F_j+L_F+E_F`.

`T_L(k)=I_L+J_L+sum_selected(U_j+m_j)+sum_full_fallback F_j+L_L+E_L`.

`T_A(k)=I_A+J_A+K_A+sum anchored_refresh_j+L_A+E_A`.

`T_D(k)=I_D+J_D+K_D+sum dynamic_refresh_and_maintenance_j+L_D+E_D`.

Each sum is an observed ledger from that exact sequence. A canceled projection scan belongs either in m_j or E_L, never both. A full fallback after partial work includes that wasted work, but preflight fallback should avoid it. Full/eager/dynamic comparisons record identical validation scope; synthetic supplied-witness sessions have no witness-generation claim. The initial action plus k refreshes is distinguished from k total proofs.

| Session length | Required direct observation |
|---|---|
| 0 | Initial proof/state capture/public load; eager/dynamic speculative prep and abandonment; lazy computes zero q entries |
| 1 | First cold miss or immediate cap fallback, plus complete proof and real pause; no warm-only number |
| 2 | Second valid transition, actual hit/miss/cancellation demand and initial cost amortization |
| 5 | Demand growth, residence, eviction or first fallback; each accepted/failing operation counted |
| 10 | Repeated demand plus miss-attempt exhaustion/fallback where the trace causes it |
| 100 | Entire actual sequence, including latched FullOnly suffix, reload/invalidation and sunk preparation |
| >100 | Exact predeclared valid trace length and sole queue budget; report unmeasured if absent/over budget |

Record retained bytes and peak separately, and integrate `private_byte_seconds=integral live_private_bytes(t) dt` over actual monotonic elapsed time, including queued/abandoned/cold-loaded state. Separately allocate shared public byte-seconds/cost by an explicit same-population rule. Do not equate compressed files, requested heap, RSS or byte-seconds. Lazy can reduce retained q and still lose time/CPU or peak due to scans/reload; report that tradeoff without labeling it a speed win.

### Selector break-even and conservative hysteresis

For the flat illustrative case only, let `Delta=F-U_hit` and H be the **future** incremental lazy admission/public load/cold miss/reload/eviction costs versus remaining full work. If Delta<=0 and H>=0, there is no speed break-even; no division by zero or negative denominator, negative crossover count or automatic admission. For Delta>0, nonnegative H gives the non-worse integer threshold `ceil(H/Delta)` and strictly favorable integer reuse at `floor(H/Delta)+1`. Equality occurs only when k*Delta=H. If a shared/already-paid-state comparison produces H<0, use the explicit prospective ledger instead of reporting a negative crossover. H itself may grow with misses, so this constant model is not evidence for real sessions.

The actual selector uses prospective ledgers: admit only if a conservative forecast of `sum future(F_j-U_j)` exceeds H plus a positive entry margin. Known sunk preparation is excluded from a new decision's future H but remains in total session reports. Unknown remaining reuse or uncalibrated miss cost defaults to Full. Cold admission includes all missing public package/anchor/entry preparation; a warm-hit saving cannot justify pretending cold prep is free. No auto-upgrade to eager anchor/dynamic is part of this ablation; those modes are independently evaluated comparators.

Freeze two margins on TRAIN before HOLDOUT: `h_enter>h_exit>=0`. Require two consecutive eligible forecast checks above h_enter before admitting lazy at an explicitly captured validated full-proof anchor; after admission require two consecutive checks below h_exit before an economics-driven Full exit. A hard cap or explicit freshness/action invalidation overrides immediately. Entropy/identity failures reject the attempted call without committing a new mode or generation. Hold the chosen mode for at least two accepted transitions for purely economic switches; hard limits override this residence rule. On any successful full fallback/exit latch FullOnly until the session ends. This hysteresis plus the latch prevents oscillating full/lazy/full/lazy preparation inside one action session. Forecast/gather overhead and a wrong admission's sunk work belong in the session ledger. Threshold values remain unmeasured training parameters, not a preset product optimization.

Accept a negative result if exact correctness holds but cold/hit/session costs lose, misses dominate, no qualifying credential demand survives caps, public load dominates, or memory savings cost unacceptable measured pause/CPU. Then retain full by default and record the bounded selective route as unsuitable for that workload. A synthetic sparse-demand win establishes that limited engine regime only; pilot benefit requires an independently observed real workload distribution and application qualification.

## 7. Evidence path

This brief is `docs/dynark/phase-2/evidence/t7-dependency.md`. Source formula mapping is in corrected `phase-1/evidence/paper-algorithms.md:111–147`; parent's hypothesis/accounting is in `phase-2/performance.md:22–30`; T7 acceptance is `phase-1/phase-2-plan.md:129–139`. No runtime evidence directory, performance table or implementation artifact was created.

## 8. Security limits and cross-action dependency boundary

Projection linearity means `q_i(a+da)=q_i(a)+sum_j da_j*phi_ij`. It does not mean an action change leaves a unchanged, or that q/proof/key/holder state can be moved to another action. The action is in the signed authorization message and signature constraints; changing it can alter many signature/message/witness intermediates and A/B/C rows. The final proof contains bilinear A*B terms, with stable/action and action/action cross terms, private linear queries and exact public statement binding. A decomposition naming some input fields stable does not establish that their compiled witness intermediates are stable or that omitted mixed terms vanish.

Accordingly a new action/holder invalidates this lazy anchor/table and takes the validated full path. No selective reuse across actions is allowed in this candidate. Any future stable/action reuse needs its own complete compiled dependency and mixed-term derivation, holder/action mixing negatives and exact component equality; it is not inferred from Theorem 2.

Retain ordinary fixed-relation/benign auxiliary-input theorem scope, full old/new satisfaction, exact key/reduction/domain, independent fresh caller r/s, immutable sensitive anchor and typed failures. Selected q entries are witness-dependent private state; even four group values are not authorized public telemetry. Authentication/confidentiality, external trusted generation, nonce/crash requirements and issuer/current-root policy remain separate boundaries. No cache-exposure, timing privacy, forward security, original-key interoperability or production security claim is added.

## 9. Next gate, work budget and unresolved choices

The mathematical dependency is sufficiently specified for the parent to approve **one** later bounded direct-entry implementation; exact performance remains unknown and may be negative. Prerequisites: T2 exposes a validated immutable anchor without eager K, exact anchor-relative deltas and transactional proof/state result; T1 RNG/package boundary is preserved; T5 comparator semantics freeze and pass their own gates before inclusion. T6 authentication is used for any claimed cold persistence test; it is not invented by T7.

Parent/later owner must freeze the measured training margins/chunk size, concrete row/group/field/byte/session budgets, the exact validated traces and k>100 length, public cost-sharing population, sample counts, initial-anchor capture ownership, and resource-ledger behavior across interrupted/reloaded evaluations. These are recorded finite experiment choices, not unresolved algebra. No actual-circuit direct scan or benchmark is authorized by this report. The first correctness record uses the small 5-minute/1-GiB ceiling above; consequential oracle results receive parent independent review before separately budgeted session work. Full remains default until measured held-out total-session evidence justifies admission.
