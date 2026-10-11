# T5 concrete state layout and failure-atomic reconstruction brief

October 10, 2026. Worker `t0_review`, parent-requested GPT-6.1 Sol/high. Read-only design; no implementation or runtime claim. Parent approved the existing T0 scheduler and, during this review, approved deferring the diagonal term to final integration to save two builder group vectors. This brief specifies that representation and a bounded first-touch undo journal. The parent must personally review it before T5 dispatch.

## 1. Scope and deviations

Read the accepted T1 public boundary at commit `9dc0547`, current `phase-2/{architecture,conformance}.md`, and T0's approved equations/scheduler/memory record. T2's immutable anchor/`ArcUpdatingMaterial` is being implemented by `t2_anchor`; no T2 source or boundary is edited or assumed to be finished. Public FFT(w) and FFT(w_reverse) are shared exact-package material, not duplicated per state.

No code, helper, build, proof, test, benchmark, setup, delegation, heavy slot or credential access. Only this document is written. The algorithm remains the approved radix-two reconstruction and grouped correction; only buffer ownership, diagonal placement and transaction representation are made concrete.

## 2. Changed files

- Added only `docs/dynark/phase-2/evidence/t5-state-layout.md`.
- Parent retains other documents; T1/T2/T3 retain their source ownership. This report does not promote runtime gates or authorize a credential-scale run.

## 3. Identities, source contract and algebra

| Source | Inspected contract |
|---|---|
| T1 commit `9dc0547` | `src/artifact.rs`: immutable Arc package, distinct validated shape, matching reduction/key/domain, opaque fully validated assignment; `src/lib.rs`: no unsafe code or vendor cache/RNG re-exports |
| T1 `src/full.rs:18–47` at that commit | Assignment/package checked; independent fallible r/s sampled before arithmetic; full coordinate-one assignment preserved; complete ordinary result only |
| T1 `src/randomness.rs:9–31` | Canonical rejection sampling, fallible caller bytes, independent draws, bounded rejection error |
| `phase-2/architecture.md:25–37` | Complete active projections, frozen builder, exactly-once pending corrections, atomic swaps, bounded state and external persistence trust |
| `phase-2/conformance.md:34–50` | Grouped identity, in-place odd/even-log FFT, quota F(u), whole-witness overshoot, conservative 4b cap and charged rollback |
| T0 `evidence/t0-review.md:94–146` | State invariants, FFT cursor and quota derivation, failure boundary, structural memory estimate |
| Primary paper | Supplied pinned DYNARK pp15–18 Eq(4)–(9)/Theorem 2 and pp20–23 block-offset/Protocol 3, mapped in corrected Phase 1 algorithm report |

T1 alone does **not** expose B1, retained blinders, raw proof or cached rows. A dynamic initializer must consume/adopt T2's matching validated internal anchor state or perform an explicitly charged internal initialization. It cannot infer private raw B1 or secure blinders from the public T1 `ProofStatement`. Statelesly full-proving a target does not automatically make it DynamicReady.

For a frozen snapshot a,b, public encoded L/p, and circular-convolution kernels w,w_reverse, Theorem 2 requires

`q_a = IFFT(FFT(a*L)*FFT(w)) + IFFT(FFT(a)*FFT(w_reverse))*L + a*p`.

The B formula is identical. These group/scalar products use the same domain ordering, truncation, N^-1 normalization and w0=0 reviewed in T0. C has no degree-N quotient contribution but full old/new satisfaction remains mandatory.

**Defer a*p and b*p until integration.** The inverse-transformed group arrays already hold the first convolution; add the field convolution times L and the frozen row times p in place. The two resulting arrays become complete q_a/q_b. This preserves exact algebra and total group multiplication count while moving two group multiplications per joint row from preparation to integration. No extra q buffers or affine conversion are required. A prepared row uses two group scalar multiplications; an integrated A/B row uses four. The implementation's unit bound must reflect this placement.

## 4. Commands and actions

Read-only `git show --stat 9dc0547`, `git show 9dc0547:<accepted source paths>`, `nl -ba`/`sed -n` on current contracts/T0, `rg --files` for source inventory, and targeted `git status --short`. `apply_patch` writes this document only. No commands failed; some combined displayed output was truncated and relevant contract/randomness ranges were read separately. No runtime command was executed.

## 5. Concrete pool, phase counts and transaction strategy

### Owned pool and initial state

Use stable **physical buffer slot IDs**, independent of logical active/builder roles. One serial state owner owns four N-length projective G1 buffers and six N-length Fr buffers:

| Role | Group vectors | Scalar vectors |
|---|---:|---:|
| Active complete anchor | q_a,q_b: 2 | frozen a,b: 2 |
| Builder | convolution/output g_a,g_b: 2 | frozen snapshot a_s,b_s: 2; FFT work f_a,f_b: 2 |
| Total core pool | **4N** | **6N** |

Active q and rows are logically immutable outside the owner transaction. Builder buffers are private; their partial contents are never available as active projections. Raw current proof/public statement/assignment/generation is one authoritative small record, separate from builder scratch.

The dynamic pool must have exclusive mutable ownership of its recyclable buffers. Prefer adopting a consumed uniquely owned T2 anchor; if external immutable T2 anchor references remain, they cannot be overwritten. An initial copy into private engine-owned buffers is permitted **once**, with its N-scale copy/peak charged. Sharing the public package/updating material through Arc does not authorize mutating an immutable holder anchor. Do not add a full dense clone on every update to preserve external aliases.

Initial state may tag its builder as `InitialReadyAlias` for the already-complete starting projections. This is not a newly completed reconstruction or a distinct snapshot evidence point. Reserve/initialize the two group/four scalar workspace arrays and journal bookkeeping under an explicit bounded initialization policy. While those are incomplete, expose PendingPreparation or the ordinary validated full route; do not claim complete dynamic maintenance capacity. Initializing workspace is paid even if the action is abandoned.

Because T1 forbids unsafe code, use safe bounded initialized storage: reserve fallibly, then append zeros in bounded initialization chunks until physical lengths reach N. Zeroing the initial two group/four scalar workspace arrays costs **6N element actions**. The ten-cell-space mark bitmap also needs `ceil(10N/64)` word-zero actions once (163,840 at N=2^20). Initial adoption/copy of active arrays is accounted separately. At every later snapshot, retain the initialized pool and overwrite rows in bounded phases; do not zero or clone all arrays again. A `valid_prefix`/phase cursor prevents reading stale initialized workspace values as snapshot/FFT data.

A frozen builder input contains its snapshot generation, immutable assignment identity/reference, source active-row slot IDs, and immutable normalized A/B overlay maps through that exact snapshot. Subsequent transitions create new staged map values; they never mutate a frozen overlay. If existing T2 maps are not shareable immutable objects, the bounded support copy required to freeze them must be preflighted, charged and completed before mutation. A header/Arc clone is not a hidden N-row copy.

### Exact ordinary reconstruction phases and W

Choose one elementary action per table row's individual cursor unit. Stage/stream changes occur as bounded metadata updates at the final action of the previous phase; no uncharged loop advances an arbitrary number of phases. All four streams are counted independently, even if an implementation later schedules a disjoint batch in parallel. k=log2(N), N>=2 is T1's validated radix-two domain.

| Phase | Work and writes | Action count |
|---|---|---:|
| Freeze header | Bind exact snapshot/source slots/immutable overlays, reset cursors and pending namespace | 1 |
| Materialize snapshot | At each row i read source a_i/b_i and the frozen overlay, write a_s[i]/b_s[i]. Sorted unique overlays use monotone cursors, at most one value per side/row | N joint rows |
| Prepare streams | g_a[i]=a_s[i]*L_i; g_b[i]=b_s[i]*L_i; f_a[i]=a_s[i], f_b[i]=b_s[i] | N joint rows |
| Forward transforms | Four streams: bit-reversal visit at each index, then k stages of N/2 butterflies | 4N+2Nk |
| Pointwise multiply | g_a/g_b by shared FFT(w); f_a/f_b by shared FFT(w_reverse) | 4N stream elements |
| Inverse transforms | Four streams: bit-reversal visits and butterflies using inverse roots | 4N+2Nk |
| Inverse scale | Each group/scalar stream element multiplied by N^-1 exactly once | 4N stream elements |
| Integrate | g_a[i]+=f_a[i]*L_i+a_s[i]*p_i; same B; results overwrite g buffers | N joint rows |
| Ready | Terminal status; no automatic restart | 0 additional cell work |

With the immutable overlay capture already complete and public root/kernel tables already paid, the deterministic reconstruction quota is

`W(N)=1 + 19N + 4N*log2(N)`.

This is **the count for the specified units**, not a count of all field operations or wall time. At N=2^20 it is 103,809,025 actions. A normal quota unit includes its fixed maximum preimage copies/index/bitmap checks, arithmetic, stores and bounded cursor update. Separate journal preparation/cleanup, map staging/capture, validation, proof correction and initial/public allocation work are charged in their own ledgers rather than incorrectly counted as completed FFT progress. If the eventual implementation uses different units or separates those operations, it must recalculate W before using F(u), not silently reuse this number.

When a transition freezes a new header, it pays the one Freeze action and initializes that builder's completed count to1, including at e=0. This bounded header work is explicit even when F(e)=0; future grants subtract it as already completed. No row/FFT work is implied. A caller's `advance(0)` still changes nothing, and a no-op proof request never creates a new header. Include the header action in transaction work preflight rather than hiding it in root metadata.

The transform arithmetic alone has 2Nk group butterflies and 2Nk scalar butterflies. Group scalar multiplication calls total `2Nk+10N`: group butterflies plus prepare2N, pointwise2N, scale2N, integration4N. At k=20 this is 52,428,800 logical group scalar multiplications. These are scalar-call counts, not internal GLV curve-operation counts. Snapshot/copy/zero visits and phase cursors are not omitted from W. There is zero per-rebuild N-array zeroing in this layout because the pool is already initialized and valid prefixes gate every read.

For bit reversal, one action visits i and swaps only when i<reverse_k(i); N visits are counted regardless of swaps. Use the full N radix-two butterfly with forward omega/inverse omega ordering. Every odd/even supported k uses the same cursor algorithm; there is no square-half size assumption. A butterfly writes exactly two cells in one stream. A positive remaining budget consumes an action or reports Ready/error; zero is an exact no-op.

T2 material must provide exact shared FFT(w)/FFT(w_reverse). A shared N-entry root-power table is a straightforward constant-index twiddle source; inverse lookup uses the corresponding reversed exponent. Its creation/load/retention is public work charged once, not private hidden preparation. If no root table exists, a separately counted bounded twiddle-generation schedule must replace it and W be amended. Do not perform uncharged exponentiation or GLV-cache preparation in each butterfly. No public root/bit-reversal table is copied per state.

### Strict failure atomicity without copying the pool per update

Use a **first-touch undo journal** for existing initialized cells plus a small metadata/ownership snapshot. Journal by `(physical buffer slot,index)`, never by logical q_a/f_a roles that can change at promotion. Root/current metadata, all phase/stream/stage/permutation/scale/materialization cursors, overlay cursors, valid prefixes, source slot references, pending-generation trackers, t/C and ownership mappings are staged or saved before mutation.

There are two value journals (groups/scalars). Each records the original value and an encoded checked physical index on first modification in this transaction. Store values and indices in separate pre-reserved arrays to avoid per-record padding/tag guesses. A mark bit per physical cell prevents repeated copies when twenty FFT stages revisit a cell. Allocate the 4N group/6N scalar mark space once; clear **only logged bits** at commit/rollback. Clearing an N-size mark array at every update would defeat the design.

Before each write: resolve/validate the physical cell, ensure journal capacity, and if its bit is unset append the old value/index and set the bit; then write the new value. Prepared tuples, swaps, butterflies and integration must journal all their writes **before** modifying any of those cells. This includes initialized stale workspace cells: late-failure tests must observe the actual pre-call contents restored, not just equivalent recomputed q or a reset cursor. One action touches at most two group and two scalar cells in the chosen layout.

On error/cancel before commit, restore each logged cell's pre-call value, clear its bit, restore the metadata/ownership snapshot, discard staged maps/assignment/proof/header, and release the transaction. Old generation/proof and actual builder contents/cursors are exactly restored. Restoration uses only fixed-value copies and pre-existing storage; it performs no proof, group arithmetic, allocation or entropy request. Completed work and rollback CPU remain in the external attempt ledger, but no transition ID or target generation is consumed. Entropy source draws are not rewound.

On success, atomically install the small root/current/pending/role metadata and ordinary proof result while still holding the serial owner. Then clear logged marks and truncate/reset journal lengths in O(number logged), not O(N). If journal capacity is retained for reuse it remains part of resident private memory; a zero length is not zero allocated bytes. No late fallible operation follows the irreversible commit. Fault hooks intended to test failure atomicity run before that point.

For a multi-chunk update keep one private PendingTransaction and its journal across chunks until the entire target succeeds. All other update/cache readers are serialized or return Busy while physical old active cells are temporarily overwritten; no partial active cache is exposed. Do **not** clear undo after each chunk while promising rollback of the whole update. A bound on the entire transaction, not only one chunk, governs the journal. Rollback itself can be chunked, but the caller does not receive a completed failure until restoration finishes. Independent maintenance-only calls may commit their own progress, but a failing target update may not secretly commit its maintenance prefix.

### Allocation/entropy/preflight and limits

Before modifying any pool cell:

1. Validate exact package/domain/reduction, target assignment/public values, base/target generation, constant-one and normalized deltas. T1/T2 full satisfaction remains paid.
2. Stage target row maps and the exact grouped raw target correction using complete old active q. Preflight field-kernel/pair/row/support limits. The grouped order remains `Quo(a0*db+b0*da)+Quo((alpha+da)*db)+Quo(da*beta)`; the new cross term occurs once.
3. Acquire both independent caller randomizers and build/stage all fallible ordinary proof obligations as early as possible. The accepted T1 entropy/rejection contract is reused. Test-only late failures still require real cell rollback.
4. Compute checked quota K including any old-builder finish and overshoot work in a prospective cursor/header simulation. Reserve bounded maps, result/header, journal values/indices and any needed bookkeeping with fallible allocation before writes. All pool lengths/capacities are already valid; there is no per-update dense allocation.
5. Conservative journal bounds are `U_G<=min(4N,2K)` and `U_F<=min(6N,2K)` unique old cells; tightened phase-aware bounds are allowed only if independently checked. Preflight value/index bytes `104*U_G+40*U_F` under the observed 96/32-byte representation and 8-byte indices, plus bookkeeping/result/maps/assignments/public/fallback scratch. No single slot/index arithmetic may overflow.
6. If the required whole-transaction undo, correction or peak budget would exceed the configured ceiling, choose explicitly charged validated full/rebase **before any pool mutation**, or return a typed budget error. Yielding does not make the undo requirement disappear. A journal push cannot reallocate after preflight; an exhausted capacity is an injected/testable typed failure with rollback.

Engine-controlled vector allocation can be preflighted fallibly. The pinned group backend's GLV/BigInt operations can still allocate internally; T1 does not promise recovery from process OOM/allocator abort. Ordinary arithmetic returns/late injected failures/cancellation are the rollback contract here. Process death/OOM cannot execute an in-memory undo guard; T6 must recover the last durable committed generation or force rebuild. Do not claim every dependency allocation failure becomes a typed error without a separate backend audit. An unwind guard can restore preimages for supported unwinding failures, but is not an abort/crash guarantee. Do not add allocator/backend changes to T5 to hide this boundary.

If parallelizing a disjoint stage batch later, complete its deterministic first-touch reservation/preimages before worker writes, and join every worker before commit or rollback. A failed worker must not race restoration. The initial correctness implementation may serialize elementary work; its actual thread/parallelism choice and all resulting performance losses must be recorded.

### Atomic promotion, target freeze and buffer recycling

At promotion the completed builder g_a/g_b and frozen a_s/b_s become new active q/rows at gs. Its post-snapshot eta/theta **through the accepted target** become active alpha/beta. Install the already-staged target raw proof/public state once. The next builder freezes the actual target as source new-active rows plus those exact immutable accumulated maps. Its pending corrections start empty; it is not handed the current transition a second time.

The old active group pair becomes the new builder's group destination, old active row pair becomes its snapshot destination, and old builder field FFT pair remains its field work destination. This recycles the same 4G/6F pool. Materialization reads new active frozen rows plus the frozen target overlays and writes the recycled row destination in bounded units; **no N-row copy occurs at freeze or root swap**. Later transitions replace current maps while the captured immutable overlays stay unchanged until materialization is finished. Release source overlay references after complete materialization when safe; do not retain an obsolete row generation accidentally.

For t+d=b, new quota is zero. The promotion/new-header root can commit before any next-builder destination write; old active buffers are recycled only as initialized private destination storage afterward. For t+d>b, e=t+d-b requires F(e) work on the new target snapshot in the **same transaction**. Recycled old active buffers may then be overwritten before final commit; their original cells and ownership remain recoverable in the same physical-slot journal. Preserve retired old active values until journaled/committed. A failure after promotion/reuse must restore both the pre-call active and pre-call builder, not merely raw proof metadata.

The old/new snapshot inputs, pending map generations and slot-role map are one atomic root. During that transaction no external immutable alias can observe overwritten retired q/rows. This is why private unique pool ownership and physical-slot journal keys are mandatory.

### Thresholds, no-op and oversized/full readiness

Retain approved t in [0,b), F(u)=floor(Wu/b), separate cumulative accepted distance C, actual snapshot distances and the conservative **4b** assignment-distance bound. Already-completed optional background actions reduce required quota, with no double charge. Keep independent matrix fanout/row/pair/memory caps; 4b assignment distance is not a row-support guarantee.

No-op proof requests obtain fresh r/s without automatic maintenance or invented distance. If the eventual T2 transition API allows a named zero-delta generation transition, only that validated metadata advances once; t/C do not change and pending numerical maps remain exact. Freeze this distinction with T2 before implementation. Cancellation/reversion cannot refund accepted distance or work.

d>b or a preflight cap breach chooses the labeled full route or typed error. A successful ordinary full proof installs the exact target statement/generation in **FullOnly**, retires both projection/rebuild generations and resets t/cycle origin while retaining lifetime C. It does not install an incomplete q as DynamicReady. Returning to dynamics requires an explicitly charged matching T2 private full anchor/raw state and complete preparation, or a PendingPreparation route that serves only ordinary full proofs until ready. Do not reuse old builder/alpha/beta after fallback. New action/holder invalidates private reuse and follows that full policy; synthetic public-action algebra tests do not authorize cross-action reuse.

## 6. Structural byte accounting versus unmeasured runtime

Use the observed E4/pinned representation G1Projective=96 bytes, Fr=32 bytes, and the current 64-bit host's 8-byte indices as **structural estimates**; the implementation must record `size_of`, actual capacities and allocator live bytes. At N=1,048,576:

| Item | Structural payload bytes | MiB |
|---|---:|---:|
| Active 2G+2Fr | 268,435,456 | 256 |
| Builder 2G+4Fr | 335,544,320 | 320 |
| Core pool 4G+6Fr | **603,979,776** | **576** |
| Ten-cell-space mark bits | 1,310,720 | 1.25 |
| Worst full-pool undo values 4G+6Fr | 603,979,776 | 576 |
| Worst full-pool undo encoded indices 10N | 83,886,080 | 80 |
| Pool+full undo+marks | **1,293,156,352** | **1233.25** |

The worst undo payload/index bound is **656 MiB**, on top of the 576-MiB pool. Small budgets log only touched cells; there is no O(N) clone on every normal small update. Large quota/overshoot can touch most of both generations and legitimately approach this bound. Cap it before execution or report fallback/loss. A retained maximum-size journal becomes resident capacity even when empty; do not report only its length.

On top: package/PK/VK/updating bases/matrix indexes, public Fourier kernels, optional shared root powers, assignments, sparse overlays/maps/deltas, cursor/header/result, diagnostic verifier scratch, allocator metadata/native stacks, serialization and any full fallback allocation. Shared FFT(w)/FFT(w_reverse) alone have 2N Fr payload=64 MiB; a shared N-root table adds32 MiB if not already present. L/p and existing weights belong to T2's measured public allocation; do not count them once here and again as a new private saving.

T1 assignments are Vec<Fr>, not cheap clonable public values. T2 may share validated immutable references: current, active anchor, frozen snapshot and staged target can still be four distinct v-element assignments in a transaction. At the prior credential v=643,563, each is20,594,016 structural bytes and four total82,376,064 bytes; caller canonical encodings/witness service data are additional if retained. Record actual aliasing/capacities rather than assume one. Adopting a T2 anchor while its external owner keeps another dense q/row allocation adds that allocation as well.

Enumerate row maps in preflight: old active alpha/beta, old builder pending eta/theta, frozen overlay pair, staged active pair, staged pending pair, and normalized current da/db can coexist; some Arc references alias and some do not. Bound each normalized support/capacity, frozen-overlay capture/merge work and assignment-delta storage. At8-byte row index+32-byte Fr, a flat pair has40 logical payload bytes before its actual layout/container; hash-map capacity/stamp arrays have separate costs. Never replace this variable bound with a zero-cost Arc label.

No dynamic resident/peak RSS, initialization time, reconstruction time, per-update pause or allocator outcome is measured here. Existing E2 private prep was510.323s; E4's instrumented repeat was746.360s under a different diagnostic scope. Those do not time this layout, but they rule out assuming a whole reconstruction is free: actual two distinct swaps might each require hundreds of seconds of maintenance, and that result/loss must be reported if observed. Quota smoothness bounds actions, not deadlines or pilot economics.

## 7. Evidence path and proposed failure-injection obligations

This brief: `docs/dynark/phase-2/evidence/t5-state-layout.md`. Parent's accepted algorithm is `phase-2/conformance.md:40–50`; T0 is `evidence/t0-review.md`; T1 remains commit `9dc0547`. No runtime evidence files were created.

Before any actual-circuit execution, the later worker records a finite small experiment for N=2/8/16/32/64/128/256 and varied raw row/assignment shapes, with at most15 minutes/2 GiB as the existing T5 plan ceiling. Record b, pool/journal caps, phase units/W, thread policy, exact dependency/source identities and watchdog/stop rules before running. Required tests are not yet run:

- Field/group forward/inverse exact arkworks equality at odd/even logs and all zero/tail/partition budgets; final q exact eager Theorem 2 including deferred diagonal and overlap.
- Instrument logical actions by phase; ordinary build completes in its declared W, initial alias is tagged separately, public/root/copy/zero work and journaling/reset/rollback CPU are counted outside quota as declared. No large cell clone/bitmap clear occurs on every small update.
- At least1,000 small valid transitions and at least two completed reconstructions of **distinct** frozen snapshots, with t+d<b/=b/>b, d>b, no-op, revert, dense/fanout and action invalidation. Target raw components/public statement match fresh full and all ordinary proofs independently verify.
- Snapshot every physical buffer value and metadata before each injected late failure on small fixtures. Fail after a snapshot write, prepared tuple's first/second group write, bit swap, butterfly first/second write, pointwise product, scale, integration, completed-builder promotion, next-header freeze and overshoot overwrite of retired active rows/q. Compare every cell, cursor/role/overlay/generation/proof after rollback, not just final verification.
- Revisit the same cell across many FFT stages in one transaction: its original value is logged once and restored correctly. Across transactions first-touch marks clear only at logged indices. Inject insufficient journal reservation/capacity, typed allocation failure before mutation, entropy failure on each draw, cancellation in every phase and corruption of a slot/reference plan before indexing.
- Cross-phase multi-chunk cancellation retains/uses the entire call journal; reader/update serialization never exposes partially recycled active vectors. The physical-slot identity remains valid when roles change. Parallel worker failure cannot race undo if batching is implemented.
- Full fallback/error happens before scans/mutation when the whole transaction cap fails; FullOnly has no usable stale q/builder and cannot advertise readiness. Initial immutable-anchor aliases remain unchanged on success/failure. T6 crash recovery is tested separately, never inferred from these in-memory tests.

## 8. Security and practical limits

The same ordinary fixed-relation, matching CRS/QAP/domain, benign auxiliary-input, valid-state/no-leakage and fresh independent r/s limits from T0 remain. Source checksums/commit identity do not authenticate an arbitrary setup. Private pool/preimages/maps/assignments are sensitive: undo increases the amount of retained historical witness-derived state. Never export journals/raw proof or log actual cells/supports as routine telemetry. No erasure/forward-security or side-channel property is established.

Undo guarantees runtime error/cancellation atomicity under its stated process/serialization assumptions. It is not a durable commit or whole-store rollback defense. T6 retains AEAD/unique-nonce/external trusted-generation and crash recover-or-rebuild obligations. Current-root/issuer/action policy remains external; internal reconstruction snapshots never authorize an old root. Allocation latency and group backend aborts remain practical bounds requiring explicit reporting.

## 9. Next gate and unresolved implementation choices

Parent must review/adopt this **4G/6Fr owned pool + physical first-touch undo** representation, the deferred diagonal unit bound, W formula, immutable frozen target overlays, and full-pool undo cap behavior before T5 dispatch. T2 must hand off exact opaque anchor/raw state and public material interfaces; no source ownership is transferred by this report. T5 adds its own typed budget/pending errors after handoff, not a bypass around T1's exported boundary.

Freeze journal/pool/global peak ceilings, root table ownership, initial anchor adoption/copy route, immutable map representation/capture accounting, generation semantics for zero-delta requests, batching/serial-owner policy, failure-hook locations and cursor unit representation before implementation. These are concrete engineering choices; no new algebraic research is required. Small oracles/failure tests and parent independent review precede promotion; actual-circuit two-swap work needs a separately recorded sole queue slot/resource budget. No claim that a tested/affordable implementation already exists follows from this brief.
