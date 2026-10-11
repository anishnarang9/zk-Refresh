# Conformance and security record

October 10, 2026. Parent review of the corrected Phase 1 algorithm/security reports and relevant reference proof code. This is a derivation/contract record, not fresh correctness evidence. Reference pin `c73a380df86d8f5d195f1e20c8a1d86a7dce084b`, with the frozen assignment-column and anchored OsRng patches. Supplied paper SHA-256 `f851f11ed8ae8a6876dafe09373650098aa792b9f886019eea4d98060fa7b259`; all 30 pages were reviewed in Phase 1. The absent expanded proofs/pseudocode remain absent; no generic paper-reading gate is reopened.

## Algebra and source mapping

| Component | Reviewed specification | Reference / acceptance |
|---|---|---|
| Full proof | Paper pp9–10, original constraint QAP; seven quotient transforms | `r1cs_to_qap::compute_quotient`, `create_proof_with_assignment`, E2 `full_without_cache`; retain one in instance slice; ordinary independent verifier |
| UK | pp15–17 Eq6, truncated H basis padded with zero, diagonal basis | `generate_updating_keys`; derive only from matching public CRS, retain N inverse and w0=0 |
| Projections | pp17–18 Theorem2 | `compute_projection_quotient`; exact dense vector oracle |
| Anchored correction | pp13–15 Eq4–8 | `update_dynark`; exact target raw components under common test r/s, independent randomized proofs |
| Fast cross term | p16 target kernel; algorithm omitted | Independent Trummer/product-tree derivation below; quadratic retained |
| Dynamic correction | pp20–23 block offset; omitted step algorithm | Grouped accumulated/current reference identity; explicit scheduler invariants and bounded progress |
| Persistence | Outside paper theorem | Authenticated confidential state; external trusted generation boundary |

Let Z=X^N-1 and x_i=omega^i. For i!=j,
`phi_ij = w_(j-i) L_i + w_(i-j) L_j`, with `w_t=omega^t/[N(1-omega^t)]`, `w_0=0`. Diagonal quotient is `phi_ii=-sum_(j!=i) phi_ij`, with remainder L_i. Quotient degree is at most N-2; this justifies truncated Lagrange encodings from the N-1 H query. Both orientations and the diagonal term are required.

Projection identity is `q^a=w*(a circ L)+(w_reverse*a) circ L+a circ phi_diag`. Parent checked the orientation by expanding `sum_j a_j phi_ij`. For valid base/target assignments, quotient change is `Quo(A dB+B dA+dA dB)`; `dC` has zero quotient but its remainder remains part of satisfaction. The C correction is `s' A'-s A+r' B1'-r B1-(r's'-rs)delta+private_linear+quotient_change`. Protocol2's printed missing 1/N and plus sign are not copied.

## Fast kernel approval boundary

For normalized union I of distinct domain indices, set c_j=a_j*x_j, D(X)=product(X-x_j), and P(X)=sum_j c_j D(X)/(X-x_j). The required off-diagonal sum is

`conv_i = [P'(x_i)/D'(x_i)-c_i D''(x_i)/(2D'(x_i))]/N`.

Parent review: factor D=(X-x_i)D_i and P=c_i D_i+(X-x_i)R_i. At x_i, D'=D_i, D''=2D_i', P'=c_i D_i'+R_i. The formula becomes R_i/(N D_i), exactly sum_(j!=i) a_j*x_j/[N(x_i-x_j)]. This confirms normalization, orientation and diagonal removal. Empty/singleton off-diagonal results are zero; the separate diagonal group term remains.

Balanced product/numerator trees and derivative multipoint evaluation through fast polynomial remainder trees are approved as an independent candidate, subject to a second review and exact oracle tests before T4 integration. BN254 odd characteristic makes 2 and N invertible for supported radix-two domains; distinct nodes ensure D' nonzero. Check all intermediate polynomial convolution sizes against available domains. O(s log²s) depends on fast multiplication/division; using naive polynomial remainders does not earn that claim. Tree construction, conversion, allocations, field and group work all count toward crossover. Unsupported sizes return bounded fallback/error; no unbounded quadratic new-action run.

## Dynamic algebra and scheduling approval boundary

Select the reference grouped-correction approach initially. With accumulated alpha/beta before an update and current da/db, use
`Quo(a_anchor db+b_anchor da)+Quo((alpha+da)db)+Quo(da beta)`.
Expansion yields `Quo(a_current db+b_current da+da db)`, including the new cross term exactly once. Corrections and current raw proof must share the exact anchor/current generations. A fast kernel over accumulated/current union has a union-support bound; it does not establish the paper's current-d-only field bound. Direct partial-K is a separate possible tradeoff, not silently claimed implemented.

The [architecture](architecture.md) freezes generation, threshold, overshoot, failure and memory contracts. T5 first closes the known odd-log FFT and tail-batch progress defects. The proposed concrete scheduler must be reviewed before implementation; high-level algebra approval does not validate a state machine. Small repairs needed to establish progress are authorized now.

### T0 second review and parent disposition

The [independent Sol high review](evidence/t0-review.md) confirms the finite-part formula, grouped correction ordering and ordinary security limits. Parent also inspected the supplied paper extraction at pp13–15 and pp19–23 and the reference's actual update/reconstruction vectors. T0 is complete as a specification gate; no runtime gate is closed by this review.

Approve the independently derived in-place radix-two reconstruction candidate with explicit bit-reversal, butterfly, normalization and bounded row/copy cursors. Every supported odd/even log size uses the same algorithm; do not copy square-half assumptions. All zeroing, allocation/materialization, stage transitions and public table preparation must be accounted for. A partial reconstruction is retained between calls; repeatedly running eager K is not an implementation of this design.

Approve quota `F(u)=floor(W*u/b)` with checked arithmetic and at most one threshold crossing when t<b and 0<d<=b. Complete the old builder before promotion; carry e=t+d-b as prepaid scheduling credit on a new builder frozen at the whole accepted target, never as a fictitious witness. New pending corrections start empty and the transition is not applied again. Parent checked the boundary argument: adjacent actual snapshots can be less than 2b apart; the previous active snapshot and current partial block therefore require a conservative 4b assignment-distance cap. Record this 4b extension explicitly; do not claim the paper's ideal 2b bound. Row support, pair work and memory have independent caps because assignment distance does not bound fanout.

One initialization may share already-complete initial projections; do not count that as a distinct completed reconstruction. Required sequence evidence must include completed work for distinct frozen snapshots and atomic promotions. Optional background work reduces outstanding quota without double charging. All maintenance, copied pages/undo state, fallback and abandoned work remain charged. Quota units establish bounded operation counts, not a wall-time guarantee.

Before a transition mutates committed state, preflight validation/identity, entropy, bounds and allocation requirements. Reconstruction/proof work must use a bounded staged representation or charged undo/copy-on-write strategy; failure injection must demonstrate the previous committed generation is preserved. The exact concrete representation is subject to implementation review, small sequence tests and a peak-memory preflight before credential-scale execution. Reference two-checkpoint vector counts are structural estimates only; they are not measured product memory.

### Concrete T5 layout approved for implementation

The parent reviewed the complete [state-layout brief](evidence/t5-state-layout.md), independently collected its phase counts and checked promotion/recycling dependencies. Approve the uniquely owned 4N group/6N field pool, deferred diagonal integration and first-touch undo keyed by physical slot/index. The proposed units give `W=1+19N+4N*log2(N)`; changing units requires recalculating W. The header action is charged at freeze even when the next quota is zero; `advance(0)` itself remains an exact no-op. Current assignment validation/copy work is in v coordinates and charged separately from N-sized reconstruction vectors.

At promotion, the completed builder's frozen rows/projections become active; its pending corrections through the target become active accumulated maps. The next frozen input references these new active rows and immutable target overlays, and materializes into recycled old-active row storage through bounded row actions. The physical undo journal must preserve retired values if overshoot writes those slots before commit. Parent checked that this avoids an immediate N-row copy and preserves exactly-once corrections. Full-pool undo can add 656 MiB to the 576-MiB structural pool at the credential N, before public data/assignments/maps; these are capacity estimates, not runtime measurements.

Use already-paid shared public forward/reverse kernel transforms and a root-power table for fixed-index twiddles in the initial implementation. Charge table creation/load and retain it once per compatible public package. Acquire entropy before group correction work after cheap validation/bound checks. A named valid zero-delta request may advance the caller's target generation and rerandomize the proof while leaving distance, numerical pending corrections and maintenance unchanged. New holder/action bindings take the explicit validated full/invalidation route. No-op/FullOnly readiness, staged map representation, journal limits, initialization, and any parallel batching still require concrete source and failure tests. Runtime OOM/abort recovery is not claimed; durable recovery belongs to T6.

## Security and discriminating fixtures

Follow [Phase 1 security analysis](../phase-1/evidence/paper-security.md), including the benign relation/auxiliary-input generator assumption inherited from Groth. Correct raw component equality with fresh independent uniform r/s supports the conditional transcript argument under valid-state/no-leakage assumptions. It does not prove arbitrary auxiliary-input, simulation-extractability, cache-compromise, forward-security, timing privacy or production setup claims. No quantitative BN254 security claim is added.

Freeze: (1) z=(1,x,w), row w*w=x, four zero rows, k=2, original and A-augmented reductions both N=8; matching-key acceptance and incompatible-reduction rejection; (2) five public values, each alteration rejected; (3) assignment counts on both sides of N, non-power-of-two raw constraints and varied matrix sparsity; (4) malformed dimensions, canonical fields, coordinate-one and wrong-key/entropy negatives. Unaugmented public u_x=0 is not itself unsoundness evidence.

T1 requires typed entropy failure before partial output, secure caller randomness and no insecure exported convenience path. Future modes must reuse that boundary. Original zkey mapping, arbitrary circuit mutation, other curves, real X.509 qualification and Solana execution remain outside Phase 2. Strict execution-current-root and authenticated issuer freshness remain external obligations; internal anchors never authorize an old root.
