# Independent revision review of reopened Phase 1

October 10, 2026. Bounded review of the revised research, Phase 2 plan, product specification, decision register, and algorithm/security reports. This reviewer independently rederived the four consequential claims requested by the parent. This is a selective independent review, not a second claim to have personally read every supplied page or certified the authors' missing proofs.

## 1. Task and configuration

Fresh independent reviewer `revision_review`; explicitly dispatched as `gpt-6.1-sol` with high reasoning and `fork_turns="none"`, with no child agents. Working directory `/Users/anishnarang/Zk-refresh`, following the parent's verified project move. Read-only research except this owned evidence report. No implementation, test, build, proof, benchmark, setup, deployment, or heavy profiling work authorized or performed.

## 2. Findings and independent derivations

**No consequential algebra correction is required in the reviewed candidate equations. No new security theorem is certified.** The current research/decision/product documents properly distinguish supplied-source reading, derived conformance, ordinary soundness, stronger security notions, original-key integration, and measured economics. E4 remains pending; this is appropriate, not a completion defect.

### Findings and remediation status

| Severity | Finding and locator | Required correction |
|---|---|---|
| P2, resolved on recheck: handoff consistency | The initial live master roadmap snapshot `docs/superpowers/plans/2026-10-10-dynark-product-roadmap.md:84,92` retained a missing-paper prerequisite, while `:19-35` presented historical measurements/526-305 crossover as current. Revised authoritative research/product instead close source reading and use E2. | Parent corrected the roadmap during this review. Fresh reads confirm explicit historical supersession at `:11,17,35`, completed source review at `:84,92`, and a link to current E2 accounting. This finding is closed. |
| P2, resolved on final recheck: workspace identity | The initial `HANDOFF.md:3` identified `/Users/anishnarang/Zk-fresh`, while the verified working project is `/Users/anishnarang/Zk-refresh`. | Final fresh read confirms `HANDOFF.md:3` uses Zk-refresh and `:23` records explicitly authorized root Git initialization/small local commits/no push. Phase 2 `:13` and D19 agree. Historical paths may remain historical. This finding is closed. |
| P3, resolved on final recheck: explicit discriminating fixture | The initial T1 checklist omitted the security report's explicit C-only public value and original-only/augmented equal-domain discriminator. | Final fresh read confirms T0 `phase-2-plan.md:48` freezes both fixtures, and T1 `:63` explicitly includes `w*w=x`, altered/unsatisfied negatives, coordinate one, matching keys for each reduction, and equal padded N without interchangeable queries. Hodd interoperability remains P4/G7. This finding is closed. |
| P3, resolved on recheck: completion terminology | The initial `phase-2-plan.md:78,144` snapshot ambiguously gated “paper-completeness” alongside open implementation gates, although G1 and the research report close reading. | Fresh reads confirm parent now explicitly separates completed supplied-paper reading from absent author proofs/unimplemented algorithms at `:78`, and full implementation conformance/production readiness at `:144`. This finding is closed. |

All findings above are closed following fresh reads of the parent's corrections. No remaining product contradiction was found in the assigned snapshot. The accepted target eligibility/application policy is separated from current v1 and later v2 integration (`product-spec.md:9-13,19-31,41,70-76`). No pilot economics, exact OIDs, freshness timeout, real corpus, or device qualification is claimed complete. The preparation and 271-refresh figures are measurements/derived estimates, not pilot observations. No omitted bounded Phase 1 research goal was identified beyond pending E4/final validation.

### A. Selected Trummer convolution and diagonal

Locators: `paper-algorithms.md:197-219`; DYNARK §3.3, equations (6)-(8), pp15-17; preserved `paper-layout.txt`; research `:29-39`.

For unique nodes `x_i=omega^i`, circular convolution orientation gives

`w'_(i-j)=w_(j-i)=x_j/[N(x_i-x_j)]` for `i != j`.

With `c_j=a_j*x_j`, `D=product_j(X-x_j)` and `P=sum_j c_j D/(X-x_j)`, write `D=(X-x_i)D_i` and `P=c_i D_i+(X-x_i)R_i`. At `x_i`, `D'=D_i`, `D''=2D_i'`, and `P'=c_i D_i'+R_i`. Therefore

`SparseConv_i = N^-1 [P'(x_i)/D'(x_i) - c_i D''(x_i)/(2D'(x_i))]`.

This independently verifies the finite part, factor `1/N`, and removed self pole. Distinct nodes and invertible `N,2` are required. The separate actual quotient diagonal remains `a_i*b_i*p_i`; setting `w_0=0` does not eliminate it. The balanced numerator/product/remainder-tree route has conditional cost `O(M(s) log s)`; `O(s log^2 s)` requires the stated suitable fast polynomial arithmetic. No local crossover or implemented bound follows from this derivation.

Manual F17 check, no executed test: `N=4`, `omega=4`, nodes `1,4`, input `(2,3)`, weights `(2,12)`. `w_1=11`, `w_3=10`; direct convolution is `(3*11,2*10)=(16,3)`. `D=X^2-5X+4`, `P=14X+14`, `D'=2X-5`, `D''=2`. The finite parts at the two nodes are `13,12`, then division by four gives `(16,3)`. The report's hand check is correct.

### B. Fully dynamic accumulated/current correction

Locators: `paper-algorithms.md:223-237`; DYNARK §4.1 pp21-22 and Protocol 3 p23; research `:106`; Phase 2 T4 `:99`.

Let anchor evaluations be `A0,B0`, accumulated corrections before this transition `alpha,beta`, and current deltas `da,db`. Before the transition, `A=A0+alpha`, `B=B0+beta`. Quotient linearity gives

`dq = Quo(A0*db+B0*da) + Quo((alpha+da)*db) + Quo(da*beta)`.

Expansion is exactly `Quo(A*db+B*da+da*db)`. The degree-below-N C correction has zero quotient; its remainder is essential to valid-assignment satisfaction. Reference ordering that adds `da` to alpha before the first cross call and reads old beta before adding `db` therefore matches the algebra.

If accumulated/current induced support sizes are `b,d`, this grouped reference route can visit `O(b*d)` field pairs and use `O(b+d)` grouped scalar multiplications per correction call. The paper's direct partial-K route corrects only current-needed entries with `O(b*d)` group work, then evaluates the current-only cross term. A product tree over an accumulated/current union instead costs `O(M(b+d) log(b+d))`, conditionally `O((b+d)log^2(b+d))` field work. It cannot establish a current-only `O(d log^2 d)` bound when `d=1` and accumulated support grows. The revised plan states this limit correctly. Distances, real row supports, touched matrix entries and scheduling work must remain separately charged.

### C. Original-only QAP, augmentation, and public H conversion

Locators: `paper-security.md:81-118`; DYNARK §2.1 pp9-10 and §3.3 pp16-17; [Groth's primary accepted paper](https://discovery.ucl.ac.uk/id/eprint/1501201/1/Groth_SNARK9.pdf), §2.3 pp8-9, Theorem 2 pp14-15, Theorem 3 p17; inspected local snarkjs H-section/preparation/prover source.

Groth's degree-bounded QAP definition imposes no public-u independence condition. Its ordinary affine/generic-group extraction argument takes auxiliary coefficients from C and public coefficients from the verifier's statement. This supports the report's limited conclusion: A-only public-row augmentation is not necessary for that ordinary theorem. It does not establish the missing DYNARK AGM reduction, simulation extractability, or a security audit of the credential circuit. The primary source also assumes a benign relation/auxiliary-input generator (§2.2 p8); inheritance must retain that scope rather than promise arbitrary auxiliary-input security.

Final reconciliation: fresh reads confirm T0 `phase-2-plan.md:48` and the security report `paper-security.md:85` now explicitly carry this benign relation/auxiliary-input assumption and exclude an arbitrary-auxiliary-input claim.

Independent relation argument: interpolation on the original roots makes `a*b-c` divisible by `Z` exactly when all original R1CS rows hold. Appended rows `z_j*0=0` preserve this language but change A/u, public queries, projections and quotients, even when both reductions round to the same domain. A public x appearing only in C in `w*w=x` remains meaningful; zero u_x alone cannot imply unsoundness. Matching setup/reduction/query identities remain mandatory.

For the supported snarkjs branch, let `eta_j=zeta*omega^j`, `zeta^2=omega`, `zeta^N=-1`. The polynomial `f_i=X^i(X^N-1)` has zero values on even 2N roots and values `-2*eta_j^i` on odd roots. For `0<=i<=N-2`, its degree is at most `2N-2`, so 2N-point interpolation yields the public identity

`Hmono_i = -2 sum_j eta_j^i Hodd_j`.

If each 2N Lagrange encoding omits the degree-`2N-1` term, that omitted term cancels in this combination because f_i has no such coefficient. This cancellation would not justify deriving `Hmono_(N-1)` by the same truncated argument. The paper instead zero-pads the required `Hmono_0..N-2` to create its truncated N-point basis; it does not assert the genuine missing H power is zero. Correct roots/order, transform normalization, group decoding, final delta, and augmented matrix/PK compatibility remain explicit preconditions. The report's formula is valid under these hypotheses; no original zkey import was performed.

### D. Fresh-proof transcript argument

Locators: `paper-security.md:32-45,49-59`; DYNARK Definition 1 pp11-12, §3.2 p13, §4 p20, Theorem 4 sketch p22.

If every valid update computes the exact ordinary target A/B/C components and samples independent uniform target r/s, then, conditional on prior public history and the chosen valid target pair, its proof distribution equals fresh ordinary proving. Induction gives equality of honest polynomial-length public proof transcripts to fresh-prover transcripts. Computational CSPRNG use adds its stated implementation assumptions. This is a conditional component/distribution argument, not an inference from a successful pairing check.

The supplied displayed game is marginal/fixed-pair and even prints old x when generating the target proof with x'; it omits the joint transcript and private-state exposure. The full-dynamic formal game and author proof are deferred. Thus the derived argument supports transcript-only ordinary privacy with valid state/fresh randomness and the applicable ordinary theorem assumptions. It does not certify adaptive simulated-proof-oracle security, simulation extractability, nonmalleability, exposed-cache privacy, timing privacy, forward security, or the authors' omitted formal game. The revised report preserves these limits.

## 3. Files changed

Only `docs/dynark/phase-1/evidence/revision-review.md`. Parent-owned documents were not edited; actionable corrections were sent to the parent.

## 4. Commands and outcomes

Targeted `rg`, `rg --files`, `nl` and `sed` reads of the assigned documents, active handoff/master roadmap, preserved paper text, and local snarkjs/wasmcurves H preparation/prover sources. Primary web open of Groth's accepted UCL PDF and relevant sections succeeded. `shasum -a 256` confirmed identical supplied/protected DYNARK PDF hashes. One optional lookup guessed nonexistent `brief.md`/`ROADMAP.md`; `rg --files` immediately identified the actual master roadmap. No search outside the relevant workspace/PDF/skill paths; no memory lookup.

The using-superpowers skill entry was read and explicitly directs dispatched subagents to skip the skill. No additional workflow or implementation skill was invoked.

Final follow-up used targeted `rg` reads of the handoff, Phase 2 plan, security report, and this report. Workspace/Git policy, T0 theorem scope, and T1 discriminating fixtures were verified in their current text. No experiment was run. The configuration statement was corrected to the actual parent-confirmed explicit fresh-context dispatch.

## 5. Measurements not done

No fresh latency, memory, sampled kernel, entropy, proof, cache, full-dynamic sequence, pilot, original-zkey conversion or Solana execution measurement. F17 arithmetic was manually derived. E2 values and E4-pending status are carried from the parent's current evidence, not newly measured or independently rerun. No theorem is certified from output checks.

## 6. Identities and residual risks

Supplied and preserved PDF SHA-256 both `f851f11ed8ae8a6876dafe09373650098aa792b9f886019eea4d98060fa7b259`. Primary paper URL: https://eprint.iacr.org/2025/1897; no assertion of current remote byte equality. Reports cite reference pin `c73a380df86d8f5d195f1e20c8a1d86a7dce084b`; no new pin/build validation in this review. Author-deferred proofs/fast/stepwise/four-FFT detail, BN254 quantitative security, compiled-circuit audit, exact imported-key conformance, private-state compromise and realistic workload economics remain separate obligations. Documents may be edited concurrently by their owners; locators describe the reviewed snapshot.

## 7. Next action

All requested document reconciliations are verified complete. Await the sole E4 owner `research_coverage`; read final evidence and residual limits before closing Phase 1/final dispatch. No additional heavyweight experiment is recommended by this review.

## 8. Deviations

No scope or mutation deviation. Narrow active handoff/master-roadmap reads were needed to check Phase 1 goal coverage and live contradictions. Narrow local H-section reads and primary Groth inspection were necessary to independently test the requested reduction/basis/security claims. No code, tests, builds, proofs, benchmarks, helpers, subagents or unrequested implementation.

## 9. Review conclusion

The four consequential derivations survive independent review within their explicitly stated assumptions. All review findings are closed by verified document corrections; no newly found algebraic or ordinary-soundness defect remains. This report does not close pending E4, production RNG/reconstruction defects, stronger-security claims or original-key/Solana gates.
