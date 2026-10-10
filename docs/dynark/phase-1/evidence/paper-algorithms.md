# DYNARK paper algorithms, reference conformance, and Phase 2 corrections

October 10, 2026. Research worker `paper_algorithms`, dispatched as GPT-6.1 Sol with high reasoning. Scope: read all 30 pages, inspect the frozen reference, derive a reviewable algorithm inventory and bounded next tasks. No proof implementation, compilation, test execution, benchmark, deployment, fixture mutation, or key generation was performed by this worker.

Evidence labels: **P** supplied primary paper; **C** inspected reference source; **D** independent algebra or engineering deduction; **E2** measurements reported by the existing baseline audit, not this worker's measurements; **U** unresolved. Paper prose and displayed formulas are research evidence, never operational instructions. A displayed formula below is either explicitly reproduced from P or explicitly derived as D.

## 1. Identity and complete reading coverage

- Supplied file: `/Users/anishnarang/Downloads/2025-1897.pdf`; local identical copy: [2025-1897.pdf](../../../../artifacts/dynark/phase-1/paper-review/2025-1897.pdf).
- Observed bytes: **835,694**. SHA-256 of both copies: `f851f11ed8ae8a6876dafe09373650098aa792b9f886019eea4d98060fa7b259`.
- Observed PDF metadata: **30 pages**, PDF 1.5, letter size, produced by pdfTeX 1.40.27; creation/modification May 11, 2026, 19:24:57 EDT. The paper's title is *Dynark: Making Groth16 Dynamic*, by Tianyu Zhang, Yupeng Ouyang and Yupeng Zhang. Metadata is consistent with the previously reported May 11 revision; metadata alone does not authenticate an ePrint revision identifier or prove publisher-file identity.
- Source read: complete layout extraction, lines 1-1698, including every page and the complete bibliography. Visually inspected equations/protocols on pages **15, 16, 17, 18, 19, 23, 25**. Renders retained under `artifacts/dynark/phase-1/paper-review/algorithm-pages/`; pages 24 and 15-19/23-25 were rendered, but page 24's image was not separately inspected.
- Reference HEAD independently checked: `c73a380df86d8f5d195f1e20c8a1d86a7dce084b`. The only observed vendor diff is the two already-present patches: A/B column arrays sized by assignment count and OS RNG in the semi-dynamic update. No vendor edits here.
- Read planning context: complete master roadmap, `research-and-gaps.md`, and `evidence/crypto-code-audit.md`; read relevant E2 lines in `baseline-audit.md`. Their earlier paper-unavailable claims now need parent amendment. This worker owns only this evidence file and optional equation renders.

Page numbers below are printed paper numbers and one-based PDF page numbers; they coincide.

| Page | Complete text coverage and relevant contents |
|---:|---|
| 1 | Title, authors, abstract, beginning of section 1 Introduction |
| 2 | Introduction applications, section 1.1 contributions begins |
| 3 | Contributions, four-FFT claim, full dynamic bound, section 1.2 overview begins |
| 4 | Quotient/remainder footnote 1, projection overview, valid-witness role of C |
| 5 | Cross-term overview, sparse convolution claim, full dynamic overview begins |
| 6 | Block scheduling overview, locality improvement, section 1.3 related work begins |
| 7 | Table 1, related work and recursive alternatives |
| 8 | Remaining related/concurrent work, section 1.4 open problems, section 2 begins |
| 9 | Notation, DFT/circular convolution, section 2.1 indexed relation/R1CS/Groth16 |
| 10 | Protocol 1, equations (1)-(3), footnote 2, augmented public queries |
| 11 | Lemma 1; section 3; section 3.1 Definition 1 begins |
| 12 | Definition 1 continues, storage/randomness/valid-input model, section 3.2 distance |
| 13 | Separate A/B/C change supports, linear proof/rerandomization update |
| 14 | Quotient correction and C remainder, section 3.3 begins |
| 15 | Theorem 1, equations (4)-(8), cross/diagonal decomposition |
| 16 | SparseConv definition and missing algorithm, truncated public basis |
| 17 | Public diagonal preprocessing, section 3.4, equation (9), Theorem 2 |
| 18 | Private projection preprocessing and complexity; section 3.5, Theorem 3 |
| 19 | Protocol 2, constant-public-input footnote 3, deferred four-FFT algorithm |
| 20 | Section 4, missing full definition, section 4.1 amortization and blocks |
| 21 | Missing step-DFT/step-K algorithms, block-offset de-amortization |
| 22 | Local partial-K formula, Theorem 4 proof sketch, generic compiler |
| 23 | Protocol 3, compiler bound, section 5 hardware/software, section 5.1 begins |
| 24 | Figure 1, synthetic support design and footnote 4, public/private prep times |
| 25 | Table 2, Figure 2, explicit quadratic implementation choice, timing comparisons |
| 26 | Figure 3, speedup regions, proof/verification size, section 5.2 |
| 27 | Table 3, comparison limits, acknowledgments, references begin |
| 28 | References, including EFG22/FK23/FHM01 |
| 29 | References, including GGS87/Gro16/LJGK25/RT97 |
| 30 | References through ZFZS20, final page; no appendix follows |

**P:** This supplied PDF has **no appendices**. Despite being 30 pages, it repeatedly defers content to a "full version": formal zkSNARK/AGM/q-DLOG definitions (p9); Theorem 1 proof (p15); SparseConv algorithm (p16); truncated-basis/diagonal proofs (pp16-17); Theorem 3 proof (p18); four-FFT Groth16 method (p19); full dynamic definition (p20); step-DFT/step-iDFT and step-K details (p21); complete serial evaluation tables (pp25-26). Theorem 4 has a proof sketch on p22. The sparse zkSNARK extension is explicitly deferred on p5. Reading all supplied pages does not make these omitted algorithms/proofs present.

## 2. Parameter map and actual update cost

**P:** Section 2.1 p9 uses matrices `A,B,C in F^(n x m)`, `z=(1,x,w) in F^m`, `x in F^(k-1)`, `w in F^(m-k)`. Thus **n is row/constraint count**, **m is assignment length**, and **k includes constant one**. Section 3.2 pp12-13 defines `d=|supp(z'-z)|`; it assumes, only for its clean asymptotic statements, `|DeltaA|,|DeltaB|,|DeltaC|=O(d)`. It explicitly says a dense changed column can violate that assumption while the algebra still works. The paper does not equate a registry-leaf change with d.

**C/E2:** The project calls the raw constraint count `m=648156` in older reports, but this is paper-n's role. Avoid reusing those letters ambiguously:

| Explicit project name | Existing audited value | Paper role / qualification |
|---|---:|---|
| `constraint_rows` | 648,156 | Paper n before zero padding |
| `assignment_len` | 643,563 | Paper m, including constant one |
| `instance_len` | 6 | Paper k; five public values plus one |
| `auxiliary_len` | 643,557 | Paper m-k |
| `domain_size N` | 1,048,576 | Paper subgroup n for the padded construction |
| `s_z` | Near transition 5,081 | Nonzero assignment-coordinate changes, not one leaf |
| `s_A,s_B,s_C` | Near 2,390 / 2,370 / 2,370 | Row-change supports after cancellation, reported in prior census |
| `t_A,t_B,t_C` | Not measured here | Matrix entries visited through changed columns, with multiplicity |
| `u_A,u_B,u_C` | Touched-row counts | Before coefficient cancellation; code may retain canceled entries |

**D:** Zero-pad the matrices/evaluation arrays to N consistently, retaining assignment length and k separately. Let `t_A=sum_{j in supp(e)} nnz(A[:,j])`, similarly B/C. Matrix-delta generation costs at least visited-entry work; a sparse result does not remove that cost. The inspected gather/sort algorithm costs `O(t_A log t_A+t_B log t_B)` plus allocation, independent of the subsequent proof correction. No C-column index is used by the reference updater, but C is still necessary for checking the new relation.

**C:** `utils.rs:11-49` materializes changed-column contributions, sorts, sums equal row indices, and **keeps zero sums**. Consequently loop lengths can follow u_A/u_B rather than s_A/s_B. `SparseRecord::parse/parse_unordered` (`dynamic_cache.rs:60-65`) similarly retains canceled values in its touched-index list. Canonical support must be obtained after combining duplicates and removing zero sums.

**P:** Table 2 p25 gives semi-dynamic group count `(4|DeltaZ|+2|DeltaA|+2|DeltaB|)G` and full dynamic `(4|DeltaZ|+b+3|DeltaA|+3|DeltaB|+n(6+2 log n)|DeltaZ|/b)G`. These are paper counts for its evaluation/construction, not instrumented counts of this BN254 adapter. The table omits field and matrix-gather work. It says DeltaC does not enter proof update because validity fixes its row evaluations. Section 5.1 pp23-24 uses synthetic square matrices `m=n` and `|DeltaZ|=2d`, `|DeltaA|=|DeltaB|=d`; footnote 4 warns that setting all three equal to d does not produce a meaningful R1CS update. Its experimental d is therefore an explicitly chosen support parameter, not automatically the section-3.2 assignment-distance convention.

## 3. Reviewed quotient, diagonal, public setup, and randomization algebra

### 3.1 Quotient versus remainder and C

**P reproduced:** Equations (1)-(3), pp10/14, set `A(X)B(X)-C(X)=q(X)(X^N-1)` for valid assignments, with all A/B/C degrees below N. Section 3.2 p14 obtains

`(q'-q)(X^N-1) = DeltaA B + DeltaB A + DeltaA DeltaB - DeltaC`.

**D:** For polynomial **quotient** `Quo_N(f)=quotient(f,X^N-1)`, linearity and `deg(DeltaC)<N` yield

`q'-q=Quo_N(DeltaA B)+Quo_N(DeltaB A)+Quo_N(DeltaA DeltaB)`.

This does not license ignoring satisfaction. The remainders are canceled by DeltaC only for valid old/new assignments. A direct division notation is not multiplication by `(tau^N-1)^(-1)` on arbitrary evaluations. Reference routines compute encoded quotient polynomials with `h_i=tau^i(tau^N-1)/delta`; they are not committing to the rational function including its remainder.

### 3.2 Theorem 1 and truncated basis

**P reproduced:** Section 3.3, Theorem 1 p15, equations (4)-(6), for i!=j:

`phi_ij=w_(j-i) ell_i+w_(i-j) ell_j`,

`ell_i ell_j=phi_ij Z`; `ell_i^2=phi_ii Z+ell_i`; `phi_ii=-sum_{j!=i}phi_ij`.

For nonzero t modulo N, `w_t=omega^t/[N(1-omega^t)]`, `w'_t=w_(-t)`. The printed vector includes t=0 even though its denominator is zero. **C/D convention:** define `w_0=w'_0=0` for the off-diagonal kernel; handle diagonal products through phi_ii/p_i. `dynark_generator.rs:70-95` implements this convention and the factor 1/N.

**D checked independently:** With `x_i=omega^i`, `ell_i(X)=x_i Z(X)/[N(X-x_i)]`. Partial fractions give the displayed phi_ij for i!=j. Summing `ell_j=1` implies `sum_j ell_i ell_j=ell_i`, so quotient linearity gives the diagonal identity. Off-diagonal leading coefficients cancel; therefore each phi_ij and phi_ii has degree at most N-2. This independently validates the identities despite the paper deferring their proof.

**P/C:** Pages 16-17 define `ellbar_i=(1/N) sum_{j=0}^{N-2}(omega^i)^(-j)X^j`. Adding a zero group element to the N-1 H-query and applying iDFT constructs `[ellbar_i(tau)Z(tau)/delta]`. It does **not** construct the untruncated degree-N-1 Lagrange commitment. The omitted leading terms cancel in complete quotient expressions. This is why no extra H-query/trapdoor is needed.

**P reproduced/C checked:** With `L=[ellbar]_1` and `p_i=[phi_ii(tau)Z(tau)/delta]_1`, page 17 gives

`p=-(sum_t w_t)L-w*L`.

`dynark_generator.rs:59-66,97-104` follows this: zero-pad the H-query, iDFT, then negate both the scalar-sum term and convolution term. Protocol 2 G4 p19 places the minus outside parentheses around **both** terms; its sign is consistent with p17 and code.

### 3.3 Projection preprocessing

**P reproduced:** Theorem 2 p17 says `A ell_i=q_i^A Z+a_i ell_i`, and

`q^A=w*(a circ ell)+(w'*a) circ ell+a circ phi_diag`.

Pages 18/19 use the same orientation on the truncated encoded basis:

`[q^A]=w*(a circ L)+(w'*a) circ L+a circ p`, and similarly B.

**C:** `compute_projection_quotient`, `dynark_prover.rs:37-73`, exactly uses w on the field-times-group convolution and w_reverse on the field convolution. It then adds the diagonal a*p/b*p. `fft_handler.rs:1176-1215` uses full-domain circular convolution; it is not SparseConv. `process_dynark:234-245` derives a/b/c from the supplied anchor assignment and installs the two vectors.

**D:** Expanding `q_i^A=sum_j a_j phi_ij` yields `sum_{j!=i}a_j w_(i-j)ell_j + (sum_{j!=i}a_j w_(j-i))ell_i+a_i phi_ii`, which confirms both convolution orientations. Theorem 2's rendered formula agrees with pp18/19; text extraction placed the prime misleadingly. No theorem-orientation erratum is asserted.

**P claim, not measured here:** Page 18 claims about 2x faster projection preparation than FK23 from circular instead of linear convolution. This is not a 2x improvement over this project's old private preparation, and no FK23 differential benchmark was run. E2's existing no-cache full comparator is a separate proving result; it does not test that preparation claim.

### 3.4 Cross and diagonal correction

**P reproduced:** Equations (7)-(8) p15 and complexity p17 use `I=I_A union I_B`, zeros outside each support, and

`cross = sum_{i in I} (DeltaA_i SparseConv_w'(DeltaB,I)_i + DeltaB_i SparseConv_w'(DeltaA,I)_i)L_i + sum_i DeltaA_i DeltaB_i p_i`.

Here `SparseConv_w'(a,I)_i=sum_{j in I,j!=i} a_j w'_(i-j)`. The diagonal is a separate p_i term; setting w_0=0 prevents singular self-interaction and does not remove that diagonal term.

**C:** `update_dynark:311-346` implements the two off-diagonal orientations as separate nested loops and a two-pointer overlap merge for p. Their sum matches equations (7)-(8) after interpreting `w_(j-i)=w'_(i-j)`. One-sided, missing-p, or untruncated-basis substitutions are incorrect. `FullyCheckpoint::calc_cross_terms:459-504` repeats the same formula.

### 3.5 Randomized linear proof update

**P reproduced from section 3.2 p13, not the erroneous Protocol 2 line:** For fresh r',s',

`A'=A+(r'-r)delta_1+sum e_j u_j`,

`B2'=B2+(s'-s)delta_2+sum e_j v2_j`, and analogous B1',

`DeltaC_lin=s'A'-sA+r'B1'-rB1-(r's'-rs)delta_1+sum_{j>=k} e_j tp_(j-k)`.

**C:** `update_dynark:265-302` implements these signs. Auxiliary indices are global assignment indices and are translated to private query positions by subtracting k. Only auxiliary changes enter tp; public changes update the statement supplied to verification. The proof update returns a complete ordinary A/B2/C proof while leaving the original anchor unchanged.

**Visually confirmed paper inconsistencies, to resolve explicitly before transcribing protocols:**

| Printed locator | Issue | Evidence-based interpretation |
|---|---|---|
| Protocol 2 G2 p19 vs Theorem 1 equation (6) p15 | G2 omits factor 1/N in w,w' | Eq(6), direct Lagrange algebra, and code `generator:70,82` require it |
| Protocol 2 U5 p19 vs section 3.2 p13 | U5 prints `+s[A]` | Taking C'-C requires `-s[A]`; executable updater uses minus |
| Eq(6) p15 | t=0 denominator is undefined without a convention | Code sets zero and handles the actual diagonal via p_i |
| Section 3.4 p18 displayed projection equality | Written product equals a sum of quotient polynomials, omitting Z and remainders | Interpret as quotient discussion using Theorem 2, not literal equality of degree-2N-2 products |
| Section 3.4 p18 prose | Says projection can be computed in O(n) groups | It is a valid loose bound; its own complexity line correctly gives O(d) under sparse supports |
| Protocol 1 p10, G5/P5 | VK tv printed in group 2 while verifier uses group 1; P5 starts private sum at k+1 despite tp definition beginning at k | Code uses group 1 tv and all auxiliaries from k; section 3.2 p13 uses [k,m] |
| Protocol 2/section 3.2 witness notation | Occasionally writes z=(x,w), omitting fixed one or using shorthand inconsistent with full m | Maintain the original R1CS definition z=(1,x,w), with e_0=0 |

Extraction-only false alarms were corrected by renders: Theorem 2's w/w' orientation and G4's diagonal sign are consistent. Parent was notified immediately of both true findings and these retractions.

## 4. Complete algorithm-to-reference inventory

All source locators below are beneath `experiments/dynark/vendor/DYNARK_/ark-groth16/src/` unless an example path is given. **Implemented** means inspected equations/dataflow, not a new test pass or production qualification.

| Advertised algorithm / exact paper locator | Inputs, output, retained state | Reference locator and conformance status |
|---|---|---|
| Groth16.G, Protocol 1 p10; equations (1)-(3); Lemma 1 p11 | Fixed indexed R1CS and randomness -> PK/VK/H query | `dynark_generator::groth16_setup_dynark:19-47`, `generate_prover_key_with_matrices:143-264`, `compute_u_v_w:270-304`: development setup for constraint-only QAP, zero padding; agreement with its own reduction. Not an original-zkey adapter |
| SemiDynark.G, Protocol 2 p19; sections 3.3/3.5 pp16-18 | Existing public PK/domain/matrices -> L,p,w,w', FFT kernels, A/B column indexes | `generate_updating_keys:51-138`: public-only derivation implemented; PK cloned inside UK. Requires exact H-query basis/scaling/domain. Constant public package; no private witness/trapdoor input |
| Optional trapdoor-assisted public preparation, section 3.5 p18 / setup evaluation p24 | Valid setup trapdoor -> extra public bases faster during ceremony | No dedicated optimized UK-with-trapdoor path inspected. Existing generator produces PK from toxic-waste tuple and then public derivation separately. Not required for compatibility; must not use development trapdoor for product derivation |
| Groth16.P / SemiDynark.P, Protocols 1/2 pp10/19 | Valid z and fresh r,s -> ordinary proof plus retained randomness | `prove_dynark:143-230` implemented but also builds base Cache; `calc_raw_proof:77-139` builds zero-blinder raw proof for full dynamics. `prover::create_proof_with_assignment` is no-cache route; matrix wrapper drops constant one (known C02) |
| SemiDynark.K, Protocol 2 p19; Theorem 2 pp17-18 | UK + anchor a,b -> two private projection vectors D | `process_dynark:234-245`, `compute_projection_quotient:37-73`, dense convolution helpers: implemented. Private cache includes proof components/r/s beyond paper D; caller must bind them to same anchor |
| Delta calculation / matrix sparsity, section 3.2 pp12-13 | e=z'-z -> DeltaA/B/C | `utils::improved_lagrange_sparse_get:11-49` implements indexed A/B calculation but retains zeros and trusts indices; `lagrange_of_dense_vec:56-86` evaluates A/B/C densely. C omission from update agrees only under validity; sparse C validation/index is not implemented here |
| SemiDynark.U linear/rerandomization, section 3.2 p13 / Protocol 2 U3-U5 p19 | Anchor proof/r/s + e -> current A/B1/B2 and private linear C correction | `update_dynark:265-302`: implemented correctly against p13, correcting printed U5 sign. OS RNG pre-existing patch, not caller fallible CryptoRng contract. APIs trust instance/aux split |
| Cross quotient, Theorem 1/equations (4)-(8) p15; Protocol 2 U6 p19 | Sparse A/B row deltas -> encoded cross quotient incl diagonal | `update_dynark:311-346`, `FullyCheckpoint::calc_cross_terms:459-504`: two quadratic field loops plus overlap; algebra matches supplied decomposition |
| Fast SparseConv_w', section 3.3 p16 / Protocol 2 U6 p19 | Support-local coefficients -> support-local fixed-kernel outputs in O(s log²s) | No product tree, rational numerator, multipoint/remainder tree, or matching fast sparse method in inspected source. Full algorithm omitted from supplied paper. Section 5.1 p25 explicitly says authors use quadratic for experiments; absence is asymptotic capability gap, not evidence of accidental benchmark nonconformance |
| Projection correction, equation (9) p17 / complexity p18 / Protocol 2 U7 | Private qa/qb + sparse row deltas -> encoded projection sum | `update_dynark:307-308`; `FullCache::calc_update_a/b:180-189`: implemented sparse group sums |
| Ordinary V, Protocols 1/2 pp10/19 | VK + current public instance + complete proof -> accept/reject | `dynark_verifier:23-54` expects full instance incl one; ordinary `verifier::prepare_inputs:28-41` expects public values without one. Pairing equation unchanged; adapter identity/order still required |
| Four-FFT full Groth16 prover, contributions p3 / p19 | Same PK/valid z -> same ordinary proof with four N-size FFTs | Advertised but algorithm deferred; absent from reference path: all inspected quotient routes use seven transforms, including the one named optimized. See exact count below |
| Sparse Groth16 extension, overview p5 | Sparse witness -> full proof with O(s)G + O(s log²s)F | Full construction deferred. Reference semi updater could start from a specially justified valid anchor, but no dedicated generic sparse-prover construction/API proof was inspected. Do not claim this extension implemented |
| FullyDynark.G/K/P/V, Protocol 3 p23 | Same setup/prep/proof/verification as semi scheme | Shared source above. `FullyCheckpoint::new/new_with_qached_quotient:383-437` create raw proof and full cache; caller n/domain agreement unchecked |
| partial-K, locality formula section 4.1 p22 / Protocol 3 U2 p23 | Previous-block projection cache + accumulated A/B changes + current needed indices -> only current projection entries | No method named partial-K. `update_from:508-560` / `sim_update_from:564-632` instead add two accumulated/current cross corrections, algebraically equivalent quotient correction. Different concrete group/field tradeoff; not a direct implementation of printed partial-K subroutine |
| step-DFT/step-iDFT/step-K, section 4.1 p21 / Protocol 3 U4 p23 | Frozen rebuilding-anchor a/b + work budget + progress -> updated projection reconstruction state | `FullCache::flash:172-177`, `step_forward:192-355`, `fft_handler::sqrt_fft_fw_field:1253-1382`, `sqrt_fft_fw_g1:1386-1515`: concrete state machine present, algorithm details omitted from paper. Validity/progress not generally established; known E3 domain/remainder/odd-log failures remain |
| Block offset and checkpoint replacement, section 4.1 pp20-22 / Protocol 3 U5 p23 | Active old-anchor cache, building new-anchor cache, cumulative update distance -> atomic generation shift | Two-checkpoint in-memory schedule only in `examples/fully_dynamic.rs:78-80,113-157`; source helpers `copy_proof_from:662-666`, `trivial_append:636-645`. No production library coordinator, parameter-b policy, authenticated persisted generation swap, or overshoot specification |
| Full dynamic fresh rand', section 4 p20 / Protocol 3 U3/U6 | Current raw proof + fresh independent r,s -> ordinary randomized proof | `get_proof_with_rs:648-659` algebraically adds blinders, but constructs test_rng twice; known production ZK blocker. Not fixed here |
| Generic semi-to-full compiler, section 4.1 pp22-23 | Stepwise K of cost T(K), U locality/cost, b -> de-amortized updater | DYNARK-specific FullCache implemented; no generic compiler/API or proof obligation instantiated for arbitrary semi-dynamic schemes. Paper bound is a construction-level theorem, not a generic delivered library |

**C exact full-prover transform count:** `R1CSToQAP::compute_quotient:126-158` calls iDFT(A), iDFT(B), coset DFT(A), coset DFT(B), iDFT(C), coset DFT(C), coset iDFT(AB-C)/Z at lines **132,133,137,138,144,145,156**. `compute_quotient_optimized` repeats seven at **203,204,208,209,222,223,234**. `LibsnarkReduction::compute_quotient_from_matrices` repeats seven at **394,395,399,400,413,414,425**. Static call count is not a timing or profiler measurement. The current E2 no-cache full path uses a correct direct call and still uses the seven-transform quotient; its independent verification does not show the advertised four-FFT method exists.

## 5. Concrete fast sparse kernel: independently derived candidate

**P:** The actual omitted operation is not an ordinary sparse-to-dense FFT. Section 3.3 p16 needs two products of a support-local vector by the fixed **zero-diagonal reciprocal-difference kernel**, returning only I entries. A dense N-size convolution would cost O(N log N) and does not achieve the stated support-size bound.

**Primary-source corroboration:** DYNARK cites GGS87 p29. The [SIAM primary abstract](https://epubs.siam.org/doi/abs/10.1137/0908017?journalCode=sijcd4) defines Trummer multiplication by off-diagonal `1/(c_i-c_j)`, with distinct nodes and O(k log²k) arithmetic cost. Full text was not accessible: its PDF link redirected to the paywalled abstract; no login/payment was attempted. The [author-hosted Olshevsky/Pan paper](https://www2.math.uconn.edu/~olshevsky/papers/icalp99.pdf), section 1 p586 and sections 2-3 pp586-588, describes exact polynomial/rational evaluation over fields and the O(M(k) log k) style approach, with its explicit FFT multiplication assumption. These sources justify the algorithm family; the DYNARK-specialized finite-part formula below is **D**, not a transcription of either missing GGS87 full text or DYNARK pseudocode.

**D derivation and reviewable algorithm:** Let `s=|I|`, unique nodes `x_i=omega^i`, and vector a supported on I. Then

`w'_(i-j)=x_j/[N(x_i-x_j)]` for i!=j, hence `SparseConv_i=(1/N)sum_{j!=i}a_j x_j/(x_i-x_j)`.

Define `c_j=a_j x_j`, `D(X)=prod_{j in I}(X-x_j)`, `P_a(X)=sum_j c_j D(X)/(X-x_j)`. The rational function `P_a/D=sum_j c_j/(X-x_j)` has a simple pole at each x_i. Its finite part at x_i is

`sum_{j!=i}c_j/(x_i-x_j) = P_a'(x_i)/D'(x_i) - c_i D''(x_i)/(2D'(x_i))`.

Proof: write `D=(X-x_i)D_i`, `P_a=c_i D_i+(X-x_i)R_i`. Differentiation at x_i gives `P_a'=c_i D_i'+R_i`, `D'=D_i`, `D''=2D_i'`, and `R_i/D_i=sum_{j!=i}c_j/(x_i-x_j)`. No singular division at x_i is performed. Distinct nodes ensure D'(x_i)!=0; N and 2 are invertible in the supported odd-characteristic field.

The concrete candidate is:

1. Normalize A/B sparse inputs, form sorted unique union I, align zero coefficients, compute x_i from the validated domain generator. Reject duplicate-node ambiguity; return empty/zero for empty/singleton off-diagonal support.
2. Build a balanced **subproduct tree** whose leaves are `(X-x_i)`. For each input a/b, build a **numerator tree** with leaf c_i and merge `P_parent=P_left D_right+P_right D_left`. Root is P_a/P_b. This avoids assuming interpolation is already available.
3. Differentiate D to D'/D'', and P_a/P_b to P_a'/P_b'. Evaluate those polynomials at all x_i with the same **remainder tree**, using fast polynomial division/remainders.
4. Batch-invert nonzero D'(x_i), multiply by N^-1, subtract the diagonal finite-part contribution as above. Return the two coefficient vectors in I order.
5. Form `DeltaA_i convB_i+DeltaB_i convA_i` on L_i and `DeltaA_i DeltaB_i` on p_i; use exact group summation/MSM. Compare the complete encoded quotient to the quadratic oracle before producing randomized proofs.

Required data structures absent in reference: canonical support/index-to-slot map, support-domain nodes, shared product/remainder tree, fast polynomial multiply/divide implementation, two numerator trees/buffers, derivative evaluations and batch inverses, bounded scratch allocator, and explicit memory/domain limits. A retained tree has O(s log s) coefficients with a straightforward representation; more economical scheduling is possible but not claimed here. Building the tree is part of the update cost unless the **exact support** is reused. Reusing a denominator tree for changed support is incorrect. Fast polynomial multiplication must independently validate its required convolution length and field two-adicity: support and intermediate polynomial products can require a larger transform than the original N-point evaluation domain. Availability of that original domain alone is insufficient. Use a supported larger domain or a documented fallback, and include that choice in the complexity and memory claims.

**D bound:** The recurrence across log s levels costs `O(M(s) log s)` field arithmetic, assuming suitable fast polynomial multiplication/division. Under `M(s)=O(s log s)`, this is `O(s log²s)`; group summation remains O(s) scalar multiplications. Sorted union costs O(s) once individual supports are normalized. Root-power generation, normalization, tree setup, allocation and all evaluations must be included in a measured crossover. Tiny s can favor the nested oracle exactly as p25 reports. This is a candidate derivation awaiting parent/cryptographic review and Phase 2 implementation; no asymptotic or empirical local achievement is claimed.

**D exact hand check, not an executed test:** In F17 take N=4, omega=4, I={0,1}, a=(2,3). The naive result is `(3*w_1,2*w_3)=(16,3)` with w_1=11,w_3=10. Nodes are 1,4, weights c=(2,12), `D=X²-5X+4`, `P=14X+14`; the finite-part formula gives `(13/4,12/4)=(16,3)` modulo 17. This fixes the kernel orientation, N scaling and diagonal removal on a nontrivial example.

## 6. Full dynamic locality, reconstruction, and replacement

**P:** Section 4.1 pp20-23 keeps preprocessing for the previous block's first witness while gradually building preprocessing for the current block's first witness. For b approximately sqrt(N log N), smooth K work is charged proportionally to **current transition distance**; previous-anchor distance can be up to 2b. Large single updates above b rerun prep according to p20. With locality, only projection entries needed for the current update are corrected, giving `O(dN log N/b+db)G+O(d log²d)F`. Protocol 3 stores t, both block witnesses, semiD, and the intermediate state; returns fresh proof/randomness and D'. It is online and does not require future witnesses.

**D locality from the reviewed Theorem 2:** If alpha is accumulated A-row change from preprocessing anchor to current witness, the current projection at requested row i is

`q_i^A(current)=q_i^A(anchor)+sum_j alpha_j phi_ij`.

For i!=j, phi_ij has the two public L_i/L_j components; i=j contributes p_i. The analogous beta correction updates q^B. Computing only current-needed entries directly costs O(current support * accumulated support) group work. Then the **current-only** DeltaA*DeltaB term can use SparseConv on current support. This is the paper's locality route, not an assumption that a new projection depends only on one row of the anchor.

**C/D reference equivalent decomposition:** In `update_from`, before the transition let alpha,beta be `mod_a/mod_b`, and da/db the current row deltas. Code appends da to mod_a first, reads old mod_b, then appends db. C receives

`Quo(a_anchor db+b_anchor da) + Quo((alpha+da)db)+Quo(da beta)`

plus the private linear query, matching the full quotient difference. This is correct algebra if frozen projections, mods, and raw proof share the declared anchor/current generations. It groups contributions on L/p before multiplication, trading more field work for fewer group multiplications. Typical accumulated-current cross calls visit O(b*d) pairs and use O(b+d) grouped multiplications rather than directly materializing d projection corrections with O(db) groups. Cancellations and matrix row fanout replace ideal b/d by their real support/touched sizes.

**Critical fast-path distinction:** Replacing these two calls with the section-5 product tree over their **combined accumulated/current union** costs O((b+d)log²(b+d)) field work, even when the current update has distance 1. It therefore does not by itself establish the paper's per-transition O(d log²d) field claim. Phase 2 must choose/document one route: (a) exact direct locality/partial-K plus current-only fast cross term, charging its O(db) group work; (b) retain the reference grouped correction with an honest accumulated-support field bound and measured tradeoff; or (c) derive/review an additional multi-support algorithm. No stronger bound follows automatically from a function named SparseConv.

**C reconstruction dataflow:** `flash` folds mods into acc_a/b and clears them, freezing the rebuild witness. `step_forward` then overwrites the rebuilding q vectors through **VecPrepare -> Dft -> PointwiseProduct -> IDft -> VecIntegrate**. It computes p*acc plus `w*(acc*L)` and `(w'*acc)*L`; updates arriving during reconstruction are recorded separately in mods. A building cache must never be used as active until its projections are complete. Four DFT streams (two groups/two fields) share progress and are checked for synchronized finish. This is a concrete implementation of the paper's smooth-prep concept, not the omitted paper step-K algorithm verbatim.

**C schedule:** The author example allocates/clones two FullyCheckpoints. For each generated transition, it drives reconstruction, copies the active **current raw proof** into the completed checkpoint, swaps the two, flashes the old active to freeze a new rebuild anchor, then appends the current delta to the rebuilding checkpoint and calls update_from on the active one. `copy_proof_from` copies only raw A/B1/B2/C; preserving the completed q anchor and its pending mods is intentional. Arbitrarily replacing an anchored Cache's proof/r/s while keeping unrelated projections is not this protocol.

**D required generation invariants:**

1. Active q_a/q_b are complete projections of a named immutable `projection_anchor`.
2. Active mods are precisely A/B changes from that anchor to the current raw-proof witness; canceled sums are tracked algebraically and excluded from numerical support counts.
3. Rebuilding acc_a/b represent a frozen `rebuild_anchor`; q scratch is unusable until all phases finish. Rebuilding mods represent changes strictly after that frozen snapshot.
4. Current raw proof and public statement belong to the same current assignment. Copy/swap can change ownership but not their logical statement.
5. Commit/swap installs complete projection vectors, anchor generation, current mods/raw proof/public statement and progress metadata together. Persistence/reload and interruption must not mix generations.

**C/D remaining schedule obligations:**

- `FullyCheckpoint::new` stores caller n even though domain construction may round up; `FullCache::new` computes half size from `n.trailing_zeros()`. Use validated **N**, never raw constraints or variable count. For existing raw 648156, N is 1048576 and the mistaken half size is 2 rather than 1024 (existing audit, not a new execution).
- `step_forward` floors `(n-id)/batch`, so a remainder smaller than its fixed batch may produce no progress while its loop still has budget. Known E3 toy failure and odd-log FFT differential failures are existing observations; this worker did not rerun them.
- Square-root FFT code uses equal half dimensions `2^floor(logN/2)`. Either correctly implement rectangular factors for odd log N or explicitly reject unsupported shapes before allocation/update. Merely choosing a power-of-two N does not ensure even log N.
- Concrete work steps bundle row transforms/2048-element vector batches; they are not automatically constant-cost or the paper's abstract b steps. Calibrate charged operations and maximum indivisible work before claiming a per-call stall bound.
- Protocol 3 p23 handles `t'=b` by equality. It does not specify arbitrary-budget overshoot or d=0. Define threshold-crossing/splitting, leftover budget and multiple crossings; a literal equality can miss a boundary. This is an under-specified implementation case, not a proof that the inspected author example suffers that exact t bug (it uses completion/remaining-step results instead).
- Schedule by cumulative **accepted transition work/distance**, not net anchor support: cancellation/repeated writes can reduce anchor support without refunding work. Record anchor distance separately for correction cost. Large updates may select verified full proof/rebase and reset both generations; no-op may rerandomize without corrupting progress or creating fictitious distance.
- `get_proof_with_rs` uses test RNG twice. Even correct raw algebra/schedule does not close zero-knowledge, secure randomness, persistence or setup concerns.

## 7. Bounded Phase 2 task corrections and falsifiable acceptance

These are concrete amendments for the parent plan; no Phase 2 source changes are authorized by this evidence file. Prerequisite order separates valid algebra, secure boundaries and observed economics.

| Task | Exact bounded work / correction | Acceptance that can fail |
|---|---|---|
| P2-A: normalized domain/delta contract | Explicit constraint rows, assignment length, k, N, generator and H-query basis identity; reject constant mutation, noncanonical fields, wrong public/aux split and mismatched key/cache. Combine duplicates; remove zeros/cancellations; count t/u/s separately | Hand-constructed rectangular matrices with sparse/dense columns, duplicate changes and canceling coefficients match dense A/B/C products exactly; malformed indices return errors before indexing; five-public/non-square fixtures verify ordinary proofs |
| P2-B: public algebra conformance | Preserve Eq6 N^-1, w0=0, both diagonal minus terms and truncated basis; document corrected Protocol2 U5 and Protocol1 offsets. Derive UK from a matching **public** ordinary PK without trapdoor | Small-domain coefficient-level polynomial quotient oracle matches every phi_ij and q_i; public UK computed by two independently expressed constructions agrees; no extra N-1 H-query/secret input allowed; incompatible reduction/keys are rejected |
| P2-C: fast semi cross kernel | Implement section-5 candidate only after derivation review; explicit canonical union/product and remainder trees; quadratic kernel remains oracle; include all tree/multipoint setup and memory limits | Exact field outputs and encoded quotient match naive loops for empty/singleton/disjoint/overlap/all-overlap, wraparound indices 0/N-1, unbalanced A/B supports, cancellation and randomized BN254 cases. Compare directly to polynomial division as an independent oracle. Complete updated proofs verify through unmodified ordinary verifier; invalid new assignments must fail validation/verification. Operation-count scaling supports O(s log²s); performance crossover includes tree allocation/setup and may legitimately favor naive |
| P2-D: secure proof randomness | Caller `RngCore+CryptoRng` or equivalent fallible entropy contract for full/semi/full-dynamic, no production test_rng reachability | Inject controlled distinct blinders to check exact delta formula; no-op updates verify and change under fresh RNG. Entropy failure produces error. Distinct proof bytes alone do not certify ZK; dependency/build and distribution checks remain |
| P2-E: explicit local partial-K versus grouped reference | Choose and document full-dynamic correction route with group/field bounds; current-only cross fast path is separate from accumulated correction | For alpha/beta/da/db, compare selected projection entries to freshly recomputed complete q; raw proof matches fresh zero-blinder full proof after each update. Vary current d=1 while accumulated support grows to b to expose hidden field complexity; all loop/transform/tree work counted |
| P2-F: reconstruction kernel and budgets | Validated N; correct or reject odd-log FFT factors; tail-batch progress; monotonic phase/index progression and defined zero budget | Field/group DFT and inverse compare exactly with ordinary domain FFT for N=16,32,64,128,256 and chosen larger shapes; all budget partitions (0,1,small,overshoot) yield the same complete projection as eager K. Each positive accepted budget must consume work or complete; all vector-tail cases terminate under bounded watchdog. Real matrix/domain smoke follows kernels |
| P2-G: full coordinator and atomic generation swap | Library API owns active/building/current identities, cumulative distance, threshold overshoot, cancellation and large-update full fallback. Persist/recover generations atomically | At least 1,000 bounded synthetic transitions, including repeated same-coordinate writes/cancellation, batches crossing 1/multiple boundaries, changed public values/no-ops, and at least two complete swaps. Every proof verifies independently; selected/full q and raw proof agree with full computation. Interrupt/reload at every reconstruction phase and boundary yields identical accepted state or safe rebuild, never mixed generations |
| P2-H: four-FFT claim as separate missing capability | Obtain full specification or explicitly derive/review a matching four-FFT quotient algorithm. Preserve the seven-transform baseline rather than conflating no-cache engineering with this claim | Same reduction, H query, valid padded z: quotient coefficients/group Q match seven-transform oracle, ordinary proof verifies, static/runtime transform accounting shows exactly intended four N-size transforms and charges all hidden larger transforms. If absent, label advertised optimization unimplemented |
| P2-I: measurement and setup interoperability | Profile fixed public/private prep, clones/scratch and exact transformed inputs first; original `.zkey` compatibility remains independent | Compare no-cache full, current semi, optimized semi and full dynamics with same circuit/key/backend/RNG/thread limits. Report public prep/private prep/full-dynamic buffers/swap cost separately; independent verification and exact key/reduction hashes accompany trials. No claim about FK23's 2x or existing deployments without its specific comparator |

**E2 context, not this worker's result:** The existing audit reports supplied-witness no-cache full proof median 2.221 s versus anchored update 0.389 s (30 trials each), and complete local full/anchored refresh medians 5.417/3.587 s (10 each) for one repeated synthetic near transition. Those observations establish an independently verified bounded baseline, not a sequence/reconstruction, four-FFT, FK23-preparation, original-zkey or Solana result. Current paper reading should refine the Phase 2 inventory without silently promoting those capabilities or rerunning the benchmark in this research task.

## 8. Source hashes and executed-command record

The reference commit alone does not identify the two local patches. Observed SHA-256 hashes of inspected key source files:

| File under `ark-groth16/src/` | SHA-256 |
|---|---|
| `dynark_generator.rs` | `4bcb08ba6f1a1c4d55cb7136db5c8989e7f56ffb5e6c15f6e11956f6788b1103` |
| `dynark_prover.rs` | `5575e85562da40578887098dccd45652e5b985319ccc1bb3734fb5e33de447ac` |
| `dynamic_cache.rs` | `fecd160dd22b705326db22fb9b125d8d5ed82e2765f34179feedf665fdff5823` |
| `fft_handler.rs` | `a278d4e66f2b34f37380f0537e9560fe818f9bf65a099d1f045f24928ddf3a7e` |
| `r1cs_to_qap.rs` | `45b86e8b59522a0b7c5121326ad644f311c77517eb76d05440fab7321ba0b5e1` |
| `utils.rs` | `f89698fd651ae8129cc6a154bdbf59950fed5c2322c60526f667f87c960f2e00` |
| `data_structures.rs` | `272b6688d7352dbf329bb40b93f2d788ce10b33612ab05deacf63961e4a5a679` |
| `dynark_verifier.rs` | `f561c7d2dfd441953dbf5f53473e0047182e1b9fb1e308ff216988b9c01fd9ef` |
| `verifier.rs` | `b2ebfd34e80fd55b5f1a3d7c6deb28956ae1b0d37ca39067d2cbbebee2ffdf41` |
| `prover.rs` | `86a2bf4b20c03b2884374a9528f8c4a4eef9c83bbfcd4eb4efce8ffea82a4f16` |

Commands actually executed (read/small render work):

- `cat` read PDF/using-superpowers skills, research/code-audit/roadmap documents; using-superpowers directs dispatched subagents to skip its process.
- `rg -n 'DYNARK|Zk-fresh|dynark' .../memories/MEMORY.md`, then `sed -n '1,80p'` for quick context. Memory used only to retain evidence-vs-claims/feasibility scope; no memory measurement treated as current.
- `wc -l` checked layout text and planning documents; `sed -n` read text ranges **1-300,301-600,601-900,901-1200,1201-1500,1501-1750**, covering all 1698 lines.
- `pdfinfo .../2025-1897.pdf`; `shasum -a 256` checked both PDF files.
- `rg --files` inventoried source; a too-broad home/workspace AGENTS search hit protected macOS folders and returned status 2. It discovered no applicable workspace AGENTS. No later permission bypass/search broadening was attempted.
- `git -C .../DYNARK_ rev-parse HEAD`, `git ... diff --stat`, `git ... diff -- <two patched files>`; `shasum -a 256` hashed the ten source files above. Root Git was not created or used for edits.
- `nl -ba`/`sed -n` inspected all of dynark_generator, dynark_prover, dynamic_cache, relevant FFT parameters/convolution/stepwise FFT routines, data structures, QAP routines and both verification paths; author fully_dynamic example inspected read-only. `rg` searched advertised fast/four-FFT/partial/step method names and found no matching source implementation.
- `mkdir -p artifacts/dynark/phase-1/paper-review/algorithm-pages`; `pdftoppm -f 15 -l 19 -r 145 -png ... algorithm-pages/paper`; `pdftoppm -f 23 -l 25 -r 145 -png ... algorithm-pages/paper`. `view_image` inspected the seven pages listed above. No PDF was authored/edited.
- Web primary-source searches/open calls for GGS87/Trummer, SIAM PDF link, related Gerasoulis AMS PDF and Olshevsky/Pan author-hosted PDF. GGS87 link redirected to abstract; AMS returned 403; author-hosted PDF available. No source downloaded/changed in workspace.
- `apply_patch` added only this research evidence file. Final checks read its headings, links, hashes and vendor diff, without executing proof/test code.

## 9. Result limits and next action

The supplied 30 pages have been read completely and the inspected construction has exact page/equation/protocol/source mapping. The reference implements the practical quadratic correction advertised in evaluation, public UK and private projections, and a full-dynamic reconstruction substrate. It does not supply the nearly-linear SparseConv or four-FFT prover, and its general full-dynamic library/persistence/RNG/domain guarantees remain open. Full-paper **reading coverage**, construction algebra inspection, independent candidate derivation, reference performance conformance, and production security are distinct gates.

Next action: parent personally review the confirmed equations/Protocol 1 and 2 corrections, finite-part SparseConv derivation, full-dynamic correction tradeoff and generation/scheduling obligations; then amend authoritative Phase 1/Phase 2 documents and derive separately approved bounded implementation tasks. No scientific claim that the omitted full-version security proofs or exact source implementation have been checked should follow solely from this file.

Failures/risks: broad AGENTS search returned access errors; extraction misplaced prime/parenthesis scopes and was corrected through rendered-page review; GGS87 full text remained unavailable; original `.zkey` and full security definitions/proofs remain unreviewed here. Known E3 failures and E2 statistics were read as existing evidence only. No task was delegated, no model substitution occurred, and no baseline artifact/report/fixture/source was modified.
