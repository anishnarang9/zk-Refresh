# Supplied-paper security review and QAP compatibility decision

October 10, 2026. Read-only research worker `paper_security`, dispatched as GPT-6.1 Sol with high reasoning. Scope: every page of the supplied DYNARK paper, security definitions and claims, ordinary Groth16 inheritance, public inputs, retained state, setup-derived updating keys, and prior gate G4. This report changes no implementation, historical evidence, keys, deployment, or benchmark. The parent must personally review the consequential derivations before changing acceptance gates.

Evidence labels: **P** inspected primary paper; **C** inspected code; **D** independent derivation; **U** unresolved; **X** proposed experiment, not executed. Printed PDF page numbers equal one-based PDF pages.

## Source completeness and exact proof limits

**P:** The complete user-supplied file is [the pinned PDF](../../../../artifacts/dynark/phase-1/paper-review/2025-1897.pdf), SHA-256 `f851f11ed8ae8a6876dafe09373650098aa792b9f886019eea4d98060fa7b259`, 835,694 bytes, 30 pages. The supplied Downloads copy and workspace copy hash identically. PDF creation/modification metadata says May 11, 2026. The [ePrint entry](https://eprint.iacr.org/2025/1897) identifies received October 10, 2025 and revised May 11, 2026; metadata agreement does not independently prove remote byte identity. [Extracted layout](../../../../artifacts/dynark/phase-1/paper-review/paper-layout.txt) SHA-256 `1a3f5673805b3c70d78fc160009434bd2c5405d56aa593fe30e519bf2a0feb3f` was read from beginning to end.

Coverage: pp1-8 abstract, introduction, overview, related work, open problems; pp8-11 preliminaries, R1CS and Protocol 1; pp11-19 Definition 1, semi-dynamic algebra and Protocol 2; pp20-23 fully dynamic construction, theorem sketch and Protocol 3; pp23-27 evaluations; pp27-30 acknowledgments and all references. **There is no appendix in this 30-page file.** Source-complete review is achieved. Authors' deferred expanded material is a separate limitation, not an unread part of this supplied file.

| Material actually supplied | Exact locator and status |
|---|---|
| R1CS relation and ordinary proof equations | Section 2.1 pp9-10; Protocol 1 p10; Equations (1)-(3) p10 |
| Base security claim | Lemma 1 p11: q-DLOG in AGM; formal zkSNARK/AGM/q-DLOG definitions explicitly deferred in Section 2.1 p9 |
| Semi-dynamic definition | Definition 1 pp11-12, including perfect completeness, extractor knowledge soundness, displayed ZK equalities, succinctness and updatability |
| Quotient decomposition | Theorem 1 and Equations (4)-(8) p15; proof explicitly deferred to a full version |
| Fast sparse convolution | Section 3.3 p16 names simplified GGS87 method and bound; algorithm itself deferred |
| Public H-query conversion | Section 3.3 pp16-17 gives truncated-basis and diagonal construction; some proofs deferred |
| Projection algebra | Theorem 2 p17 and operational formulas p18 |
| Semi-dynamic security theorem | Theorem 3 p18 is stated, its proof explicitly deferred; Protocol 2 p19 is supplied |
| Fully dynamic security definition | Section 4 p20 explains that sequences and updated D/rand are included, but formal definition deferred |
| Stepwise transform/preprocessing algorithms | Section 4.1 p21 explains interface and smoothness, detailed algorithms deferred |
| Fully dynamic security theorem | Theorem 4 p22 has an inheritance/correctness sketch, not a detailed extractor/simulator proof; Protocol 3 p23 supplied |
| Four-FFT ordinary prover | Section 3.5 p19 announces it; algorithm deferred |

Bounded expanded-source search, October 10: primary-domain searches for `Dynark full version` and `Dynark appendix` on ePrint and the two authors' sites returned no results. [Tianyu Zhang's page](https://tnyuzg.github.io/) and [Yupeng Zhang's publication page](https://zhangyp.web.illinois.edu/publications.html) both link only the same ePrint entry. The entry was accessible; its linked [versions endpoint](https://eprint.iacr.org/archive/versions/2025/1897) and PDF endpoint returned HTTP 403 to the web tool. No separate expanded file was located. No outreach, account login, purchase, challenge bypass, or guessed archive-version request was performed. **The supplied paper is available and fully reviewed; only the specifically deferred material remains unlocated.**

## What the stated security claims cover

**P:** Definition 1 pp11-12 gives K the old valid instance/witness and gives U both valid old/new pairs, the old proof, randomness and preprocessing. Completeness is for both proofs with the matching statements. Knowledge soundness quantifies a PPT adversary and extractor on public `(pk,vk)` and rejects extractor failure on an accepted statement. The prose on p12 says an adversary may invoke U. This is an argument of knowledge for the fixed indexed relation, not proof that a client's supplied delta is correctly labeled, that an external revocation is genuine, or that an application executes the right action.

**P:** The first displayed ZK equality on p11 compares a simulated ordinary proof with P; the second on p12 equates the marginal distribution of a refreshed proof to P for a new valid pair. The displayed distinguisher arguments are `(vk,x,proof)`: public pk, retained D/rand, and a joint old/new transcript are absent. The p12 equality even prints x where the generated proof uses x'. Treat the intended target statement as x' and record this notation inconsistency. The literal displayed games quantify fixed valid pairs; they do not explicitly give an adaptive multi-theorem oracle game. Section 4 p20 says the fully dynamic definition includes a sequence, but the formal game is not in this file.

**P:** Lemma 1 p11, Theorem 3 p18 and Theorem 4 p22 use **q-DLOG in the algebraic group model (AGM)**. The supplied source does not specify the exact q function, group-specific DLOG instance, auxiliary-input model, or reduction loss. No standard-model, random-oracle, quantum-security, BN254-bit-security, or simulation-extractability theorem is supplied. The paper's experiments use BLS12-381 exclusively (Section 5 p23), so BN254 numerical security and setup provenance are independent product-review obligations.

**D:** Security inheritance can be made precise, rather than asserted from the fact that a pairing check passes:

1. All extra public UK elements must be efficiently derivable from the **same** public Groth16 CRS, with the same relation, QAP reduction, domain and generators. Any algebraic adversary using derived elements can have its representations expanded back into the original CRS. This avoids publishing independent new trapdoor-dependent powers and preserves the underlying model when its hypotheses hold.
2. A correct updater must compute exactly the ordinary target proof for the chosen target witness and fresh target r/s. This is an algebraic equality of components, stronger than a one-off verifier-success observation.
3. If each call uses independent uniform r/s, conditional on the prior public history and the chosen valid target witness, its output has the same distribution as a new ordinary Groth16 proof. Repeating this conditional equality gives a transcript-distribution argument for polynomially many updates. A real CSPRNG gives the corresponding computational implementation claim, subject to RNG assumptions and no state leakage.
4. Fully dynamic reconstruction must preserve the raw target polynomial/proof state; its cache scheduling is not a new proof relation. Its correctness is needed before item 2 can be used across reconstruction/swap cycles.

This is an independently derived route to transcript-only sequence privacy and ordinary knowledge soundness. **It is not a completed audit of the authors' unavailable AGM reduction or a formal adaptive multi-theorem theorem supplied in these pages.** A marginal ZK definition alone would not prove joint-transcript privacy; the conditional component equality is the required extra argument. Nothing here establishes nonmalleability, simulation soundness/extractability after simulated-proof oracles, exposed-state privacy, forward security, oblivious RAM/access patterns, or timing privacy.

## Randomization and private-state exposure

**P/D:** Section 3.2 pp13-14 requires fresh r',s' and gives

`A' = A + (r'-r) delta_G1 + sum_i Delta_z_i u_i_G1`

`B' = B + (s'-s) delta_G2 + sum_i Delta_z_i v_i_G2`

with the matching G1 B component needed for C. The linear C correction is

`s' A' - s A + r' B1' - r B1 - (r's'-rs) delta_G1 + sum_aux Delta_z_i t_p_i`.

Section 3.2 p14 and Equations (7)-(9) pp15-17 provide the quotient correction. For valid old/new assignments, `a'b'-c' - (ab-c) = a Delta_b + b Delta_a + Delta_a Delta_b - Delta_c`. Delta_c has degree below the vanishing polynomial, so it contributes no polynomial quotient. Its remainder is still required to vanish. Omitting C's quotient does **not** mean that invalid witness changes or unconstrained C values are allowed.

**C:** `dynark_prover.rs:265-267` uses one OsRng for successive r'/s' sampling; `:299-302` matches the minus-sign formula above. The current unused fully dynamic `dynamic_cache.rs:648-659` instead constructs `test_rng()` twice. The already documented no-getrandom release makes r=s and repeats calls' blinders. This is a reference-code/RNG defect; the paper explicitly requires refreshed randomness. Valid proofs or distinct proof encodings cannot certify the entropy policy. Phase 2 needs caller CSPRNG, independent draws, fail-closed entropy errors, and no test RNG reachable through production interfaces.

**P:** Section 3.1 p12 explicitly says rand is not sent to the verifier, assumes valid old/new witnesses, and allows linear storage. Protocol 2 p19 defines D as private witness-dependent projection vectors; Protocol 3 p23 retains previous/current block witness snapshots and preprocessing state, with updated randomness separately retained (Section 4 p20). The theorem is about emitted proofs, not publication of this storage.

**C/D:** `data_structures.rs:184-204` serializes r/s, q_a/q_b and A/B/C components; fully dynamic storage includes raw proof/evaluation records. If r/s leak, `A-r delta_G1` and `B-s delta_G2` are unblinded witness commitments. A candidate full assignment can be tested against these using public queries. This is a concrete disclosure consequence without claiming arbitrary witness recovery or discrete-log inversion. A leaked Protocol 3 witness snapshot directly exposes its assignment. Private projections and update-index/timing logs are not justified as safe to publish merely because they contain group elements. No exposed-cache simulator, erasure guarantee, or recovery/rollback security is provided.

Product consequence: keep witnesses, snapshots, blinders, raw commitments and projections holder-private; authenticate/encrypt persisted state; bind package/action/holder/generation; bound parsing and allocations; use atomic committed generations; do not put detailed delta supports or credential identifiers in routine telemetry. Outsourced preparation changes who sees the witness. Ordinary ZK also does not hide the public issuer/dates/action, chain payer, retry timing, or witness-service queries identified in product-spec.

## Public inputs and the paper's distance parameter

**P:** Section 2.1 p9 sets `A,B,C in F^(n x m)`, `x in F^(k-1)`, `w in F^(m-k)`, `z=(1,x,w) in F^m`. Thus k counts **constant one plus public values**. For this compiled credential relation, use paper m=643,563 assignment coordinates and k=6; original constraints are 648,156 and the roots-of-unity evaluation domain is N=1,048,576 after padding. Do not reuse the old report's m-for-constraints convention inside paper equations. Padding adds zero rows, not assignment coordinates. The constant-one delta is always zero.

**P:** Section 3.2 pp12-13 defines `d=|support(z'-z)|`, including changed public inputs and auxiliaries; the missing constant in occasional `(x,w)` shorthand is not authorization to mutate coordinate zero. It assumes `|Delta_A|,|Delta_B|,|Delta_C|=O(d)` for its simple asymptotic statements, explains fanout can violate that assumption, and says the algorithms still work. Section 5.1 pp23-24 instead constructs benchmark samples with `|Delta_Z|=2d` and `|Delta_A|=|Delta_B|=d`; benchmark d=1 means two assignment changes. Table 2 p25 gives separate support counts. That convention is compatible up to a constant for asymptotics, but not a direct apples-to-apples numeric comparison to one changed leaf or one witness coordinate.

**P:** The O(1) verifier-time claim has footnote 3 on p19, explicitly assuming constant public-input size. The verifier does a public-input linear combination; general input-count cost is not O(1). A fixed five-public-input credential circuit satisfies that counting assumption. BLS12-381's reported 192-byte proof (p26) is not the BN254/Solana wire encoding.

**P/C:** Definition 1 and Section 3.2 allow x to change. The public linear queries enter A/B; only auxiliary deltas enter the private `t_p` sum. `dynark_prover.rs:272-297` follows that split. The verifier must receive the **target** public vector, and policy must compare its target root to the execution-current chain root. A correct mathematical proof under an old root remains a proof for its old statement. DYNARK supplies no issuer-status feed, revocation-publication guarantee, deadline, account binding or replay policy.

## G4 resolution: relation soundness, reduction identity and stronger properties

**P/C:** The DYNARK paper does **not** assume arkworks instance-row augmentation. Equations (2)-(3) p10 interpolate the original n constraint rows. Reference `dynark_generator.rs:270-304`, `r1cs_to_qap.rs:364-427` and `dynark_generator.rs:24-26` match that choice. Crates.io ark-groth16 0.5.0 `r1cs_to_qap.rs:111-145` instead selects a domain for constraints+k and adds `L_(constraints+j)` to each public/constant u_j; `:173-176` inserts z_j in appended A rows with B=C=0. These extra rows are tautological constraints `z_j*0=0`: they preserve the indexed R1CS language while changing its QAP polynomials and key queries.

**P (separate Groth source, limited scope):** [Groth's accepted original paper](https://discovery.ucl.ac.uk/id/eprint/1501201/1/Groth_SNARK9.pdf), Section 2.3 p9, defines degree-bounded QAP relations without a public-u independence requirement. Section 3.1 Theorem 2 pp14-15 extracts auxiliaries from C-query coefficients; Section 3.2 Theorem 3 p17 carries this into the generic bilinear group model. Its coefficient argument assigns the public coefficients from the verifier's statement, rather than solving for them from public u polynomials. Consequently A-only public-row augmentation is not a necessary condition of that **ordinary** QAP knowledge-soundness theorem. This generic-model theorem is not itself the missing DYNARK AGM/q-DLOG reduction, nor a theorem about simulated-proof oracle attacks.

The inherited theorem also retains Groth's benign relation/auxiliary-input generator assumption (Section 2.2 p8). This review does not establish security for arbitrary auxiliary input; that distinction belongs in the product's eventual security claim.

**D:** For either reduction, evaluation at all domain roots proves `(Az)(Bz)=Cz` iff `a(X)b(X)-c(X)` is divisible by `X^N-1`. For the augmented reduction the appended rows are always satisfied. Ordinary proof algebra therefore binds the supplied statement through its matching `t_v` query and relation. Lack of linear independence of just the public A/u columns is not sufficient evidence of a forged statement. For example, the meaningful relation `w^2=x` has public x only in C, so its u_x is zero; requiring every public u column to be independent would reject this relation unnecessarily. Stronger extractability/security notions may need additional restrictions, and cannot be silently substituted for the actual product claim.

**C/D:** The credential source constrains all five declared values: root at `credential.circom:115`, issuerHash at `:69`, signed notBefore/notAfter at `:41-44`, and actionHash through strict bit decomposition and the holder-signature message at `:73-93`; public schema at `:117`. This supports the intended relation. It is not a completed soundness proof of the compiled circuit/gadgets or a compiled-polynomial independence audit. Historical success of mapped ordinary verification proves acceptance of the tested outputs for the reference-derived VK, not security for every imported R1CS.

**Decision:** Remove the implication that the absence of augmentation alone is a general-purpose soundness defect. Retain a precise gate for (a) equivalent compiled relation and correct public/aux split, (b) exact PK/VK/QAP/domain identity, (c) inherited theorem/model scope and fresh randomization, and (d) separately requested stronger properties. The arbitrary-R1CS reference adapter must validate these identities and constraints. Do not impose a blanket public-u rank requirement without identifying a theorem that needs it. Do not close existing-zkey compatibility from an ordinary pairing check with a mapped reference VK.

Even when both domains round to the same N, added A rows change u queries, public `t_v` queries, A evaluations, projections and quotients. For the credential shape, 648,156+6 still rounds to 1,048,576; **equal padded sizes do not make the two reductions interchangeable**. UK's domain-only bases can match under the same tau/delta while its matrix indexes and PK do not. Existing developer setup and original zkey have different setup identities as well.

## Deriving UK from an ordinary setup and from snarkjs zkey

**P:** Section 3.3 pp16-17 explains why the original H query supplies powers only through degree N-2: full L_i has degree N-1, but the highest-degree terms of every quotient cancel. Append a zero group element to `[tau^i (tau^N-1)/delta]` and apply iDFT to obtain **truncated** Lagrange encodings. Derive the diagonal p vector by convolution. Section 3.5 p18 and Protocol 2 G p19 publish only these derived elements. No toxic waste is needed. The reference's `generate_updating_keys(:59-104)` implements that construction using its own matching monomial H-query vector.

These basis elements do not use witness values or R1CS matrix coefficients, but still depend on curve, domain/root ordering, tau/delta and the setup. The reference's whole UK also contains circuit matrices and PK. They are not a universal package that can be shared across arbitrary setup identities. Receiving an ordinary VK alone is insufficient to derive them; the necessary public proving CRS/H queries are required.

**C:** Local snarkjs 0.7.6 is relevant to the original `credential_final.zkey` route:

| Source locator | Verified code fact |
|---|---|
| `zkey_new.js:59-72` | Domain selected for original constraints+public+constant |
| `zkey_new.js:290-300` | Appends A-only rows for all public/constant values; adds them to A/IC/coefficient sections |
| `powersoftau_preparephase2.js:67-88`; nested `ffjavascript/src/engine_fft.js:443-475` | Prepared powers-of-tau section12 uses group iDFT/Lagrange evaluations; highest unavailable power can be filled with zero |
| `zkey_new.js:182-200` | For domain below field two-adicity, H section9 stores odd-indexed Lagrange encodings of a 2N domain, not the reference monomial H-array |
| `zkey_contribute.js:90-92` | Circuit phase-two contributions apply inverse delta to private L and H sections |
| `groth16_prove.js:64-79,99-101`; `wasmcurves/src/build_qap.js:217-268` | Prover evaluates A/B/C on the odd coset, forms A*B-C without division, and MSMs against that H section |

**D (requires parent review and a conformance test):** Let omega be the N-domain generator and zeta the actual snarkjs 2N-domain generator, with zeta^2=omega and zeta^N=-1. Write eta_j=zeta omega^j. Let Hodd_j denote the final zkey's odd 2N-Lagrange encoding divided by delta. It may be truncated in degree 2N-1 if the prepared ceremony powers omit that last power. For `0 <= i <= N-2`, interpolation of `f_i(X)=X^i(X^N-1)` on the 2N roots gives

`Hmono_i = [tau^i (tau^N-1)/delta] = -2 sum_(j=0..N-1) eta_j^i Hodd_j`.

Proof: f_i vanishes on even roots and equals `-2 eta_j^i` on odd roots; degree f_i is at most 2N-2. Thus the 2N-point interpolation is exact. If each Lagrange basis was truncated in degree 2N-1, the omitted terms cancel because f_i has no such coefficient. The expression is an ordinary public linear combination of final H points, with no tau/delta disclosure. Equivalently use the **matching** forward transform and zeta^i factor. Root ordering, orientation, normalization and point decoding are explicit preconditions, not guessed conventions.

After obtaining Hmono_0..N-2, append zero and perform the paper's iDFT/truncated-basis and diagonal construction. Map A/B1/B2/private-L/VK points from the **same final zkey**, and compute projections/deltas over the **augmented** row evaluations (including public A-only rows). No new trusted setup is algebraically required by this route. **This is a credible derived interoperability path, not achieved original-zkey interoperability.** The current reference API and probe do not perform the conversion or include those rows. Directly assigning zkey section9 to `tau_powers_g1`, or retaining original-only matrices with augmented PK queries, is invalid.

The current BN254 domain N=2^20 is below the field's two-adicity; the proposed formula is specifically for that supported roots-of-unity case. A maximal-domain coset branch needs a separately derived formula. Trustworthy original zkey provenance, input bounds, group/subgroup checks, exact generators and serialization remain required.

## Source inconsistencies to resolve before transcription

The relevant page images are under [security renders](../../../../artifacts/dynark/phase-1/paper-review/security-pages/). These are literal print inconsistencies, not inferred attacks:

- Definition 1 p12's updated-proof distinguisher receives x while P uses x'; intended statement comparison must use x'.
- Protocol 1 p10 prints `[t_v]_2` in VK, while its verifier pairing uses a G1 public linear combination; the ordinary implementation uses G1.
- Protocol 1 C sum prints `[k+1,m]`; Section 3.2 p13 uses `[k,m]`, consistent with k counting constant plus public values.
- Protocol 2 G step2 p19 omits 1/N in w/w' relative to Equation (6) p15. It also leaves the zero-index denominator undefined; the code sets w_0=0.
- Protocol 2 U step5 p19 prints `s'A'+sA`; Section 3.2 p13 and reference executable code require `s'A'-sA`.
- Protocol 2 U refers to r'/s' without an explicit sampling step. Section 3.2 p13 supplies the fresh-randomness requirement.
- Protocol 2 and some surrounding notation omit the constant in z=(x,w); Section 2.1 p9 is authoritative for z=(1,x,w).

Implement from a reviewed coherent algebraic specification and differential oracle, not by copying these protocol boxes literally. The separate algebra worker should reconcile the Theorem 2 convolution orientations and other kernel details.

## Corrected gates and actionable Phase 2 acceptance

| Previous item | Correction / exact acceptance |
|---|---|
| Paper unavailable in research-and-gaps, code audit, T0/G1 | Replace with fully reviewed supplied-file identity and exact page locators. Split G1 into completed source review and specifically deferred proof/fast-algorithm/stepwise details. No claim that an appendix exists or was read |
| G4 framed around unaugmented QAP/public independence | Record the supplied paper uses that reduction; ordinary Groth QAP soundness does not require A-only instance augmentation. Require relation/query binding and theorem scope, and keep actual key interchangeability gated |
| T1 generic public-input tests | Include a C-only public input (`w^2=x`) to prevent treating public-A rank as an unstated requirement. Test valid proof, altered public input, invalid full assignment and exact coordinate-one handling for each selected reduction |
| T2/T5 update privacy | Compare raw target components with full P under common explicit test r'/s'; then check independent randomized ordinary verification. Review conditional-history equality, no-op rerandomization and failure paths. Repeated proof equality is a defect signal, not the sole RNG test |
| T0/G7 original zkey mapping | Apply public H-basis conversion and augmented row evaluations under the original final setup, or explicitly choose a matching separate setup/deployment. Verify final outputs under original VK, snarkjs and ordinary arkworks before claiming existing-key support |
| T4 fast kernel | The supplied text defines the kernel and target bound but omits detailed fast algorithm; a reviewed derivation from its cited method can resolve this rather than repeating a blanket PDF-access blocker. Label such derivation honestly |
| T5 fully dynamic acceptance | State exactly what is independently established versus the missing authors' formal scheduling/security proof. Positive step budget must progress; handle zero/revert/dense updates, block-boundary overshoot, no-op blinding, snapshots and atomic swap. Valid full target components after each transition are essential |
| T6 cache privacy | Exposed cache/witness/blinders are outside proved ZK; validate identity/authentication/rollback/crash boundaries and protect private state. Persistence correctness is separate from prover correctness |
| Product claim | Strict execution-current-root plus the credential/application policy must remain external enforced semantics. Do not promise public-input anonymity, immediate unpublished revocation, adaptive SE, state compromise resistance, original setup compatibility or production readiness from this paper |

### Minimal discriminating G4 experiment proposal (not executed)

Hypothesis: original-only and instance-augmented reductions encode the same indexed R1CS language but require different A/public queries, and a C-only public value does not need public-A independence for ordinary soundness.

Use public synthetic BN254 data only: z=(1,x,w), row0 `w*w=x`, four padding/zero constraints, k=2, five original rows. Both original-only and +k reductions round to N=8, isolating row augmentation from domain rounding. Select nondegenerate test setup values/generators and satisfying `(w,x)=(2,4)` and `(3,9)`; no real credential or original toxic waste. For each reduction:

1. Compute original/augmented A/B/C evaluations and exact coefficient polynomials. Assert divisibility for satisfying pairs and a nonzero remainder for x changed alone. Record u_x=0 for original-only.
2. Generate matching full PK/VK and UK; under common explicit test r/s, compare raw quotient encodings and full proof components to the corresponding dense ordinary target calculation.
3. Refresh x and w together; require exact target components and ordinary verifier acceptance for the matching target public x. Reuse unchanged proof with altered x and require false. Reject coordinate-one changes. Cross-use mismatched PK/VK/reduction and require rejection or mismatch detected before proving.
4. In a tiny independently generated snarkjs final zkey, derive Hmono from Hodd and compare **each group element** with direct fixture monomial H queries; include the truncated-highest-power case. Refresh using augmented projections, then require original snarkjs VK and ordinary-verifier success. Also preserve a deliberately wrong direct-H-copy result as a negative basis test.

Resource proposal: at most 5 minutes and 1 GiB, fixed dependency versions, deterministic publicly labeled test setup/randomness, no credential preprocessing. Pre-record source/artifact hashes, roots/ordering, counts, expected negatives and stop conditions. This checks algebra and implementation discriminators; it cannot prove computational security, hidden entropy, the missing AGM theorem, or security of a real ceremony. Only after this succeeds should an explicitly budgeted original-credential zkey experiment run.

## Nine-part worker evidence contract

1. **Task/model/reasoning:** `paper_security`, parent-requested GPT-6.1 Sol/high read-only research; all supplied pages and relevant code/doc boundaries inspected. No subagent spawned.
2. **Findings:** source-complete 30-page review; deferred proofs clearly located; fixed-pair displayed privacy scope; derived conditional transcript equality; private-state disclosure consequences; public inputs count k-1; d assignment support versus benchmark convention; original-only QAP is the paper's choice; ordinary soundness and stronger properties separated; exact-key mismatch remains; public-only snarkjs H conversion derived but untested.
3. **Changes:** only this evidence document plus page11/page12/page19 PNGs in the explicitly owned `security-pages/` directory. Existing pinned PDF/layout had already been preserved by the parent; both hashes verified. No historical doc overwritten.
4. **Commands/actions:** `pdfinfo`, `shasum -a 256`, `sed`/`nl`/`rg` read-only source and whole-paper inspection; `git -C experiments/dynark/vendor/DYNARK_ rev-parse HEAD` and `status --short`; `pdftoppm -f 11 -l 12 -r 120 -png` and `-f 19 -l 19 -r 140 -png`; viewed all three generated images. Primary web lookups recorded above plus Groth original UCL accepted PDF. No test, build, benchmark, setup or deployment command.
5. **Measured/not measured:** file bytes/pages/hashes and local version/pin/dirty boundary observed. No latency, memory, entropy distribution, new proof, zkey import, attack, private-witness recovery or ceremony security measured. Proposed experiment was not run.
6. **Source/version/hash:** DYNARK reference HEAD `c73a380df86d8f5d195f1e20c8a1d86a7dce084b`; preexisting dirty files generator/prover only. arkworks QAP source 0.5.0; snarkjs 0.7.6; PDF identity above. Additional source hashes below.
7. **Failures/risks:** expanded-version endpoint/PDF HTTP403; independent primary-site search found no expanded appendix. One initial ffjavascript root-path lookup was wrong; corrected to snarkjs's nested dependency and inspected actual implementation. No inference of remote PDF-byte identity. Formal AGM/q-DLOG proof, quantitative BN254 security, compiled credential soundness, exposed-state/adaptive-stronger properties, and original-zkey conformance remain outside completed evidence.
8. **Next action:** parent personally checks the G4 ordinary-extraction scope and H-conversion derivation; updates historical availability gates accurately; approves the finite synthetic conformance package in Phase 2. Preserve separate code RNG/domain defects and require their resolution before production/actual-circuit fully dynamic use.
9. **Deviations:** none from read-only/no-implementation scope. Supplemental original Groth and local snarkjs source inspection was needed to resolve the requested G4/setup questions. No baseline mutation, root Git initialization, private real material, paid service, publication, deployment or outreach.

| Inspected file | SHA-256 |
|---|---|
| reference `r1cs_to_qap.rs` | `45b86e8b59522a0b7c5121326ad644f311c77517eb76d05440fab7321ba0b5e1` |
| reference locally patched `dynark_generator.rs` | `4bcb08ba6f1a1c4d55cb7136db5c8989e7f56ffb5e6c15f6e11956f6788b1103` |
| reference locally patched `dynark_prover.rs` | `5575e85562da40578887098dccd45652e5b985319ccc1bb3734fb5e33de447ac` |
| crates.io ark-groth16 0.5.0 `r1cs_to_qap.rs` | `973bb853b38ea1efe428a77a46778b33b67da0fc909c752f540138defb982ad0` |
| snarkjs `zkey_new.js` | `3db862c8c5aa49ed6fb94f6dd4937ed1ea0aa66a5b28164b6a3333dd6b488bcc` |
| snarkjs `powersoftau_preparephase2.js` | `4e16d6499c51277da9047f73c6b864dcd47a55be5a09424d97bd1d5196b8ceaf` |
| snarkjs `groth16_prove.js` | `36b58c6b524596c009cad1afda4342c4e779965c875ff3b5ad5a0c687cce01f6` |
| snarkjs `zkey_contribute.js` | `abd0bac078280a5a4b578cf818165551115ed212af184dab04806de2abc233b2` |
| `circuits/credential.circom` | `66c76a69bc8da77248778f2c651705022e572320af29dbf38d3541e21ed4b9f4` |

Memory use was limited to project-history registry lines1-39 to orient the applied-research goal; all substantive paper/code conclusions above were inspected fresh. No historical timing or compatibility fact was adopted from memory as a current result.
