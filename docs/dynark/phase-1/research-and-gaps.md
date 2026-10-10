# Complete-paper review, conformance, and research agenda

October 10, 2026, corrected after the user supplied the paper. Evidence labels: **P** primary source; **C** inspected code; **F** fresh observation; **H** historical artifact; **D** derived argument/estimate; **X** hypothesis; **U** unresolved. Measurements are in [baseline audit](baseline-audit.md); detailed source lines and mappings are in [paper algorithms](evidence/paper-algorithms.md), [paper security](evidence/paper-security.md), and [code audit](evidence/crypto-code-audit.md). Older top-level documents under `archive/pre-full-paper/` are superseded.

## Source and completeness

**P:** The user supplied `/Users/anishnarang/Downloads/2025-1897.pdf`, *Dynark: Making Groth16 Dynamic*, Tianyu Zhang, Yupeng Ouyang and Yupeng Zhang. All **30 pages** were read by the parent and independent algorithm/security reviewers, including related work, evaluation and references. Source identifier: [ePrint 2025/1897](https://eprint.iacr.org/2025/1897). Supplied file SHA-256: `f851f11ed8ae8a6876dafe09373650098aa792b9f886019eea4d98060fa7b259`; 835,694 bytes. PDF metadata creation/modification date is May 11, 2026; inspection date October 10, 2026. Protected copy and extraction: `artifacts/dynark/phase-1/paper-review/`. Metadata agrees with the previously retrieved revision date; this does not establish byte equality with a currently served remote version.

**Correction:** The previous Phase 1 package did not review the paper and overstated completion. The supplied document is now fully reviewed. It contains **no appendix** and itself defers material to a “full version”: formal definitions (§2.1, p9), Theorem 1's proof (p15), fast sparse convolution (p16), truncated-basis/diagonal proofs (p17), Theorem 3's proof (p18), four-FFT full proving (p19), full-dynamic formal definitions and stepwise preprocessing (pp20–21), and serial evaluation detail (pp25–26). Theorem 4 has an inheritance sketch (p22), not a complete proof. Complete reading is achieved; absent author-supplied arguments are not certified or invented.

Coverage: pp1–8 motivation, contributions and prior work; pp9–10 algebra and ordinary Groth16; pp11–13 dynamic definition and linear update; pp14–19 quotient decomposition, cross/projection terms and Protocol 2; pp20–23 deamortization, partial preprocessing and Protocol 3; pp23–27 methodology/results/comparison; pp27–30 acknowledgments/references. Independent reports give finer locators, source retrieval limits and code mapping.

## Parameters and personally reviewed algebra

**P:** Paper §2 uses n constraints/domain points, m extended-assignment length and k instance length **including one**: z=(1,x,w), private indices start at k. Section 3.2 defines d as nonzero assignment differences, then assumes induced A/B/C row supports are O(d) for compact asymptotic statements. Arbitrary R1CS sparsity does not guarantee this. Section 5 instead explicitly uses |ΔZ|=2d and |ΔA|=|ΔB|=d in synthetic benchmarks (p24, footnote4).

**C/H:** Our raw constraints r=648,156, assignment length v=643,563, instance length k=6, public values5, padded domain N=1,048,576. Use distinct names in product code; raw r is not an FFT domain. The paper's square benchmark m=n differs from our circuit.

| Quantity | Meaning | Frozen near-root case, E4 census |
|---|---|---:|
| s_z | Nonzero assignment changes | 5,081: one public,5,080 auxiliary |
| t_A,t_B,t_C | Matrix entries visited through changed columns, with multiplicity | 2,390 /2,370 /10,450 |
| u_A,u_B,u_C | Distinct touched rows before deleting canceled sums | 2,390 /2,370 /5,080 |
| s_A,s_B,s_C | Nonzero row-evaluation changes after cancellation | 2,390 /2,370 /2,370 |
| s_A × s_B | Pair visits per existing cross loop with zero rows removed | 5,664,300 |

Column fanout and cancellation determine work. `improved_lagrange_sparse_get` merges equal rows but retains zero sums. E4's exact sparse/dense check found no retained A/B zero rows for this transition; deleting zeros therefore offers no near-case A/B speedup here. C has2,710 touched rows whose changes cancel to zero. One Merkle-leaf change is not d=1 in compiled assignments. A new action historically changes104,175 assignments and yields about10.50billion cross-pair visits per loop; it must not silently take the near-update path.

**D — derived/reviewed by parent:** Let Z=X^N−1, L_i=(ω^i/N)Z/(X−ω^i), w_t=ω^t/[N(1−ω^t)] for t≠0, w_0=0, and w'_t=w_(−t). Circular convolution is (a*b)_i=Σ_j a_j b_(i−j). Partial fractions give, for i≠j:

`L_i L_j / Z = w_(j−i) L_i + w_(i−j) L_j`.

Since Σ_j L_j=1, the quotient of L_i² is φ_ii=−Σ_(j≠i)φ_ij, with remainder L_i. Both off-diagonal orientations and the overlap term are required. Resulting quotients have degree≤N−2: degree-N−1 terms cancel. Thus truncated Lagrange bases can be encoded from the N−1-element Groth16 H query padded with a zero point, without an extra secret power. This checks Theorem1's algebra; it does not reconstruct its security argument.

For A=Σa_i L_i, projection q_i^a=(A L_i−a_i L_i)/Z satisfies:

`q^a = w*(a∘L) + (w'*a)∘L + a∘φ_diag`.

This agrees with Theorem2 (p17), p18 preprocessing, Protocol2 K and code. Encoded diagonal p=−(Σ_t w_t)ell−w*ell. PDF text extraction displaced a prime/parenthesis; rendered pp17–19 resolve them. These are **not paper errors**.

For valid base/target assignments AB−C=qZ:

`q'−q = quotient(A ΔB + B ΔA + ΔA ΔB − ΔC, Z)`.

Degree(ΔC)<N, so its quotient is zero; its remainder remains essential to satisfaction. This explains the absent separate C-delta update, not permission to omit valid-witness preconditions. Groth16 C randomization changes by:

`s' A' − s A + r' B1' − r B1 − (r's'−rs)δ1 + private-linear(Δz) + quotient-correction`.

Parent checked executable `update_dynark` and p13. Public changes affect A/B and the verifier statement; only auxiliary changes enter the private linear query. Every proof emission requires fresh independent r,s from a secure source.

**P/C, visually confirmed discrepancies:** Protocol2 G2 (p19) omits1/N, although Eq6 (p15) and code include it. Protocol2 U5 prints +s[A]; p13, direct subtraction and code require −s[A]. Eq6 includes the singular zero index without explicitly defining w_0=0; code supplies it. Sampling of new randomizers is implicit in Protocol2. Do not implement the box literally. Protocol3's t'=b transition also needs an explicit overshoot/large-update policy; its pseudocode does not specify every boundary case.

Protocol1 p10 also prints the verifier's public query in G2 even though its verification equation requires G1, and starts the auxiliary sum at k+1 despite its own zero-based split beginning at k. Parent visually checked the page. The reference's typed queries and instance/auxiliary split follow the required algebra; these typesetting errors must not be copied into a new implementation.

## Paper-to-code matrix

Source paths are beneath `experiments/dynark/vendor/DYNARK_/ark-groth16/src/` unless stated. Detailed function/line citations and retained arrays are in the algorithm report. Reference pin: `c73a380df86d8f5d195f1e20c8a1d86a7dce084b` plus two pre-existing local patches.

| Paper locator/capability | Inputs → outputs; assumptions, state and cost | Code and observed status | Obligation/owner |
|---|---|---|---|
| §2.1, Protocol1 pp9–10; §3.5 p19 full proving | Matrices/setup→PK/VK; valid z,fresh r,s→ordinary proof. Dense O(NlogN)F+O(v+N)G | `dynark_generator::{groth16_setup_dynark,generate_prover_key_with_matrices}`, `r1cs_to_qap::compute_quotient`, assignment prover; E2 direct no-cache path verified. Raw matrix wrapper drops one | T1 preserve reduction/query/public order. Separate four-FFT claim lacks supplied algorithm and is not a measured local improvement |
| §3.3 pp16–17; Protocol2 G p19 UK | Compatible H query/domain/matrices→ell,p,w,indexes; public O(NlogN)G, no new toxic waste | `generate_updating_keys`; public UK generated/measured, includes cloned PK | T1/T3 sharing and identities. Existing-key compatibility requires matching relation/reduction/domain/queries/encoding |
| Theorem2 pp17–18; Protocol2 K projections | UK+anchor A/B rows→two N-entry vectors; private O(NlogN)G prep, O(N) retained | `process_dynark`, `compute_projection_quotient`; circular convolutions implemented, prep measured | T3 attribute transforms/clones. Paper≈2× vs FK23 is not our measured improvement |
| Definition1 p11; §3.2 pp12–13; Protocol2 U | Valid base/target+immutable projections/proof/blinders→new proof; public/private changes supported | `update_dynark`; actual anchored updates verified, both B groups and randomization mapped | T2 canonical indexes/cancellation/public/anchor binding; T1 secure RNG |
| Eq7 p15; §5.1 p25 practical cross term | Sparse A/B→product quotient; O(s_A s_B)F and support-linear group sums | Nested loops in `update_dynark`/`FullyCheckpoint::calc_cross_terms` | **Disclosed paper implementation choice**, not accidental nonconformance. Retain oracle/small-support option |
| Eq8 pp15–16 fast cross term | Selected w' convolution→same quotient; claimed O(s log²s)F | Fast kernel absent; PDF defers pseudocode, citing GGS87 Trummer problem | T4 independently reviewed derivation/oracle/measured crossover; no mandatory replacement based only on asymptotics |
| §4.1 pp20–23; Protocol3 dynamics | Consecutive transition+active/rebuilding snapshots→proof,new randomness,state; partial correction O(db)G, scheduling O(dNlogN/b)G | `FullyCheckpoint::{update_from,sim_update_from,trivial_append}`, `FullCache::{flash,step_forward}`; no credential sequence verified | T5 generation/snapshot/accumulation and oversized-step fallback; correct E3 defects first |
| §4.1 pp21–22 stepwise DFT/block offset/partial-K | Previous-block cache serves current block while current snapshot rebuilds; b≈sqrt(NlogN), total O(d sqrt(NlogN))G+O(dlog²d)F under support assumptions | `fft_handler`, reconstruction stages, author example; several O(N) buffers | E3:32 odd-log mismatches and partial-batch timeout. T5 positive-budget progress/atomic swap; author stepwise pseudocode absent |
| §2/§3 public/private handling | Instance includes one; auxiliary starts at k; public delta changes verified statement | Probe deltas, private-query split and ordinary verifier adapter | T1/T2 five-public tests, canonical bounds/split, constant-one preservation |
| Definition1; Thms3–4 pp11,18,22 security/randomness | q-DLOG in AGM; updated-proof distribution as fresh proof; valid statements, secure setup/randomness | Anchored OsRng patch; dynamic `get_proof_with_rs` calls deterministic test RNG twice under captured features | T1 production RNG correction. Separate ordinary soundness from simulation/adaptive/cache-compromise claims |
| §3.5 p19; §5.1 p26 proof/verifier | Ordinary proof/VK unchanged; constant verifier only at constant public count | Independent crates.io verification; BN254 compressed proof128B | Paper BLS12-381 proof192B/4.4ms not our format/timing. Original zkey/Solana256B adapter remain P4 gates |
| §5 pp23–27 evaluation | BLS12-381,192-vCPU AWS, square random R1CS,3prep/10proof repeats, controlled d; prior-system published numbers | Our BN254/M3/four-thread/rectangular circuit has direct local-refresh evidence | No imported speedup/crossover/hardware scaling. Related-system comparison is not same-relation independent reproduction |

## Security and state invariants

An anchor binds one circuit/setup/domain, assignment/public vector, projection pair, proof components and randomizers to one generation. Updating a proof alone does not rebase projections. Dynamic state additionally binds frozen rebuild input, pending corrections, progress and active/rebuilding generation IDs. Replace atomically only after data and corrections are complete. A no-op still needs specified randomization; zero step budget must not mutate progress; oversized steps need splitting with a proved bound or an explicitly charged full fallback.

The paper's unaugmented interpolation is the reference's intended construction. Its difference from arkworks instance-row augmentation is **not by itself an unsoundness finding**. Ordinary soundness, stronger simulation-extractability/adaptive claims and exact key interoperability are separate questions; [security evidence](evidence/paper-security.md) supplies the reviewed scope. Private cache compromise, rollback, side channels, application binding and authenticated issuer freshness are product obligations beyond the public proof theorem.

## Ranked, falsifiable optimization agenda

Ranks reflect bottlenecks and reversibility; targets remain provisional. Every experiment records bounds and stops before code.

| Rank/category | Evidence and expected effect | Minimum falsifiable experiment/rejection rule | Dependency/phase |
|---|---|---|---|
| 1. Optimized ordinary path/adaptive default; established | No-cache full2.221s, complete5.417s; update complete3.587s with costly prep. Full is credible for short sessions | Same key/reduction, independent verification, transform/MSM/allocation ablations. Separately assess unprovided four-FFT proposal. Reject cache-building or changed-relation comparator advantage | E1/E2 comparator established; T1/T3 improve full and update together |
| 2. Shared public state/no duplicate PK; established | UK clones PK; public prep382.969s. Reduce resident duplication and shared per-user cost | One/two/ten private states with single public ownership; live bytes/load/serialized bytes/all CPU. Reject hidden load penalty or weakened identity | T1 boundary,T3 |
| 3. Projection FFT/group/allocations; established | Private prep510.323s baseline; E4 peak requested2.512GB including retained oracle,50.329GB allocation traffic,1.467billion allocation calls;13 sampled group-transform windows | Use measured stage counters and sampled paths to choose one buffer/scheduling ablation; exact vectors and valid proofs; prep/peak/session totals. Reject shifted background work or attributing all timing difference to instrumentation | E4 completed,T3 |
| 4. Incremental witness; exploratory dependency engineering | Full witness≈3.13s dominates warm refresh despite5,081 changed near wires | Exact executable dependency schedule and full-witness equality on near/mid/far/random/own-revocation. Require end-to-end gain; reject omitted changed wire | P3; R1CS/symbols alone insufficient |
| 5. Sparse layout/zero deletion/group sums; established | Gather/sort touched entries, canceled rows, separate multiplications | Actual/cancellation-heavy supports; dense-row/raw-quotient equality and proof verification; include conversion/allocations, reject net loss | T2 then T3 |
| 6. Fast cross crossover; established technique, independently derived candidate | Quadratic intentionally wins paper small cases; large action supports may reverse | Review Trummer/Cauchy derivation/diagonal/normalization; nested oracle and actual tiny-to-large supports. Keep quadratic below measured crossover | T4; do not claim author-supplied pseudocode |
| 7. Lazy/selective projections; exploratory | Used entries sparse but each can depend on full anchor; smaller retention may not mean faster prep | Exact subset,cold miss,warm hit,fallback/all transforms over0/1/2/5/10/100 refreshes. Reject worse session cost/unbounded miss | T7 after dependency derivation |
| 8. Stable/cross-action reuse; exploratory | Action changes104,175 wires; linear projections do not eliminate bilinear proof cross terms | Full stable/action/signature dependency derivation, holder/action-mix negatives and exact equality. Reject omitted dependence or negative economics | T7/P3; otherwise invalidate on new action |
| 9. Full dynamics/rebuild; paper concept + engineering | Growing anchor distance vs O(N) buffers/maintenance, no valid credential sequence yet | Correct small odd/even FFT/partial batches first; multiple swaps, arbitrary d, failures/reloads; fresh-state equality,max pause,total CPU/byte-seconds | T5 RNG/progress/invariants first |
| 10. Profile/circuit changes; established gadgets/exploratory profile | Two RSA/SHA checks, fixed DER, domain rounding drive all costs | One qualified change preserving eligibility with positive/negative corpus,new domain/support/prep/full/update results. Reject security weakening | P3 issuer/profile qualification |
| 11. Hardware; exploratory | No transfer/kernel evidence establishes device win | Profile first; compare including startup/transfers/prep/verification, reject net loss/unsupported device | Optional P5; spending approval |

## Readiness limits

The supplied paper's reading and locator map no longer block Phase 2. Author omissions restrict specific claims: no assertion of checked complete author proofs, supplied four-FFT implementation or supplied fast/stepwise pseudocode. Independently reviewed derivations/tests may support those tasks when labeled accurately.

Production RNG, malformed-input/state binding and custom reconstruction defects block promotion of affected engine paths; they are concrete Phase 2 work. Original zkey/Solana remain integration gates. Real credential/profile/workload qualification remains outside synthetic validation. See [bounded plan](phase-2-plan.md) and [product requirements](product-spec.md) for owners/acceptance. No old-root acceptance, hidden prep or assumed cross-action reuse is allowed.

### Two additional implementation decisions from the complete review

The reference quotient path used by E2 performs **seven domain-size transforms**: three inverse transforms for A/B/C, three coset transforms, then an inverse coset transform for the quotient. The similarly named optimized routine still has seven. The p19 four-FFT proposal is absent from both supplied algorithm text and these code paths. E2 is an optimized comparator in the specific sense that unnecessary DYNARK cache construction is removed; it is not evidence of an optimal full prover. T3 must preserve this baseline while assessing any reviewed lower-transform full-prover candidate, charging all transforms/MSMs and verifying the exact quotient before comparing dynamic savings.

The reference fully dynamic `update_from` obtains accumulated/current projection corrections through additional cross-term calls. Its group aggregation differs from the direct partial-K explanation on p22, while field pair work can scale with accumulated support times current support. Replacing a cross call by a fast transform on their whole union can cost O(b log²b) even when current d is tiny; that alone does not establish the paper's O(d log²d) field bound. T4/T5 must report separate accumulated/current supports and group/field work, and derive the call-site strategy before claiming the final fully dynamic complexity.
