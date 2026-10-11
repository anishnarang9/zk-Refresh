# T4 independent specification, code and security review

October 10, 2026 (America/New_York). Reviewer `t1_review`, GPT-6.1 Sol high. Read-only review; only this report is written. No code/helper/test/build/measurement/benchmark/setup/commit/delegation was executed by the reviewer and no execution slot was used. No actual credential/private artifact was read.

## 1. Scope, review order and disposition

Reviewed the approved finite-part derivation in `conformance.md`, P2-E4a in `experiments.md`, Phase 1 plan T4, accepted T2 weighted quadratic and polynomial oracle, and candidate `src/cross.rs`, `src/cross_proof_tests.rs`, `tests/cross_conformance.rs`. Specification review preceded code/security disposition. Parent independently identified comparator/work-accounting issues during implementation; those fixes were checked before the final candidate disposition.

**Pass for the exact frozen source-002 T4 candidate and standalone/same-key small correctness boundary.** No remaining actionable defect was found. This is an independent reviewer recommendation for the source identities below, supported by fresh worker logs and the parent's independent executable reruns; the reviewer executed no runtime rerun. Parent retains final acceptance authority. Timing/crossover, actual protected near/middle/far supports, complete production/dynamic integration and credential improvement remain open. Later live diagnostic observer hooks are a separate unaccepted source change and are excluded from this verdict.

The original plan's broader T4 acceptance includes measured crossover; this report closes only P2-E4a's first correctness scope. The candidate remains an isolated private module in the accepted-T2 test snapshot. No production T2 call was replaced; `UpdatingMaterial::cross` remains the accepted weighted quadratic implementation. A synthetic deterministic development setup in same-key tests is test-only, not a new production/credential setup or provenance claim.

## 2. Findings and resolved issues

No new actionable finding remains in reviewed final source. Parent's two earlier findings are resolved:

- **Unfair comparator:** the quadratic route now borrows the same exact shared UK weight table and uses table lookups, with no inversion per pair (`cross.rs:315-347`). Inverse-per-pair direct field sums remain independent correctness oracles, not performance comparators.
- **Uncounted union work:** the pair loop iterates nonzero normalized A positions by nonzero normalized B positions, not the union Cartesian square. `quadratic_pair_visits` increments once per actual pair, including diagonal pairs, and preflight checks exactly `|A|*|B|`. The N=128, A=128/B=1 regression succeeds at cap128 and rejects at127; it cannot hide 128² pair iterations behind a128 counter.

No empirical crossover is inferred from those repairs or correctness timings. `FastOrQuadratic` is a caller-requested bounded fallback, not adaptive selection from measured costs. The code explicitly delegates material identity/setup/public-package authentication to the owning proof boundary; a supplied weight table is not authenticated by its length/zero entry. The same-key tests borrow `uk.0.weights` from the exact validated package.

## 3. Algebra, code/security quality and bounds

For distinct nodes x_i and c_i=a_i*x_i, construct D=product(X-x_j) and P=sum c_j*D/(X-x_j). Write D=(X-x_i)D_i and P=c_i*D_i+(X-x_i)R_i. At x_i, D'=D_i, D''=2D_i', P'=c_i*D_i'+R_i, so

`(P' - c_i*D''/2)/(N*D') = R_i/(N*D_i) = sum_(j!=i) a_j*x_j/[N*(x_i-x_j)]`.

This matches `fast`'s `(pav - a_i*x_i*d2v/2)*inverse_d1/N` exactly. There is no missing extra inverse or normalization factor. Both A/B numerator families share the denominator tree; D'/D'' evaluations are shared. The output L coefficient is `a_i*conv(b)_i+b_i*conv(a)_i`; `a_i*b_i` is encoded separately against the diagonal basis. Off-diagonal sum is zero for empty/singleton unions, but singleton overlap retains the diagonal contribution.

| Contract | Source and independent assessment |
|---|---|
| Normalized union | `normalize` sums additive duplicates, removes zeros; `align` creates sorted distinct union with explicit zeros on the missing side. Every raw coordinate, including a zero-valued out-of-range entry, is rejected before normalization. Raw input cap/precharge precedes map allocation; exact support cap precedes arithmetic |
| Domain/material | Reject N<2, non-power-of-two/non-radix-two domain, domain cap and weight length/w0 errors. Compatible domain/root, all other weights and matching L/diagonal tables are supplied through the authenticated owner boundary; no hidden N-table scan or regeneration occurs per sparse call |
| Product/numerator tree | Balanced floor/ceil splits handle uneven support. Leaves use X-x_i and a_i*x_i/b_i*x_i; merges P_l*D_r+P_r*D_l build the exact numerator. Tree node allocation is pre-reserved and root denominator is monic |
| FFT multiplication | Full coefficient convolution length checked, then next supported radix-two FFT size checked before vectors. Two forward transforms and one inverse; constant multiplication uses a bounded linear loop. No schoolbook general polynomial multiplication is hidden in the candidate |
| Newton reciprocal | `g_new=g*(2-f*g) mod X^next`, doubling prefix to requested length, with nonzero constant inversion. Zero padding/truncation is intentional; full intermediate multiply sizes are checked. Even a constant inverse's padded prefix advances rather than stalling |
| Reversed division | For f degree>=d, reverse the needed top f coefficients, multiply by the reciprocal of reversed divisor modulo X^quotient_len, reverse q, subtract q*divisor's low coefficients. Monic tree divisors are nonzero; no naive long-division production fallback appears. Polynomial copies/trims and scalar inversions are paid work |
| Remainder evaluations | Four bounded traversals evaluate D', D'', P_a', P_b'; leaf remainder is evaluation. If polynomial degree is smaller, return its copy. D'(x_i) is checked nonzero before one batch inversion. Characteristic2 and N inversion are excluded by fixed supported BN254 domain |
| Encoding | Checks vector/table lengths, domain shape, support count, index bounds and strict sorted uniqueness before any group multiplication. Encodes nonzero L/diagonal coefficients separately. No proof randomness, raw cache access, setup or ordinary proof success API is introduced |
| Failure/fallback | FastOrQuadratic falls back only after supported-domain/scratch preflight failures, with independent pair/storage preflight. Overflow, input/support/identity-shape errors or runtime reservation errors do not silently launch unbounded quadratic work. Pure borrowed-input kernel failure cannot mutate the package or anchor |

### Intermediate FFT and allocation analysis

`required_fft_size(s)=next_power_of_two(2*(s+1)-1)` for s>1 is deliberately conservative. Root D length is s+1; numerator/derivative/remainder degrees do not exceed it. A reversed quotient has at most s+1 coefficients. Newton multiplies at most a needed <=s+1 prefix by its shorter inverse prefix, and the subsequent full reversed-q reciprocal product fits <=2*(s+1)-1 coefficients; q*divisor is no larger. Thus the preflight bound covers full Newton products, not only truncated outputs, and covers unequal tree children. Each multiply independently checks its actual size as defense in depth. The conservative ceiling may reject or fall back when a tighter actual-domain ceiling could succeed; that is an allowed bounded policy, not an algebra defect.

Fast preflight charges raw normalization/alignment storage, O(s*levels) field storage with a large96-fields-per-node/level factor, 24*largestFFT temporary fields and tree headers using actual `size_of<Node>`. That dominates the product tree, live paired numerator recursion, derivative/output vectors, recursive remainder path, inverse/reversal/product/FFT buffers and return vectors for this source. Quadratic preflight separately charges union/output/index storage and exact pair visits. Checked arithmetic rejects count/byte/domain overflow before polynomial work. Normalization's BTreeMap/collect, padding/resizing and backend FFT/batch-inversion allocations are covered structurally; not all use fallible reservation. This is a conservative requested-storage bound, not an allocator/RSS maximum or a promise to recover from OS OOM/abort.

The polynomial core uses FFT multiplication and Newton/reversed division; its balanced product/remainder machinery supports the proposed O(s log²s) field asymptotic under the pinned FFT model. The complete call additionally pays raw normalization O(r log r), alignment, s domain-element exponentiations O(s log N), field inversions/conversion and O(s) group encoding. Dynamic accumulated/current union size s is not the current changed-witness distance d; this review does not establish the paper's current-d-only bound or end-to-end speedup.

## 4. Oracle independence and coverage

- **Arithmetic unit tests:**44 seeded cases compare Newton inverse prefixes using schoolbook convolution and remainder using independently implemented descending long division, plus zero divisor/noninvertible constant errors. Sizes include3/5/13/25/47 and powers of two. These naive loops are test oracles only.
- **Finite-part vectors:**24 cases through N=64 compare both complete convolution vectors with direct rational field sums, including outputs whose local A/B partner is zero; this catches accidentally evaluating only slots needed by the final encoded coefficient.
- **Standalone coefficients:**112 seeded randomized raw-input cases through N=128 plus deterministic empty/singleton/overlap/disjoint/duplicate/cancel/uneven cases. All three methods equal direct independent field sums. Exact comparator pair/statistics and intermediate FFT upper bound are asserted.
- **Dense polynomial/group quotient:**48 seeded random cases through N=64 plus empty/diagonal cases use explicit Lagrange coefficient construction, schoolbook multiplication and descending division by X^N-1; no candidate FFT/tree or vendor quotient. Synthetic L/diagonal encodings evaluate at public tau23 and are explicitly not trusted setup evidence. Full coefficient field tests and same-key tests complement that one evaluation/group comparison.
- **Same-key path:**48 transitions across raw rows5/9, N8/16, v=N-3/N+3 and original/A-augmented reductions. Tests compare cross encoding with independent dense schoolbook cross quotient, total correction with target-minus-base quotient encoding, every A/B1/B2/C component with target full under common test r/s, explicit vendor proof with the independently supplied quotient, and ordinary crates.io verification. Both methods yield96 accepted proofs and96 altered-public rejections. Common deterministic test r/s establish exact algebra, not entropy quality. Synthetic fixture setup seed82 and eight package/key identities are recorded in the worker summary.
- **Negatives/bounds:** domain/input/support/FFT/allocation/pair limits, huge unavailable intermediate domain and usize overflow without large allocations, independently bounded fallback, malformed output/table shapes and duplicate/out-of-range encoding indices. T4 same-key fixture has one nonconstant public value; five-public and wrong reduction/key identity negatives remain accepted T1/T2 coverage, not new T4 evidence.

Pinned Arkworks field/group/domain primitives and accepted row evaluation/proof formulas are shared dependencies. The decisive division/finite-part/dense quotient oracles do not duplicate the candidate tree. Ordinary verification checks the correct key/public statement independently, but pass count or fixed-randomizer verification does not prove a generic cryptographic theorem. The same-key correction code is test-only and does not claim a replaced production Anchor::update route. New production/dynamic call sites need their own exact material/domain/generation and bounded-work review.

## 5. Files, ownership and exact identities

Written only `docs/dynark/phase-2/evidence/t4-review.md`. Read T4-owned sources, accepted T2 code, protected source/log snapshots and public aggregate metadata. T5 live shared source, reference algorithms, original seven-transform full proof, manifests/locks and unrelated untracked files were not changed. Snapshot source-002 is accepted T2 commit `b6b00954290b32fb87d74b0b404a83d32ff48dba` plus the three named T4 overlays and only `mod cross; #[cfg(test)] mod cross_proof_tests;` registrations in lib. Reference pin remains `c73a380df86d8f5d195f1e20c8a1d86a7dce084b`.

Independent SHA-256 checks and live-versus-tested-snapshot equality at the worker's correctness freeze (subsequent live diagnostic edits are excluded):

| Identity | SHA-256 |
|---|---|
| src/cross.rs | `63483f6a0c3ebac424ced53383354641230320cc50f2f6f2d81065800f214869` |
| src/cross_proof_tests.rs | `38f52796ada9553738c80e55fcfcb0b5ae4890411085fdf3638323525f3763ff` |
| tests/cross_conformance.rs | `2565174768a95d8e4f51511abaeb736e9540dbe775dc1a99480ec8bbfa13dfa8` |
| tested snapshot lib.rs (minimal registrations) | `d0ce7266a7cbce960d4a0bba5eb7a9d95ef3a2c769ca32fbd41c0ff51ab3b53b` |
| Cargo.toml | `45215cb72b2d609506ced27e4c60f192856f559d43382647cc863da13c46e58f` |
| Cargo.lock | `aaf70b9ecf4dbbefc4d6c1cb34a3eabb7762860884f100497a22f92fd70d75c8` |
| source-002.json manifest | `e2ba2b2747c3466c22efaf694ca3e7b72cfcebcc142fcfbe5750b7530d76dd8e` |
| snapshot-green-002.json | `8238d2d7a431e289a9a0a4078710708a01587cd4fcab9deffa3aeb93a92e8433` |
| snapshot-proof-001.json | `98de423d2d44a03f6269ac10a5319729cb038845775b8955daaded95d3dabb5c` |

Worker `small-correctness-summary.json` records source/executable/dependency/fixture identities and preserved trials. Its standalone executable SHA is `f84bc7c48331aaaa394f9ea7ea56fee60bdfbbbb5ef5e4f2ba6b48135db2c52a`; same-key lib executable SHA is `c92597e0c3089453a0704da2efb1ac76c540d5869129a6acd333e5597dff3924`. These recorded executable IDs do not substitute for source review or fresh stdout. No dependency/license/version or vendor arithmetic change belongs to this candidate. Actual baseline manifests and reached accepted source identities match the protected manifest.

## 6. Commands and observed outcomes

Reviewer performed only read-only rg/cat/nl/sed/ls/jq/git show/diff/shasum inspections and apply_patch of this report. The following commands were executed by the named T4 worker, **not this reviewer**. Both run in protected source-002 with accepted T2 code, RAYON_NUM_THREADS=4, CARGO_BUILD_JOBS=2, shared protected target directory and single test thread:

| Worker run | Command body | Fresh aggregate stdout / runner outcome |
|---|---|---|
| snapshot-green-002 | `cargo test --locked --test cross_conformance -- --nocapture --test-threads=1` |12 passed/0 failed; body47.63s; runner50.792538875s; exit0, stop null, no remaining owned children |
| snapshot-proof-001 | `cargo test --locked --lib cross_proof_tests:: -- --nocapture --test-threads=1` |1 passed/0 failed/9 filtered;48 same-key cases; body12.01s; runner14.945695167s; exit0, stop null, no remaining owned children |

Standalone counted oracle/comparator work is **886,264 pairs =811,016 integration+24,090 finite-part+51,158 division**. Same-key invocation is **23,320 pairs**. Pre-case cap1,000,000 and invocation cap20,000,000 remain checked; standalone internal units reserve/cap their separate subtotals. Single-thread invocation makes its final atomic subtotal report complete. These counters describe executed test work, not cryptographic security strength or benchmark throughput.

Historical `red-001`, `red-002`, failed live `green-001` and earlier protected snapshot trials remain preserved. The live green compilation failure involved concurrently unfinished T5 sources and establishes no pass/fail of frozen T4 algebra; protected accepted-T2 snapshots prevent conflating that source state with this gate. No test pass is inferred from compilation alone.

Parent subsequently ran the frozen executables independently: `parent-kernel-001` passed12/12 with runner48.142203708s and sampled RSS4,636,672 bytes; `parent-proof-001` passed1/1 with runner12.344s and sampled RSS7,389,184 bytes. Both exit0, stop null, no remaining owned children. These are direct executable reruns, separate from the worker Cargo build/test command observations and not kernel latency benchmarks. Parent supplied the pass counts; aggregate JSON was independently inspected by this reviewer.

## 7. Measurements versus claims

Fresh worker runner samples record standalone peak process-tree RSS **458,260,480 bytes**, positive logical storage growth **7,727,847 bytes**; same-key RSS **414,892,032 bytes**, growth **29,931,298 bytes**. Both stay below their sampled command ceilings with no stop. These include build/test activity and exclude runner/ps RSS; polling can miss short peaks/deleted-file growth. They are not actual allocator live/peak/traffic, kernel latency samples or credential memory measurements.

No timing benchmark was run for this gate. `proposed-timing-plan.md` is explicitly unapproved/unexecuted and does not close any crossover or credential gate. Complete paid normalization/node conversion/tree/evaluation/inversion/encoding/public preparation and cold/repeated totals must be measured later, with counterbalanced samples and allocation diagnostics separated from timing. The candidate's union-based group encoding combines both L contributions and skips zeros; a later complete-group comparison must retain/label the accepted T2 separate-support comparator rather than silently use different group-call baselines.

## 8. Evidence and security limits

Evidence: approved `conformance.md` finite-part derivation/P2-E4a/T4 plan; code/source ranges above; `results/dynark/phase-2/cross-term/{source-002,snapshot-green-002,snapshot-proof-001,small-correctness-summary,parent-kernel-001,parent-proof-001}.json`; matching protected source snapshot, invocation, stdout and stderr under `artifacts/dynark/phase-2/cross-term/`. Reviewer inspected aggregate logs/public fixture metadata only.

This is a bounded arithmetic candidate for the exact fixed BN254 reduction/domain with authentic matching public material. Owning proof/state paths still require package/setup trust, canonical full assignment/public satisfaction, exact base/generation/holder/action binding, independent fresh secure caller r/s and protected valid private state. T4 contains no entropy path to bypass the accepted boundary. Correctness under test randomness does not show RNG security, arbitrary auxiliary-input security, simulation extractability, cache-compromise/side-channel/forward-security protection, original-zkey compatibility, real credential qualification or Solana execution. The reviewed benign-relation/auxiliary assumption and valid-state/no-leakage limits remain unchanged.

## 9. Next gate and nine-part return

Parent personally accepts these exact source identities after the completed independent frozen-executable reruns before promoting P2-E4a small correctness. No source fix is requested by this review. Diagnostic hooks, production call-site integration and T5 dynamics remain separate reviewed changes. A separately authorized recorded timing/allocator plan with protected actual support evidence is required before crossover selection or a speed claim; synthetic shape-matched timing alone cannot establish credential crossover.

Return: **scope** isolated T4 spec/code/security; **deviations** narrow P2-E4a correctness, crossover open; **files** report only; **identities** exact table/snapshot above; **commands/outcomes** worker12+1 and parent12+1 pass, reviewer none; **measurements vs claims** bounded test-command observations only; **evidence** independent field/division/polynomial/group/same-key checks; **security limits** inherited owner/provenance/entropy/state assumptions; **next gate** parent acceptance, then separately approved diagnostics/timing/integration.
