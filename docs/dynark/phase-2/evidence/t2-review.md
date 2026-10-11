# T2 independent specification and code/security review

October 10, 2026 (America/New_York). Reviewer `t1_review`, GPT-6.1 Sol high, reassigned to T2. Accepted T1 baseline `9dc0547`; reference pin `c73a380df86d8f5d195f1e20c8a1d86a7dce084b`. Final source freeze was explicitly relayed by the parent after worker `final-small-gate-v3`. Only this report was written. No code/helper/build/test/benchmark/setup/commit/delegation was executed by this reviewer, and no actual private scalar/witness/cache contents were inspected.

## 1. Scope and review order

Reviewed approved `architecture.md`, `conformance.md`, `experiments.md` P2-E2 and Phase 1 `phase-2-plan.md` T2 against the exact T1 package/assignment/randomness boundary. Specification review identified the import defects below before the code/security disposition. Rechecked their fixes and final source, then reviewed normalization, shared column indices, exact immutable-anchor binding, projection/cross/correction algebra, legacy trust boundaries, test oracle independence and fresh aggregate logs.

**Verdict: pass for the narrow T2 source and small correctness gate.** No actionable defect remains in the frozen reviewed source. Worker and parent independent runs both record 23 passing tests. This does not close the separately budgeted credential-scale near/middle/far replay, later T4/T5/T6 gates, production security or original-key/Solana compatibility.

## 2. Findings, fixes and deviations

Three actionable import findings were sent to the parent during implementation and confirmed by the parent:

1. **P1 — R1CS artifact identity could describe bytes other than those parsed.** The initial legacy importer hashed an R1CS reader, dropped it, then reopened the path without hashing the parsed stream. A substituted file with identical matrices and changed non-matrix bytes could keep the expected matrix/package identity while falsely retaining the old artifact digest. Fixed: `import.rs:481-519,689-698` captures bounded immutable bytes and verifies the exact snapshot digest; `read_r1cs_received` parses that snapshot. Regression `exact_received_snapshot_survives_file_mutation_and_rejects_same_matrix_changed_header` verifies both captured-snapshot stability and rejection of same-matrix changed-header bytes against the old expected digest.
2. **P1 — preliminary hashing could exceed the received-file limit.** Initial hashing continued until EOF after only a metadata size check; a growing file could exceed the byte cap or prolong the loop. Fixed: `LimitedFile` bounds reads/seeks to its captured length and rejects changed length at EOF (`import.rs:65-118`); `hash_bounded` counts received bytes, and the second imported stream is capped and hashed. A growing-reader regression stops at the bound plus one detection byte. No metadata-only file-length claim remains.
3. **P2 — section-index allocation was not charged.** With a permissive configured section count, many empty sections could allocate a BTreeMap beyond the independently configured allocation ceiling. Fixed: supported WTNS/R1CS section counts and kinds are restricted before insertion, and the immutable snapshot plus conservative index storage is charged (`import.rs:153-201`). Tests cover excess supported section counts and insufficient index allocation.

The parent separately required field aggregation of the quadratic cross loop, checked second-pass entry sums, reuse of package column indices for legacy checks, explicit allocation accounting/capacity planning and security-binding negative fixtures. Final source includes these. The cross change preserves the same algebra; it is not T4's fast kernel. No reference arithmetic patch or dependency upgrade was introduced.

Legacy E2 bytes predate credential/action/generation metadata. The parent confirmed the required qualification now documented at `import.rs:821-825`: the external trusted manifest must associate the exact cache digest with the intended package, exact validated witness/public statement and initial binding. The digest alone cannot authenticate absent labels. Generic label-to-statement meaning and application authorization remain caller-policy obligations. This qualification does not relax subsequent exact anchor-token comparison.

## 3. Specification and code/security coverage

| Contract | Reviewed implementation and evidence | Disposition |
|---|---|---|
| Canonical bounded R1CS/WTNS | Captured immutable stream; file/type/received-byte/section/count/row-entry/allocation caps; exact BN254 modulus; canonical field decoding; checked instance split/index ranges; two-pass constraint counts and repeated allocation-pass checks. Snapshot/index storage and reader storage are charged. | Covered for supported formats and declared structural ceilings |
| Legacy public package | Preflight serialized vector/column lengths before allocating; checked fixed domain/key dimensions and canonical group decoding; actual consumed UK stream digest verified after import; exact original/augmented matrix and trusted PK/VK identity retained. Imported A/B columns checked against the existing shared package index rather than a duplicate. | Covered under externally authenticated content/setup provenance |
| Legacy anchor | Exact cache digest, fixed domain/instance/vector lengths and canonical groups; package/assignment checks; A, B1 and B2 checked against the validated witness and retained randomizers; C accepted only through the independent ordinary verifier; A/B rows recomputed, retained q imported without silent eager regeneration. | Covered under trusted manifest context and correct retained-projection provenance |
| No self-hash authentication claim | Strict importer requires externally trusted expected package and UK identities. `audit_legacy_package` explicitly supplies a development/audit candidate identity from authenticated legacy content, to record/review before strict replay. Legacy cache manifest context requirement is explicit. | Covered; audit bootstrap is not setup/application authentication |
| Shared immutable package/UK | `artifact.rs:49-59,289-308`: PK, matrices and exact column indices share one private Arc allocation; columns use counted capacities. `UpdatingMaterial` owns only L/w/diagonal public tables, no cloned PK; clones share its Arc. | Covered |
| Canonical normalized full-coordinate transitions | `delta.rs:134-186`: exact package/domain and increasing target generation; raw length/work/allocation limits; index bounds and canonical fields; reject every attempted nonzero constant mutation even if attempts cancel; additive duplicates summed and zeros removed. | Covered |
| Sparse row evaluations and counts | `delta.rs:190-258`: update full assignment, perform full exact-public/satisfaction validation; gather only normalized changed columns; preserve physical touched-entry/touched-row versus actual nonzero-row counts; separately charge full-validation entries and logical cross work. | Covered; full validation is not presented as incremental work |
| Exact named base and holder/action/generation binding | `anchored.rs:273-297` commits package/domain/credential/action/generation, full assignment, A/B rows, all raw proof components, both randomizers and both projections. `update:298-335` compares the entire transition base with the anchor binding before target validation/entropy/group work. | Covered; no plausible-public-vector shortcut |
| Entropy and immutable failure/success | Creation/update use only T1 fallible independent r/s; both sampled before proof arithmetic. Package, UK and Anchor expose no mutation/raw state/scalar serializer/accessor. Tests compare complete private-state snapshots after success, second-draw failure, pair cap and binding failures. | Covered under genuinely secure fresh caller entropy |
| Correct projection/cross/proof algebra | N-1 H basis padded with zero; N inverse and w0=0 preserved; correct reversed convolution/diagonal; both off-diagonal orientations and overlap term retained. C-row differences have zero quotient and still participate in full satisfaction. Correction uses exact anchor components and all public/private query deltas. | Covered by derivation/source mapping and independent polynomial oracle |
| Ordinary randomized verifier acceptance | Original/augmented reductions, v below/above N, non-power raw rows, no-op/reverse/overlapping/diagonal/disjoint support and five-public fixture; every altered public coordinate verifies false. Changed application action binding rejects. | Covered for finite synthetic fixtures |
| Wrong identity negatives | `binding_negatives_preflight_without_entropy_and_preserve_all_state` changes credential, base generation, anchor_state, proving-key identity, domain and action; wrong UpdatingMaterial rejects. All reject before RNG access and preserve complete state. Different-witness anchor token also rejects. | Covered |
| Original reference and T1 boundaries | Vendor Rust tree compares byte-identical to Phase 1; T1 full/randomness/manifest/lock/test files are unchanged against accepted baseline. | Covered |

The final cross loop (`anchored.rs:108-149`) makes exactly `|da|*|db|` checked pair visits, accumulates both oriented field coefficients and performs logical group scalar multiplications for each A/B support entry plus diagonal overlap. Normalized row supports are sorted and distinct. It retains quadratic field work and linear group work; no subquadratic claim is made. Cross caps are enforced before entropy and again inside the kernel.

`Transition::validate_target` is a reusable assignment/row-preparation operation; the exported successful proof path additionally enforces exact anchor binding. Its output is not a separately authenticated state generation. T2 anchors remain immutable bases, and returned target generation/public proof labels do not implement a dynamic commit or anti-rollback store.

## 4. Files and ownership

Reviewed `src/{import,delta,anchored}.rs`, changes to `artifact.rs`/`lib.rs`, unchanged `full.rs`/`randomness.rs`, `tests/{delta_contract,anchored_conformance}.rs`, `tests/support/mod.rs`, T1 tests and the reached reference source. Only `docs/dynark/phase-2/evidence/t2-review.md` was written. Unrelated untracked files, T3 standalone GLV microexperiment, persistence design and later engine tasks were not modified or promoted by this review.

## 5. Frozen source identities

SHA-256 independently read after the explicit final freeze:

| File under `crates/dynark-bn254/` | SHA-256 |
|---|---|
| `src/lib.rs` | `796f9bf89e7b984b82846388bc0eba3fe3d98e836656c34a31693016e977a826` |
| `src/artifact.rs` | `ac675e7ddefb0f16a9394fa1f1a83472bf4decca2a621dfe7747a27b2a2a50cf` |
| `src/delta.rs` | `e01256db13e5d8d89333e4a0ddcda14dcdcb35f5a52cd5455322d4b3d61aa879` |
| `src/anchored.rs` | `6ef6e2949e414644aac94e77c104a3fdda1bac756a0fcc05b43f01e910a60737` |
| `src/import.rs` | `1447fc1d29a640a933e1fcee674a78b676d7af0b5ef75e1e9019a64f2d36dc10` |
| `src/full.rs` | `8aa23983a9524d3b72022552a219be457ad970b02c7ca385de3ef8d4956b6579` |
| `src/randomness.rs` | `7fc2324647ae948009854dcca956dcf8ca80e890d68a562f739f5984cc7a6cbc` |
| `tests/delta_contract.rs` | `6b4afcc152b5c070c2ac3c49e54215f4a476b540affefeca9b3accc40ea0d25c` |
| `tests/anchored_conformance.rs` | `18cf02b404c60b3677d86c4a59700835891e39c69b90a733040ce97be1d86c58` |
| `tests/full_conformance.rs` | `2647c89712e3068d5d43a435376983e814a7b34ec9b99d4f9208051ac3928dc5` |
| `tests/support/mod.rs` | `6494f89840b98721e6b2dc6c923b4f9803ef9c5f0d388a92c523190080878a1e` |
| `Cargo.toml` | `45215cb72b2d609506ced27e4c60f192856f559d43382647cc863da13c46e58f` |
| `Cargo.lock` | `aaf70b9ecf4dbbefc4d6c1cb34a3eabb7762860884f100497a22f92fd70d75c8` |

`git diff 9dc0547` shows no manifest/lock/full/randomness/T1-test changes. `diff -qr` shows no vendor Rust difference from `experiments/dynark/vendor/DYNARK_/ark-groth16/src`. Final `identities.json` records source-tree digest `e31f1de5938318af7e3fc257b2fb873e32b98573e28e58348a59e5e94afa7db2` using SHA256 over sorted path/NUL/file-hash/newline records for the crate excluding target/.DS_Store. That worker aggregate includes the separately owned T3 binary as context; this review's scope is the individually verified T2/T1 files above. The manifest also records the four test executable identities and 25 unchanged accepted-T1 files. No source identities are inferred from test count or filenames.

## 6. Commands and exact observed outcomes

Reviewer commands were read-only `rg`, `cat`, `nl`, `sed`, `wc`, `ls`, `jq`, `git status/diff`, `diff` and `shasum`; `apply_patch` created only this report. No execution slot was used. The following commands were executed by the named worker/parent, not by this reviewer:

- Worker `final-small-gate-v3/invocation.json`: `/usr/bin/time -l cargo test --locked --manifest-path crates/dynark-bn254/Cargo.toml --lib --test delta_contract --test anchored_conformance --test full_conformance -- --nocapture`; four Rayon threads. Aggregate stdout: **6 library + 2 anchored + 3 delta + 12 T1 = 23 passed, 0 failed**. Exit 0, no stop reason, no remaining owned processes. Run UTC `2026-10-11T01:02:06.051515` through `01:02:16.157975`, duration 10.107 s.
- Parent `parent-conformance.json`, owner `orchestrator_t2_verification`: independently reran `cargo test --locked --offline --manifest-path crates/dynark-bn254/Cargo.toml --lib --test full_conformance --test delta_contract --test anchored_conformance` after freeze. Aggregate stdout: **23 passed, 0 failed**; exit 0, no stop reason, duration 5.854 s.

Historical red/gate trials remain preserved. For example, `gate-3` had a touched-count fixture failure; final worker and parent trials pass that named test. Those historical failures are not suppressed and are not treated as current failures.

## 7. Measurements versus claims and oracle independence

Worker final sampled process-tree peak RSS **631,242,752 bytes** and positive logical storage growth **21,682,389 bytes**; parent rerun sampled **55,033,856 bytes** and **9,471 bytes**. These are bounded-command/resource observations, include differing rebuild work, exclude runner/ps RSS, and can miss inter-sample peaks. They are not prover performance, allocator peak, credential memory or latency evidence. Declared allocation ceilings are conservative structural/requested-storage checks, not a guarantee of allocator/RSS behavior or recoverable operating-system exhaustion.

The raw algebra oracle (`anchored.rs:382-560`) uses independently written schoolbook polynomial multiplication and division by X^N-1, separate from the vendor quotient routine. It checks every projection entry and diagonal against directly constructed Lagrange coefficients; cross encoding against polynomial multiplication; quotient correction against dense target-minus-base coefficients; all A/B1/B2/C target components under common test r/s; and whole-anchor serialized-state equality. Arkworks interpolation/group primitives and the vendor explicit-assignment proof formula are shared dependencies, with an independent crates.io ordinary verifier at the randomized proof boundary. Four small shape/reduction configurations and finite satisfying pairs are evidence, not a generic theorem or security-through-pass-count argument.

## 8. Evidence and security limits

Evidence paths: approved contracts in section 1; named source ranges above; `results/dynark/phase-2/t2/{red-1,gate-1,gate-2,gate-3,gate-4,gate-5,gate-6,gate-7,final-small-gate,final-small-gate-v2,final-small-gate-v3,parent-conformance}.json`; corresponding protected invocation and aggregate logs under `artifacts/dynark/phase-2/t2/`.

The externally trusted manifest must authenticate exact artifact context; hashes cannot certify an honest ceremony, executable semantics, application holder/action meaning or projections produced incorrectly by a trusted producer. Legacy q acceptance specifically depends on trusted exact-cache/projection provenance and matching context; T2 intentionally does not spend another full eager preparation to recompute them. Group/raw/proof checks add binding evidence but do not establish arbitrary retained-projection correctness from serialization alone.

Fresh secure caller entropy, confidentiality/no leakage of anchor/cache state, the reviewed Groth16 benign-relation/auxiliary-input assumption and exact relation/setup/reduction remain requirements. No arbitrary-auxiliary-input, simulation-extractability, cache-compromise, timing privacy, forward-security, quantitative BN254 or production setup claim follows. E2 plaintext legacy import is a protected local migration/replay tool, not T6 authenticated confidential persistence or rollback protection. Strict execution-current-root/issuer freshness, real credential/application qualification, original-zkey/H-basis compatibility and Solana execution remain outside this gate.

## 9. Next gate

Parent personally confirms the frozen hashes and independent 23-test rerun, then may accept the T2 source/small correctness boundary. No further T2 source fix is requested by this review. Record a separate bounded actual near/middle/far replay before reading/preparing credential-scale artifacts; enforce the trusted manifest's package/witness/public/session context and compute each delta from its actual named base. Small-gate acceptance permits the separately approved T4 work; T4/T5/T6 need their own source/oracle/state/security gates and cannot inherit a pass from this report.
