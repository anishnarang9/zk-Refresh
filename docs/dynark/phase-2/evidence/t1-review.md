# T1 independent specification and code/security review

October 10, 2026 (America/New_York). Reviewer: `t1_review`, GPT-6.1 Sol high. This review is read-only apart from this report. Source baseline: root `0365566`; approved contracts `19ec7e1`/`bc10572`; reference pin `c73a380df86d8f5d195f1e20c8a1d86a7dce084b`. No implementation, helper, build, test, setup, benchmark, or commit was executed by this reviewer.

## 1. Scope and review order

First compared the implementation with `phase-2/architecture.md`, `conformance.md`, `experiments.md` and `phase-1/phase-2-plan.md` T1. No blocking specification deviation was identified, so proceeded to source-level code/security review. Inspected the new package boundary, all twelve conformance tests, the actual quotient/prover/setup routines reached by the boundary, the Phase 1 `full_without_cache` comparator, initial vendor metadata, lockfile differences and worker aggregate execution evidence.

**Verdict:** source review passes the narrow T1 gate, conditional on the parent independently rerunning consequential tests and confirming final source/evidence identities. No prioritized actionable code defect was found. This is neither a proof of general security nor permission to promote later engine modes or production/original-zkey claims.

## 2. Specification deviations and coverage

No blocking deviation. The stateless caller-supplied generation is explicitly documented as a label, not an authenticated persistence commit (`src/full.rs:8-15`, README). Stateful committed-generation/rollback obligations remain T5/T6. Bounded file parsing is T2; T1 consumes already allocated typed matrices/key and documents allocation exhaustion as unrecoverable.

| T1 requirement | Source and test evidence | Disposition |
|---|---|---|
| Exact circuit, matrix, schema, setup, curve, reduction and domain identity | `artifact.rs:195-259`: matrix rows/counts/terms; ordered length-prefixed schema; all supplied artifact digests; BN254, reduction, root/encoding conventions, domain; canonical PK/VK commitments. Metadata and setup provenance limitations documented. | Covered |
| Trusted expected manifest distinct from checksum | `artifact.rs:262-273`: required expected identity, full equality before package construction; `inspect_identity` explicitly identifies development/audit use. README warns against deriving expected identity from the same untrusted inputs. | Covered under the stated external trust contract |
| One immutable shared PK/matrix allocation | `artifact.rs:49-59,264-294,302-304`: consumed PK and matrix set live in one private `Arc`; clone shares storage. VK remains inside PK. Ordinary verifier copies only the instance query (`306-314`). Test `540-551`. | Covered; no UK/cache exists |
| Full no-cache seven-transform path preserving one | `full.rs:31-45`; vendor quotient has 3 inverse transforms, 3 coset forward transforms and 1 final inverse. Explicit instance slice begins at zero, matching Phase 1 `full_without_cache`. | Covered |
| Opaque canonical validated assignment | `artifact.rs:61-66,318-354`: no public constructor/accessor/deserializer; exact count, canonical field decoding, z0=1, exact expected public vector, full effective-row satisfaction, exact package identity. `full.rs:27-29` rejects assignment/package swaps before RNG access. | Covered |
| Fallible independent unbiased r/s; second draw and rejection exhaustion | `randomness.rs:9-31`: only `try_fill_bytes`, 254-bit mask and modulus rejection, separate sequential draws, at most 128 candidates each. `full.rs:30` samples both before arithmetic. Tests `501-536,555-602` cover first/second entropy failure, first/second exhaustion, rejection then acceptance and legal zero samples. | Covered assuming caller really supplies fresh cryptographic entropy |
| No insecure product proof convenience exports | `lib.rs:5-13`: private modules, only validated package/assignment/prove exports. Vendor setup, fixed-blinder, unblinded/raw, matrix-wrapper and RNG convenience APIs are not re-exported. | Covered; directly depending on experimental vendor remains outside the product boundary |
| v>N, v<N, non-power raw rows, varied sparsity/public layouts | `five()` gives v=9, N=8, six raw rows, five publics and a distant private coordinate; `c_only()` gives v=3, N=8, five raw rows. Duplicate/zero terms and zero public values at `634-649`. | Covered for these small fixtures |
| Five public alterations explicitly false | Ordinary registry verifier assertions `167-173` and `645-648`. | Covered |
| C-only public x in w*w=x | `32-44`, original/augmented matching proofs `191-201`: valid x=9 accepted, altered x=10 rejected; unsatisfied assignment rejected in full validation. No blanket public-u rank requirement. | Covered |
| Original/augmented same N=8 matching keys and mismatched quotient/key rejection | `178-272`: original five rows and augmented seven rows both N=8; matching package proofs accepted; exact identities differ; crossed raw quotient/key proofs use identical domain and explicit setup parameters and verify false in both directions. | Covered; cross fixture isolates reduction rather than ceremony |
| Malformed dimensions, fields, queries, identity and invalid groups | `320-417,420-497,606-630`: count/index/split/overflow/domain/schema/query failures; canonical modulus rejection; wrong setup/metadata/matrix identities; invalid curve point/denominator. | Covered for specified cases |
| Reference/probe and registry versions/licenses preserved | Read-only vendor tree/manifest/license comparisons and lockfile diff described below. | Covered |

No sparse transition or state-generation API is claimed by T1; its public/private/zero cases are full assignments. Delta normalization, valid transition pairs and anchored atomicity remain T2. The full proof equality test intentionally shares the vendor dense quotient and explicit-assignment prover; it is a wrapper/source-mapping oracle, not an independently implemented polynomial coefficient oracle. Independent crates.io verification and the reduction-crossing fixture provide different checks, but do not turn finite fixtures into a generic correctness theorem.

## 3. Code/security findings

No actionable defect found within T1 scope.

Reviewed the apparent mismatched-PK trust loophole: dimensions and subgroup checks cannot prove that a PK was honestly generated for the matrix, and the constructor does not claim that they can. Canonical matrix/circuit/PK/VK commitments all participate in the required separately trusted expected identity. Any changed PK or relation is rejected against that identity. Accepting a freshly computed identity for an untrusted or incorrectly generated tuple would violate the caller's expressly documented setup-provenance obligation, not bypass the comparison. T1 must retain this qualification in downstream integration.

Reviewed all arithmetic preconditions for the vendor full path: checked row/assignment arithmetic, supported exact radix-two domain and root convention, exact matrix rows and column bounds, instance/query split, N-1 H query, canonical point validity, nonzero gamma/delta denominator points, full satisfaction and constant one. Those validations make the vendor dense-evaluation indexing and supported-domain coset inversions well-defined. BN254's multiplicative generator is outside every supported radix-two subgroup, so the full quotient's coset denominator cannot vanish for these domains. The returned quotient must have N coefficients with final coefficient zero before the product sends exactly N-1 scalars to the H query. For satisfying rows, A*B-C is divisible by X^N-1 and has quotient degree at most N-2.

Randomness sampling is exactly uniform conditional on success for uniform input bytes: masking gives a uniform 254-bit candidate, then canonical modulus rejection admits each field element equally. The two draw loops are independent under a caller's independent CSPRNG draws; finite exhaustion bounds pathological callers without silently substituting a scalar. `CryptoRng` is a marker, not proof of entropy quality; deterministic scripted sources appear only in integration tests. Randomness errors return no proof, and the package/opaque assignment have no mutation path.

## 4. Files and ownership

Reviewed `crates/dynark-bn254/{Cargo.toml,Cargo.lock,README.md,src/lib.rs,src/artifact.rs,src/full.rs,src/randomness.rs,tests/full_conformance.rs}` and initial `vendor/ark-groth16/{Cargo.toml,PATCHES.md,LICENSE-APACHE,LICENSE-MIT,src/*}`. Source mapping read `experiments/dynark/proof-probe/src/bin/phase1-baseline.rs` and existing probe tests. Execution evidence read only scrubbed JSON reports and aggregate test/build output.

Only file written: `docs/dynark/phase-2/evidence/t1-review.md`. No other source or evidence was modified; no commit created.

## 5. Identities directly checked

The vendor Rust tree is byte-identical to the preserved Phase 1 tree (`diff -qr` produced no differences). Vendor manifest and both license files compare equal (`cmp` returned success). Existing assignment-column/anchored-OsRng patches remain isolated reference patches; T1 adds no arithmetic patch.

| Reviewed file | SHA-256 |
|---|---|
| `Cargo.toml` | `45215cb72b2d609506ced27e4c60f192856f559d43382647cc863da13c46e58f` |
| `Cargo.lock` | `aaf70b9ecf4dbbefc4d6c1cb34a3eabb7762860884f100497a22f92fd70d75c8` |
| `src/lib.rs` | `f2c5a65b0dfbaee2dd736b260799a0c65d4e609ca1f34bb3da84df816d4efc79` |
| `src/artifact.rs` | `a3c916f333ad7663b2d81c29b4d54a030752b8348092f09ca6798b8b23df25af` |
| `src/full.rs` | `8aa23983a9524d3b72022552a219be457ad970b02c7ca385de3ef8d4956b6579` |
| `src/randomness.rs` | `7fc2324647ae948009854dcca956dcf8ca80e890d68a562f739f5984cc7a6cbc` |
| `tests/full_conformance.rs` | `2647c89712e3068d5d43a435376983e814a7b34ec9b99d4f9208051ac3928dc5` |
| `vendor/ark-groth16/PATCHES.md` | `4c6c17017d0b4baf79d81725178c79088bec26ea9903fc624969c80d3e4ae46c` |

Direct probe lock hash: `8ac93d908b9fbada9e9844037d398241b117c25483c59b9298a49d698eb9374e`, matching the pre-copy snapshot. Lockfile diff removes probe-only packages and changes the local root package, without adding/upgrading registry package identities; this agrees with `dependencies.json`'s empty `changed_or_added_registry_dependencies`. Source snapshot and preserved patch-diff identity: `reference-snapshot.json`; patch diff `cce04ed6e83262cfbbb934fe035a77b57c6e54620cf95bf9598c714d241321e0`.

## 6. Commands and observed outcomes

Reviewer commands were read-only `rg`, `cat`, `sed`, `nl`, `wc`, `ls`, `jq`, `git status/show/diff`, `shasum`, `diff`, and `cmp`. No worker command below was executed by this reviewer.

Worker invocation `test-final-2/invocation.json` records `cargo test --locked --manifest-path crates/dynark-bn254/Cargo.toml --test full_conformance`, four Rayon threads. Its stdout records **12 passed, 0 failed**, test-body duration 1.03 s. Runner report records exit 0, no stop reason, complete owned-process cleanup, total command duration 3.960 s.

Worker `probe-tests/invocation.json` records `cargo test --locked --manifest-path experiments/dynark/proof-probe/Cargo.toml`. Aggregate stdout records **14 passed, 0 failed** across test-bearing targets (2 baseline, 3 census, 2 CLI, 6 import, 1 proof), including the expected regression that the direct vendor matrix wrapper rejects due to constant-one mismatch. Runner report records exit 0, no stop reason and total duration 3.315 s. Probe-build report records exit 0, 32.796 s.

Preserved red reports show the initial build failure and later 9-test trial with 3 passed/6 failed; the final conformance trial resolves those recorded failures. Red results are historical evidence, not current source findings. No private scalar/key/witness content was inspected or copied into this report.

## 7. Measurements versus claims

Worker `test-final-2.json` sampled peak owned-process-tree RSS **297,533,440 bytes**, positive logical storage growth **11,118,487 bytes**, within the declared small-test limits. Probe tests sampled **58,621,952 bytes** peak tree RSS and **10,780 bytes** storage growth; probe build sampled **480,722,944 bytes** and **233,884,674 bytes**. These include build/runner command activity, exclude runner/ps RSS, are sampled rather than guaranteed peaks, and are not prover memory or performance benchmarks. No credential-scale run, allocation optimization or security-through-test-count claim follows.

## 8. Evidence and security limits

Evidence: approved contracts cited in section 1; source ranges in section 2; `results/dynark/phase-2/t1/{reference-snapshot,dependencies,build-red,test-red,test-final-2,probe-build,probe-tests}.json`; protected invocation and aggregate test logs under `artifacts/dynark/phase-2/t1/`.

Trustworthy relation/setup provenance and genuinely fresh caller entropy remain external assumptions. Hashes identify supplied artifacts; they do not authenticate the witness executable or establish its relation semantics. The reviewed Groth16 benign-relation/auxiliary-input assumption remains unchanged. This source review does not establish arbitrary-auxiliary-input, simulation-extractability, cache-compromise, timing/privacy, production ceremony, quantitative BN254 security, original-zkey interoperability, original H-basis mapping, Solana execution or application freshness/authorization. No private cache, UK, anchored update, dynamic reconstruction or persistence product boundary was reviewed as implemented here. Experimental vendor convenience paths retain their documented limitations.

## 9. Next gate

Parent independently reruns consequential product/probe tests through the sole bounded execution slot, confirms final source/lock/executable/reference identities and personally reviews this boundary before declaring T1 complete. No T1 code fix is requested by this review. T2 may then implement bounded canonical import, exact normalized transitions and immutable anchored state under its own acceptance gate. Later proof paths must reuse the same validated package and fallible randomness boundary.
