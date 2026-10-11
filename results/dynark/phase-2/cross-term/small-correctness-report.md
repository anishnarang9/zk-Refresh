# T4 small correctness handoff

## 1. Scope and deviations

Implemented the parent/T0-reviewed independent finite-part Trummer/product/remainder-tree kernel. The supplied paper omits the fast algorithm. The candidate uses FFT multiplication and reversal/Newton polynomial division; it shares one denominator tree and derivative evaluations across both numerators, preserves a separate diagonal term, and keeps bounded weighted quadratic fallback. Parent review corrected the initial proposed quadratic per-pair inversion and whole-union zero scans before successful tests: the final comparator borrows existing weights and visits exactly normalized A×B pairs.

Concurrent unfinished T5 module registration blocked the first live GREEN compilation. The parent authorized an accepted-T2 source snapshot, later extending ownership to test-only cross_proof_tests.rs and snapshot-only module registration. Successful tests use that snapshot; no live integration or dynamic-state acceptance is claimed. No timing, credential input/load/setup/preparation, push, PR or deploy occurred.

## 2. Changed files

Only live source additions: crates/dynark-bn254/src/cross.rs, src/cross_proof_tests.rs and tests/cross_conformance.rs. Results are confined to results/dynark/phase-2/cross-term/, and protected snapshots/logs/binaries to artifacts/dynark/phase-2/cross-term/. The protected source-002 lib.rs alone adds `mod cross; #[cfg(test)] mod cross_proof_tests;`. Live lib.rs/anchored.rs/artifact.rs/delta.rs/import.rs/manifests/lock/vendor/shared tests were not edited by T4. Existing baseline untracked files were not staged, swept or deleted. Parent owns any commit.

## 3. Source, dependency, build and fixture identities

Baseline snapshot commit: b6b00954290b32fb87d74b0b404a83d32ff48dba. Frozen reference pin remains c73a380df86d8f5d195f1e20c8a1d86a7dce084b, with only its pre-existing generator/prover modifications observed.

Final source hashes:

- cross.rs: 63483f6a0c3ebac424ced53383354641230320cc50f2f6f2d81065800f214869
- cross_proof_tests.rs: 38f52796ada9553738c80e55fcfcb0b5ae4890411085fdf3638323525f3763ff
- cross_conformance.rs: 2565174768a95d8e4f51511abaeb736e9540dbe775dc1a99480ec8bbfa13dfa8
- unchanged Cargo.lock: aaf70b9ecf4dbbefc4d6c1cb34a3eabb7762860884f100497a22f92fd70d75c8
- cross test executable: f84bc7c48331aaaa394f9ea7ea56fee60bdfbbbb5ef5e4f2ba6b48135db2c52a
- library proof test executable: c92597e0c3089453a0704da2efb1ac76c540d5869129a6acd333e5597dff3924

Complete source-001/source-002 manifests and small-correctness-summary.json contain per-file archive/overlay hashes, pinned resolved dependency identities and eight actual synthetic matrix/circuit/PK/VK/package fixture hashes. Build toolchain: rustc 1.100.0-nightly (908501772,2026-08-30), cargo 1.100.0-nightly (e8cb624d5,2026-08-22), Darwin25.6.0 arm64. This is a pinned local build result, not a portability qualification.

## 4. Exact commands

All launches use the unchanged existing results/dynark/phase-2/bootstrap/bounded_runner.py, named exclusive parent queue ownership, fresh output paths and explicit 600-second / 1,073,741,824-byte sampled tree-RSS / 2,147,483,648-byte storage-growth ceilings. Each child command explicitly sets RAYON_NUM_THREADS=4 and CARGO_BUILD_JOBS=2; successful snapshot commands additionally set CARGO_TARGET_DIR to the protected source-001 target. Test threads are one.

Exact argv/cwd/output paths for every trial, including failures, are preserved in protected invocation.json files and copied into small-correctness-summary.json. The two successful child commands, in source-002/crates/dynark-bn254, were:

```
cargo test --locked --test cross_conformance -- --nocapture --test-threads=1
cargo test --locked --lib cross_proof_tests:: -- --nocapture --test-threads=1
```

No further build/test runs occurred after releasing the queue. rustfmt touched only the three owned source files. Compiled protected binaries are owner-executable mode700; protected directories700/files600.

## 5. Fresh passes and preserved failures

| Trial | Result |
|---|---|
| red-001 | Compile failure: missing AdditiveGroup for Fr::ZERO in test/scaffold; preserved |
| red-002 | Intended RED: finite-part test executes and rejects zero scaffold versus nonzero direct sums |
| green-001 | Concurrent live T5 compile failures before T4 tests; preserved and relayed to owner |
| snapshot-green-001 | Owned randomized test borrowed RNG simultaneously in filter/map closures; corrected to filter_map; preserved |
| snapshot-green-002 | 12/12 tests pass; 112 randomized field cases,48 randomized dense quotient cases,24 complete finite-part vector cases,44 independent reciprocal/remainder cases,edge/cancellation/uneven support,FFT/support/allocation/overflow/pair/fallback/encoding negatives |
| snapshot-proof-001 | 1/1 test passes:48 validated transitions ×2 methods across eight matching-key fixtures, N8/N16, original/augmented, v<N/v>N; exact cross/quotient and all A/B1/B2/C comparisons;96 ordinary accepts and96 altered-statement rejects |

Field/group oracles independently express direct reciprocal sums, explicit Lagrange interpolation, schoolbook polynomial multiplication and division by X^N-1. The arithmetic unit oracle checks fast polynomial division against independent long division. Invalid field-domain size preflight is tested without large allocation. Actual observed intermediate FFT sizes are checked against required_fft_size for uneven and randomized trees. No algebra mismatch or resource stop occurred in the successful trials. Existing pinned vendor/GLV warnings remain; snapshot registration also gives expected dead-code warnings in a non-test library build before live integration.

## 6. Measured units, samples and conditions

The following are correctness-command resource measurements, not kernel performance samples:

| Successful run | Runner wall seconds | Test wall seconds | ps/storage samples | Sampled peak owned-tree RSS bytes | Sampled positive logical-byte growth |
|---|---:|---:|---:|---:|---:|
| snapshot-green-002 | 50.792538875 | 47.63 | 205 | 458,260,480 | 7,727,847 |
| snapshot-proof-001 | 14.945695167 | 12.01 | 61 | 414,892,032 | 29,931,298 |

The first isolated dependency build failure had sampled peak RSS801,144,832 bytes and155,953,269-byte growth, still below its ceilings. All six runs ended with no live owned descendants and known cleanup status; no watchdog limit fired. Runner RSS excludes runner/ps and is not allocator requested-live/traffic; storage is logical positive size growth, not blocks or retained memory. Short intersample spikes may be missed. Child thread settings are explicit argv; runner environment metadata alone describes the runner, not the child env wrapper.

Standalone pair visits:811,016 integration/direct/weighted/polynomial +24,090 complete finite-part +51,158 polynomial-division oracle =886,264. Each case is prechecked <=1,000,000 and the standalone invocation's ledger reserves2,000,000 for the two independently <=1,000,000 unit subtotals, within20,000,000. Same-key invocation:23,320 checked visits. Public test seeds and exact count records are in stdout/summary; no deterministic production proof RNG was introduced.

## 7. Primary logs and results

Scrubbed aggregate entry point: small-correctness-summary.json. Per-run sampled reports: red-001.json,red-002.json,green-001.json,snapshot-green-001.json,snapshot-green-002.json,snapshot-proof-001.json. Complete source manifests: source-001.json/source-002.json. Primary protected successful logs: artifacts/dynark/phase-2/cross-term/snapshot-green-002/{stdout,stderr}.log and snapshot-proof-001/{stdout,stderr}.log. Failed source snapshot and trial logs remain preserved.

## 8. Security assumptions, risks and limits

Rows normalize only after raw length/allocation/overflow and index checks; duplicate additions cancel in the field and zeros are removed. Exact domain and s+1/Newton intermediate transform support are checked. Quadratic fallback independently preflights its scratch and pair budget, and occurs only on selected preflight FFT/allocation failures, never invalid input or arithmetic mismatch. Encode checks all material/output lengths, sorted distinct bounded indices and domain shape before group work.

The kernel borrows authenticated public weight tables, checks only lengthN and w0=0, and does not recompute/hash allN weights. Package/material provenance and matching identity remain the owner's boundary. A same-length arbitrary basis/table is not authenticated by this module. Structural allocation estimates are deliberately conservative and include map/tree/numerator/remainder/Newton/FFT/output work; they are not an allocator measurement or runtime OOM/abort recovery promise.

The polynomial core is O(M(s)log s), with FFT/Newton enabling O(s log²s) polynomial work. Full calls additionally pay raw-entry normalization and s domain.element root exponentiations, O(s log N). No current-d-only bound follows for an accumulated/current union. Result stats distinguish raw A/B, normalized A/B, union and diagonal overlap; the caller separately records current/accumulated support.

Candidate encoding collects both L orientations into one coefficient per union index and skips zero terms. The accepted anchored quadratic comparator remains unchanged and separately uses A/B-support L calls plus overlap diagonal calls. Any later complete-group comparator must preserve or explicitly isolate this grouping change; it cannot be silently attributed to Trummer field work.

Exact deterministic common-r/s tests establish algebra under valid assignments, not production entropy quality, zero-knowledge under compromised state, timing privacy, setup-ceremony honesty or external root/issuer freshness. T1's caller randomness/full-validation contracts and external application authorization remain necessary. No private raw state or field values appear in scrubbed reports; protected failure assertions contain only synthetic test data.

## 9. Next gate and prerequisites

Parent must independently review/rerun the frozen source and accept this small correctness result. T5 alone performs live module registration and production call integration, preserving trusted package/material and caller-entropy boundaries; live dynamic integration remains untested by T4. The proposed-timing-plan.md is a separate unexecuted request: fair shared-weight field comparison, inclusive tiny/uneven/near-middle-far work budget and30 counterbalanced paired samples, separate allocator diagnostics and charged public table construction. Public aggregate shape-matched support data cannot establish credential-specific crossover; protected actual support replay requires another explicit budget. New-action unbounded quadratic work remains prohibited. No timing or credential speedup gate is closed here.
