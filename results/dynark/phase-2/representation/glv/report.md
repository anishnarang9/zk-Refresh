# P2-E3a public-twiddle GLV reuse microexperiment

## 1. Scope and specification

October 10, 2026 local date. Isolated public-synthetic BN254 scalar-multiplication ablation under the previously recorded P2-E3a contract. The exact signed pair returned by unchanged pinned `GLVConfig::scalar_decomposition` is cached. `cached_mul` then preserves the pinned endomorphism, signs, zipped bit traversal (including its existing skip-zero behavior), doubling and joint addition. Parent personally reviewed this source before measurement and independently reran its tests afterward. No library/backend integration, new scalar algorithm, secret table, side-channel claim, credential projection, setup, deployment or full preparation/session claim is made.

Measured domains N=256 and N=4096; table contains all N forward powers, N inverse powers and N inverse normalization (513/8193 entries). Duplicated equal scalars across directions remain separate entries; no deduplication optimization is mixed in. Kernel selects 32 uniformly spaced powers per direction plus normalization: 65 multipliers/repeat. Four repeating point categories are infinity, generator, deterministic public pseudorandom subgroup point and projectively rescaled subgroup point. Thus approximately one quarter of points are each category; this is not a representative complete FFT workload. Cold pays for the entire table even when only 65 entries are sampled.

## 2. Files

Added only `crates/dynark-bn254/src/bin/phase2-glv-ablation.rs` with inline tests, and evidence beneath `results/dynark/phase-2/representation/glv/` plus protected `artifacts/dynark/phase-2/representation/glv/`. No manifest, lockfile, vendor, product library or baseline source edit by this worker. Other workers' concurrent changes remain untouched. No commit or push.

## 3. Identities

Frozen product snapshot: accepted T1 commit `9dc0547` (full commit and every file digest in `snapshot.json`), with only the candidate binary added. Snapshot identity SHA256 `358f19da668cee067bfd66873462a67c5111ca9ebb81067546e12c75688d1604`.

- Formatted candidate source SHA256: `6f22f3a90e8fe6533ee58b8d01f94bff6c5b56087b8d84facb6206839ce82e11`.
- Frozen Cargo.lock SHA256: `aaf70b9ecf4dbbefc4d6c1cb34a3eabb7762860884f100497a22f92fd70d75c8`.
- Uninstrumented executable SHA256: `5550f0f4af85216f232037eb675608e1c4e38de07038bc6e45e61e7347d46a62`.
- Allocation diagnostic executable SHA256: `1924a8075d545ba09284b21bc40076d7376f03a5e3edd6d2bede636fbc5aa03e`.

Pinned joint-multiply source `ark-ec 0.5.0/src/scalar_mul/glv.rs` SHA256 `5809156073c036613032fb992bffdfe522a3be41f15f369f474dd2815742d612`; BN254 config source SHA256 `d524540d74248d7fa6cfe7e141959b1b6ba04eda7c1265b32f981bed636e5e95`. Fixture identities in `provenance.json` hash the deterministic generation recipe (N, exact source, seed and curve/domain version), not serialized fixture bytes. No private inputs exist.

## 4. Commands and environment

Exact credential-free argv/cwd, report paths and observed limits are in `provenance.json`; protected invocation files retain the same commands. All jobs used the existing bounded runner and a serial execution slot. Cargo used `--offline --locked --release`, `-j1`, and fresh protected separate targets. First built `--bin phase2-glv-ablation`; separately built tests with `cargo test ... --no-run`, then ran that prebuilt test executable with `--test-threads=1`. Diagnostic target alone used `RUSTFLAGS=--cfg=glv_alloc`; timing executable has no custom global allocator and rejects diagnostic mode. Runtime invocations were `phase2-glv-ablation diagnostic 256/4096` and `phase2-glv-ablation timing 256/4096`.

Rust 1.100.0-nightly (908501772, 2026-08-30), aarch64-apple-darwin; Cargo 1.100.0-nightly; macOS 26.6.2; Mac15,6; 11 logical CPUs; 19,327,352,832 RAM bytes. RAYON_NUM_THREADS=4; this candidate executes serially and does not invoke Rayon. Build limits 600s/1GiB sampled tree RSS/2GiB target growth; prebuilt tests and each diagnostic/timing 300s/256MiB sampled tree RSS. Combined target logical size after builds 295,566,261 bytes. Private ancestors/directories are mode700; data files600; executable files retain required owner execution access. Public evidence is readable.

## 5. Tests and trial outcomes

Three tests passed: signed decomposition equality in Fr; equality to ordinary `point * scalar` including normalized affine equality, zero/one/order-minus-one/order-minus-two, generator/infinity, full-width deterministic public random scalars and rescaled subgroup points; every forward/inverse twiddle and normalization at powers of two N=1 through4096 plus individual selected heterogeneous-point equality. Checked twiddle suite budget is below75,000 logical group multiplications; other bounded tests add fewer than1,000. Parent independent prebuilt rerun also passed3/3 (1.64s body).

All three builds, worker tests, two diagnostics and two timing runs passed without limit stops or remaining children. Each timing has two excluded warmup batches then30 measured batches,15 each cached-first/pinned-first for each repeat scenario, all120 sample rows/domain plus30 lifecycle rows retained. Total work per timing run includes setup and warmup:20,865 logical group multiplications; each diagnostic715. Aggregate outputs also matched for every batch and repeat. No discarded measured samples.

## 6. Metrics

Descriptive medians of30 batches, milliseconds; paid cache total is construction + kernel + measured drop. Common synthetic fixture/public-scalar generation is outside these timed regions for both paths. These are table-and-kernel costs, not complete cold-session costs.

| N | Repeats | Pinned kernel | Cached warm kernel | Cached paid total | Paid wins/30 |
|---|---:|---:|---:|---:|---:|
|256|1|1.912|1.884|2.446|0|
|256|4|7.643|7.537|8.089|0|
|4096|1|1.871|1.817|10.342|0|
|4096|4|7.464|7.265|15.776|0|

Construction medians0.565ms/8.525ms for N256/N4096. Cached warm paired wins30/30,28/30,30/30,30/30 in table order; median paired warm savings are small relative to the batch spread. All paired paid outcomes lose. Full raw ranges, paired differences and process CPU tick distributions are in `summary.json`. POSIX process `clock()` uses1,000,000 ticks/second on this host; wall timing is monotonic. CPU/wall remain distinct.

Separate instrumented allocation diagnostics:

| Region | Requested live delta | Incremental peak | Allocation traffic | Allocation calls |
|---|---:|---:|---:|---:|
|N256 construction|41,040|41,352|557,136|16,902|
|N4096 construction|655,440|655,752|8,912,826|270,342|
|Pinned65 multipliers, repeat1|0|312|64,516|2,117|
|Pinned65 multipliers, repeat4|0|312|258,064|8,468|
|Cached kernel, either repeat|0|0|0|0|

Actual signed-pair layout80 bytes/entry versus66 logical payload bytes, plus24 bytes Vec metadata. Construction retained exactly41,040/655,440 requested bytes. Cached kernel has no observed allocation calls, while cold allocation traffic including construction loses for both tested repeat counts. Counters measure successful allocation/reallocation requested sizes, count reallocation new sizes as traffic, and exclude allocator metadata. Absolute live bytes and lifecycle table byte-nanoseconds are preserved separately in raw evidence; byte-seconds reflect this microexperiment's joint-batch table lifetime, not a holder/session lifetime.

Worker test sampled peak tree RSS3,555,328 bytes; parent3,538,944. Timing sampled peaks2,146,304/3,014,656 bytes. Diagnostic N256 ends too quickly to resolve a meaningful RSS peak (only32,768 bytes sampled); N4096 sampled1,998,848. Do not equate these sampled RSS observations with exact lifetime peaks or allocator live/peak. Build sampled peaks575,094,784 and574,275,584 bytes, safely below the declared ceiling.

## 7. Evidence paths

Public `summary.json`, `provenance.json`, `snapshot.json`, `timing-n256.jsonl`, `timing-n4096.jsonl`, `diagnostic-n256.jsonl`, `diagnostic-n4096.jsonl`, all corresponding bounded-run JSON and `parent-tests.json` reside beside this report. Protected snapshot, separate targets and raw stdout/stderr/invocations reside beneath `artifacts/dynark/phase-2/representation/glv/`. Source remains reviewable in the assigned standalone binary file.

## 8. Limitations and disposition

Measured paid work loses at repeats1 and4 for both domains. Preserve this negative result. Warm-kernel allocation elimination and small timing differences keep a higher-reuse hypothesis open; no statistically precise speed percentage or measured amortization threshold is established. These short approximately2–8ms batches on one machine are susceptible to scheduling/cache/clock noise. Whole tables are intentionally paid despite sampled entry use; domain/cardinality/deduplication and per-point mix materially affect economics.

No exact full FFT/projection vector, proof component, full preparation, credential-scale session, serialization/load, long-lived cache retention or constant-time security evidence is provided. Correct pinned scalar multiplication is necessary but insufficient for product integration. No product integration decision is taken.

## 9. Next gate

Parent has the reviewed candidate and exact microevidence. If pursuing higher reuse, prerecord finite workload/table economics and independent evaluation before a further bounded trial. Integration requires separately reviewed public cache identity/ownership, exact complete field/group transform and projection vectors on the same backend/key/reduction, relevant proof-component/ordinary-verifier evidence and a separately budgeted full preparation/session comparison charging construction, load, retention, all validation and discarded work. No new execution is authorized by this report. Serial slot was returned to parent/T2 after the measurements.
