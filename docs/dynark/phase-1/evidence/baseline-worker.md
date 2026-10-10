# Baseline worker evidence record

Owner: `baseline_audit`, GPT-6.1 Sol, medium reasoning. Date: October 10, 2026. Sole heavyweight-job queue owner. This file records primary local evidence; the parent owns the synthesized baseline audit. E1/E2 scope is approved in [experiments](../experiments.md).

## Preserved identity and historical claims

Root Git remains absent (`git status --short` returns fatal not a repository); no Git was initialized. The vendored reference has its own Git metadata: HEAD `c73a380df86d8f5d195f1e20c8a1d86a7dce084b`, exactly two modified files, generator column sizing and semi-dynamic `OsRng`, matching retained `reference.patch`. Current-source and historical artifacts are hashed in [baseline-freeze.json](../../../../results/dynark/phase-1/baseline-freeze.json), 165 entries. This records observed identities, not a recovered historical source snapshot.

The original R1CS is unchanged: SHA256 `ff4ee937061ee60e4d4043f1213ff562f72e0828986462e8ebbec8cdfabb326d`; original zkey `c0701766fce4ad681e1cc45b5a7812209fb7451f0e81e08220b08429970cbfd2`; original VK JSON `32edd11a18cefe52dc1eb9290313428857e0c25ccec3d54a1c95cef8f8ef31a8`. These match `artifacts/setup/setup.json`. The reported public-ceremony pin was computed from an organizer HTTPS download, not an organizer-published checksum; full ceremony verification is explicitly false, phase two has one development contributor. No production-setup claim is justified.

Historical near-v1 has 648,156 constraints, 643,563 assignment values including constant one, five public signals, domain 1,048,576. Near assignment delta 5,081 comprises one public root plus 5,080 auxiliaries; nonzero A/B/C evaluation deltas 2,390/2,370/2,370. The per-loop nested support pair count is 5,664,300. Middle/far/new-action and ten serial transitions remain witness/census evidence only; own revocation log has the exact `Credential_426 line: 115` assertion rather than generic CLI failure.

Retained near-v1 contains cache, ordinary VK, initial/updated proofs and before/after public values. The cache is 67,109,349 bytes; each proof 128 compressed bytes. **No historical proving/updating key is retained.** The reported 136,525,077/427,598,901-byte key values were serialization sizing, not files. The retained cache includes proof randomizers/private projections and is incompatible with a different development setup. One new matching preparation is therefore required for E2; fresh replay needs none.

Historical raw stage/sample report is `artifacts/dynark/engine/near-v1/report.json`; process timing log `artifacts/dynark/engine/logs/near-v1.log` establishes 994.55s total wall, 3,791.64s user, 28.86s system, 1,605,271,552-byte lifetime RSS, 2,857,863,904-byte macOS peak footprint. RSS/footprint are different metrics and neither measures stage allocation. Four Rayon threads, fixed full-before-update order, one warm-up and five measured pairs; host applications were open. Full proof includes base cache construction. Complete-refresh figures in feasibility are sums of separate stage medians, excluding import/path/network/maintenance. These remain historical observations, not fresh measurements.

Historical measured binary SHA256 `21ab5b74d48c42514a39860e6c4ed707ec96e5407e5bc897cb3091c07ad285ad` is documented but not retained at the current binary path. Current original release binary hash matches the stated final rebuild `e4a03d9a6e4cf2891563838ee576a5ea0517219780d68b7886e611fb13ec6e22`; Cargo.lock matches `8ac93d908b9fbada9e9844037d398241b117c25483c59b9298a49d698eb9374e`. An archived pre-robustness probe exists at `artifacts/dynark/engine/upstream-regression-probe/`; textual comparison to current main/lib confirms only atomic output creation and parser allocation bounds differ, with prover/benchmark equations unchanged. Its Cargo file points to an upstream-regression vendor, and no historical build manifest establishes that this exact archived copy produced the measured binary. Thus source-diff evidence supports the documented parser/output-only change, while the complete measured-source-to-binary association remains unresolved. The archived copy is frozen in `results/dynark/phase-1/historical-probe-source-identity.json`. New E2 establishes explicit current-source/build identity.

Historical `all-tests-final.log` actually contains six proof tests; the final source has nine, including later robustness checks. Fresh tests reconcile this naming/provenance gap without rewriting old logs.

## Source trace and compiler provenance

Observed compile command in `harness/src/main.rs`: `circom circuits/credential.circom --r1cs --wasm --sym -l node_modules --O1 -o artifacts/circuit`. It calls `write_profile()` first; no compile command was rerun. Source/generated-profile hashes and dependency locks are frozen, but a historical full compiler/library source manifest is unavailable. Installed versions freshly read: snarkjs0.7.6, circomlib2.0.5, @zk-email/circuits6.3.4. The experiment reuses exact hashed R1CS/WASM; it does not establish that rebuilding every historical compiler dependency reproduces those bytes.

The circuit has fixed certificate bytes/dynamic ranges, two RSA checks and depth10 path; public order is root/issuer/notBefore/notAfter/action. Rust registry revocation clones active flags and rebuilds the whole tree before publishing a new snapshot, rather than incrementally maintaining a path. The original prover locks one proof job, calculates the full WASM witness, invokes snarkjs with original zkey, then verifies retained proof/public artifacts. The DYNARK witness probe freezes synthetic credential/signature/action inputs and changes tree witnesses; importer validates canonical fields/shape and full R1CS satisfaction; assignment deltas are global wire indices. The new proof pipeline keeps this same relation and uses a separate matching development setup.

`harness/src/policy.rs` separately enforces time/issuer/current root or bounded historical policy. `program/src/lib.rs` enforces canonical public fields, issuer, expected program/registry/recipient/action digest, execution Clock time, accepted root and ordinary proof before receipt creation. New E2 ordinary verifier tests statement binding only; no execution/root-publisher integration is rerun. Tree/path construction and acquisition are outside E2 because it begins from frozen near-after input JSON; no total application authorization claim follows.

## Fresh inexpensive verification

[Retained proof replays](../../../../results/dynark/phase-1/retained-proof-replays.json) record exact arguments, stdout, stderr and exits. Six replays passed: initial/original and updated/current ordinary acceptance; updated/stale and initial/new-root ordinary rejection (`valid=false`, exit 1); two retained baseline snarkjs proofs `OK`. This verifies mathematical statement binding, not execution-current-root program integration.

Commands actually run (all logs under `artifacts/dynark/phase-1/baseline-audit/`):

```sh
cargo test --locked --offline --manifest-path harness/Cargo.toml
cargo test --locked --offline --manifest-path program/Cargo.toml
CARGO_TARGET_DIR=harness/target cargo test --locked --offline --manifest-path experiments/dynark/witness-probe/Cargo.toml
cargo test --locked --offline --manifest-path experiments/dynark/proof-probe/Cargo.toml
cargo test --locked --offline --manifest-path experiments/dynark/proof-probe/Cargo.toml --bin phase1-baseline
cargo build --locked --offline --release --manifest-path experiments/dynark/proof-probe/Cargo.toml --bin phase1-baseline
```

Fresh outcomes: harness 23, program 13, witness 8, proof 9 existing plus 2 new = 11. Logs: `harness-tests.log`, `program-tests.log`, `witness-tests.log`, `proof-tests.log`, `e1-final-tests.log`, `release-build-final.log`. Existing vendor warnings remain; no warning fixes were made.

Test-first comparator evidence: `e1-red.log` fails with intentional `Unsatisfiable` placeholder; `e1-green.log` records initial compilation failure from JSON numeric literal inference; corrected `e1-green-2.log` and `e1-final-tests.log` pass both inline tests. The ordinary no-cache path preserves constant one and verifies a nine-wire/six-constraint relation with five public values; changed action rejects. The vendor direct matrix wrapper returns an invalid proof on this relation because it strips constant one before a prover that expects the full instance. Its regression test confirms ordinary rejection without modifying vendor code.

## E2 design and resource boundary

Only implementation change owned by this worker: `experiments/dynark/proof-probe/src/bin/phase1-baseline.rs` (inline tests, Cargo auto-discovery). The corrected comparator uses the same vendor QAP reduction and PK as anchored update; it moves A/B/C evaluations into quotient computation without extra clones and creates the full assignment proof without constructing retained DYNARK cache. It is an optimized ordinary comparator within the reference reduction, not a crates.io-key or snarkjs-zkey import.

One fresh matching PK/UK/cache package is saved with mode600 inside a new mode700 run directory, hash checked and reloaded. Full-cache/full-no-cache/update supplied-witness order is counterbalanced; warm-up separate. Complete local trials measure witness calculation, canonical WTNS parsing/count/constant validation, necessary assignment delta, proof, encoding and ordinary verification inside one outer wall clock. Full R1CS satisfaction is preflight; generated-WTNS hash checking is outside timed refresh. No incremental witness engine, path acquisition, transport or Solana submission is measured. Anchored cache stays immutable, so synchronous maintenance is zero for this experiment only.

Stage process and child CPU, wall time, lifetime RSS and current RSS snapshots are recorded; snapshot overhead is inside outer refresh time. Child live/peak memory and allocator tracing are unavailable. An external watchdog enforces35m,4GiB prover RSS and2GiB total retained files during long calls, rather than only at stage boundaries. No automatic preparation retry.

Hardware/runtime observed: Apple M3 Pro,18GiB RAM,11 logical/physical CPUs, Darwin25.6.0 arm64; rustc1.100.0-nightly(908501772,2026-08-30), Cargo1.100.0-nightly(e8cb624d5,2026-08-22), Node24.10.0, Circom2.2.3. E2 uses four Rayon threads and release thin LTO. [E2 build manifest](../../../../results/dynark/phase-1/e2-build-manifest.json) freezes source/vendor/lib/build/runtime identities. Its hash is `2f99307503f2bdf280b28d6b230cfe9c454cb3f6340702400946c34da0279adb`; E2 binary `ac864557c42fff1cd680da3b7f793e9b35660601b4f61f0300a6ac9f8e84837f`.

Before launch the host was occupied: OS/user GUI processes consumed substantial CPU. Applications are left running; results must retain that caveat. No baseline fixture, circuit, key or historical report was changed.

## Interpretation rules for E2 aggregates

Main no-cache/update proof positions are balanced15 first/15 last among measured triples. The cache-building full path is always in the middle, so its timing relative to the endpoints has carryover/order confounding. Report its raw descriptive timing without attributing an isolated causal cost to cache construction; moving quotient inputs also removes array clones.

Complete refresh comparisons report10 raw paired wall-time differences, medians/ranges and mean saving. Repeated-session economics for0/1/2/5/10/100/1000 updates use the measured mean paired saving with explicit fixed-transition assumptions. These are derived estimates, not sequential-root/workload measurements. Common development setup and first action proof are reported separately; they are excluded from differential refresh economics. Public updating-key preparation and private projection preparation are distinct measured stages. Package serialization and reload each include mixed public/private state and are measured only in aggregate, so charge each once and never pretend to split their wall time by serialized byte proportion. A warm shared-public/no-I/O private-preparation lower bound and conservative all-package-I/O scenario are shown separately. The initial cached versus no-cache proof cost difference is unisolated and must not be presented as a causal overhead.

## Status

E1 complete. After the crypto worker hit rate limits, parent transferred E3 routine execution to this worker without source ownership or modification. Unchanged E3 ran in3.54s with4,243,456-byte parent lifetime RSS:80 cases completed,48 matched arkworks,32 mismatched. Every n32/128 field/G1 FFT/IFFT case mismatched; n16/64/256 matched. All zero-budget controls preserved state. The n2052 reconstruction child printed its start and hit the built-in2s timeout without returning. This is diagnostic correctness/liveness failure, not proof rejection and not a fully dynamic proof test. Primary E3 report: `results/dynark/phase-1/fft-smoke/run-v1/report.json`; exact command, source/executable hashes and external watchdog: `execution-v1.json`; child log: `run-v1/remainder-child.log`.

E2 completed with exit0 in1,235.682s measured experiment wall /1,237.118s external watchdog wall. PID75943 and supervisor session43694 are finished. The private directory is `artifacts/dynark/phase-1/near-e2-v1/`; raw log and external watchdog are `artifacts/dynark/phase-1/baseline-audit/e2-run.log` and `e2-watchdog.json`. Actual-circuit no-cache comparator passed ordinary verification before updating-key generation. Input identities and all run correctness controls passed. Public metrics-only copies: [raw report](../../../../results/dynark/phase-1/e2-report.json), [watchdog](../../../../results/dynark/phase-1/e2-watchdog.json), [aggregates and session economics](../../../../results/dynark/phase-1/e2-summary.json).

The exact measured command was:

```sh
experiments/dynark/proof-probe/target/release/phase1-baseline --output artifacts/dynark/phase-1/near-e2-v1 --threads 4 --repetitions 30 --refresh-repetitions 10 --warmup 1
```

| Measurement | n | Median ms | Observed range ms |
|---|---:|---:|---:|
| Supplied-witness full, no retained cache |30|2221.008|2197.849–2430.791|
| Supplied-witness full, retained cache |30|2252.204|2216.918–2533.041|
| Supplied-witness anchored update |30|389.048|385.093–449.506|
| Complete local full refresh |10|5416.884|5383.929–5710.363|
| Complete local anchored refresh |10|3586.780|3555.232–3658.150|
| Paired complete-refresh saving |10|1840.415|1786.801–2054.273|

One warm-up pair per study is excluded from the table. Mean paired complete-refresh saving is1,885.445ms; ratio of full/update means is1.524. These trials repeat the same frozen near transition, with four threads and occupied host applications; they do not establish broad workload or successive-root performance. The full-cache path remains position-confounded and no isolated causal cache overhead is inferred.

Public UK preparation took382.969s; private projections510.323s; package serialization12.991s; validated matching UK/cache reload63.453s. Common development setup5.753s and first anchored proof2.393s are separately reported and excluded from differential session economics. Mixed serialization/reload is charged once. Derived repeated fixed-transition break-even is515 refreshes with all public/private preparation and mixed I/O,271 with ideal shared-public/no-I/O private preparation, or312 with public preparation shared and all mixed I/O charged conservatively. These shared scenarios are accounting bounds because public/private I/O was not measured separately. Rows for0/1/2/5/10/100/1000 refreshes and exact charge boundaries are in the aggregates.

The retained cache is67,109,349B; the original anchor WTNS20,594,092B adds separately required assignment state, giving at least87,703,441B before other action/signing state. Saved PK/UK/cache/VK/initial proof/public package totals631,234,215B; including the final updated proof631,234,343B. Separate PK serialization duplicates the PK embedded in UK; runtime after reload holds only UK.pk. The22 regenerated WTNS evidence files are experiment retention, not production requirements. Lifetime maxRSS was1,552,285,696B; watchdog RSS maximum1,513,455,616B. These do not isolate full-only client memory or child memory. Watchdog `started_at_utc` is null due a metadata bug; run-directory creation time is separately identified in the aggregate, not substituted as an asserted launch timestamp.

[Fresh independent proof replays](../../../../results/dynark/phase-1/e2-proof-replays.json) preserve exact commands/stdout/stderr/exits: initial/before and updated/after accept; updated/before, initial/after and updated/wrong-action reject. These are ordinary mathematical statement checks, not execution-current-root integration.

[Post-run preservation](../../../../results/dynark/phase-1/e2-preservation.json) rehashed all165 baseline entries, all build-manifest entries and archived relocation protected files with zero hash/mode changes. The final private run recount including the wrong-action replay input is1,084,438,466B, below2GiB; directory700/all files600; no active owned benchmark/build jobs remain. Source/build identities remain frozen. No preparation rerun occurred.

The ark-std release fingerprint is preserved byte-for-byte in [fingerprint](../../../../results/dynark/phase-1/ark-std-release-fingerprint.json) with [identity](../../../../results/dynark/phase-1/ark-std-release-fingerprint-identity.json): SHA256 `25647cf1ef57aa6ff5e6dfe97a1e70f983ed9f1df79482c61cf123a0e68b9ae4`. Enabled features are default/parallel/rayon/std; declared `getrandom` is not enabled. Cryptographic interpretation belongs to the parent audit.

Recommendation: treat the fresh complete-local saving as a bounded anchored-update observation and retain the matching development package for any next research step. The measured preparation/private-state charge and FFT diagnostic failures prevent promotion to a production refresh claim; no incremental witness/path/network/Solana or real fully dynamic update was measured. Final documentation acceptance validation is recorded in [final-validation.json](../../../../results/dynark/phase-1/final-validation.json); that report records its checks and outcome.
