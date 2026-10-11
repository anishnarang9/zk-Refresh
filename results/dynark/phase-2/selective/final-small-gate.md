# T7 bounded selective engine: worker correctness return

## 1. Scope and deviations

The single approved immutable-anchor direct-entry engine and bounded synthetic correctness gate are implemented. No proof algebra, vendor/backend, dependency, Fast/GLV, dynamic persistence, actual credential scan or session-timing change. Source001/build001 remain preserved and unexecuted; the independent source review prompted only the accepted source002 initial full preflight and attempted-work telemetry repairs. Coding ownership was released after source002 freeze; no source was edited during either source002 trial. This is a worker small-gate pass, with parent independent acceptance/rerun pending.

## 2. Changed files

New src/selective.rs, tests/private/selective_private.rs and selective_fixture.rs; exactly two authorized lib registration/export lines. Owned reports, commands, identities and aggregate outcomes under results/dynark/phase-2/selective/. No manifest/lock/vendor or existing engine/test changes. Preserve unrelated workspace files. The source001-to-002.diff contains the exact reviewed repair scope.

## 3. Identities

Accepted implementation base df0b3a780074e44d85884643183cd26ccfa8d2be; source002 freeze recorded the subsequent parent documentation HEAD83f51e73baa4da1b6d457ee1640c98513d4e4c92 separately. Source002 selective SHA256e7de63d79de22c955379e6f8a4f698b8e642fae39d6010a7e4b55289ebd743b5, private tests3e77c54e7c912e57099b9ed227d5c56e96093d8f9fe02b153f8a8ce7246fc628. Fixture/lib and the other50 pins remained unchanged; all54 complete source/manifest/lock/vendor/private-fixture hashes match before/after build and small trial. Complete identities: source-before-build-002.json, source-after-build-002.json and source-after-small-002.json. The immutable owner0700 executable is artifacts/dynark/phase-2/selective/executables-build-002/dynark_bn254-b64331f2da87499a, SHA256e141589c282038cb904ced45ada995829723c03d7f57b1044e2051694b96b9b1,15,132,096B, independently rehashed after the test.

## 4. Exact commands

command-build-002.json records the granted bounded runner argv:600s/1GiB treeRSS/2GiB growth; env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u CARGO_TARGET_DIR RAYON_NUM_THREADS=4 CARGO_BUILD_JOBS=2 cargo test --manifest-path crates/dynark-bn254/Cargo.toml --lib selective::tests --no-run --locked --offline. command-small-002.json records the granted frozen-executable runner argv:600s/1GiB/2GiB; env RAYON_NUM_THREADS=4 <exact copied executable> selective::tests --nocapture --test-threads=1. --list was metadata inventory only. Inline read-only sysctl pressure guards monitored each granted child; no source helper was added. Stop policy: critical immediately or three consecutive warnings, plus runner limits/drift; no stop occurred. No repair, retry or extra runtime.

## 5. Fresh outcomes

Build002 exit0. Small002:19 passed,0 failed,0 ignored,0 measured,37 unrelated tests filtered,37.95s body. All19 primary names/results read and retained in outcomes-small-002.json; stderr empty. Tests cover N8/16/32/64/128/256, both reductions, v above/below N, all five altered public-input rejections, eager and independent polynomial entries, full/common-r/s A/B1/B2/C, dense/zero/sparse endpoints, every precommit action boundary, entropy1/2, late fault, typed malformed cursor, LRU/hit/eviction/recomputation, eight/ninth attempt, one/two/third miss, fifth/accumulated/fanout demand, C-only/no-op, caps/preallocation, FullOnly/invalidation/reload loss, zero-full admission and failed-validation reservations. Prior source001 build passed but its16 test bodies were never run. No failed runtime trial was discarded. This does not claim a separately executed red/green regression cycle against source001.

## 6. Metrics and conditions

One source002 build observation: runner3.865917292s,14 samples, peak sampled treeRSS527,237,120B, logical growth20,177,476B;5 host-pressure samples all normal1. One source002 small correctness observation: runner38.099110958s,170 samples, peak sampled treeRSS11,550,720B, growth2,619B;39 host-pressure samples all normal1. Both exit0/no stop/error,0 remaining owned processes/known cleanup. External CPU was not measured; these are correctness/limit observations, not session-performance samples. RSS excludes observer/runner process overhead; short between-sample spikes can be missed, storage measures logical positive growth, and structural private/global caps are not RSS/allocator guarantees.

The preregistered source-derived entry ledger stays7,068 row visits/7,172 logicalG1 calls/13,852 Fr multiplications including private mathematical oracles;88 engine-started tickets across distinct cold evaluations plus54 private entry oracle calculations. Schoolbook pairs1,054,464 and conservative inclusive sparse ceiling1,054,976, maximum393,216 per case;43 setups, at most85 capture calls and31 eager projection oracles, allN<=256/v<=264. These conditional source inventories are corroborated by all cases reaching their assertions, not a whole-process backend curve-operation instrument. Setup/eager/full/caller admission work belongs to this test process and is separate from entry counts.

## 7. Evidence and protected retention

Public aggregate: build-001/002.json, small-002.json, both exact command sets, source before/after manifests, executable identities,19-name inventory/outcomes, host-during-build/small-002.json, source-001-to-002.diff and both review briefs. Protected artifacts/dynark/phase-2/selective/ contains both owner0700 source snapshots/executables and0600 primary stdout/stderr/invocation records. Source001/source002 and every granted trial are preserved. No witness, selected q or blinder values appear in public results. Heavy queue explicitly released after each trial and after small002 for the parent's independent rerun; coding ownership remains released.

## 8. Assumptions, risks and limits

Finite small synthetic algebra/state correctness only. Secure caller CryptoRng and application holder/action authorization remain external contracts; content tokens are not authorization/freshness. Validation/copy/current-A/B/C/anchor-touch counters are checked conservative pre-dispatch reservations retained on failure/cancel; entry operations and both anchor scans are separately counted. Initial normalization/admission validation, caller-retained outputs/other engines and whole-session CPU still require harness accounting. Full fallback may be staged during begin_update but zero advance cannot commit it. There is no selective codec or durable external ledger; explicit reload/restart loses cache and pays a fresh validated full result, while the same opaque evaluation ledger retains spent attempts. Losing that ledger starts a distinctly labelled, fully charged cold evaluation. No erasure, timing-privacy, recoverable OOM, original-zkey or credential-benefit claim.

## 9. Next gate

Parent independently reruns/reviews consequential frozen19 tests before acceptance. Then the separately scoped Sol-medium session evaluator may measure the four actual modes and frozen training/held-out traces under its own preregistration/queue budget. No worker timing, batching rewrite, real credential dense entry computation or additional test run follows automatically from this pass.
