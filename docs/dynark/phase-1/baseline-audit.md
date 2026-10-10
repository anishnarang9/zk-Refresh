# Baseline and performance audit

October 10, 2026. E1–E4 completed; their observed failures and limits remain explicit. Evidence classes: **F** fresh local observation; **C** inspected code; **H** historical artifact; **D** derived estimate; **U** unresolved. The [baseline worker](evidence/baseline-worker.md) and [profiling worker](evidence/research-coverage.md) retain commands, logs, environment and hashes; [experiment records](experiments.md) define authorization and resource bounds.

## What is established

- **F:** 55 relevant tests passed: harness 23, program 13, witness 8, proof 11 (nine existing plus two comparator tests). Six retained-proof replays produced their expected outcomes. Mathematical rejection returned an explicit verifier result, not a crash or timeout.
- **C/F:** The reference matrix-prover wrapper drops constant one before calling a function that expects it. The new comparator avoids this wrapper, computes the same quotient under the same reduction and proving key, and omits DYNARK cache construction. A five-public-input small relation and the unchanged real circuit both independently verify.
- **F:** The unused fully dynamic path has reproducible FFT/scheduler failures: 32 of 80 bounded vector cases mismatch arkworks; a toy partial-batch reconstruction times out. These are failed algorithm diagnostics. They are not failed anchored proofs or evidence against the paper. See [crypto audit](evidence/crypto-code-audit.md).
- **C:** Fully dynamic proof emission uses deterministic test randomness in the inspected release feature configuration. Shape/index/state validation and key/reduction security obligations remain open. Ordinary proof acceptance does not close them.
- **H:** Near-case anchored updates previously verified. Middle/far/new-action and serial revocation evidence consists of witness/census checks, not fully dynamic proof sequences.

## Relation, artifacts and preservation

The unchanged circuit has 648,156 constraints, 643,563 assignment entries including constant one, five public values and a padded domain of 1,048,576. Public order is root, issuer hash, not-before, not-after, action hash; the instance slice has six entries. The synthetic certificate profile is an exact 439-byte TBS template, two RSA-2048/e65537/SHA-256 signature checks and a depth-10 membership path. These facts do not imply support for arbitrary X.509 files.

The reference pin is `c73a380df86d8f5d195f1e20c8a1d86a7dce084b`. Two pre-existing patches size column arrays by assignment count and use OS randomness for anchored updates. Phase 1 adds three isolated diagnostic/benchmark binaries (E2 baseline, E3 FFT smoke, E4 profile), without replacing the reference or baseline circuit. Root Git was initially absent; the user's later request authorized initialization and small local commits, without a push. [The 165-entry freeze](../../../results/dynark/phase-1/baseline-freeze.json) preserves original source/artifact identities; [the E2 manifest](../../../results/dynark/phase-1/e2-build-manifest.json) ties current source, dependency features, toolchain and binary to the new run.

Historical near-v1 retained a private cache, ordinary verification key and proof/public artifacts but no reusable PK/UK. Consequently E2 uses one new matching development setup, saves PK/UK/cache privately, checks identities and reloads them. The old private cache cannot be paired with the new keys. The original `.zkey`, deployed verification key and new development key are distinct; original-key compatibility, Solana encoding and dynamic execution remain unestablished.

The older measured binary hash is documented but its binary is not retained at that path; the later final binary is retained. An archived pre-robustness probe source exists: parent inspected its main/lib diffs, which show only atomic output-directory creation and parser allocation bounds, with no prover-algebra change. Its Cargo manifest points to an upstream-regression vendor, however, and no build manifest ties that archive to the measured historical binary. [Source identities](../../../results/dynark/phase-1/historical-probe-source-identity.json) support the limited textual comparison, not complete build provenance. The old file named `all-tests-final.log` records six proof tests while the final source contains nine. Fresh test results resolve current correctness counts without manufacturing old provenance. The initial setup's organizer artifact hash was calculated from the HTTPS download, not an independently published organizer checksum; full phase-one ceremony verification was false and phase two had one development contributor. None is a production setup.

## End-to-end boundary and stage accounting

| Stage | Current computation | Measurement classification |
|---|---|---|
| Issuance/enrollment/status ingestion | Synthetic configured issuer and fixture; no live issuer adapter | Product requirement, not measured |
| Registry/path | Host reconstructs tree/snapshot after revocation; frozen after-input supplies path | Source inspected; path acquisition outside E2 |
| Witness | Full Circom WASM calculation through Node | Included in each complete local refresh |
| Import | Canonical WTNS fields, counts, constant one; full R1CS satisfaction preflight | Necessary import included; matrix-wide satisfaction preflight outside refresh |
| Delta | Linear comparison of complete assignments in global wire space | Update path included; diagnostic census excluded |
| Public setup/UK | Development key generation; domain-wide public UK computation | One-time setup/UK separately measured |
| Private preparation | Base anchor and witness-specific projections | Separately charged to one exact witness/action |
| Full proof | Dense evaluations, quotient, ordinary assignment prover | No retained-cache comparator; same key/reduction/backend |
| Anchored update | Sparse delta plus immutable original anchor | Complete proof emitted; no sequential cache mutation |
| Maintenance | None for unchanged immutable anchor | Zero here only; no claim about fully dynamic maintenance |
| Encoding/reload | Canonical compressed proof; private package serialized/hash-checked/reloaded | Encoding inside refresh; persistence/reload separately charged |
| Verification | Ordinary crates.io ark-groth16 exact-public-statement check | Included in refresh and separate correctness controls |
| Submission/execution | RPC, confirmation, current-root/time/replay policy and protected effect | Excluded; no complete application latency claim |

Witness-byte hashing is a diagnostic outside the refresh timer. Stage snapshots add measurement overhead inside the outer elapsed timer. Private WTNS artifacts are retained only within the experiment bound. Full R1CS satisfaction preflight establishes the frozen relation/input pair; these trials do not benchmark a production policy that rechecks every constraint on every import. Untrusted-witness validation policy remains an explicit engine design decision.

## Historical observations, kept separate

The old run used one warm-up and five pairs, always full before update, on an occupied M3 Pro with four Rayon threads. These are descriptive observations, not current results or tail-latency estimates.

| Quantity | Historical observation | Limitation |
|---|---:|---|
| Full proof with base-cache construction | Median 2.353 s, range 2.291–2.430 s | Unnecessary cache work included in ordinary comparator |
| Anchored update | Median 0.411 s, range 0.399–0.713 s | Same near-after transition from original anchor |
| Full witness generation | Median 3.054 s | Separate trials |
| Delta plus diagnostic census | Median 0.114 s | Includes work unnecessary for production delta |
| Derived local refresh | Full 5.408 s; update 3.580 s | Sum of separate medians; import omitted; not complete trials |
| UK preparation | 403.460 s | Public per circuit/setup |
| Private projection preparation | 551.614 s | Witness/action-specific |
| Cache/verifier serialization | 5.709 s | Different persistence scope from E2 |
| Private cache file | 67,109,349 bytes | Actual compressed file, not live memory |
| PK / UK size | 136,525,077 / 427,598,901 bytes | Historical serialized-size estimates, no retained key files |
| Lifetime max RSS / macOS footprint | 1,605,271,552 / 2,857,863,904 bytes | Different high-water metrics; neither stage allocation |

Near/middle/far changed 5,081 / 2,541 / 509 assignment coordinates. Near nonzero A/B/C row changes were 2,390 / 2,370 / 2,370, leading to 5,664,300 pairs per current cross-term loop. A new action changed 104,175 coordinates and projects to 10,502,938,566 pairs per loop; no new-action update benchmark was run. A changed leaf does not mean one changed witness coordinate, and neighboring root changes may accumulate relative to an immutable anchor.

## Fresh E2 measurements

**F:** One warm-up followed by30 measured supplied-witness triples, then one warm-up and10 measured complete local-refresh pairs finished in1,235.682s (20.59min). Every proof independently verified; regenerated witness hashes and frozen input identities matched. [Raw samples](../../../results/dynark/phase-1/e2-report.json), [aggregate statistics](../../../results/dynark/phase-1/e2-summary.json), [watchdog](../../../results/dynark/phase-1/e2-watchdog.json) and [five fresh-process replays](../../../results/dynark/phase-1/e2-proof-replays.json) are retained. Replays accepted initial/original and updated/current proofs, and explicitly rejected updated/stale root, old proof/new root and updated/wrong action with verifier false/exit1. The frozen near-after input is reused to isolate repeat cost; this is not a measured series of distinct root updates.

| Measured operation | Samples | Median seconds | Observed min–max seconds |
|---|---:|---:|---:|
| Supplied-witness no-cache full proof | 30 | 2.221 | 2.198–2.431 |
| Supplied-witness full proof with base cache | 30 | 2.252 | 2.217–2.533 |
| Supplied-witness anchored update | 30 | 0.389 | 0.385–0.450 |
| Complete local full refresh | 10 | 5.417 | 5.384–5.710 |
| Complete local anchored refresh | 10 | 3.587 | 3.555–3.658 |
| Paired complete-refresh saving | 10 | 1.840 | 1.787–2.054 |

The ratio of complete-refresh medians is1.510; mean paired saving is1.885s. Neither is a tail-latency estimate. The supplied-witness stage ratio is about5.71, but that is not an application speedup. Actual complete local trials support the narrower1.51× observation for this fixed synthetic transition. Warm-ups are excluded throughout.

Complete refresh component medians (full/update): full witness3.125/3.128s; canonical import53.501/53.515ms; necessary update delta2.734ms (no delta needed for full); proof2.230/0.390s; encoding0.004/0.005ms; ordinary verification0.898/0.903ms. These medians do not sum exactly to the outer-trial median. Total process-plus-child CPU median is11.001s full versus4.866s update, including instrumentation inside the outer boundary. Witness calculation now dominates warm anchored refresh. Historical114ms delta+census is not the necessary delta cost, and old summed-refresh figures are not substituted for these direct trials.

Fresh one-time stage observations:

| Stage | Wall seconds | Parent user+system CPU seconds | Charge / limit |
|---|---:|---:|---|
| Development setup | 5.753 | 21.656 | Common research setup, not production ceremony |
| Updating key | 382.969 | 1,504.562 | Public per exact circuit/setup |
| Initial anchor proof | 2.393 | 7.941 | Includes base cache and ordinary verification |
| Private projections | 510.323 | 2,024.387 | One original witness/action |
| Matching package serialization | 12.991 | 12.892 | Includes files and SHA-256 identity reads |
| Matching package reload | 63.453 | 97.485 | Hash checks, canonical decompression/validation, UK with embedded PK and cache |

Reload occurred immediately after serialization in the same run, with warm filesystem cache; it is not a cold boot/download measurement. Its63.453s wall cost still demonstrates that persistence cannot be treated as free. File outputs now establish actual PK136,525,077B, UK427,598,901B and private cache67,109,349B (same representation sizes as historical estimates); keys/cache are new matching values, not historical keys. Proof encoding remains128B. Final parent lifetime peak RSS is1,552,285,696B (about1.45GiB); the two-second watchdog observed a smaller1,513,455,616B peak because sampling can miss peaks. No resource limit tripped. Stage-end RSS may fall with OS memory behavior and is not an allocation census.

The cache file is not the complete private action state: delta construction also retains the original assignment (about19.64MiB serialized WTNS), plus action/input/signer state. E2 refers to the preserved anchor witness outside its new package. The recovery package saves both a separate PK and a UK embedding PK; after reload, runtime uses only `uk.pk` and has dropped the separate PK. One-process lifetime RSS therefore does not isolate each proving mode's independent memory needs. The22 generated WTNS files are retained benchmark evidence, not a proposed production-cache requirement.

[Post-run preservation](../../../results/dynark/phase-1/e2-preservation.json) found zero baseline/build/protected-archive hash or mode mismatches. Final retained experiment files, including the separate-process wrong-action input, total1,084,438,466B; private run directory is700 and every file600. The aggregate raw report's earlier retained-byte count precedes its own final rewrite and the extra replay artifact; the final recount is authoritative. The watchdog's `started_at_utc` is null due a metadata omission; directory birthtime is separately recorded, not asserted as exact launch time.

Independent source review confirmed the main no-cache/update endpoint order is balanced15/15; the cache-building full mode is always the middle member. Its median is descriptive, and subtracting the no-cache median does not isolate a causal cache-construction overhead from order/carryover effects. Serialization combines PK/UK/private cache/VK/proof/public artifacts, and reload combines UK (including PK) plus private cache; per-file public/private I/O time was not measured. Shared-public I/O allocation must therefore be an explicit assumption, and combined package time is charged once. Parent accepted these limits without altering the active benchmark.

Environment: Apple M3 Pro, 18 GiB, 11 cores, Darwin 25.6.0 arm64; four Rayon threads; release thin LTO; Rust/Cargo 1.100 nightly, Node 24.10.0, Circom 2.2.3. User/OS GUI processes remained active. The exact toolchain, build identity and source hashes are in the E2 manifest. The watchdog enforces 35 minutes, 4 GiB parent RSS and 2 GiB retained files throughout long calls. Parent/child CPU and parent lifetime/current RSS snapshots are recorded; child live/peak memory and allocator attribution were unavailable in E2 and are separately investigated in E4. These are workstation observations, not qualification of all native desktops.

## E4 allocation and kernel diagnostics

E4 uses the same retained E2 package with four threads, one unchanged private-preparation repeat and a separate witness child. Its System allocator tracker measures requested Rust heap bytes, including Rayon workers, with successful reallocations counted as old bytes freed and new bytes allocated. This is distinct from native allocator overhead, stacks, physical footprint and RSS. Tests cover allocation/reallocation conservation, owned-child traversal and touched/canceled/nonzero counts. Atomic counters and native stack sampling materially perturb timing; E4 must not replace the E2 latency distributions.

The completed load/proof windows establish the following diagnostic counters. Proof work starts with the imported matrices, both assignments, UK including PK and retained original cache already live. These are incremental peaks above that measured process baseline, not independently launched per-mode product memory requirements.

| Window | Requested live bytes afterward / maximum | Additional peak above window start | Allocation traffic |
|---|---:|---:|---:|
| Import plus full satisfaction | 252,833,419 afterward | 323,056,204 B | 775,027,732 B |
| Validated UK including PK load | 1,000,754,749 afterward | 780,190,606 B | 1,234,466,281 B |
| Validated private cache load | 1,202,083,742 afterward | 411,050,054 B | 687,874,481 B |
| No-cache full proof, three diagnostic calls | 1,555,148,398 maximum | 352,335,920 B maximum | 2,567,601,288 B median |
| Anchored update, fourteen diagnostic calls | 1,203,785,507 maximum | 895,224 B maximum | 30,936,970 B median |
| Private preparation, one call | 2,511,531,089 maximum | 1,308,633,510 B | 50,328,625,677 B |

The cache's retained requested allocation increase is201,326,592B, exactly two N-element projective G1 vectors at96B per element. Its compressed67,109,349B file is not its live representation. UK-with-PK loading retains747,917,192B beyond the previous baseline; this includes its matrix indexes and container allocations, not just serialized group points. The full proof churn and update's approximately827,512 allocation calls per call motivate different buffer/scheduling experiments; neither establishes the speedup of any unimplemented optimization. The near update does not retain A/B canceled-zero rows, so zero deletion alone has no measured near-case benefit.

E4 completed in878.370s within its900s bound; no limit stopped it. The one private-preparation call took746.360s under instrumentation, versus E2's510.323s baseline observation; no controlled measurement isolates instrumentation from host/runtime effects. It made1,467,151,506 allocation calls and136,102,934 successful reallocations, with50.329GB cumulative requested allocation traffic. That is traffic over time, not simultaneous memory. Stage live allocation rose from1,202,897,579B to1,404,234,833B; the original projection oracle remains included. Peak requested bytes2,511,531,089B and lifetime RSS1,583,857,664B measure different things. RSS at stage end was138,887,168B and cannot stand in for retained logical state or total physical footprint.

Thirteen successful ten-second preparation samples span the call, in addition to one full and one update window. Parent inspected primary stack trees showing group FFT/IFFT/butterfly and group-scalar-product paths, with blocked main-thread Rayon waits separate from worker computation. Sampling establishes observed code paths; inclusive stack frames cannot be summed as CPU time, and periodic windows are not exact whole-stage percentages. Kernel-specific allocation stacks and public-UK generation attribution remain unmeasured. These are scoped limitations, not reasons to repeat all completed Phase1 profiling.

Both re-prepared N=1,048,576 projection vectors exactly equal the retained originals, and the resulting update independently verifies. All diagnostic proofs verify; stale-root/wrong-action controls explicitly reject. The one Node witness child exited0, reproduced the expected WTNS hash, and had direct maximumRSS222,314,496B; its monitored outer stage took4.804s. This single child observation is not a latency distribution. Allocator conservation passed after releasing cryptographic objects:612,706B remained for runtime/report support. All165 original hash/mode checks passed and owned processes exited.

The completed census is exact: assignment support5,081 (one public,5,080 auxiliary); A/B touched entries and nonzero rows2,390/2,370; C touched entries10,450, distinct rows5,080, canceled rows2,710, nonzero rows2,370. Sparse A/B results equal dense differences. Raw stacks stay in protected local artifacts; scrubbed counters and sampling methodology are in [E4 summary](../../../results/dynark/phase-1/profile-v1/summary.json) and [coverage report](evidence/research-coverage.md).

## Session economics and optimization implications

Let k be refreshes of one pending action after its initial proof; F and U denote directly measured complete full/update refresh costs; B the extra initial base-cache cost over a no-cache proof; P private projection preparation and private serialization; J the incremental public UK preparation/distribution/load cost; L any cache reload cost. Common initial witness/proof/setup costs cancel only if both strategies actually pay the same costs.

`extra anchored session cost(k) = B + P + J + L + sum_i(U_i - F_i)`.

For an already available shared public package set J to that session's measured load/share cost, not automatically zero; for one standalone user charge all J. Repeated-identical-transition estimates use `k × (F-U)` and explicitly assume flat update cost. Break-even exists only for positive savings and enough actual same-action reuse. Anchored deltas can grow; maintenance, new actions and churn change this model.

The following are **derived scenario estimates**, not measured sessions. They repeat the10-pair mean saving1.8854445s, omit common setup/first action work, and set the unisolated initial cache-overhead B to zero. No-cache independent cold PK-load cost is unmeasured; charging all mixed package I/O to the dynamic strategy is deliberately conservative, not a measured differential startup comparison. Standalone charges UK+private prep+one serialization+one reload=969.736s. Ideal shared public/no-I/O charges only private prep510.323s; shared public with all measured package I/O charges586.767s. Actual per-user public/private I/O allocation lies outside these measurements.

| Refreshes k | Extra seconds: standalone + all package I/O | Extra seconds: ideal shared public, no I/O | Extra seconds: shared public + all package I/O |
|---:|---:|---:|---:|
| 0 | +969.736 | +510.323 | +586.767 |
| 1 | +967.851 | +508.437 | +584.882 |
| 2 | +965.965 | +506.552 | +582.996 |
| 5 | +960.309 | +500.896 | +577.340 |
| 10 | +950.882 | +491.468 | +567.913 |
| 100 | +781.192 | +321.778 | +398.223 |
| 1,000 | −915.708 | −1,375.122 | −1,298.677 |

Positive means more time than repeated full refresh. Conditional crossover counts are515 /271 /312, respectively. The1,000-repeat rows merely extrapolate an unchanged transition; they are not evidence that distinct roots retain constant anchored support/cost. Historical526/305 figures used derived1.828s savings and different I/O scope, so they are not comparable as an optimization result. The fresh evidence supports full proving by default for short or unknown-reuse sessions and prioritizes reducing preparation/witness/reload costs before application integration.

- **Zero updates/abandonment:** all speculative private preparation is wasted; public artifacts remain amortizable only over users that actually use them. Background preparation still consumes CPU, energy and resident memory.
- **Eviction:** count sunk preparation, storage and byte-seconds. If no valid persisted private state remains, another private preparation is required; full proving may win.
- **Reload:** charge authentication, decompression, allocations and peak memory. Hash checking alone is prototype identity validation, not production authenticated persistence.
- **New action/holder:** assume a new private preparation unless a complete algebraic dependency argument and tests justify reuse. Stable credential lifetime does not establish stable action witness lifetime.
- **Many updates:** repeated-near timing is only an illustrative constant-cost estimate. Distinct revocations and reconstruction must be measured before claiming savings in a long sequential session.

Observed code duplication and E4 live allocation/traffic measurements motivate shared public artifacts, buffer ownership and small-allocation scheduling experiments. Preparation's sampled group transforms are now directly observed; exact whole-stage kernel percentages and kernel-specific allocation attribution remain limited. Full witness generation remains on every refresh. Faster cross terms, selective projections, incremental witnesses and cross-action reuse are separate hypotheses with separate correctness gates; their ranked experiments are in [research-and-gaps.md](research-and-gaps.md).
