# Fixed-depth witness suffix prerequisites, October 14

The accepted final-level evaluator has already matched all 643,563 original witness coordinates and passed ordinary Groth16 verification. Extending it to the near and middle revocation fixtures requires explicit compiler mappings for all affected Merkle levels. This record concerns those prerequisites; it does not claim a completed successor evaluator or a speedup.

## Preserved mapping failure and diagnosed cause

Mapping source001 ran fourteen synthetic alias tests successfully, then rejected a repeated top-level label in the actual compiler substitution artifact. Its failed raw report remains unchanged: SHA-256 `b56ba018688ba1463f179cf3d01ee9d5126a1759f117557d821c990fb4b5233c`, exit 1, 4.592966 seconds, 52,183,040-byte sampled peak RSS, no cap/runner error and known clean cleanup. The complete coordinate/alias extraction did not finish, so no suffix closure is accepted from that run.

ROOT independently inspected substitution lines 1,423,229 and 1,423,230: both map original label 1,832,486 to constant one. The symbol is `main.issuance.padder.paddedMessageBits[417]`, outside the selected Merkle scope. The worker's separate bounded public-metadata census reports 1,425,357 emitted records, 1,425,245 distinct labels and 112 repeated records across sixteen labels. All 2,501 selected aliases plus the one auxiliary `slotBits.in` alias occur exactly once. This occurrence census is not a completed transitive dependency extraction. [First duplicate](../../../../results/dynark/phase-3/witness-dependency/path-suffix-substitution-first-duplicate-001.json), [occurrence census](../../../../results/dynark/phase-3/witness-dependency/path-suffix-substitution-repeat-census-001.json).

Installed Cargo metadata associates Circom 2.2.3 with commit `d54c93d8ff35ce497524d558411d5fcd61615b46`; this is an installation association, not a reproduced-build claim. At that commit the [substitution writer](https://github.com/iden3/circom/blob/d54c93d8ff35ce497524d558411d5fcd61615b46/constraint_writers/src/json_writer.rs) appends every received substitution without deduplication, and [constant simplification](https://github.com/iden3/circom/blob/d54c93d8ff35ce497524d558411d5fcd61615b46/constraint_list/src/constraint_simplification.rs) logs each qualifying constraint. These sources and the observed identical pair explain why global uniqueness was too strict. They do not justify taking the last definition of an ambiguous selected label.

The source002 repair counts unrelated repeated records as metadata, parses every selected occurrence, and permits repeated selected definitions only when their canonical affine expressions are identical. Conflicting, noncanonical or internally duplicate-key definitions fail before replacement. Existing complete name/coordinate coverage, bounded DFS, intermediate-output bindings and scope checks remain unchanged. Six discriminating parser tests were authored before the repair; no separate synthetic red execution is claimed.

ROOT subsequently reviewed source002 and executed mapping002 under the unchanged limits. All twenty tests passed and the complete mapping succeeded: ten components each have 767 named signals, 518 retained coordinates and 249 aliases; the outer signals bring the selected total to 2,501 plus one auxiliary alias. All 643,562 named retained coordinates and the unnamed constant-one coordinate 0 were covered. Resolution depth was one, with no affine exceptions; intermediate outputs bind coordinates 392–400 and only the final output binds public root coordinate 1. All 26 pre/post identity and mode pins matched, primary and duplicate reports were byte-identical, cleanup was known empty, and ROOT independently observed the former workload processes absent.

Mapping002 took 4.028806 seconds with 66,879,488-byte sampled peak RSS, nineteen samples and 2,069,882-byte observed growth. Raw report SHA-256: `7b66f727a6c234ffd2a0babccd527ce62a8aa553d87a3b48dcc7930e53f1abaa`. The [complete mapping](../../../../results/dynark/phase-3/witness-dependency/path-suffix-mapping-output-002/mapping.json) is 2,063,440 bytes, SHA-256 `b842dd6bbcce1765629dad6af9e2b7e1d318df73a356887922316a40ed92ad67`; its [summary](../../../../results/dynark/phase-3/witness-dependency/path-suffix-mapping-output-002/summary.json) has SHA-256 `2c51581e644c6f0c1e5694ffd93622d66f618a944998e19cdaad17cc59e0abc0`. This accepts the compiler mapping prerequisite. Fixed-depth evaluator authoring may proceed; actual successor witness equivalence, ordinary proof acceptance and performance remain separate gates.

## Independent original target witnesses

Previously validated near and middle baselines are reused through exact replay004 input/witness/public associations and the frozen source path that validates every relation row. No baseline generation or relation-validation run was repeated.

ROOT ran each original target generator once using the unchanged original WASM and byte-identical JavaScript under the already accepted CommonJS scope. Each used supervisor006 with the existing 60-second, 4-GiB RSS and 128-MiB output limits. Both exited zero, retained all 23 input/tool/source identity and mode pins, and had verified cleanup. ROOT compared each entire new WTNS to its historical target; both are byte-identical.

| Target | Workload seconds | Sampled peak RSS, bytes | Raw report SHA-256 |
|---|---:|---:|---|
| Near | 3.410449 | 183,271,424 | `b288d19418edc3b9899446956a063a84c5887798b07bd007ab82d479f986cb62` |
| Middle | 3.416667 | 174,211,072 | `7862f3d45729ed720fb9cbef140f710129a421fa273e9a904c7b1243ecf84d3b` |

Near WTNS SHA-256 is `fb304dfc489111a2b788aeff118fb3a980b6f3b42188c0f793949909877703c6`; middle is `64da64c1526f8651a9a8be4bc1cf23ca0c21ba1f055353829f61ff5ed0afb296`. Each file is 20,594,092 bytes. These runs establish independent original-generator provenance for later field-by-field comparison; they do not run the new evaluator or produce new proof evidence.

Private baseline and producer receipts are under `artifacts/dynark/phase-3/witness-dependency/path-suffix-mapping-source-001/baseline-receipts/`. Original proposals, failed source001 extraction and every raw report remain preserved.
