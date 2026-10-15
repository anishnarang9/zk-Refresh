# Fixed-depth witness suffix prerequisites, October 14

The fixed ten-level evaluator has matched all 643,563 original witness coordinates for near, middle and far revocation fixtures, including compiler aliases and intermediate values. All three candidates have ordinary Groth16 proof evidence. The matched witness pilot below is now accepted; product integration and a combined refresh benchmark remain open.

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

## Successor evaluator and unit checks

ROOT and the independent reviewer accepted the fixed-depth evaluator, comparator and exact launchers. For one changed sibling at level `k`, it recomputes levels `k` through 9, including the retained intermediate nodes and all compiler aliases. It emits sorted nonzero deltas, preserves every coordinate outside its conservative scope, and checks the computed final root against the supplied target. Every other input must remain unchanged. This is a fixed-circuit experiment bound to separately validated baseline artifacts, not a general certificate parser or production witness API.

The source freeze is 5,412 bytes, SHA-256 `f70bd42159e648ef9839a2482e71428b5c548c05e281fb07279c801cfc8f38d2`. ROOT ran all 37 unit methods: the accepted 21 far tests and sixteen new suffix tests. They cover every changed level and both selectors, independent Poseidon root references, complete outside-scope preservation, malformed or inconsistent inputs, intermediate and retained aliases, and exact regression against the accepted far evaluator. All passed in 17.111 seconds reported by unittest. Synthetic fixtures do not establish relation satisfaction.

The bounded workload took 17.481509 seconds with 269,631,488-byte sampled peak RSS, 79 samples, 7,196-byte observed growth and known clean cleanup. Primary and duplicate report SHA-256: `135edff3d56fabd5a8952041bd23bb97ff2281b51b30740b59dcafd35abe90f9`. All 31 pre/post identity and mode pins matched. The finite allowance remained 120 seconds, 1 GiB RSS and 128 MiB output. These unit results are not a speed measurement.

## Actual near, middle and far field equivalence

ROOT executed the three comparators serially under their unchanged 120-second / 1-GiB / 128-MiB limits. Each compared all 643,563 canonical fields against the independently produced original target and found **zero mismatches**. Every coordinate outside the conservative patch scope, the baseline bytes and all checked compiler aliases were preserved. Each additionally checked the one auxiliary slot alias.

| Case | Recomputed levels | Named values | Selected aliases | Conservative coordinates | Direct nonzero deltas |
|---|---:|---:|---:|---:|---:|
| Near | 10 | 7,690 | 2,501 | 5,191 | 5,081 |
| Middle | 5 | 3,845 | 1,251 | 2,596 | 2,541 |
| Far | 1 | 769 | 251 | 520 | 509 |

ROOT independently compared the complete candidate files to the original targets. Near and middle retain the target digests recorded above. Far has SHA-256 `e4a72ebe72f4b48112c28f5c2dcfb8ac8ad1d39b0ed862a2f6b943d39d50e447` and also matches the previously accepted far candidate byte for byte. The comparator confirmed identical far deltas and named values against the earlier evaluator. Its prior proof evidence can therefore be reused for the exact same witness, target and package; no additional far proof was run.

| Case | Workload seconds | Sampled peak RSS, bytes | Raw report SHA-256 |
|---|---:|---:|---|
| Near | 0.926229 | 187,645,952 | `e153af4d70182de24a8943cf073fdef9642caac181801619b03c55dbfae29f4b` |
| Middle | 0.927402 | 187,531,264 | `d280248b1fdee1e59f685437ef4939d393547c2577de6203a9cf81624b840a4c` |
| Far | 1.154799 | 221,134,848 | `d819506db173f29825bf04327f1c76fb0939a9ae7f0f708f5ec9796426519aa4` |

Primary/duplicate reports and pre/post identity receipts match for every case, with no cap or runner error and known clean cleanup. ROOT observed the former workload processes absent. These are one-shot correctness workloads, including authentication and complete oracle comparison; the far case also runs the old evaluator for regression. They are not matched latency measurements or evidence of a far-versus-near performance ordering.

The [near acceptance](../../../../results/dynark/phase-3/witness-dependency/suffix-near-equivalence-accepted-001.json) and [middle acceptance](../../../../results/dynark/phase-3/witness-dependency/suffix-middle-equivalence-accepted-001.json) bind exact candidate, source and original-generator provenance. The later proof gate below closes their separate relation and ordinary-verification checks. No key generation, anchor preparation, real credential parsing or Solana execution is included.

## Near and middle ordinary proof acceptance

ROOT executed the frozen Cargo binary once for both candidates. Each passed all 648,156 relation rows, 643,563 canonical coordinates and five public values. Each fresh proof used caller OsRng with two successful draws totaling 64 bytes. The independent ordinary verifier accepted original and canonical decoded proofs and rejected each of five individually altered public values: four positive checks and ten negative checks overall.

The workload completed in 101.544288 seconds, with 1,145,159,680-byte sampled peak RSS, 450 samples, 3,170-byte observed output growth, no cap or runner error and known clean cleanup. Primary and duplicate reports match at SHA-256 `fbdf2d59699c196543e26d76d32f747cfe61c5de6d6348ba450c460a7c6b6234`. All 95 pre/post identity and mode pins match; ROOT observed the former workload processes absent. The two private proof files are each 128 bytes with mode 0600.

One immutable package import took 93.042354 seconds. Near and middle full proving took 2.402973 and 2.204707 seconds. These single correctness observations are not a witness-generation or end-to-end benchmark. No new setup, anchor or cache preparation ran. [Proof acceptance](../../../../results/dynark/phase-3/witness-dependency/suffix-near-middle-ordinary-proof-scrubbed-acceptance-001.json) and [complete three-fixture aggregate](../../../../results/dynark/phase-3/witness-dependency/suffix-three-fixture-correctness-scrubbed-aggregate-001.json) preserve source, binary, input and raw-report associations. The earlier aggregate with pending proof status remains unchanged as a historical snapshot.

The next experiment compares the original full witness generator with the accepted suffix evaluator under matched conditions, accounting separately for initialization and retained state. Incremental witness reuse must also be available to the optimized full prover. Comparing proof modes on the same witness is a separate measurement; historical unmatched timings cannot establish the combined speedup.

## Paired witness measurement prerequisites

ROOT and the independent reviewer accepted the isolated 74-file benchmark source, including 64 unchanged inherited files. It schedules two fresh generator/evaluator process pairs and five measured warm pairs per case, plus an excluded warm pair, for 48 complete WTNS outputs. All outputs must match the accepted canonical, relation-checked and proof-checked targets byte for byte. One shared validator imports the existing package once and admits nine baselines; no new proof, setup, anchor preparation or repeated output-consumer relation check is included. Both lanes include complete output materialization and file write/close. Incremental authentication, scans and alias checks remain inside its generation call. OS caches are uncontrolled, and composed first-use estimates are explicitly distinct from a measured fresh whole application.

The finite protocol gate passed all thirteen Python methods, twenty-one Node checks and the Node worker syntax check. ROOT executed once under supervisor006, read all output and checked cleanup; all 94 identity/mode pins matched. Bounded duration was 0.485471 seconds with only three RSS samples, so this is correctness evidence only. Primary/duplicate report SHA-256: `473e691e13d7363ca0a1c00593af6d9928762c3051a45422a40e9438569afc62`. [Protocol acceptance](../../../../results/dynark/phase-3/witness-dependency/witness-measurement-unit-scrubbed-acceptance-001.json).

The exact offline locked single-job baseline-validator build completed in 67.723827 seconds with 539,459,584-byte sampled peak RSS and known clean cleanup. Cargo emitted one matching bin artifact and `build-finished: success`; all 96 checked pins matched. Primary/duplicate report SHA-256: `bd87514938c003c03620180a91d64ca9b4391d9184345216fcfc2e622c0815d8`. Cargo retained a nonfatal debug-stripping tool warning along with unused-code warnings; no rebuild was performed. ROOT compared the emitted executable with its frozen copy, SHA-256 `6d4a1cfd5c4f2e43d1d96126a00f3b0b14d0affc192ee4a54d43641a02c8e63e`, before granting the measurement.

## Accepted matched witness pilot

All 48 complete outputs matched the accepted original targets byte for byte. ROOT read the complete result and independently calculated the five-pair warm medians below; independent postflight rechecked every output and all 127 source/tool/input/receipt identities and modes. Six excluded warmup outputs remain paid and checked. Each case also has two fresh generator/evaluator process pairs, with OS caches uncontrolled.

| Case | Full warm median | Incremental warm median | Ratio of medians | Paired wins |
|---|---:|---:|---:|---:|
| Near | 3.168751 s | 0.202172 s | 15.67× | 5/5 |
| Middle | 3.121085 s | 0.196901 s | 15.85× | 5/5 |
| Far | 3.187004 s | 0.199047 s | 16.01× | 5/5 |

The windows include a complete 20,594,092-byte WTNS output and file write/close. Incremental generation retains input authentication, full canonical scans, compiler-alias and unaffected-coordinate checks, and full witness plus sparse-delta materialization. The full control uses the unchanged original calculator. There is no durable-fsync or delta-only consumer claim.

The whole pilot took 189.240558 seconds, with 989,118,464-byte sampled peak workload-tree RSS, 847 samples and 988,568,922-byte observed output growth, within its unchanged 300-second / 4-GiB / 1-GiB limits. Primary and duplicate report SHA-256: `599c4073c751128845e3a72730adf2f179f9982218aa680595909d30bf24d52c`. It exited zero with empty stderr, no stop/error and known clean cleanup; ROOT observed all 32 former workload processes absent. RSS includes the resident validator and idle workers and is not a per-lane peak.

Shared validation-context startup cost 103.133312 seconds once, including package import. Nine baseline admissions cost 1.256472 seconds; all 24 full-generation windows cost 77.336912 seconds and all 24 incremental windows 5.544847 seconds. These disjoint paid components, warm process setup, all 48 external comparisons and residual overhead reconcile to the whole workload. Child component times are nested, not added twice. Fresh evaluator windows ranged from 0.265377 to 0.335217 seconds; adding the separately measured context and admission gives only a composed first-use estimate. Initial baseline generation and earlier preparation are not silently treated as free.

The [scrubbed aggregate](../../../../results/dynark/phase-3/witness-dependency/witness-measurement-scrubbed-aggregate-001.json), SHA-256 `54468485b6df1da54f22833860ccc00e75cab07a8bbbbb79461cf407085d54ca`, preserves all 21 measured pairs, 48 lane records, both ratio definitions and paid costs. This one fixed-fixture pilot establishes a witness-stage improvement on this host. It does not establish average-laptop, chained-update, general-circuit, combined-proof or end-to-end performance. Incremental witness reuse also benefits ordinary full reproving; the gain is not exclusive to DYNARK.
