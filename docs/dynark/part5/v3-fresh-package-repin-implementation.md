# Fresh v3 package repin: implementation proposal

**Scope:** make the bounded v3 setup and proof package reproducible from a clean checkout using a newly generated private witness suite. This is a source plan only. No fresh setup, package check, proof, R0 run, or campaign is claimed here.

## Decision

Keep the accepted Training-010 v1 setup, proof runner, packet preparer, freeze tool, and receipts unchanged. Add a versioned v2 path that retains the same circuit semantics but accepts a separately reviewed fresh witness-suite identity and binds every later output to that run. Reproduction means independently reaching the same bounded relation and application semantics from reviewed source. It does not mean reproducing the same OS-CSPRNG Groth16 keys, proving-key/VK bytes, package digest, elapsed-time report bytes, or receipt hashes.

The stable semantic pins remain the R1CS, WASM, profile, circuit source/schema, public-input order, and exact census. A fresh witness report includes measured durations, so its SHA changes even when all 52 cases pass with the same meaning. Fresh setup uses `OsRng`, and both setup and package-check reports include elapsed time; their package identity and report hashes therefore belong to the new package record, not the historical v1 pins.

## Versioned source and record set

Add these files without editing their v1 counterparts:

- `circuits/credential-v3-bounded/qualification/prover-v2/Cargo.toml`, `Cargo.lock`, and `src/main.rs`. Keep the current compiler/profile/schema/census checks. Replace the embedded Training-010 suite digest with an explicit, independently reviewed v2 input pin. The v2 manifest must record the fresh suite digest and v2 source/lock/binary identities.
- `circuits/credential-v3-bounded/qualification/proof-runner-v2/Cargo.toml`, `Cargo.lock`, and `src/{main.rs,artifacts.rs,context.rs,ordinary.rs}`. Pin the v2 setup manifest, package-check report, package digest, setup source/lock/binary, ordinary VK, and fresh suite identity. Its source-level tests must not require the ignored Training-010 setup manifest.
- `tools/part5/prepare_proof_inputs_v2.py` and `tools/part5/freeze_v3_campaign_cohort_v2.py`. Preserve the v1 tools and make the v2 tools consume explicit v2 package/compile paths and hashes; do not silently retarget their current `v3-compile-001` or `v3-development-setup-001` paths.
- `tools/part5/tests/test_prepare_proof_inputs_v2.py` and `tools/part5/tests/test_freeze_v3_campaign_cohort_v2.py`, plus fixture-free Rust tests in the new setup and proof-runner crates.
- `docs/dynark/part5/v3-fresh-package-v2-input-pins.json` and, after package outputs exist, `docs/dynark/part5/v3-fresh-package-v2-package-pins.json`. The first record pins reviewed inputs before setup; the second records the measured package outputs. A later freeze records the proof-runner source and binary identities after it is built. Keep private WTNS files, corpus inputs, and the raw assignments manifest out of both public records. Store their exact hashes and paths in the owner-only run receipt instead.
- Update `docs/dynark/part5/v3-clean-checkout-reproduction.md` only after the v2 path has completed its gates. Its existing bounded R0 procedure remains the procedure for creating fresh local R0 state; the v2 freeze tool must bind that state to the new package.

Use fresh ignored output directories such as `v3-compile-002`, `v3-witness-corpus-002`, `v3-witness-qualification-002`, `v3-development-setup-002`, `v3-package-check-002`, and separate v2 build targets. Require paths to be absent and private directories/files to retain the existing 0700/0600 policy.

## Trust sequence

1. From a clean checkout, pin the selected compiler/toolchain and rebuild into `v3-compile-002`. Recheck the existing R1CS, WASM, profile, schema, symbol-map, and public-input identities before generating any witness. The source guide documents that the compiler/runtime versions are not all repository-pinned (`v3-clean-checkout-reproduction.md:7-9,116-145`); finish those toolchain pins as part of the v2 input record.
2. Generate a fresh private corpus and run the bounded 52-case suite under `tools/part5/WITNESS-PROPOSAL.md` limits. Review the complete report: exactly 18 positive accepted assignments, 34 expected circuit-assertion negatives, all complete relation checks passing, and no runtime or resource error. Independently calculate and review the report SHA. Do not treat the report's own digest as authority.
3. Freeze that reviewed suite digest and the unchanged semantic identities in `v3-fresh-package-v2-input-pins.json`. Review and commit this record before setup. Build `prover-v2` from that source/pin pair. Run `create_v3_accepted_assignments_manifest.py` against the exact private report using its explicit `--suite-report`, `--suite-sha256`, and `--output` arguments. Independently rehash/review its mode-0600 output and all 18 WTNS/public bindings before passing its path and SHA to package-check.
4. Use named v2 CLI options so each trust input is visible and auditable. Proposed interfaces:

   ```text
   credential-v3-bounded-qualification-v2 setup \
     --r1cs PATH --wasm PATH --profile PATH \
     --suite-report PATH --suite-sha256 REVIEWED_SHA \
     --input-pins PATH --input-pins-sha256 REVIEWED_SHA --output FRESH_DIR

   credential-v3-bounded-qualification-v2 check-package \
     --r1cs PATH --wasm PATH --profile PATH \
     --setup-manifest PATH --setup-manifest-sha256 ROOT_REVIEWED_SHA \
     --assignments PATH --assignments-sha256 ROOT_REVIEWED_SHA \
     --input-pins PATH --input-pins-sha256 REVIEWED_SHA --output FRESH_DIR
   ```

   The CLI must validate the externally supplied pin-record digest and each referenced artifact digest before parsing/using it. It must not trust a digest copied from the artifact being authenticated. Keep the existing exact 18-witness package validation and add the fresh report path/hash equality check.
5. After setup and package-check pass, independently review the new `setup-manifest.json`, `package-check-report.json`, `ordinary.vk`, package digest, v2 launcher binary, source files, and lockfiles. Record their exact hashes in `v3-fresh-package-v2-package-pins.json`; the record is a new package identity and must not contain the private assignment manifest or any raw witness/corpus data. The v2 proof runner and v2 input preparer consume the package/setup/VK pins. After building the proof runner, the v2 freeze records its binary/source hash and binds the fresh setup manifest/circuit ID into the newly prepared R0/cohort boundary. Use the existing `v3-clean-checkout-reproduction.md` R0 section (`:203-372`) for the local validator and ledger steps, then continue only with v2 packet/freeze inputs.

The input-pins record is reviewed before setup; the package-pins record is written only after measured outputs exist. Neither generated report authenticates itself. A later clean checkout can rerun the semantic checks and produce another valid, reviewed package record, but it cannot reproduce the prior random keys or timing-dependent hashes.

## R0 and application boundary

The existing clean-checkout guide's R0 step builds a local validator identity and ledger only; it does not initialize application accounts or execute a request (`v3-clean-checkout-reproduction.md:213-220`). A fresh setup creates a different ordinary VK. The current application embeds the Training-010 VK and setup/package IDs in `program/src/generated_vk_v3.rs:17-36,57-71`, and the runtime verifies with that static key (`program/src/application_runtime_v3.rs:210-212`). The build-prep source inventory also pins that file (`harness/tests/queue_v3_build_prep.py:103-109`). Therefore the v2 package gates do not authorize reusing the current ELF or claim application compatibility. A separate reviewed VK export/source repin and ELF rebuild must precede a v2 R0 run; application effect and devnet remain later gates.

## Tests and deferred work

Add source/unit coverage for: exact semantic pins and case counts; missing/extra/duplicate cases and report fields; incorrect suite, setup, assignment, VK, package-check, and pin-record digests; a manifest whose public coordinates do not match WTNS; exact accepted assignment names; v2 path isolation from v1; package identity/context mismatches; and rejection of any attempt to derive an expected digest from the received manifest. Replace the v1-style filesystem test that opens ignored `v3-development-setup-001/setup-manifest.json` with fixture-free provenance validation, or a fixture explicitly supplied to the test. The existing manifest-generator suite already exercises exact output schema, private mode, suite/WTNS hashes, root-only pairs, stale pins, symlinks, and no-overwrite behavior (`tools/part5/tests/test_create_v3_accepted_assignments_manifest.py:106-207`); retain it and add only a narrow regression if v2 adds a new invariant.

Training-011 stopped at its storage cap. Until the separately registered Training-012 matrix reaches a terminal state and its completion/clock gates have been inspected, defer compiler rebuilds, corpus generation, the 900-second witness suite, setup, package-check, Full/Anchor proving, SBF build, validator/R0 preparation, and all campaign/session jobs. Source review and bounded tests that do not start those jobs can be prepared independently. After Training-012 ends, run one separately bounded stage at a time, preserve failures and paid work, and do not resume or mix v1/Training-010 receipts into the v2 package.

## Source references checked

- Setup constants and accepted-suite gate: `circuits/credential-v3-bounded/qualification/prover/src/main.rs:26-44,390-453`; setup manifest provenance and output: `:455-468,508-563`; package-check CLI, 18-assignment validation, and timed report: `:584-620,641-718`.
- Fresh assignments bridge and existing tests: `tools/part5/create_v3_accepted_assignments_manifest.py:13-55,142-200,235-340`; `tools/part5/tests/test_create_v3_accepted_assignments_manifest.py:106-207`.
- Historical proof-runner pins and setup validation: `circuits/credential-v3-bounded/qualification/proof-runner-v1/src/artifacts.rs:468-507,510-531`; packet context pins: `.../src/context.rs:510-535`; ignored-file test: `.../src/artifacts.rs:622-640`.
- Existing fixed path/hash consumers: `tools/part5/prepare_proof_inputs_v1.py:21-27,124-184`; `tools/part5/freeze_v3_campaign_cohort.py:21-30,180-225`.
- Witness timing and resource bounds: `tools/part5/witness_suite.cjs:62-96`; `tools/part5/WITNESS-PROPOSAL.md:14-48`.
- Current clean-checkout and R0 guidance: `docs/dynark/part5/v3-clean-checkout-reproduction.md:7-9,116-201,203-372,421-495`.
- Current application VK binding: `program/src/generated_vk_v3.rs:17-36,57-71`; `program/src/application_runtime_v3.rs:210-212`; `harness/tests/queue_v3_build_prep.py:103-109`.
- Training-011 registration and post-run gates: `docs/dynark/part5/v3-training-011-registration.md:1-25`; `docs/dynark/part5/v3-campaign-training-011-runbook.md:1-25,40-106`.
