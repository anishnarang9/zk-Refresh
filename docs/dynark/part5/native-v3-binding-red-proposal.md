# V3 complete-witness binding: source-only RED proposal

No Cargo, proof, key/artifact loading or validator execution has run. The active
shared-setup admission source and all earlier tests/workers remain unchanged.

| New source | SHA-256 |
| --- | --- |
| `crates/dynark-native-client/src/v3_binding.rs` | `92b02823ae90647522b3ee25c2210f93c1163211e0d605890f9aef3fe174c116` |
| `crates/dynark-native-client/tests/v3_binding.rs` | `e16981df439f68a22133e68cc807741764477fb6299508c19c19be68ac8ea4ec` |

The new integration target directly includes the new module and the frozen action
module for its `V3PreparedAction` type. No library export or dependency changes.

## Minimal orchestrator boundary

`V3BoundWitness::open_full(input, now, control)` remains `Unsupported`.
`V3FullProofInput` requires references to `ImportedV3Credential`, `V3SharedSetup`,
`AuthenticatedV3State` and `V3PreparedAction`, plus the holder signature and an
untrusted complete candidate containing canonical input JSON, WTNS and mode.
There are no caller-selected certificate offsets, setup identities or credential
labels. The output has a private constructor and retains a shared public package,
complete validated assignment and private credential/action/context binding.

The proposed implementation must capture/recheck authenticated state, derive
credential identity from imported signed bytes, verify the holder signature,
match all 751 declared input values to their complete witness coordinates, then
call `PublicPackage::validate_assignment` with exactly six authenticated fields:
`root, issuerHash, notBefore, notAfter, actionHash, policyHash`. Full witness is
mandatory; no incremental/Anchor or persisted private-cache import is exposed.
Fresh Full proving can then use `dynark_bn254::prove`, OS randomness and matching
ordinary verification after live context rechecks. No proof API is implemented.

## Focused RED and envelope

The focused assertion tests an internal envelope check only. Its synthetic
canonical WTNS contains zero private coordinates and satisfies no credential
relation. Matching six public fields cannot identify a credential: local context
must also reject different credential/holder/action/signature/package/allocation/
generation/source bindings. Other unexecuted tests reject incremental mode,
truncation, a wrong constant and noncanonical scalar encodings.

ROOT must grant the sole slot and fresh output paths before running:

```sh
CARGO_BUILD_JOBS=1 RAYON_NUM_THREADS=4 OMP_NUM_THREADS=1 \
CARGO_TARGET_DIR=/Users/anishnarang/Zk-refresh/crates/dynark-native-client/target \
python3 results/dynark/phase-2/bootstrap/bounded_runner.py \
  --owner M2-NATIVE-V3-BINDING-RED-001 \
  --cwd /Users/anishnarang/Zk-refresh \
  --private-output /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/native-v3-binding-red-monitor-001 \
  --report /Users/anishnarang/Zk-refresh/results/dynark/part5/native-v3-binding-red-bounded-001.json \
  --runtime-seconds 180 --rss-bytes 1073741824 --storage-bytes 268435456 \
  --storage-path /Users/anishnarang/Zk-refresh/crates/dynark-native-client/target \
  --poll-seconds 0.25 -- \
  /Users/anishnarang/.cargo/bin/cargo test --offline --locked \
  --manifest-path /Users/anishnarang/Zk-refresh/crates/dynark-native-client/Cargo.toml \
  --test v3_binding binding::tests::complete_full_envelope_binds_six_publics_and_private_credential_context \
  -- --exact --test-threads=1
```

Expected: compile success, one assertion failure at
`complete v3 envelope binding is implemented`, actual `Unsupported` versus
expected `Ok(())`, Cargo exit 101 and no cap/runner error/residual process.
Compile/resource failure or zero tests is inconclusive. No automatic retry.

## Remaining dependencies and ownership

- ROOT owns the in-flight `v3_setup.rs`. After admission, request separately
  reviewed read-only accessors for package/manifest/key identity; never alter that
  file during its run. `PublicPackage` clones already share one immutable Arc.
- Request read-only access to imported DER/TBS from `v3_admission.rs` and prepared
  action hash from `v3_action.rs`, plus later action library export. No changes to
  either frozen source are part of this slice.
- A pinned v3 input builder and Full calculator still need separately owned new
  modules/workers. Reuse reviewed structural DER parsing, public RSA verification
  and immutable WASM/calculator pins, with no certificate-specific offsets.
- Adapt the proof runner's strict input mapping into a reviewed client component:
  751 unique in-range coordinates, public coordinates 1..6, exact pinned symbols
  SHA `d2d66e238bdc0a731c86c1897c2978d23908dcc19460582cc873dc2d41e5dbf0`.
  The runner's synthetic enrollment labels are not product authentication.
- A real state capability must authenticate finalized request/config/enrollment,
  publisher/source current heads, signed policy, allocation and active v3 path.
  Existing coherent records and arbitrary trait implementations do not do so.
- After these dependencies, separate real Full relation/proof grants require an
  admitted retained v3 training credential and holder signer. Unit envelopes are
  not evidence of that integration or of held-out/application acceptance.
