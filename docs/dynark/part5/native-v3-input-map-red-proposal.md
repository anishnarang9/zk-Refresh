# Standard v3 Full input boundary: compiler-map RED

Source-only: no Cargo, proof, signing, key reads or credential generation occurred.
`V3BoundWitness::open_full` stays `Unsupported`. Publicly implementable state
traits and caller-constructed coherent snapshots are not chain authentication.

## New independent tests-first source

| File | SHA-256 |
| --- | --- |
| `crates/dynark-native-client/src/v3_input_map.rs` | `8d922abdb1da2d8b059cca9471c2694e774abaa4ffad32fa52b5b18c3f779ae4` |
| `crates/dynark-native-client/tests/v3_input_map.rs` | `91d5b31846e9fb2068d8258982bb46a41dae0686ed0b45443788ee739a11255e` |

`V3CompilerInputMap::load(symbols, control)` and its private parser remain closed
scaffolds. The map has a private constructor; the API accepts no certificate
offsets or candidate coordinate labels. Hash assertions are caller data and must
match the fixed compiler pin before source bytes are parsed.

The actual proof-runner schema has 14 keys and 751 individual field scalars:
six ordered public fields, layout, slot, TBS[672], issuerModulus[17],
issuerSignature[17], holderSignature[17], siblings[10], pathIndices[10]. The map
must contain each required name exactly once, 751 unique indices in 1..784795,
and public coordinates 1..6 in order. Tests also reject missing/duplicate names,
aliased/eliminated/out-of-range indices, wrong public order and malformed rows.
Synthetic parser rows establish structure only and cannot pass the hash gate.

## One bounded RED

ROOT must authorize the sole execution slot. Fresh output paths must be absent.

```sh
CARGO_BUILD_JOBS=1 RAYON_NUM_THREADS=4 OMP_NUM_THREADS=1 \
CARGO_TARGET_DIR=/Users/anishnarang/Zk-refresh/crates/dynark-native-client/target \
M2_V3_INPUT_MAP_SCOPE=native-v3-compiler-map \
python3 results/dynark/phase-2/bootstrap/bounded_runner.py \
  --owner M2-NATIVE-V3-INPUT-MAP-RED-001 \
  --cwd /Users/anishnarang/Zk-refresh \
  --private-output /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/native-v3-input-map-red-monitor-001 \
  --report /Users/anishnarang/Zk-refresh/results/dynark/part5/native-v3-input-map-red-bounded-001.json \
  --runtime-seconds 180 --rss-bytes 1073741824 --storage-bytes 268435456 \
  --storage-path /Users/anishnarang/Zk-refresh/crates/dynark-native-client/target \
  --poll-seconds 0.25 -- \
  /Users/anishnarang/.cargo/bin/cargo test --offline --locked \
  --manifest-path /Users/anishnarang/Zk-refresh/crates/dynark-native-client/Cargo.toml \
  --test v3_input_map input_map::tests::pinned_v3_compiler_map_covers_exactly_751_unique_inputs \
  -- --ignored --exact --test-threads=1
```

Expected: successful compilation, exactly one failure at
`pinned v3 compiler map admission is implemented: Unsupported`, exit 101,
no resource/runner failure and no residual process. Compilation failure, a scope
guard failure or zero executed tests is inconclusive; no automatic retry.
The positive is ignored because its eventual GREEN reads an ignored compiled
symbol artifact, rather than requiring that artifact during ordinary Cargo tests.
The scaffold RED opens no artifact. No PK/setup or credential input is required.

## Actual dependencies and pins

Paths are relative to `/Users/anishnarang/Zk-refresh`.

| Dependency | SHA-256 |
| --- | --- |
| Compiler input: `artifacts/dynark/part5/v3-compile-001/credential.sym` (ROOT's accepted source pin; no new hashing run) | `d2d66e238bdc0a731c86c1897c2978d23908dcc19460582cc873dc2d41e5dbf0` |
| Schema/map reference: `circuits/credential-v3-bounded/qualification/proof-runner-v1/src/context.rs` | `b11ff7786729ffcb14664dd257a3d46ee289cb087fef1a9475cfe73d345a454e` |
| Map preparer reference: `tools/part5/prepare_proof_inputs_v1.py` | `dacb2e8ff1ca77b35671da1b490c09650ffd9081449667febba2a1a24302b23c` |
| Existing importer worker | `4ebb5c0201c3b98955d8fa0bc0ce8ce5f76104302b5e70f2a7359919e6b29a28` |
| Existing public signature verifier worker | `46692db2692d35f8624fde87ba9aa87239a5f8fab829a15a515a5a88ea6e80a6` |
| Frozen Full WASM pin | `fbf73cff59660574add16ba8acafe824a9d57e0c91f23557b6462979b85c9aa6` |
| Calculator source, independently rehashed public file | `cc2d37b2cff2a589dd86f8636f1a1dc9fe4a854550b021aa0cea2e235d14e942` |

No library export, dependency, manifest, engine, circuit, proof-runner or existing
worker change belongs to this map gate. Existing binding and setup source hashes
remain `4e1541f7a600d18b87cad1adab3c9522418e87dafdc84a40b3692de5032ad88a`
and `c394698064d71301474463f0d910784bed4e8ec1192f871fdf68e80042db1125`.

## Subsequent real Full integration dependencies

1. **Retained signer:** source and filename inspection found the retained v2
   synthetic key/certificate set, not an eligible retained v3 signer. The v3
   corpus generator explicitly discards keys. Existing signed mathematical
   actions cannot sign a new finalized request. Propose a separately reviewed
   `tests/support/prepare_v3_context.py` to generate an independently encoded
   eligible TRAINING certificate and retain its synthetic holder capability in
   fresh 0700/0600 ignored artifacts. Its source and execution must be reviewed
   first; no such helper or credential was generated here. Held-out credentials
   are generated only after the later final implementation/setup freeze.
2. **Read-only accessors:** after explicit source review, add minimal borrowed
   DER/TBS, prepared-action hash and shared package/manifest/key accessors. They
   must not let callers construct admission tokens or alter existing semantics.
3. **Input builder/calculator:** separately own new pinned worker/modules that
   derive layout, signed values, RSA limbs and active membership inputs from
   imported DER, exact action signature and verified state. Verify every returned
   public and private scalar; no fixture names/offsets or new setup per certificate.
4. **Opaque authenticated state:** a configured concrete verifier must validate
   finalized account owners/PDAs/exact bytes, issuer/config policy, clock, signed
   source and publisher head, allocation and active v3 path before minting a
   private state capability. Neither a user trait nor a unit snapshot suffices.
5. **Real relation admission:** only after the above, link all 751 actual inputs
   to complete canonical WTNS coordinates and call full package relation
   validation. Then recheck live state before a randomized Full proof. The old
   five-public WitnessContext cannot provide this six-public path. Until these
   dependencies are real, `open_full` stays closed regardless of map-test success.
