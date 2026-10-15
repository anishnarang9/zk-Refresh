# Native v3 action/request/signature RED proposal

Source-only independent slice. No Cargo, signer/key generation, proof or validator
work has run. Existing `v3_setup.rs`, library exports and frozen admission/input
modules remain unchanged. The new Rust integration target includes its new source
module directly, so it needs no manifest, lock or export changes.

| New file | SHA-256 |
| --- | --- |
| `crates/dynark-native-client/src/v3_action.rs` | `f3b6ce3b36aa165491ac3a89fe9ec5dd6966df78ff1a004cf0098452a818dcde` |
| `crates/dynark-native-client/tests/v3_action.rs` | `8c399fad4aaf287a2312eca05524df07937771186e87444df475e85806e23ff3` |
| `crates/dynark-native-client/workers/v3_action_worker.py` | `9d58171e8b49640a3e99b8c3c4bbb7b8b19c000270f5743c09f3d69488b4f486` |
| `crates/dynark-native-client/tests/test_v3_action_worker.py` | `b66ffffc333e6740c1b07894acff9f45189b96c1b9adb7755018166298a7bbde` |

Rust APIs are `Unsupported` scaffolds: canonical preimage/hash, holder-modulus
matching and preparation against ordered actual accounts plus expected action.
The Python signature boundary raises an explicit `NotImplementedError` and
exposes no signing or key-loading entrypoint. GREEN is not implemented.

The public Rust vector fixes every action-v2 field and ordered meta bytes into
a 394-byte preimage. Its expected canonical BE32 action hash is
`09b1b947699a3927e6654b5b37caf74211edde16b887afba5da2796b56411cc2`.
It preserves `DYNARK-WORK-REQUEST`, version 2, and SHA256 reduction into Fr.
Other tests bind account keys, owners, privileges, order, holder modulus and
expected action. Owners remain separately validated outside the action preimage.
The six-field proof schema remains unchanged; this slice prepares its actionHash
field and does not produce a witness or proof.

## Single proposed Rust RED

ROOT must grant the sole heavy slot. Fresh output paths must be absent.

```sh
CARGO_BUILD_JOBS=1 RAYON_NUM_THREADS=4 OMP_NUM_THREADS=1 \
CARGO_TARGET_DIR=/Users/anishnarang/Zk-refresh/crates/dynark-native-client/target \
python3 results/dynark/phase-2/bootstrap/bounded_runner.py \
  --owner M2-NATIVE-V3-ACTION-RED-001 \
  --cwd /Users/anishnarang/Zk-refresh \
  --private-output /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/native-v3-action-red-monitor-001 \
  --report /Users/anishnarang/Zk-refresh/results/dynark/part5/native-v3-action-red-bounded-001.json \
  --runtime-seconds 180 --rss-bytes 1073741824 --storage-bytes 268435456 \
  --storage-path /Users/anishnarang/Zk-refresh/crates/dynark-native-client/target \
  --poll-seconds 0.25 -- \
  /Users/anishnarang/.cargo/bin/cargo test --offline --locked \
  --manifest-path /Users/anishnarang/Zk-refresh/crates/dynark-native-client/Cargo.toml \
  --test v3_action action::tests::canonical_action_v2_bytes_and_reduced_hash_match_fixed_vector \
  -- --exact --test-threads=1
```

Expected: compile success, exactly one test, Cargo exit 101 at
`canonical action-v2 preimage is implemented: Unsupported`. Compile errors,
scope/resource/monitor failures and zero executed tests are inconclusive. Require
no remaining owned process; no automatic retry or cap change.

## Separate queued signature gate

Only after its own ROOT grant, a single Python positive test can execute under
a separate finite monitor (proposed 60 seconds / 512 MiB RSS / 16 MiB storage):

```sh
python3 -B -m unittest discover \
  -s crates/dynark-native-client/tests -p test_v3_action_worker.py \
  -k matching_synthetic_holder_verifies_exact_canonical_action
```

Expected RED is the one explicit unimplemented verification error. The tests
generate two temporary synthetic RSA-2048/e65537 keys in memory, retain no PEM
or real holder key, and check SHA256/PKCS1-v1_5 verification of the exact BE32
action. Negative tests cover wrong signer/modulus declaration, spoofed signer
modulus, changed action/signature, truncation, signature integer alias, Fr alias,
double hashing and RSA-PSS. These tests have not run and establish no real signer
qualification, certificate import, finalized-account authentication or authority.
