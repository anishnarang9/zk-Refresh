# Native v3 shared setup: proposed RED gate

This is a source-only proposal. No Cargo, key loading, proof or validator job
has run for this slice. ROOT owns the sole execution slot; this gate stays
queued behind the Anchor pilot. No retry or cap increase is authorized.

## Frozen source

| File | SHA-256 |
| --- | --- |
| `crates/dynark-native-client/src/v3_setup.rs` | `5d0763a12d2bb4c11283c9688536d6c804d97d2c5201161c695eb9378e7df157` |
| `crates/dynark-native-client/src/lib.rs` | `a07ca96f338d2c611592329492f0f0875f951984e566800bd21d8487146fbd35` |
| `crates/dynark-native-client/src/v3.rs` (unchanged) | `958e7a74d251eb65ee077088f138bb88524b54061bba6426dc47dd084feb4588` |
| `crates/dynark-native-client/src/v3_input.rs` (unchanged) | `1bfa72d1d2053bfa40fbde1166009ed14b226613cb37ab1b8605528e5b3ba0b8` |
| `crates/dynark-native-client/Cargo.toml` (unchanged) | `8a1d75494af752e6f4746f47019f3a6dd384282508a82ed54a85c4d7d20fe47f` |
| `crates/dynark-native-client/Cargo.lock` (unchanged) | `f70a994d244173c89e54473fa2dfcc845b028c188fa1e54ebbb5900ce068b8ed` |

`V3SharedSetup::load(sources, manifest, control)` is an `Unsupported` scaffold.
It opens no artifact and decodes no key. Source formatting and diff checks
passed; compilation has not been checked for this slice.

## Exact proposed command and envelope

Working directory: `/Users/anishnarang/Zk-refresh`.

```sh
CARGO_BUILD_JOBS=1 RAYON_NUM_THREADS=4 OMP_NUM_THREADS=1 \
CARGO_TARGET_DIR=/Users/anishnarang/Zk-refresh/crates/dynark-native-client/target \
M2_V3_SETUP_SCOPE=native-v3-shared-setup \
python3 results/dynark/phase-2/bootstrap/bounded_runner.py \
  --owner M2-NATIVE-V3-SHARED-SETUP-RED-001 \
  --cwd /Users/anishnarang/Zk-refresh \
  --private-output /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/native-v3-shared-setup-red-monitor-001 \
  --report /Users/anishnarang/Zk-refresh/results/dynark/part5/native-v3-shared-setup-red-bounded-001.json \
  --runtime-seconds 180 --rss-bytes 1073741824 --storage-bytes 268435456 \
  --storage-path /Users/anishnarang/Zk-refresh/crates/dynark-native-client/target \
  --poll-seconds 0.25 -- \
  /Users/anishnarang/.cargo/bin/cargo test --offline --locked \
  --manifest-path /Users/anishnarang/Zk-refresh/crates/dynark-native-client/Cargo.toml \
  --lib v3_setup::tests::accepted_development_setup_loads_one_shared_six_field_package \
  -- --ignored --exact --test-threads=1
```

Both output paths must be absent. The intended result is successful compilation,
exactly one executed test, and Cargo exit 101 at:
`accepted shared development setup admission is implemented: Unsupported`.
Compilation errors, resource stops, scope-guard failures or zero executed tests
are inconclusive. The monitor must report no runner error and no remaining owned
process. Its ordinary `passed: false` is expected for this assertion failure.

The positive test is ignored because its eventual GREEN implementation reads the
real accepted development PK and performs full package/key validation. Routine
`cargo test` must not launch that workload. The exact environment scope plus
`--ignored --exact` makes execution deliberate. The scaffold RED does not read
those artifacts. Actual admission GREEN requires its own reviewed resource grant.

## Artifact locations and external pins

All paths below are relative to `/Users/anishnarang/Zk-refresh`. Assertions
supplied through `V3SetupSources` are untrusted data. The eventual implementation
must compare independently accepted pins before decoding or using key bytes.

| Path | SHA-256 |
| --- | --- |
| `artifacts/dynark/part5/v3-development-setup-001/setup-manifest.json` | `d31f82e3f147e31b30074b3a570a9d7945c5e1f5d3f3dd74172801abbe984918` |
| `artifacts/dynark/part5/v3-compile-001/credential.r1cs` | `976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888` |
| `artifacts/dynark/part5/v3-compile-001/credential_js/credential.wasm` | `fbf73cff59660574add16ba8acafe824a9d57e0c91f23557b6462979b85c9aa6` |
| `circuits/credential-v3-bounded/profile.json` | `2e5d26564fb055e70cff924c4cb6e296509030b8c0062130f86ad5af783f7918` |
| `artifacts/dynark/part5/v3-development-setup-001/development.pk` | `879563839a95ab1a9e5a44b316ba86290918a5cf522863c1ddc58379365293bc` |
| `artifacts/dynark/part5/v3-development-setup-001/ordinary.vk` | `87edb4608c2140f3c7fddc8503e49b68931cda973711ce2c831bd44f1b98a875` |
| `results/dynark/part5/v3-ordinary-vk-identity-001.json` (public, 1,458 bytes) | `6a6fd9d207c778b085f56de3327ec15ccee886ab127de1e90e970da039fef429` |

The expected package is
`61d941890d823433468048dd1bd91da80c1bf7e1b3d2b6f5d509077a47ed06c8`.
The tagged ordinary VK identity is
`2f9b770ff51ac399619a3127ddb32efad67697402f10c4549441a3578e4f9a4e`;
it differs from the raw VK file hash and extended engine VK commitment.
The test requires 784,796 assignment fields, seven instance fields including
one, 793,681 constraint/reduction rows, domain 1,048,576, seven ordinary VK ICs
and the matching 456-byte ordinary VK projection.

Two additional unexecuted tests reject wrong PK/VK/setup/profile/receipt hash
assertions and a caller-modified package/profile manifest. Successful setup
admission will establish public development-package identity only. It will not
authenticate issuer enrollment, status, a holder credential or an application.

No new dependency is required for the scaffold. Proposed later adapter integration
is `dynark-solana-adapter = { path = "../dynark-solana-adapter" }`; Cargo.toml and
the lock remain unchanged pending ROOT review.
