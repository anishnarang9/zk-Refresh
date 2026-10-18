# Clean-checkout reproduction status and build steps

This partial guide separates two goals: checking the evidence for the specific Training-010 run, and running a new campaign from the pinned source. A new run creates new keys, state, binary hashes, and receipts; it cannot recreate Training-010's receipt hashes. The Training-010 matrix was still in progress in the registered snapshot, and the heldout runbook says its acceptance steps have not run. Neither is a completed application acceptance result. The missing setup package and initial R0 preparation inputs below still prevent a clean-checkout rerun.

## Source and runtime pins

Start from a source tree matching the Training-010 file-hash pins. The campaign freeze records source bundle hashes, not a Git commit, and the public registration does not name the source commit used to create it. Publish the commit and scrubbed freeze/identity manifest alongside the source hashes before calling this a clean-checkout recipe.

The checked-in Rust manifests use edition 2021 and lock dependency versions. No `rust-toolchain.toml` is present. The current machine reported Rust/Cargo 1.100.0-nightly, Python 3.14.2 with `cryptography` 46.0.5, Node 24.10.0, OpenSSL 3.6.2, and `solana-test-validator` 4.2.1. These are observations, not repository-enforced versions. The current `package.json` and `package-lock.json` are versioned and pin the JavaScript dependencies; after selecting Node 24.10.0, run `npm ci` from the repository root. The existing campaign interpreter at `artifacts/dynark/part5/v3-campaign-python-002` is ignored. There is no checked-in Python dependency lock. A clean build still needs versioned Rust, Python/`cryptography`, OpenSSL, and Solana/Agave CLI pins.

## Build the required executables

Run from the repository root. The commands below use fresh ignored build directories and do not overwrite the canonical Training-009 proof executable or the existing Training-010 executable. They have not been run as part of writing this guide.

```bash
set -euo pipefail
umask 077
ROOT="$(git rev-parse --show-toplevel)"
PART5="$ROOT/artifacts/dynark/part5"
CARGO="${CARGO:-cargo}"
export CARGO_BUILD_JOBS=1
mkdir -m 700 -p "$PART5"

PROOF_MANIFEST="$ROOT/circuits/credential-v3-bounded/qualification/proof-runner-v1/Cargo.toml"
PROOF_TARGET="$PART5/v3-proof-runner-clean-target"
PROOF_NAME=credential-v3-bounded-proof-qualification-v1
PROOF_COPY="$PART5/v3-proof-runner-clean"
test ! -e "$PROOF_TARGET" && test ! -e "$PROOF_COPY"
mkdir -m 700 "$PROOF_TARGET"
CARGO_TARGET_DIR="$PROOF_TARGET" "$CARGO" test --locked \
  --manifest-path "$PROOF_MANIFEST" -- --test-threads=1
CARGO_TARGET_DIR="$PROOF_TARGET" "$CARGO" build --locked --release \
  --manifest-path "$PROOF_MANIFEST"
install -m 700 "$PROOF_TARGET/release/$PROOF_NAME" "$PROOF_COPY"
shasum -a 256 "$PROOF_COPY"
```

Build the queue test executable once. It provides both the campaign effect runner and the heldout runner. `--no-run` compiles the tests without executing them or accessing private fixtures. The stable copy is required at the heldout runner path; the new campaign manifest should pin this copy and its new hash.

```bash
QUEUE_TARGET="$PART5/v3-queue-runner-clean-target"
QUEUE_COPY="$PART5/v3-heldout-queue-runner-002"
test ! -e "$QUEUE_TARGET" && test ! -e "$QUEUE_COPY"
mkdir -m 700 "$QUEUE_TARGET"
CARGO_TARGET_DIR="$QUEUE_TARGET" "$CARGO" test --locked \
  --manifest-path "$ROOT/harness/Cargo.toml" --test queue_v3 --no-run
QUEUE_BINS="$(find "$QUEUE_TARGET/debug" -maxdepth 8 -type f \
  -perm -111 -name 'queue_v3-*' -print)"
test -n "$QUEUE_BINS"
test "$(printf '%s\n' "$QUEUE_BINS" | wc -l | tr -d ' ')" -eq 1
QUEUE_BINARY="$QUEUE_BINS"
"$QUEUE_BINARY" --list > "$QUEUE_TARGET/queue-v3-tests.txt"
for name in root_pinned_queue_v3_stage root_pinned_queue_v3_campaign_stage \
  root_pinned_queue_v3_campaign_transition root_pinned_queue_v3_campaign_effect \
  root_pinned_queue_v3_execute root_pinned_queue_v3_unrelated_transition \
  root_pinned_queue_v3_branch root_pinned_queue_v3_disabled_config_negative; do
  grep -Fqx "$name: test" "$QUEUE_TARGET/queue-v3-tests.txt"
done
install -m 700 "$QUEUE_BINARY" "$QUEUE_COPY"
shasum -a 256 "$QUEUE_COPY"
```

Build the adapter test executable and exporter. The adapter target is a test harness; compile it with `--no-run` only. Pass its resulting executable path and SHA to the new freeze and manifest rather than reusing Training-010's path/hash.

```bash
ADAPTER_TARGET="$PART5/v3-adapter-clean-target"
test ! -e "$ADAPTER_TARGET"
mkdir -m 700 "$ADAPTER_TARGET"
CARGO_TARGET_DIR="$ADAPTER_TARGET" "$CARGO" test --locked \
  --manifest-path "$ROOT/crates/dynark-solana-adapter/Cargo.toml" \
  --test v3_request_bound_host --no-run
ADAPTER_BINS="$(find "$ADAPTER_TARGET/debug/deps" -maxdepth 1 -type f \
  -perm -111 -name 'v3_request_bound_host-*' -print)"
test -n "$ADAPTER_BINS"
test "$(printf '%s\n' "$ADAPTER_BINS" | wc -l | tr -d ' ')" -eq 1
ADAPTER_BINARY="$ADAPTER_BINS"
shasum -a 256 "$ADAPTER_BINARY"

EXPORTER_TARGET="$PART5/v3-exporter-clean-target"
test ! -e "$EXPORTER_TARGET"
mkdir -m 700 "$EXPORTER_TARGET"
CARGO_TARGET_DIR="$EXPORTER_TARGET" "$CARGO" build --locked \
  --manifest-path "$ROOT/program/Cargo.toml" \
  --example export_v3_request_fixture
EXPORTER="$EXPORTER_TARGET/debug/examples/export_v3_request_fixture"
shasum -a 256 "$EXPORTER"
```

Build the shared setup/package launcher separately from the proof runner. This
is the `credential-v3-bounded-qualification` binary from the `prover` Cargo
manifest. The commands compile and test source only; they do not create setup
keys. The copied binary path is fresh and leaves the Training-010 launcher
untouched.

```bash
SETUP_MANIFEST="$ROOT/circuits/credential-v3-bounded/qualification/prover/Cargo.toml"
SETUP_TARGET="$PART5/v3-setup-launcher-clean-target"
SETUP_COPY="$PART5/v3-setup-launcher-clean"
SETUP_NAME=credential-v3-bounded-qualification
test ! -e "$SETUP_TARGET" && test ! -e "$SETUP_COPY"
mkdir -m 700 "$SETUP_TARGET"
CARGO_TARGET_DIR="$SETUP_TARGET" "$CARGO" test --locked \
  --manifest-path "$SETUP_MANIFEST" -- --test-threads=1
CARGO_TARGET_DIR="$SETUP_TARGET" "$CARGO" build --locked --release \
  --manifest-path "$SETUP_MANIFEST"
install -m 700 "$SETUP_TARGET/release/$SETUP_NAME" "$SETUP_COPY"
shasum -a 256 "$SETUP_COPY"
```

The application also needs its loaded SBF ELF. The program README documents this build command; it builds an artifact and does not deploy it. The freeze tool currently expects the resulting file under this exact private path.

```bash
SBF_OUT="$PART5/application-v3-sbf-build-002/elf"
test ! -e "$SBF_OUT"
mkdir -m 700 -p "$SBF_OUT"
cargo build-sbf --manifest-path "$ROOT/program/Cargo.toml" --sbf-out-dir "$SBF_OUT"
test -s "$SBF_OUT/zk_fresh_program.so"
shasum -a 256 "$SBF_OUT/zk_fresh_program.so"
```

Use the `cargo-build-sbf` subcommand installed with the pinned Solana/Agave toolchain. The command is documented in `program/README.md`; the toolchain installation itself is not pinned in the repository.

## Fresh private inputs and a new campaign

The source documents a Circom invocation and implements a setup CLI, but neither
step alone reproduces the pinned campaign package. The freeze tools hardcode
`artifacts/dynark/part5/v3-compile-001` and
`v3-development-setup-001`; run these commands only in a clean checkout where
those outputs are absent. The compile command follows the v3 circuit README and
first-compile record. It assumes Circom 2.2.3 is installed; the repository does
not pin or install the compiler binary.

```bash
COMPILE="$PART5/v3-compile-001"
test ! -e "$COMPILE"
mkdir -m 700 "$COMPILE"
circom --version
circom circuits/credential-v3-bounded/credential.circom \
  --r1cs --wasm --sym -l node_modules -o "$COMPILE"
test -s "$COMPILE/credential.r1cs"
test -s "$COMPILE/credential.sym"
test -s "$COMPILE/credential_js/credential.wasm"
shasum -a 256 "$COMPILE/credential.r1cs" \
  "$COMPILE/credential_js/credential.wasm" "$COMPILE/credential.sym"
```

The first frozen outputs were R1CS
`976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888`, WASM
`fbf73cff59660574add16ba8acafe824a9d57e0c91f23557b6462979b85c9aa6`, and
symbols `d2d66e238bdc0a731c86c1897c2978d23908dcc19460582cc873dc2d41e5dbf0`.
Stop if any differs. This command does not recreate the original compiler
report or source-freeze receipt; those are also absent from a clean checkout.

The corpus and witness-qualification commands below follow
`tools/part5/WITNESS-PROPOSAL.md`. They create fresh private keys, 52 cases, and
eighteen WTNS assignments. Run only under the separate 60-second corpus and
900-second witness-suite limits specified in that proposal.

```bash
PYTHON="$(command -v python3)"
NODE="$(command -v node)"
CORPUS="$PART5/v3-witness-corpus-clean"
QUALIFICATION="$PART5/v3-witness-qualification-clean"
test ! -e "$CORPUS" && test ! -e "$QUALIFICATION"
"$PYTHON" -B -m tools.part5.corpus --private-out "$CORPUS"
"$NODE" tools/part5/tests/test_witness_runner.cjs
"$NODE" --max-old-space-size=1024 tools/part5/witness_suite.cjs \
  "$COMPILE" "$CORPUS" "$QUALIFICATION" "$PYTHON" \
  tools/part5/witness_check.py "$COMPILE/credential.r1cs"
```

This is a fresh qualification output, not the approved receipt. The setup
launcher accepts only the approved suite
report hash embedded in
`circuits/credential-v3-bounded/qualification/prover/src/main.rs`:
`1878dff43be66019b077c1398805e044e659238b6e74800904e66c803241d044`. A new
suite report includes measured durations and will have different bytes. A
clean-checkout evidence capsule must provide the exact original safe report, or
a separately reviewed binary/source with a new suite pin. The original report,
accepted assignments, WTNS files, and input corpus are ignored local artifacts.

With that exact report restored at
`$PART5/v3-witness-qualification-001/report.json`, the implemented setup CLI
has this syntax. It creates fresh OS-CSPRNG keys and therefore a new package
identity; it cannot reproduce Training-010's key hashes. Do not run this when
the output exists or when the goal is exact Training-010 verification.

```bash
SUITE="$PART5/v3-witness-qualification-001/report.json"
SETUP_DIR="$PART5/v3-development-setup-001"
SUITE_SHA=1878dff43be66019b077c1398805e044e659238b6e74800904e66c803241d044
test "$(shasum -a 256 "$SUITE" | awk '{print $1}')" = "$SUITE_SHA"
test ! -e "$SETUP_DIR"
mkdir -m 700 "$SETUP_DIR"
"$SETUP_COPY" setup "$COMPILE/credential.r1cs" \
  "$COMPILE/credential_js/credential.wasm" \
  "$ROOT/circuits/credential-v3-bounded/profile.json" \
  "$SUITE" "$SUITE_SHA" "$SETUP_DIR"
```

The corrected proof runner also pins the original setup manifest and package
check identities. `check-package` needs the eighteen accepted WTNS/public
statements and an externally pinned assignments manifest. Those files are not
in a clean checkout, and a new package-check report will not match the fixed
package-check hash. Thus the setup invocation is a valid source interface, but
the current proof runner cannot admit a newly generated setup under its pins.
A new package needs a versioned source update to accept new provenance receipts,
or the original setup/VK and reports in the evidence capsule.

The initial R0 campaign preparation also lacks a complete from-zero input
command. `harness/tests/queue_v3_local_prepare.py` accepts only an existing
`--config` and its hash; `tools/part5/create_v3_campaign_stage_config.py` starts
from a prior prepare config/status/monitor. Training-010 consumes the ignored
`application-v3-campaign-prepare-config-002.json`, status, and ledger. The repo
does not construct that initial R0 config/fixture, so it cannot be recreated
from source commands listed in the current runbook.

After a new bounded prepare run produces a fresh `PREPARE_STATUS`, and after local `artifacts/dynark/part5` contains a reviewed prior-public-key inventory, use the documented freeze and cohort CLIs. The freeze source requires at least one earlier PEM/DER public-key input (`freeze_v3_campaign_cohort.py:129-130`); the clean checkout has none, and no public inventory seed is packaged. Choose new output names; do not replace the Training-010 freeze or reuse its private cohort. These are application input-generation commands, not acceptance or a matrix run:

```bash
RESULTS="$ROOT/results/dynark/part5"
FREEZE_DIR="$RESULTS/v3-campaign-freeze-clean"
FREEZE="$FREEZE_DIR/freeze.json"
IDENTITY="$FREEZE_DIR/identity-manifest.json"
COHORT_HOME="$PART5/application-v3-campaign-cohort-clean"
COHORT="$COHORT_HOME/cohort"
CONTEXT="$COHORT_HOME/context.json"
PREPARE_STATUS="$PART5/application-v3-campaign-prepare-control-clean/status.json"

test ! -e "$FREEZE_DIR" && test ! -e "$COHORT_HOME"
test -f "$PREPARE_STATUS"
mkdir -m 700 "$FREEZE_DIR" "$COHORT_HOME"
python3 -B tools/part5/freeze_v3_campaign_cohort.py \
  --prepare-status "$PREPARE_STATUS" --adapter-binary "$ADAPTER_BINARY" \
  --proof-binary "$PROOF_COPY" --output "$FREEZE" \
  --identity-manifest "$IDENTITY"
FREEZE_SHA="$(shasum -a 256 "$FREEZE" | awk '{print $1}')"
python3 -B tools/part5/prepare_v3_campaign_cohort.py \
  --freeze "$FREEZE" --freeze-sha256 "$FREEZE_SHA" --output "$COHORT"
COHORT_SHA="$(shasum -a 256 "$COHORT/cohort-receipt.json" | awk '{print $1}')"
MEMBERSHIP_SHA="$(shasum -a 256 "$COHORT/membership.json" | awk '{print $1}')"
python3 -B -m tools.part5.prepare_v3_campaign_context \
  --cohort "$COHORT" --cohort-sha256 "$COHORT_SHA" \
  --membership-sha256 "$MEMBERSHIP_SHA" --output "$CONTEXT"
```

The `old_packet` consumed by `tools/part5/build_v3_campaign_packet.py` is not a
credential fixture. The builder copies only ten package/setup/compiler/input-map
path-and-hash fields. Those fields are reconstructible after restoring the
accepted setup and package-check report and deriving the symbol map from the
frozen `.sym`; it is safe to recreate the JSON metadata template. The builder
has no dedicated template command, so the following constructs it from the
source-pinned values. It stops unless the accepted setup/check and compiler
files are present at their frozen paths with their exact hashes.

```bash
PACKET_META="$PART5/v3-packet-metadata-clean"
test ! -e "$PACKET_META"
mkdir -m 700 "$PACKET_META"
python3 -B - "$ROOT" "$PACKET_META" <<'PY'
import hashlib
import json
import pathlib
import sys
from tools.part5.prepare_proof_inputs_v1 import map_from_lines, write_json

root, meta = map(pathlib.Path, sys.argv[1:3])
part5 = root / 'artifacts/dynark/part5'
compile_root = part5 / 'v3-compile-001'
setup = part5 / 'v3-development-setup-001/setup-manifest.json'
package_check = part5 / 'v3-package-check-001/package-check-report.json'
r1cs = compile_root / 'credential.r1cs'
wasm = compile_root / 'credential_js/credential.wasm'
symbols = compile_root / 'credential.sym'
profile = root / 'circuits/credential-v3-bounded/profile.json'
expected = {
    setup: 'd31f82e3f147e31b30074b3a570a9d7945c5e1f5d3f3dd74172801abbe984918',
    package_check: '4a8d521fc0890d10878932c67f39629b673dc4f537082b167c4f873bb0212c81',
    r1cs: '976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888',
    wasm: 'fbf73cff59660574add16ba8acafe824a9d57e0c91f23557b6462979b85c9aa6',
    symbols: 'd2d66e238bdc0a731c86c1897c2978d23908dcc19460582cc873dc2d41e5dbf0',
    profile: '2e5d26564fb055e70cff924c4cb6e296509030b8c0062130f86ad5af783f7918',
}
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
for path, digest in expected.items():
    if sha(path) != digest:
        raise SystemExit(f'pinned input mismatch: {path}')
with symbols.open() as stream:
    coordinates = map_from_lines(stream)
input_map = meta / 'symbol-input-map.json'
write_json(input_map, {
    'schema': 'credential-v3-bounded-input-wire-map-v1',
    'symbols_sha256': expected[symbols],
    'assignment_fields': 784796,
    'coordinates': coordinates,
})
packet = {
    'package_digest': '61d941890d823433468048dd1bd91da80c1bf7e1b3d2b6f5d509077a47ed06c8',
    'setup_manifest_path': str(setup), 'setup_manifest_sha256': expected[setup],
    'package_check_path': str(package_check), 'package_check_sha256': expected[package_check],
    'r1cs_path': str(r1cs), 'wasm_path': str(wasm), 'profile_path': str(profile),
    'input_map_path': str(input_map), 'input_map_sha256': sha(input_map),
}
write_json(meta / 'packet-template.json', packet)
print(json.dumps({'template': str(meta / 'packet-template.json'),
                  'template_sha256': sha(meta / 'packet-template.json'),
                  'input_map_sha256': sha(input_map)}))
PY
```

This recreates only metadata; downstream proof-runner checks still require the
original pinned package, setup, package-check, and input-map identities. If any
of those frozen files are missing, obtain them through an approved evidence
capsule. A fresh setup or package-check report does not satisfy these pins.

After the missing R0 preparation and accepted package inputs are supplied,
continue by generating a new stage, authenticated transitions for `k=1,2,5,10`,
fresh packet fixtures, and a new matrix manifest with the new binary paths and
hashes. Run only one validator or proof job at a time. The existing Training-010
runbook consumes the old `prepare-002` status/ledger and treats freeze, cohort,
and stage inputs as already generated. It is not a complete clean-checkout,
from-zero campaign recipe.

## Verify Training-010 specifically

Verification of Training-010 requires its original exact bytes. Do not rebuild the corrected proof runner or regenerate keys in place: either changes hashes and breaks the frozen identity. The documented pins include the proof binary, freeze, matrix manifest and plan, and smoke receipts. The complete public evidence needed for independent verification is not yet packaged: publish a scrubbed freeze/identity, stage and four transition receipts, smoke receipts, matrix manifest/plan, final sequence receipt, all 60 slot receipts with scrubbed session/outer reports, and economics/reconciliation/total reports after they exist. At the registered snapshot, the sequence receipt and economics manifest were absent.

Keep these private inputs and outputs out of Git: issuer and holder private keys, raw credentials when designated protected, witnesses/WTNS, proofs, signed request envelopes and wires, validator ledger clones, and private run journals. Publish only a schema-reviewed scrubbed evidence capsule with hashes and scalar outcomes. The final application report must distinguish a fresh rerun from verification of the original receipts and must not call training smoke or matrix progress heldout acceptance.
