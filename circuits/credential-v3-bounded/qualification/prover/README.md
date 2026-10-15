# V3 shared setup/package launcher: Gate 2 source review

The intended decoder red test was observed by ROOT: one executed assertion
failure, Cargo exit101, no resource stop or residual process. Its original source
and source freeze remain in the protected Gate1 artifacts. This successor source
implements setup/package validation. It has not been compiled or tested yet.
No setup, key generation, proof or package-validation run is authorized here.

## Implemented commands

`setup R1CS WASM PROFILE ACCEPTED_SUITE SUITE_SHA FRESH_OUTPUT` authenticates the
accepted 52-case report by its reviewed constant SHA256, validates all 18 complete
positive row/assignment/term counts and 34 circuit assertion rejections, imports
the exact Original six-public-field relation, and makes one OS-CSPRNG development
PK/VK pair. Its manifest pins input/compiler/source/schema/census identities,
engine matrix/circuit/PK/extended-VK/package identities, raw PK/VK file hashes and
the executable hash. Compiler-embedded `launcher_src_sha256` and
`package_lock_sha256` record the exact source/local-lock bytes used by the
build, and reload requires them to match. These are descriptive provenance
fields; ROOT’s externally accepted executable/receipt pins establish authority.
The key and manifest output is fresh 0700/0600.

`check-package R1CS WASM PROFILE SETUP_MANIFEST SETUP_SHA ASSIGNMENTS ASSIGNMENTS_SHA FRESH_OUTPUT`
requires externally trusted expected manifest hashes from ROOT's receipts.
Digests claimed by an untrusted file are not trust anchors. The authenticated
setup manifest binds its PK/VK digests and exact expected engine identity. The
loader authenticates bytes before PK/WTNS/JSON decoding, rejects trailing PK/VK
bytes. The authenticated PK alone uses unchecked codec decoding, then immediately
passes to `PublicPackage::new` for the full key/subgroup/dimension/identity
validation exactly once. The loader checks the projected ordinary VK equals the stored canonical seven-IC
VK. It loads one `PublicPackage`, then validates all 18 complete accepted WTNS
assignments sequentially with all six public coordinates. All nine refresh pairs
must preserve the five public fields after root. No proof mode exists.

The assignments manifest is a private bounded JSON object:

```
{
  "schema": "credential-v3-bounded-private-assignments-v1",
  "synthetic_only": true,
  "accepted_suite_path": "/absolute/protected/qualification/report.json",
  "accepted_suite_sha256": "ROOT-accepted report SHA256",
  "assignments": [
    {
      "name": "credential_0",
      "wtns_path": "/absolute/protected/qualification/credential_0.wtns",
      "wtns_sha256": "ROOT-pinned WTNS SHA256",
      "public_path": "/absolute/protected/qualification/credential_0-public.json",
      "public_sha256": "ROOT-pinned public file SHA256"
    }
  ]
}
```

Exactly 18 entries must name all and only `credential_0` through `credential_8`
and their `_unrelated_refresh` pairs, with no duplicates. Each path must equal
the corresponding accepted-suite-directory artifact path. The manifest itself
is trusted only through ROOT's separate expected hash. The actual accepted suite
is interleaved; validation uses case names and classifications independent of
array order.

## File classes and trust

| Class | Mode and admission |
| --- | --- |
| Public checked-in profile | Regular, non-symlink, owner matches; 0644 or 0600 accepted; exact compiled profile SHA required. |
| Public R1CS/WASM compiler output | Same file policy and exact frozen digests; common compile root must be owned 0700, WASM subdirectory regular/non-symlink. |
| Accepted report, trusted input manifests, WTNS/public statements, PK/VK | Regular, non-symlink, exact owner 0600 and bounded size; trusted expected SHA before decoding. |
| Setup/package output | Fresh owned 0700 directory, create-new 0600 files; never overwrite. |
| Executable | Owned regular non-symlink, <=64 MiB, no group/world write; measured hash binds setup to the same reviewed binary for reload. |

Open-time inode/device checks and finite reads defend controlled immutable
artifacts. ROOT retains exclusive protected ownership during execution. These
checks do not claim resistance to a same-user attacker replacing the trusted
executable or externally accepted receipt. Internal allocation caps and external
sampled RSS are distinct bounds.

## Test list, pending first green execution

1. Canonical WTNS roundtrip with six ordered public coordinates.
2. Malformed headers/counts/truncation/trailing bytes, noncanonical fields and
   non-one constant rejection.
3. Exactly six canonical decimal public scalars; aliases/field-bound failures.
4. Complete accepted-suite context/census, duplicate/path-like names, counts and
   rejection classifications.
5. All five engine identity digests are canonical and independently named.
6. Original descriptor has six names and differs from v2's five-name schema.
7. Setup context rejects changed reduction, instance count, schema/profile,
   suite identity, IC count and public-name order.
8. Pinned loader rejects changed digest, oversize file, symlink and wrong mode.
9. Actual accepted 52-case report compatibility plus interleaved/reversed fixture.
10. Every public coordinate, including policy, binds to the complete witness.
11. Public0644 profile works only under the exact static pin; private policy
    rejects that public-mode file.

12. Authenticated PK decoder rejects the wrong pin before parsing and rejects
    authenticated trailing bytes; codec success alone does not admit a package.

These tests do not generate keys or proofs, import the large R1CS, or validate
actual WTNS assignments. Actual-report/profile tests read only their small
pinned metadata files. All heavy operations await separate runtime grants.

## Proposed exact Gate2 commands

Working directory `/Users/anishnarang/Zk-refresh`. Environment:

```
CARGO_BUILD_JOBS=1
RAYON_NUM_THREADS=4
OMP_NUM_THREADS=1
CARGO_TARGET_DIR=/Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-prover-build-001
```

ROOT freezes this successor source and unchanged local Cargo.lock/dependency
closure before the test grant. Use fresh monitor/report paths for each stage.

```sh
/Users/anishnarang/.cargo/bin/cargo test --offline --locked --manifest-path /Users/anishnarang/Zk-refresh/circuits/credential-v3-bounded/qualification/prover/Cargo.toml -- --test-threads=1
```

Cap 180s, 2 GiB sampled aggregate RSS, 512 MiB new target/monitor output, one Cargo
job. Expected 12 executed tests and exit0. A compile failure is not a green test
result. Stop and preserve evidence on any failure/cap; no automatic retry.

After ROOT accepts green tests, under its separate release-build grant:

```sh
/Users/anishnarang/.cargo/bin/cargo build --offline --locked --release --manifest-path /Users/anishnarang/Zk-refresh/circuits/credential-v3-bounded/qualification/prover/Cargo.toml
```

Cap 300s, 4 GiB sampled aggregate RSS, 512 MiB new target/monitor output. ROOT records
the actual executable hash, dependency/source receipt and zero residual process
count before any setup/package runtime grant. The setup proposal retains
1200s/4GiB/1GiB bounds. The original300-second package-check wall proposal is
likely too tight for full `pk.check()` plus eighteen assignment validations;
ROOT will set a revised finite Gate4 envelope after assessing setup/key
measurements. No Gate4 execution is currently granted.

## Application handoff and remaining gates

One public package/VK serves every accepted and future supported certificate.
Application configs enable one signed `policyHash`, with `policy_id` equal to
its canonical 32-byte big-endian field encoding. A config can enroll multiple
issuerHash values; another signed org/group policy uses another config under
the same v3 circuit/setup. This application selection does not change frozen
profile semantics or demand per-policy key generation.

The current five-field ordinary adapter/tag remains incompatible. This launcher
records the raw ordinary VK file hash and seven IC entries; it leaves the tagged
six-field adapter digest null and qualification false. Ordinary Full/Anchor
proofs, matching application verification, real issuer/status policy, signer
integration, production ceremony and frozen-artifact unseen-credential acceptance
remain open. No secret scalar or signing key is logged/serialized by this tool;
secure process-memory erasure is not claimed.
