# V3 Original BN254 setup and public-package qualification plan

Proposal only, October 15, 2026. ROOT owns resource grants and execution. No
Cargo command, setup, public-package reload or proof has run under this plan.
The new package contains an intentionally failing decoder test scaffold, not a
setup implementation. Positive implementation follows an observed, accepted red
test. The frozen circuit/profile, compiled artifacts, witness tools and v2 setup
launcher remain unchanged.

## One shared setup

Run exactly one OS-CSPRNG Original BN254 development setup for the frozen v3
R1CS. Save its development PK and ordinary VK once. Every eligible certificate,
including later unseen supported certificates, uses that same circuit descriptor,
matrices, PK/VK and immutable package identity. Certificate bytes, layout selector,
issuer key/AKI, signed org/group, holder action signature and registry path are
witness/public-statement values; none is a circuit/setup input. Do not generate
new keys per certificate or admit new code because a certificate arrives.

Original reduction uses seven instance coordinates including constant one for
six public fields. InstanceAugmentedA, v1/v2 keys and the original snarkjs zkey
are incompatible. A changed relation, semantic profile/schema, reduction or
public package requires a new identity and separate review.

## Frozen relation and identities

| Field | Exact value |
| --- | --- |
| R1CS SHA-256 | `976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888` |
| WASM SHA-256 | `fbf73cff59660574add16ba8acafe824a9d57e0c91f23557b6462979b85c9aa6` |
| Profile-file SHA-256 | `2e5d26564fb055e70cff924c4cb6e296509030b8c0062130f86ad5af783f7918` |
| Semantic schema SHA-256 | `eabfaa2d95e4abc9126b87a04e94397091c103891e92dbaefaafba79cf3b26d4` |
| Constraints / assignment / instance coordinates | 793,681 / 784,796 / 7 |
| Exact matrix terms | 4,257,583 |
| Radix-2 domain | 1,048,576 |
| Ordered public names | `root, issuerHash, notBefore, notAfter, actionHash, policyHash` |

The semantic digest is SHA256 of canonical JSON (`sort_keys=True`, compact
separators, ASCII) of `profile.json["schema"]`. It is distinct from the engine's
`public_schema_digest(ordered_names)` and from the raw profile-file digest.
The profile digest binds test OIDs, finite layouts, signed eligibility and
issuer/AKI/policy commitment semantics. Both semantic and ordered-name digests
must be recorded explicitly.

Before building, ROOT freezes the exact recursive Circom source/include closure,
compiler executable, Rust launcher, local lock, vendor/engine sources and eventual
launcher executable. A compiler source-closure identity and a launcher source
identity are separate provenance fields. Neither is silently substituted for the
engine circuit/package identity.

`PublicPackage::inspect_identity` yields separately named matrix, circuit,
proving-key, engine-extended-VK and package digests. The manifest must also record
raw PK-file SHA256, raw ordinary-VK-file SHA256, accepted witness-report hash,
semantic-schema digest, ordered-name digest, reduction, curve, census, source
provenance and executable hash. These identities are not interchangeable.

The current Solana adapter's tagged ordinary digest accepts five public fields
and six IC entries only. It cannot validate v3's six public fields/seven IC
entries. Initial setup/reload records the exact ordinary VK **file** hash and
verifies its canonical serialization matches the ordinary VK projected from the
engine package. A separately reviewed six-field adapter/tag must later define
the **tagged ordinary VK digest** and bind it in the application package. No v2
tagged digest or verifier is reused or relabeled. This is a remaining interface
gate, not a reason to add another trusted setup.

## New versioned package and adaptation

Owned path: `circuits/credential-v3-bounded/qualification/prover/`. Its local
manifest uses the reviewed v2 dependency versions and engine/vendor paths. No
shared manifest/lock or engine/adapter source changes are requested.

After ROOT observes the decoder red test, adapt the reviewed v2 boundaries:

1. Canonical bounded WTNS decoder: exact prime, sections, count, constant one,
   field bounds and six ordered public coordinates. Retain malformed-header,
   truncation, trailing-byte and noncanonical-field negatives; add explicit
   five-vs-six field and changed-policy coordinate tests.
2. Bounded received-file loader: regular non-symlink files, exact owner/modes,
   inode/dev/open checks, bounded allocation and trusted expected SHA256 before
   JSON/PK/WTNS deserialization. Existing files are never overwritten.
3. Exact descriptor: pin the hashes/census above, set `Reduction::Original`,
   enforce 4.5M matrix-entry cap, 4-GiB internal allocation cap, max R1CS192MiB,
   section160MiB, row4096 terms, and four Rayon workers.
4. Setup command: require a ROOT-pinned passed v3 complete-witness suite report
   before creating setup randomness. Check report schema, R1CS/WASM identities,
   all52 cases,18 positives/34 negatives and complete positive relation census.
   Generate setup once with `OsRng`; no seed/toxic-scalar CLI, logs or files.
   Serialize canonical development PK, matching ordinary VK and manifest.
5. Package-check command: authenticate the trusted setup manifest by separately
   granted hash; check all artifact/context/census fields; hash PK bytes before
   decoding; reject trailing PK bytes; reconstruct one `PublicPackage::new`
   against the manifest's expected identity. The identity is trusted through
   ROOT's accepted setup receipt, not self-asserted by an imported key.
6. Compare projected ordinary VK serialization to the stored VK file. Enforce
   seven IC entries; validate curve/subgroup/canonical encoding with existing
   engine/ordinary checks. Missing/wrong schema, key, profile, reduction or
   package identity fails before assignment/proof use.
7. Validate all18 accepted complete witness assignments sequentially using that
   one admitted `PublicPackage`, matching all six public values. Record one
   package/VK identity for the entire loop and unchanged identity before/after;
   no per-certificate key setup or copy. One complete assignment is live at a
   time. Preserve each credential's Full/near pair for later proof work.

The package-check stage executes no proof. Full/Anchor proof qualification is a
subsequent independent grant: one shared setup, nine credential pairs, six
altered-public negatives per proof, cross-root and cross-holder/key/policy
binding negatives, and ordinary/application checks. Dynamic, Selective,
incremental witness generation and automatic mode selection stay disabled.

## Sequential finite gates and exact proposed commands

Working directory: `/Users/anishnarang/Zk-refresh`. ROOT checks every output path
is absent and runs each job in its existing external monitor. Four Rayon workers,
one Cargo job and one test thread; no parallel heavy jobs. Environment values:

```
CARGO_BUILD_JOBS=1
RAYON_NUM_THREADS=4
OMP_NUM_THREADS=1
CARGO_TARGET_DIR=/Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-prover-build-001
```

The following commands are inert proposals. Cargo and runtime grants are
separate; `setup` and `check-package` are intended interfaces to implement only
after the observed red gate, and are unavailable in today's scaffold.

### Gate 1: offline local lock and intended red test

```sh
/Users/anishnarang/.cargo/bin/cargo generate-lockfile --offline --manifest-path /Users/anishnarang/Zk-refresh/circuits/credential-v3-bounded/qualification/prover/Cargo.toml
```

Cap30s,256MiB RSS,4MiB output. Freeze only the new package-local Cargo.lock and
its exact dependency closure after generation; no dependency download or shared
lock edits. Then under a separate build grant:

```sh
/Users/anishnarang/.cargo/bin/cargo test --offline --locked --manifest-path /Users/anishnarang/Zk-refresh/circuits/credential-v3-bounded/qualification/prover/Cargo.toml tests::canonical_v3_wtns_round_trip_and_six_public_coordinates -- --exact --test-threads=1
```

Cap180s,2GiB aggregate RSS,512MiB new output. Expected: exactly one executed
assertion failure at the intentionally unimplemented decoder, exit101. Zero
tests, compile/import/dependency failure or a resource stop is not the red gate.
Preserve its source/report before implementing positive code.

### Gate 2: positive unit tests and release build

ROOT reviews the adapted source and expanded tests. Under finite separate grants:

```sh
/Users/anishnarang/.cargo/bin/cargo test --offline --locked --manifest-path /Users/anishnarang/Zk-refresh/circuits/credential-v3-bounded/qualification/prover/Cargo.toml -- --test-threads=1
/Users/anishnarang/.cargo/bin/cargo build --offline --locked --release --manifest-path /Users/anishnarang/Zk-refresh/circuits/credential-v3-bounded/qualification/prover/Cargo.toml
```

Unit cap180s/2GiB/512MiB; release cap300s/4GiB/512MiB additional output. ROOT
freezes the actual executable hash and complete dependency/source receipt. No
setup grant exists merely because a binary was built.

### Gate 3: one-time setup

Only after the complete-witness suite is accepted and the exact executable is
reviewed/frozen, populate `ACCEPTED_SUITE_SHA` from ROOT's protected receipt.
This variable is a required trusted input, not a new source constant or placeholder
that may default. Exact proposed argument order:

```sh
/Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-prover-build-001/release/credential-v3-bounded-qualification setup /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-compile-001/credential.r1cs /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-compile-001/credential_js/credential.wasm /Users/anishnarang/Zk-refresh/circuits/credential-v3-bounded/profile.json /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-witness-qualification-001/report.json "$ACCEPTED_SUITE_SHA" /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-development-setup-001
```

Cap1200s,4GiB sampled aggregate RSS,1GiB new output, four Rayon threads. Expected
v3 time30–120s, RSS1–2GiB and key output160–256MiB are planning estimates only.
The historical reviewed v2 setup took20.95s, sampled peak RSS1,213,562,880bytes
and output156,615,676bytes; v3 has the same FFT domain but a new relation and must
be measured independently. Retain the exact emitted package/VK identities and
ROOT-pinned setup-manifest hash; do not rerun setup for another credential.

### Gate 4: public-package reload and all accepted assignments

ROOT prepares a private0600 manifest with accepted suite and eighteen WTNS/public
paths and expected hashes; freezes it outside the importer's authority. Populate
`SETUP_MANIFEST_SHA` and `ACCEPTED_ASSIGNMENTS_SHA` from the accepted protected
receipts. Intended command:

```sh
/Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-prover-build-001/release/credential-v3-bounded-qualification check-package /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-compile-001/credential.r1cs /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-compile-001/credential_js/credential.wasm /Users/anishnarang/Zk-refresh/circuits/credential-v3-bounded/profile.json /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-development-setup-001/setup-manifest.json "$SETUP_MANIFEST_SHA" /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-accepted-assignments-001.json "$ACCEPTED_ASSIGNMENTS_SHA" /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-package-check-001
```

Cap300s,4GiB aggregate RSS,64MiB new output. Expected30–120s and RSS1–2GiB are
unmeasured estimates. Report only source/package/VK identities, counts, finite
stage durations and relation validation outcomes. No raw assignments, credential
fingerprints, signing keys, projections, caches, blinders or toxic scalars in
normal logs or scrubbed reports.

Stop on any pin, schema, census, canonical decoding, relation, allocation,
resource, ownership or cleanup failure. Preserve all paid work and diagnostics.
No automatic retry, cap expansion, alternate reduction, per-certificate setup,
setup/proof execution or deployment is authorized by this plan.

## Tests-first source pins

- New package manifest SHA-256: `85d5a59a358d259a17fec3790f593ddae3a8b869d946fce3c751fee0115f5dcd`.
- Formatted Rust scaffold SHA-256: `498da550e32eb9629021276c8a36d5747ae8cd78b2deae7b87a34048f2fa9c24`.
- `rustfmt --check` passes. No Rust compilation or test execution has occurred;
  the intended failing decoder assertion must still be observed by ROOT.
- The scaffold has no setup/proof execution path. The gate3/4 commands describe
  reviewed interfaces to implement after the red gate and cannot run today.

## Development trust limits

This is one trusted synthetic development generator with OS CSPRNG. Toxic setup
scalars exist in process memory and are not serialized or intentionally logged;
secure erasure is not claimed. A production ceremony remains separate. Public
PK/VK/package material is designed to be shareable within this profile after
review, but all emitted development artifacts remain private local files under
0700 directories/0600 files and outside Git during qualification. No signing
key is an input to setup or package loading.

A self-computed content hash does not establish ceremony provenance, issuer
eligibility, current status or application authorization. ROOT's accepted receipt
pins the development setup association; the later reviewed deployment package
pins the exact application and six-field ordinary VK. Same-user replacement of
the trusted executable/receipt is outside this controlled local qualification
trust boundary. Frozen-artifact unseen-credential acceptance still requires
additional certificates generated/imported after public artifacts are frozen,
with no source/setup changes, Full and Anchor proofs and actual queue effects.
