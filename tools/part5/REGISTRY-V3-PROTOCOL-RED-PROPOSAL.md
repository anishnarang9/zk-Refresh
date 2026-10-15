# V3 registry source authentication: first RED slice

Source-only rejecting scaffold. No Cargo/heavy/proof command has run. Tree GREEN,
v2 source/storage/protocol and dependency lockfiles remain unchanged. No snapshot,
publisher GREEN, tree application or persisted state is implemented here.

## Exact files and hashes

| File | SHA256 |
| --- | --- |
| `crates/credential-registry/src/v3/mod.rs` | `bd5309c1e88a96d59912720a8437535727804f7dd88a568740dff4048313a4ce` |
| `crates/credential-registry/src/v3/protocol.rs` | `d47d56ce77019ca6d13719dbeda989c4698b29609921f51899384c422d66e38a` |
| `crates/credential-registry/tests/v3_protocol.rs` | `c20ae073aedf4dedd5fc27e3bcc70f15378d8b0ac8cc266f35a4821a6661af8b` |
| `crates/credential-registry/tests/vectors/v3-source-auth-v1.json` | `8b4044523fccc19e5834db290c7fe9c810c1b32328ac24f3aef909ffd18e5afd` |
| `tools/part5/registry_v3_source_vectors.py` | `2b96d8a40c2c9cd03c371b97da4eb7895c0a2852a47db1c62212df6e642fcfee` |

Unchanged tree GREEN SHA:
`798eadc673f459b88431df97b8c33f29da2a8fbaf77ff7318a76b549302af6ab`.
Unchanged existing lib.rs SHA:
`74b0f31e048c2fe56656a00fba967555039d4faf060f42b308b4eab391f72ff9`.
Existing dependency pins, unchanged: Cargo.toml
`394f5f86e31c6f0f3617e7a4cc36022c7d05205f875590131b580e6c5022bb83`;
Cargo.lock `0c6053b17473af31354e18a4aed172d5fd7a45041b9912c86d79b73c5a1f17fc`.

## Exact signed records and fail-closed boundaries

The new `v3::protocol` namespace uses separate typed records and denies unknown
serde fields. It does not re-export v2 protocol types or offer migration.

`Scope` field order is network,program,config,registry,profile,circuit,schema,
package,ordinary_vk,policy_hash,policy_version,config_eligibility_epoch,
leaf_domain,depth. The latter fields must match the fixed tree domain2026101504
and depth10 in future verification, not become a caller-selected tree profile.

`IssuerScope` field order is issuer_account,issuer_hash,source_key,
issuer_eligibility_epoch,enrollment_evidence_version,evidence_digest. The
issuerHash binds the enrolled modulus and signed AKI; its association and
evidence are supplied by authenticated administrator enrollment, never by the
source choosing its own authority. Both eligibility epochs are lifecycle values
separate from enrollment evidence version. Initialized epoch zero can be valid.

`Observation` field order is scope,issuer,sequence,previous_digest,observed_at,
valid_until,issuer_status_active,changes. Each change names only a TBS digest
under this observation's issuer (Issue adds slot/allocation epoch; Revoke does
not carry an issuer override). Each issuer has its own Ed25519 source key,
positive sequence and predecessor digest. A source cannot authorize another
issuer or alter trusted enrollment/config enablement.

The exact signing preimage is:

```text
"DYNARK-V3-SOURCE-STATUS-v1\0" || compact typed JSON(Observation)
```

The proposed source-head digest is:

```text
SHA256("DYNARK-V3-SOURCE-WIRE-v1\0" || compact typed JSON(SignedSource))
```

SignedSource field order is observation,signature. Compact JSON follows the
declared field order with no whitespace; byte arrays are integer arrays and
field words represent canonical BE32. Strict bounded decode/re-encode, Fr checks,
signature/sequence/freshness/enrollment checks remain future GREEN work.

`SignedSource::verify` deliberately always returns `Error::Authentication`.
The future successful `VerifiedSource` is opaque, unconstructible by a caller
and has no serde/Debug implementation. No authentication succeeds now.

`PublisherBinding` binds the same Scope and IssuerScope (therefore **both config
and issuer eligibility epochs**), source head, root/version, publisher key,
separate publication sequence and previous publication digest. Its signature
field is unverified; the fixture's publisher signature is explicitly a zero
placeholder, not an independent valid publisher vector.

`CurrentHead` expresses the external adapter boundary: exact account scope,
issuer, source head, root/version, publisher key, current enabled/status flags,
observed_config_epoch,observed_issuer_epoch and authenticated clock validity.
Constructing/deserializing this record is not chain, enrollment or finality
authentication. M2 must obtain it from authenticated M1 account/clock state.
`PublisherBinding::require_current` deliberately always rejects. Source sequence
zero is unobserved; root version zero can represent initialized current state.

## Independent vectors and authored tests

The Python generator independently encodes and signs two synthetic issuers with
distinct Ed25519 keys and sequence heads (3 after2,8 after7). Known deterministic
seeds are labeled PUBLIC TEST DATA, not usable development/production authority
credentials. No heldout or real issuer/holder key was created or read.

There are25 independently re-signed negative observations: all realm identities,
policy/version, fixed tree metadata, both eligibility epochs, enrollment evidence
version/digest, issuer identity/hash, zero/replayed/gapped sequence, predecessor,
self-selected other issuer key and the v2 signing domain. They carry genuine
signatures so future scope/sequence tests cannot pass merely by detecting stale
signatures after a mutation.

Each vector retains exact signing bytes; presentation JSON may sort its own
keys without changing the signed preimage. A check initially reconstructed a
preimage from sorted presentation order and failed; investigation confirmed
that typed field order verified the original signature. Exact preimages are
now retained for every case, and tests compare typed serialization against
those bytes before attempting authentication.

All27 signatures (two positives plus25 re-signed negatives) were independently
verified using OpenSSL CLI `pkeyutl -verify -rawin`, including the negative's
declared alternate key/domain where applicable. Public fixture size443020bytes.
Generation/fixture checks were lightweight; no native build/test occurred.

Six Rust tests are authored but not executed:

1. Exact independent positive source signature (intended RED); first compare
   typed signing bytes and verify the real signature using OpenSSL, then assert
   production acceptance. The deliberate Authentication stub fails this last
   assertion.
2. Separate issuer keys/sequences, cross-issuer rejection and independent positives.
3. Unsigned epoch/evidence/scope/key/signature mutations reject.
4. Replay/gap/stale/zero-sequence/predecessor and disabled authority reject.
5. Twenty-five genuinely re-signed mismatches reject; first independently verify
   their exact preimages/signatures within the test.
6. Publisher/current-head gate remains fail-closed in this source-only slice.

Rustfmt parses the new source and tests. A successful compiler result and the
intended RED assertion remain pending. No GREEN or snapshot implementation is
authorized by this proposal.

## Exact bounded RED proposal

After explicit ROOT grant, recheck every pin and all fresh paths, then run only:

```sh
env CARGO_BUILD_JOBS=1 RAYON_NUM_THREADS=4 OMP_NUM_THREADS=1 CARGO_TARGET_DIR=/Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-protocol-build-001 python3 -B /Users/anishnarang/Zk-refresh/results/dynark/phase-2/bootstrap/bounded_runner.py --owner part5-v3-registry-protocol-red-001 --cwd /Users/anishnarang/Zk-refresh --private-output /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-protocol-red-monitor-001 --report /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-protocol-red-bounded-001.json --runtime-seconds 180 --rss-bytes 2147483648 --storage-bytes 536870912 --storage-path /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-protocol-build-001 --poll-seconds 0.25 -- /Users/anishnarang/.cargo/bin/cargo test --offline --locked --manifest-path /Users/anishnarang/Zk-refresh/crates/credential-registry/Cargo.toml --test v3_protocol independent_v3_enrolled_source_signature_is_accepted -- --exact --test-threads=1
```

Caps:180s wall,2GiB sampled owned-tree RSS,512MiB output growth; one Cargo job,
four Rayon workers,OMP1. Separate fresh protocol target; no lock generation or
network/dependency change. Expected cold build30–90s, below0.6GiB RSS/250MiB
output; caps remain authoritative. Target/monitor/report paths are absent.

Accept RED only if exactly one test executes (five filtered), independent
preimage/signature assertions pass, and the final source-acceptance assertion
fails `Err(Authentication)` versus `Ok(())`, exit101. Require no cap stop, runner
error or residual process. Compiler/resource/fixture failures do not establish
RED. Preserve source pins, stdout/stderr/warnings and exact receipt; stop without
retry or GREEN until ROOT reviews it.
