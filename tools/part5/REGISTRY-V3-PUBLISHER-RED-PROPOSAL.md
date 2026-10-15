# Publisher/current-head RED: source-only preparation

No Cargo or qualification helper has run. `protocol.rs` remains unchanged and
`PublisherBinding::require_current` still always rejects. No production source
implementation, snapshot or authenticated chain adapter was added.

## Source pins and fixture prerequisite

| File | SHA256 |
| --- | --- |
| New `crates/credential-registry/tests/v3_publisher.rs` | `9dedde326443a5cab4c9a6a382f3c394805c72992b6916e5ed475569e4462b0f` |
| New `tools/part5/registry_v3_publisher_vectors.py` | `28cd8c59d0cad0fa40ca2fdfd9d320fb0af3ebac6837abfdaff0d729c291f48c` |
| Unchanged `crates/credential-registry/src/v3/protocol.rs` | `ebdb8f06d2e266608d2057bb4bd709ac5545c87c5978ad77c905c964308be5ad` |
| Frozen source fixture | `8b4044523fccc19e5834db290c7fe9c810c1b32328ac24f3aef909ffd18e5afd` |

The NEW signature bytes have **not been generated**: the instruction prohibits
helper execution. The concrete independent recipe is ready for a separate
bounded materialization grant. Its future output is
`crates/credential-registry/tests/vectors/v3-publisher-auth-v1.json`.
ROOT must receive/pin that output hash before RED. No output hash, signature
verification or successful fixture generation is claimed at this point.

The helper uses cryptography Ed25519 and independently ordered compact JSON;
the Rust tests independently reconstruct the typed preimage and verify with
OpenSSL before reaching production code. It derives a NEW known public TEST
seed in a publisher-specific domain, checks its public key differs from both
per-issuer source keys and a second publisher test key. None is an authority
or a real/heldout credential. The source-positive fixture is imported only after
its frozen SHA matches. Inactive source status is independently re-signed with
the explicitly public source test seed; it contains a Revoke, never an Issue.

Rustfmt parses the new test source. Python generator execution/syntax checking
and native compilation remain pending; ROOT's materialization gate must stop
on any failure and review the source rather than retry automatically.

## Exact signed binding

Signing preimage:

```text
"DYNARK-V3-PUBLISHER-BINDING-v1\0" || compact JSON(body)
```

Body field order is scope,issuer,source_head,root,root_version,publisher_key,
publication_sequence,previous_publication_digest. Scope/IssuerScope use the
already reviewed typed ordering and include BOTH config/issuer eligibility
epochs, separate enrollment evidence version/digest, all package/policy/network
identities, fixed tree domain/depth and the enrolled issuer/source association.
Only signature is excluded. `source_head` must equal the opaque VerifiedSource
head; its canonical source-wire digest commits the authenticated status bit.

The helper retains exact signing bytes for every genuinely signed case. Sorted
presentation JSON is never reconstructed as a signing preimage. Publisher key,
per-issuer source sequence and publisher publication sequence are separate.
Root version zero is a legitimate initialized current version, not proof of an
unobserved issuer. Source sequence zero remains invalid.

## Required safe API change after ROOT's RED review

The existing `require_current(&CurrentHead,now)` cannot establish chain authority:
its argument is publicly constructible and serde-decodable, and it receives no
VerifiedSource or trusted publisher predecessor. It must remain permanently
rejecting; verifying a signature under a key selected by that JSON is unsafe.

Propose a NEW entrypoint, conceptually:

```text
verify_with_current(
    &VerifiedSource,
    &AuthenticatedCurrentHead,
    &AuthenticatedPublisherCheckpoint,
    now
) -> VerifiedPublication
```

The new result and current-head/checkpoint tokens have private fields and no
serde, public constructor, From<CurrentHead> or Debug implementation.

- M2's configured, reviewed chain/account/clock verifier authenticates the
  program/owners/network/finality and exact current config/issuer records before
  producing current-head capability through an explicitly trusted provider
  boundary. A remote request cannot select a provider implementation or mint a
  token by supplying JSON. A trait implementation alone is not authentication.
- The capability binds full scope, issuer enrollment/evidence, both current and
  observed eligibility epochs, enabled/status state, publisher key, exact current
  root/version, source sequence/digest, clock validity and finality context.
- The publisher checkpoint is scoped trusted previous state, obtained from a
  previously accepted publisher envelope or separately authenticated recovery.
  It is NOT a caller's JSON sequence/digest and is NOT inferred from root version.
  The current program does not establish an offchain publisher envelope sequence.
- Verification requires active VerifiedSource status, exact head/scope/epochs,
  fresh source again at use time, exact current authority and publisher signature,
  next publisher sequence/predecessor, canonical fields and bounded encoding.
- Signed inactive facts remain ingestible by the source pipeline but cannot
  produce VerifiedPublication or authorize membership/application work.

The test's clearly marked RED-only shim currently reaches the legacy rejecting
method after independent fixture/source checks. This establishes the missing
publisher gate without changing production code. **Before any GREEN**, ROOT
must approve the capability API and migrate that one shim to it; enabling the
legacy method to satisfy the positive assertion is forbidden. The separate
JSON-only negative must continue to pass. These are prefreeze source tests;
this necessary API migration requires fresh source pins, not fixture invention.

An actual configured M2 adapter gate is separate from these synthetic fixture
tests. Neither fixture JSON nor known signatures establish chain finality,
upstream revocation completeness or loaded application authorization.

## Prepared matrix (not executed)

Recipe declares28 genuine publisher cases: two positives (current root versions0
and9),26 negatives. Negative cases cover wrong root/version, config/issuer epoch,
evidence version, package/policy, publisher key, source sequence/digest, zero
source sequence, replay/gap/predecessor, stale/future clock, disabled config/issuer,
invalid status, stale observed epochs, exact Fr-modulus root, authenticated inactive
source and a source key used as publisher. All mutations are independently
re-signed with the declared signing key to avoid masking missing binding checks
with invalid signatures.

One case authenticates a source at150 but attempts publisher use at201 after its
expiry at200, while the supplied current-clock window is fresh. This must fail
at source freshness on use, not merely at a stale current-clock guard.

Six Rust tests are authored: intended independent positive RED; initialized/later
positive roots; genuine negative matrix; inactive source; corrupted publisher
signature; legacy caller-constructed JSON gate always rejecting. The first test
verifies the publisher preimage/signature using OpenSSL, authenticates the source
through committed SignedSource::verify, compares source heads, then expects
acceptance from the deliberately rejecting production gate.

## Separate proposed bounded grants

### Prerequisite: materialize NEW public synthetic fixture

Recheck generator/source-fixture pins and fresh output/monitor paths. Then, only
after ROOT's explicit grant:

```sh
python3 -B /Users/anishnarang/Zk-refresh/results/dynark/phase-2/bootstrap/bounded_runner.py --owner part5-v3-registry-publisher-vector-001 --cwd /Users/anishnarang/Zk-refresh --private-output /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-publisher-vector-monitor-001 --report /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-publisher-vector-bounded-001.json --runtime-seconds 30 --rss-bytes 268435456 --storage-bytes 4194304 --storage-path /Users/anishnarang/Zk-refresh/crates/credential-registry/tests/vectors/v3-publisher-auth-v1.json --poll-seconds 0.25 -- python3 -B -m tools.part5.registry_v3_publisher_vectors --output /Users/anishnarang/Zk-refresh/crates/credential-registry/tests/vectors/v3-publisher-auth-v1.json
```

Caps30s/256MiB/4MiB, including monitor/output growth. Expected under5s/128MiB/
2MiB; exact measurements replace estimates. Require exit0 and28 cases, output
at most2MiB, no cap/error/residual. Return fixture SHA before the RED grant.
No automatic Cargo launch follows successful generation.

### Focused publisher RED, after fixture pin and separate ROOT grant

```sh
env CARGO_BUILD_JOBS=1 RAYON_NUM_THREADS=4 OMP_NUM_THREADS=1 CARGO_TARGET_DIR=/Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-protocol-build-001 python3 -B /Users/anishnarang/Zk-refresh/results/dynark/phase-2/bootstrap/bounded_runner.py --owner part5-v3-registry-publisher-red-001 --cwd /Users/anishnarang/Zk-refresh --private-output /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-publisher-red-monitor-001 --report /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-publisher-red-bounded-001.json --runtime-seconds 180 --rss-bytes 2147483648 --storage-bytes 536870912 --storage-path /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-protocol-build-001 --poll-seconds 0.25 -- /Users/anishnarang/.cargo/bin/cargo test --offline --locked --manifest-path /Users/anishnarang/Zk-refresh/crates/credential-registry/Cargo.toml --test v3_publisher independent_v3_publisher_binding_is_accepted -- --exact --test-threads=1
```

Caps180s/2GiB/512MiB, one Cargo job/four Rayon workers/OMP1; reuse the existing
versioned registry protocol target. Expected warm build5–30s/below0.7GiB/100MiB.
Recheck Cargo.toml/lock and all committed source pins immediately before launch.
Only one test executes/five filtered. Accept RED only when independent crypto
and VerifiedSource prerequisites pass and the final comparison fails
`Err(Authentication)` versus `Ok(())`, exit101, no cap/error/residual. Missing
fixture, serialization/crypto/compile/resource failures are not RED. Preserve
receipts/warnings/logs and stop; no GREEN, API change or helper retry without
ROOT review.
