# Private publisher-envelope crypto GREEN review

ROOT accepted the focused publisher RED after materializing the independent
28-case fixture. This follow-up implements **private crypto/coherence only**.
No Cargo/helper/proof command has run. No native/program files, generator,
vector, tree, dependencies or source-authentication behavior changed.

## Exact pins

| File | SHA256 |
| --- | --- |
| `src/v3/protocol.rs` | `3684a4e5565c55827027d21e105e3720851844fab0d775ae36b596c682a734f2` |
| `tests/v3_publisher.rs` | `a1f27a6f4c217c7b145dfdb0f3578a330cc2a8076a6bc0b56ea589fb2e94a5ed` |
| Frozen `tests/vectors/v3-publisher-auth-v1.json` | `c2e4d6c73cdfe20ff2b7d8cd06a5e47b4a622ad9716de3671bd910632f461b48` |
| `Cargo.toml` (unchanged) | `394f5f86e31c6f0f3617e7a4cc36022c7d05205f875590131b580e6c5022bb83` |
| `Cargo.lock` (unchanged) | `0c6053b17473af31354e18a4aed172d5fd7a45041b9912c86d79b73c5a1f17fc` |

Paths above are relative to `crates/credential-registry/`.

## Private scope, public rejection

`check_publisher_envelope_claim` checks the independent signature, bounded
canonical JSON, exact source/scope/issuer/epoch/evidence correspondence,
canonical roots, source-head equality, explicit publisher/source-key separation,
active status, enable/status flags,
current/observed epoch equality, clock/source freshness on use and explicit
next-sequence/predecessor CLAIMS. Root version zero is permitted. Source expiry
is rechecked even when its opaque VerifiedSource was created earlier.

Inputs called CurrentHead/PublisherPredecessorClaim are explicitly untrusted
records. The result CheckedPublisherClaim has private fields, no public export,
constructor, serde/Debug/Clone or authorization operation. It only retains the
checked binding/source head and derived envelope digest. Private helpers are
deliberately disconnected from public authorization; limited dead-code
annotations express that boundary rather than exporting an unsafe entrypoint.

The legacy public `require_current(&CurrentHead,now)` remains unconditional
`Error::Authentication`. External tests now assert that it remains closed even
for genuine signatures and matching caller JSON. No public trait implementation
can mint a capability through it. No synthetic positive is called authenticated
chain state or application authorization.

## Exact digest contract sent to M1

Signature preimage:

```text
"DYNARK-V3-PUBLISHER-BINDING-v1\0" || compact typed JSON(body)
```

Body order: scope,issuer,source_head,root,root_version,publisher_key,
publication_sequence,previous_publication_digest.

Envelope digest:

```text
SHA256("DYNARK-V3-PUBLISHER-WIRE-v1\0" || compact typed JSON(PublisherBinding))
```

PublisherBinding has those eight fields followed by signature as the ninth and
final field. The exact64 signature octets ARE INCLUDED. No digest field is
inserted, so there is no self-reference. The private checker exposes this only
internally as CheckedPublisherClaim.envelope_digest after signature/coherence
checks. JSON has no whitespace; arrays contain integer octets; Fr words are
canonical BE32, identities and raw signature bytes are not field-reduced.
Scope/IssuerScope order is the existing reviewed declaration order, including
both config/issuer lifecycle epochs and separate enrollment evidence version.

A dedicated unit test independently reconstructs the full signed wire from
frozen generator signing bytes plus the exact signature array; it does not use
the production PublisherBinding serializer to derive the expected digest.

M1 may atomically store this declared digest under a publisher-signed transaction
without onchain JSON/Ed25519 parsing. The eventual offchain verifier must verify
the canonical detached signature/digest and compare it with finalized PDA state.
A future committed_at value is execution evidence, NOT part of this wire hash.

## Missing authority/provenance boundary

The current native client exposes trait/coherence contracts, not a configured
finalized v3 account verifier. Existing v2 harness confirmed-account helpers
cannot supply this authority. A future concrete verifier must pin trusted
deployment/network/program/ELF identities, verify finalized RPC account context,
owners, exact PDA derivations, discriminators/lengths, identities, lifecycle
epochs, active source/status/root bindings and authenticated clock before minting
opaque current-state capabilities. Caller JSON or a public trait alone cannot
replace those checks. Synthetic crypto vectors are not application addresses.

Current onchain Config381/Issuer374 store root/version and bound source head,
but NO publisher envelope sequence/digest. Thus a root/source match cannot prove
the latest publisher envelope or its predecessor. No durable authenticated
publisher checkpoint implementation exists here. A protected signed/HMAC cache
can still be rolled back; restart must fail closed without a fresh independent
checkpoint/anti-rollback anchor or reviewed onchain publisher-head extension.

ROOT/M1 are separately considering an additive per-config/issuer/publisher head
PDA and atomic versioned Bind-with-head. It would authenticate the latest
finalized COMMITTED envelope in that issuer stream, not unsubmitted messages.
This slice neither implements nor assumes it. ROOT/M1 approved the actual
application mapping Scope.registry=Scope.config=root-owning config PDA;
the future configured adapter must enforce it. Generic public crypto vectors
intentionally use distinct synthetic IDs and make no application-mapping claim.

## Pending focused verification

Seven new internal tests cover:

1. All28 independent signatures/preimages are genuine.
2. Exact crypto/coherence classification: two positives,26 negatives.
3. Corrupted signature rejection in the private checker.
4. A checked private claim still cannot authorize through public JSON.
5. Full-envelope digest/domain/signature inclusion from independent frozen bytes.
6. Authenticated inactive source remains a negative fact.
7. Coherently replacing both declared/current publisher with the genuine source
   signing key still rejects role collapse, without a key-mismatch mask.

Six existing external tests were migrated to permanent public rejection and
still cover independent publisher/source signatures, zero/later root claims,
wrong root/epochs/publisher/source, replay/staleness, inactive source, signature
mutation and caller-constructed JSON. Fixtures and generator remain unchanged.

Rustfmt and diff whitespace checks pass; compilation/test results are pending.
After a separate ROOT grant, recheck pins and fresh monitor/report paths:

```sh
env CARGO_BUILD_JOBS=1 RAYON_NUM_THREADS=4 OMP_NUM_THREADS=1 CARGO_TARGET_DIR=/Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-protocol-build-001 python3 -B /Users/anishnarang/Zk-refresh/results/dynark/phase-2/bootstrap/bounded_runner.py --owner part5-v3-registry-publisher-crypto-green-001 --cwd /Users/anishnarang/Zk-refresh --private-output /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-publisher-crypto-green-monitor-001 --report /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-publisher-crypto-green-bounded-001.json --runtime-seconds 180 --rss-bytes 2147483648 --storage-bytes 536870912 --storage-path /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-protocol-build-001 --poll-seconds 0.25 -- /Users/anishnarang/.cargo/bin/cargo test --offline --locked --manifest-path /Users/anishnarang/Zk-refresh/crates/credential-registry/Cargo.toml --lib --test v3_publisher -- --test-threads=1
```

Exactly seven library unit tests and six external integration tests are selected.
Caps180s/2GiB sampled owned-tree RSS/512MiB logical output growth, one Cargo job,
four Rayon workers,OMP1. Reuse the existing versioned registry protocol target.
Expected warm compilation/tests5–30s, below0.7GiB RSS/100MiB output; caps govern.
Require13 actual passing tests, exit0, no cap/runner error or residual processes.
Preserve exact logs/receipt/warnings. Stop on failure without retry, cap increase
or native/program/authority integration. Crypto-only GREEN does not complete the
authenticated publisher/current-head product gate.
