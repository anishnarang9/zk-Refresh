# Versioned v3 registry tree: first RED slice

Source-only scaffold. No Cargo command has run for this slice. The Anchor pilot
retains the heavy slot. No protocol/snapshot implementation is included.

## Owned changes and pins

The only existing-source change is the additive `pub mod v3;` line in
`crates/credential-registry/src/lib.rs`; the v2 tree, protocol, storage, API,
dependencies and wire behavior are unchanged.

| File | SHA256 |
| --- | --- |
| `crates/credential-registry/src/lib.rs` | `74b0f31e048c2fe56656a00fba967555039d4faf060f42b308b4eab391f72ff9` |
| `crates/credential-registry/src/v3/mod.rs` | `1a0b9dc728e760847a3772df80ff260b5386297b2dfb1931d1468e7c13e5c52d` |
| `crates/credential-registry/src/v3/tree.rs` | `12dddf3802cc19d5bbdddb5777e17b705c29a982dafe6dce5eb31ed3fe322411` |
| `crates/credential-registry/tests/v3_tree.rs` | `447ea126df79ff675dd9755325850e1dca95ca13e82308caf746dfc8e8eda227` |
| `crates/credential-registry/tests/vectors/v3-membership-v1.json` | `5fe328c2fcb56bd039fced406d43e7df37cd91e341f6b388b5ccf53a98bee2a3` |
| `tools/part5/registry_v3_vectors.py` | `4cd302205e05a58ca9ce0fedb0af9f315d411c34e88db32f019634843bd8fa6e` |

Existing dependency pins, unchanged:
Cargo.toml `394f5f86e31c6f0f3617e7a4cc36022c7d05205f875590131b580e6c5022bb83`;
Cargo.lock `0c6053b17473af31354e18a4aed172d5fd7a45041b9912c86d79b73c5a1f17fc`.

## Independent vector provenance

The generator imports only the pinned Python scalar Poseidon evaluator/constants.
It does not call Rust registry code, a credential/profile constructor or the
training-corpus root helper. It reconstructs whole levels from1024 public
synthetic leaves, independently of Rust's incremental update algorithm. Its
hash memoization avoids recalculating identical public subtrees.

- Python evaluator SHA: `82d6a93d2af03f17fe340eb7a2d0edbd47dd774ef205d7332b956c2e8c743d68`.
- Circom constants SHA: `94c9e4b5ea891ab4d1ba626f1d719f8c661014d9b628f6096c803f75f39e3eee`.
- Frozen circuit SHA: `2c973626535cd997c8d665b25043ac099017a5cea6f00d8686e4c68b0d866041`.
- Frozen profile SHA: `2e5d26564fb055e70cff924c4cb6e296509030b8c0062130f86ad5af783f7918`.

Vector provenance embeds all these identities and the generator hash. Generation
completed in0.287s and an independent second invocation of `build()` matched the
parsed JSON exactly. Output is15404bytes of public synthetic data. No certificate,
signing key, setup, witness or heldout credential was created or read.

Formula: Poseidon(5)(2026101504,BE128(digest[0:16]),BE128(digest[16:32]),slot,active).
Parents are Poseidon(2)(left,right), ten levels, path bits `(slot >> level) & 1`.
Registry fields use canonical BE32; a full SHA256 digest is split, not reduced.
Empty leaves are zero; inactive allocated leaves retain digest with active=0.

The first exact independent vector is:

```text
digest = 329f18af8fea7e292a7c58dd14ed561e84d3679382f6e4fab4e061c5b9c327e7
slot   = 0
active = true
leaf   = 1dc13c39a9c5dfd6351a0d693a538d9c28c169ed8f855499e64067f8b77a19d0
```

Its full digest exceeds Fr, deliberately testing the distinction between raw
SHA256 bytes and canonical scalar inputs. Both digest halves are below2^128.

## Scaffold and prepared tests

`v3::leaf_hash`, `Tree::new/set/path/verify` deliberately reject with
`Error::Invalid`; `Tree` cannot be constructed externally or through the stub.
Its root accessor is explicitly unimplemented. No positive v3 membership or
authentication can be claimed. Domain2026101504 is a fixed public constant,
with no domain-selector argument in the Rust API.

Seven integration tests are authored but **not compiled or executed**:

1. One exact independent active leaf (the intended RED).
2. Twelve active/inactive leaves, six boundary/mixed-direction slots and v2-domain differences.
3. Sparse complete tree, independent roots/paths and least-significant-bit directions.
4. Unrelated revocation changes exactly one sibling; own revocation rejects active membership.
5. Digest-half/byte reversal, wrong slot and path-order rejection.
6. Invalid slots/path lengths, altered siblings, noncanonical field values including exact Fr modulus, and mutation atomicity.
7. Nonempty v2/v3 membership does not cross-verify; empty roots intentionally coincide and need distinct later protocol scopes.

Low-level verification of an inactive commitment is useful for tree integrity;
later authorization must require active=true. This slice supplies no issuer,
policy, freshness, source signature, current-head or application authority.

Rustfmt parses the new source/tests. A native compiler result is still pending.

## Proposed one-test bounded RED

Only after ROOT's explicit queue grant, recheck the pins above and fresh paths.
Use a separate target; no lock generation or dependency/network change.

```sh
env CARGO_BUILD_JOBS=1 RAYON_NUM_THREADS=4 OMP_NUM_THREADS=1 CARGO_TARGET_DIR=/Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-tree-build-001 python3 -B /Users/anishnarang/Zk-refresh/results/dynark/phase-2/bootstrap/bounded_runner.py --owner part5-v3-registry-tree-red-001 --cwd /Users/anishnarang/Zk-refresh --private-output /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-tree-red-monitor-001 --report /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-tree-red-bounded-001.json --runtime-seconds 180 --rss-bytes 2147483648 --storage-bytes 536870912 --storage-path /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-registry-tree-build-001 --poll-seconds 0.25 -- /Users/anishnarang/.cargo/bin/cargo test --offline --locked --manifest-path /Users/anishnarang/Zk-refresh/crates/credential-registry/Cargo.toml --test v3_tree independent_v3_active_leaf_vector_matches_exactly -- --exact --test-threads=1
```

Caps:180s wall,2GiB sampled owned-tree RSS,512MiB logical output growth;
one Cargo job/four Rayon workers/OMP1. Expected fresh-target compilation may
take30–120s, with approximately0.5GiB RSS/200MiB output; caps are authoritative.
The monitor and report paths are absent at review. No command has been launched.

Accept RED only if exactly this one test executes and fails at the equality
assertion (`Err(Invalid)` versus the exact expected `Ok(leaf)`), exit101, no cap
stop and no residual owned process. A compile/resource failure is not RED.
Preserve logs, warnings, source pins and exact receipt; do not retry or implement
GREEN without ROOT review. Protocol/snapshot is a separate later slice.
