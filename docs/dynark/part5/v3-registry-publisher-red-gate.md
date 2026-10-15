# V3 registry publisher/current-head: tests-first RED gate

The publisher binding must be independently signed and linked to an
authenticated source head, trusted current program state and a trusted
publisher predecessor. The existing `require_current(&CurrentHead, now)`
cannot establish those facts: `CurrentHead` is caller-constructible JSON, so
that legacy entrypoint remains deliberately rejecting.

A bounded helper materialized 28 public synthetic signed publisher cases in
`crates/credential-registry/tests/vectors/v3-publisher-auth-v1.json` (126,245
bytes, SHA-256 `c2e4d6c73cdfe20ff2b7d8cd06a5e47b4a622ad9716de3671bd910632f461b48`).
The helper used an independently derived known **test** publisher Ed25519 key,
distinct from the signed per-issuer source keys, and retained the exact
preimage for independent OpenSSL verification in Rust. No key is a real
enrollment or chain authority. The helper's bounded receipt is
`results/dynark/part5/v3-registry-publisher-vector-bounded-001.json` (SHA-256
`a356345066173f18fcdb10cf4c7184e9d17908f960e197d6a5a7dce885b012f5`):
0.333 seconds, sampled peak RSS 6,111,232 bytes, storage growth 1,263,203
bytes, no cap/error/residual process.

The focused Rust RED compiled, reconstructed the exact typed publisher
preimage, independently verified its signature with OpenSSL, authenticated
the signed source through the existing `SignedSource::verify`, and matched
the resulting source head. It then failed at the expected final assertion:
`Err(Authentication)` versus `Ok(())` from the legacy rejecting gate. One
test failed with five filtered; runtime was 4.910 seconds, sampled peak RSS
184,336,384 bytes, storage growth 2,214,235 bytes, no cap/error/residual.
The receipt is `results/dynark/part5/v3-registry-publisher-red-bounded-001.json`
(SHA-256 `b77aba6901c8eb9330b7667760175b3bf943e3a9a8a5d845dfab70320706fd38`).

`protocol.rs` remains SHA-256
`ebdb8f06d2e266608d2057bb4bd709ac5545c87c5978ad77c905c964308be5ad`.
The next gate must add a capability-taking API whose current-head and
publisher-predecessor inputs have authenticated provenance. Enabling the
legacy JSON-only method would defeat this gate. This RED does not establish
chain finality, source completeness, publication or application admission.
