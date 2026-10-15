# V3 pure complete-input candidate gate

The pure v3 input builder accepts the fixed `V3Q1` binary request and derives
the exact 751 canonical Circom scalars. It re-admits the supplied DER under the
bounded profile, verifies the issuer signature and the holder's signature of
the canonical action field, recomputes signed issuer/policy hashes and an
active depth-10 Poseidon membership path, then emits the fixed `V3I1` response.
It loads the exact pinned profile/Poseidon sources and constants from bounded
same-handle snapshots; no caller hash or mutable repository import supplies
those computations. Errors are normalized without input bytes in messages.

The [bounded GREEN receipt](../../../results/dynark/part5/native-v3-input-worker-green-bounded-001.json)
records seven passing tests, exit 0, no cap or runner error, no residual owned
process, 1.480 seconds, 88,522,752 bytes sampled peak owned-tree RSS and 659
bytes sampled test-directory growth. The cases include eight independently
issued certificate layouts with varied keys, exact 751-field output,
adversarial DER/key/policy/action/signature/path mutations and a coherent
unrelated-root refresh. Private stdout/stderr remain in
`artifacts/dynark/part5/native-v3-input-worker-green-monitor-001`.

This is a pure mathematical candidate builder. Its CLI is deliberately closed,
and no Rust standard-client path consumes it yet. The Rust side must derive the
request from imported credential, prepared action and authenticated state,
compare every candidate and complete-WTNS input coordinate, and validate the
full R1CS relation under the shared setup. Finalized issuer/current-state
authority and application Execute remain separate requirements.
