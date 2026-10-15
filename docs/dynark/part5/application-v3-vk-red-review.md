# V3 ordinary verifier RED gate

The new public-only vector pins one corpus Full proof, six public values and
the shared ordinary VK by exact source hashes and sizes. The tests decode Ark
compressed points into the Solana ABI at runtime, require seven IC points and
the tagged six-input VK digest, then check valid and changed proofs/fields.
This component proof has a synthetic action field and does not exercise a
finalized application request or queue effect.

The [bounded RED receipt](../../../results/dynark/part5/v3-vk-red-bounded-001.json)
records only the expected compile errors: missing
`generated_vk_v3::VERIFYING_KEY` and `application_runtime_v3::verify`. Exit 101
occurred in 1.567 seconds, with 170,377,216 bytes sampled peak owned-tree RSS,
1,674,992 bytes sampled target growth, no resource cap and no residual owned
process. The proof conversion and positive verification have not executed yet.
Private compiler diagnostics remain under
`artifacts/dynark/part5/v3-vk-red-monitor-001`.

The legacy five-input keys remain separate. Execute stays unavailable until
the ordinary verifier is integrated with preflight and an atomic queue effect.
