# V3 ordinary verifier component gate

The program now embeds the reviewed six-public-input ordinary VK. Its 896
coordinate bytes match the pinned public projection
`b3321c0bbc47f8775de86539f04b38e7768c8cefd58d7e62619f99d8b1103c94`.
The v3 component verifier checks canonical public scalars and proof
coordinates, rejects infinity, and then runs the ordinary BN254 Groth16
verifier. The v1/v2 keys remain separate.

The [focused bounded receipt](../../../results/dynark/part5/v3-vk-green-bounded-001.json)
records seven passed tests, exit 0, no cap and no residual owned process. A
public corpus Full proof verifies under both an independently decoded VK and
the embedded VK. All six changed public fields and tested malformed proofs
reject. The [full program receipt](../../../results/dynark/part5/v3-vk-regression-bounded-001.json)
records 109 passed tests across the program targets, exit 0, no cap and no
residual owned process. Both receipts use sampled resource accounting; detailed
logs stay under `artifacts/dynark/part5/`.

This proves the host component boundary. The proof fixture's action field is
synthetic. Runtime Execute still returns Unavailable, and no loaded v3 SBF,
compute-unit, packet-size, finalized-request, or queue-effect gate has passed.
