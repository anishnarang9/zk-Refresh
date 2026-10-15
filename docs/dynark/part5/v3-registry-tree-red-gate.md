# V3 registry tree tests-first RED gate

On October 15, 2026, the bounded registry test built the newly tracked
`credential-registry` crate offline and executed exactly
`independent_v3_active_leaf_vector_matches_exactly`. The deliberately closed
v3 leaf function returned `Err(Invalid)` where the independent Python
Poseidon vector expected canonical BE32 leaf
`1dc13c39a9c5dfd6351a0d693a538d9c28c169ed8f855499e64067f8b77a19d0`.
Six other v3 tree tests were filtered. This is an accepted RED assertion, not a
positive tree qualification.

Cargo exited 101 after successful compilation. The bounded job took 34.081
seconds with no resource stop, runner error or residual owned process. Sampled
peak owned-tree RSS was 522,829,824 bytes and positive storage growth was
151,772,903 bytes under the fresh registry target. The copied external receipt
is `results/dynark/part5/v3-registry-tree-red-bounded-001.json`, SHA-256
`676a1fb2f87e82bd44a343d356b798ce47b3545f3296eaa0b2994a74238bfeae`.
The protected stdout/stderr and original receipt remain in
`artifacts/dynark/part5/`.

The v3 tree must still implement the fixed `2026101504` leaf domain, full
SHA-256 digest split into two unsigned BE128 fields, ten Poseidon parent levels,
active and inactive leaves, canonical paths, and atomic mutation. Protocol,
source signatures, issuer enrollment and current-head authority are later
gates. The existing v2 tree remains a separate domain.
