# V3 proof runner release build

The isolated proof runner compiled with one Cargo job, offline locked
dependencies, and the reviewed source closure on October 15, 2026. The bounded
build exited 0 in 75.105 seconds, with no cap stop or residual owned process.
Sampled peak owned-tree RSS was 512,311,296 bytes and sampled new storage was
172,626,055 bytes. The build emitted existing vendor/dependency warnings.

The 3,089,712-byte release executable is
`artifacts/dynark/part5/v3-proof-runner-v1-build-001/release/credential-v3-bounded-proof-qualification-v1`,
SHA-256 `7331299159d7abb38cc69edb961e02778d0e2f03942c2c60bffcb4a8e13a48d6`.
The external bounded receipt is
`results/dynark/part5/v3-proof-runner-v1-release-bounded-001.json`, SHA-256
`ad9bc4c7c44f402811af89b349fef1336600bd017207e970d3ffa2fcf8efe3c6`.

Compilation establishes an executable identity for subsequent packet and proof
gates. No credential Full or Anchor proof has run under this executable yet.
