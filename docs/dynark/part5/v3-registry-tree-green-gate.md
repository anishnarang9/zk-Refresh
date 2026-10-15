# V3 registry tree GREEN gate

On October 15, 2026, the versioned v3 membership tree passed all seven
committed independent-vector and adversarial tests. They cover exact active
and inactive leaf commitments, sparse roots and paths, boundary slots,
least-significant-bit directions, unrelated and own revocation math,
noncanonical field rejection, mutation atomicity and separation from nonempty
v2 membership. The v3 leaf uses fixed domain `2026101504`, two unsigned BE128
halves of the complete SHA-256 TBS digest, slot and active bit. Empty leaves are
zero; inactive allocated leaves retain their digest commitment.

The bounded offline Cargo job exited 0 after **3.944 seconds**. It recorded
seven passed, zero failed or ignored, no cap stop, runner error or residual
owned process. Sampled peak owned-tree RSS was **531,562,496 bytes** and
positive storage growth was **76,464 bytes** in the warmed separate target.
The copied external receipt is
`results/dynark/part5/v3-registry-tree-green-bounded-001.json`, SHA-256
`e11b1b1df67f9a269cbf4761b3bcbc34c0ad955c6310bb7acdaf854a2c33fb61`.
Source SHA-256 values: `tree.rs`
`798eadc673f459b88431df97b8c33f29da2a8fbaf77ff7318a76b549302af6ab`;
`mod.rs` `df9643b19348ff31473a3e4a63583904813fbe0f482a1f789329ecc5fcc79d27`.

This gate establishes membership mathematics only. It does not authenticate
issuer enrollment, source signatures, publisher/current head, status freshness,
policy, or application effects. The v3 protocol, client and application gates
remain open.
