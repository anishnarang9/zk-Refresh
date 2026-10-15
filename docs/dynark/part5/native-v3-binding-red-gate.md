# V3 complete-witness envelope: tests-first RED gate

The new client scaffold requires concrete imported credential, shared setup,
authenticated state and prepared action references. Its real `open_full`
method remains closed with `Unsupported`. The private envelope check is also
`Unsupported` pending implementation; it is never an authorization or proof
admission gate by itself.

The focused bounded test compiled and failed at the intended first assertion:
`Err(Unsupported)` versus `Ok(())` for a synthetic Full WTNS envelope. It ran
one test with six filtered, exited 101 in 2.379 seconds, hit no cap or runner
error, and left no owned process. Sampled peak owned-tree RSS was 248,430,592
bytes and sampled storage growth was 2,423,982 bytes. The receipt is
`results/dynark/part5/native-v3-binding-red-bounded-001.json` (SHA-256
`2fe1d836493cd61c48b9bf6198667493876e3967d405338c346cfb30d3111977`).

| New file | SHA-256 |
| --- | --- |
| `crates/dynark-native-client/src/v3_binding.rs` | `92b02823ae90647522b3ee25c2210f93c1163211e0d605890f9aef3fe174c116` |
| `crates/dynark-native-client/tests/v3_binding.rs` | `e16981df439f68a22133e68cc807741764477fb6299508c19c19be68ac8ea4ec` |

The synthetic container has zero private coordinates and satisfies no X.509
relation. The later GREEN envelope can check shape and local context only.
Actual Full witness mapping, relation validation, source authentication,
proving, and application authorization remain separate gates.
