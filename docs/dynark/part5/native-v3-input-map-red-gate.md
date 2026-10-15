# V3 Full compiler-input map: tests-first RED gate

The standard client needs the frozen compiler's map for 14 input names and
751 individual scalar coordinates. Six public inputs must occupy witness
coordinates 1–6 in the declared order. The other inputs cover layout, slot,
the 672 signed TBS bytes, RSA modulus/signature limbs, ten siblings and ten
path bits. Neither certificate offsets nor witness coordinates may be selected
by an individual credential.

The standalone map loader and parser are currently closed with `Unsupported`.
The focused ignored positive compiled and failed at that intended boundary:
`pinned v3 compiler map admission is implemented: Unsupported`. One test
failed with two filtered in 2.069 seconds. Sampled peak owned-tree RSS was
265,486,336 bytes and storage growth was 1,660,513 bytes, with no cap,
runner error or residual process. Receipt:
`results/dynark/part5/native-v3-input-map-red-bounded-001.json` (SHA-256
`0b35473ef9210e959e60f1134554275d8d69cecdeaa2bd7b34913100d23198a4`).

| New file | SHA-256 |
| --- | --- |
| `crates/dynark-native-client/src/v3_input_map.rs` | `8d922abdb1da2d8b059cca9471c2694e774abaa4ffad32fa52b5b18c3f779ae4` |
| `crates/dynark-native-client/tests/v3_input_map.rs` | `91d5b31846e9fb2068d8258982bb46a41dae0686ed0b45443788ee739a11255e` |

Map admission alone authenticates no credential, issuer, state, signer or
relation. The v3 corpus discarded its holder keys, so a separate protected
synthetic training credential/signer preparation is needed for an actual
finalized action. `open_full` remains closed, and the frozen unseen cohort
still waits until after implementation/artifact freeze.
