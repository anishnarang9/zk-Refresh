# Native v3 canonical action: tests-first gate

The frozen vector defines the 394-byte action-v2 request preimage and its
canonical BE32 SHA-256 reduction into Fr. Account order, owners, privileges,
holder modulus, and expected action are separate checks in the same frozen
Rust test target. This boundary prepares an actionHash field; it does not prove
or authorize a request.

The exact fixed-vector test compiled and failed at the intended `Unsupported`
scaffold. One test failed, four were filtered, and bounded duration was 2.054
seconds. The monitor recorded no cap, runner error or residual process. Sampled
peak owned RSS was 219,152,384 bytes; positive storage growth was 1,289,399
bytes. Public receipt
`results/dynark/part5/native-v3-action-red-bounded-001.json` has SHA-256
`9da2915d51299724b2f0c2358215db948c3f74c1b2b37efac38ef6465a94d47c`.
The tests-first scaffold and proposed command are in
`docs/dynark/part5/native-v3-action-red-proposal.md`.
