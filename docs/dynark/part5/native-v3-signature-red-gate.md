# Native v3 holder signature: tests-first gate

The frozen worker interface verifies RSA-2048, exponent 65,537, SHA-256 with
PKCS#1 v1.5 over the canonical 32-byte big-endian action hash. The separate
Rust request boundary derives that hash from the exact 394-byte action-v2
preimage. The worker does not receive that preimage.

The first synthetic matching-holder positive failed at the intended
`NotImplementedError` scaffold. One test ran in 0.310 seconds of bounded time;
the monitor recorded no cap, runner error or residual process. The sampled
peak owned RSS was 6,586,368 bytes and positive storage growth was 2,272 bytes.
The public receipt is
`results/dynark/part5/native-v3-action-python-red-bounded-001.json` (SHA-256
`659d013cf1c1ac5b10469c202a30226e11b31a90f2f95e66545e0fc06e72ee5f`).
No signature is admitted by this RED result.
