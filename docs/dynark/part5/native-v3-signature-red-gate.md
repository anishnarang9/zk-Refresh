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

## Focused GREEN result

The worker now compares exact-width, equal holder modulus declarations and
checks a canonical action field and RSA signature integer before public-key
verification. It verifies the SHA-256 DigestInfo encoding of the BE32 action
field with exponent 65,537. It loads no key and signs nothing. The four frozen
tests passed in 0.301 bounded seconds, with no cap or residual process. The
sampled peak owned RSS was 6,127,616 bytes and positive storage growth was
659 bytes. Public receipt
`results/dynark/part5/native-v3-action-python-green-bounded-001.json` has
SHA-256 `ad910b4cab165d5c5a607923cfbe817dbe2e0dacb40e24a434c76e33de1a8e44`;
the reviewed worker source has SHA-256
`46692db2692d35f8624fde87ba9aa87239a5f8fab829a15a515a5a88ea6e80a6`.
This is synthetic signature verification, not a holder credential or request
admission gate.
