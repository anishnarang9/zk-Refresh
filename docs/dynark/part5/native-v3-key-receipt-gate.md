# Native v3 ordinary key receipt gate

The frozen full manifest and ordinary verification key record have distinct
package, raw VK, tagged VK and reviewed receipt commitments. The exact 1,458
byte reviewed receipt is authenticated against a digest pinned in the client.
Caller supplied hashes and JSON reserialization cannot substitute for it.
This admits the reviewed **ordinary key identity only**. It does not admit an
issuer, authenticate the full proving key, or authorize an application action.

The focused positive first failed at the `Unsupported` scaffold: one failure,
25 filtered, 2.047 seconds, no cap or residual process. After implementation,
the seven `v3::tests` passed in 2.019 seconds, with 20 filtered and no cap or
residual process. The sampled peak owned RSS was 243,105,792 bytes; positive
storage growth was 603,175 bytes. The bounded public receipts are
`results/dynark/part5/native-v3-key-receipt-red-bounded-001.json` and
`results/dynark/part5/native-v3-key-receipt-green-bounded-001.json` (SHA-256
`028c59dc0afda2eadd16c7a2789bb3e4eb4349d29a318fd900be16213cfb403d`
and `7214e0fca27b8b63cb8f7dede43cf4a5e39adf9201c36c61d5b5f57a66cd770c`).
The reviewed source SHA-256 is
`06eaed93c7503ec06aadf56ad86ec1a59944c692dbdc4d4646d124622345f52b`.

This local admission is deliberately exact to the currently reviewed setup
release. Future circuit/profile releases need their own reviewed material;
individual supported certificates under this release do not.
