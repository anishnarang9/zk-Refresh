# V3 training proof packet preflight

The first bounded packet invocation on October 15, 2026 exited before reading
credential data because invoking `prepare_proof_inputs_v1.py` by file path did
not put the repository package on Python's import path. No private packet was
created. Its failure receipt is
`results/dynark/part5/v3-proof-contexts-v1-bounded-001.json`, SHA-256
`c7e8bec16302312b5d224857cdd8de2ee5a68d6ea9258b23b749da4b5df1b1ab`.
The corrected invocation uses `python3 -B -m tools.part5.prepare_proof_inputs_v1`.

The second bounded preflight passed in 1.426 seconds with no cap stop or
residual owned process. It prepared nine training base/near pairs and selected
the independently OpenSSL-issued pair `credential_8` for the Anchor pilot.
The preparer verified accepted witness hashes, six public values, and all 751
input coordinates against the pinned compiler symbol map. It executed no
proofs. Sampled peak owned-tree RSS was 29,065,216 bytes; sampled positive
storage growth was 38,375 bytes.

The protected packet is
`artifacts/dynark/part5/v3-proof-contexts-v1-private/packet.json`, SHA-256
`46816fe620efbf080fd0f0d6f79e7165af31c2f3057b260767ca0e16891687eb`.
The protected symbol-input map SHA-256 is
`11753af6134ec956d8729681e94fa6c1e6b7ca6647c82f613b2c864b8a4943a7`.
The passing external receipt is
`results/dynark/part5/v3-proof-contexts-v1-bounded-002.json`, SHA-256
`a1d1a0eb0ccb8d732ff22f7fe687a35c6511910fe28e8ac0313d2cb99c20e9f6`.

These are retained training credentials with synthetic authority/action
metadata. The later frozen unseen-credential acceptance cohort remains pending.
