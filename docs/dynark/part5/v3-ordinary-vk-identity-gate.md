# Actual bounded-v3 ordinary verifier-key identity

The frozen development setup's 456-byte ordinary VK was parsed with canonical
subgroup checks, full input consumption and exact reserialization. The key has
seven IC entries for the six ordered publics
`[root, issuerHash, notBefore, notAfter, actionHash, policyHash]`. An allocation
guard rejected other compressed vector counts before key deserialization. The
adapter's versioned tag and an independently constructed canonical preimage
agreed on tagged ordinary-VK digest
`2f9b770ff51ac399619a3127ddb32efad67697402f10c4549441a3578e4f9a4e`.

This value is distinct from raw ordinary VK file SHA-256
`87edb4608c2140f3c7fddc8503e49b68931cda973711ce2c831bd44f1b98a875`
and engine extended-VK digest
`2611d58c8c8d0b0c1f2c3f0facc4516e5c08e1fb3a7f14b16e32b948bc8f3c70`.
The pinned setup manifest SHA-256 is
`d31f82e3f147e31b30074b3a570a9d7945c5e1f5d3f3dd74172801abbe984918`.
No setup or proof was generated in this identity gate.

Both focused tests passed in the bounded command. The monitor exited zero in
about 2 seconds, sampled 209,043,456 bytes peak workload RSS and 3,432,353
bytes peak positive target growth, with no cap stop or residual owned process.
The exact identity receipt is
`results/dynark/part5/v3-ordinary-vk-identity-001.json` (SHA-256
`6a6fd9d207c778b085f56de3327ec15ccee886ab127de1e90e970da039fef429`),
with monitor receipt `v3-vk-identity-bounded-001.json`. The receipt labels
`profile_admitted=false` and `proof_verified=false`; actual v3 Full/Anchor and
application verification remain separate gates.
