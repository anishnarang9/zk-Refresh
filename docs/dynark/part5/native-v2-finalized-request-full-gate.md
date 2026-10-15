# Exact finalized-request v2 Full proof gate

The native client produced one Full Groth16 proof for the already finalized
local v2 queue request. It used the pinned synthetic development credential,
holder signer, action preimage, current-root test snapshot, v2 R1CS/WASM and
the exact Original-reduction development package. The test checked the full
relation, verified the proof under the package's matching ordinary key, and
rejected five proofs with one altered public field each. The exported 416-byte
wire starts with the five exact public values in the finalized request plan.
An independent read of the plan and wire confirmed that byte match.

The private wire is
`artifacts/dynark/part5/native-v2-request-full-001-private/full.wire`,
SHA-256 `80f7ddf91e6f6de2dd4dfb405fafe10d89eaea5aab127ea89db79ccec0dc152d`.
The plan SHA-256 is
`783c1c8c9110e41e1cf3d1cd79d6bb10c07c79f81aa3d17774b60fb6f7bd4c4b`;
the action field is
`204adc0e5bc8095de0e3d5d768f1ca596267148fd3ca130c0290e5976015cdb0`.
The protected proof report records one positive ordinary verification and five
negative public substitutions. The output includes only synthetic test material
and remains owner-only; it is not a reusable production holder credential.

Under the reviewed 600-second, 4-GiB sampled workload RSS and 512-MiB storage
envelope, the external monitor recorded exit zero, no stop and no residual owned
process. The complete command, including its release build, took 133.975
seconds, reached 1,369,227,264 bytes sampled peak workload RSS, and grew
167,431,420 bytes of measured storage. The test's phase markers put package
decode at 31.461 seconds, package validation at 45.466 seconds, complete
witness/relation validation at 49.597 seconds, and Full proof completion at
52.144 seconds after the test started. The scrubbed bounded receipt is
`results/dynark/part5/native-v2-request-full-001-bounded.json`.

This is a native proof and exact-wire gate. The loaded Solana application has
not yet executed it; the local test snapshot is not a live issuer-status check.
The next gate must reuse the prepared validator ledger, submit this exact wire,
and verify finalized request/queue bytes, replay rejection and actual compute.
The supported population is still the single fixed v2 development fixture;
the six-field bounded v3 profile has separate qualification gates.
