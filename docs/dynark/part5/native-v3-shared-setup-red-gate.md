# Native v3 shared setup: tests-first gate

The intended loader must admit the independently reviewed profile, R1CS,
ordinary VK, proving key, and setup manifest as one compatible public package.
Its source assertions are untrusted until checked against pinned release
identities. This is shared per circuit/profile; a new eligible certificate does
not need a new setup. The proposed loader and reviewed artifact hashes are in
`docs/dynark/part5/native-v3-shared-setup-red-proposal.md`.

The ignored positive test was invoked by exact name and scope, compiled, and
failed at the intended `Unsupported` scaffold. One test failed, 26 were
filtered, in 0.395 bounded seconds. The monitor recorded no cap, runner error
or residual process; sampled peak owned RSS was 524,288 bytes and positive
storage growth was 9,282 bytes. Public receipt
`results/dynark/part5/native-v3-shared-setup-red-bounded-001.json` has SHA-256
`d896efb631078c3964f7745a76f96a4594895f55e8d82917fa5df72ef1c90df8`.
No key was loaded or authenticated by this RED result.
