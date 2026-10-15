# Six-field Solana adapter focused gate

The separately typed `dynark_solana_adapter::v3` module implements the
six-public-field ordinary Groth16 wire boundary. It requires seven verifying
key IC points and 192 canonical public-input bytes, and retains the existing
256-byte proof point encoding. Its tagged ordinary-key digest uses domain
`dynark-solana-adapter/ordinary-vk/v2` with explicit six/seven counts. Circuit,
package, semantic schema, profile and ordinary-key digest are separate typed
identity fields supplied from a trusted manifest. The earlier five-field API
and its v1 digest domain remain in the crate.

The focused test first failed as intended with seven stub-boundary failures.
After implementation, all nine tests passed. They cover exact widths and
public order, independent coordinate-digest preimage, bad IC counts/points,
canonical field and point parsing, identity substitutions, and rejection of a
synthetic proof. The source SHA-256 was
`0148353f8ea06afa03df9e16aefd81e3cfe3e9049be6da20f923a4d8061bc816`;
the focused test SHA-256 was
`c8ca38a6bf9872a638aea1f1838a67e78787bc29cab7ce532e4a6892e9164956`.

The bounded GREEN command used offline locked Cargo, one build job and one
test thread. It finished in 2.992 seconds, reached 279,330,816 bytes sampled
peak workload RSS, added 1,544,879 bytes of measured target storage, exited
zero, and left no owned process. Limits were 180 seconds, 2 GiB sampled RSS
and 512 MiB positive storage growth. The scrubbed receipt is
`results/dynark/part5/v3-adapter-green-bounded-001.json`.

These tests use synthetic curve points and do not verify an actual v3
credential proof or loaded Solana program. A later gate must authenticate the
v3 development setup's ordinary key, encode real Full and refreshed proofs,
and exercise a versioned six-field application under that exact key.
