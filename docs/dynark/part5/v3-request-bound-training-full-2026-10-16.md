# V3 request-bound training Full proof, local qualification

This is one newly issued **training** credential, not a held-out credential or an
application authorization. The certificate and holder key remain in an ignored,
owner-only directory. The signed holder action came from the Rust-finalized v3
request plan; the pinned input worker received that exact V3Q1 request. The
fixture uses local synthetic Config, membership, program and genesis values.

## Pinned inputs and output checks

- Shared v3 package: `61d941890d823433468048dd1bd91da80c1bf7e1b3d2b6f5d509077a47ed06c8`.
- Setup manifest SHA-256: `d31f82e3f147e31b30074b3a570a9d7945c5e1f5d3f3dd74172801abbe984918`.
- Ordinary VK file SHA-256: `87edb4608c2140f3c7fddc8503e49b68931cda973711ce2c831bd44f1b98a875`.
- Private V3Q1 SHA-256: `4f13ab3614e2693e59872ccc2ea7c92b277e62682681ffebc686a39cddc045db`.
- Canonical input JSON SHA-256: `ba7397f1dee4eb8ef1a062c8c812d62776172a753a7bff8c5dbdd9c780a5113a`.
- Six ordered public fields JSON SHA-256: `a735f317efa8f69c724482f82d420223d4c02c7db3f623278af9fa0bb5ef45bc`.
- Complete 25,113,548-byte WTNS SHA-256: `31ae5bba5a7353a12a8d91f6bef70e79270111334b7edb014c03b0f296d5da6a`.
- 128-byte ordinary compressed proof SHA-256: `3abf6da3618bcdacc88ed239b14a6c205afa04a40d1a7176e3445b7515e5db07`.
- 192-byte six-field LE public encoding SHA-256: `c53bb9b61e14cba0ee80fe38b14ae0ffe8a663dee471a45f718b1a3c672d2cc4`.

The private input helper checked the certificate summary, all 751 worker input
scalars and the six fields against the finalized action. The pinned calculator
generated the WTNS. The independent streaming R1CS check accepted all 793,681
rows. The native `V3CheckedRelation` checked the complete assignment and used
fresh `OsRng` for a Full proof; its ordinary verifier accepted all six fields.
The proof bridge is compiled only for tests and has no authorization API.

## Bounded local runs

All three jobs exited zero without a resource stop or residual owned process.
The bounded runner sampled the owned process tree; these figures are individual
stage measurements, not a whole application session or Full-vs-DYNARK pair.

| Stage | Wall seconds | Sampled peak RSS bytes | Sampled storage growth bytes |
| --- | ---: | ---: | ---: |
| Complete witness | 3.587 | 351,322,112 | 25,124,542 |
| Independent R1CS preflight | 3.680 | 33,636,352 | 169,076,304 |
| Native setup load, complete relation, Full proof, ordinary verify | 57.497 | 1,095,057,408 | 2,345,733 |

The local private fixture and complete bounded receipts are at
`artifacts/dynark/part5/v3-request-bound-training-001/`. They are intentionally
ignored by Git. The proof has not yet passed the Solana adapter or host verifier;
`V3BoundWitness::open_full` and v3 Execute remain closed. No authenticated live
registry state, protected queue effect, refresh, own-revocation result, held-out
acceptance or net-benefit measurement follows from this qualification.
