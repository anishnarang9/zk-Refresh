# V3 request fixture action boundary

A development exporter now accepts canonical `Config` and finalized `Request`
objects with six proposed public fields. It verifies their codec round trips,
PDA links, leading request/queue metas, current deadline, canonical field
encodings, validity range, and exact root/issuer/policy/action values. It
returns the encoded accounts, five derived addresses, and the action preimage
and hash computed by the application code.

The tests-first valid case failed at the fail-closed exporter scaffold with
`Unavailable`. After the narrow implementation, that case passed under the
bounded runner. The RED and GREEN receipts are
`results/dynark/part5/v3-request-export-red-001.json` and
`v3-request-export-green-001.json`. Their runs took 4.50 and 4.21 seconds;
the GREEN sampled peak owned-tree RSS was 154,042,368 bytes. Neither hit a cap.

The fixture uses a certificate-era clock and actual v3 PDA/action functions,
but its values are still synthetic. It provides no credential, real issuer
status, current chain state, proof or Solana effect. The example's CLI remains
unavailable. Fresh signer/credential preparation, a complete relation check,
one request-bound Full proof and a loaded-program positive Execute test are
separate gates.
