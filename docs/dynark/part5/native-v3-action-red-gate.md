# Native v3 canonical action: tests-first gate

The frozen vector defines the 394-byte action-v2 request preimage and its
canonical BE32 SHA-256 reduction into Fr. Account order, owners, privileges,
holder modulus, and expected action are separate checks in the same frozen
Rust test target. This boundary prepares an actionHash field; it does not prove
or authorize a request.

The exact fixed-vector test compiled and failed at the intended `Unsupported`
scaffold. One test failed, four were filtered, and bounded duration was 2.054
seconds. The monitor recorded no cap, runner error or residual process. Sampled
peak owned RSS was 219,152,384 bytes; positive storage growth was 1,289,399
bytes. Public receipt
`results/dynark/part5/native-v3-action-red-bounded-001.json` has SHA-256
`9da2915d51299724b2f0c2358215db948c3f74c1b2b37efac38ef6465a94d47c`.
The tests-first scaffold and proposed command are in
`docs/dynark/part5/native-v3-action-red-proposal.md`.

## Focused GREEN result

The implementation serializes the tagged action-v2 fields in the frozen order,
hashes the payload, reduces only the preimage SHA-256 digest into Fr, and
validates request bounds and canonical supplied policy/issuer fields. Before
signing, preparation checks ordered actual keys, owners and privileges,
request/queue associations, holder modulus match, deadline and expected action.
Owners are checked separately because action-v2 hashes meta keys and flags.

All five frozen Rust action tests passed in 1.399 bounded seconds, with no cap,
runner error or residual process. Sampled peak owned RSS was 155,664,384 bytes
and positive storage growth was 722,908 bytes. Public receipt
`results/dynark/part5/native-v3-action-green-bounded-001.json` has SHA-256
`d21e6cef9b82eed3971ae4b72832e544570107c70abd9190579752257751f599`;
reviewed source SHA-256 is
`ba99039b0332f3a449394b034f0a8ac35d0508b4ed59eda977e7118e1a025bcd`.
The result uses supplied request/account records and does not authenticate
their finalized chain state or perform application verification.
