# Versioned v2 queue application contract

This is the five-public-input `credential-v2-dev` Full application path. It is
an additive `0x50` instruction family in `program/`; the earlier receipt
instructions and their verifier key retain their separate identity. This
contract describes the implemented host boundary as of `c6d4808`, not a
successful loaded-program or devnet authorization.

## Accounts and authorities

| Account | PDA seeds after the versioned literal | Bytes | Owner and role |
| --- | --- | ---: | --- |
| Config, `dyn-config-v2` | admin, 32-byte seed | 309 | Program-owned; admin sets the development network, policy, circuit, package and schema at initialization and may enable/disable policy. |
| Issuer, `dyn-issuer-v2` | config, issuerHash | 229 | Program-owned; admin enrolls a fixed v2 issuer/profile/AKI and may enable/disable it. A distinct source signer advances status observations. |
| Request, `dyn-request-v2` | config, creator, 32-byte nonce | 2,249 | Program-owned; creator stages and finalizes one immutable request, or cancels it. |
| Queue, `dyn-queue-v2` | config | 2,090 | Program-owned; publisher does not append directly. Successful authorization appends the request PDA once. |

The admin, root publisher and issuer-status source are distinct signers. Root
publication uses an exact predecessor `root_version`; status observation uses
an independent exact predecessor `sequence`, a new digest, a strictly newer
observed time, and an expiry bounded by the 300-second **development test
policy**. The source signs the Solana transaction targeting the issuer PDA.
The onchain program does not validate an upstream X.509 CA chain or prove that
the source saw every real-world revocation. Enrollment must establish the
fixed v2 CA/AKI association outside the relation. The application demands the
root currently stored in the program configuration at execution.

## Request and effect

The single supported `request_type` is `1`: append the finalized request PDA
to the queue. The queue capacity is 64 entries. Each request has at most 1,024
payload bytes and 16 ordered relevant account metas. Its first two relevant
metas are the writable request and queue PDAs; additional metas must have
their exact declared keys, order, owner and signer/writable flags when the
program executes. Payload and metas upload in contiguous chunks of at most
512 bytes and four metas. Finalization locks the bytes before holder signing.
Cancellation retains a tombstone; a completed append changes the request to
`Consumed`. Deadline expiry is derived from the immutable signed deadline.

The program reconstructs the exact canonical action-v2 preimage from the
stored request, configured genesis/policy/circuit, its own program ID and the
actual relevant accounts. It checks the five public fields in order:
`[root, issuerHash, notBefore, notAfter, actionHash]`. It also checks current
root, enabled fixed v2 profile/package/schema, fresh issuer status, certificate
validity at the runtime clock, and the deadline before pairing. The installed
key is the matching v2 ordinary Groth16 key. Queue append and request
consumption are writes in one Solana instruction; a failed transaction must
leave application state unchanged. Transaction fees and durable nonce behavior
are separate runtime concerns.

No account count or payload cap alone proves a transaction fits the 1,232-byte
packet limit. The actual loaded program, full proof, compute budget, packet
size, positive queue effect, failure rollback and concurrent replay still need
local validator evidence. Host tests alone do not establish them. This v2
program cannot verify the six-field bounded v3 successor, including its
`policyHash`, under the v2 key.

## Instruction family

After prefix `0x50`, the opcode is `0` Initialize, `1` Enroll, `2` Publish,
`3` Observe, `4` Create, `5` Finalize, `6` Upload payload, `7` Execute,
`8` Upload metas, `9` Cancel, or `10` SetEnabled. All wire integers are big
endian; the instruction parser rejects unknown opcodes, trailing bytes and
oversize chunks, while authorization rejects noncanonical field values.
Account codecs require exact magic, size and zero
unused allocation padding. `Execute` carries five 32-byte public scalars and
a 256-byte proof, and takes config, issuer, request, queue, then any extra
relevant accounts.
