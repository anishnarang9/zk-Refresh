# Versioned v2 queue application contract

This is the five-public-input `credential-v2-dev` Full application path. It is
an additive `0x50` instruction family in `program/`; the earlier receipt
instructions and their verifier key retain their separate identity. This
contract includes the pre-first-ELF publisher-binding revision. It describes
an implemented host boundary, not a successful loaded-program or devnet authorization.

## Accounts and authorities

| Account | PDA seeds after the versioned literal | Bytes | Owner and role |
| --- | --- | ---: | --- |
| Config, `dyn-config-v2` | admin, 32-byte seed | 309 | Program-owned; admin sets the development network, policy, circuit, package and schema at initialization and may enable/disable policy. |
| Issuer, `dyn-issuer-v2` | config, issuerHash | 309 | Program-owned; admin enrolls a fixed v2 issuer/profile/AKI and may enable/disable it. A distinct source signer advances status observations. |
| Request, `dyn-request-v2` | config, creator, 32-byte nonce | 2,249 | Program-owned; creator stages and finalizes one immutable request, or cancels it. |
| Queue, `dyn-queue-v2` | config | 2,090 | Program-owned; publisher does not append directly. Successful authorization appends the request PDA once. |

The admin, root publisher and issuer-status source are distinct signers. Root
publication uses an exact predecessor `root_version`; status observation uses
an independent exact predecessor `sequence`, a new digest, a strictly newer
observed time, and an expiry bounded by the 300-second **development test
policy**. The source signs the Solana transaction targeting the issuer PDA.

The issuer account uses discriminator `DYNIS2B1`. Its original 229-byte
`DYNISS02` layout is rejected. After the original fields, the revision stores
`bound_root[32]`, `bound_root_version:u64_be`,
`bound_source_sequence:u64_be`, and `bound_source_digest[32]`.
`BindCurrent` requires the configured publisher signature, exact expected root
version and source sequence, and enabled fresh issuer status. It copies the
actual current root/version and source sequence/digest from authenticated
program state. Execution requires an exact match against those current values.
Every `Publish` increments the global root version, including a same-root
publication. Every `Observe` increments the independent source sequence. Either
therefore fences execution until the publisher rebinds the issuer. Unrelated
root publication requires rebind too; no historical binding is accepted.
Publisher binding attests incorporation or an authenticated no-change decision;
the source cannot perform this publisher step on its own.

The local harness's controlled synthetic source signs a new observation bound
to the independently read current config root, issuerHash, and pinned synthetic
public context. This authenticates the declared synthetic source's statement.
It is not evidence of an upstream issuer-status check, immediate real-world
revocation publication, or honest behavior by a compromised trusted authority.
The real upstream authenticated envelope remains a separate integration gate.

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
`8` Upload metas, `9` Cancel, `10` SetEnabled, or `11` BindCurrent. All wire integers are big
endian; the instruction parser rejects unknown opcodes, trailing bytes and
oversize chunks, while authorization rejects noncanonical field values.
Account codecs require exact magic, size and zero
unused allocation padding. `Execute` carries five 32-byte public scalars and
a 256-byte proof, and takes config, issuer, request, queue, then any extra
relevant accounts.

`BindCurrent` has exactly 18 instruction bytes: prefix `0x50`, opcode `11`,
expected root version `u64_be`, and expected source sequence `u64_be`. Its
accounts are publisher signer, config read-only, and issuer writable. Binding
is embedded in the issuer account, so the action-v2 preimage and Execute
account ordering remain unchanged. Canonical action bytes do not include root
or source versions, permitting a newly proven root-only retry for the same
finalized action.

## Proposed six-field successor boundary

This section is a design proposal; no v3 adapter or application key is admitted
by the v2 runtime. The successor must have a separate module, generated key,
account/instruction family and trusted manifest. Its six ordered public fields
are `[root, issuerHash, notBefore, notAfter, actionHash, policyHash]`.

One v3 config pins exactly one signed policyHash. Its action-v2 `policy_id` is
the canonical 32-byte big-endian policyHash field, with the declared policy
version. Varied policy hashes use separate configs under the same circuit and
public setup. Administrator-enabled issuer/policy permit accounts authorize
only the exact `(issuerHash, policyHash, profile, circuit)` tuple. The program
must check the sixth public field against this immutable config policy and the
permit, in addition to enabled issuer, current root, fresh authenticated source,
exact publisher binding, execution-time validity and reconstructed action.

A six-field adapter must require seven VK IC points and exactly 192 public
input bytes, preserve the 256-byte proof point ABI, and reject all five-field
keys and statements. Its ordinary VK commitment uses a separate versioned tag
and six/seven count prefix. Engine extended-VK digest, tagged ordinary-VK
digest, raw key file hash, profile, semantic schema, circuit/package and actual
application ELF hash remain separately named and pinned. Existing five-field
adapter/key identities and v2 queue accounts are preserved. No implicit account,
request, proof or cache migration is authorized by this proposal.

## Local harness and persistent-ledger proposal

The focused `harness/tests/queue_v2.rs` prepare/execute tests remain ignored in
ordinary host tests. Preparation must load the reviewed actual application
ELF, verify its RPC bytes and configured local genesis, stage and finalize the
request, compare its entire account bytes with an independent encoding, and
export the exact action before signing/proving. Execute refreshes a controlled
synthetic source observation and then obtains a distinct publisher BindCurrent
attestation before authorization. It verifies the exact resulting request and
queue bytes and rejects a distinct replay. Both successful phases wait for the
last observed transaction slot to reach finalized commitment before reporting
success. Already-consumed reconciliation checks the exact request/queue again
at finalized commitment and sends no new Execute; an existing reconciliation
report does not prevent another successful read-only reconciliation.

`harness/tests/queue_v2_supervisor.py` is a reviewed-proposal child launcher for
separate build, prepare and execute invocations under ROOT's external bounded
monitor. Initial preparation requires an absent protected ledger and is the
only path that may use `--reset` and genesis `--bpf-program` loading. Execution
requires the same persisted genesis, ELF, public context and finalized prepare
report and never resets or reloads genesis. It uses the separate deterministic
local public program ID `FPixV9CAxXGFiHH6udUhyTPUzposTYEf1uxmQxYc8xha`, not an
existing deployment key. The launcher validates pinned sources and binaries,
restricts output to ignored protected Part 5 artifacts, and keeps synthetic
application keys private. It must not run without a fresh bounded ROOT grant.
Direct-child cleanup is not a claim of complete process-tree cleanup; the
external monitor supplies the independent whole-tree receipt. A forced stop or
failed runtime marks ledger reuse as requiring review, preserving partial work.

The proposed SBF stop is 180 seconds, 4 GiB sampled workload RSS and 512 MiB
positive storage growth. Each local validator/runner phase proposes 180 seconds,
4 GiB combined sampled RSS and 256 MiB positive storage growth, including a
20-second readiness and bounded runner deadline. These are finite feasibility
bounds, not observed application measurements or automatic retry allowances.
