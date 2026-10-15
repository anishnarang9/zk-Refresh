# V3 bounded-credential application contract

October 15, 2026. This is the implementation contract for the successor to the
fixed v2 development-certificate application. The supported DER profile is
`credential-v3-bounded-der-v1` in `supported-profile.md`. All eligible
certificates in that profile use the same frozen six-field ordinary VK and
setup package. A new certificate changes private witness, holder signature,
membership and request state; it does not select or create a new key.

## Version and authority

Use a new `0x51` instruction prefix, `DYNCONF3`, `DYNISS03`, `DYNREQ03`, and
`DYNQUE03` account discriminators, and v3 PDA seed domains. Reject every
cross-version account/instruction combination. Preserve the canonical action
encoding tagged `DYNARK-WORK-REQUEST`, version 2; reconstruct it from the
immutable request and actual ordered relevant accounts. A fresh local program
identity and ELF will be measured separately. No v2 account or request is
silently migrated.

One config fixes one policyHash (the exact canonical BE32 `policy_id`), the
profile/circuit/schema/package and tagged ordinary VK identities, a trusted
network genesis, one current registry root/version and the policy authority.
It has one queue. It may enroll many issuers under that policy, each addressed
by `(config, issuerHash)` rather than a fixture issuer ID. Another signed
organization/group policy uses another config and queue under the **same** VK
and setup. Config and issuer enable controls are distinct.

An issuer enrollment binds its public `issuerHash`, signed AKI association,
status source key, enrollment version and evidence digest under administrator
authority. Admission tooling must verify the approved CA key/AKI/chain/purpose
before computing that digest. The onchain program enforces the administrator's
signed enrollment, not general PKIX parsing. Disabling either config or issuer
invalidates active bindings. Re-enabling requires a fresh authenticated status
observation and publisher bind; old observations cannot revive eligibility.
Each actual config enable-state change increments its eligibility epoch. Each
actual issuer enable-state change increments a separate issuer eligibility
epoch and clears that issuer's status validity. Observe and Bind instructions
carry both expected epochs in the signed transaction and reject a mismatch
before mutation. An accepted Observe records both epochs. Authorization and
Bind require those recorded epochs to match the current config and issuer;
the enrollment version remains evidence versioning and is never used as this
lifecycle fence. This rejects a transaction signed before disable even if it
lands after re-enable. Repeating the current enabled value changes no epoch;
epoch overflow rejects without mutation.
Every root publication invalidates bindings to the previous root. An Observe
for an issuer invalidates that issuer's old source binding. Source sequence
zero is unobserved, even if a zero-valued publisher field matches it.
An authenticated source observation can report `issuer_status_active=false`.
The exact 83-byte Observe wire carries a canonical signed active byte at
offset 66, after the digest. The program retains the signed sequence, digest
and times for an inactive observation as a negative fact while setting
`status_valid=false`; authorization and Bind reject it. A later active
observation must advance the sequence and still requires an explicit Bind.
The previous 82-byte wire is rejected. This host-tested repair does not
authenticate the upstream source envelope or enable Execute by itself.

## Publisher current-head provenance gate

The current `BindCurrent` account stores a root/source binding but no
publisher-envelope sequence or digest. An offchain signed publisher envelope
cannot establish that it is the latest committed envelope merely by matching
the root version or by presenting a caller-supplied previous-head JSON. Until
this gap is closed, the registry's public `require_current(CurrentHead, now)`
remains rejecting and v3 Execute is unavailable.

The reviewed tests-first application revision uses a per-config, per-issuer,
per-publisher head PDA with seeds `dyn-pubhead-v3`, config key, issuer key and
publisher key. Its exact 280-byte `DYNHEAD3` record stores those three keys,
publication sequence, envelope and predecessor digests, root/version, source
sequence/digest, both eligibility epochs and commit time. A version-1,
179-byte opcode-13 Bind instruction carries the expected and next publisher
sequence/digest plus the exact root/source/epoch context. The publisher-signed
transaction must compare the previous onchain sequence/digest, advance once,
and atomically store the new head while updating the issuer binding. It may
allocate an empty prefunded System-owned PDA. An existing malformed or
out-of-stream head must never be treated as a fresh one. New commitment
requires an active observation with `now < expires_at`.

The envelope digest is raw SHA-256 of
`"DYNARK-V3-PUBLISHER-WIRE-v1\0" || compact typed JSON(PublisherBinding)`, including
the signature bytes. The program stores this opaque digest under the signed
transaction; it does not verify detached JSON or Ed25519. The offchain verifier
must verify that envelope and compare its digest with the latest finalized
head account. Execute must verify this head; the older Bind path cannot bypass
it. Existing config and issuer account layouts remain unchanged. Opcode-13
host tests now pass; loaded-SBF CPI and rollback evidence remains pending.

A configured client verifier must read the current config, issuer and head
accounts at finalized commitment, verify owners, PDAs, codecs, program/network
pins, enabled/status state and clock, then compare the signed envelope and
source fact. It may claim the latest **finalized committed** envelope for that
issuer stream, not every unsubmitted offchain message or immediate real-world
revocation. A public trait implementation or parsed JSON alone is not that
verifier.

## Execute checks and effect

The proof wire contains six canonical public scalars in order
`[root, issuerHash, notBefore, notAfter, actionHash, policyHash]`, followed by
one canonical 256-byte ordinary proof. The VK has seven IC entries. The
program checks the fixed identities and enabled exact issuer/policy tuple,
the execution-current root, a fresh authenticated status observation and
current publisher binding, execution-time validity, the unexpired finalized
request, the reconstructed action-v2 hash, actual account keys/order/owner/
signer/writable privileges, and queue capacity before any write.

On success it appends the precisely bound work item to the program-owned queue
and consumes the request/nonce atomically. Every failure leaves those
application accounts unchanged. A root-only retry can generate a refreshed
proof for an unconsumed action, but a consumed request remains consumed even
with a newly randomized proof. Cancellation and expiry retain explicit states.

The status source and publisher authenticate assertions about issuer status
and current publication. They do not by themselves prove that an upstream
issuer published every real-world revocation promptly. A production issuer
enrollment, status feed and signer remain separate qualification gates.

## Implementation and acceptance order

The program owner first adds versioned account/parser/action tests, then
authority/current-state tests, then the six-field VK verifier and atomic queue
effect. The six-field verifier and a fail-closed Execute preflight pass host
tests; the atomic effect remains pending. The native client owner supplies the
supported DER importer, exact
request/action signer and proof/submission/reconciliation path. Each heavy
Cargo, SBF or validator run is separately bounded and serialized.

The local matrix must cover two enrolled issuers and varied holders/layouts,
unenrolled or disabled issuers, a mismatched signed policy, stale observation
or publisher binding, unrelated and own revocation, changed request/accounts,
malformed proof, queue capacity, replay and restart. An actual loaded v3 ELF
must verify the shared setup proof and exact finalized queue bytes. After
source/artifact freeze, fresh independently issued supported credentials must
pass Full authorization and unrelated-root refresh without source/setup edits,
and fail after own revocation. The latter frozen cohort is the product
acceptance gate, not the retained nine-pair training corpus.
