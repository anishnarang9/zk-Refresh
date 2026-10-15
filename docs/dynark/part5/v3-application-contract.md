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
Every root publication invalidates bindings to the previous root. An Observe
for an issuer invalidates that issuer's old source binding. Source sequence
zero is unobserved, even if a zero-valued publisher field matches it.

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
effect. The native client owner supplies the supported DER importer, exact
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
