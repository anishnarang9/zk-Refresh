# Phase 2 interface contracts

October 10, 2026. These contracts precede implementation and constrain all workers. The engine is fixed-circuit BN254/Groth16 and generic over supported R1CS shapes; the credential adapter retains `[root, issuerHash, notBefore, notAfter, actionHash]`. No real credential parsing, witness incrementality or application execution is added.

## Public package and validation

Circuit identity binds R1CS content, witness executable, profile and public-schema hashes; curve, exact reduction, domain/root convention and format version. Shape uses separate `constraint_rows`, `assignment_len`, `instance_len` (including one), and padded `domain_size`. Setup identity binds canonical PK/VK content, not a path or user label. Metadata hashes identify supplied artifacts; they do not authenticate an arbitrary setup or prove that a caller's executable implements the declared R1CS.

The package owns one immutable PK, VK and matrix/index set, shared by references/Arc. Optional UK belongs to that exact package and must not embed a duplicate PK. Construction validates all dimensions, matrix indices, domain support, instance split, query lengths and identity consistency before proof arithmetic. Imported packages require a trusted expected manifest; matching hashes do not replace trustworthy setup provenance. Original and instance-A-augmented reductions have distinct identities even at equal N.

`ValidatedAssignment` is opaque: exactly the assignment count, canonical field encodings, coordinate zero equal to one, exact expected public values, exact package identity, and full satisfaction checked. T1 uses full satisfaction; an incremental policy needs a separately reviewed dependency argument. Full validation costs must be charged in later comparisons because E2 excluded repeated matrix-wide preflight. No arbitrary deserialization may bypass validation.

## Proof randomness and results

Every exported product proof path accepts caller cryptographic randomness with fallible entropy sampling. Draw independent unbiased field r/s using fallible byte acquisition and rejection sampling; prohibit silently mapping entropy failure to a seed, zero or panic. Deterministic common randomness is test-only. Internal unblinded components may exist for algebra/state computation, but are sensitive and never exported as an ordinary successful proof.

Return a complete proof, exact public statement and committed generation, or a typed error. Sample all required randomness before mutation. Work on staged state and commit only after all fallible validation/proving obligations succeed. Successful proof verification cannot certify entropy quality. Public APIs must not expose the known-bad constant-one wrapper or insecure vendor convenience methods.

## Transition and anchor

A transition names package/setup, credential/action, base and target generations and expected target public values. Use full assignment coordinates. Check bounds and prohibited constant-coordinate mutation before arithmetic; combine additive duplicates and delete field-zero sums. Require an exact transition from the named base, not just a plausible resulting public vector. Maintain separate touched-entry, touched-row and actual nonzero-row counts.

An immutable anchor binds assignment, row evaluations/projections, proof components/blinders and generation to circuit/setup/domain/credential/action. Success and failure leave all anchor components unchanged. Cross-action transitions cannot implicitly reuse an anchor without the explicit validated transition and supported binding policy; default new-action behavior invalidates private reuse and full-proves. Synthetic mathematical tests may exercise public action-coordinate changes without asserting application authorization.

## Dynamic state and scheduler

The active state owns complete projections for a named anchor, exact accumulated row differences from that anchor, and current raw proof/witness/public metadata. Rebuilding owns a frozen snapshot, unusable partial projections, phase/index progress, and separate exactly-once corrections after that snapshot. Never read partially rebuilt projections as active.

Cumulative accepted transition distance and net accumulated support are distinct counters. Cancellation cannot refund completed work. Budget zero is a no-op for maintenance; positive budgets must consume a bounded unit or report completion/error. No-op proof requests still obtain fresh randomizers. At a threshold use `>=`, never equality alone. Whole proof transitions are atomic; artificial intermediate invalid witnesses are not emitted. Overshoot is carried in accounting. An update above the supported correction/memory budget takes an explicitly charged validated full/rebase route. Reset both reconstruction generations consistently on fallback. The exact scheduler representation and unit bound need T5 review and tests before promotion.

A reconstruction swap installs complete projections, frozen anchor identity, corrections to the current witness, raw proof/public metadata and progress together. Advance current state exactly once even when completion and a new update coincide. Memory/work ceilings include both generations, pending corrections and scratch.

## Persistence and trust boundary

Public setup material stays separate from sensitive assignments, projections, blinders and raw proof state. T6 will use bounded versioned authenticated encryption, exact associated identity and lengths, unique nonces, restrictive modes and atomic durable file replacement. The caller supplies a protected secret-key provider; no real holder key is required. Confidentiality must come from encryption, not modes.

Rollback rejection requires a trusted expected generation/commit identity outside the attacker-replaceable store, or a fresh authority revalidation that forces rebuilding. A MAC, AEAD or monotonic counter in the same rolled-back file cannot prevent complete-store rollback. Crash recovery must return one complete committed generation or explicit rebuild; it may never infer freshness from a local file timestamp. Local invalidation hooks cover own revocation, issuer disable and action completion. Integrating OS key storage or a remote trusted-generation service is outside this engine phase; their required contract and limitations must be tested with synthetic providers.
