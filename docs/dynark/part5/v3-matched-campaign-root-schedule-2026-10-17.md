# V3 matched campaign root schedule

Registered before the multi-count campaign and before generating its credentials.
This extends the [matched method amendment](v3-matched-session-protocol-amendment-2026-10-17.md)
with one finite root sequence. The existing k=1 engineering pilot remains separate.

Use one admitted holder certificate at slot 0 and ten distinct, independently
issuer-signed unrelated certificates at slots 16 through 25. All eleven
certificates share one enrolled issuer; their signed TBS digests must be distinct.
The source's first signed observation contains exactly eleven `Issue` changes
with those digests, slots and nonzero allocation epochs. Replay them from the
empty bounded v3 tree and require the resulting root to equal finalized R0.
The first signed publisher envelope commits to R0 at root version 0.

At update j (1 through 10), revoke the certificate at slot 15+j. Each signed
source observation and signed publisher envelope must chain from its actual
predecessor. Independently rebuild the complete tree, require a distinct
finalized Rj root and version j, and retain the holder as active. The final
request and action stay unchanged and unconsumed until the one protected effect.
All modes receive the identical authenticated checkpoint sequence.

These leaves all sit inside the holder's level-4 sibling subtree (slots 16–31).
Consequently each cumulative R0-to-Rj holder path differs at exactly sibling
level 4. This retains the currently qualified single-sibling transition shape
while exercising ten genuine root changes. It is a controlled synthetic churn
pattern, not measured issuer/operator behavior or an arbitrary-tree claim.

For each registered k in 0, 1, 2, 5 and 10, use the prefix R0..Rk. The primary
Full mode proves and ordinary-verifies R0 and every later checkpoint. The
Anchor mode pays eager public/private preparation once at R0, then computes
each target delta from the immutable R0 assignment, refreshes and
ordinary-verifies at every checkpoint. The coalesced Full control authenticates
the same history but proves only the final Rk witness. At k=0, each primary
mode has one Full proof and Anchor still pays its eager preparation. Only the
final proof is submitted to a fresh clone of the matching pre-execution ledger.

No timing from this schedule enters the campaign until signed allocation
history, dynamic source/publication state, cumulative proof behavior, final
effect, fair Full accounting and all frozen identities pass focused gates.
