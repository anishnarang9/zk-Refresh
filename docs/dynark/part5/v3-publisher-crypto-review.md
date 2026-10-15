# V3 publisher envelope crypto review

The private publisher-envelope checker now verifies the frozen typed Ed25519
preimage, exact signed-wire digest, source/scope/issuer/epoch coherence, active
status, freshness, and explicit predecessor claims. Its result is private and
cannot authorize an application action. The public legacy
`PublisherBinding::require_current(&CurrentHead, now)` route still returns
`Authentication` for every caller-provided record.

The frozen independent vector contains 28 genuinely signed cases: two coherent
claims and 26 negative cases. The bounded offline command reported exit 0,
no cap or runner error, no owned residual process, 4.867 seconds, 539,246,592
bytes sampled peak owned-tree RSS, and 2,427,515 bytes sampled logical target
growth. Its stdout records 12 passing library tests (seven new publisher tests
and five existing storage tests) plus six passing external publisher tests.
The public [receipt](../../../results/dynark/part5/v3-registry-publisher-crypto-green-bounded-001.json)
contains the measured limits and sampling caveats; private stdout/stderr remain
under `artifacts/dynark/part5/v3-registry-publisher-crypto-green-monitor-001`.

This is a crypto/coherence milestone. `CurrentHead` and the predecessor claim
are not authenticated finalized chain state. A configured finalized account
verifier, publisher-head commitment check, and restart provenance are still
required before the standard client may authorize with these envelopes.
