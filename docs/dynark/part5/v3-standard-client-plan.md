# V3 standard client integration plan

The standard client must accept a previously unseen eligible DER certificate
without a source edit, certificate offset edit or individual setup. The current
v3 importer and coherent-record types are partial contracts; the retained
training corpus is a mathematical proof corpus, not a live signer or
authenticated registry session.

## Ordered boundaries

1. **Import:** structurally parse exact-profile DER, verify canonical
   re-encoding and issuer RSA signature, and derive signed AKI,
   organization/group policy, validity and holder modulus. Reject unsupported
   sizes, algorithms, encoding and extensions before witness work. The importer
   must not use a fixture-specific byte offset or issuer allowlist.
2. **Shared setup:** hash the frozen setup receipt, PK, R1CS, WASM, profile,
   semantic schema and raw ordinary VK before decoding; validate the public
   package once and compare its seven-IC ordinary projection to the measured
   tagged adapter identity. A private-constructor token represents only key
   identity, never issuer/status eligibility. Reuse this public material across
   certificates; keep witnesses and holder capabilities private per request.
3. **Authenticated state and request:** use a v3 registry tree and path. Its
   leaf domain is `2026101504`, whereas the existing development registry
   uses `20261015`; reusing the old path would produce the wrong root. A chain
   adapter must authenticate actual config/issuer/source/publisher/registry
   accounts, exact owners/PDAs/versions, current root and finalized immutable
   request. The builder receives the full action-v2 preimage fields, not a
   caller-supplied action digest. Sequence zero is unobserved; initialized
   root version zero is valid only when current and publisher-bound.
4. **Sign and witness:** reconstruct the canonical action-v2 hash from the
   request and ordered accounts. The holder signer signs its BE32 scalar
   encoding through SHA-256/RSA-PKCS#1 v1.5. Check the signer's public modulus
   against the imported holder key and verify the returned signature. Generate
   a complete 784,796-field witness, check every input binding, all R1CS rows
   and the six public values before Full proving. Reauthenticate the immutable
   state around signing and generation, then prove with fresh secure randomness
   and independently verify the ordinary proof.
5. **Submit and reconcile:** encode the 448-byte six-field/public-proof wire
   under the exact v3 adapter. The application Execute instruction adds its
   two-byte version/opcode prefix. Before submission, recheck current root,
   issuer/status and request. After submission, read exact request and queue
   effects at finalized commitment. An ambiguous outcome freezes automatic
   resubmission until reconciliation determines whether the nonce was consumed.
   A signature or confirmed transaction alone does not establish the effect.

## Required source slices

The client owner completes the focused Observe-sequence and tagged-key receipt
gates first. Separate modules then hold shared setup admission, exact
request/action construction, v3 witness/Full proof, and submission/reconciliation.
The v1/v2 five-field interfaces remain versioned. A v3 input worker and local
synthetic signer may be used for development evidence, but production signer
security remains a separate qualification.

The retained nine-pair training corpus discarded issuer/holder private keys and
uses synthetic signed action fields. It cannot sign a new finalized action-v2
request. A development end-to-end case needs a newly issued supported training
certificate with a retained protected signer. The held-out acceptance cohort
must be generated **after** implementation/artifact freeze, with fresh issuer
and holder keys and signers retained through Full, unrelated-root refresh and
own-revocation checks. A consumed Full request cannot serve as the unconsumed
refresh retry; use a separate finalized request and nonce.
