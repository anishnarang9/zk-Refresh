# V3 registry authenticated source: tests-first gate

The new protocol record separates two enrolled issuers with distinct Ed25519
source keys and sequence heads. Its signed scope includes the config and issuer
eligibility epochs plus a separate enrollment evidence version. The public
fixture has two positive observations and 25 independently re-signed negative
observations. The source preimage is typed compact JSON under the v3 status
domain; the test compares its exact bytes and verifies the positive signature
with OpenSSL before calling the registry verifier.

The exact positive compiled and failed at the intended `Authentication` stub:
one failure, five filtered, 32.338 bounded seconds. The monitor recorded no cap,
runner error or residual process. Sampled peak owned RSS was 512,540,672 bytes
and positive build storage growth was 151,711,164 bytes. The public receipt
`results/dynark/part5/v3-registry-protocol-red-bounded-001.json` has SHA-256
`98e066b23f91322e72685d7aa34d5cfdd75977639b5c8394c2fe50b238056814`.
The source proposal, exact source hashes and independent fixture checks are in
`tools/part5/REGISTRY-V3-PROTOCOL-RED-PROPOSAL.md`.

Publisher/current-head admission remains deliberately unavailable. The source
signature alone cannot enroll an issuer, choose its own policy or prove the
latest chain state.

## Focused GREEN result

The source verifier now checks exact independently supplied enrollment and
scope, both eligibility epochs, fixed tree domain/depth, canonical field
words, bounded typed signing bytes, the enrolled Ed25519 key, per-issuer
sequence/predecessor and the 300-second development freshness ceiling. It
returns an opaque checked observation and derived head. A signed inactive
issuer status is retained as a negative fact; it cannot carry an Issue change
or grant authorization.

All six frozen protocol tests passed in 3.040 bounded seconds, including 25
genuinely re-signed out-of-scope negatives and the still closed publisher
boundary. The monitor recorded no cap, runner error or residual process;
sampled peak owned RSS was 546,029,568 bytes and positive storage growth was
1,463,633 bytes. Public receipt
`results/dynark/part5/v3-registry-source-green-bounded-001.json` has SHA-256
`475e542f49471f1710c9e219374abefe02cedd7df96265d485acc39166a73f03`;
reviewed source SHA-256 is
`ebdb8f06d2e266608d2057bb4bd709ac5545c87c5978ad77c905c964308be5ad`.

Raw-wire decoding, actual enrollment/clock account authentication, publisher
signature and current-head reconciliation remain separate gates.
