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
