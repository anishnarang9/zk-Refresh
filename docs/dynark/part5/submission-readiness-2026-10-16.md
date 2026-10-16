# Part 5 submission readiness — October 16, 2026

## What can be demonstrated now

| Boundary | Verified evidence | Current limit |
| --- | --- | --- |
| Supported credential population | `supported-profile.md` declares exact bounded X.509 DER/RSA, signed authorization fields, extensions and issuer enrollment. `v3-witness-qualification.md` records 18 positive complete relations across nine credentials and 34 rejected malformed or ineligible cases. | Development profile with test-only OIDs; no real issuer enrollment policy. |
| Shared proof material | `v3-full-corpus-gate.md` records 27 randomized Full proofs and 207 ordinary checks under one setup/VK across the nine training credentials. `v3-anchor-pilot-gate.md` records one valid unrelated-root Anchor refresh for an independently OpenSSL-issued credential. | Actions and eligibility context in these proof runs were synthetic; the eight-credential post-freeze acceptance cohort has not run. |
| Request construction | `v3-request-builder-green-evidence.md` records a Rust-staged finalized request, exact action/V3F1/V3F2 identities, 1 positive and 4 adversarial builder tests, and 4 exporter regression tests. | Public local fixture, not authenticated chain accounts. |
| Private input bridge | `v3-q1-bridge-green-evidence.md` records 7 new and 3 existing passing Python tests for a fresh supported credential, retained holder signature and active/unrelated membership path. | The test supplies a canonical action to the bridge; a finalized Rust request has not yet fed it. |
| Program and registry | `v3-private-queue-effect-gate.md` records 113 passing host program tests, including private queue effect mechanics. Chain-current parsing and a loopback transport have focused tests. | `Execute` still returns `Unavailable` after preflight/proof verification. No positive queue append under a request-bound proof, loaded v3 application ELF or production current-state authority. |

## Submission claim today

A report or prototype demonstration can present a **bounded credential circuit
and shared-proof-material research result with a partially integrated
application**. It can show varied credential admission, complete relation and
Full proof checks, the one Anchor correctness pilot, request/action encoding,
and fail-closed application scaffolding. The evidence does not establish a
working end-to-end credential application, general product readiness, a
deployed program, or measured multi-credential refresh economics. Complete
v3 witness generation remains required; incremental witness generation is
not exposed.

## Required gates for the complete Part 5 application

1. Feed a **Rust-derived finalized request action** into the retained holder
   signer and V3Q1 input worker, then verify the complete WTNS and exact
   request-bound Full proof under the shared package.
2. Bind the standard client to independently authenticated current config,
   issuer/status, registry head, clock, finalized request and holder capability.
   The current `V3BoundWitness::open_full` remains closed.
3. Pass ordinary adapter and program host verification for that same proof;
   connect the checked Execute path to the atomic queue append/consume effect.
   Test replay, changed action, wrong root, own revocation and failure rollback.
4. Build and load the actual v3 application ELF, verify artifact identities,
   and run the positive and adversarial local-validator path.
5. Freeze source, setup and ELF, then run `v3-heldout-acceptance-plan.md` on
   newly issued credentials without code changes or individual trusted setup.
   Measure complete preparation, refresh, memory and application costs across
   that cohort.
6. Prepare the concrete devnet deployment package. Deployment and devnet
   verification require review of its identities and authorities.

The branch containing the documented work is
`codex/engine-focus-oct14` on the configured GitHub remote. This document
is a status snapshot; the submission format and deadline determine which
evidence and demo artifacts should be packaged first.
