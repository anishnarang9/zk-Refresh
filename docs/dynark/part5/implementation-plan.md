# Part 5 Credential Application Implementation Plan

> **For agentic workers:** Use the applicable implementation and verification skills for each owned task. Steps use checkbox syntax for tracking. ROOT reviews and commits each accepted small chunk.

**Goal:** Authorize one exact program-owned queue append with a reusable, bounded X.509 credential profile and prove the result under current authenticated Solana state.

**Architecture:** Preserve the legacy receipt and fixed v2 development circuit. Add a versioned queue program and native Full client, then a separate credential-profile successor that shares one public setup across eligible certificates. Keep issuer/status authorities, private identity/action state, and all artifact identities explicit.

**Tech Stack:** Rust, Solana program test/SBF, Circom 2.2.3, Python corpus tooling, BN254/Groth16 DYNARK engine and adapter.

---

## Current progress, October 15

The fixed-certificate v2 path has already appended and consumed one exact
request through a locally loaded application ELF under a Full proof; its
evidence is in `application-v2-local-full-execute-gate.md`. That is an
integration milestone for the fixture, not the supported population.

The bounded v3 profile, structural importer, eight-layout/independent-OpenSSL
relation corpus, shared development setup, nine-pair randomized Full proof
corpus and one independent OpenSSL Anchor pilot have separate gates. They
demonstrate a reusable public proof shape, but no v3 application authorization
or corpus-wide refresh economics. The v3 program has six-field state/parser
and administrator host tests, including signed inactive-status handling,
bounded request staging and a per-config/issuer/publisher head commitment.
Its read-only Execute preflight, canonical six-input ordinary VK, and direct
Full-proof component verification now pass host tests. Execute also checks
preflight and proof together and fails closed before an effect. The full program
host regression passes 111 tests. Publisher-head CPI, a request-bound Full proof,
the loaded v3 ELF and atomic queue effect still need local-validator evidence. The registry
verifies per-issuer source and private publisher-envelope signatures/claims;
caller-JSON authorization stays closed. A finalized chain-current checker
now validates one ordered account batch for deployment, issuer, head, request,
queue and Clock against supplied pins. Its bounded loopback JSON-RPC parser and
private HTTP transport pass 29 crate tests, including the zero-padded Solana
ProgramData allocation case. Its production RPC constructor remains closed.
These supplied pins do not constitute independent deployment authority. The
native client has DER admission, a shareable setup
loader, canonical action checks, a Full-envelope check and the pinned
751-coordinate compiler map. Its pure complete-input builder and private CLI
passed seven and twelve tests respectively. The Rust client now has a
private worker transport and independent 751-coordinate candidate comparison;
one genuine fresh-credential worker roundtrip passed. It still
does not import a complete WTNS or validate an R1CS in the standard client,
and its real Full witness/proof workflow still rejects. The frozen unseen credential cohort
has not been generated or run.

For the v3 successor, Execute requires **six** ordered public fields and the
matching seven-IC ordinary VK. Earlier v2 five-field steps below remain
historical baseline work and cannot qualify the v3 product objective.

---

## Track A: Versioned local Full application

### Task A1: Account and instruction contract

**Files:** `program/src/lib.rs`, new versioned module files under `program/src/`, `program/tests/`, `docs/dynark/part5/`.

- [ ] Write the exact account layouts, PDA seeds, authority roles, capacity limits, lifecycle and instruction encodings. Confirm canonical action-v2 byte order against `docs/dynark/pre-part5/component-contracts.md`.
- [ ] Write failing parser/state tests for wrong versions, lengths, owners, seeds, ordering, privileges, and bounds.
- [ ] Implement minimal additive parsers/state and run the focused program tests under ROOT's build grant.
- [ ] Review the diff, commit this bounded unit and push.

### Task A2: Finalized request and queue effect

**Files:** new request/queue module files under `program/src/`, `program/tests/`.

- [ ] Test creator authority, bounded staging/finalization, immutable request bytes, queue capacity, duplicate nonce, and exact ordered metas.
- [ ] Implement PDA request and queue accounts with one append effect and consumed status in the same transaction.
- [ ] Test failure rollback in the pinned local runtime; commit and push the unit.

### Task A3: Authenticated execution policy and exact proof

**Files:** new application policy/verifier modules under `program/src/`, `program/tests/`, matching versioned VK module only after digest review.

- [ ] Test root predecessor, separate status sequence, source/admin/publisher authority, stale status, issuer disablement, current-root only, validity and deadline.
- [ ] Test action-v2 reconstruction against independently encoded vectors and reject changed work, recipient, nonce, network, account order/flags, policy, circuit and malformed fields.
- [ ] Bind the matching v2 ordinary VK and five ordered public fields. Test Full proof success and altered public/proof failure in the actual loaded application ELF.
- [ ] Commit and push each verified policy, encoding and VK unit.

### Task A4: Native workflow and local integration

**Files:** `crates/dynark-native-client/` and focused tests; targeted `harness/src/` and `crates/credential-registry/` only after an ownership transfer.

- [ ] Test v2 Full witness import, exact package/schema binding, signer input, relation validation and fresh-randomness Full proof; reject v1-only worker assumptions.
- [ ] Test authenticated current Head, root supersession, own revocation, stale/disabled issuer, cancellation, restart rebuild and uncertain-confirmation reconciliation.
- [ ] Add a small native CLI or equivalent runnable entry point and execute a synthetic local-validator request through the actual program.
- [ ] Record actual queue account changes, compute units, transaction bytes, memory and per-stage wall times. Commit and push reviewed units.

## Track B: Generalizable credential profile

### Task B1: Profile and fixture-assumption inventory

**Files:** `docs/dynark/part5/supported-profile.md`, `docs/dynark/part5/fixture-assumption-inventory.md`; source read-only.

- [ ] Inventory fixed signed bytes, issuer/AKI, holder/subject, organization/group, offsets, witness mappings, setup and registry assumptions.
- [ ] Specify allowed certificate algorithms, sizes, DER encodings/lengths, extension set/order/variations, authorization fields and issuer enrollment. Distinguish profile restrictions from fixture constants.
- [ ] Review circuit-soundness and explicit reject reasons; commit and push the frozen profile.

### Task B2: Successor circuit and profile admission

**Files:** new `circuits/credential-<successor>/` and `tools/part5/` profile tooling/tests; preserve `circuits/credential-v2-dev/`.

- [ ] Write failing positive and negative admission tests before implementation. Include independently generated DER from a different generator.
- [ ] Implement bounded canonical DER parsing and automatic layout derivation, with exact signed authorization bytes constrained by the circuit and issuer-key public binding.
- [ ] Verify the corpus under one compiled R1CS. Pin source/profile/schema/shape identity and run a separate development setup once for the frozen successor.
- [ ] Commit and push profile parser, corpus, circuit, compile and setup-manifest units separately.

### Task B3: Per-credential proof and isolation qualification

**Files:** new focused tests and scrubbed `results/dynark/part5/` reports; no private keys or witnesses in Git.

- [ ] Test multiple holders, keys, serials, validity periods, enrolled issuers and each permitted encoding/extension variant with the same public package.
- [ ] Verify Full and Anchor-refreshed proofs independently, including unrelated and own revocation; keep incremental witness generation disabled until complete-witness equality, relation and proof checks pass for every exposed variation.
- [ ] Test cross-holder/cache/action binding and incompatible package/profile rejection.
- [ ] Commit and push reviewed tests and aggregate evidence, with setup and private cache material remaining ignored.

### Task B4: Frozen unseen-credential acceptance

**Files:** frozen manifest, scripted acceptance input boundary and scrubbed evidence under `docs/dynark/part5/` and `results/dynark/part5/`.

- [ ] Freeze source and public artifacts, record exact hashes, and then generate/import additional supported certificates without editing source or setup.
- [ ] Execute valid authorization, refreshed authorization after unrelated revocation, own-revocation rejection, and exact queue verification for each accepted certificate.
- [ ] Measure preparation, peak memory and complete refresh across multiple credentials with individual samples and conditions; charge failed/abandoned work.
- [ ] Review the gate, commit and push evidence. Do not call the profile product-ready unless all checks pass.

## Track C: Deployment preparation

### Task C1: Actual application build and devnet package

**Files:** `docs/dynark/part5/devnet-package.md`, scrubbed `results/dynark/part5/` build/validator evidence.

- [ ] Build the actual application ELF, compare loaded bytes, and pin source revision, ELF, circuit/profile/schema/package/VK identities separately.
- [ ] Record network genesis, program ID, payer, publisher/admin/status and upgrade authorities, fees, initialization steps, recovery and rollback.
- [ ] Run adversarial local-validator cases and reconcile queue/request state, compute and bytes; commit and push the reviewable package.
- [ ] Request explicit approval for the exact devnet package. Deploy and verify effect/state only after approval.

## Resource and review gates

ROOT serializes heavyweight builds/proofs, with four Rayon workers and one test thread. Each heavy run has a finite command, time/memory/storage boundary and a stop condition; no automatic retry after a cap failure. Workers own disjoint source paths, do not delegate, do not commit, and return changed files, exact results, hashes, risks and next gate. ROOT stages exact reviewed files and pushes each accepted commit to `codex/engine-focus-oct14`. Existing untracked/ignored baselines and historical evidence remain untouched.
