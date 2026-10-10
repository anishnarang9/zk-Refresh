# Phase 1 decision register

October 10, 2026. “Accepted” means established by the user's brief or a reversible engineering decision within it. A recommendation is not user approval. Questions left unanswered remain pending.

| ID | Decision / status | Rationale and evidence | Alternatives / effect |
|---|---|---|---|
| D01 | **Accepted by user:** DYNARK over BN254/Groth16; X.509/RSA first | Current brief and master roadmap supersede historical split-proof plan | Splitting remains an evaluation comparator, not primary implementation |
| D02 | **Accepted by user:** strict execution-current-root | Already-effective onchain revocation must exclude authorization; old mathematical validity is separate | No historical-root acceptance or delayed publication to improve success rates |
| D03 | **Accepted engineering boundary:** preserve original baseline; additive probes/docs only | Root Git absent; existing evidence must remain attributable | No root Git initialization, reorganization, circuit/fixture/key overwrite |
| D04 | **Accepted evidence rule:** ordinary full comparator must avoid unnecessary DYNARK cache construction | Old comparator includes cache; inspected matrix wrapper has constant-one mismatch | Use reviewed direct no-cache path with same setup/reduction and independent verifier. Keep old comparator clearly labeled |
| D05 | **Accepted bounded experiment:** one fresh development preparation, E1/E2/E3 | Historical UK/PK were not retained, so old cache cannot be reused with new keys. See [experiment limits](experiments.md) | No production ceremony/deployment; preserve matching new artifacts privately |
| D06 | **Accepted by user October 10:** native desktop local proving first; browser/mobile later | User selected the native-desktop recommendation in this chat; measurements still must qualify a supported device budget | Browser/mobile remain later qualification; no implied performance guarantee |
| D07 | **Accepted by user October 10:** controlled organization CA and narrow RSA profile | User selected the administrator-enrolled controlled-CA recommendation. See [product specification](product-spec.md) | Broad certificate chains are outside first product scope |
| D08 | **Accepted by user October 10:** permissioned work-request queue as pilot protected effect | Member authorizes one exact work request with replay prevention; network/program/registry/policy/action/recipient and complete effect arguments must be bound | Existing demo creates receipts only; queue integration and concrete request schema remain later work |
| D09 | **Accepted by user October 10:** pause authorization while authenticated issuer status is stale | Strict root currently has no feed-age bound. Authenticated no-change heartbeats may establish fresh source status; repeating a stale root alone cannot | User accepts the availability tradeoff; exact timeout and recovery service agreement require the pilot issuer |
| D10 | **Accepted by user October 10:** dedicated signed authorization fields | Signed organization/group identifiers and application authorization purpose establish eligibility. Narrow RSA-2048/e65537/SHA-256/PKCS#1 v1.5 and bounded DER remain the proposed concrete suite | Issuer-agreed OIDs, encodings, real corpus, signer capabilities and size limits must be qualified before circuit freeze; no real private corpus accessed |
| D11 | **Accepted gate:** no claim of complete paper conformance without full revised text | ePrint PDF/history HTTP403, browser challenge, author links same endpoint, publisher subscription preview | Full-text hash/theorem identifiers remain unavailable. Safe representation/import tasks can proceed; fast sparse/dynamic theorem-based work gated |
| D12 | **Accepted security gate:** exported fully dynamic test RNG is unusable for production | Code audit observes deterministic-feature build and separate `test_rng()` calls | Require caller CSPRNG/entropy handling before any production exposure, regardless of proof validity |
| D13 | **Accepted evidence boundary:** new setup ≠ original-zkey compatibility ≠ Solana execution | Different QAP conventions and encodings; ordinary verifier only tests exact VK/public statement | Existing-key mapping and local Solana tests have distinct task gates; deployment still requires approval |
| D14 | **Recommended default policy, informed by E2 measurements and derived session economics:** use ordinary full proving for short or unknown-reuse sessions | E2 measured5.417s full/3.587s anchored refresh medians but510.323s private preparation; ideal shared-public/no-I/O crossover271 repeated comparable refreshes. Actual action reuse must pay preparation; long credential lifetime is insufficient | Anchored/full-dynamic modes remain available after correctness gates, selected from total measured costs and future pilot workload evidence |

No external spending, publication, outreach, private real-key use, deployment, or production setup was approved by these decisions. The user's earlier deployment authorization recorded in the root historical HANDOFF does not override the present brief's explicit deployment-approval boundary.

## Resolution ownership

- D06–D10 are accepted by the user. The product/credential lead must qualify exact profile limits, issuer OIDs/encodings, request schema, device budget and freshness timeout; these are open parameters, not unanswered top-level product choices.
- D11: Astra paper lead; obtain legitimate full text and amend [research matrix](research-and-gaps.md).
- D12–D13: proof/security lead; independently reviewed tests plus derivation, not output verification alone.
- D14: performance lead; complete local timings and sessions with abandonment/eviction/reload, as specified in [baseline audit](baseline-audit.md).
