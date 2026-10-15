# Later-phase readiness: current-engine session rebind

Read-only source/metadata note. No execution, source/wrapper changes, setup, grants or future receipt identities. Credential runtime003 retains ROOT's queue. The accepted bindings are source003 (`4f2a5f9a…`), launcher005, normal003 (`cbb1696d…`), diagnostic004 (`d16b8135…`) and unchanged ledger007 (`2ea68dbf…`). All 224 remaining template job/group/envelope pairs match ledger007: 36 TRAIN, 180 HOLDOUT, 8 allocation diagnostics.

| Phase/template | Fixed scope and cap | Actual predecessor needed |
| --- | --- | --- |
| `session-train-006-proposal.json` | 24 forced + 12 selectors; 1800 s | Complete current-source audit-pilot paid ledger |
| `session-holdout-005-proposal.json` | 180 registered groups; 1800 s | Complete current-source TRAIN paid ledger and frozen fit outputs |
| `session-allocation-diagnostic-005-proposal.json` | 8 registered instrumented groups; 900 s | Complete current-source HOLDOUT paid ledger |

All retain 4 GiB sampled workload RSS, 192 MiB monitor planning allowance, 128 MiB total phase growth, 4 Rayon / 1 test / 8 process limits and existing side/core splits. No retries, cap changes or additional jobs are proposed.

## Enforced fit boundary and inputs

`session-launcher-source-005/launch_sessions.py:349` requires the exact forced schedule followed by the selector schedule. Line 373 calls `freeze_training` at zero-based index 24, before dispatching the first selector; line 392 injects that newly frozen policy. It fits only Full/Selective records from the completed 24 forced groups: `train-forced`, case`train`, samples 4. Anchor/Dynamic records are excluded.

The other inputs must be exactly the two registered audit-pilot cold10 Full and Selective provenance files: runner`group-005/provenance.json` and `group-008/provenance.json` under the actual accepted audit output. These paths are known from the nine-job ordering; their contents, sizes and hashes do not yet exist. `fit_role`(263), `fitted_records`(272) and `freeze_training`(289) require policy identity, passed group provenance, exact study/current source, Full/Selective mode, audit-pilot/cold/k10/samples1, matching group markers, positive runtime <= 300 seconds, literal passed primary report and identical primary/duplicate report hashes matching provenance, authenticated stdout and finite nonnegative timing. Only census/shadow-selector stage times enter pilot overhead. ROOT must bind the two distinct expected groups exactly; the role validator is per entry, not an exact-two cardinality check. No HOLDOUT/diagnostic input enters fitting. Cold10 also occurs in HOLDOUT and must not be called unseen.

Beyond diagnostic finite acceptance and audit completion, **actual paid TRAIN observations are a concrete prerequisite**. `tooling-source-001/fit_train.py:53-72` needs Full refreshes, qualifying one-coordinate/one-row Selective hits with zero entry attempts, Selective initial preparation, qualifying first-refresh two-entry cold cost, and both pilot overhead categories. Missing categories fail; an unprofitable valid fit may select Full default. No surrogate or prefilled policy can close this gate.

## Bindings that must wait

TRAIN must receive the actual audit `paid-phase.json` and those two provenance identities. From index 24, the launcher writes `train-policy.txt`(SESSION_TRAIN_POLICY_V3), `conditional-ledger.json` and `train-fit.json` beneath the chosen fresh TRAIN root. ROOT must inspect/freeze the actual policy digest, conditional model, fit result/sample counts and authenticated input lineage before HOLDOUT. Its Known/Unknown jobs need exact SESSION_POLICY/SESSION_POLICY_SHA256; policy/model/fit evidence must enter the frozen catalog. HOLDOUT checks the conditional ledger against `session_plan.model_ledger(policy)`; no fitting occurs there. Diagnostics consume diagnostic004, have no Known/Unknown jobs and do not use the old template's conditional-ledger field for dispatch or fitting.

Each later phase needs its immediately preceding actual cumulative ledger with matching study/source and complete registered phase chain, accepted full phase evidence/cleanup, fresh sibling output roots, exact catalog pins and a separate ROOT queue/admission/grant. Launcher005 permits aborted ledgers for conservative accounting; that alone is not acceptance of an incomplete predecessor. The original PREPARE source-migration exception is restricted to prepare→audit and must not be supplied again.

The existing templates can be minimally rebound after these artifacts exist: update source003/launcher005/supervisor006 closure, actual normal003 or diagnostic004 identity, original public-artifact pins, fresh output roots, actual predecessor/pilot/policy/model/fit identities and satisfied gate records. Preserve group order, all fourteen counters, caps, fitting scope and source/study checks. Their old source005/launcher004 bindings and unresolved/null policy/receipt fields are inert historical template data, never evidence. No additional source blocker was found in this bounded inspection.
