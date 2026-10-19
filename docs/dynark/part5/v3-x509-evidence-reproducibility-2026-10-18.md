# X.509 application evidence: public reproducibility index

This guide points to the verified Training-012 public matrix chain and gives the offline check for a future heldout public bundle. No heldout public bundle exists yet, so its publication path and SHA-256 remain pending. Training-025 case 00 now has a passing single-case CORE-PATH journal and fragment; case 01 is pending and cases 02–07 have not started. Training-021 is historical: case 00 was interrupted during its first Full proof after stage, transition, and source preparation. The proof step remained `running`, with no bounded proof monitor report or validated proof receipt; the outcome and elapsed proof work are unknown. No application effect or acceptance follows, and the same root is non-resumable. See the [Training-021 runbook](v3-heldout-training-021-runbook.md) for that execution record. Training-022 case 00 has **failed and is not accepted**; its frozen inputs and recovery record are in the [Training-022 runbook](v3-heldout-training-022-runbook.md).

Training-022 has a heldout freeze with SHA-256 `353c2e5cb7bb910277cb4c13b391894fd25e522c172cd80b4754daa8d2e24172`; its prior-key inventory records 162 public keys. The cohort issued eight certificates to eight holders across four issuers, and all eight case manifests validated. In case 00, the Full proof and fresh replay-proof steps passed, the loaded Full Execute report recorded an application effect, and the disabled-config negative report gate passed. The later ambiguous-restart step failed: the proxy dropped one response after one matching submission, restart identity was verified, but after 150 seconds no finalized signature or five-account reconciliation was present. The cloned-ledger `reopen-report.json` diagnostic found no signature/history and unchanged hashes for all five checked accounts at its diagnostic point. That means no effect was observed at that snapshot; it does not supply finality/reconciliation or acceptance. The case overall failed. No heldout cost result is available or claimed. The registered economics matrix remains Training-012; this failed attempt does not replace or extend its results. See the Training-022 runbook for frozen inputs, output paths, and recovery rules.

Training-023 then ran on a fresh freeze with SHA-256 `14c437186e50a97a7e9a77c645a0ccd5b13e433207ab848abf667e130c91b5d4`; its prior-key inventory recorded 174 public keys. The cohort issued eight certificates to eight holders across four issuers, and all eight manifests validated. Case 00 passed the Full proofs, loaded Full effect, and disabled-config negative. Its ambiguous-restart gate failed in 48.3 seconds with `ValueError: pinned finalized request and empty v3 queue required` during pre-stop reconciliation. The outer child exited 1 uncensored with zero remaining processes. No pre-restart finality receipt passed validation, no restart or case fragment was produced, and cases 01–07 were not run. No heldout acceptance or cost result is available. Preserve this failed root; do not resume or retry it.

After Training-023, commit `488ebd9` added the staged-config-public-key correction. Training-024 used a fresh freeze (`0705e86049b6e6f01f2e0a7c185e33ed0e92cfeb26289d08edfad2999dc56478`), an inventory of 186 prior keys, an eight-certificate/eight-holder cohort across four issuers, and eight manifests. Case 00 **failed** after 32 passed journal steps at `own_revocation:effect`: the supervisor omitted the R1 finalized-slot floor, queried at slot 54, and received the saved R0 config finalized at slot 45 instead of R1 finalized at slot 81. The Rust runner did not spawn; the journal's `FileNotFoundError` was secondary to the absent branch report. A separate bounded R1 replay diagnostic on a fresh clone passed and observed the loaded program and all five expected R1 account hashes at slot 81. It submitted no transaction and provides no effect, proof, acceptance, or cost result. Preserve the failed case and launch roots; cases 01–07 were not run. See the [Training-024 runbook](v3-heldout-training-024-runbook.md).

Training-025 is the current fresh attempt. Freeze SHA-256: `df4f6edec1bb69eddd9d85822270046ef9bfd4c1d403e07ec19869a9a9c09481`; prior-key inventory SHA-256: `40e36fb292e3a050d84f1633456604ed4c2ac75ae09173d46a115132973d9eb7` (198 keys); cohort receipt SHA-256: `8866bf1110e2fb0c1db84f6adfd9cd56a9598c07f7efdbb9d8f543aed3bc53c3`. The bounded cohort outer run passed and all eight manifests are present. Case 00 completed with owner exit code 0 and 35 passed journal steps. Its journal SHA-256 is `8466acfb2f771de77a6604d92862137d39b93e0d06e9e6f1ea268bd58260c774`; its variant-0 fragment SHA-256 is `93ccd87f3efd120a508f0154e5f02fe800b41a060bc92de39a1a5a0705383837`. The Full protected effect, unrelated-root Full and refreshed Anchor effects, own-revocation effect denial, R2 active-witness rejection, disabled-config gate, and ambiguous-restart gate passed. All 29 top-level bounded monitor reports referenced by the journal record zero remaining owned processes and known cleanup. This is a single-case CORE-PATH pass, not independent eight-case acceptance. Case 01 has launched and remains pending, with no completion fragment or owner exit code at this report snapshot. Cases 02–07 have no case roots or launch records. No eight-case acceptance, heldout cost result, or direct Full/Anchor economic result exists. See the [Training-025 runbook](v3-heldout-training-025-runbook.md). The journal, fragment, and owner exit-code receipts remain in ignored owner-only local artifacts; their digests are recorded above.

## Existing public matrix evidence

Training-012 is the registered 60-slot training matrix: four repetitions at each sampled update count `k = 0, 1, 2, 5, 10`, with 20 matched Full/Anchor pairs. Its public projection, 60 slot receipts and sequence receipt, metrics capsule, clock audit, report, and interpretation are available under [`results/dynark/part5`](../../../results/dynark/part5). The [interpretation](../../../results/dynark/part5/v3-training-012-interpretation.md) reports that semi-dynamic Anchor lost all 20 matched pairs (all paired Full-minus-Anchor differences were negative), the 20% total-savings target was not met at any sampled count, and strict-positive break-even was not observed through `k=10`.

The totals are component sums, not direct timings of complete application arms or a direct heldout total. No heldout cost result is established. Training-012 measures semi-dynamic Anchor and does not measure fully dynamic anchor rebuild and maintenance. Its metrics capsule SHA-256 is `4b3914d405202bb1e3b711ea88dd6fca627e721c620cea14816f2507e1c9f582`.

The offline commands below currently verify the public projection, receipt
chain, cross-bindings, clock audit, and capsule arithmetic. Their verifier
outputs mark each scoped check `verified`; they do not independently verify
withheld private session/effect truth or matched identity. The Training-012
component sums therefore remain distinct from direct whole-session arms.

From the repository root, verify the public matrix chain offline:

```bash
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
PROJECTION="$ROOT/results/dynark/part5/v3-training-012-public-projection-001"
RECEIPTS="$ROOT/results/dynark/part5/v3-training-012-public-receipts-001"
METRICS="$ROOT/results/dynark/part5/v3-training-012-public-metrics-001"
METRICS_SHA256=4b3914d405202bb1e3b711ea88dd6fca627e721c620cea14816f2507e1c9f582

test "$(cat "$METRICS/metrics.sha256")" = "$METRICS_SHA256"
python3 -B tools/part5/verify_v3_campaign_public_projection.py "$PROJECTION"
python3 -B tools/part5/verify_v3_campaign_public_receipts.py "$RECEIPTS"
python3 -B tools/part5/verify_v3_campaign_public_bundle_bindings.py "$PROJECTION" "$RECEIPTS"
python3 -B tools/part5/verify_v3_campaign_public_clock_audit.py "$METRICS/clock-audit.json"
python3 -B tools/part5/verify_v3_campaign_public_metrics.py \
  "$PROJECTION" "$RECEIPTS" "$METRICS/metrics.json" \
  --expected-sha256 "$METRICS_SHA256" \
  --clock-audit "$METRICS/clock-audit.json"
```

The expected capsule digest must come from a separately trusted publication or reviewed commit. The `metrics.sha256` sidecar is a consistency check, not an independent trust anchor. The [public release runbook](v3-training-012-public-release-runbook.md) explains each verifier's scope and the private-report limits.

## Current heldout status and next-attempt gates

Training-022's freeze, prior-key inventory, eight-certificate cohort, and eight
validated manifests exist. Case 00 is **failed, not accepted**. The journal and
outer/status evidence record passing Full and fresh replay proofs, a loaded
Full effect, and a passing disabled-config negative report gate, followed by
an ambiguous-restart timeout after 150 seconds. The proxy dropped one response
after one matching submission and restart identity was verified, but no
finalized signature or five-account reconciliation was present. The bounded
cloned-ledger reopen diagnostic found no signature/history and unchanged hashes
for the five checked accounts at that diagnostic point; this is a snapshot
observation, not a final reconciliation. Do not treat the passed substeps as a
case pass. No acceptance report or heldout cost report is available.

Preserve the failed Training-022 case 00 root and all reports/receipts,
including the journal, outer/status reports, proof receipts, disabled-negative
report, and `reopen-report.json`. Do not rerun it in place or claim
acceptance. Training-023 also failed and its root is not retryable. It used the
fresh freeze `14c437186e50a97a7e9a77c645a0ccd5b13e433207ab848abf667e130c91b5d4`,
an inventory of 174 prior public keys, an eight-certificate/eight-holder cohort
across four issuers, and eight validated manifests. Case 00 passed the Full
proofs, loaded Full effect, and disabled-config negative. Pre-stop reconciliation
then failed in 48.3 seconds with `ValueError: pinned finalized request and empty
v3 queue required`. The outer child exited 1 uncensored with zero remaining
processes. There is no validated pre-restart finality receipt, restart, or case
fragment, and cases 01–07 were not run. Preserve the root and reports unchanged.

Training-024 is a failed preserved attempt; case 00 failed at
`own_revocation:effect` after 32 passed steps because the supervisor omitted
the R1 finalized-slot floor. The separate bounded R1 replay diagnostic passed
and observed all five expected R1 account hashes at slot 81, but submitted no
transaction and established no application effect or acceptance. Training-025
is now the current attempt: its freeze and inventory identities, 198 prior keys,
cohort receipt, passed bounded cohort outer run, and eight manifests are
recorded above. Case 00 passed the single-case CORE-PATH gate with exit code 0, 35
passed steps, and the journal/fragment digests above. Case 01 is pending; cases 02–07
have not started. The Training-025 runbook revalidates the Training-012 receipt and accounting chain
read-only; do not rerun the matrix. Source hashes and preflight checks do not
establish heldout acceptance. Then:

1. Case 00 completed with owner exit code `0`, 35 passed journal steps, and a
   hash-pinned variant-0 fragment. Its journal-referenced monitor reports record
   zero remaining owned processes with cleanup status known. Preserve these
   receipts as the completed case record.
2. Case 01 has launched and is pending. Inspect its owner outcome, journal,
   receipts, and cleanup when it completes. Continue cases 02–07 serially only
   after case 01 passes; stop at the first failure and preserve failed roots.
3. Require eight complete journals and eight distinct fragments for variants
   0–7. Assemble with fragment digests, then require the independent acceptance
   verifier to pass before cost analysis.
4. Keep the outcome scoped to the verifier's implemented core path. The
   required eight loaded expired-status negatives and one loaded full-queue
   capacity negative are not measured or covered by the current assembler and
   verifier. A core-path pass is not full binding-plan acceptance.
5. Report the heldout cost analyzer's request-B component sums and conditional
   `k > 1` model separately. Neither is a directly timed complete Full/Anchor
   arm or a measured heldout break-even. An older one-off training engineering
   pair directly timed bounded sessions, but Full paid Anchor-only preflight;
   it cannot stand in for the registered fair arm comparison.

The [direct-arm measurement plan](v3-heldout-direct-arm-measurement-plan.md)
is a separate prospective matched-arm gate. Its timed segment excludes shared
preparation and transition costs, so it is not a complete application-session
total. Training-025 has eight manifests; case 00 passed its core-path gate, case 01
is pending, and cases 02–07 have not started. No direct-arm result is available or
established. Once the heldout case gate is complete, the plan calls for
serial matched arms across all eight credentials, with balanced mode order. Its
invocation for each variant is:

```bash
python3 -B -m tools.part5.run_v3_heldout_direct_arm \
  --manifest "$RUN_MANIFESTS/case-$V.json" \
  --output-root "$PART5/v3-heldout-direct-arm-$RUN_ID-$V"
```

Use a fresh output root for each variant and follow the plan's serial-run and
identity-matching requirements. No direct-arm result is currently available.

The current evidence counts are **0/8 loaded expired-status negatives** and
**0/1 loaded queue-capacity negative**. Source checks, fixture tests, or a
supplied-report validator do not count as loaded-program execution.

## Verify the heldout public bundle when published

If a **core-path-only** bundle is published, its summary must retain the
explicit missing-negative counts and must not claim full binding-plan
acceptance. Full-plan acceptance additionally requires those negative reports
to be integrated and independently verified. For either released four-file
bundle, obtain its absolute directory and the `SHA256SUMS` digest from a
separately trusted release record. Then run:

```bash
HELDOUT_PUBLIC_DIR="<absolute path to published bundle>"
EXPECTED_SHA256SUMS="<trusted SHA-256 of SHA256SUMS>"
python3 -B tools/part5/verify_v3_heldout_public.py \
  "$HELDOUT_PUBLIC_DIR" --expected-sha256sums "$EXPECTED_SHA256SUMS"
```

These are future release inputs, not current artifact identities. The verifier
requires exactly `index.json`, `summary.json`, `report.md`, and `SHA256SUMS`; it
checks the trusted digest, internal file hashes, allowlisted summary schema and
arithmetic, provenance-hash agreement, and that the report is rendered from the
summary. A core-path-only status must retain the missing loaded-negative counts
(`8` expired-status, `1` queue-capacity) until those categories are integrated
and independently verified. A successful offline bundle check verifies the
published schema and hashes, not loaded execution truth or private source
reports.

## Rerun prerequisites and resource limits

Use the [Training-022 runbook](v3-heldout-training-022-runbook.md), [Training-023 runbook](v3-heldout-training-023-runbook.md), and [Training-024 runbook](v3-heldout-training-024-runbook.md) as records of those failed attempts. Training-025 is the current attempt: it has a fresh freeze, 198-key inventory, cohort, and eight manifests; case 00 passed its core-path gate, case 01 is pending, and cases 02–07 have not started. The Training-025 runbook requires the complete Training-012 receipt, clock, economics, reconciliation, and total-cost chain to be revalidated read-only, along with the pinned Training-010 campaign freeze and identities, existing prepare status, adapter, proof executable, queue runner, and frozen sources.

The resource ceilings listed in the Training-025 runbook describe this attempt's plan and bounded children; they are not evidence of a successful case. Case 00 completed with exit code 0 and 35 passed steps; its 29 top-level journal-referenced bounded monitor reports show zero remaining owned processes with cleanup status known. Case 01 is pending. Wait for its owner to finish and verify cleanup before starting another case. Stop at the first failed gate. The case journal lock only coordinates the same output root; it is not a global execution lock.

The source-only v2 pin/preflight checks do not establish clean-checkout reproduction. The heldout procedure currently retains the existing Training-010 v1 setup and proof path; v2 compile/setup/package, a compatible application VK/ELF, and a clean-checkout heldout run remain separate gaps. See the [partial clean-checkout guide](v3-clean-checkout-reproduction.md) for the current evidence boundary.

## Claim boundary and private artifacts

The Training-012 public chain supports its stated training component-sum result and arithmetic. The future heldout bundle can support only the allowlisted heldout summary and its published provenance hashes. Source hashes bind reported inputs; they do not independently prove withheld session/effect truth, private matched identity, CPU savings, an economic winner, a directly timed whole-application benefit, full binding-plan acceptance, deployment, or production readiness. Keep credentials, keys, raw reports, configs, witnesses, proofs, and private ledger state in owner-only storage; publish only the reviewed projection and its trusted digest.
