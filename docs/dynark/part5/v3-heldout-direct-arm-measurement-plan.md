# Heldout direct B-arm measurement plan

## Design

Add an isolated pair supervisor and B-only worker without changing the frozen heldout case runner or any source it pins. For one existing `case-XX.json` manifest, run one complete Full-B arm and one complete Anchor-B arm serially under separate invocations of `results/dynark/part5/session_runner.py`. The pair supervisor chooses Full then Anchor for even variants and Anchor then Full for odd variants, and acquires the stable `.v3-heldout-heavy.lock` used by the heldout runbook.

Each arm creates a fresh private pair view and fresh case-run output root, then runs the existing B pipeline: prepare, stage, unrelated R0-to-R1 transition, R0/R1 source and witness preparation, the selected proof path (including ordinary verification), a fresh R1 ledger clone, and loaded branch Execute. The existing bounded child monitors remain in force. The outer session runner's monotonic wall duration is the arm duration; it includes the arm worker and owned-process cleanup. Its CPU values remain explicitly unqualified.

The pair report is accepted only if both arm receipts pin the same finalized request bytes, action hash, authenticated R0/R1 roots, circuit/setup/VK/ELF identities, and independently copied R1 ledger tree hash. A mismatch fails closed and yields no comparison. The R1 clones are separate destinations; neither application effect can consume the other's request.

## Accounting and limits

The direct arm duration replaces the current heldout B component sum as the primary wall comparison. The existing `analyze_v3_heldout_costs.py` adds separately timed prepare, stage, transition, source, proof, clone, and effect durations at `k=1`; it is attribution/accounting, not a timer around one continuous arm. The new arm timer starts before pair-view and request preparation and stops after owned processes are gone, so it includes work between nested jobs and monitor/report overhead inside the arm command.

The outer Full arm has a 6,000-second limit and the Anchor arm an 8,000-second limit, each above the sum of its existing nested child ceilings. Each outer arm has a 4 GiB RSS and 2 GiB private-root storage-growth cap. A stopped or censored arm yields no matched pair.

This path measures one unrelated root change for the exact B action. It starts from an already issued credential and excludes initial cohort issuance and enrollment; those are shared one-time costs reported separately. It does not establish the registered import-to-Execute complete-session result, `k>1` timing, an update-frequency model, qualified complete-tree CPU savings, retained private-cache size, or an implemented private proof-state serialization/reload cost. The ledger is persisted, cloned, and loaded for each branch as the current application path does. The existing workflow does not test expired-status or full-queue negatives. Any result must be labeled core-path heldout B-pipeline evidence with these limits.

## Implementation and verification

1. Add the pair supervisor, B-only arm worker, and pure validation helpers in a new Part 5 module.
2. Add focused source-only tests for order balancing, exact-action/root matching, clone independence/tree equality, and failed/censored outer reports.
3. Run only those focused tests and Python syntax checks. Do not run a case, proof, validator, build, or other heavy job in this implementation task.

After the selected freeze/cohort and case manifests are accepted, one pair can be invoked as:

```bash
python3 -B -m tools.part5.run_v3_heldout_direct_arm \
  --manifest "$RUN_MANIFESTS/case-$V.json" \
  --output-root "$PART5/v3-heldout-direct-arm-$RUN_ID-$V"
```

The command handles one variant. Run variants serially with fresh output roots to cover all eight credentials; even and odd variants balance the first mode across the cohort.
