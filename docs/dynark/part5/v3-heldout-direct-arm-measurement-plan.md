# Heldout direct B-arm measurement plan

## Design

Add an isolated pair supervisor and B-only worker without changing the frozen heldout case runner or any source it pins. For one existing `case-XX.json` manifest, the pair supervisor acquires the stable `.v3-heldout-heavy.lock` used by the heldout runbook and produces one shared pinned B context: pair view, prepare, stage, and the unrelated R0-to-R1 transition. Prepare, stage, and transition retain their existing bounded child owners. The supervisor measures and records the shared segment and each component separately.

Then run Full and Anchor serially under separate invocations of `results/dynark/part5/session_runner.py`. The pair supervisor chooses Full then Anchor for even variants and Anchor then Full for odd variants. Both workers consume the same pinned pair view, prepare result, staged ledger, and stopped R1 transition. Each timed worker independently prepares R0/R1 source and witness material, runs its selected proof path (including ordinary verification), clones that same stopped R1 ledger to a distinct destination, and performs loaded branch Execute. The existing bounded child monitors remain in force. The outer session runner's monotonic wall duration is the direct post-transition B segment duration; it includes the arm worker and owned-process cleanup. Its CPU values remain explicitly unqualified.

The pair report is accepted only if both arm receipts pin the same shared-context digest, stage and transition reports, finalized request bytes, action hash, authenticated R0/R1 roots, circuit/setup/VK/ELF identities, and independently copied R1 ledger tree hash. A mismatch fails closed and yields no comparison. The R1 clones are separate destinations; neither application effect can consume the other's request.

## Accounting and limits

The direct post-transition segment duration is the primary Full-versus-Anchor wall comparison. The shared pair-view, prepare, stage, and transition costs are reported separately and are excluded from both arm durations. The existing `analyze_v3_heldout_costs.py` adds separately timed prepare, stage, transition, source, proof, clone, and effect durations at `k=1`; it remains attribution/accounting, not a timer around one continuous arm. Each arm timer starts before its worker launches and stops after owned processes are gone, so it includes source preparation, proof, clone, effect, work between nested jobs, and monitor/report overhead inside the arm command.

The outer Full arm has a 6,000-second limit and the Anchor arm an 8,000-second limit, each above the sum of its existing nested child ceilings. Each outer arm has a 4 GiB RSS and 2 GiB private-root storage-growth cap. A stopped or censored arm yields no matched pair.

This path measures one unrelated root change for the exact B action. It shares pair-view construction, prepare, stage, and transition, then compares only the directly timed post-transition B segments. Initial cohort issuance and enrollment remain excluded from the direct segment comparison; their existing costs must be reported separately. This is not a complete import-to-Execute arm and does not establish the registered complete-session result, `k>1` timing, an update-frequency model, qualified complete-tree CPU savings, retained private-cache size, or an implemented private proof-state serialization/reload cost. The ledger is persisted, cloned independently from the same stopped R1 state, and loaded for each branch as the current application path does. The existing workflow does not test expired-status or full-queue negatives. Any result must be labeled direct post-transition heldout B-segment evidence with these limits.

## Implementation and verification

1. Add the pair supervisor, one-time shared B setup, B-only arm workers, and pure validation helpers in a new Part 5 module.
2. Add focused source-only tests for order balancing, shared-context/stage/transition identity, exact-action/root matching, clone independence/tree equality, and failed/censored outer reports.
3. Run only those focused Python tests. Do not run a case, proof, validator, build, syntax command, or other heavy job in this implementation task.

After the selected freeze/cohort and case manifests are accepted, one pair can be invoked as:

```bash
python3 -B -m tools.part5.run_v3_heldout_direct_arm \
  --manifest "$RUN_MANIFESTS/case-$V.json" \
  --output-root "$PART5/v3-heldout-direct-arm-$RUN_ID-$V"
```

The command handles one variant. Run variants serially with fresh output roots to cover all eight credentials; even and odd variants balance the first mode across the cohort.
