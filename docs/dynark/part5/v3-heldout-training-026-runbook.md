# Heldout Training-026 fresh boundary

Training-025 is stopped after case 03 failed at the disabled-config finalization gate. Cases 00–02 passed individually, but case 03 has no acceptance fragment and cases 04–07 did not start. Preserve its partial output and all earlier attempts. This Training-026 root is a fresh post-freeze cohort boundary; it does not reuse a Training-025 ledger or credential.

## Observed preparation

The tracked branch was `codex/engine-focus-oct14` at `50b82c2` with a clean tracked worktree. No proof, validator, build, or heldout owner job was running. The accepted failed prepare-002 receipt still matched the current application source manifest at SHA-256 `0db58d4b9738a60895107c8fbf2c7aee2e45027ddd27b3a8fc460349832e6ae5`; it records no application effect and reviewed child cleanup. The isolated Training-010 proof executable matched SHA-256 `093659cec842945fd3db15e9e51087b5717d71dcb375fdf60ced58279a5ad19a`. Thirteen source and executable pins in the Training-025 runbook matched, and all five proposed Training-026 output paths were absent. The completed Training-012 evidence was revalidated read-only: 60 contiguous receipts, passing clock audit, economics, reconciliation, and 20 matched-pair total summary. No matrix job was relaunched.

The owner-only preissuance freeze was then created at `results/dynark/part5/v3-heldout-freeze-training-026`. It has exactly two mode-0600 files under a mode-0700 directory:

| File | SHA-256 |
| --- | --- |
| `freeze.json` | `d96643daff635d59234f7e9adf6356a18e437ff6e34e702e59a95d7b980c4283` |
| `prior-key-inventory.json` | `0504c0198989cf60671093bc1625a2a8a4f4850e5eb2a0db8b08888eaad4a782` |

The inventory cross-binds to the freeze, was observed before the freeze timestamp, and contains **210 distinct prior RSA public-key fingerprints**, including the keys from Training-025. The freeze pins the same Training-010 proof executable. No Training-026 keys or certificates have been issued, no manifests have been built, and no application case has started. These freeze files are local evidence, not a heldout acceptance or cost result.

The freeze invocation used repository paths resolved to an absolute output destination. An initial invocation with a relative output path was rejected before creating output; the CLI requires a fresh direct absolute results directory. This command records the observed invocation. For reproduction, choose a new output destination and first confirm that it does not exist:

```bash
ROOT="$(git rev-parse --show-toplevel)"
python3 -B "$ROOT/tools/part5/freeze_v3_heldout_cohort.py" \
  --prepare-status "$ROOT/artifacts/dynark/part5/application-v3-campaign-prepare-control-002/status.json" \
  --adapter-binary "$ROOT/crates/dynark-solana-adapter/target/debug/build/dynark-solana-adapter/3a4659842a713e9a/out/v3_request_bound_host-3a4659842a713e9a" \
  --proof-binary "$ROOT/artifacts/dynark/part5/v3-proof-runner-training-010" \
  --output-dir "$ROOT/results/dynark/part5/v3-heldout-freeze-training-026"
```

## Next gate

The host was on battery power, discharging, when the freeze completed. Before a new cohort or long case owner starts, verify AC power, an open lid, an active sleep-prevention assertion, absence of any other proof/validator/build job, and the fresh Training-026 output paths. Record power and sleep events throughout the run. A lid close during Training-025 case 03 coincided with a large wall/monotonic time discrepancy, although its causal relationship to the finalization deadline is unproven. Do not alter the 20-second finalization barrier on that evidence alone.

Once the host gate passes, issue the eight-credential cohort only through the bounded parent observer and the stable heavy-job lock, using new `training-026` private, monitor, and report paths. Require the 1,020-second outer limit, 4 GiB owned-tree RSS cap, 256 MiB storage-growth cap, clean owner exit, known cleanup, zero remaining owned processes, and exact freeze/inventory hash bindings. Then build and verify eight new manifests before any serial case launch. The [Training-024 runbook](v3-heldout-training-024-runbook.md) documents the cohort-owner command and resource bounds; replace every attempt-specific destination and owner with `training-026` and keep the historical roots intact. The [Training-025 runbook](v3-heldout-training-025-runbook.md) documents the current source pins and case-level checks.
