# Isolated v3 proof-runner RED gate

A new proof qualification package has a separate Cargo lock and target from
the frozen setup runner. Its initial source is a tests-first scaffold: it
contains no setup, Full proving or Anchor execution path. The local lock was
generated offline from the frozen package manifest; its SHA-256 is
`a3d0449b242fe6ac73f3c167d0a7f743457f7e420c428b37a25baed9302ddfcd`.
The lock differs from the accepted setup-runner lock only by the local package
name; registry versions and checksums stayed the same. The bounded lock
receipt records exit zero in 0.588 seconds, 79,708,160 bytes sampled peak RSS,
26,864 bytes positive storage growth and no residual process.

The exact named test
`tests::same_credential_action_root_only_refresh_is_admitted` then ran once
and failed at the deliberate unimplemented root-only context assertion. This
is the intended RED condition, not a compile or resource failure. Offline
locked Cargo took 44.057 seconds including its first build, reached
462,995,456 bytes sampled peak workload RSS, grew 172,670,059 bytes of target
storage, and left no residual process under limits of 180 seconds, 2 GiB RSS
and 512 MiB storage. The monitor returned exit 101 because the test failed.
Scrubbed bounded receipts are
`results/dynark/part5/v3-proof-runner-v1-lock-bounded-001.json` and
`results/dynark/part5/v3-proof-runner-v1-red-bounded-001.json`.

The next implementation must authenticate the one accepted setup and all
private input-to-witness bindings, prove all nine credential pairs with the
shared package, and separately qualify per-credential Anchor refresh. The
bounded runner proposal is in `tools/part5/PROOF-QUALIFICATION-PROPOSAL.md`.
Neither this RED gate nor the earlier complete-witness corpus establishes a
v3 Full or refreshed proof yet.
