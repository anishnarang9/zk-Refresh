# V3 matched k=1 Anchor attempt excluded

The first frozen Anchor session reached a real R1 protected effect and replay
rejection, but did **not** satisfy the registered complete-pair acceptance
rule. Its outer monitor exited 2 after 1,283.388 seconds, with no resource
stop and no surviving owned process. The protected branch runner passed and
reported one effect. The Python supervisor then marked `branch_verified:false`
because it expected the success scenario `v3-valid-anchor`; the runner's
actual, correct scenario was `v3-valid-anchor-R1`. This is a report-validation
error after application work, not evidence of a failed proof or transaction.

Preserved receipts:

- Scrubbed outer receipt: `results/dynark/part5/v3-matched-k1-anchor-outer-001.json`, SHA-256 `ca7dc42e01c860e545acb4d4bd4e143998303c68fe55a8c13885454f1461b758`.
- Protected session report: `artifacts/dynark/part5/application-v3-matched-k1-anchor-session-001/session-report.json`, SHA-256 `8fde3a31e95f4060bdfca067dd8bc8858dae6498ebd9490c8961fd9f303ed1e3`.
- Protected proof report: `artifacts/dynark/part5/application-v3-matched-k1-anchor-session-001/proof/proof-report.json`, SHA-256 `4e6f2d55f5cd7914ba2669270654a7981ce54f3ebedbc673c06d3327c194e90b`.
- Protected branch report: `artifacts/dynark/part5/application-v3-matched-k1-anchor-effect-private-001/branch-report.json`, SHA-256 `73c0fc74fafc3099c148544a6961b9172f2a2ce49a37c5cf9359ca0e0aabd57b`.

The focused supervisor regression failed before the correction and passed
after it. Commit `1fcf73c` fixes only the exact success name. Both modes are
being rerun from fresh ledger clones under new freeze
`results/dynark/part5/v3-matched-k1-freeze-003.json`, SHA-256
`50e07d1cd0312a7bf41d609a7fedc5e2435e4120877cf14671f33cc8a2c1329d`.
The failed Anchor timing is excluded from matched savings and break-even.
