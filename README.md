# zk-Refresh

Research prototypes for updating Groth16 proofs when a credential registry changes.

## Research boundary

- `crates/dynark-bn254/` contains BN254 proof-update and dynamic reconstruction research.
- `experiments/dynark/proof-probe/` contains the earlier feasibility probes.

The ongoing bounded X.509 authorization study, developed on a separate branch, evaluates the **semi-dynamic Anchor** path on a local Solana queue. Fully dynamic components have separate functional research, but a fully dynamic X.509 application and its economics have **not** been evaluated. This repository does not establish a production deployment, general X.509/PKIX support, protection after a holder signing key is stolen, or a net application-level performance benefit.

The early research code is retained for provenance and is separate from any later application integration. Its local study documents, run records, and generated artifacts are excluded from the current public tree. Historical Git commits still contain previously published records. The phase-1 profiling command reads two archived result files and requires those files to be restored locally before it can be rerun.

The potential benefit under study is the cost of updating a proof after a small authenticated registry change. Authorization freshness, revocation, action binding, and replay policy are application properties; a faster proof update does not replace them.
