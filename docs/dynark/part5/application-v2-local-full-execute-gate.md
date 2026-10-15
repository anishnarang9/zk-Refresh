# Local v2 Full application Execute gate

On October 15, 2026, the pinned `credential-v2-dev` Full proof exercised the
actual loaded local SBF application. The validator restarted from the original
prepared ledger without reset or program reload. The startup barrier observed
all four exact prepared accounts at both confirmed and finalized commitment,
each at context slot 9 after finalized preparation slot 8. It waited 12 RPC
samples before launching the runner.

The program bytes loaded through the BPF upgradeable loader matched the
186,984-byte reviewed ELF, SHA-256
`e20d0df801e49e211a5b791d2f1c284240568049656edf8991b7cc00dbe7e639`.
The bound synthetic source observation and separate publisher action succeeded.
Wrong action and malformed proof transactions failed with custom errors 512 and
514 while request and queue stayed prepared. The exact Full proof then appended
one request to the program-owned queue and consumed it atomically. A distinct
replay transaction failed with custom error 507; request and queue hashes
remained the expected consumed/one-entry values at confirmed commitment. The
runner waited until finalized slot 47, but this first success report did not
re-read the exact account bytes at finalized commitment. That additional
verification is a follow-up gate.

The valid Execute transaction was 760 bytes, used 144,445 compute units, paid
5,000 lamports and reached confirmed response in 503.416 ms in this one local
sample. The bounded complete Execute invocation, including validator restart,
synthetic Observe/Bind, two negative transactions, valid Execute, replay and
finalization, exited zero in 19.29 seconds. Its monitor sampled 586,563,584
bytes peak workload RSS and 32,369,047 bytes peak positive storage growth,
with no cap stop or residual owned process. These individual observations do
not establish a multi-credential speedup or devnet performance.

The independently checked report has six transactions: source observation,
publisher binding, wrong action, invalid proof, valid append and replay. The
public receipts are
`results/dynark/part5/application-v2-local-execute-report-001.json`,
`application-v2-local-execute-status-001.json`,
`application-v2-local-execute-readiness-001.json`, and
`v2-execute-retry-bounded-001.json`. They contain public local transaction
signatures and account hashes; private keys, witness and proof preparation
material remain under ignored protected artifacts.

An independent review identified the finalized-account evidence gap in the
normal success path. A separately reviewed code repair and read-only
reconciliation on the stopped original ledger are pending. The local proof and
confirmed queue effect are observed; this document does not yet claim exact
finalized account bytes.

The tests-first finalized-state regression compiled and ran two tests against
the old slot-only success helper. Both failed at the intended assertions:
divergent finalized request bytes were accepted, and the helper returned slot
100 before the exact account queries that would report slot 101. The bounded
RED receipt is `results/dynark/part5/v2-finalized-effect-red-bounded-001.json`;
it had no cap stop or residual owned process. No validator or transaction was
run in this regression.

This is a **Full-only local integration result for the fixed development
certificate**. The source observation is controlled and synthetic; it does not
show an upstream issuer check. This gate does not verify Anchor refresh through
the application, independently generated new credentials, production issuer
enrollment, a general v3 client, or any devnet effect.
