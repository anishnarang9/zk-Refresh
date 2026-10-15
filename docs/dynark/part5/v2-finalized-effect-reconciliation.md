# Exact finalized v2 queue effect

On October 15, 2026, a bounded consumed-only restart used the **original**
local validator ledger, the reviewed v2 ELF, the original Full proof wire and a
rebuilt host runner. It did not reset the ledger, reload the program, or submit
another Execute transaction. The prior Execute report and transaction journal
remained byte-for-byte unchanged at SHA-256
`78cef88f778ce0f71170dbf7ce6a069c1936cba63eb62501edaa37b9971ce3cb`
and `1618e42187e72e66a49b804beb9c7631844492ad63fb809d3d2bd3d44fee7e13`.

The startup barrier observed the exact four account bytes at both confirmed
and finalized commitment, each at context slot 48, with matching genesis and
loaded ELF. It selected `consumed` mode after 13 samples. The runner then
queried the request and queue directly at finalized commitment and returned
finalized slot 48. The consumed request SHA-256 was
`4c73b9203867f1d6268631d72fab00a9798a3ce41369cfccc2be675d3360d489`;
the one-entry queue SHA-256 was
`c07619bf42b78ff35b81ff07ad1f9e1649b409a34355b563465e805757b5b74f`.
The fresh report records one effect and zero new Execute transactions.

The external bounded invocation exited 0 in 1.675 seconds, with no cap stop
or residual owned process. Its sampled peak owned-tree RSS was 662,224,896
bytes, and sampled positive storage growth was 5,547 bytes. The validator was
reaped gracefully. The bounded receipt is
`results/dynark/part5/v2-finalized-reconciliation-bounded-001.json`, SHA-256
`5c04ebf79582069a32fce8fe08a764b90ae721e7b6938c122d8903fe54eddca2`.
The protected fresh report is
`artifacts/dynark/part5/application-v2-local-runtime-001/private/reconciled-report.json`,
SHA-256 `b5f8f58a8d9c5a0b40efd13980c193a029d298bc06bace6a986fc1e709309d05`.

This closes the specific finalized-byte evidence gap for the earlier fixed
development-certificate queue effect. It does not qualify upstream issuer
status, another credential, a refreshed Anchor proof, or the v3 application.
