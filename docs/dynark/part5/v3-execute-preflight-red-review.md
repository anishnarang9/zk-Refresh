# V3 Execute preflight tests-first boundary

The non-authorizing program preflight contract checks the exact ordered
account plan `[config, issuer, publisher head, request, queue, extras...]`
against the immutable finalized request, six canonical public fields, the
current root/source/eligibility epochs, strict source expiry, action-v2 hash,
certificate validity, request deadline, queue capacity and replay state. Its
tests use real v3 PDA derivations and an independently assembled action-v2
preimage, but synthetic account state. The runtime Execute handler remains
`Unavailable` even when this structural preflight would pass. No proof or
queue mutation belongs to this slice.

The [focused bounded RED receipt](../../../results/dynark/part5/v3-preflight-red-bounded-001.json)
records one test reaching the intended assertion: `check` returned
`Err(Custom(799))` instead of `Ok(())`; seven other tests were filtered. The
run compiled and executed without a resource cap or runner error, left no
owned residual process, took 3.608 seconds and reached 180,174,848 bytes
sampled peak owned-tree RSS. Private stdout/stderr remain in
`artifacts/dynark/part5/v3-preflight-red-monitor-001`.

This preflight takes a supplied time only for structural tests. A later runtime
must obtain the authenticated onchain Clock itself and must also verify the
ordinary proof under the exact seven-IC VK before an atomic queue append and
request consumption. Loaded SBF, account rollback and proof compatibility
remain separate gates.
