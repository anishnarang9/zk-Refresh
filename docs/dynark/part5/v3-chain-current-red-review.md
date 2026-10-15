# V3 finalized chain-current RED gate

The new tests request deployment, config, issuer, publisher head, finalized
request, queue and Clock from one ordered finalized account batch. They require
exact owning-program codecs/PDAs, current issuer observation and both epochs,
strict source expiry, matching current head, request completeness, queue
capacity and replay checks. A positive synthetic fixture uses the same ordered
request/queue relevant metas as the program. The selected keys discover
accounts; they provide no authority.

The [bounded RED receipt](../../../results/dynark/part5/v3-current-state-red-001.json)
records the intended focused failure: `Err(Unavailable)` versus `Ok(100)`
after an exact finalized-batch request. It compiled and ran one test with 11
filtered; exit 101, no resource cap or residual owned process, 2.343 seconds,
211,795,968 bytes sampled peak owned-tree RSS and 614,806 bytes sampled target
growth. Private diagnostics remain in
`artifacts/dynark/part5/v3-current-state-red-001`.

This gate is for chain-current state relative to separately trusted deployment
pins. It does not verify detached source/publisher signatures, Merkle
membership, a holder proof or an application effect. Production transport and
the public constructor remain closed.
