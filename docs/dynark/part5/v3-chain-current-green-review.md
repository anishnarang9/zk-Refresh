# V3 finalized chain-current candidate gate

The private verifier now reads deployment and current application records in
one fresh ordered finalized batch. It rechecks genesis, loader/ELF, config,
Clock, issuer, publisher head, finalized request and queue under exact program
owners and PDAs. Current issuer observation, recorded epochs, root/source/head
binding, strict source expiry, request deadline, capacity and replay are
required before it constructs its private chain-current record.

The [focused receipt](../../../results/dynark/part5/v3-current-state-green-focused-001.json)
records one passing test (2.033 seconds, 192,675,840 bytes sampled peak
owned-tree RSS). The [full receipt](../../../results/dynark/part5/v3-current-state-green-full-001.json)
records 12/12 passing tests (0.632 seconds, 80,166,912 bytes sampled peak
owned-tree RSS). Neither run reached a resource cap or left an owned process.
Private logs remain under `artifacts/dynark/part5/`.

This record is a snapshot relative to separately trusted, publicly
constructible deployment pins. The public constructor still rejects because
there is no production RPC transport or trusted pin provenance. It does not
authenticate detached publisher/source envelopes, an active Merkle path,
extra relevant accounts, a holder proof or a later execution outcome.
