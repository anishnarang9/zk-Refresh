# V3 finalized deployment consistency gate

The deployment verifier now checks one ordered finalized four-account batch
against supplied genesis, program/programdata/config PDA, loader state and
upgrade authority, exact ELF length/hash, compiled v3 config identities, and
a recent Clock sysvar. It also checks the finalized context slot and the
separately obtained genesis response. Its public constructor remains closed;
only the module's scripted tests can construct its private transport.

The [bounded GREEN receipt](../../../results/dynark/part5/v3-current-green-001.json)
records 6/6 passing tests, 2.683 seconds, 244,940,800 bytes sampled peak
owned-tree RSS, 387,452 bytes sampled peak target growth, no resource stop, and
no residual owned process. Negative cases cover wrong identity, loader image,
account role/order, finality and clock age. Private test output remains under
`artifacts/dynark/part5/v3-current-green-001`.

This is consistency relative to caller-constructible deployment pins, not
authenticated configuration provenance. It does not yet use a production RPC
transport, validate signed issuer/source/publisher state, or mint an
authorization capability. The standard client remains closed at that boundary.
