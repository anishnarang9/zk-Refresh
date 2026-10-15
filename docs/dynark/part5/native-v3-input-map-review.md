# V3 native compiler input map

The native client now admits only the exact compiler symbol artifact pinned by
SHA-256 `d2d66e238bdc0a731c86c1897c2978d23908dcc19460582cc873dc2d41e5dbf0`.
It reads and hashes one bounded file handle before parsing, rejects changed
identity/size or noncanonical rows, and requires 751 distinct noneliminated
coordinates including the six public coordinates in their declared order.
The `.sym` file is 227,653,284 bytes; it remains a local public build artifact.

The first GREEN attempt did not execute a test: the standalone test compilation
could not resolve `decode_digest` through its crate root. Replacing that runtime
decode with the exact 32-byte constant repaired this isolated import boundary.
The [failed compile receipt](../../../results/dynark/part5/native-v3-input-map-green-bounded-001.json)
had exit 101 with no cap or residual owned process.

The fresh bounded rerun passed all three tests in 11.127 seconds. Its
[receipt](../../../results/dynark/part5/native-v3-input-map-green-bounded-002.json)
records exit 0, no cap or runner error, no residual process, 270,057,472 bytes
sampled peak owned-tree RSS, and 867,962 bytes sampled logical target growth.
The command used one Cargo job, four Rayon workers, one test thread, a 180-second
runtime cap, a 1 GiB RSS cap, and a 256 MiB storage-growth cap. Private output
is under `artifacts/dynark/part5/native-v3-input-map-green-monitor-002`.

This map does not authenticate a credential, current state, signer, complete
witness, proof, or application authorization. The standard client `open_full`
path remains closed until those gates are connected and qualified.
