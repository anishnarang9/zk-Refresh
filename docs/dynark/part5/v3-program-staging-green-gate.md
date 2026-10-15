# V3 request staging: host GREEN gate

The versioned runtime now creates a request PDA for an enabled enrolled
issuer and lets its creator upload bounded payload and ordered account
metadata. Finalize requires complete uploads, the request and queue as the
first two writable program-owned metas, unique keys and no config/issuer
collisions. It fixes the action bytes; later upload/finalize attempts reject.
Cancel retains the partial or finalized request as a nonce tombstone, including
after expiry or config disablement. Creation is preparatory and does not grant
issuer/status authorization. Execute still rejects as `Unavailable`.

The bounded host run passed all 48 tests across the v3 model (24), admin
runtime (7), signed status (6) and staging (11) targets in 4.961 seconds.
Sampled peak owned-tree RSS was 211,091,456 bytes and storage growth was
11,433,522 bytes. The run used one Cargo job, four Rayon workers, one test
thread and finite 180-second/1-GiB/256-MiB caps; it hit none and left no
owned process. Receipt: `results/dynark/part5/v3-staging-green-bounded-001.json`
(SHA-256 `675461375817a9f618d801d9ab9819260603dbae60fbd83ccc92660137a75a1e`).

Reviewed changed source identities:

| File | SHA-256 |
| --- | --- |
| `program/src/application_v3.rs` | `46d2c2b754f72494e81fcd032555a982f42fc11b1a1ec1bcc132631c0fff3c9c` |
| `program/src/application_runtime_v3.rs` | `d5f64041d9e3d7648201506a9c2dda08e47fd42e01347f4aa859c44730cd7794` |
| `program/tests/application_runtime_v3.rs` | `20dd7650bef21e79afd902674f1feb9df5895adcafd020ab3246efb007b4d733` |

The host CPI stub models fresh account creation. It does not establish actual
SBF allocation, transaction rollback, proof verification or atomic queue
consumption. Those require a loaded v3 ELF and integrated tests.
