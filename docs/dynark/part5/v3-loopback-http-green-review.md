# V3 private loopback HTTP transport gate

The private transport now sends exact `getGenesisHash` and finalized
`getMultipleAccounts` requests to a canonical `127.0.0.1` endpoint. It uses
explicit monotone IDs, ordered keys and a minimum context slot, then delegates
response validation to the duplicate-aware bounded parser. Proxy, redirect,
retry and compression behavior is disabled; request, connection, total time
and streamed response size are bounded. The public current-state constructor
remains closed, so these raw RPC records grant no application authority.

The [bounded full-crate receipt](../../../results/dynark/part5/v3-http-green-full-bounded-001.json)
records 26 passed tests, exit 0, 10.820 seconds, 308,887,552 bytes sampled
peak owned-tree RSS, 6,333,810 bytes sampled storage growth, no cap and no
residual process. Local server tests include exact requests, endpoint and
proxy isolation, redirects/errors, timeouts and streamed overflow. Protected
logs remain under `artifacts/dynark/part5/v3-http-green-full-monitor-001/`.

A production verifier still needs separately trusted deployment pins and
authentication of the latest issuer observation and publisher envelope against
the finalized onchain head. This transport is not exposed as an authority
factory.
