# V3 loopback HTTP transport RED gate

The private transport contract accepts only a canonical
`http://127.0.0.1:PORT/` endpoint. Tests freeze two JSON-RPC POSTs with
explicit IDs, ordered keys, finalized commitment and a minimum context slot.
They also cover invalid endpoints, redirects, status/RPC errors, proxy
environment, timeouts, no retries and streamed body overflow. The transport
currently returns `Unavailable`; the public current-state constructor remains
closed.

The [offline lock receipt](../../../results/dynark/part5/v3-http-lock-bounded-001.json)
records exit 0 for the pinned blocking-only `reqwest` dependency. The
[focused bounded RED receipt](../../../results/dynark/part5/v3-http-red-bounded-001.json)
records the intended `Err(Unavailable)` versus a valid genesis hash, with one
failed test and 25 filtered tests. It exited 101 in 139.914 seconds after a
new offline dependency build, with 479,952,896 bytes sampled peak owned-tree
RSS, 161,209,494 bytes sampled storage growth, no cap and no residual process.
Protected compiler and test logs remain under
`artifacts/dynark/part5/v3-http-red-monitor-001/`.

The next step is the private bounded HTTP implementation and full local server
test. HTTP response parsing alone does not authenticate a remote node, current
publisher envelope, issuer status or deployment authority.
