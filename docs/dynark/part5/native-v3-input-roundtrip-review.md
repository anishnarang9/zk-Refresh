# Native v3 input worker real roundtrip

The ignored, exact-scope integration test generated fresh RSA issuer and
holder keys in memory and encoded two new X.509 credentials with the frozen
independent `cryptography.x509` fixture strategy. They have different issuer
keys, holder keys, actions and membership roots. The test constructed both
requests through the same pinned native `V3InputWorker`, accepted both private
candidate comparisons, and rejected a structurally valid request whose root
mathematically marks its own leaf revoked. Constructor, success and rejection
paths left the native worker directory empty. The temporary private fixture
directory was removed after the run; no DER, key, signature or witness is
committed.

The [bounded receipt](../../../results/dynark/part5/native-v3-input-roundtrip-bounded-001.json)
records one passed test, exit 0, 3.004 seconds, 244,105,216 bytes sampled peak
owned-tree RSS, 1,965,819 bytes sampled storage growth, no resource cap and no
residual owned process. Protected logs remain under
`artifacts/dynark/part5/native-v3-input-roundtrip-monitor-001/`.

This is an input-worker qualification, not an admitted credential, complete
WTNS/R1CS comparison, Full proof, Anchor refresh, authenticated chain state or
application effect. The worker's Python runtime is pinned to the local host;
portable runtime packaging remains open.
