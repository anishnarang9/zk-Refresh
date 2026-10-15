# Native v3 input candidate RED gate

The tests freeze a non-authorizing Rust boundary around the private Python
input worker. They require an exact fixed request/reply format, independently
reconstructed values for all 751 input scalars, exact summary and request
binding, canonical field encodings, and cancellation before file or process
work. The synthetic positive is deliberately not a valid credential. No
private certificate, key or witness is committed.

The [bounded RED receipt](../../../results/dynark/part5/native-v3-input-transport-red-bounded-001.json)
records the intended focused failure: response comparison returned
`Unsupported` after the test built its independent 751-field oracle. It
compiled and ran one test with 31 filtered; exit 101, no resource stop or
residual owned process, 2.418 seconds, 223,870,976 bytes sampled peak
owned-tree RSS and 1,131,752 bytes sampled target growth. Private diagnostics
remain under `artifacts/dynark/part5/native-v3-input-transport-red-monitor-001`.

The expected summary is caller-constructible in this slice. A later admitted
credential, exact action, authenticated state and complete-WTNS/R1CS gate must
provide authority before Full proof. This transport alone cannot authorize.
