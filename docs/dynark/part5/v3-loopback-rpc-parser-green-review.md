# V3 loopback RPC response parser gate

The private parser now accepts only bounded, complete JSON-RPC responses for
genesis or one ordered finalized four/eight-account batch. It rejects duplicate
object keys at every nesting level, wrong IDs, errors, unknown fields, invalid
context slots and account shapes. It bounds traversal and role-specific data
before decoding, and requires canonical base58 and padded base64. The output is
raw account data associated with requested keys by response index; it grants no
chain or application authority. No HTTP transport or production constructor
was opened in this slice.

The [bounded full-crate receipt](../../../results/dynark/part5/v3-rpc-parser-green-bounded-001.json)
records 19 passed tests, exit 0, 2.774 seconds, 275,922,944 bytes sampled
peak owned-tree RSS, 4,310,647 bytes sampled storage growth, no cap and no
residual owned process. This includes the previous current-state tests and
seven parser tests. Protected compiler/test logs remain under
`artifacts/dynark/part5/v3-rpc-parser-green-monitor-001/`.

The next boundary is a configured loopback transport that obtains the genesis
and both finalized batches without user-supplied account values. Separately
trusted deployment pins and current issuer/publisher authority are still
required before a production authorization capability can be exposed.
