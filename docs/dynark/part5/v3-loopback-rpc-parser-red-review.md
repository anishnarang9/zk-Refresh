# V3 loopback RPC parser RED gate

The new private response parser contract covers a canonical JSON-RPC envelope,
bounded genesis and finalized account responses, four or eight ordered account
positions, role-specific byte limits, canonical base58/base64 encodings, context
slot floors and duplicate-key rejection. It returns raw records only; neither
decoder nor the public current-state constructor authorizes an application.

The [offline lock receipt](../../../results/dynark/part5/v3-rpc-parser-lock-bounded-001.json)
records exit 0 with the three pinned direct dependencies added to this crate.
The [focused bounded RED receipt](../../../results/dynark/part5/v3-rpc-parser-red-bounded-001.json)
records exit 101, one failed test and 17 filtered tests, with no resource cap or
residual owned process. The only failure is the intended comparison of
`Err(Unavailable)` to `Ok((100, 4))`. No HTTP transport is in this slice.

The GREEN parser must detect duplicate object keys before conversion to a
generic JSON value, which would discard duplicates. Full parser tests and
current-state regressions remain to run after implementation.
