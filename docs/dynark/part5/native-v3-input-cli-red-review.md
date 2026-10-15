# V3 private complete-input CLI RED gate

The frozen CLI tests exercise private request and response files, exact output
equivalence to the pure builder, directory and file ownership/modes, exclusive
creation, no-follow opens, same-handle metadata checks, and deterministic file
replacement/change races. The test corpus is independently signed in memory;
the private DER and keys are not committed. These tests do not establish chain
authority or proof validity.

The [bounded RED receipt](../../../results/dynark/part5/native-v3-input-cli-red-bounded-001.json)
records the focused fresh-output test failing at the intended closed CLI
boundary: actual exit 3 versus required exit 0. It ended without a resource
cap, runner error, or residual owned process (0.866 seconds, 44,777,472 bytes
sampled peak owned-tree RSS, 1,479 bytes sampled test-directory growth).
The protected diagnostic log is under
`artifacts/dynark/part5/native-v3-input-cli-red-monitor-001`.

Implementation is limited to the existing worker CLI. It must not make the
standard client or current-state admission appear complete.
