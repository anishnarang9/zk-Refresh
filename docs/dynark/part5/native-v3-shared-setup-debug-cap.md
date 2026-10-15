# Native v3 shared setup: debug execution cap review

The candidate loader compiled, and its two early rejection tests passed in
2.017 bounded seconds. The ignored real-package positive was then invoked by
exact name under a 600-second, 4-GiB RSS, 512-MiB setup-root growth envelope.
It reached proving-key subgroup validation but did not return before the
runtime cap. The bounded runner stopped it at 600.320 seconds, with exit -15,
`stop_reason=runtime_seconds`, no runner error and no remaining owned process.
Sampled peak owned RSS was 464,666,624 bytes; sampled maximum positive
setup-root growth was 169,084,608 bytes from the transient R1CS snapshot.
The snapshot was absent after cleanup. No positive admission is claimed.

The source-level stack sample taken during the run showed
`PublicPackage::new`/`pk.check()` in Arkworks parallel curve/subgroup
validation. That observation identifies the slow stage; it does not prove
that the package would have passed. The earlier reviewed release-mode public
package reload completed in 44.552 seconds with the same frozen setup. The
debug test runner used unoptimized code and is a poor execution mode for this
large key check.

The public bounded receipts are
`results/dynark/part5/native-v3-shared-setup-negative-green-bounded-001.json`
(SHA-256 `0d127107da0e14f7e39ddb8aed44c9b40215b4ba130c677dcedf8690c194e691`)
and `results/dynark/part5/native-v3-shared-setup-positive-green-bounded-001.json`
(SHA-256 `addd639cb6c3ee8483f40e7c19f6b8e102c5eb48bff54ce3714bcd53bba67995`).
The candidate loader source SHA-256 is
`c394698064d71301474463f0d910784bed4e8ec1192f871fdf68e80042db1125`.

The next distinct gate uses the **same frozen source and artifacts** in Cargo
release mode, with a new output receipt and the same 600-second/4-GiB/512-MiB
external limits. The existing release target is 155 MiB; only the source
delta is expected to compile. Its exact ignored positive and scope variable
remain unchanged. The setup-root storage monitor captures any transient R1CS
snapshot. A release failure or cap requires another review, not an automatic
increase. No other heavy command will run alongside it.
