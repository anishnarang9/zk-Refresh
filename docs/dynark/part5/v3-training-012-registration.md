# Training-012 registered matrix

**Registered and launched 2026-10-18 08:27 UTC; not yet a result.** Training-012 is a fresh
attempt after the [Training-011 storage stop](v3-training-011-storage-stop.md).
The 60-slot design retains four counterbalanced repetitions, counts
`{0, 1, 2, 5, 10}`, and Full, Anchor, and coalesced Full modes. The controlled
cohort, authenticated histories, freeze-003, setup, application, and session
tool pins are exactly the Training-011 values. No output or cost sample from
Training-010 or Training-011 is reused.

The private canonical manifest is
`results/dynark/part5/v3-campaign-matrix-training-012.json`, SHA-256
`21612a6451c00b7a46d9abaa3445e5acecec3c14583317884800b49b2614ff53`.
Compared with Training-011, only the campaign ID, fresh output root, and
`k=10` Anchor storage cap changed. That cap is 1,073,741,824 bytes (1 GiB)
for its four repetitions, at planned positions 14, 28, 45, and 59. The other
56 slot caps remain 536,870,912 bytes (512 MiB); all per-slot runtime and RSS
limits and the 129,600-second campaign envelope remain unchanged. The cap is
sampled positive logical file growth, not a disk quota. The revised cap is
roughly twice the 541,843,789-byte censored peak observed in Training-011 and
leaves another 531,898,035 bytes of sampled headroom; this is a bound for a
fresh attempt, not evidence that it will pass.

The tested matrix driver has SHA-256
`dee858b687dcb657814d98d376c9510136e3d16a4a38bd5c40d320933e0781ba`.
Its Training-012 exception permits 1 GiB only at `k=10` Anchor. The pinned
campaign Python has SHA-256
`4fce274f0e60574ada0b53f17bceb49bbd804125ddae972c7674b8eb13d9e49d`.
Its read-only `--plan` preflight validated all manifest evidence and tool pins
and produced 60 ordered slots. The private preflight plan at
`artifacts/dynark/part5/v3-matrix-training-012-preflight-plan.json` has raw
SHA-256 `b9f548defaf13fd9cb389b09f70b7e08ba65c40262ddb276b74e4972c0271d78`.
All 180 planned slot, effect, and control output paths were absent and not
symlinks at registration. The host reported 414 GiB free; this is a point-in-time
check, not a reservation.

Before economics, the fresh driver must exit successfully, all 60 contiguous
slot receipts and the final sequence must validate against its generated plan,
and the maximum five-second UTC-versus-monotonic clock audit must pass. Only
then may the fixed economics, reconciliation, and total-cost tools run. The
eight new heldout credentials and direct complete-arm timing remain separate
gates. This registration makes no savings or acceptance claim.

## Launch and public design projection

The sole serial matrix driver launched under `caffeinate -is`. Its private
campaign state records start `2026-10-18T08:27:55.697769+00:00` and deadline
`2026-10-19T20:27:55.697769+00:00`. A read-only launch check observed the
driver, its first bounded `r1-k0-full` slot, and active
`PreventSystemSleep`/`PreventUserIdleSystemSleep` assertions. The actual
generated 60-slot `matrix-plan.json` has SHA-256
`e1cd1b9eb1c08fed70cd7544b0286af82422eb50a49a63875be267b57907f467`
and matched the registered preflight plan semantically. These checks show a
launch, not completion or absence of later host suspension.

The scrubbed [public projection](../../../results/dynark/part5/v3-training-012-public-projection-001/index.json)
has index SHA-256 `d846e56347d3a244837426bf08f9358e7c0b0cc6aff62666ed5440090967e340`.
Its independent verifier passed the three-file inventory, byte pins, source
digest consistency, allowed tool roles, registered 60-slot design, and narrow
Training-012 storage policy. The private manifest and actual plan were
separately rehashed against the index's source pins. Projection verification
does not verify any application effect, private slot receipt, or cost result.
