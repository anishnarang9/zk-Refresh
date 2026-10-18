# Training-011 stopped at its registered storage limit

**Observed 2026-10-18 08:19 UTC.** Training-011 recorded 13 ordered slot
receipts, through `r1-k10-full`. Slot 14, `r1-k10-anchor`, did not produce a
slot receipt. The matrix driver exited 1 and published no final sequence or
economics input. There is no Training-011 total-cost or break-even result.

The failed slot's private `outer-report.json` under
`artifacts/dynark/part5/v3-matrix-training-011/slot-r1-k10-anchor/` has
SHA-256 `afb0d7e966de4b32c5f85161caff2a3d251e1ba4538416fe620f14425b372589`.
Its bounded monitor sampled 541,843,789 bytes of positive logical file growth
against the registered 536,870,912-byte (512 MiB) limit. It stopped the slot
with exit `-15`, `passed=false`, zero remaining owned processes, and known
cleanup. Sampled peak owned-tree RSS was 1,921,908,736 bytes, below the
4 GiB RSS limit. The final storage sample jumped from 276,658,463 bytes to
541,843,789 bytes within one polling interval. These are sampled values; the
monitor does not establish the unsampled transient peak or disk-block usage.

At the stop, `work/` held about 276.7 MB, including eleven 25.1 MB witness
files. The clone's RocksDB directory had two newly written SST files totaling
272.9 MB. Their timing and size strongly implicate validator startup storage
growth in the final jump; the outer report aggregates roots and does not
attribute that jump to individual files. The separate application monitor
counts its own private output plus effect and control outputs. Effect and
control held about 2.3 KB at the stop.
Its 256 MiB bound was not the observed stop reason, and its own final report
was never written.

The slot's proof report (SHA-256
`60316d54ec89d0defe11129c39829c267af6f4cfbfe7790dd593d307e8740d52`)
records a passing proof stage. The application effect had begun, but there is
no completed effect monitor, session report, or slot receipt. The failed slot
therefore says nothing about application authorization or Anchor's total cost.
The 13 earlier receipts remain partial historical evidence and must not be
pooled with another campaign. Training-010 remains a separate sleep-interrupted
attempt.

Training-011 is not eligible for `--resume` under its registered completion
runbook. A new attempt needs a fresh campaign ID and output root, an explicitly
registered storage bound, and its own 60-slot sequence and clock audit before
economics. Preserve this stopped run's private outputs for audit.
