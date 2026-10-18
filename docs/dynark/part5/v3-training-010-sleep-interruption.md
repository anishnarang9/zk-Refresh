# Training-010 matrix stop after host sleep

**Observed 2026-10-18 06:04 UTC.** Training-010 stopped at repetition 1,
`k = 1`, Anchor. Four preceding ordered slots have passing receipts. The fifth
slot has an outer report but no completed proof report, effect, or slot receipt. The matrix
driver exited 1 and published no final sequence or economics input. No
Training-010 total-cost or break-even result follows from this run.

The fifth slot's outer report is SHA-256
`a12359d4ae82e4b20850abea7bb94b2c4325682e4a72f43f59495382cef4afdf`.
It records exit `-15`, `passed=false`, no resource stop, zero remaining owned
processes, and known cleanup. It measured 684.644 seconds by the runner's
monotonic clock, while its own UTC start/end timestamps span 5,052.156 seconds:
**4,367.511 seconds of clock divergence**. The host power log records an idle
sleep beginning at 00:46:06 EDT (04:46:06 UTC), about six minutes after the
slot started, followed by repeated sleep and maintenance wake intervals.
The preceding four outer reports had UTC-minus-monotonic differences of
0.000, 0.023, 0.001, and 0.001 seconds respectively.

The active proof was terminated through its verified slot process group after
the sleep discrepancy was established. The bounded outer runner wrote its
failure and cleanup report; the driver then rejected the slot. The partial
output remains intact for audit and is ineligible for `--resume` because it
has no passing receipt. Even had it completed, host sleep would make this
Anchor wall-time sample incomparable with the matched Full sample. Do not pool
these partial slots into accepted campaign economics.

The four passing receipt SHA-256s, in sequence, are:

| Sequence | Slot | Receipt SHA-256 |
|---:|---|---|
| 1 | `r1-k0-full` | `e54e3339df92f4f0a938c11336c99a8b6e8c1edf800277c5dc0bcb8490d1c0f1` |
| 2 | `r1-k0-anchor` | `97e474b5eb740e465fc81c411a029642efec11353909ba021ab2ee85623d8f79` |
| 3 | `r1-k0-coalesced-full` | `8a194ea4caf50028afefe627eb488726a68a6e4f1bde76734a44ee2065c49f0a` |
| 4 | `r1-k1-full` | `a88fab91df0a7f8d4ecba505ff13400444d36778260604ca37706333aff3d030` |

The next registered measurement must use a fresh campaign ID and output root,
prevent host idle/system sleep for the command's entire lifetime, and audit
each completed outer report's UTC span against monotonic duration before cost
reconciliation. This is an environmental measurement failure, not a v3
credential correctness or DYNARK proof failure.
