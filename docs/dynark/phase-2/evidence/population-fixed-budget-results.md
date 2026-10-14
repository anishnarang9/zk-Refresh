# Fixed-budget population results

October 14, 2026. Both continuous zero/one/two-state runs completed under `dynark-fixed-budget-v1`: 4 GiB sampled workload-tree RSS, four compute workers, one heavy job, 1,200 seconds and 2 GiB output growth. Normal and diagnostic runs are separate observations on this laptop, not a claim about an average device.

| Retained states | Shared public vector capacity, bytes | Private vector capacity, bytes | Normal retained RSS, bytes | Diagnostic retained RSS, bytes |
|---:|---:|---:|---:|---:|
| 0 | 907,245,168 | 0 | 376,520,704 | 637,403,136 |
| 1 | 907,245,168 | 289,029,472 | 958,054,400 | 904,986,624 |
| 2 | 907,245,168 | 578,058,944 | 913,801,216 | 991,412,224 |

The public package and updating material remained shared. Each private state was decoded separately; all private allocation ranges were disjoint, while identities and commitments matched. Two fresh no-op proofs verified, and all ten altered-public attempts were rejected. The full ledger counted sixteen ordinary verifications including import checks, four full assignment validations, zero q preparations and zero quadratic pair visits. Contents were identical synthetic fixtures in separate allocations, not independent real-user credentials.

Each private state retains 643,563 field coordinates, two 1,048,576-element field projections and two equally long projective point vectors. Their measured vector capacities total `643563 × 32 + 2 × 1048576 × 32 + 2 × 1048576 × 96 = 289029472` bytes, plus 1,096 fixed bytes per anchor. The historical 67,109,349-byte serialized cache covers a different representation and scope. Serialized size, vector capacity, requested heap and resident memory are not interchangeable.

The normal run took 131.036531 seconds, with 591 samples and a 1,003,683,840-byte sampled workload-tree RSS peak. The diagnostic took 128.220226 seconds, with 577 samples and a 994,361,344-byte RSS peak. These are single whole-run observations; the diagnostic time is not used as a normal performance comparison. Both exited successfully without a resource or host stop, with verified zero-process cleanup.

The diagnostic observed a 1,669,022,602-byte requested-live peak and 4,697,084,558 bytes of total allocation traffic. All ninety allocation boundaries satisfied `traffic − freed = live`. These counters measure requested sizes and do not infer allocator metadata, fragmentation or copied bytes.

Ten states were not admitted. The preregistered rule requires complete normal and diagnostic small cases with monotonic retained RSS before a numeric projection; normal RSS decreased from one to two. The rule and cap were preserved. This does not establish that ten states would exceed 4 GiB, nor supply a ten-state measurement. The accepted result demonstrates sharing and separate private allocations for the measured populations; it does not establish a session break-even point.

Parent inspected primary reports, duplicate equality, workload/host evidence and frozen identities. Evidence: [normal return](../../../../results/dynark/phase-2/fixed-budget/oct14-preflight/population-normal-zero-one-two-001-worker-return.json), [diagnostic return](../../../../results/dynark/phase-2/fixed-budget/oct14-preflight/population-diagnostic-zero-one-two-001-worker-return.json), [execution record](oct14-execution.md), [resource policy](fixed-budget-review.md). The diagnostic report SHA256 is `8723c6f34fe30dd9440be1743b1dbac33c1d780df27740d6012659d385805531`; its allocator repair was separate from the population binary and was not linked into this run.
