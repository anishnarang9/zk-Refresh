# DYNARK for X.509 authorization: application evidence

**Status: public report draft; incomplete.** Training-012's 60-slot component-sum matrix and public arithmetic chain are verified. No heldout acceptance, registered direct Full/Anchor whole-session arm result, loaded expired-status negative, or loaded queue-capacity negative is established. Training-017 and Training-018 case 00 each passed a Full protected effect but stopped at disabled-config negative supervisor failures. Training-019 also passed that Full effect, then its disabled-config audit timed out before finality and reporting. Training-020 completed the Full protected effect and disabled-config negative, but its ambiguous-restart child dropped the response after one forwarded submission and no duplicate; no restart, finality receipt, or reconciliation followed, so the application effect is unknown. Training-024 case 00 failed at the own-revocation effect gate after 32 passed steps; a bounded R1 replay diagnostic passed but established no application effect or acceptance. Training-025 has a fresh freeze, cohort, and eight manifests; case 00 passed its single-case CORE-PATH run, case 01 is pending, and cases 02–07 have not started. This is not eight-case independent acceptance.

Training-021 case 00 reached the first Full proof after stage, transition, and source preparation, but its owning terminal/process disappeared while that proof step remained `running`. No bounded proof monitor report or validated proof receipt exists; the proof outcome and elapsed work are unknown. No application effect, case acceptance, or heldout cost result follows. Its same case root is non-resumable because the runner rejects a `running` step with unknown work time; preserve it and do not retry it. See the [Training-021 recovery runbook](v3-heldout-training-021-runbook.md). Training-022's freeze SHA-256 is `353c2e5cb7bb910277cb4c13b391894fd25e522c172cd80b4754daa8d2e24172`, its prior-key inventory records 162 public keys, its cohort has eight certificates and holders across four issuers, and all eight manifests validated. Training-022 case 00 is **failed, not accepted**. The Full proof and fresh replay-proof steps passed, and the loaded Full Execute report recorded an application effect. The disabled-config negative report gate passed. The later ambiguous-restart step failed: the proxy dropped one response after one matching submission, restart identity was verified, but after 150 seconds there was no finalized signature or five-account reconciliation. The bounded cloned-ledger `reopen-report.json` diagnostic found no signature/history and unchanged hashes for all five checked accounts at its diagnostic point; this is no observed effect at that snapshot, not a finalized reconciliation or case acceptance. Preserve the case root and all artifacts. See the [Training-022 recovery runbook](v3-heldout-training-022-runbook.md); detailed status was audited from the case journal, outer reports, supervisor status, and reopen diagnostic.

Training-023 used a fresh freeze (`14c437186e50a97a7e9a77c645a0ccd5b13e433207ab848abf667e130c91b5d4`) after 174 prior public keys; its cohort issued eight certificates to eight holders across four issuers, and all eight manifests validated. Case 00 passed the Full proofs, loaded Full protected effect, and disabled-config negative. Its ambiguous-restart gate then **failed** in 48.3 seconds with `ValueError: pinned finalized request and empty v3 queue required` during pre-stop reconciliation. The bounded outer child exited 1 without censoring and reported zero remaining processes. No pre-restart finality receipt passed validation, and no restart or case fragment was produced. Case 00 is not accepted; no heldout cost result is available, and cases 01–07 were not run. Preserve this root and its reports.

After the Training-023 failure, commit `488ebd9` added a staged-config-public-key correction. Training-024 used a fresh source freeze (`0705e86049b6e6f01f2e0a7c185e33ed0e92cfeb26289d08edfad2999dc56478`), an inventory of 186 prior public keys, an eight-certificate/eight-holder cohort across four issuers, and eight manifests. Case 00 **failed, not accepted**, after 32 passed journal steps and one failed step, `own_revocation:effect`. Its branch supervisor omitted the R1 finalized-slot floor, queried at slot 54, and received the saved R0 config finalized at slot 45 instead of the R1 config finalized at slot 81; the Rust runner did not start. The journal's `FileNotFoundError` was secondary to the missing branch report. A separate bounded replay diagnostic on a fresh clone of the stopped transition ledger passed and observed the pinned loaded program plus all five expected R1 account hashes at finalized slot 81. It submitted no application transaction and produced no proof or acceptance result. Preserve the failed case and launch roots; cases 01–07 were not run. See the [Training-024 runbook](v3-heldout-training-024-runbook.md) for the diagnosis and receipts.

Training-025 is the fresh attempt. Its freeze SHA-256 is `df4f6edec1bb69eddd9d85822270046ef9bfd4c1d403e07ec19869a9a9c09481`; the prior-key inventory SHA-256 is `40e36fb292e3a050d84f1633456604ed4c2ac75ae09173d46a115132973d9eb7` and records 198 keys. The eight-certificate/eight-holder cohort receipt is `8866bf1110e2fb0c1db84f6adfd9cd56a9598c07f7efdbb9d8f543aed3bc53c3`; its bounded outer cohort run passed, and eight case manifests are present. Training-025 case 00 completed with tmux owner exit code 0, all 35 journal steps passed, and a variant-0 case fragment. The journal SHA-256 is `8466acfb2f771de77a6604d92862137d39b93e0d06e9e6f1ea268bd58260c774`; the fragment SHA-256 is `93ccd87f3efd120a508f0154e5f02fe800b41a060bc92de39a1a5a0705383837`. Its Full protected effect passed; the unrelated-root Full and refreshed semi-dynamic Anchor effects passed; own-revocation denied the effect and left the request unconsumed; the R2 active-witness attempt was rejected; and the disabled-config and ambiguous-restart gates passed. All 29 top-level bounded monitor reports referenced by the case journal record zero remaining owned processes and known cleanup status. This is a single-case CORE-PATH pass, not independent eight-case acceptance. Case 01 has launched and remains pending, with no completed fragment or owner exit code at this report snapshot. Cases 02–07 have no case roots or launch records. No eight-case acceptance, heldout cost result, or direct Full/Anchor economic result exists. See the [Training-025 runbook](v3-heldout-training-025-runbook.md) for the execution procedure. The journal, fragment, and owner exit-code receipts remain in ignored owner-only local artifacts; their digests are recorded above.

## Question and scope

This evaluation asks whether DYNARK reduces the total work of a bounded X.509 authorization workflow while preserving the protected application action and current-revocation checks. The registered comparison is ordinary Full Groth16 versus DYNARK's **semi-dynamic Anchor** mode, using matched application sessions and the same underlying action and state history. The 20% total-savings level is the registered material-benefit target. [Application-benefit plan](../../superpowers/plans/2026-10-16-v3-x509-application-benefit.md)

The Training-012 results below are a completed training-corpus matrix. They compare component-sum totals for Full and Anchor; they do not answer the heldout or complete-session question. The Anchor result must not be read as a measurement of fully dynamic DYNARK: anchor rebuild and maintenance costs for the fully dynamic algorithm are outside this matrix. [Training-012 interpretation](../../../results/dynark/part5/v3-training-012-interpretation.md)

## Training-012 matrix

The registered matrix completed **60 of 60 slots**, including **20 matched Full/Anchor pairs**: four pairs at each sampled update count `k ∈ {0, 1, 2, 5, 10}`. The UTC-versus-monotonic clock audit passed all 60 slots within its five-second tolerance. No interpolation or extrapolation was used. [Metrics report](../../../results/dynark/part5/v3-training-012-public-metrics-001/report.md) · [Metrics capsule](../../../results/dynark/part5/v3-training-012-public-metrics-001/metrics.json) · [Clock audit](../../../results/dynark/part5/v3-training-012-public-metrics-001/clock-audit.json)

| Root updates `k` | Median Full component-sum total (s) | Median Anchor component-sum total (s) | Median paired Full − Anchor (s) | Median savings | At least 20%? |
| ---: | ---: | ---: | ---: | ---: | :---: |
| 0 | 175.813 | 1,310.37 | −1,133.7 | −644.84% | No |
| 1 | 209.078 | 1,344.63 | −1,135.57 | −543.77% | No |
| 2 | 238.656 | 1,370.99 | −1,131.3 | −474.46% | No |
| 5 | 325.041 | 1,453.31 | −1,128.21 | −347.04% | No |
| 10 | 479.15 | 1,595.69 | −1,117.06 | −233.23% | No |

There was **no sampled strict-positive Full-minus-Anchor break-even through `k=10`**. The registered 20% target was not met at any sampled count. These results describe this training matrix and its synthetic update schedule; they do not predict a crossover beyond `k=10` or show that this schedule represents operator workload. [Training-012 matrix interpretation](../../../results/dynark/part5/v3-training-012-interpretation.md)

Semi-dynamic Anchor lost all 20 matched Full/Anchor pairs: the four paired repetitions at each `k` all had negative Full-minus-Anchor differences. The individual Full-minus-Anchor ranges, recomputed from the public capsule's component values, were −1,180.934 to −1,132.966 seconds at `k=0`, −1,149.217 to −1,132.615 at `k=1`, −1,134.005 to −1,130.023 at `k=2`, −1,131.921 to −1,125.353 at `k=5`, and −1,118.193 to −1,111.891 at `k=10`. Development setup took 21.340 seconds and cohort preparation 0.983 seconds; both are disclosed separately and were not charged to each request. [Metrics capsule](../../../results/dynark/part5/v3-training-012-public-metrics-001/metrics.json)

### Timing and resource limits

The totals are **component sums**, not direct timings of complete Full and Anchor arms. They add each mode's directly timed source-import-through-effect session and clone preparation to common preparation, staging, and the signed `R0`-to-`Rk` transition duration. A directly timed complete-application Full-versus-Anchor pair, with all shared and per-mode work in one end-to-end arm, is absent. The capsule also says that underlying private report truth and matched identity cannot be independently verified offline. [Metrics report](../../../results/dynark/part5/v3-training-012-public-metrics-001/report.md) · [Training-012 matrix interpretation](../../../results/dynark/part5/v3-training-012-interpretation.md)

The clock audit passed, but **CPU accounting is unqualified**: leader wait and sampled process-tree self-CPU overlap. Therefore this evidence supports no CPU-savings conclusion. Publisher-side observations from withheld reports show 825-byte, 5,000-lamport effect transactions; 184,352 compute units for Full and 184,352–184,364 for Anchor; sampled peak owned-tree RSS of 1.30–1.98 GiB for Full and 1.37–2.06 GiB for Anchor; and sampled storage growth of 194.2–445.7 MB and 194.2–550.2 MB, respectively. Those resource ranges are not independently recoverable from the public capsule. [Training-012 matrix interpretation](../../../results/dynark/part5/v3-training-012-interpretation.md)

## Application correctness and heldout evidence

**Training-fixture correctness only:** The earlier signed-history check reports two controlled demo-issued credentials. On separate matching clones it recorded one Full effect and one Anchor effect, replay rejection, stale-R0 rejection after unrelated R1 revocation, and rejection of both old Full and R1 Anchor attempts after own-leaf revocation at R2. Its scrubbed pair and own-revocation receipts are SHA-256 `6265ce079fbe52661822fe81c3aee8b18bf16882bc43c8f7622c6764d24615d6` and `9e4fd3173ca119270b9e7dc08418d2062034e5279c08c9f6a7c9f9e3fa8d2c3f`. This was one engineering pair under the earlier method; the Full arm paid an Anchor-support preflight. It is correctness evidence for that training fixture, not heldout acceptance or an eligible result for the registered economics comparison. See the [signed-history check](v3-signed-history-k1-training-effect-2026-10-17.md). Training-022 case 00 did not pass its heldout gate, as detailed below.

**Heldout result: not accepted.** Training-022 failed at ambiguous restart as described above. Training-023 used a new freeze, cohort, and manifests, passed its Full proofs, loaded Full effect, and disabled-config negative, then failed during pre-stop reconciliation with `ValueError: pinned finalized request and empty v3 queue required`. No pre-restart finality receipt passed, no restart or acceptance fragment exists, and cases 01–07 were not run. Its bounded outer child exited 1 uncensored with zero remaining processes. Training-024 case 00 failed at `own_revocation:effect` after 32 passed steps because its supervisor omitted the R1 finalized-slot floor; the bounded replay diagnostic later observed the expected R1 accounts at slot 81 but submitted no transaction and did not establish an own-revocation effect. Training-025 has the fresh freeze, 198-key inventory, cohort, and eight manifests described above; case 00 passed its single-case CORE-PATH run with 35 passed steps and a variant-0 fragment. Case 01 is pending, and cases 02–07 have not started. This attempt does not supply eight-case independent acceptance or a heldout cost result. Training-017 through Training-019 did not complete case 00; Training-020's ambiguous-restart response was dropped after one forwarded submission and no duplicate, with no restart, finality receipt, or five-account reconciliation, leaving its application effect unknown. Training-021's first Full proof step remained `running` after its owning process disappeared; its outcome and elapsed work are unknown, and the same root is non-resumable. See the [Training-021 runbook](v3-heldout-training-021-runbook.md), [Training-022 runbook](v3-heldout-training-022-runbook.md), [Training-023 runbook](v3-heldout-training-023-runbook.md), and [Training-024 runbook](v3-heldout-training-024-runbook.md).

| Heldout evidence gate | Current evidence state |
| --- | --- |
| Training-022 case 00 | **Failed; not accepted.** Full and fresh replay proofs, loaded Full effect, and disabled-config negative report gate passed. Ambiguous-restart did not produce finalized signature or five-account reconciliation within 150 seconds. Reopen diagnostic saw no signature/history and unchanged five-account hashes at that point. |
| Training-023 case 00 | **Failed; not accepted.** Freeze `14c437186e50a97a7e9a77c645a0ccd5b13e433207ab848abf667e130c91b5d4`, 174 prior public keys, eight-certificate cohort across four issuers, and eight manifests. Full proofs, loaded Full effect, and disabled-config negative passed. Pre-stop reconciliation failed in 48.3 seconds with `ValueError: pinned finalized request and empty v3 queue required`; no validated pre-restart finality receipt, restart, or fragment. Outer child exited 1 uncensored with zero remaining processes. |
| Training-023 cases 01–07 | **Not run.** Case 00 failed; the failed Training-023 root is not a retry target. |
| Training-024 case 00 | **Failed; not accepted.** After 32 passed steps, `own_revocation:effect` failed before the Rust runner spawned because the branch supervisor omitted the R1 finalized-slot floor and read the R0 config at slot 54. A bounded R1 replay diagnostic later observed the expected five R1 account hashes at slot 81; it submitted no transaction and is not an effect result. |
| Training-024 cases 01–07 | Not run; preserve the failed root and do not retry it. |
| Training-025 case 00 | **CORE-PATH pass; not independent campaign acceptance.** Owner exit code 0; 35/35 journal steps passed. Journal SHA-256 `8466acfb2f771de77a6604d92862137d39b93e0d06e9e6f1ea268bd58260c774`; variant-0 fragment SHA-256 `93ccd87f3efd120a508f0154e5f02fe800b41a060bc92de39a1a5a0705383837`. All 29 top-level journal-referenced bounded monitor reports show zero remaining owned processes and known cleanup. Full protected effect, unrelated-root Full/Anchor effects, own-revocation denial, R2 active-witness rejection, disabled-config, and ambiguous restart passed. Private journal, fragment, and owner exit-code receipts are retained locally. |
| Training-025 case 01 | **Launched; pending.** No completion fragment or owner exit code is present at this report snapshot. |
| Training-025 cases 02–07 | Not started; no case roots or launch records are present. |
| Eight heldout cases | Not complete. Case 00 has one passing core-path fragment; case 01 is pending and cases 02–07 are absent. All eight cases must finish with complete journals and distinct fragments covering variants 0–7, then pass the independent acceptance verifier. |
| Loaded expired-status negative | **0 of 8 demonstrated.** Existing source/fixture checks do not establish eight finalized loaded-ELF rejections with unchanged application-account bytes. |
| Loaded full-queue capacity negative | **0 of 1 demonstrated.** A validator for a supplied evidence record and host tests do not establish a loaded run with 64 finalized fills and a rejected 65th request. |
| Registered direct matched Full/Anchor whole-session arms | **Not measured.** Training-012 is a component-sum matrix, not a direct heldout total, and no heldout cost result is established. The older one-off training engineering pair did time bounded sessions, but Full paid Anchor-only preflight, so it is not the registered fair comparison. |

### Exact post-case checklist

1. Preserve the failed Training-022 and Training-023 roots and reports
   unchanged. Do not convert passing substeps into case passes or retry any
   failed root. Training-025 case 00 has completed with owner exit code 0 and 35 passed journal steps, as recorded in the case journal and fragment identified in the Training-025 evidence summary above. Its 29 top-level journal-referenced bounded monitor reports show zero remaining owned processes and known cleanup status.
2. Case 00 passed the core-path gate. Case 01 has launched and is pending; inspect its
   owner outcome, journal, receipts, and cleanup when complete. Continue cases 02–07
   serially only after the prior case passes; stop and preserve evidence at the first
   failure. A single case pass does not establish eight-case acceptance.
3. After all eight cases pass, require eight distinct hash-pinned fragments
   covering variants 0–7 and complete journals. Assemble them, then require
   the independent acceptance verifier to pass before running cost analysis.
   Freeze/cohort/manifests alone are not acceptance evidence.
4. Record the eight loaded expired-status negatives and the one loaded full-
   queue negative as separate required gates, with exact source/ELF identity,
   finalized error, five-account before/after equality, and bounded cleanup.
   The existing assembler/verifier does not yet include these evidence types;
   a core-path verifier pass therefore remains short of full binding-plan
   acceptance.
5. If a request-B component-sum report or conditional `k > 1` model is later
   produced, keep it separate from direct whole-session arms. The [direct-arm measurement
   plan](v3-heldout-direct-arm-measurement-plan.md) is a separate prospective
   gate after fresh case manifests are available; it calls for serial matched
   Full/Anchor arms across the eight credentials. Its directly timed segment
   excludes shared preparation and transition costs, so it is not a complete
   application-session total. No such arm result is available. Do not call the
   conditional model a measured heldout break-even.

The Training-022 and Training-023 commands and source pins document their
respective failed attempts. Training-024 and its R1 replay diagnosis are preserved as a failed attempt.
Training-025 uses a fresh freeze and case roots; case 00 passed the CORE-PATH run,
case 01 is pending, and cases 02–07 have not started. The expired-status and
queue-capacity criteria are detailed in the
[negative-evidence checklist](v3-heldout-negative-evidence-checklist.md).

## Interpretation and remaining limits

Training-012 is an unfavorable component-sum comparison for Anchor at every measured `k`, and it establishes no application-level win. It does not by itself prove that DYNARK cannot benefit under another workload: heldout acceptance, a directly timed complete-session comparison, and a justified update pattern remain unmeasured here. The public metrics capsule explicitly marks whole-application benefit and directly timed whole-application timing as not established. [Metrics capsule](../../../results/dynark/part5/v3-training-012-public-metrics-001/metrics.json)

The evaluated DYNARK variant is semi-dynamic Anchor. **Fully dynamic DYNARK is unevaluated here** because its anchor rebuilding and maintenance work is not included. Training-corpus measurements, a heldout credential result, and a complete-application economics result are separate evidence claims. [Training-012 matrix interpretation](../../../results/dynark/part5/v3-training-012-interpretation.md) · [Application-benefit plan](../../superpowers/plans/2026-10-16-v3-x509-application-benefit.md)

## Final conclusion

**Not established.** Training-012 found no Anchor win through `k=10` in its component-sum training comparison. Heldout acceptance, the loaded expired-status and capacity negatives, and a directly timed matched Full/Anchor complete-session comparison remain unavailable. Revisit this conclusion only after the checklist above passes; report the update pattern and measured wall-time/resource costs, or retain “not established”/report a negative result if that is what the evidence supports. [Application-benefit plan](../../superpowers/plans/2026-10-16-v3-x509-application-benefit.md)

## Publication record

- Public report URL: **pending publication**
- Final report SHA-256: **pending final publication**
- Metrics capsule SHA-256: `4b3914d405202bb1e3b711ea88dd6fca627e721c620cea14816f2507e1c9f582`; external public link: **pending release**
- Frozen source, setup, profile, ordinary VK, proof runner, client, adapter, and loaded ELF identities with public links: **pending final evidence bundle**
- Heldout evidence bundle and public links: **pending; Training-022 through Training-024 case 00 failed; Training-025 case 00 passed its CORE-PATH run, case 01 is pending, and cases 02–07 have not started; no eight-case acceptance or heldout cost result exists**

## Sources

- [Training-012 public metrics report](../../../results/dynark/part5/v3-training-012-public-metrics-001/report.md)
- [Training-012 public metrics capsule](../../../results/dynark/part5/v3-training-012-public-metrics-001/metrics.json)
- [Training-012 matrix interpretation and evidence identities](../../../results/dynark/part5/v3-training-012-interpretation.md)
- [Signed-history training correctness check](v3-signed-history-k1-training-effect-2026-10-17.md)
- [Training-022 execution and recovery runbook](v3-heldout-training-022-runbook.md)
- [Training-023 failed-attempt runbook](v3-heldout-training-023-runbook.md)
- [Training-024 failed-attempt runbook and R1 replay diagnosis](v3-heldout-training-024-runbook.md)
- [Training-025 execution runbook](v3-heldout-training-025-runbook.md)
- [Prospective direct-arm measurement plan](v3-heldout-direct-arm-measurement-plan.md)
- [Loaded expired-status and queue-capacity evidence checklist](v3-heldout-negative-evidence-checklist.md)
- [Application queue/status implementation](../../../program/src/application_v3.rs), [Execute preflight](../../../program/src/application_preflight_v3.rs), [loaded effect runtime](../../../program/src/application_runtime_v3.rs), [host loaded-negative checks](../../../harness/tests/queue_v3_loaded_negative_checks.py), and [capacity evidence validator](../../../tools/part5/heldout_queue_capacity_evidence.py) (source/test/report-validation contracts, not loaded execution receipts)
- [V3 X.509 application-benefit plan](../../superpowers/plans/2026-10-16-v3-x509-application-benefit.md)
