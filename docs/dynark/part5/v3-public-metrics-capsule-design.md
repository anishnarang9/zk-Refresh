# Proposed public Training-011 metrics capsule

Design and implementation contract, 2026-10-18. The exporter, offline verifier, and synthetic interoperability test implement this contract, but no completed Training-011 measurement or heldout outcome is asserted here. Publish only after the registered 60-slot completion/report/clock gates pass. Keep the existing public receipt bundle unchanged: its verifier rejects additional top-level entries. Publish `metrics.json` in a separate directory with an independently published byte SHA-256.

## Existing evidence and privacy boundary

The receipt exporter copies only strict slot/sequence allowlists; the public verifier establishes the 60-slot registered chain and hash consistency, explicitly excluding independent verification of underlying session/effect reports. Receipts bind session, outer and clone report hashes and expose clone preparation time, but omit session wall time and shared signed-state preparation. They alone cannot reproduce total costs.

The first completed Training-011 slot was inspected for field names/types only. Its slot receipt has numeric clone time, integer sequence/repetition/count/order position, string mode/schema/report/identity hashes, list registered order and nullable predecessor hash. Its outer report has numeric duration, booleans for success/censoring/cleanup, dictionaries for CPU/limits/environment, and a samples list. Its session report has string identities/hashes, numeric command/stage times, booleans for accounting/verification, dictionaries for source identities/cleanup, and a stages list. These observations establish projection feasibility, not a matrix result.

Do not publish raw economics sessions: `current_root` is a filesystem path (`run_v3_campaign_session.py` serializes its stage/transition directory), and the analyzer copies it into `sessions`. Raw outer samples/limits, nested stages, configs, cleanup records and arbitrary strings/maps have no public allowlist here. Redacting only keys named `path` is insufficient. The reconciler and total summarizer are narrower, but copying entire reports would silently inherit future fields.

## Exact proposed v1 field contract

All objects reject unknown fields, duplicate JSON keys and nonfinite numbers. `hash` means exactly 64 lowercase hexadecimal characters. `seconds` means a finite JSON number >= 0, excluding booleans. Publish original numeric precision, with no rounding. No field contains a local path. Array ordering below is mandatory.

| Object | Exact fields and types |
| --- | --- |
| root | `schema`: literal `part5-v3-public-metrics-capsule-v1`; `campaign_id`: literal `training-011`; `training_only`: true; `matrix_grid_complete`: true; `source_hashes`: object below; `slots`: 60 slot objects in sequence order; `shared`: object below; `one_time`: object below; `claims`: object below |
| source_hashes | `projection_index_sha256`, `receipt_index_sha256`, `sequence_receipt_sha256`, `matrix_manifest_canonical_sha256`, `clock_audit_report_sha256`, `economics_input_manifest_sha256`, `economics_report_sha256`, `reconciliation_report_sha256`, `total_summary_report_sha256`, `exporter_source_sha256`, `economics_analyzer_source_sha256`, `reconciler_source_sha256`, `total_summarizer_source_sha256`: hashes |
| slot | `sequence`: integer 1..60; `repetition`: integer 1..4; `target_count`: integer in 0,1,2,5,10; `mode`: enum full/anchor/coalesced-full; `slot_identity_sha256`, `slot_receipt_sha256`, `session_report_sha256`, `outer_report_sha256`, `clone_report_sha256`: hashes; `status`: literal valid; `match_group`: integer 1..20; `outer_wall_seconds`, `clone_preparation_seconds`: seconds |
| shared | `prepare_seconds`, `stage_seconds`: positive seconds; `transitions`: four transition objects ordered by count; `prepare_status_sha256`, `prepare_monitor_sha256`, `stage_status_sha256`, `stage_monitor_sha256`, `stage_config_sha256`: hashes |
| transition | `target_count`: integer in 1,2,5,10; `seconds`: positive seconds; `config_sha256`, `status_sha256`, `monitor_sha256`: hashes |
| one_time | `development_setup_seconds`, `cohort_preparation_seconds`: positive seconds; `setup_manifest_sha256`, `cohort_receipt_sha256`: hashes; `charged_per_request`: false |
| claims | `directly_timed_whole_application_session`: false; `whole_application_benefit_established`: false; `complete_tree_cpu_qualified`: false; `interpolation_or_extrapolation_used`: false; `identity_join_scope`: literal `publisher-validated equality; underlying private reports omitted` |

Byte hashes refer to original unmodified source bytes. The matrix digest alone uses the existing convention: SHA-256 of UTF-8 `json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n'`. Do not substitute a byte hash for it. The external capsule byte digest avoids a self-hash cycle.

## Identity joins and export gate

On the publisher's private machine, validate the registered manifest and run the existing complete-matrix validation, analyzer, reconciliation and total-summary recomputation read-only. Require all 60 valid sessions, 20 matched pairs, complete three-mode grid and matching newly recomputed reports. Recompute and require the registered clock audit to pass, then pin its raw byte SHA-256 in the capsule. An exported boolean cannot replace it.

For each slot, join by `(repetition, target_count, mode)` AND its registered sequence; require every report hash and slot identity to equal the current slot receipt and the sequence entry. Recheck source bytes after projection. Copy clone seconds exactly from the receipt. Copy outer seconds only from the analyzer's validated session record, agreeing with the pinned outer report `duration_seconds`. Do not derive it from stage sums or timestamp subtraction.

Assign `match_group = (repetition - 1) * 5 + index(target_count) + 1`, where counts are ordered 0,1,2,5,10. Before assigning a group, require the analyzer's full `_pair` equality checks across Full, Anchor and valid coalesced Full: freeze/cohort identities, current root/report, source identities, exact request, outer environment and all charged/wait flags. The group is a publisher assertion of equality, not a digest of a path. Do not publish `current_root`, its hash, arbitrary `source_identities` map keys, environment strings or request/credential identifiers. Existing source-report byte hashes provide opaque provenance references without revealing those values.

Require shared times to equal `shared_steps()` and one-time times to equal `one_time_costs()` from the current reconciler. Include only the named source pins above; never copy source evidence objects containing paths. Require capsule arithmetic to reproduce all pair totals, per-count summaries and sampled crossings in the pinned total summary within its existing tolerance (`rel_tol=1e-9`, `abs_tol=1e-7` for total consistency).

## Offline recomputation

First verify the unchanged public bundle with its current independent verifier and the separate input projection. Hash capsule bytes against the separately trusted digest; reject unexpected fields/types/cardinality. Match the capsule's public index/sequence/manifest hashes to those verified bundles, then join every slot to its receipt by sequence, tuple, slot identity and all three report hashes. Check clone time equality and exactly three modes in each of the 20 groups. This makes omission or duplicate pairs detectable. The capsule pins the public clock report by raw SHA; verify that report's arithmetic separately. Source report hashes absent from the bundle remain references only.

For count k, define `S(k) = prepare_seconds + stage_seconds + (0 if k=0 else transition[k].seconds)`. Within each repetition/count pair, calculate `F = Full.outer_wall_seconds + S(k) + Full.clone_preparation_seconds` and `A = Anchor.outer_wall_seconds + S(k) + Anchor.clone_preparation_seconds`; require both positive. Then `D = F-A` and savings `q = D/F`. Coalesced Full is retained for full grid/identity coverage but does not enter this pair's totals.

For each k, calculate medians of the four F, A, D and q values independently; min/max q; and counts of positive/zero/negative D. The registered 20% indicator is `median(q) >= 0.20` with four complete pairs. Never subtract separate mode medians to obtain median D or divide median D by median F to obtain median q. The median sampled break-even is the first k in 0,1,2,5,10 with `median(D)>0`, with the preceding sampled k recorded; otherwise report not crossed through k10. Per repetition, find the first sampled k with D>0 and tabulate those first crossings. Zero is not positive; k0 may cross; a first crossing need not persist at later k. No interpolation, continuous break-even or extrapolation follows.

One-time development setup and cohort preparation stay separate. These totals are derived sums of observed components, not one directly timed deployment-to-action session; they exclude idle gaps and unmeasured operator churn. Training economics does not establish an operator workload or whole-application benefit.

## Smaller fallback and provenance limit

The required timing scalars and hashes can be allowlisted without publishing private values. Raw economics `current_root`, unrestricted nested measurement data and original configs cannot be safely published wholesale. If any source cannot be privately revalidated, or even opaque report hashes are unsuitable for the publication policy, publish only the existing receipt bundle and its receipt-chain-only scope; do not label that fallback independently recomputable economics. If equality metadata alone is unsuitable, omit match-group assertions and label any numeric table publisher-selected descriptive arithmetic, with no independently validated matched-pair claim.

An offline reader can verify receipt linkage, coverage and arithmetic. They cannot prove that projected outer/shared durations or private identity equality are truthful merely from hashes of withheld reports. The public receipt chain does not commit to these new projections, and a hash does not reveal or authenticate its preimage. A separately trusted published capsule digest fixes the asserted projection, not its truth. Stronger provenance needs independently reviewed public source projections bound during receipt creation, or an authorized private audit; neither is supplied by this design.

Sources inspected: `tools/part5/export_v3_campaign_public_receipts.py`, `verify_v3_campaign_public_receipts.py`, `analyze_v3_campaign_economics.py`, `reconcile_v3_campaign_costs.py`, `summarize_v3_campaign_total.py`, and first-slot report shapes only. No private artifact values are quoted.
