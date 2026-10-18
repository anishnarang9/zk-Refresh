# Prospective v2 heldout relation input chain

This is a source-inspected procedure, not an execution receipt. Training-012 is
the sole live heavy job. Do not run this chain, generate witnesses/proofs, start a
validator, compile, or build alongside it. The v2 compile/setup/application ELF
outputs are absent; their expected identities and source checks do not establish
that those outputs exist or that a campaign passed.

All runtime outputs, including JSON reports and manifests, remain private. Use
canonical absolute paths beneath owner-only 0700 directories and fresh 0600
regular files; never reuse an output path. Keep externally reviewed SHA-256 pins
for each boundary. The placeholders below are deliberately not measured hashes.
Record real digests only after the corresponding bytes exist and are reviewed.

## Two freeze boundaries

The source bridge consumes the **issuance v1 freeze**, schema
`credential-v3-frozen-holdout-boundary-v1`. Its key-generation/issuance identities,
forbidden prior keys, frozen cohort, and post-freeze chronology bind eight new
credentials. This is the freeze referenced by each source receipt and by the
bridge manifest's `freeze` pin.

`prepare_proof_inputs_v2.py` separately requires the **v2 campaign freeze**, schema
`credential-v3-frozen-holdout-boundary-v2`. It checks the v2 package/setup identity,
package-output-record digest, its own source digest, and campaign component
identity fields. Original inputs, WTNS/public files, relation report, and assignments
must satisfy its post-freeze chronology checks. Plan this boundary before producing
those files; copying older evidence later is not a substitute. Do not interchange
the two freeze receipts or imply that the bridge checks the v2 boundary.

## 1. Generate request-bound source inputs under the issuance boundary

After the registered prerequisites exist and the Training-012 job has exited, use
`prepare_v3_heldout_source.py` for each case index 0–7, first R0 and then R1.
Required CLI arguments are `--case-root`, `--cohort-root`, `--freeze-receipt`,
`--freeze-sha256`, `--stage-root`, `--exporter`, `--variant`, and `--output`.
R1 additionally supplies `--transition-root`, `--transition-context`,
`--transition-context-sha256`, `--r0-source-receipt`, and
`--r0-source-receipt-sha256`. Use the independently checked case context, frozen
full cohort receipt, local stage/transition evidence, and pinned exporter.

Each fresh source directory supplies `input.json` and `source-receipt.json` for
the next step. It also contains private request/summary/public/coordinate artifacts.
Source receipts use `credential-v3-heldout-request-source-v1`; they assert no proof,
application effect, or authenticated live state.

## 2. Assemble and pin the bridge manifest

Create a private manifest with exactly these top-level fields:

```json
{
  "schema": "credential-v3-heldout-relation-inputs-v2",
  "freeze": {"path": "<absolute issuance-v1 freeze>", "sha256": "<external pin>"},
  "cohort": {"path": "<absolute full cohort receipt>", "sha256": "<external pin>"},
  "cases": [
    {
      "case_index": 0,
      "context": {"path": "<absolute case context>", "sha256": "<external pin>"},
      "R0": {
        "receipt": {"path": "<absolute R0 source receipt>", "sha256": "<external pin>"},
        "input": {"path": "<absolute R0 input.json>", "sha256": "<external pin>"}
      },
      "R1": {
        "receipt": {"path": "<absolute R1 source receipt>", "sha256": "<external pin>"},
        "input": {"path": "<absolute R1 input.json>", "sha256": "<external pin>"}
      }
    }
  ]
}
```

The displayed case is a shape example: the actual manifest must contain all eight
unique indices 0–7. Every pin is exactly `{path, sha256}`. The bridge rebuilds
membership from the frozen cohort, checks receipt/input hashes and R0→R1 linkage,
and requires the same action/request with only root and sibling 0 changing.

```sh
python3 -B tools/part5/prepare_v3_heldout_relation_inputs_v2.py \
  --manifest "$BRIDGE_MANIFEST" --manifest-sha256 "$BRIDGE_SHA256" \
  --output "$INPUT_ROOT"
```

This publishes a fresh private directory containing exactly `cases.json` and 16
inputs: `holdout_0.input.json` through `holdout_7.input.json` and the corresponding
`holdout_N_unrelated_refresh.input.json` files. It loads no compiled circuit,
witness, or proof and does not establish relation satisfaction.
Publication currently uses macOS `renameatx_np` with `RENAME_EXCL` and fails closed
on platforms without that primitive. The owner-only artifact directory assumes
other processes running as the same user do not mutate its unpredictable pending
directory; a same-user process can otherwise race the final source pathname.

## 3. Qualify the complete relation, then index the assignments

The following is a future heavy execution step requiring the resource monitor
and completed, pinned v2 artifacts. `COMPILE` must be the repository's absolute
`artifacts/dynark/part5/v3-compile-002` path; the checker and R1CS paths are exact.

```sh
node tools/part5/witness_suite_heldout_v2.cjs \
  "$COMPILE" "$INPUT_ROOT" "$SUITE_ROOT" "$PYTHON" \
  "$REPO/tools/part5/witness_check.py" "$COMPILE/credential.r1cs"
```

The runner pins WASM, calculator, and R1CS bytes and checks all 16 complete WTNS
assignments against the R1CS. Its private `report.json` retains schema
`credential-v3-bounded-witness-qualification-v1`; require `passed=true`, 16 accepted,
zero rejected, and all complete checks passing. It emits each case's `.wtns` and
`-public.json`; this is witness qualification with no setup or proofs executed.

After reviewing and externally pinning the report:

```sh
python3 -B tools/part5/create_v3_heldout_assignments_manifest_v2.py \
  --suite-report "$SUITE_ROOT/report.json" --suite-sha256 "$RELATION_SHA256" \
  --output "$SUITE_ROOT/assignments.json"
```

The new 0600 manifest must be a direct child of the suite root. Its schema is
`credential-v3-bounded-private-assignments-v1`, with `synthetic_only=true`, pinned
accepted suite, and 16 rows pinning WTNS/public files. This step reads existing
assignments; it does not establish the separate freeze or original-input linkage.

## 4. Prepare the v2 proof template

Use the reviewed fresh v2 package-output record, its external pin, the separate
v2 campaign freeze, and the original bridge output directory:

```sh
python3 -B tools/part5/prepare_proof_inputs_v2.py \
  --repo-root "$REPO" \
  --package-pins "$PACKAGE_OUTPUT_RECORD" --package-pins-sha256 "$PACKAGE_SHA256" \
  --assignments "$SUITE_ROOT/assignments.json" --assignments-sha256 "$ASSIGNMENTS_SHA256" \
  --relation-report-sha256 "$RELATION_SHA256" --input-root "$INPUT_ROOT" \
  --freeze-receipt "$CAMPAIGN_V2_FREEZE" --freeze-sha256 "$CAMPAIGN_V2_FREEZE_SHA256" \
  --private-out "$PROOF_INPUT_ROOT" --cohort heldout-v2
```

The preparer verifies package identities, freeze/chronology, report census,
assignment hashes, and every original input scalar's WTNS/public linkage. It
publishes private `packet-template.json`, `heldout-pairs.json`, input-wire mapping,
and bridged pair directories, with returned output digests. It generates no
witnesses or proofs. These outputs alone establish neither proof verification,
loaded application acceptance, heldout generalization, nor a whole-session benefit.
