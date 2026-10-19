# Matched heldout prepared-import arms

`tools/part5/run_v3_heldout_complete_arm.py` directly times separate Full and
semi-dynamic Anchor prepared-ledger-import-to-Execute arms at k=1. The filename
does not imply the registered complete-session gate: shared initial preparation
and a control-stage fixture are outside both timers. No measured result exists
from this source-only implementation slice.

## Provenance and timing

Acquire the stable heavyweight lock in the Git owner checkout, including when
invoked from a worktree. Create one bounded prepared-only baseline, then import
it to a separate control ledger and stage a random request there. Preserve the
baseline unchanged. Package the control plan and four signer files with exact
hashes and the full stage-context hash; retain these private ignored artifacts.
Report the common baseline and control fixture costs separately, alongside the
excluded initial issuance/cohort costs.

The entire shared-fixture build, including ledger import/inventories and replay
packaging, runs in its own authenticated `session_runner` worker before either
mode launches. A one-time ticket binds parent PID, token, manifest and exact
fixture root; the worker verifies that parent still holds the global heavy lock.
Its outer owner has a 900-second, 4-GiB RSS and 2-GiB storage-growth cap. Require
success, uncensored evidence, matching owner/caps and verified cleanup before
reading the fixture and launching an arm. The separately retained
`direct_fixture_outer_wall_seconds` is an excluded shared cost; internal fixture
body/component timings remain attribution.

All fixture and arm outer monitors use fresh canonical owner-only Git-ignored
directories beside Part 5. Those private monitor roots are disjoint from the
covered Part 5 tree. Each session runner automatically measures its own private
root and also measures positive storage growth across all Part 5 artifacts,
covering the complete fixture tree and the baseline/control application ledger
siblings. Overlapping roots are rejected before a session launches.

For each mode, start one bounded outer timer before its worker launches. Inside
that timer, independently import the original prepared baseline, build the pair
view, stage with the identical pinned replay package, publish the authenticated
unrelated R0-to-R1 transition, build R0/R1 sources and complete witnesses, run the
selected proof path and ordinary verification, independently clone that arm's
stopped R1 ledger, and perform loaded Execute. The timer ends after owned-process
cleanup. Counterbalance Full/Anchor order by variant parity. Nested durations
are attribution only; do not sum them into a session duration. Outer monitor
metadata setup and final report writing remain outside its timer.

`harness/tests/queue_v3_clone_prepared.py` writes a distinct
`part5-v3-prepared-import` config/status. Its source prepare config, status,
monitor, cleanup, genesis, loaded ELF identity and ledger inventory are pinned.
It verifies source stability and byte-identical copying into a fresh disjoint
private destination. The import status explicitly records that live identity
has not been reattested; it contains no invented validator cleanup. Opt-in stage
admission rechecks that chain and both tree inventories before restart. Existing
stage logic then reattests the finalized loaded identity before transactions.
Frozen downstream provenance can derive the imported ledger from the truthful
import config without changing the heldout case runner.

The replay package is needed because the protected action includes genesis,
plan seed/nonce and request/account identity. Independent fresh validator
genesis creation cannot guarantee the same action. Reusing an unmodified
prepared baseline preserves this domain while each arm stages and executes
against separate ledger destinations.

Match credential, exact finalized request-account bytes and PDA, Rust V3F2
transport/action digest, program/genesis, authenticated R0/R1 roots, replay
package/plan, common prepare source and frozen setup/VK/ELF identities. Each R1
clone must match its own stopped source; independently staged arm ledger trees
need not equal each other. Retain V3F1 frame hashes as per-source evidence: those
frames include clock/root/config data and are not the exact request-account
identity. Failed, censored, unmatched or incompletely cleaned arms yield no pair
comparison.

## Verification and remaining gates

Lightweight Python tests cover copy/source races, changed provenance, import
admission, the frozen case stage checker, preserved random/replay behavior,
exact action/root matching, global locking, serial fixture/arm timing,
authenticated fixture launches and failed/censored fixture rejection before
any arm launch. A bounded, offline, locked Cargo `--no-run` build of the v3
queue test target passed after the replay and expired-status source integration;
its private owner report SHA-256 is
`02f0e9a12b54cc7d26c56bab3f9b5ab8ab3239dafc59b231a14893fbd9e3cae8`.
No proof, validator or application runtime was invoked for this arm. Source and
runner identities must be frozen again before use; existing heldout manifests
are not silently rewritten.

The fresh-freeze inventory includes
`harness/tests/queue_v3_clone_prepared.py` in `REGISTRY_FILES`, and
`tools/part5/run_v3_heldout_complete_arm.py` plus
`tools/part5/run_v3_heldout_direct_arm.py` in `CLIENT_FILES`, in
`tools/part5/freeze_v3_heldout_cohort.py`. It also retains the stage wrapper.
The supervisor refuses manifests missing these four exact current source pins.
The direct runner's reviewed `_shared_lock_artifacts` resolver supplies the
stable owner-checkout lock; the supervisor refuses an older checkout-local-lock
module.

Rebuild and freeze the replay-capable harness runner, reverify the application
ELF and unchanged product assets, publish a fresh complete source boundary and
prior-key inventory, then generate and observe a new unseen cohort and build
new manifests. The application ELF can remain byte-identical if its source and
loaded identity remain unchanged. This supervisor prepares a new common ledger;
its genesis/action is new relative to earlier Training-024 trials, while both
arms share that new genesis/action.

Training-024 credentials/manifests cannot be source-repinned into this new
frozen unseen run. Both the cohort receipt and parent observation bind the old
freeze, and issuance must follow the new source freeze. Changing those receipts
would fabricate chronology. Existing credentials and ledgers may be reused only
under a separately declared training protocol; the current strict heldout
supervisor does not admit such a migration. No Training-024 direct-arm evidence
is claimed or retrospectively registered here.

After the new freeze/cohort and manifests are accepted, one serial pair uses:

```sh
python3 -B -m tools.part5.run_v3_heldout_complete_arm \
  --manifest "$RUN_MANIFESTS/case-$V.json" \
  --output-root "$PART5/v3-heldout-import-arm-$RUN_ID-$V"
```

This is a directly timed import-through-effect segment with common baseline and
fixture costs excluded. It does not establish whole-application timing, total
work savings, complete-tree CPU, private proof-state serialization/reload,
k>1/break-even distributions, all Gate 3 workload cases or Gate 5 eight-credential
acceptance. Both `complete_import_to_execute_arm` and
`registered_complete_session_gate_satisfied` remain false in reports.
