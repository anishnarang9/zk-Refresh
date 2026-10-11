# Phase 2 bootstrap evidence

Owner: `evidence_steward`. This directory contains the pre-run bounded experiment, fresh preservation evidence, and a Python stdlib foreground-process watchdog. No proving, setup, Rust build, profiler or credential-scale job was run by this owner.

Use `preservation-v3.json` and `preservation-runner-v3.json` as the completed fresh scan. Earlier reports are preserved failures in auxiliary metadata path handling: first the vendor source nesting, then the E2 package's run-relative paths. All three direct baseline165/build28/retained54 checks matched. No frozen input or original manifest was repaired. `verification-amendment.json` records the fixes before the fresh scan. Full exact artifact paths/hashes are only in ignored `artifacts/dynark/phase-2/bootstrap/preservation-v3-private.json` (600).

The final scan directly verifies the original Phase1 manifests, rather than accepting V2 booleans. Absolute historical `/Users/anishnarang/Zk-fresh/` paths map by relative path to `/Users/anishnarang/Zk-refresh/`; originals remain unchanged. Vendor source/license and executable identities, resolved original probe dependency versions, Git status, safe executable-name process snapshots, host/version/clock/storage snapshots are included. Public private-artifact results are counts/match booleans. Hash equality is content identity, not authentication or setup provenance.

## Bounded runner

Parent source review approved `bounded_runner.py` SHA256 `f2a0669b538f3f67751fafd132fee25211b637cc1082f24c4a40a43f85d01137`. Seven public dummy tests passed in 1.617 seconds; parent independently reran them in 1.550 seconds. The earlier six-test run is intermediate evidence. Tests cover normal/nonzero exit, no overwrite, existing group-leader invocation, descendant timeout without killing an unrelated process, sampled RSS/storage limits, modes, and process-inspection failure cleanup/reporting. No repository cryptography is used.

After obtaining the execution slot and reviewed command/bounds, invoke:

```sh
python3 results/dynark/phase-2/bootstrap/bounded_runner.py \
  --owner OWNER --cwd /Users/anishnarang/Zk-refresh \
  --private-output /Users/anishnarang/Zk-refresh/artifacts/dynark/phase-2/OWNER/FRESH_RUN \
  --report /Users/anishnarang/Zk-refresh/results/dynark/phase-2/OWNER/FRESH_REPORT.json \
  --runtime-seconds SECONDS --rss-bytes BYTES --storage-bytes BYTES \
  --storage-path /ABSOLUTE/TARGET/DIRECTORY -- COMMAND ARGUMENTS
```

The private parent and public report parent must exist. Output paths must be fresh; monitored storage roots must be disjoint. Private output directory mode is700 and logs/invocation/report mode600. The public report contains numeric samples and aggregate exit/limit status; argv/stdout/stderr stay private. Never provide credentials in argv. Selected environment metadata is limited to `RAYON_NUM_THREADS`, `OMP_NUM_THREADS`, and `TZ`.

`Popen(start_new_session=True)` establishes a new owned process group even when the runner was already a session/group leader. The monitor tracks group members, discovered descendants and their process birth identity; group cleanup does not require `ps` to succeed. Inspection failure preserves a failure report, terminates/reaps the direct child and marks cleanup status unknown. Only that established owned group and verified owned descendants may be signaled. The helper never signals unrelated process groups.

These are sampled limits (default0.2s), not hard real-time OS quotas. Short spikes or a daemon that escapes ancestry/group tracking between polls may be missed; foreground jobs must not daemonize. Owned-tree RSS is `ps` KiB converted to bytes and summed, including shared pages counted separately by the OS. It excludes runner/inspection RSS and is not requested heap allocation. Storage is positive logical file-size growth per supplied root (including private logs), not physical disk blocks; temporary files deleted between polls may be missed. Baseline target bytes are recorded before launch; existing target contents are excluded from growth. Report metadata is written after the measured command. No benchmark authorization is conveyed by owning this helper.

All protected artifacts remain ignored. Do not stage `__pycache__` or anything under `artifacts/`. Stage only reviewed explicit public helper, test, experiment and report paths.
