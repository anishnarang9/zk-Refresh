# V3 proof runner: source-only GREEN review

The accepted one-test RED gate ran the intended admission assertion and failed
deliberately (exit101,44.057s). This change implements that path and the reviewed
proof-only driver. **No GREEN Cargo command, setup, packet preparation, proof or
heldout generation has run.** ROOT must grant each bounded execution separately.

## Exact proposed source freeze

Paths in this table are relative to the repository root.

| File | SHA256 |
| --- | --- |
| `circuits/credential-v3-bounded/qualification/proof-runner-v1/Cargo.toml` | `7768c6770b1d6dad8bdb47641d38e5d655d7dd167f8036e07884b26dbf8d3d93` |
| `circuits/credential-v3-bounded/qualification/proof-runner-v1/Cargo.lock` | `a3d0449b242fe6ac73f3c167d0a7f743457f7e420c428b37a25baed9302ddfcd` |
| `circuits/credential-v3-bounded/qualification/proof-runner-v1/src/main.rs` | `d72dddc72d84a20c3f870dcd789bc5c2c4b509a922ff670c5279a9618b9da2a9` |
| `circuits/credential-v3-bounded/qualification/proof-runner-v1/src/artifacts.rs` | `5a870be3a88d6f6854887ff29ea4441f66ae9e24d8a7701feebfc078379d29aa` |
| `circuits/credential-v3-bounded/qualification/proof-runner-v1/src/context.rs` | `b11ff7786729ffcb14664dd257a3d46ee289cb087fef1a9475cfe73d345a454e` |
| `circuits/credential-v3-bounded/qualification/proof-runner-v1/src/ordinary.rs` | `f687498f55e64c16dd0f448338d360d20244b77553fb0616198cb064e2d26c46` |
| `tools/part5/prepare_proof_inputs_v1.py` | `dacb2e8ff1ca77b35671da1b490c09650ffd9081449667febba2a1a24302b23c` |
| `tools/part5/tests/test_proof_inputs.py` | `a8c1130a1d8385f9f821f709270f86d61d425564b182cb1006ab5367bc4c5ef7` |

Compiler-embedded proof source closure identity:
`9ad82d2930c11f29a7876121e57b440f6bdc37c8e3b68cd6dec389124d044e70`.
It hashes tag `dynark-v3-proof/source-closure/v1`, then the files in order
main.rs,artifacts.rs,context.rs,ordinary.rs,Cargo.lock,Cargo.toml, each framed by
BE32 filename byte length, filename bytes, BE64 content length, content bytes.
This is provenance; ROOT's separately pinned executable remains the launch
authority. Original setup provenance is checked against the accepted setup
source/lock/binary, never against this new proof executable.

## Changes and boundaries

- `artifacts.rs` adapts the accepted bounded canonical loaders and exact Original
  descriptor/census. The externally pinned setup/report authenticates imported
  PK bytes before unchecked codec parsing, followed immediately by one complete
  `PublicPackage::new` admission. The ordinary VK must be its exact seven-IC
  projection. Public pinned profile/compiler files allow0644/0600; private files
  require0600 and protected output/setup directories0700.
- The preparer streams the pinned `.sym` and requires all751 input symbols,
  unique retained indices, exact public indices1..6, canonical decimal strings
  and input-to-WTNS matches. It selects accepted report cases by classification
  and exact names, independent of their interleaved array positions. This does
  not replace native complete relation checks.
- `context.rs` derives credential identity from actual matched signed TBS,
  issuerHash/AKI enrollment/version, policyHash, package/profile/schema and holder
  key embedded in TBS. Action identity binds actual actionHash and policy/version.
  Retry admission requires unchanged credential/action/policy/allocation epoch,
  a newer different root, identical nonroot public fields and private inputs
  except exactly one Merkle sibling. Complete WTNS deltas and target relations
  are checked before any UpdatingMaterial or private Anchor preparation.
- `ordinary.rs` counts executed proofs separately from ordinary checks, checks
  canonical128-byte proofs and six ordered public fields, and rejects each
  altered public and cross-root statement. Full rerandomization is explicit.
- The main driver loads one shared package, preflights all pairs sequentially,
  then executes one selected mode. Shared public UpdatingMaterial is prepared
  once per Anchor process and charged to total paid cost. Every private Anchor
  is new, bound to its own credential/action/root and dropped before the next.
  Engine binding mutations, replay, local cross-credential and policy/allocation
  changes must reject. Durable private stage markers bracket material/Anchor
  preparation and updates; they preserve the current operation on failure.
- Anchor modes additionally require the ROOT-pinned successful Full report for
  the exact packet and computed cohort counts. CLI:
  `full-corpus PACKET PACKET_SHA FRESH_OUT`, or
  `anchor-pilot|anchor-corpus PACKET PACKET_SHA FULL_REPORT FULL_SHA FRESH_OUT`.
- Training remains exactly nine named pairs. `heldout-v1` permits1..16 fresh
  pairs under the same setup, without a training credential allowlist. The ROOT
  freeze receipt pins the final proof binary/source, input preparer, client,
  adapter and app hashes. Input ctime following its timestamp is an operational
  check only: ROOT's independent key-generation/import receipt is still needed
  to substantiate genuinely unseen credentials. No heldout artifacts exist yet;
  any subsequent source change requires a new freeze and fresh cohort.

Qualification uses synthetic issuer/policy/allocation authority metadata and
signed synthetic action fields. It does not establish app request-v2 binding,
issuer enrollment/status policy, loaded app verification, durable private cache
reuse, production ceremony or production signer security. Ordinary verification
cannot distinguish holders with identical public statements; captured private
Anchor/context bindings provide local cache isolation. No cache or UpdatingMaterial
from v2 is imported. Dynamic/Selective and incremental witnesses are disabled.

## Narrow first verification proposal

Rustfmt parsed all four modules. Three lightweight Python toy regressions passed
in0.004s with `python3 -B -m unittest tools.part5.tests.test_proof_inputs -v`:
symbol mapping ambiguity/absence, canonical scalar/input shape, and all-coordinate
WTNS input binding. These toy tests make no relation-satisfaction claim.

The pending native gate runs **15 unit tests** only: positive root admission,
max-version guard, unknown/setup modes; credential/action/policy/allocation/root
mutations; canonical input shapes/BE encoding; derived identity sensitivity;
all-coordinate input binding; root-only private mutation rejection; bounded
training/heldout selection; canonical WTNS/six publics; actual small accepted
setup-manifest provenance; tiny PK hash/trailing-byte boundary; private loader
hash/mode/symlink/size; exact proof-versus-check accounting. It does not load the
large PK, generate keys, prepare updating material or generate proofs.

Proposed exact command after a separate ROOT grant (not executed):

```sh
env CARGO_BUILD_JOBS=1 RAYON_NUM_THREADS=4 OMP_NUM_THREADS=1 CARGO_TARGET_DIR=/Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-proof-runner-v1-build-001 python3 -B /Users/anishnarang/Zk-refresh/results/dynark/phase-2/bootstrap/bounded_runner.py --owner part5-v3-proof-runner-v1-green-001 --cwd /Users/anishnarang/Zk-refresh --private-output /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-proof-runner-v1-green-monitor-001 --report /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-proof-runner-v1-green-bounded-001.json --runtime-seconds 180 --rss-bytes 2147483648 --storage-bytes 536870912 --storage-path /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-proof-runner-v1-build-001 --poll-seconds 0.25 -- /Users/anishnarang/.cargo/bin/cargo test --offline --locked --manifest-path /Users/anishnarang/Zk-refresh/circuits/credential-v3-bounded/qualification/proof-runner-v1/Cargo.toml -- --test-threads=1
```

The monitor/report paths are absent at this review. Recheck source pins and path
freshness immediately before execution. Expect10–60s using the existing separate
target, below1GiB RSS and100MiB new output; enforce180s/2GiB/512MiB caps regardless.
Require all15 tests actually execute and pass, no cap stop and no residual owned
process. Preserve warnings and receipt hashes. Stop on compile/test/resource
failure for source review, without retry or release/proof launch.

After accepted units, ROOT separately reviews release build, protected packet
creation, Full corpus, Anchor pilot and all-nine Anchor grants from the main
proposal. Their caps are unchanged. Future heldout proof grants need explicit
cohort-sized caps rather than assuming the training timing applies.

The original setup source and frozen executable were rehashed unchanged:
`2ac7f3f2b81627800ac9e5c13b0318bb38fde2d46354f94437b4b76d532e8cb6`
and `a32006a2d73edf8c42202a78e4b6ab6ff91ff5f84090820e31cde65680b659e5`.
