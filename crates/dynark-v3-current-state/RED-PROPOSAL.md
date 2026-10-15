# V3 finalized deployment verifier: first RED

Source-only scaffold. No Cargo, lock generation, helper, RPC or proof run.
This deliberately narrows the first gate to deployment/finality/config PDA
admission. It does not claim source/publisher signatures or application state
authentication. Independent source/publisher signatures are the next separate
slice after this deployment gate; the generic existing vectors use a different
registry/config mapping and must not be relabeled as application fixtures.

## Acyclic dependency boundary

Direct dependencies: credential-registry (path ../credential-registry),
zk-fresh-program (path ../../program, no-entrypoint), solana-program =2.3.0,
sha2 0.10, bincode =1.3.3. There is NO dynark-native-client dependency. Native may
later depend on this crate after separate M2 review. The registry dependency is
reserved for the signature slice, with no changed registry API in this scaffold.
No HTTP crate is introduced yet. The production constructor always rejects.

Public types have private capability fields/read-only getters, no serde, Clone,
Debug, public transport trait or caller-JSON conversion. VerifiedDeployment is
expressly non-authorizing. AuthenticatedV3Current has no minting operation.
ConfiguredVerifier's transport and injection point are private; the scripted
implementation exists only under cfg(test). No existing crate is edited.

## Exact intended failure and fixture provenance

One unit test: tests::finalized_deployment_pda_gate. It creates public synthetic
Config bytes using the current program Config codec and identity constants,
independently derives the config and upgradeable-programdata PDAs, serializes
the official upgradeable loader states and Clock, and checks Config roundtrip.
It supplies a pinned synthetic ELF image, loader/programdata owner/linkage,
upgrade authority, genesis, root-version-zero Config and finalized batch slot.
The image is NOT a deployed program or real ELF execution test.

The private scripted transport asserts exact requested keys, Finalized commitment
and minimum_context_slot=90, and permits exactly one response. The test checks
the genesis/accounts call trace before its final assertion. verify_deployment
unconditionally returns Unavailable after those calls: final expected Ok(100)
versus actual Err(Unavailable) is the intentional RED. No capability is minted.

The follow-up GREEN must check genesis, loader/state/linkage and expected upgrade
authority, exact ELF digest/length, config owner/PDA/codec/identity, ordered exact
account set, finalized context floor, Clock owner/data/slot and bounded use age.
No mocked success may claim chain authorization. Production transport/finality
trust and complete source/publisher/current-state checks have separate gates.

## Bounded gates; ROOT runs only after separate grants

First generate a package-local lock OFFLINE, without compiling. Before running,
ROOT verifies source SHA pins, package Cargo.lock absent, target path absent,
and all monitor/report paths fresh. Parent directories are private0700; use
umask077. No automatic retry or positive implementation after RED.

From /Users/anishnarang/Zk-refresh, lock command:

```sh
python3 results/dynark/phase-2/bootstrap/bounded_runner.py --owner m3-v3-current-lock-001 --cwd /Users/anishnarang/Zk-refresh --private-output /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-current-lock-001 --report /Users/anishnarang/Zk-refresh/results/dynark/part5/v3-current-lock-001.json --runtime-seconds 30 --rss-bytes 268435456 --storage-bytes 4194304 --storage-path /Users/anishnarang/Zk-refresh/crates/dynark-v3-current-state/Cargo.lock -- /Users/anishnarang/.cargo/bin/cargo generate-lockfile --offline --manifest-path /Users/anishnarang/Zk-refresh/crates/dynark-v3-current-state/Cargo.toml
```

Report lock SHA and offline dependency closure before RED review. Offline cache
failure is a gate failure; no network fallback. After ROOT pins the lock:

```sh
python3 results/dynark/phase-2/bootstrap/bounded_runner.py --owner m3-v3-current-red-001 --cwd /Users/anishnarang/Zk-refresh --private-output /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-current-red-001 --report /Users/anishnarang/Zk-refresh/results/dynark/part5/v3-current-red-001.json --runtime-seconds 180 --rss-bytes 2147483648 --storage-bytes 536870912 --storage-path /Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-current-target-001 -- /usr/bin/env CARGO_BUILD_JOBS=1 RAYON_NUM_THREADS=4 OMP_NUM_THREADS=1 CARGO_TARGET_DIR=/Users/anishnarang/Zk-refresh/artifacts/dynark/part5/v3-current-target-001 /Users/anishnarang/.cargo/bin/cargo test --offline --locked --manifest-path /Users/anishnarang/Zk-refresh/crates/dynark-v3-current-state/Cargo.toml --lib tests::finalized_deployment_pda_gate -- --exact --test-threads=1
```

Require exactly one executed final assertion failure, exit101, no cap stop,
compile error or residual process. Record elapsed/RSS/storage/logs/source pins.

## Explicit remaining security gates

- A configured bounded real RPC transport with trusted endpoint/genesis/finality
  policy must replace the unavailable production constructor. Public mocks stay
  impossible. Finalized RPC is trusted-node evidence, not a light-client proof.
- Check full Config/Issuer/Request/Queue/PublisherHead and relevant account state
  in one coherent finalized context; verify exact lifecycle epochs, action and
  membership/path, latest committed envelope and predecessor provenance.
- Add independent signed application-scope source/publisher fixtures, including
  Scope.registry=Scope.config; verify signed bytes and exact onchain commitments.
- Use strict now<source.valid_until for authorization, with expiry-1/equality/+1
  regressions. Existing source fact-authentication inclusivity does not grant use.
- Authenticate source catch-up/checkpoint provenance; the current source API's
  fresh-observation check cannot replay expired historical facts on restart.
- Fresh finalized onchain head is the antirollback anchor on restart. Cached
  JSON, signed/HMAC files or caller public trait implementations cannot replace it.
- Native product integration must consume the final opaque capability; the
  existing arbitrary AuthenticatedV3State trait remains insufficient by itself.
