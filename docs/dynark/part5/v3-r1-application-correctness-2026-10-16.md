# V3 request-bound R1 application correctness

Status: local training demonstration, with finalized application effects independently reconciled. The supervised branches have `branch_verified: true` and outer resource monitors report no stop or surviving owned process. Their overall supervisor and bounded-runner statuses are `failed` because the local validator returned `-SIGINT` during cleanup. Neither branched ledger is approved for reuse. This is not a complete-session savings or heldout-credential result.

## Exact application and proof identities

| Item | Pinned value |
| --- | --- |
| Loaded v3 ELF SHA-256 | `298c8c84c504038bafea858370a42872f03b016a09adbadd396dd4322991b99c` |
| Program | `3nqhgGtpPD8UyYMYtYFb4nBLntsW36gDUnzPXh5j9JNi` |
| Finalized request | `G999QVUEZLpGXML6vySxddrggkS1mA7rCFLVcwUcaG2w` |
| R0 stage report SHA-256 | `7cf748aad7a701c0ce8329b191d486c7658b07f823eb152e4ab076a213adf33c` |
| Signed unrelated R1 transition report SHA-256 | `ce65958081bb85e0d152c9370aaa425e07df6efd13a9f03a5b93e65544b4f40c` |
| R0 root | `1d0e3cf7726a2f412557c764da26c8dd1a34638e09963b2a63f23e15d6fe4a9c` |
| R1 root | `12ce7aee2c5c3f0dfd4864b2e07fdfc462debf8907cc30a0950c3fe8295c7a22` |
| Request-bound Full/Anchor proof report SHA-256 | `5224fa82213866b6f9864263ba2f065a19a776a8c4bca5ec4c84b959e8efe295` |
| R0 Full Solana wire SHA-256 | `d69955194258733260eecd49ef154aad5a81868d92f0076106da6c9face663cd` |
| R1 Anchor Solana wire SHA-256 | `2eef8e7173fb030f3eec612ef930d1fa6cdcecb37e32f9718c818a802acb1fec` |
| Identical stopped-R1 clone inventory SHA-256 | `47abe2ebc19b51664cca909191392e29f721318125cd925694821e0799aa0c63` |

The two ordinary proofs use the same circuit, setup, VK, credential and finalized action. Their six public fields differ only in `root`. The pinned proof runner ordinary-verified both; the v3 adapter and program host independently accepted the encoded wires. That host verification did not authorize a request. The R1 transition came from a signed source observation revoking the adjacent, unrelated certificate. Both branch clones began with the same five finalized R1 account bytes and the request unconsumed. The clone helper excluded only a checked, connection-refusing `admin.rpc` socket left by the stopped validator; all 63 persistent entries matched.

## Finalized branches

| Branch | Exact transaction sequence and results | Finalized state |
| --- | --- | --- |
| R1 Anchor | signed current status; bind current head; stale R0 Full rejected `713`; wrong action rejected `712`; invalid proof rejected `714`; R1 Anchor accepted; replay rejected `707` | Slot 181; exactly one queue append and request consumption. Private branch report SHA-256 `43a93f859dd14698fc69d74ed14dd3b6dfd3f1b88c15c37afec5b841b411caf6`. |
| R2 own revocation | publish R2 root; signed own-revocation status; bind current head; stale R0 Full rejected `713`; R1 Anchor rejected `713` | Slot 148; zero effects, request and queue unchanged. Independent tree reconstruction found no active R2 path for the holder. Private branch report SHA-256 `ab1416ff335dd73432c1c43e03671e6070941f6ea8c93b487a8273ed08db5586`. |

The supervisors independently checked the source Ed25519 signatures, loaded program account and ELF identity, exact transaction errors, finalized account byte hashes and effect bytes. The Anchor branch config SHA-256 is `c9ad1989af3fdae2fc972d158d7cc3065b38f54312a67944d778f5ad1171976f`; the own-revocation config SHA-256 is `6a6dae27abec50bc2e5e986e07367cd4c5b20a8c73513ba32d53b50429bc20b3`. The protected private reports, proof wires, signer material and ledgers are ignored by Git and retained locally; this pushed note pins their identities but cannot recreate the private issuer/holder material by itself.

To replay locally, first verify the listed SHA-256 pins and the reviewed stopped-R1 transition status. Use `harness/tests/queue_v3_clone_ledger.py` for two fresh owner-only ledger destinations, `tools/part5/create_v3_branch_config.py` for each mode with fresh output/control paths, and run `harness/tests/queue_v3_local_branch.py` under `results/dynark/phase-2/bootstrap/bounded_runner.py` with the registered 180-second, 4-GiB RSS and 256-MiB growth limits. The branch supervisor requires `P5_V3_BRANCH_SUPERVISOR=reviewed-r1-clone`; its config builder pins the exact source evidence, wires and compiled runner. Reuse of an already started clone is disallowed without a new inventory and finalized-state review.

## Remaining qualification

The native client's `open_full` path remains closed, the one-credential training branch is not the frozen unseen-credential cohort, and the local source/ledger model is not devnet or a production revocation history. No matched whole-session Full-versus-DYNARK trials have been run. The paid proof session took 1,215.290 seconds, including 477.599 seconds of shared public preparation and 689.426 seconds of private Anchor preparation; the 0.984-second warm refresh/verify stage alone is not a total application benefit. The registered matched-session protocol controls the next economics gate.
