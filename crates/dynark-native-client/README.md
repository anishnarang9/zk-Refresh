# Native witness/client component, development v1 and v2 Full

This crate packages the accepted v1 witness evaluator, an additive exact-package
`credential-v2-dev` Full path, and the local lifecycle boundary. The Part 5
focused Rust run passed 10 fast tests (five library and five v2 contract tests);
the Node v2 canonical-input checks also passed. The first bounded real-v2
integration run compiled, then reached its 300-second runtime cap during checked
proving-key import. It never reached witness generation or proving; that gate
remains unpassed. Its report is
`results/dynark/part5/native-v2-full-001-bounded.json`.
No application throughput or readiness claim follows from the fast tests.

The component contract is `docs/dynark/pre-part5/component-contracts.md`.
`NativePackageManifest` carries a mandatory nonzero opaque ordinary-VK digest
from the selected trusted manifest. It is distinct from the extended engine VK
digest inside `PackageIdentity`; M5 owns its canonical encoding/domain tag and
checks it during wire conversion. M2 does not invent another ordinary-VK hash.
`WitnessBinding` holds exact package/profile/mapping, credential and issuer
identity/version, action, policy, root/version and local generation. All field
words and deltas at this native boundary are canonical little-endian Fr. The
action binding is the application's canonical big-endian actionHash; its reverse
must equal public coordinate 5. M5 owns the final big-endian wire adapter.

## Native path

1. A trusted M3 `CredentialProfile` adapter admits the supported credential. A
   trusted M4 `AuthenticatedTarget` adapter binds its private input and public
   values to that identity, authenticates membership/status/order and checks
   current policy, revocation, expiry and issuer freshness. The trait is a trust
   boundary. Implementing it does not itself prove authentication.
2. `WitnessContext::open` starts v1 with full generation and complete relation
   validation. `WitnessContext::open_v2` admits only the pinned development v2
   package, profile and semantic schema through `V2FullManifest`. It also
   requires Full generation and complete relation validation. Caller-selected
   witness hashes cannot create trusted baselines.
3. V2 `prepare` always requests Full; a non-Full candidate fails closed. V2
   bindings require the zero mapping sentinel because no incremental mapping
   is qualified. V1 `prepare` uses a single sibling suffix only when context
   bindings permit reuse. The unchanged evaluator rejects every unsupported input change; valid
   unsupported shapes use the original full WASM generator. Malformed input,
   source/mapping failure, inconsistent root or corrupted baseline fails closed.
4. Every candidate receives full canonical, public and relation validation.
   Sorted nonzero witness/public deltas are computed in the native boundary.
   `commit` requires unchanged base binding/generation and the exact newly
   authenticated current target. Cancelled, superseded and invalidated results
   cannot replace installed state.
5. `prove_full` uses caller CSPRNG and independently verifies the resulting
   ordinary proof. Additional proof modes remain gated behind qualification of
   their exact native path. `ensure_submission_current` checks the freshly
   authenticated current target again before M5 encoding/submission.

`Client` is a pure lifecycle coordinator. Its events represent trusted backend
completion; calling those events does not create a proof or execute an effect.
`authenticate` connects M4 errors to pause/invalidation. The caller uses its
generation to wrap each M4 target and cancels pending controls when newer state
arrives. A transaction's uncertain outcome fences retries until the exact action
receipt is confirmed or authoritatively absent. Receipt absence must come from
the submission adapter's reconciled transport, not from a timeout. Restart begins
at `RebuildRequired`; no persisted private state is trusted by this crate.

## Runtime and security boundary

`NativeWitnessGenerator` needs absolute, pinned runtime/script/WASM/calculator
paths and an existing mode-0700 private work directory.
`NativeV2FullWitnessGenerator` requires the separate compiled-in v2 Full worker,
exact v2 WASM and calculator pins. It checks canonical decimal strings, exact
v2 input dimensions and field/byte/limb bounds, and copies verified WASM and
calculator bytes into each private invocation directory. `V2FullManifest` keeps
the tagged ordinary VK digest, raw VK-file SHA-256 and engine extended VK
commitment separately named; `ProofResult::v2_manifest` retains that binding.
Trusted installation
directories, Python/Node standard runtime dependencies and OS process execution
are outside the attacker-replaceable cache threat model. Executable digest
verification is not a reproduced runtime build or immunity to same-user code
replacement between verification and execution.

Worker scripts are pinned to their compiled-in bytes. Accepted evaluator copies
are byte-identical historical public source; verified source bytes are compiled
directly, avoiding a cached Python bytecode substitution. The original v1 mapping
and constants remain at their historically pinned workspace paths. This first
package requires the authoritative checkout's historical public artifacts;
relocatable bundles remain a separate release gate.

Each request owns one child at a time, uses no shell, discards stdout/stderr, and
has a caller deadline/cancellation token. Cancellation kills and joins the child.
Private input is bounded to 64 KiB; v1 WTNS is exactly 20,594,092 bytes and
v2 WTNS is exactly 24,611,532 bytes (769,108 coordinates). Request
directories/files use 0700/0600 and are removed on success/error/cancellation.
Process crash can leave a private directory for explicit startup cleanup; no
crash-atomic cache or durable-fsync claim is made. Request files are temporary
private artifacts, not public reports.

The enclosing supervisor enforces workload RSS/CPU/process/storage caps; byte
bounds and deadlines in this crate do not constitute a hard RSS cap. Full
relation validation and ordinary proving are existing monolithic engine calls.
Cancellation is checked before and after them; an overrun result is discarded,
but these calls cannot be interrupted internally. Context invalidation clears
retained raw input/witness buffers and drops the opaque engine assignment. This
does not claim compiler-guaranteed zeroization of all allocator copies or
side-channel resistance.

## Qualification gates

Fast tests cover generation races, exact-action receipt fencing, invalidation,
stale issuer, retry limits, worker exit/cancellation/deadline, changed code pins,
canonical field/header checks, and conservative transition routing. They use
synthetic adapters and public source, with no actual credential proof.

ROOT owns serialized execution. The next v2 gate is the ignored
`credential_v2` integration test under a separately reviewed resource grant. It
will import the existing pinned development package, generate a real Full
witness, compare the complete output to the qualified oracle, reject a corrupt
relation, and independently check randomized Full proofs and altered publics.
Preparing that test does not establish a passed gate. Existing v1 integration
evidence does not establish the new v2 native path.

V2 incremental witness generation, Dynamic, Selective and automatic mode choice
remain disabled. The separate generalizable successor profile and its corpus
are unqualified by this crate; the pinned fixed-template v2 package does not
admit arbitrary certificates. Native signer, authenticated registry/status,
request finalization, exact submission and actual queue-effect integration
remain application gates. This crate alone does not deploy or execute the
protected application effect.
