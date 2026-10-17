# Loaded v3 Full queue effect: training gate

This is one controlled-issuer **training** request at root R0, not the held-out
acceptance or DYNARK benefit result. The v3 ELF loaded in a loopback Solana
validator accepted a genuine request-bound ordinary Groth16 Full proof and
atomically consumed the request and appended its address to the protected queue.
The separate current-root refresh, holder revocation, and matched total-cost
gates remain open.

## Pinned run and result

| Item | Observed value |
| --- | --- |
| Code | `c38ec2f` Execute transport; `bb65e6f` independent supervisor |
| Loaded program | `3nqhgGtpPD8UyYMYtYFb4nBLntsW36gDUnzPXh5j9JNi` |
| Genesis | `DdZNmGzXCu8YPfVpsoop3QcSE23EtXf8SzeuHgyheA4M` |
| Loaded ELF SHA-256 | `298c8c84c504038bafea858370a42872f03b016a09adbadd396dd4322991b99c` |
| Staged finalized slot | 44 |
| Staged report SHA-256 | `7d29fb2b5d8e16deb065ee61eceee1fdc969b11471af09baabc14de86b53004f` |
| Full Solana wire SHA-256 | `8c59b0691b0ea69188ff8712526b9a74831d96dbe40c03d167b070c8925fe5b6` |
| Execute finalized slot | 145 |
| Execute report SHA-256 | `7086b608888aca6424ce128ff3a4d5a505c4dcf89ec6cf71d1868c553284f274` |
| Supervisor status SHA-256 | `0e64b98591995a234b76ab529012c0a8925754c0d906a8cfc743fa39bb868950` |
| Bounded runner report SHA-256 | `3a1e88a766188abdfe073af7318da5cbb47bea9598b303adaaa77784ddb240f0` |

The private artifacts are ignored and owner-only at
`artifacts/dynark/part5/application-v3-local-stage-private-001/`,
`artifacts/dynark/part5/v3-bound-local-full-001/`, and
`artifacts/dynark/part5/application-v3-local-execute-private-006/`. Their
hashes above identify this observation but do not make the private keys or
proof redistributable. A fresh reproducible issuance and execution recipe is
still required for the final submission.

The staged request bytes and the public V3F1/V3F2 action were rebuilt from the
loaded config and finalized request. The complete witness and independent R1CS
check passed in bounded runs (3.949 and 3.299 seconds). The ordinary Full proof
run passed in 46.929 seconds; the adapter and host verifier passed in a separate
3.957-second run. These are separate stage durations, **not** an end-to-end
session measurement.

The loaded test submitted a refreshed active source observation and publication
head, then observed these transactions in its private journal:

| Attempt | Result | Compute units | Transaction bytes |
| --- | --- | ---: | ---: |
| Wrong action | custom error 712 | 56,208 | 825 |
| Malformed proof | custom error 714 | 56,660 | 825 |
| Exact Full Execute | success | 191,204 | 825 |
| Replay in a new transaction | custom error 707 | 51,410 | 825 |

At finalized commitment, the supervisor independently compared all five
account hashes and bytes to the retained artifacts. It checked that the
request state alone changed from finalized to consumed, the queue count became
one and its first entry was exactly this request, and the config was unchanged.
The Rust runner also checked the refreshed issuer and head and unchanged bytes
after both rejected Execute attempts. The supervisor recorded
`effect_verified=true`, `application_effect=true`, and `effect_count=1`.

The bounded Execute tree ran for 49.450 seconds, sampled peak RSS 631,685,120
bytes and peak storage growth 86,863,702 bytes, with no resource stop or
remaining owned process. The validator returned `-2` on SIGINT instead of a
clean zero exit. Consequently, the supervisor's overall status is `failed`
and `ledger_reuse_requires_review=true` despite the independently finalized
application effect. Any reuse must reattest the loaded ELF, genesis, and exact
finalized state. Early preflight attempts produced no submitted transaction;
the successful effect was attempt `006`.

This gate does not establish a DYNARK refresh, a currently revoked holder's
rejection, a held-out credential result, or an economic win.
