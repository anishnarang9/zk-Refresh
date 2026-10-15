# Private v3 queue effect gate

The private `apply_execute_effect` helper prepares an exact encoded queue append
and request consumption. It checks finalized state, deadline, matching config,
queue capacity and replay. It acquires both mutable account-data borrows and
checks both destination lengths before either copy, so a failed second borrow
cannot leave a partial append. The helper has no public entry point and is not
called by Execute.

The tests-first positive case initially failed with `Unavailable` versus
`Ok(())`. The GREEN run passed both synthetic effect tests and the complete
113-test program suite under a 300-second, 3-GiB sampled RSS, 1-GiB storage
growth bound. It took 21.26 seconds with sampled peak owned-tree RSS of
209,158,144 bytes. The held-borrow test demonstrates unchanged request and
queue bytes on a failed second mutable borrow.

Evidence: `results/dynark/part5/v3-effect-red-001.json` and
`v3-effect-green-001.json`. These tests do not establish certificate, issuer,
current-root or proof authorization. Execute still verifies preflight and the
ordinary proof, then returns `Unavailable`. Wiring this helper requires a
genuine Full proof for the exact finalized request, a positive Execute gate
and loaded v3 application ELF evidence.
