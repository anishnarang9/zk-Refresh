# V3 matched campaign method amendment 1

Registered before the multi-count campaign and while the separate k=1 engineering
pilot was still running. The pilot keeps its original freeze and is not pooled
with the campaign. This amendment changes the method only where the proof-runner
source review found work that would distort the Full comparator.

All modes must authenticate the same source history and execution-current
accounts, and validate every complete witness that they consume. The Full and
coalesced Full modes do not construct DYNARK deltas, Anchor bindings, updating
material, or algebraic transition/support preflights. The Anchor mode pays for
those operations. Authenticated registry-transition checking is common work;
Anchor's algebraic transition validation is additional work. The k=1 pilot's
Full mode did perform an Anchor-support preflight, so its timing remains
engineering evidence under its original protocol, not a campaign observation.

Count `k` as distinct authenticated root changes for one unconsumed exact
request. A source-status or head refresh without a root change does not
increase `k`. For `k > 0`, the Anchor uses one immutable R0 base; each later
proof uses the cumulative R0-to-current delta, including after prior refreshes.
At `k = 0`, both modes make and ordinary-verify one Full proof; Anchor still
pays its eager public and private preparation. The coalesced Full control
authenticates the same complete history, waits for the final state, and then
generates, validates and proves one final witness, with no preliminary R0
proof. Record its idle time separately from active work.

Keep the registered four matched pairs at each `k = 0, 1, 2, 5, 10`. Add four
coalesced Full controls at each count, using the corresponding frozen request
and root sequence. Their execution order within the four repetitions is
Full/Anchor/Coalesced, Anchor/Coalesced/Full,
Full/Coalesced/Anchor, Coalesced/Anchor/Full. All three modes start from a
fresh clone of the same pre-execution ledger. Coalesced Full is an operational
control, not a replacement for the preregistered within-pair break-even rule.
The 36-hour campaign envelope, per-session caps, failed-trial preservation,
and target of 20% total savings remain unchanged.

The current two-certificate adjacent-leaf transition and request-bound proof
context only support one root change. Multi-count timing may start only after
the expanded authenticated transition sequence, proof context and exact
application effect path pass their own focused correctness gates and are
frozen. Synthetic root arithmetic does not satisfy this prerequisite.
