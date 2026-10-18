"""Pure acceptance checks shared by loaded v3 negative supervisors.

These helpers inspect already-parsed clocks, RPC errors, account bytes, and
request addresses. They do not contact a validator or process proof material.
"""

ACCOUNT_NAMES = ("config", "issuer", "head", "request", "queue")
STATUS_MAX_AGE = 300
QUEUE_CAPACITY = 64


def _timestamp(name, value):
    if type(value) is not int or value < 0:
        raise ValueError(name + " must be a nonnegative integer timestamp")
    return value


def check_expired_status(*, observed_at, expires_at, now,
                         status_active, issuer_active, head_bound,
                         request_live, full_wire_valid):
    """Accept only the expired-status negative's otherwise-valid setup."""
    observed_at = _timestamp("observed_at", observed_at)
    expires_at = _timestamp("expires_at", expires_at)
    now = _timestamp("now", now)
    for name, value in (("status_active", status_active),
                        ("issuer_active", issuer_active),
                        ("head_bound", head_bound),
                        ("request_live", request_live),
                        ("full_wire_valid", full_wire_valid)):
        if type(value) is not bool or not value:
            raise ValueError(name + " precondition must be true")
    if expires_at <= observed_at:
        raise ValueError("signed expiry must follow observation time")
    if expires_at - observed_at > STATUS_MAX_AGE:
        raise ValueError("signed status lifetime exceeds maximum age")
    if now < expires_at:
        raise ValueError("signed issuer status has not expired at submit clock")
    if now - observed_at > STATUS_MAX_AGE:
        raise ValueError("issuer observation is too old for a clean expired-status negative")


def check_execute_error(rpc_error, custom_error):
    """Require finalized RPC's parsed error to be exactly Execute@1/custom."""
    if type(custom_error) is not int or custom_error not in (705, 708):
        raise ValueError("only status 705 or capacity 708 is accepted")
    expected = {"InstructionError": [1, {"Custom": custom_error}]}
    if type(rpc_error) is not dict or rpc_error != expected:
        raise ValueError("finalized Execute error does not match exact instruction/custom error")


def check_application_accounts_unchanged(before, after):
    """Require exactly five ordered application account names and equal bytes."""
    if type(before) is not dict or type(after) is not dict:
        raise ValueError("application snapshots must be account-to-bytes dictionaries")
    if tuple(before) != ACCOUNT_NAMES or tuple(after) != ACCOUNT_NAMES:
        raise ValueError("application snapshots must contain the five ordered accounts")
    for name in ACCOUNT_NAMES:
        if type(before[name]) is not bytes or type(after[name]) is not bytes:
            raise ValueError(name + " snapshot must be bytes")
        if before[name] != after[name]:
            raise ValueError(name + " application account changed after rejection")


def check_full_queue(before_addresses, after_addresses, request65):
    """Require a stable full queue of 64 distinct requests excluding request65."""
    if type(request65) is not str or not request65:
        raise ValueError("65th request address must be a nonempty string")
    for label, addresses in (("pre-submit", before_addresses),
                             ("post-submit", after_addresses)):
        if type(addresses) not in (list, tuple):
            raise ValueError(label + " queue addresses must be a list or tuple")
        if len(addresses) != QUEUE_CAPACITY:
            raise ValueError(label + " queue must contain exactly 64 requests")
        if any(type(address) is not str or not address for address in addresses):
            raise ValueError(label + " queue contains an invalid request address")
        if len(set(addresses)) != QUEUE_CAPACITY:
            raise ValueError(label + " queue entries must be distinct")
        if request65 in addresses:
            raise ValueError("65th request must be absent from the queue")
    if set(before_addresses) != set(after_addresses):
        raise ValueError("queue membership changed after capacity rejection")


def check_finalized_fill_history(fill_rows, before_addresses, request65):
    """Validate the ordered 64 successful finalized fills that created a full queue."""
    row_fields = {"request_address", "signature", "slot", "finalized",
                  "consumed", "queue_after_addresses"}
    if type(request65) is not str or not request65:
        raise ValueError("65th request address must be a nonempty string")
    if type(fill_rows) is not list or len(fill_rows) != QUEUE_CAPACITY:
        raise ValueError("fill history must contain exactly 64 rows")
    previous = []
    seen_requests = set()
    for index, row in enumerate(fill_rows):
        if type(row) is not dict or set(row) != row_fields:
            raise ValueError("fill row has an unknown or missing field")
        request = row["request_address"]
        if type(request) is not str or not request:
            raise ValueError("fill row has an invalid request address")
        if request == request65:
            raise ValueError("65th request cannot be one of the successful fills")
        if request in seen_requests:
            raise ValueError("fill request addresses must be distinct")
        if type(row["signature"]) is not str or not row["signature"]:
            raise ValueError("fill signature must be a nonempty string")
        if type(row["slot"]) is not int or row["slot"] <= 0:
            raise ValueError("fill slot must be a positive integer")
        if type(row["finalized"]) is not bool or not row["finalized"]:
            raise ValueError("every fill must be finalized")
        if type(row["consumed"]) is not bool or not row["consumed"]:
            raise ValueError("every fill request must be consumed")
        queue_after = row["queue_after_addresses"]
        expected = previous + [request]
        if type(queue_after) is not list or queue_after != expected:
            raise ValueError("fill order must append exactly its request to the queue")
        if request65 in queue_after:
            raise ValueError("65th request must be absent from fill queue history")
        seen_requests.add(request)
        previous = expected
    if type(before_addresses) not in (list, tuple):
        raise ValueError("pre-submit queue addresses must be a list or tuple")
    if list(before_addresses) != previous:
        raise ValueError("fill history must produce the pre-submit queue in order")
