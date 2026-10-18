#!/usr/bin/env python3
"""Supervise one bounded loaded-ELF queue-capacity negative.

The Rust test entrypoint is intentionally required before any validator is
started. This file does not seed queue state or manufacture an RPC result.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from harness.tests import queue_v3_local_execute as execute
from harness.tests import queue_v3_loaded_negative_checks as checks
from harness.tests.queue_v3_clone_ledger import inventory as ledger_inventory
from tools.part5 import heldout_queue_capacity_evidence as capacity_evidence

SCOPE = "part5-v3-loaded-queue-capacity-negative"
CONFIG_SCHEMA = "part5-v3-queue-capacity-negative-supervisor-v1"
RUST_CONFIG_SCHEMA = "part5-v3-queue-capacity-negative-config-v1"
RUST_TEST = "root_pinned_queue_v3_queue_capacity_negative"
RUST_FN = "queue_capacity_negative_from_env"
QUEUE_CAPACITY = 64
ACCOUNT_NAMES = checks.ACCOUNT_NAMES
LIMITS = {"runtime_seconds": 3600, "rss_bytes": 4294967296,
          "storage_growth_bytes": 1073741824}
MAX_CONFIG_BYTES = 1024 * 1024
MAX_ACCOUNT_BYTES = 1024 * 1024
MAX_PROOF_RECEIPT_BYTES = 256 * 1024
MAX_WIRE_BYTES = 4096
MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024
ENTRYPOINT_SOURCES = (
    REPO / "harness/tests/queue_v3.rs",
    REPO / "harness/src/solana/queue_v3.rs",
)
INPUT_FIELDS = {
    "request_address", "action_sha256", "request_account", "request_sha256",
    "proof_receipt", "proof_receipt_sha256", "full_wire", "full_wire_sha256",
}

# Required producer contract for the next source wave, not an accepted schema.
# Rust emits runtime facts; the supervisor and outer runner supply their own
# process/resource/cleanup receipts after the Rust process has exited.
LOADED_REPORT_CONTRACT = {
    "status": "required_design_not_implemented",
    "identity_fields": ["runner_test", "rust_config_sha256", "cohort_id",
                        "cohort_freeze_sha256", "cohort_manifest_sha256",
                        "stage_report_sha256", "clone_receipt_sha256",
                        "program", "genesis", "genesis_sha256", "loaded_program"],
    "loaded_program_fields": list(execute.IDENTITY_FIELDS) + ["elf_match"],
    "input_rows": "65 ordered request/action/account/proof/wire pins matching the Rust config; validated Full wire for each action",
    "fills": "64 distinct ordered successful finalized Execute signatures/slots; pinned request before bytes, consumed after bytes, and each queue append",
    "rejection": "exact 65th request; finalized signature/slot; InstructionError index 1 Custom 708; unconsumed",
    "preconditions": "active config and issuer, current bound head, fresh status and live request at submit clock",
    "snapshots": "five ordered config/issuer/head/request/queue addresses and private before/after byte files; unchanged by rejection",
    "supervisor_checks": "recheck loaded ELF/genesis and finalized RPC transactions/accounts against report and pinned inputs",
    "ownership": "separate supervisor and outer bounded_runner receipts; Rust must not claim whole-tree cleanup while validator and runner are alive",
}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _hash(value, label):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(label + " must be a lowercase SHA-256")


def _opaque(value, label):
    if (type(value) is not str or not 1 <= len(value) <= 128
            or any(char.isspace() for char in value)):
        raise ValueError(label + " must be a bounded nonempty token")


def _read_pinned(path, expected, cap, label, private=False):
    _hash(expected, label + " digest")
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError(label + " must be an absolute canonical file")
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > cap:
            raise ValueError(label + " must be a bounded regular file")
        if private:
            parent = path.parent.lstat()
            if (stat.S_IMODE(parent.st_mode) != 0o700 or parent.st_uid != os.getuid()
                    or stat.S_IMODE(before.st_mode) != 0o600
                    or before.st_uid != os.getuid() or before.st_nlink != 1):
                raise ValueError(label + " must be owner-only with a private parent and one link")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            identity = lambda row: (row.st_dev, row.st_ino, row.st_size,
                                    row.st_mtime_ns, row.st_ctime_ns)
            if identity(before) != identity(opened):
                raise ValueError(label + " changed before read")
            raw = stream.read(cap + 1)
            after = os.fstat(stream.fileno())
        if (len(raw) != before.st_size or len(raw) > cap
                or identity(before) != identity(after) or _sha(raw) != expected):
            raise ValueError(label + " pin mismatch or changed during read")
    except OSError as error:
        raise ValueError(label + " unavailable") from error
    return raw


def _decode_pinned_config(path, expected):
    """Decode the exact pinned bytes; JSON whitespace/order is not normalized."""
    raw = _read_pinned(path, expected, MAX_CONFIG_BYTES, "supervisor config")
    return execute.base.decode_json(raw)


def _canonical_child(path, label):
    path = Path(path)
    root = REPO / "artifacts/dynark/part5"
    if (not path.is_absolute() or path.resolve() != path or path.parent != root
            or not path.name.startswith("queue-capacity-")):
        raise ValueError(label + " must be a direct protected artifacts child")
    return path


def _validate_inputs(inputs):
    """Pin 65 distinct externally prepared request/proof/wire inputs."""
    if type(inputs) is not list or len(inputs) != QUEUE_CAPACITY + 1:
        raise ValueError("exactly 65 request/proof/wire inputs are required")
    checked = []
    addresses, actions = set(), set()
    for index, row in enumerate(inputs):
        if type(row) is not dict or set(row) != INPUT_FIELDS:
            raise ValueError("input row has unknown or missing fields")
        _opaque(row["request_address"], "request address")
        if row["request_address"] in addresses:
            raise ValueError("request addresses must be distinct")
        addresses.add(row["request_address"])
        _hash(row["action_sha256"], "action digest")
        if row["action_sha256"] in actions:
            raise ValueError("action bindings must be distinct")
        actions.add(row["action_sha256"])
        _read_pinned(row["request_account"], row["request_sha256"],
                     MAX_ACCOUNT_BYTES, f"request {index + 1} account")
        _read_pinned(row["proof_receipt"], row["proof_receipt_sha256"],
                     MAX_PROOF_RECEIPT_BYTES, f"request {index + 1} proof receipt", private=True)
        wire = _read_pinned(row["full_wire"], row["full_wire_sha256"],
                            MAX_WIRE_BYTES, f"request {index + 1} Full wire", private=True)
        if not wire:
            raise ValueError(f"request {index + 1} Full wire is empty")
        checked.append(dict(row))
    return checked


def _rust_code(text):
    """Mask Rust strings/comments so textual decoys cannot register a test."""
    token = re.compile(r'//[^\n]*|/\*|(?:br|r)(?P<hashes>\#*)".*?"(?P=hashes)|"(?:\\.|[^"\\])*"', re.S)
    pieces, position = [], 0
    while match := token.search(text, position):
        pieces.append(text[position:match.start()])
        end = match.end()
        if match.group() == "/*":
            depth = 1
            while depth:
                boundary = re.search(r'/\*|\*/', text[end:])
                if boundary is None:
                    end = len(text)
                    break
                depth += 1 if boundary.group() == "/*" else -1
                end += boundary.end()
        masked = text[match.start():end]
        pieces.append(" " + "\n" * masked.count("\n") if masked.startswith("/") else '""')
        position = end
    pieces.append(text[position:])
    return "".join(pieces)


def _require_rust_entrypoint(sources=ENTRYPOINT_SOURCES):
    """Stop before process startup unless both Rust registration points exist."""
    if len(sources) != 2:
        raise RuntimeError("Rust queue-capacity entrypoint is not integrated")
    test_source, module_source = map(Path, sources)
    try:
        test_text = _rust_code(test_source.read_text(encoding="utf-8"))
        module_text = _rust_code(module_source.read_text(encoding="utf-8"))
    except OSError as error:
        raise RuntimeError("Rust queue-capacity entrypoint is not integrated") from error
    registered = (r'^\s*#\[\s*test\s*\]\s*#\[\s*ignore(?:\s*=\s*"")?\s*\]\s*'
                  r'fn\s+' + re.escape(RUST_TEST) + r'\s*\(\s*\)\s*\{\s*'
                  r'zk_fresh_benchmark\s*::\s*solana\s*::\s*queue_v3\s*::\s*'
                  + re.escape(RUST_FN) + r'\s*\(\s*\)\s*\.\s*unwrap\s*\(\s*\)\s*;\s*\}')
    implemented = (r'^\s*pub\s+fn\s+' + re.escape(RUST_FN)
                   + r'\s*\(\s*\)\s*->\s*Result\s*<\s*\(\s*\)\s*>\s*\{')
    if (len(re.findall(registered, test_text, re.M)) != 1
            or len(re.findall(implemented, module_text, re.M)) != 1):
        raise RuntimeError("Rust queue-capacity entrypoint is not integrated")


def _catalog_digest(inputs, receipt_field):
    rows = [{"request_address": row["request_address"],
             "action_sha256": row["action_sha256"],
             receipt_field: row[receipt_field]} for row in inputs]
    raw = json.dumps(rows, sort_keys=True, separators=(",", ":"),
                     allow_nan=False).encode()
    return _sha(raw)


def _check_private_evidence_dir(evidence_dir):
    root = Path(evidence_dir)
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise ValueError("private evidence output must be an absolute canonical directory")
    root_meta = root.lstat()
    if (not stat.S_ISDIR(root_meta.st_mode) or stat.S_IMODE(root_meta.st_mode) != 0o700
            or root_meta.st_uid != os.getuid()):
        raise ValueError("private evidence output must be owner-only")
    if {entry.name for entry in root.iterdir()} != {"before", "after"}:
        raise ValueError("private evidence output contains an unexpected path")
    expected_names = {name + ".bin" for name in ACCOUNT_NAMES}
    for phase in ("before", "after"):
        directory = root / phase
        meta = directory.lstat()
        if (not stat.S_ISDIR(meta.st_mode) or stat.S_IMODE(meta.st_mode) != 0o700
                or meta.st_uid != os.getuid() or {entry.name for entry in directory.iterdir()} != expected_names):
            raise ValueError("private evidence output contains an unexpected path")
        for path in directory.iterdir():
            item = path.lstat()
            if (not stat.S_ISREG(item.st_mode) or stat.S_IMODE(item.st_mode) != 0o600
                    or item.st_uid != os.getuid() or item.st_nlink != 1):
                raise ValueError("application snapshot must be a private owner-only file")


def _expected_identities(config):
    return {
        "freeze_sha256": config["cohort_freeze_sha256"],
        "genesis_sha256": config["expected_genesis_sha256"],
        "elf_sha256": config["expected_elf_sha256"],
        "stage_sha256": config["stage_report_sha256"],
        "proof_sha256": _catalog_digest(config["inputs"], "proof_receipt_sha256"),
        "wire_sha256": _catalog_digest(config["inputs"], "full_wire_sha256"),
        "clone_sha256": config["clone_receipt_sha256"],
    }


def _validate_stage_binding(config, clone, source):
    """Bind the accepted report and cloned source to the externally pinned stage run."""
    stage_config = execute.base.decode_json(_read_pinned(
        config["stage_config"], config["stage_config_sha256"],
        MAX_CONFIG_BYTES, "local-stage config"))
    stage_status_path = Path(config["stage_status"])
    stage_status = execute.base.decode_json(_read_pinned(
        stage_status_path, config["stage_status_sha256"], 65536,
        "local-stage status"))
    if type(stage_config) is not dict or type(stage_status) is not dict:
        raise ValueError("pinned local-stage status and config must bind the staged source ledger")
    stage_root = Path(config["stage_report"]).parent
    stage_control = Path(stage_config.get("control_output", ""))
    validator_cleanup = stage_status.get("validator_cleanup")
    runner_cleanup = stage_status.get("runner_cleanup")
    if (type(stage_config) is not dict
            or stage_config.get("schema") != 1
            or stage_config.get("scope") != "part5-v3-local-stage"
            or stage_config.get("stage_output") != str(stage_root)
            or Path(config["stage_report"]) != stage_root / "stage-report.json"
            or stage_config.get("expected_genesis") != config["expected_genesis"]
            or stage_config.get("ledger") != str(source)
            or stage_control != stage_status_path.parent
            or stage_status_path != stage_control / "status.json"
            or type(stage_status) is not dict
            or stage_status.get("schema") != 1
            or stage_status.get("scope") != "part5-v3-local-stage"
            or stage_status.get("status") != "failed"
            or stage_status.get("stage_verified") is not True
            or stage_status.get("ledger_reuse_requires_review") is not True
            or stage_status.get("application_effect") is not False
            or stage_status.get("devnet") is not False
            or stage_status.get("config_sha256") != config["stage_config_sha256"]
            or stage_status.get("stage_report_sha256") != config["stage_report_sha256"]
            or stage_status.get("stage_output") != str(stage_root)
            or type(validator_cleanup) is not dict
            or validator_cleanup.get("spawned") is not True
            or validator_cleanup.get("reaped") is not True
            or validator_cleanup.get("graceful") is not False
            or validator_cleanup.get("exit_code") != -2
            or type(runner_cleanup) is not dict
            or runner_cleanup.get("spawned") is not True
            or runner_cleanup.get("reaped") is not True
            or runner_cleanup.get("exit_code") != 0
            or clone.get("stage_status_sha256") != config["stage_status_sha256"]):
        raise ValueError("pinned local-stage status and config must bind the staged source ledger")


def _validate_report(report, config, evidence_dir):
    """Validate the established supplied-evidence schema and tie it to inputs.

    This checks report consistency only. The loaded result is established only
    by a registered Rust test run under the bounded supervisor.
    """
    _check_private_evidence_dir(evidence_dir)
    result = capacity_evidence.validate_report(
        report, evidence_dir, _expected_identities(config))
    owner = report["owner"]
    if (owner["wall_limit_seconds"] > LIMITS["runtime_seconds"]
            or owner["rss_limit_bytes"] > LIMITS["rss_bytes"]
            or owner["storage_limit_bytes"] > LIMITS["storage_growth_bytes"]):
        raise ValueError("capacity report exceeds supervisor limit")
    inputs = config["inputs"]
    expected_fills = [row["request_address"] for row in inputs[:QUEUE_CAPACITY]]
    if ([row["request_address"] for row in report["fill_history"]] != expected_fills
            or report["before_queue_addresses"] != expected_fills
            or report["after_queue_addresses"] != expected_fills
            or report["rejected_request"]["request_address"] != inputs[-1]["request_address"]):
        raise ValueError("capacity report does not bind the ordered 64 fills and exact 65th request")
    preconditions = report["preconditions"]
    if preconditions["full_wire_valid"] is not True:
        raise ValueError("65th request Full wire was not validated against its action")
    snapshot = report["snapshots"][ACCOUNT_NAMES.index("request")]["before"]
    request_bytes = capacity_evidence._snapshot(snapshot, Path(evidence_dir))
    if _sha(request_bytes) != inputs[-1]["request_sha256"]:
        raise ValueError("65th request snapshot differs from its pinned finalized bytes")
    return {"report_consistent": True, "loaded_run_established": False,
            "successful_fill_count": result["successful_fill_count"],
            "rejected_custom_error": result["custom_error"],
            "rejected_instruction_index": result["execute_instruction_index"],
            "unchanged_application_account_count": result["unchanged_application_account_count"]}


def _validate_config(config):
    fields = {
        "schema", "scope", "cohort_id", "cohort_freeze", "cohort_freeze_sha256",
        "cohort_manifest", "cohort_manifest_sha256", "stage_report",
        "stage_report_sha256", "stage_config", "stage_config_sha256",
        "stage_status", "stage_status_sha256", "clone_receipt", "clone_receipt_sha256", "ledger",
        "expected_program", "expected_genesis", "expected_genesis_sha256",
        "expected_elf", "expected_elf_sha256", "validator", "validator_sha256",
        "runner", "runner_sha256", "rust_config_path", "rust_config_sha256",
        "output_dir", "control_output", "inputs", "outer_limits_required",
    }
    if (type(config) is not dict or set(config) != fields
            or config.get("schema") != CONFIG_SCHEMA or config.get("scope") != SCOPE
            or config.get("outer_limits_required") != LIMITS):
        raise ValueError("explicit pinned queue-capacity supervisor contract required")
    _opaque(config["cohort_id"], "cohort id")
    _opaque(config["expected_program"], "program id")
    _opaque(config["expected_genesis"], "genesis hash")
    for name in ("cohort_freeze_sha256", "cohort_manifest_sha256", "clone_receipt_sha256",
                 "stage_report_sha256", "stage_config_sha256", "stage_status_sha256",
                 "expected_genesis_sha256",
                 "expected_elf_sha256", "validator_sha256", "runner_sha256",
                 "rust_config_sha256"):
        _hash(config[name], name)
    _read_pinned(config["cohort_freeze"], config["cohort_freeze_sha256"],
                 MAX_CONFIG_BYTES, "cohort tooling freeze")
    _read_pinned(config["cohort_manifest"], config["cohort_manifest_sha256"],
                 MAX_CONFIG_BYTES, "heldout cohort manifest")
    stage_raw = _read_pinned(config["stage_report"], config["stage_report_sha256"],
                             MAX_CONFIG_BYTES, "accepted stage report")
    stage_report = execute.base.decode_json(stage_raw)
    if (type(stage_report) is not dict
            or stage_report.get("schema") != "part5-v3-local-stage-v1"
            or stage_report.get("passed") is not True
            or stage_report.get("program") != config["expected_program"]
            or stage_report.get("genesis") != config["expected_genesis"]
            or stage_report.get("loaded_program", {}).get("elf_match") is not True
            or stage_report.get("loaded_program", {}).get("elf_sha256") != config["expected_elf_sha256"]):
        raise ValueError("accepted stage report must bind the expected loaded ELF and genesis")
    # Parse the externally pinned local-stage config even before the clone source
    # is resolved; this confirms the configured stage artifact paths are direct.
    stage_config_raw = _read_pinned(config["stage_config"], config["stage_config_sha256"],
                                    MAX_CONFIG_BYTES, "local-stage config")
    stage_config = execute.base.decode_json(stage_config_raw)
    if (type(stage_config) is not dict or stage_config.get("schema") != 1
            or stage_config.get("scope") != "part5-v3-local-stage"
            or stage_config.get("stage_output") != str(Path(config["stage_report"]).parent)
            or stage_config.get("expected_genesis") != config["expected_genesis"]):
        raise ValueError("pinned local-stage config does not bind the accepted stage report")
    _read_pinned(config["stage_status"], config["stage_status_sha256"],
                 65536, "local-stage status")
    clone_raw = _read_pinned(config["clone_receipt"], config["clone_receipt_sha256"],
                             MAX_CONFIG_BYTES, "queue-capacity clone receipt")
    clone = execute.base.decode_json(clone_raw)
    ledger = Path(config["ledger"])
    if (type(clone) is not dict or clone.get("schema") != "part5-v3-heldout-r0-ledger-clone-v1"
            or clone.get("heldout_acceptance") is not False
            or clone.get("source_stable") is not True or clone.get("copy_identical") is not True
            or clone.get("loaded_identity_rechecked_after_restart") is not False
            or clone.get("application_effect") is not False
            or clone.get("stage_report_sha256") != config["stage_report_sha256"]
            or clone.get("stage_status_sha256") != config["stage_status_sha256"]
            or not ledger.is_absolute() or ledger.resolve(strict=True) != ledger
            or ledger.name != "ledger" or clone.get("destination") != str(ledger)
            or Path(config["clone_receipt"]) != ledger.parent / "clone-report.json"
            or clone.get("source") == str(ledger)):
        raise ValueError("fresh isolated finalized-ledger clone receipt required")
    source = Path(clone["source"])
    if (not source.is_absolute() or source.resolve(strict=True) != source
            or source.name != "ledger" or source in ledger.parents or ledger in source.parents):
        raise ValueError("capacity clone must be separate from its finalized source ledger")
    _validate_stage_binding(config, clone, source)
    source_rows = ledger_inventory(source)
    clone_rows = ledger_inventory(ledger)
    clone_tree_sha = _sha(json.dumps(source_rows, separators=(",", ":")).encode())
    if (source_rows != clone_rows or clone.get("entry_count") != len(clone_rows)
            or clone.get("tree_sha256") != clone_tree_sha):
        raise ValueError("capacity ledger clone must remain byte-identical before its run")
    genesis_rows = [row for row in clone_rows if row[0] == "genesis.bin"]
    if (len(genesis_rows) != 1 or genesis_rows[0][1] != "file"
            or genesis_rows[0][3] != config["expected_genesis_sha256"]):
        raise ValueError("capacity genesis bytes differ from their external pin")
    _read_pinned(config["expected_elf"], config["expected_elf_sha256"],
                 4 * 1024 * 1024, "accepted loaded application ELF")
    execute.base.checked(config["validator"], config["validator_sha256"], MAX_EXECUTABLE_BYTES)
    execute.base.checked(config["runner"], config["runner_sha256"], MAX_EXECUTABLE_BYTES)
    inputs = _validate_inputs(config["inputs"])
    output = _canonical_child(config["output_dir"], "private output directory")
    control = _canonical_child(config["control_output"], "control output directory")
    if output == control or output.exists() or control.exists():
        raise ValueError("fresh separate queue-capacity output and control directories required")
    rust_raw = _read_pinned(config["rust_config_path"], config["rust_config_sha256"],
                            MAX_CONFIG_BYTES, "Rust queue-capacity config")
    rust_config = execute.base.decode_json(rust_raw)
    expected_rust = {
        "schema": RUST_CONFIG_SCHEMA, "scope": SCOPE, "runner_test": RUST_TEST,
        "cohort_id": config["cohort_id"], "cohort_freeze_sha256": config["cohort_freeze_sha256"],
        "cohort_manifest_sha256": config["cohort_manifest_sha256"],
        "stage_report_sha256": config["stage_report_sha256"],
        "clone_receipt_sha256": config["clone_receipt_sha256"], "ledger": str(ledger),
        "program": config["expected_program"], "genesis": config["expected_genesis"],
        "genesis_sha256": config["expected_genesis_sha256"],
        "elf_sha256": config["expected_elf_sha256"], "input_count": 65,
        "queue_capacity": QUEUE_CAPACITY,
        "inputs": [{"request_address": row["request_address"],
                    "action_sha256": row["action_sha256"],
                    "request_account": row["request_account"],
                    "request_sha256": row["request_sha256"],
                    "proof_receipt": row["proof_receipt"],
                    "proof_receipt_sha256": row["proof_receipt_sha256"],
                    "full_wire": row["full_wire"],
                    "full_wire_sha256": row["full_wire_sha256"]} for row in inputs],
        "output_dir": str(output), "outer_limits_required": LIMITS,
    }
    if type(rust_config) is not dict or rust_config != expected_rust:
        raise ValueError("Rust config differs from the pinned capacity supervisor inputs")
    return inputs


def _write_integration_failure(config, config_sha256, config_path, error,
                               blocker="missing_rust_entrypoint"):
    control = _canonical_child(config["control_output"], "control output directory")
    control.mkdir(mode=0o700)
    status = {
        "schema": 1, "scope": SCOPE, "status": "failed",
        "error_type": type(error).__name__, "error_message": str(error)[:256],
        "config_path": str(config_path), "config_sha256": config_sha256,
        "validator_started": False, "runner_started": False,
        "loaded_execution_established": False, "application_effect": False,
        "integration_blocker": blocker,
        "integration_required": "Implement and review the Rust runtime report producer and its supervised RPC checks before enabling loaded execution.",
        "required_loaded_report_contract": LOADED_REPORT_CONTRACT,
        "report_consistency_establishes_loaded_execution": False,
        "validator_cleanup": {"spawned": False, "reaped": True},
        "runner_cleanup": {"spawned": False, "reaped": True},
        "remaining_owned_processes": 0,
        "outer_limits_required": LIMITS,
    }
    execute.base.write_new(control / "status.json", status)
    return status


def run(config, config_sha256, config_path):
    if os.environ.get("P5_V3_QUEUE_CAPACITY_NEGATIVE_SCOPE") != SCOPE:
        raise ValueError("explicit bounded queue-capacity negative scope required")
    config_path = Path(config_path)
    if not config_path.is_absolute() or config_path.resolve(strict=True) != config_path:
        raise ValueError("canonical absolute supervisor config required")
    if _decode_pinned_config(config_path, config_sha256) != config:
        raise ValueError("supervisor config content mismatch")
    if (type(config) is not dict or config.get("schema") != CONFIG_SCHEMA
            or config.get("scope") != SCOPE or "control_output" not in config):
        raise ValueError("explicit queue-capacity failure-status path required")
    _validate_config(config)
    try:
        _require_rust_entrypoint()
    except RuntimeError as error:
        _write_integration_failure(config, config_sha256, config_path, error)
        return 2

    error = RuntimeError(
        "Rust queue-capacity loaded report interface is not integrated: "
        "supplied evidence v1 establishes consistency only; a reviewed runtime "
        "producer, finalized RPC checks, and separate outer cleanup receipt are required")
    _write_integration_failure(config, config_sha256, config_path, error,
                               blocker="missing_loaded_report_interface")
    return 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--config-sha256", required=True)
    args = parser.parse_args()
    try:
        config = _decode_pinned_config(args.config, args.config_sha256)
        return run(config, args.config_sha256, args.config)
    except Exception as error:
        raise SystemExit(f"queue-capacity negative failed closed: {type(error).__name__}") from None


if __name__ == "__main__":
    sys.exit(main())
