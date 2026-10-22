#!/usr/bin/env python3
"""Freeze the v3 product boundary and every earlier RSA public-key fingerprint.

The output directory contains only ``freeze.json`` and its matching
``prior-key-inventory.json``. It is created atomically as an owner-only
directory under results/dynark/part5. This tool does not generate keys,
certificates, proofs, or application requests.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.part5 import freeze_v3_campaign_cohort as prior_freeze
from tools.part5 import generate_v3_heldout_keys as keygen
from tools.part5 import prepare_v3_campaign_cohort as cohort

PART5 = ROOT / 'artifacts/dynark/part5'
RESULTS = ROOT / 'results/dynark/part5'
SETUP = PART5 / 'v3-development-setup-001'
COMPILE = PART5 / 'v3-compile-001'
PROOF = ROOT / 'circuits/credential-v3-bounded/qualification/proof-runner-v1'
RUNNER_BINARY = 'artifacts/dynark/part5/v3-heldout-queue-runner-005'
LOADED_ELF = PART5 / 'application-v3-sbf-build-002/elf/zk_fresh_program.so'
INVENTORY_SCHEMA = 'credential-v3-prior-public-key-inventory-v1'

REGISTRY_FILES = [
    *[str(path.relative_to(ROOT)) for path in sorted(
        (ROOT / 'crates/credential-registry/src').rglob('*.rs'))],
    *[str(path.relative_to(ROOT)) for path in sorted(
        (ROOT / 'program/src').rglob('*.rs'))],
    *[str(path.relative_to(ROOT)) for path in sorted(
        (ROOT / 'harness/src').rglob('*.rs'))],
    'harness/Cargo.toml',
    'harness/Cargo.lock',
    'circuits/profile.json',
    'program/Cargo.toml',
    'crates/credential-registry/Cargo.toml',
    'harness/tests/queue_v3.rs',
    RUNNER_BINARY,
    'harness/tests/queue_v3_build_prep.py',
    'harness/tests/queue_v3_local_prepare.py',
    'harness/tests/queue_v3_local_stage.py',
    'harness/tests/queue_v3_local_transition.py',
    'harness/tests/queue_v3_local_execute.py',
    'harness/tests/queue_v3_local_expired_status_negative.py',
    'harness/tests/queue_v3_blank_seed.py',
    'harness/tests/queue_v3_capacity_runtime.py',
    'harness/tests/queue_v3_local_queue_capacity_negative.py',
    'harness/tests/queue_v3_loaded_negative_checks.py',
    'harness/tests/queue_v3_ambiguous_rpc_proxy.py',
    'harness/tests/queue_v3_local_ambiguous_restart.py',
    'harness/tests/queue_v3_local_disabled_config_negative.py',
    'harness/tests/queue_v3_local_branch.py',
    'harness/tests/queue_v3_clone_ledger.py',
    'harness/tests/queue_v3_clone_heldout_r0.py',
    'harness/tests/queue_v3_local_campaign_transition.py',
    'harness/tests/queue_v3_clone_prepared.py',
    'tools/part5/prepare_v3_campaign_context.py',
    'tools/part5/create_v3_branch_config.py',
]
CLIENT_FILES = [
    'crates/dynark-native-client/src/v3_binding.rs',
    'crates/dynark-native-client/workers/v3_input_worker.py',
    'crates/dynark-native-client/tests/support/prepare_v3_request_bound_training.py',
    'crates/dynark-native-client/tests/support/v3_relation_witness.cjs',
    'crates/dynark-native-client/tests/support/prepare_v3_relation.py',
    'program/examples/export_v3_request_fixture.rs',
    'program/target/debug/examples/export_v3_request_fixture',
    'results/dynark/part5/session_runner.py',
    'tools/part5/credential_profile.py',
    'tools/part5/issue_v3_heldout_certificate.py',
    'tools/part5/generate_v3_heldout_keys.py',
    'tools/part5/prepare_v3_revocation_cohort.py',
    'tools/part5/prepare_v3_request_fixture.py',
    'tools/part5/prepare_v3_campaign_training_source.py',
    'tools/part5/prepare_v3_campaign_target.py',
    'tools/part5/build_v3_campaign_packet.py',
    'tools/part5/build_v3_request_bound_anchor_packet.py',
    'tools/part5/prepare_v3_matched_training_source.py',
    'tools/part5/run_v3_matched_k1.py',
    'tools/part5/prepare_v3_heldout_context.py',
    'tools/part5/prepare_v3_heldout_source.py',
    'tools/part5/prepare_v3_heldout_proof.py',
    'tools/part5/check_v3_r2_counterfactual.py',
    'tools/part5/witness_check.py',
    'tools/part5/build_v3_heldout_run_manifest.py',
    'tools/part5/run_v3_heldout_case.py',
    'tools/part5/run_v3_heldout_complete_arm.py',
    'tools/part5/run_v3_heldout_direct_arm.py',
    'harness/tests/queue_v3_local_disabled_config_negative.py',
    'tools/part5/assemble_v3_heldout_acceptance.py',
    'tools/part5/verify_v3_heldout_acceptance.py',
    'tools/part5/finalize_v3_expired_status_negative.py',
    'tools/part5/heldout_expired_status_evidence.py',
    'tools/part5/build_v3_expired_status_negative_inputs.py',
    'tools/part5/heldout_queue_capacity_evidence.py',
    'tools/part5/prepare_v3_queue_capacity_fixture.py',
    'tools/part5/finalize_v3_queue_capacity_negative.py',
    'tools/part5/run_v3_heldout_whole_session.py',
    'tools/part5/verify_v3_campaign_public_projection.py',
    'tools/part5/analyze_v3_heldout_costs.py',
    'tools/part5/model_v3_heldout_break_even.py',
    'tools/part5/freeze_v3_heldout_cohort.py',
    # Pin the exact heldout issuer that consumes this freeze.
    'tools/part5/build_v3_heldout_cohort.py',
    'tools/part5/observe_v3_heldout_cohort.py',
    # Keep every local Python import reachable from the declared client and
    # verifier sources inside the same frozen source bundle.
    'tools/part5/freeze_v3_campaign_cohort.py',
    'tools/part5/prepare_v3_campaign_cohort.py',
    'tools/part5/registry_v3_vectors.py',
    'tools/part5/poseidon.py',
    'tools/part5/corpus.py',
]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def file_digest(path):
    return digest(prior_freeze.read_input(path))


def _profile_bounds(raw):
    value = cohort.issuance.decode_parameters(raw)
    if (type(value) is not dict
            or value.get('profile') != 'credential-v3-bounded-der-v1'
            or value.get('certificate_length') != 952
            or value.get('tbs_length') != 672
            or value.get('aki_bytes') != 20
            or value.get('organization_bytes') != 16
            or value.get('group_bytes') != 32
            or value.get('rsa') != {'bits': 2048, 'digest': 'SHA256',
                                    'exponent': 65537, 'padding': 'PKCS1-v1_5'}
            or value.get('serial') != 'canonical positive exactly 16 octets; first octet 1..127'
            or value.get('validity') != 'canonical UTCTime 2000-2049, real calendar, inclusive endpoints'
            or type(value.get('layouts')) is not list
            or len(value['layouts']) != 8
            or [item.get('layout') if type(item) is dict
                and type(item.get('layout')) is int else None
                for item in value['layouts']] != list(range(8))):
        raise ValueError('bounded v3 credential profile required')


def _prepare_status(path):
    raw = prior_freeze.read_input(path, 65536)
    value = cohort.issuance.decode_parameters(raw)
    if (type(value) is not dict
            or value.get('schema') != 1
            or value.get('status') not in ('passed', 'failed')
            or value.get('application_effect') is not False
            or value.get('devnet') is not False
            or value.get('error_type') is not None
            or value.get('cleanup', {}).get('reaped') is not True
            or not value.get('loaded_program', {}).get('genesis')
            or value.get('scope') != 'part5-v3-local-prepare'
            or value.get('loaded_program', {}).get('elf_match') is not True
            or value.get('prepared_application_accounts') is not False
            or not keygen._hash(value.get('source_manifest_sha256'))
            or (value.get('status') == 'failed' and (
                value.get('cleanup', {}).get('exit_code') != -2
                or value.get('ledger_reuse_requires_review') is not True))):
        raise ValueError('fresh loaded-v3 prepare identity required')
    return raw, value


def _fresh_output(output):
    output = Path(output)
    if (not output.is_absolute() or output.parent != RESULTS
            or output.parent.resolve(strict=True) != output.parent
            or output.exists() or output.is_symlink()
            or not output.name or output.name in ('.', '..')
            or output.parent.stat().st_uid != os.getuid()
            or output.parent.stat().st_mode & 0o022):
        raise ValueError('fresh direct results directory required')
    return output


def _write_file(directory, name, raw):
    path = directory / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
        os.fsync(fd)
    finally:
        os.close(fd)


def _publish_pair(output, freeze_raw, inventory_raw):
    """Write both files privately, then expose the complete directory by rename."""
    output = _fresh_output(output)
    temporary = Path(tempfile.mkdtemp(prefix='.' + output.name + '.pending-',
                                      dir=output.parent))
    try:
        os.chmod(temporary, 0o700)
        info = temporary.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('owner0700 staging directory required')
        _write_file(temporary, 'prior-key-inventory.json', inventory_raw)
        _write_file(temporary, 'freeze.json', freeze_raw)
        directory_fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                               | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        if output.exists() or output.is_symlink():
            raise ValueError('fresh direct results directory required')
        # The output parent is owner-controlled and not group/world writable;
        # the rename makes the inventory and freeze visible together.
        staged = temporary.stat()
        os.rename(temporary, output)
        parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                            | os.O_CLOEXEC)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)
        elif output.exists() and 'staged' in locals():
            published = output.stat()
            if (published.st_dev, published.st_ino) == (staged.st_dev, staged.st_ino):
                shutil.rmtree(output)
        raise


def freeze(prepare_status, adapter_binary, output_dir, proof_binary=None):
    """Validate the current product and publish its prior-key census and freeze."""
    output = _fresh_output(output_dir)
    proof_binary = Path(proof_binary) if proof_binary is not None else (
        PROOF / 'target/release/credential-v3-bounded-proof-qualification-v1')
    prepare_raw, prepared = _prepare_status(prepare_status)
    setup_path = SETUP / 'setup-manifest.json'
    setup_raw = prior_freeze.read_input(setup_path, 65536)
    setup = cohort.issuance.decode_parameters(setup_raw)
    profile_path = ROOT / 'circuits/credential-v3-bounded/profile.json'
    profile_raw = prior_freeze.read_input(profile_path, 65536)
    _profile_bounds(profile_raw)

    from harness.tests import queue_v3_build_prep as build_prep
    application_manifest = build_prep.source_manifest(ROOT)
    application_sha = digest(json.dumps(application_manifest, sort_keys=True).encode())
    if application_sha != prepared['source_manifest_sha256']:
        raise ValueError('prepared application source inventory changed')
    if (type(setup) is not dict
            or setup.get('schema') != 'credential-v3-bounded-setup-v1'
            or setup.get('development_only') is not True
            or type(setup.get('identity')) is not dict
            or not keygen._hash(setup['identity'].get('circuit'))
            or prepared.get('v3_vk', {}).get('setup_manifest_sha256') != digest(setup_raw)
            or prepared.get('v3_vk', {}).get('circuit_id') != setup['identity']['circuit']):
        raise ValueError('prepare/setup provenance mismatch')

    singles = {
        'profile': profile_path,
        'r1cs': COMPILE / 'credential.r1cs',
        'witness_executable': COMPILE / 'credential_js/credential.wasm',
        'setup_manifest': setup_path,
        'ordinary_vk': SETUP / 'ordinary.vk',
        'proof_runner': proof_binary,
        'signer_interface': ROOT / 'tools/part5/prepare_v3_request_fixture.py',
        'ordinary_adapter': Path(adapter_binary),
        'loaded_elf': LOADED_ELF,
    }
    identities = {role: file_digest(path) for role, path in singles.items()}
    registry_sha, _ = prior_freeze.bundle(REGISTRY_FILES)
    client_sha, _ = prior_freeze.bundle(CLIENT_FILES)
    identities.update(
        circuit=setup['identity']['circuit'], registry=registry_sha, client=client_sha,
        application_source=application_sha)
    if (set(identities) != keygen.IDENTITY_ROLES
            or not all(keygen._hash(value) for value in identities.values())
            or identities['profile'] != setup.get('profile_sha256')
            or identities['r1cs'] != setup.get('r1cs_sha256')
            or identities['witness_executable'] != setup.get('wasm_sha256')
            or identities['setup_manifest'] != digest(setup_raw)
            or identities['ordinary_vk'] != setup.get('ordinary_vk_file_sha256')
            or identities['loaded_elf'] != prepared['loaded_program'].get('elf_sha256')):
        raise ValueError('accepted v3 package/ELF identity changed')

    forbidden, _ = prior_freeze.prior_keys()
    observed_at = time.time_ns()
    if observed_at <= 0:
        raise ValueError('positive prior-key inventory timestamp required')
    boundary = {
        'schema': keygen.FREEZE_SCHEMA,
        'frozen_at_unix_ns': None,
        'issuance_tool_sha256': file_digest(keygen.ISSUANCE_TOOL),
        'key_generation_tool_sha256': file_digest(Path(keygen.__file__).resolve()),
        'identities': identities,
        'forbidden_public_key_sha256': forbidden,
    }

    # Recheck all live inputs and the complete key census immediately before
    # assigning freeze time. A changed source or newly added earlier key aborts.
    if (prior_freeze.read_input(prepare_status, 65536) != prepare_raw
            or any(file_digest(path) != identities[role] for role, path in singles.items())
            or prior_freeze.bundle(REGISTRY_FILES)[0] != registry_sha
            or prior_freeze.bundle(CLIENT_FILES)[0] != client_sha
            or digest(json.dumps(build_prep.source_manifest(ROOT), sort_keys=True).encode())
               != application_sha
            or prior_freeze.prior_keys()[0] != forbidden
            or file_digest(keygen.ISSUANCE_TOOL) != boundary['issuance_tool_sha256']
            or file_digest(Path(keygen.__file__).resolve())
               != boundary['key_generation_tool_sha256']):
        raise ValueError('heldout freeze inputs changed before publication')

    frozen_at = time.time_ns()
    if frozen_at <= observed_at:
        raise ValueError('prior inventory must predate the freeze')
    boundary['frozen_at_unix_ns'] = frozen_at
    freeze_raw = (json.dumps(boundary, sort_keys=True, indent=2) + '\n').encode()
    freeze_sha = digest(freeze_raw)
    inventory = {
        'schema': INVENTORY_SCHEMA,
        'observed_at_unix_ns': observed_at,
        'freeze_sha256': freeze_sha,
        'public_key_sha256': forbidden,
    }
    inventory_raw = (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode()
    inventory_sha = digest(inventory_raw)
    _publish_pair(output, freeze_raw, inventory_raw)
    return {
        'freeze_sha256': freeze_sha,
        'prior_key_inventory_sha256': inventory_sha,
        'frozen_at_unix_ns': frozen_at,
        'prior_inventory_observed_at_unix_ns': observed_at,
        'prior_public_key_count': len(forbidden),
        'identities': identities,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare-status', required=True, type=Path)
    parser.add_argument('--adapter-binary', required=True, type=Path)
    parser.add_argument('--proof-binary', type=Path,
                        default=PROOF / 'target/release/credential-v3-bounded-proof-qualification-v1')
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    try:
        receipt = freeze(args.prepare_status, args.adapter_binary, args.output_dir,
                         proof_binary=args.proof_binary)
    except Exception:
        raise SystemExit('v3 heldout preissuance freeze rejected') from None
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()
