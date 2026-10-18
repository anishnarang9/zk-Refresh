#!/usr/bin/env python3
"""Independently verify pinned held-out v3 application evidence.

The input manifest is explicit and immutable by SHA-256. It contains global
freeze/cohort/source pins and eight cases. Each case has four outcomes built
from three independent request slots A/B/C, each with staged R0/R1 source
receipts and an independently verified transition. The outcomes map to
Full(A), Full(B), Anchor(B), and own-R2 revocation(C), with distinct clone
receipts.

This verifier accepts the existing training-local report schemas only when all
held-out provenance is independently pinned and joined. It emits a derived
acceptance report; it does not run a proof or validator.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.part5.generate_v3_heldout_keys import FREEZE_SCHEMA, IDENTITY_ROLES
from tools.part5.prepare_v3_heldout_context import COHORT_SCHEMA, CASE_SCHEMA, _base58
from tools.part5.prepare_v3_revocation_cohort import membership_for_pair
from tools.part5.credential_profile import ProfileError, admit_certificate, parse_tbs, public_bindings
from tools.part5.registry_v3_vectors import h as poseidon_parent, leaf as poseidon_leaf
from harness.tests.queue_v3_clone_ledger import inventory as ledger_inventory
from harness.tests.queue_v3_clone_ledger import stale_admin_socket

MANIFEST_SCHEMA = 'credential-v3-heldout-acceptance-manifest-v1'
OUTPUT_SCHEMA = 'credential-v3-heldout-application-report-v1'
SOURCE_SCHEMA = 'credential-v3-heldout-request-source-v1'
PAIR_SCHEMA = 'v3-two-signed-training-credentials-v1'
RUN_SCHEMA = 'credential-v3-heldout-case-run-v1'
JOURNAL_SCHEMA = 'credential-v3-heldout-case-run-journal-v1'
QUEUE_RUNNER_REL = 'artifacts/dynark/part5/v3-heldout-queue-runner-002'
BRANCHES = ('full', 'unrelated_full', 'anchor', 'own_revocation')
ACCOUNT_NAMES = ('config', 'issuer', 'head', 'request', 'queue')
SOURCE_FILE_ROLES = ('heldout_source_tool', 'training_helper', 'exporter',
                     'request_fixture_bridge')
PROOF_INPUT_ROLES = ('packet_template', 'witness_js', 'relation_checker', 'node',
                     'proof_runner', 'adapter_binary', 'bounded_supervisor', 'exporter')
PROOF_STAGE_PIN_FIELDS = frozenset({
    'program_id', 'genesis_hash', 'loaded_elf_sha256',
    'base_stage_report_sha256', 'base_config_sha256',
    'finalized_request_sha256', 'request_address', 'base_finalized_slot',
    'near_state_report_sha256', 'near_config_sha256', 'near_finalized_slot',
    'base_root', 'near_root', 'action_hash',
})
PACKET_IDENTITY_FIELDS = (
    'package_digest', 'setup_manifest_path', 'setup_manifest_sha256',
    'package_check_path', 'package_check_sha256', 'r1cs_path', 'wasm_path',
    'profile_path', 'input_map_path', 'input_map_sha256',
)
FROZEN_FILE_ROLES = ('profile', 'r1cs', 'witness_executable', 'setup_manifest',
                     'ordinary_vk', 'proof_runner', 'signer_interface',
                     'ordinary_adapter', 'loaded_elf')
MAX_JSON = 4 * 1024 * 1024
MAX_ARTIFACT = 512 * 1024 * 1024
PROOF_POLL_SECONDS = 0.25
HEX64 = re.compile(r'[0-9a-f]{64}\Z')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _is_sha(value):
    return type(value) is str and HEX64.fullmatch(value) is not None


def _unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON key')
        value[key] = item
    return value


def _artifact(ref, *, cap=MAX_ARTIFACT):
    _require(type(ref) is dict and set(ref) == {'path', 'sha256'},
             'pinned artifact path and SHA-256 required')
    raw_path, expected = ref['path'], ref['sha256']
    _require(type(raw_path) is str and Path(raw_path).is_absolute() and _is_sha(expected),
             'absolute path and canonical SHA-256 pin required')
    path = Path(raw_path)
    before = path.lstat()
    _require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
             and before.st_nlink == 1 and not before.st_mode & 0o022
             and 0 < before.st_size <= cap and path.resolve(strict=True) == path,
             'bounded owner-controlled regular artifact required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    digest = hashlib.sha256()
    chunks = [] if cap <= MAX_JSON else None
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        _require(_identity(opened) == _identity(before), 'artifact changed at open')
        total = 0
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            total += len(chunk)
            _require(total <= cap, 'artifact exceeds size cap')
            digest.update(chunk)
            if chunks is not None:
                chunks.append(chunk)
        _require(_identity(os.fstat(stream.fileno())) == _identity(before),
                 'artifact changed while reading')
    _require(total == before.st_size and _identity(path.lstat()) == _identity(before),
             'artifact changed during verification')
    actual = digest.hexdigest()
    _require(actual == expected, 'artifact SHA-256 pin mismatch')
    return path, actual, b''.join(chunks) if chunks is not None else None


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_private_key_artifact(path, *, cap=4096):
    path = Path(path)
    _require(path.is_absolute() and path.resolve(strict=True) == path,
             'canonical heldout private-key path required')
    before = path.lstat()
    _require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
             and 0 < before.st_size <= cap,
             'owner-only heldout private-key file required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        _require(_identity(opened) == _identity(before),
                 'heldout private key changed at open')
        raw = stream.read(cap + 1)
        _require(_identity(os.fstat(stream.fileno())) == _identity(before)
                 and len(raw) == before.st_size
                 and _identity(path.lstat()) == _identity(before),
                 'heldout private key changed during import')
    return raw


def _spki_sha256(public_key):
    return _sha(public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo))


def _expect_profile_rejection(certificate, issuer_modulus, expected_message):
    try:
        admit_certificate(certificate, issuer_modulus)
    except ProfileError as error:
        _require(str(error) == expected_message,
                 'negative certificate admission rejected for unexpected reason')
        return expected_message.casefold().replace(' ', '_')
    raise ValueError('negative certificate admission unexpectedly succeeded')


def _verify_cohort_import(cohort_root, by_variant, key_rows_by_identity,
                          prior_keys, freeze_sha, cohort_sha, *, frozen_at_unix_ns):
    """Independently import every generated key and issued certificate."""
    cohort_root = Path(cohort_root)
    _require(cohort_root.is_absolute() and cohort_root.resolve(strict=True) == cohort_root,
             'canonical heldout cohort directory required')
    expected_key_ids = ({('issuer', index) for index in range(4)}
                        | {('holder', index) for index in range(8)})
    _require(set(key_rows_by_identity) == expected_key_ids
             and set(by_variant) == set(range(8)),
             'complete imported key and certificate maps required')

    observed_started = time.time_ns()
    _require(observed_started > frozen_at_unix_ns,
             'independent key and certificate import must occur after freeze')
    imported_keys, fingerprints = {}, set()
    for role, index in sorted(expected_key_ids):
        path = cohort_root / 'keys' / f'{role}-{index}.pem'
        raw = _read_private_key_artifact(path)
        try:
            key = serialization.load_pem_private_key(raw, password=None)
        except (TypeError, ValueError) as error:
            raise ValueError('heldout private key import failed') from error
        _require(isinstance(key, rsa.RSAPrivateKey) and key.key_size == 2048
                 and key.public_key().public_numbers().e == 65537,
                 'imported heldout RSA-2048/e65537 key required')
        fingerprint = _spki_sha256(key.public_key())
        _require(fingerprint == key_rows_by_identity[(role, index)].get('public_key_sha256'),
                 'imported key differs from pinned generation receipt')
        _require(fingerprint not in fingerprints and fingerprint not in prior_keys,
                 'imported heldout keys must be unique and absent from prior inventory')
        fingerprints.add(fingerprint)
        imported_keys[(role, index)] = key

    certificate_evidence = []
    negative_certificate_evidence = []
    for variant in range(8):
        row = by_variant[variant]
        issuer = imported_keys[('issuer', row['issuer_index'])]
        holder = imported_keys[('holder', row['holder_index'])]
        cert_path = cohort_root / f'certificate-{variant:02d}' / 'credential.der'
        _, cert_sha, raw = _artifact(
            {'path': str(cert_path), 'sha256': row['credential_sha256']}, cap=952)
        _require(len(raw) == 952,
                 'imported heldout certificate must match the bounded DER length')
        parsed = admit_certificate(raw, issuer.public_key().public_numbers().n)
        issuer_hash, policy_hash = public_bindings(
            parsed, issuer.public_key().public_numbers().n)
        _require(parsed['variant'] == variant
                 and _sha(parsed['tbs']) == row['tbs_sha256']
                 and _sha(parsed['aki']) == row['aki_sha256']
                 and _sha(parsed['organization']) == row['organization_sha256']
                 and _sha(parsed['group']) == row['group_sha256']
                 and parsed['serial'].hex() == row['serial_hex']
                 and parsed['not_before'] == row['not_before_unix']
                 and parsed['not_after'] == row['not_after_unix']
                 and parsed['holder_modulus'] == holder.public_key().public_numbers().n
                 and _spki_sha256(issuer.public_key()) == row['issuer_public_key_sha256']
                 and _spki_sha256(holder.public_key()) == row['holder_public_key_sha256']
                 and str(issuer_hash) == row['issuer_hash']
                 and str(policy_hash) == row['policy_hash'],
                 'imported certificate fields or issuer/holder key bindings differ from receipt')

        malformed = raw[:-1]
        malformed_error = _expect_profile_rejection(
            malformed, issuer.public_key().public_numbers().n,
            'DER content exceeds parent')

        signature_integer = int.from_bytes(raw[-256:], 'big')
        wrong_issuer_candidates = [
            index for index in range(4) if index != row['issuer_index']]
        wrong_issuer_index = next((
            index for index in wrong_issuer_candidates
            if signature_integer < imported_keys[('issuer', index)].public_key()
                .public_numbers().n), wrong_issuer_candidates[0])
        wrong_issuer = imported_keys[('issuer', wrong_issuer_index)]
        wrong_issuer_expected_error = (
            'RSA signature verification failed'
            if signature_integer < wrong_issuer.public_key().public_numbers().n
            else 'noncanonical RSA signature')
        wrong_issuer_error = _expect_profile_rejection(
            raw, wrong_issuer.public_key().public_numbers().n,
            wrong_issuer_expected_error)

        tbs_start = raw.find(parsed['tbs'])
        _require(tbs_start >= 0 and raw.count(parsed['tbs']) == 1,
                 'unique imported TBS required for same-length mutation')
        organization_offset = parsed['offsets']['organization']
        _require(0 <= organization_offset < len(parsed['tbs']),
                 'bounded signed organization offset required')
        tampered_tbs = bytearray(parsed['tbs'])
        tampered_tbs[organization_offset] ^= 1
        tampered_tbs = bytes(tampered_tbs)
        reparsed_tampered_tbs = parse_tbs(tampered_tbs)
        _require(len(tampered_tbs) == len(parsed['tbs'])
                 and reparsed_tampered_tbs['organization'] != parsed['organization'],
                 'same-length structurally valid signed organization mutation required')
        tampered = (raw[:tbs_start] + tampered_tbs
                    + raw[tbs_start + len(parsed['tbs']):])
        tampered_error = _expect_profile_rejection(
            tampered, issuer.public_key().public_numbers().n,
            'RSA signature verification failed')

        negative_certificate_evidence.append({
            'variant': variant,
            'credential_sha256': cert_sha,
            'malformed_der': {
                'label': 'truncate_final_byte',
                'der_sha256': _sha(malformed),
                'error_category': malformed_error,
            },
            'wrong_issuer_key': {
                'label': 'unmodified_der_with_other_cohort_issuer_key',
                'issuer_public_key_sha256': _spki_sha256(wrong_issuer.public_key()),
                'error_category': wrong_issuer_error,
            },
            'tampered_signed_organization': {
                'label': 'same_length_organization_bit_flip_signature_unchanged',
                'structurally_parseable': True,
                'der_sha256': _sha(tampered),
                'error_category': tampered_error,
            },
        })
        certificate_evidence.append({
            'variant': variant,
            'credential_sha256': cert_sha,
            'tbs_sha256': _sha(parsed['tbs']),
            'issuer_public_key_sha256': row['issuer_public_key_sha256'],
            'holder_public_key_sha256': row['holder_public_key_sha256'],
            'issuer_signature_verified': True,
            'encoder_claim': row['encoder'],
        })

    observed_completed = time.time_ns()
    _require(observed_completed >= observed_started,
             'independent import observation clock moved backward')
    return {
        'schema': 'credential-v3-heldout-independent-import-evidence-v1',
        'status': 'all_heldout_keys_and_certificates_imported_and_verified',
        'freeze_sha256': freeze_sha,
        'cohort_receipt_sha256': cohort_sha,
        'observation_started_unix_ns': observed_started,
        'observation_completed_unix_ns': observed_completed,
        'creation_time_basis': 'cohort and key-generation receipt claims only',
        'openssl_route_basis': (
            'freeze-pinned source and receipt encoder labels; invocation not independently observed'),
        'counts': {'issuer_keys': 4, 'holder_keys': 8, 'certificates': 8},
        'certificates': certificate_evidence,
        'local_negative_admission': {
            'scope': 'local_admission_only',
            'loaded_execute_observed': False,
            'changed_policy_allowlist_tested': False,
            'counts': {
                'certificates': len(negative_certificate_evidence),
                'malformed_der_rejections': len(negative_certificate_evidence),
                'wrong_issuer_key_rejections': len(negative_certificate_evidence),
                'tampered_signed_organization_rejections': len(negative_certificate_evidence),
            },
            'certificates': negative_certificate_evidence,
        },
    }


def _json(ref, *, cap=MAX_JSON):
    _, actual, raw = _artifact(ref, cap=cap)
    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(
                               ValueError('non-finite JSON number')))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError('pinned JSON artifact required') from error
    _require(type(value) in (dict, list), 'JSON object or array required')
    return value, actual


def _read_json_path(path, *, cap=MAX_JSON):
    path = Path(path)
    before = path.lstat()
    _require(path.is_absolute() and path.resolve(strict=True) == path
             and stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
             and before.st_nlink == 1 and not before.st_mode & 0o022
             and 0 < before.st_size <= cap,
             'bounded owner-controlled manifest required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        _require(_identity(opened) == _identity(before), 'manifest changed at open')
        raw = stream.read(cap + 1)
        _require(_identity(os.fstat(stream.fileno())) == _identity(before)
                 and _identity(path.lstat()) == _identity(before),
                 'manifest changed while reading')
    _require(len(raw) == before.st_size, 'manifest size changed while reading')
    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(
                               ValueError('non-finite JSON number')))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError('valid pinned manifest JSON required') from error
    _require(type(value) is dict, 'manifest object required')
    return value, _sha(raw)


def _bytes32(value, label):
    _require(type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None,
             f'canonical {label} required')
    return bytes.fromhex(value)


def _field_bytes(value, label):
    _require(type(value) is list and len(value) == 32
             and all(type(item) is int and 0 <= item <= 255 for item in value),
             f'canonical {label} byte array required')
    return bytes(value)


def _verify_offline_provenance_flags(context, pair):
    expected_auth = {'registry_history': False, 'live_state': False,
                     'current_head': False, 'finalized_account_batch': False}
    _require(type(context) is dict and context.get('heldout_acceptance') is False
             and context.get('authenticated') == expected_auth,
             'offline context must not claim heldout acceptance or authentication')
    _require(type(pair) is dict and pair.get('heldout_acceptance') is False
             and pair.get('allocation_authorized') is False
             and pair.get('registry_history_authenticated') is False
             and pair.get('live_state_authenticated') is False,
             'pair receipt must remain explicitly unauthenticated offline evidence')


def _verify_exporter_adapter_roles(source_hashes, proof_hashes, frozen_hashes):
    _require(source_hashes.get('exporter') == proof_hashes.get('exporter'),
             'heldout exporter source must match proof-input exporter role')
    _require(proof_hashes.get('adapter_binary') == frozen_hashes.get('ordinary_adapter'),
             'proof adapter binary must match frozen ordinary-adapter role')


def _validate_packet_and_proof_report(packet, report, *, packet_sha256, proof_mode,
                                      stage_pins, packet_fields, artifact_refs,
                                      report_identities, proof_counts):
    expected_packet_keys = (set(PACKET_IDENTITY_FIELDS)
                            | {'schema', 'synthetic_only', 'application_verified',
                               'cohort', 'proof_source_identity', 'application_stage',
                               'pairs'})
    _require(type(packet) is dict and set(packet) == expected_packet_keys
             and packet.get('schema') == 'credential-v3-request-bound-anchor-v1'
             and packet.get('synthetic_only') is False
             and packet.get('application_verified') is False
             and packet.get('cohort') == 'request-bound-training-v1'
             and _is_sha(packet.get('proof_source_identity'))
             and type(packet.get('application_stage')) is dict
             and set(packet['application_stage']) == set(PROOF_STAGE_PIN_FIELDS)
             and packet['application_stage'] == stage_pins
             and {name: packet.get(name) for name in PACKET_IDENTITY_FIELDS}
                == packet_fields,
             'proof packet must pin exact application stage and frozen proof inputs')
    pairs = packet.get('pairs')
    _require(type(pairs) is list and len(pairs) == 1
             and type(pairs[0]) is dict and set(pairs[0]) == {'name', 'base', 'near'}
             and pairs[0].get('name') == 'request_bound_training',
             'proof packet must contain the registered base/near witness pair')
    for side, root_version in (('base', 0), ('near', 1)):
        witness = pairs[0][side]
        _require(type(witness) is dict and set(witness) == {
            'input_path', 'input_sha256', 'public_path', 'public_sha256',
            'wtns_path', 'wtns_sha256', 'issuer_version', 'policy_version',
            'allocation_epoch', 'root_version'}
            and witness.get('issuer_version') == 1
            and witness.get('policy_version') == 1
            and witness.get('allocation_epoch') == 1
            and witness.get('root_version') == root_version,
            f'proof packet {side} witness identity mismatch')
        for file_kind, packet_kind in (('input.json', 'input'),
                                       ('public.json', 'public'),
                                       ('output.wtns', 'wtns')):
            _require(type(artifact_refs) is dict
                     and artifact_refs.get(f'{side}/{file_kind}') == {
                         'path': witness.get(f'{packet_kind}_path'),
                         'sha256': witness.get(f'{packet_kind}_sha256')},
                     f'proof packet {side} {file_kind} must link to its pinned artifact')
    _require(type(report) is dict
             and report.get('schema') == 'credential-v3-matched-k1-proof-v1'
             and report.get('passed') is True
             and report.get('mode') == proof_mode
             and report.get('packet_sha256') == packet_sha256
             and report.get('counts') == proof_counts
             and report.get('application_verified') is False
             and report.get('setup_executed') is False
             and report.get('private_cache_persisted') is False
             and report.get('qualification_extras_executed') is False
             and report.get('old_base_full_rejected_at_near_publics') is True
             and report.get('application_stage_pins_authority')
                == 'caller-supplied; external finalized-state verification required'
             and report.get('application_stage_pins') == stage_pins
             and all(report.get(name) == value
                     for name, value in report_identities.items()),
             'proof report stage pins or frozen identities mismatch')


def _case_cohort(freeze, freeze_sha, cohort, cohort_sha):
    _require(type(freeze) is dict and freeze.get('schema') == FREEZE_SCHEMA
             and type(freeze.get('frozen_at_unix_ns')) is int
             and freeze['frozen_at_unix_ns'] > 0
             and type(freeze.get('identities')) is dict
             and set(freeze['identities']) == set(IDENTITY_ROLES)
             and all(_is_sha(value) for value in freeze['identities'].values()),
             'complete frozen boundary identity required')
    _require(type(cohort) is dict and cohort.get('schema') == COHORT_SCHEMA
             and cohort.get('status') == 'cohort_issued_pending_application_gate'
             and cohort.get('keys_generated_after_freeze') is True
             and cohort.get('freeze_sha256') == freeze_sha
             and cohort.get('frozen_at_unix_ns') == freeze['frozen_at_unix_ns']
             and type(cohort.get('generation_started_unix_ns')) is int
             and cohort['generation_started_unix_ns'] > freeze['frozen_at_unix_ns']
             and type(cohort.get('generation_completed_unix_ns')) is int
             and cohort['generation_completed_unix_ns'] >= cohort['generation_started_unix_ns']
             and cohort.get('identities') == freeze['identities'],
             'post-freeze cohort and boundary identities must match')
    counts = cohort.get('counts')
    rows = cohort.get('certificates')
    _require(counts == {'issuers': 4, 'holders': 8, 'certificates': 8,
                        'openssl_issuances': 4, 'policies': 2}
             and type(rows) is list and len(rows) == 8,
             'exact four-issuer/eight-certificate/four-OpenSSL cohort required')
    by_variant, issuer_keys, holder_keys, holders = {}, {}, set(), set()
    issuer_rows, policies, akis = {}, set(), set()
    for row in rows:
        _require(type(row) is dict, 'certificate provenance row required')
        variant, issuer, holder = (row.get('variant'), row.get('issuer_index'),
                                   row.get('holder_index'))
        _require(type(variant) is int and variant in range(8) and variant not in by_variant
                 and type(issuer) is int and issuer in range(4)
                 and type(holder) is int and holder in range(8) and holder not in holders,
                 'unique variant/layout/issuer/holder assignment required')
        for name in ('credential_sha256', 'tbs_sha256', 'issuer_public_key_sha256',
                     'holder_public_key_sha256', 'aki_sha256'):
            _require(_is_sha(row.get(name)), f'pinned {name} required')
        _require(row.get('encoder') == ('openssl' if variant < 4 else 'cryptography'),
                 'four OpenSSL and four cryptography layouts in registered order required')
        prior = issuer_keys.setdefault(issuer, row['issuer_public_key_sha256'])
        _require(prior == row['issuer_public_key_sha256'],
                 'issuer index changed public-key fingerprint')
        _require(type(row.get('issuer_hash')) is str and row['issuer_hash'].isdecimal()
                 and type(row.get('policy_hash')) is str and row['policy_hash'].isdecimal(),
                 'canonical issuer and policy hashes required')
        _require(type(row.get('not_before_unix')) is int
                 and type(row.get('not_after_unix')) is int
                 and 0 <= row['not_before_unix'] < row['not_after_unix'],
                 'bounded certificate validity required')
        issuer_rows.setdefault(issuer, []).append(row)
        policies.add(row['policy_hash'])
        akis.add(row['aki_sha256'])
        by_variant[variant] = row
        holders.add(holder)
        holder_keys.add(row['holder_public_key_sha256'])
    _require(set(by_variant) == set(range(8)) and set(issuer_keys) == set(range(4))
             and len(set(issuer_keys.values())) == 4 and holders == set(range(8))
             and len(holder_keys) == 8 and len(policies) == 2 and len(akis) == 4
             and cohort.get('policy_hashes') == sorted(policies, key=int)
             and cohort.get('issuer_aki_sha256') == sorted(akis)
             and all(len(group) == 2
                     and {row['policy_hash'] for row in group} == policies
                     and len({row['issuer_hash'] for row in group}) == 1
                     and len({row['aki_sha256'] for row in group}) == 1
                     for group in issuer_rows.values()),
             'all eight layouts, four issuers, and both policies per issuer required')
    return by_variant


def _verify_cohort_generation_provenance(freeze, freeze_sha, cohort, by_variant,
                                        freeze_ref, cohort_ref):
    freeze_path = Path(freeze_ref['path'])
    cohort_path = Path(cohort_ref['path'])
    _require(freeze_path.name == 'freeze.json'
             and cohort_path.name == 'cohort-receipt.json',
             'deterministic freeze and cohort receipt paths required')

    inventory_path = freeze_path.parent / 'prior-key-inventory.json'
    inventory, inventory_sha = _json(
        {'path': str(inventory_path),
         'sha256': cohort.get('prior_key_inventory_sha256')}, cap=MAX_JSON)
    forbidden = freeze.get('forbidden_public_key_sha256')
    _require(_is_sha(cohort.get('prior_key_inventory_sha256'))
             and type(forbidden) is list and forbidden
             and all(_is_sha(item) for item in forbidden)
             and len(set(forbidden)) == len(forbidden)
             and type(inventory) is dict
             and set(inventory) == {'schema', 'observed_at_unix_ns',
                                    'freeze_sha256', 'public_key_sha256'}
             and inventory.get('schema') == 'credential-v3-prior-public-key-inventory-v1'
             and type(inventory.get('observed_at_unix_ns')) is int
             and 0 < inventory['observed_at_unix_ns'] < freeze['frozen_at_unix_ns']
             and inventory.get('freeze_sha256') == freeze_sha
             and type(inventory.get('public_key_sha256')) is list
             and inventory['public_key_sha256']
             and all(_is_sha(item) for item in inventory['public_key_sha256'])
             and len(set(inventory['public_key_sha256']))
                == len(inventory['public_key_sha256'])
             and set(inventory['public_key_sha256'])
                == set(forbidden),
             'pinned prior-key inventory must match the frozen earlier-key census')
    prior_keys = set(inventory['public_key_sha256'])

    key_receipt_path = cohort_path.parent / 'keys' / 'key-generation-receipt.json'
    key_receipt, key_receipt_sha = _json(
        {'path': str(key_receipt_path),
         'sha256': cohort.get('key_generation_receipt_sha256')}, cap=65536)
    provenance = key_receipt.get('provenance') if type(key_receipt) is dict else None
    _require(_is_sha(cohort.get('key_generation_receipt_sha256'))
             and type(key_receipt) is dict
             and key_receipt.get('schema') == 'credential-v3-heldout-key-generation-v1'
             and key_receipt.get('freeze_receipt_sha256') == freeze_sha
             and key_receipt.get('frozen_at_unix_ns') == freeze['frozen_at_unix_ns']
             and key_receipt.get('identities') == freeze['identities']
             and key_receipt.get('issuance_tool_sha256') == freeze.get('issuance_tool_sha256')
             and key_receipt.get('key_generation_tool_sha256')
                == freeze.get('key_generation_tool_sha256')
             and key_receipt.get('counts') == {'issuers': 4, 'holders': 8}
             and type(key_receipt.get('generation_started_unix_ns')) is int
             and type(key_receipt.get('generation_completed_unix_ns')) is int
             and cohort['generation_started_unix_ns']
                <= key_receipt['generation_started_unix_ns']
             and freeze['frozen_at_unix_ns']
                < key_receipt['generation_started_unix_ns']
             and key_receipt['generation_started_unix_ns']
                <= key_receipt['generation_completed_unix_ns']
             and key_receipt['generation_completed_unix_ns']
                <= cohort['generation_completed_unix_ns']
             and key_receipt.get('prior_public_key_count') == len(prior_keys)
             and cohort.get('prior_public_key_count') == len(prior_keys)
             and type(provenance) is dict
             and provenance.get('implementation')
                == 'cryptography.rsa.generate_private_key'
             and type(provenance.get('cryptography_version')) is str
             and provenance['cryptography_version']
             and type(provenance.get('backend')) is str and provenance['backend']
             and provenance.get('key_size') == 2048
             and provenance.get('public_exponent') == 65537
             and provenance.get('imported_keys') is False
             and provenance.get('certificates_issued') is False
             and provenance.get('reuse_scope')
                == 'supplied earlier-key inventory and complete new cohort',
             'pinned post-freeze heldout key-generation receipt required')

    keys = key_receipt.get('keys')
    _require(type(keys) is list and len(keys) == 12,
             'exact four issuer and eight holder key-generation rows required')
    keys_by_role_index = {}
    generated_fingerprints = set()
    previous_key_time = key_receipt['generation_started_unix_ns']
    for row in keys:
        _require(type(row) is dict, 'key-generation row required')
        role, index = row.get('role'), row.get('index')
        expected_count = {'issuer': 4, 'holder': 8}.get(role)
        _require(expected_count is not None and type(index) is int
                 and 0 <= index < expected_count
                 and (role, index) not in keys_by_role_index
                 and _is_sha(row.get('public_key_sha256'))
                 and type(row.get('generation_started_unix_ns')) is int
                 and type(row.get('generation_completed_unix_ns')) is int
                 and previous_key_time <= row['generation_started_unix_ns']
                 and row['generation_started_unix_ns']
                    <= row['generation_completed_unix_ns']
                 and row['generation_completed_unix_ns']
                    <= key_receipt['generation_completed_unix_ns'],
                 'ordered bounded key-generation row required')
        fingerprint = row['public_key_sha256']
        _require(fingerprint not in generated_fingerprints and fingerprint not in prior_keys,
                 'heldout public keys must be unique and absent from prior inventory')
        generated_fingerprints.add(fingerprint)
        keys_by_role_index[(role, index)] = row
        previous_key_time = row['generation_completed_unix_ns']
    _require(set(keys_by_role_index) == {
        *(("issuer", index) for index in range(4)),
        *(("holder", index) for index in range(8)),
    } and key_receipt['generation_completed_unix_ns'] >= previous_key_time,
             'complete issuer/holder key-generation map required')

    serials = set()
    previous_issuance_time = key_receipt['generation_completed_unix_ns']
    for variant in range(8):
        row = by_variant[variant]
        serial_hex = row.get('serial_hex')
        expected_serial = (1 << 120) + variant + 1
        _require(type(serial_hex) is str
                 and re.fullmatch(r'[0-9a-f]{32}', serial_hex) is not None
                 and int(serial_hex, 16) == expected_serial
                 and 0 < expected_serial < 1 << 128
                 and 1 <= bytes.fromhex(serial_hex)[0] <= 0x7f
                 and serial_hex not in serials,
                 'canonical distinct positive 16-byte heldout serial sequence required')
        serials.add(serial_hex)
        issuer_key = keys_by_role_index[('issuer', row['issuer_index'])]
        holder_key = keys_by_role_index[('holder', row['holder_index'])]
        _require(row['issuer_public_key_sha256'] == issuer_key['public_key_sha256']
                 and row['holder_public_key_sha256'] == holder_key['public_key_sha256'],
                 'certificate row keys must match the pinned key-generation receipt')
        started, completed = (row.get('issuance_started_unix_ns'),
                              row.get('issuance_completed_unix_ns'))
        _require(type(started) is int and type(completed) is int
                 and previous_issuance_time <= started <= completed
                 and completed <= cohort['generation_completed_unix_ns'],
                 'ordered certificate issuance must follow key generation within cohort window')
        previous_issuance_time = completed
    _require(len(serials) == 8,
             'all heldout certificate serials must be distinct')
    import_evidence = _verify_cohort_import(
        cohort_path.parent, by_variant, keys_by_role_index, prior_keys,
        freeze_sha, cohort_ref['sha256'],
        frozen_at_unix_ns=freeze['frozen_at_unix_ns'])
    return {'prior_key_inventory_sha256': inventory_sha,
            'key_generation_receipt_sha256': key_receipt_sha,
            'cohort_import_evidence': import_evidence}


def _source(source_ref, expected, globals_, case, stage, transition_sha=None,
            prior_r0_sha=None, prior_r0=None):
    _require(type(source_ref) is dict and set(source_ref) == {'receipt', 'artifacts'},
             'pinned source receipt and artifact map required')
    receipt, receipt_sha = _json(source_ref['receipt'], cap=16384)
    files = source_ref['artifacts']
    _require(type(files) is dict and files, 'complete source artifact map required')
    receipt_artifacts = receipt.get('artifacts_sha256')
    _require(type(receipt_artifacts) is dict and set(receipt_artifacts) == set(files),
             'source receipt artifact inventory must be complete')
    actual_files = {}
    for name, ref in files.items():
        _require(type(name) is str and not name.startswith('/') and '..' not in Path(name).parts,
                 'safe source artifact name required')
        _, actual, raw = _artifact(ref, cap=4 * 1024 * 1024)
        _require(receipt_artifacts.get(name) == actual,
                 'source artifact hash differs from source receipt')
        actual_files[name] = (actual, raw)
    _require(receipt.get('schema') == SOURCE_SCHEMA
             and receipt.get('freeze_sha256') == globals_['freeze_sha256']
             and receipt.get('cohort_receipt_sha256') == globals_['cohort_sha256']
             and receipt.get('case_context_sha256') == case['case_sha256']
             and receipt.get('pair_receipt_sha256') == case['pair_sha256']
             and receipt.get('target_variant') == case['variant']
             and receipt.get('issuer_index') == case['target']['issuer_index']
             and receipt.get('holder_index') == case['target']['holder_index']
             and receipt.get('target_der_sha256') == case['target']['credential_sha256']
             and receipt.get('target_tbs_sha256') == case['target']['tbs_sha256']
             and receipt.get('issuer_public_key_sha256') == case['target']['issuer_public_key_sha256']
             and receipt.get('holder_public_key_sha256') == case['target']['holder_public_key_sha256']
             and receipt.get('stage_report_sha256') == stage['report_sha256']
             and receipt.get('stage_plan_sha256') == stage['plan_sha256']
             and receipt.get('context_sha256') == case['case_sha256']
             and receipt.get('stage_context_sha256') == case['stage_context_sha256']
             and receipt.get('membership_sha256') == case['membership_sha256']
             and receipt.get('membership_roots') == case['roots']
             and receipt.get('transition_report_sha256') == transition_sha
             and receipt.get('variant') == expected,
             'heldout source receipt identity or branch stage mismatch')
    for field in ('staged_request_sha256', 'finalized_request_sha256',
                  'finalized_action_transport_sha256', 'action_hash', 'exporter_sha256',
                  'training_helper_sha256', 'training_receipt_sha256'):
        _require(_is_sha(receipt.get(field)), f'pinned source {field} required')
    for role in ('exporter', 'training_helper'):
        _require(globals_['source_files'][role] == receipt[
            'exporter_sha256' if role == 'exporter' else 'training_helper_sha256'],
            f'heldout source {role} drift detected')
    _require(actual_files.get('staged-request.bin', (None, None))[0]
             == receipt['staged_request_sha256']
             and actual_files.get('finalized-request.bin', (None, None))[0]
             == receipt['finalized_request_sha256']
             and actual_files.get('action-transport.bin', (None, None))[0]
             == receipt['finalized_action_transport_sha256'],
             'finalized source request or action bytes changed')
    f1 = actual_files['finalized-request.bin'][1]
    f2 = actual_files['action-transport.bin'][1]
    _require(f1 is not None and len(f1) == 2874 and f1[:4] == b'V3F1'
             and f2 is not None and len(f2) == 561
             and f2[:4] == b'V3F2' and f2[164:196].hex() == receipt['action_hash'],
             'Rust-finalized V3 request/action transport required')
    if expected in ('R0', 'R1'):
        selected = 'R0' if expected == 'R0' else 'R1'
        _require(receipt.get('selected_root') == case['roots'][selected],
                 'source selected the wrong membership root')
    if expected == 'R1':
        _require(prior_r0_sha is not None and receipt.get('r0_source_receipt_sha256') == prior_r0_sha
                 and type(prior_r0) is dict
                 and receipt.get('staged_request_sha256') == prior_r0.get('staged_request_sha256')
                 and receipt.get('action_hash') == prior_r0.get('action_hash')
                 and receipt.get('finalized_action_transport_sha256')
                    == prior_r0.get('finalized_action_transport_sha256')
                 and receipt.get('finalized_request_sha256')
                    != prior_r0.get('finalized_request_sha256'),
                 'R1 request must preserve exact R0 action and stage request')
    return receipt, receipt_sha, actual_files


def _accounts(bundle, report, label):
    refs = bundle.get('accounts')
    _require(type(refs) is dict and set(refs) == set(ACCOUNT_NAMES),
             f'{label} five finalized account artifacts required')
    hashes = report.get('account_sha256')
    _require(type(hashes) is list and len(hashes) == 5 and all(_is_sha(x) for x in hashes),
             f'{label} five account hashes required')
    raw_accounts = {}
    for name, expected, ref in zip(ACCOUNT_NAMES, hashes, (refs[n] for n in ACCOUNT_NAMES)):
        _, actual, raw = _artifact(ref, cap=16384)
        _require(actual == expected, f'{label} {name} account differs from report')
        raw_accounts[name] = raw
    return raw_accounts


def _outer(ref, label, *, expected_exit=1):
    outer, _ = _json(ref, cap=65536)
    expected_passed = expected_exit == 0
    _require(type(outer) is dict and outer.get('schema') == 1
             and outer.get('passed') is expected_passed
             and outer.get('exit_code') == expected_exit
             and outer.get('stop_reason') is None and outer.get('runner_error_type') is None
             and outer.get('cleanup_remaining_owned_processes') == 0
             and outer.get('cleanup_status_unknown') is False
             and type(outer.get('duration_seconds')) in (int, float)
             and outer.get('duration_seconds') > 0
             and type(outer.get('sample_count')) is int and outer['sample_count'] > 0,
             f'{label} complete uncensored outer session with expected exit required')
    return outer


def _proof_outer_limits_match(outer, limits):
    observed = outer.get('limits') if type(outer) is dict else None
    return (type(observed) is dict
            and set(observed) == {'runtime_seconds', 'owned_tree_rss_bytes',
                                  'storage_growth_bytes', 'poll_seconds'}
            and observed.get('runtime_seconds') == limits.get('runtime_seconds')
            and observed.get('owned_tree_rss_bytes') == limits.get('rss_bytes')
            and observed.get('storage_growth_bytes') == limits.get('storage_bytes')
            and observed.get('poll_seconds') == PROOF_POLL_SECONDS)


def _reviewed_validator_sigint(cleanup):
    return (type(cleanup) is dict and cleanup.get('spawned') is True
            and cleanup.get('reaped') is True and cleanup.get('graceful') is False
            and cleanup.get('exit_code') == -signal.SIGINT)


def _reviewed_runner_exit(cleanup):
    return (type(cleanup) is dict and cleanup.get('spawned') is True
            and cleanup.get('reaped') is True and cleanup.get('exit_code') == 0)


def _verify_reviewed_local_status(status, *, scope, verified_field, report_field,
                                  report_sha256, application_effect, effect_count,
                                  mode=None):
    _require(type(status) is dict and status.get('scope') == scope
             and status.get('status') == 'failed' and status.get('error_type') is None
             and status.get(verified_field) is True
             and status.get(report_field) == report_sha256
             and status.get('application_effect') is application_effect
             and status.get('effect_count') == effect_count
             and (mode is None or status.get('mode') == mode)
             and _reviewed_validator_sigint(status.get('validator_cleanup'))
             and _reviewed_runner_exit(status.get('runner_cleanup')),
             'reviewed stop must pin a verified result and expected cleanup')


def _proof_case_label(case, request_name):
    variant = case.get('variant') if type(case) is dict else None
    _require(type(variant) is int and variant in range(8)
             and request_name in {'positive_full', 'unrelated_compare', 'own_revocation'},
             'registered heldout proof case identity required')
    return f'heldout_v{variant:02d}_{request_name}'


def _declared_limits_match(declared, observed):
    return (type(declared) is dict
            and set(declared) == {'runtime_seconds', 'rss_bytes', 'storage_growth_bytes'}
            and type(observed) is dict
            and set(observed) == {'runtime_seconds', 'owned_tree_rss_bytes',
                                  'storage_growth_bytes', 'poll_seconds'}
            and observed.get('runtime_seconds') == declared.get('runtime_seconds')
            and observed.get('owned_tree_rss_bytes') == declared.get('rss_bytes')
            and observed.get('storage_growth_bytes') == declared.get('storage_growth_bytes')
            and type(observed.get('poll_seconds')) in (int, float)
            and observed['poll_seconds'] == 0.2)


def _verify_report_runtime_identity(report, status, config, frozen_elf_sha256, *,
                                   expected_program, expected_genesis):
    """Join the report's ELF summary to the full identity saved in stop status."""
    summary = report.get('loaded_program') if type(report) is dict else None
    runtime = status.get('loaded_program') if type(status) is dict else None
    _require(type(summary) is dict and type(runtime) is dict
             and type(config) is dict and config.get('expected_genesis') == expected_genesis
             and type(report.get('program')) is str and report['program']
             and type(report.get('genesis')) is str and report['genesis']
             and report.get('program') == expected_program
             and report.get('genesis') == expected_genesis
             and summary.get('elf_match') is True
             and summary.get('elf_sha256') == frozen_elf_sha256
             and summary.get('loader') == runtime.get('loader')
             and type(summary.get('local_bytes')) is int
             and summary.get('local_bytes') == runtime.get('elf_bytes')
             and type(summary.get('remote_bytes')) is int
             and summary.get('remote_bytes') == runtime.get('elf_bytes')
             and runtime.get('elf_match') is True
             and runtime.get('elf_sha256') == frozen_elf_sha256
             and runtime.get('program') == report.get('program')
             and runtime.get('genesis') == report.get('genesis')
             and all(type(runtime.get(name)) is str and runtime.get(name)
                     for name in ('program', 'programdata', 'loader', 'genesis'))
             and _is_sha(runtime.get('program_account_sha256'))
             and _is_sha(runtime.get('programdata_account_sha256')),
             'report and stop-status runtime identity mismatch')
    return {name: runtime[name] for name in (
        'program', 'programdata', 'elf_sha256', 'program_account_sha256',
        'programdata_account_sha256', 'genesis')}


def _validate_stage(stage_bundle, case, frozen_elf_sha256):
    _require(type(stage_bundle) is dict and set(stage_bundle) == {
        'report', 'plan', 'allocations', 'signed_history', 'accounts',
        'config', 'status', 'monitor', 'monitor_owner'},
        'complete stage evidence bundle required')
    report, report_sha = _json(stage_bundle['report'], cap=65536)
    plan, plan_sha = _json(stage_bundle['plan'], cap=16384)
    allocations, allocations_sha = _json(stage_bundle['allocations'], cap=16384)
    history, history_sha = _json(stage_bundle['signed_history'])
    config, config_sha = _json(stage_bundle['config'], cap=65536)
    status, status_sha = _json(stage_bundle['status'], cap=65536)
    monitor, monitor_sha = _json(stage_bundle['monitor'], cap=65536)
    monitor_owner = stage_bundle['monitor_owner']
    _outer(stage_bundle['monitor'], 'stage', expected_exit=1)
    _require(report.get('schema') == 'part5-v3-local-stage-v1'
             and report.get('passed') is True and report.get('training_only') is True
             and report.get('registry_history_authenticated') is True
             and report.get('allocation_history_authenticated') is True
             and report.get('proof_created') is False and report.get('application_effect') is False
             and report.get('plan_sha256') == plan_sha
             and report.get('signed_history_sha256') == history_sha
             and report.get('initial_allocations_sha256') == allocations_sha
             and allocations == case['stage_context'].get('initial_allocations'),
             'raw heldout stage report does not bind its plan/history/allocations')
    _verify_pre_enrollment_create(
        report.get('transactions'), report.get('pre_enrollment_create_request_absent'))
    _require(type(monitor_owner) is str and monitor_owner
             and config.get('scope') == 'part5-v3-local-stage'
             and config.get('stage_output') == str(Path(stage_bundle['report']['path']).parent)
             and type(status) is dict and status.get('scope') == 'part5-v3-local-stage'
             and status.get('status') == 'failed'
             and status.get('config_sha256') == config_sha
             and status.get('stage_report_sha256') == report_sha
             and status.get('stage_verified') is True
             and status.get('stage_output') == config.get('stage_output')
             and status.get('application_effect') is False
             and status.get('ledger_reuse_requires_review') is True
             and status.get('error_type') is None
             and status.get('validator_cleanup', {}).get('exit_code') == -signal.SIGINT
             and status.get('validator_cleanup', {}).get('graceful') is False
             and status.get('validator_cleanup', {}).get('reaped') is True
             and status.get('runner_cleanup', {}).get('exit_code') == 0
             and status.get('runner_cleanup', {}).get('reaped') is True
             and monitor.get('owner') == monitor_owner
             and monitor.get('stop_reason') is None
             and monitor.get('runner_error_type') is None
             and monitor.get('cleanup_remaining_owned_processes') == 0
             and monitor.get('cleanup_status_unknown') is False
             and _declared_limits_match(config.get('outer_limits_required'),
                                        monitor.get('limits')),
             'verified stopped R0 stage config/status/monitor required')
    history_chain = _verify_history(history, plan, case, [case['roots']['R0']])
    _require(type(plan) is dict and _field_bytes(plan.get('root'), 'stage root').hex()
             == case['roots']['R0'], 'stage plan must start from heldout R0')
    expected_program = _base58(_field_bytes(plan.get('program'), 'stage program'))
    expected_genesis = _base58(_field_bytes(plan.get('genesis'), 'stage genesis'))
    runtime_identity = _verify_report_runtime_identity(
        report, status, config, frozen_elf_sha256,
        expected_program=expected_program, expected_genesis=expected_genesis)
    accounts = _accounts(stage_bundle, report, 'stage')
    _require(len(accounts['config']) == 381 and len(accounts['request']) == 2249
             and accounts['request'][:8] == b'DYNREQ03',
             'finalized stage config/request account shape required')
    _require(report.get('source_head_digest') == history_chain['source_sha256']
             and report.get('publisher_envelope_digest')
                == history_chain['publisher_sha256']
             and len(accounts['head']) == 280
             and accounts['head'][112:144].hex() == history_chain['publisher_sha256']
             and accounts['head'][224:256].hex() == history_chain['source_sha256'],
             'stage signed history must match its finalized publisher head')
    return {'report': report, 'report_sha256': report_sha,
            'plan': plan, 'plan_sha256': plan_sha,
            'allocations': allocations, 'allocations_sha256': allocations_sha,
            'history': history, 'history_sha256': history_sha,
            'accounts': accounts, 'request_sha256': _sha(accounts['request']),
            'config': config, 'config_sha256': config_sha,
            'config_path': stage_bundle['config']['path'],
            'status': status, 'status_sha256': status_sha,
            'status_path': stage_bundle['status']['path'],
            'monitor': monitor, 'monitor_sha256': monitor_sha,
            'monitor_path': stage_bundle['monitor']['path'],
            'monitor_owner': monitor_owner,
            'runtime_identity': runtime_identity}


def _verify_transition(bundle, stage, case, frozen_elf_sha256):
    _require(type(bundle) is dict and set(bundle) == {
        'report', 'status', 'outer', 'config', 'monitor', 'monitor_owner',
        'context', 'signed_history',
        'signed_source', 'enrolled_source', 'accounts'},
        'complete R0-to-R1 transition evidence bundle required')
    report, report_sha = _json(bundle['report'], cap=65536)
    status, _ = _json(bundle['status'], cap=65536)
    config, config_sha = _json(bundle['config'], cap=65536)
    monitor, monitor_sha = _json(bundle['monitor'], cap=65536)
    monitor_owner = bundle['monitor_owner']
    context, context_sha = _json(bundle['context'], cap=16384)
    history, history_sha = _json(bundle['signed_history'])
    _require(bundle['outer'] == bundle['monitor'],
             'transition outer and monitor must be the same pinned runner report')
    outer = _outer(bundle['outer'], 'transition', expected_exit=1)
    _require(type(status) is dict
             and status.get('scope') == 'part5-v3-local-unrelated-transition'
             and status.get('config_sha256') == config_sha
             and status.get('status') == 'failed'
             and status.get('transition_verified') is True
             and status.get('transition_report_sha256') == report_sha
             and status.get('transition_output') == config.get('transition_output')
             and status.get('ledger_reuse_requires_review') is True
             and status.get('validator_cleanup', {}).get('exit_code') == -signal.SIGINT
             and status.get('validator_cleanup', {}).get('reaped') is True
             and status.get('runner_cleanup', {}).get('exit_code') == 0
             and status.get('runner_cleanup', {}).get('reaped') is True
             and status.get('error_type') is None
             and type(monitor_owner) is str and monitor_owner
             and monitor.get('owner') == monitor_owner
             and monitor.get('stop_reason') is None
             and monitor.get('runner_error_type') is None
             and monitor.get('cleanup_remaining_owned_processes') == 0
             and monitor.get('cleanup_status_unknown') is False
             and outer.get('owner') == monitor_owner
             and _declared_limits_match(config.get('outer_limits_required'),
                                        outer.get('limits'))
             and config.get('scope') == 'part5-v3-local-unrelated-transition'
             and config.get('expected_genesis') == stage['report'].get('genesis')
             and config.get('stage_root') == stage['config']['stage_output']
             and config.get('ledger') == stage['config'].get('ledger')
             and config.get('stage_report_sha256') == stage['report_sha256']
             and config.get('stage_plan_sha256') == stage['plan_sha256']
             and config.get('transition_context') == bundle['context']['path']
             and config.get('transition_context_sha256') == context_sha
             and config.get('transition_output') == str(
                 Path(bundle['report']['path']).parent)
             and config.get('prior_stage_config') == stage['config_path']
             and config.get('prior_stage_config_sha256') == stage['config_sha256']
             and config.get('prior_stage_status') == stage['status_path']
             and config.get('prior_stage_status_sha256') == stage['status_sha256']
             and config.get('prior_stage_monitor') == stage['monitor_path']
             and config.get('prior_stage_monitor_sha256') == stage['monitor_sha256'],
             'transition supervisor status does not pin its report')
    _require(report.get('schema') == 'part5-v3-unrelated-local-transition-v1'
             and report.get('passed') is True and report.get('training_only') is True
             and report.get('application_effect') is False
             and report.get('request_unconsumed') is True
             and report.get('upstream_source_authentication') is True
             and report.get('stage_report_sha256') == stage['report_sha256']
             and report.get('stage_plan_sha256') == stage['plan_sha256']
             and report.get('transition_context_sha256') == context_sha
             and report.get('signed_history_sha256') == history_sha
             and report.get('base_root') == case['roots']['R0']
             and report.get('near_root') == case['roots']['R1']
             and report.get('program') == stage['report'].get('program')
             and report.get('genesis') == stage['report'].get('genesis'),
             'signed unrelated-root transition does not bind R0 to R1')
    runtime_identity = _verify_report_runtime_identity(
        report, status, config, frozen_elf_sha256,
        expected_program=stage['report']['program'],
        expected_genesis=stage['report']['genesis'])
    _require(runtime_identity == stage['runtime_identity'],
             'transition loaded runtime differs from its exact stage')
    chain = _verify_history(history, stage['plan'], case,
                            [case['roots']['R0'], case['roots']['R1']])
    signed, _ = _json(bundle['signed_source'], cap=65536)
    _require(signed == history['checkpoints'][-1]['source'],
             'transition signed source must be the latest signed-history checkpoint')
    _verify_signed_source(bundle['signed_source'], bundle['enrolled_source'],
                          stage['plan'], report, case,
                          expected_changes=[{'Revoke': {'tbs_digest': list(
                              bytes.fromhex(case['unrelated']['tbs_sha256']))}}],
                          expected_prior=chain['previous_source_sha256'],
                          expected_sequence=2)
    accounts = _accounts(bundle, report, 'transition')
    _require(report.get('source_head_digest') == chain['source_sha256']
             and report.get('publisher_envelope_digest')
                == chain['publisher_sha256']
             and len(accounts['head']) == 280
             and accounts['head'][112:144].hex() == chain['publisher_sha256']
             and accounts['head'][224:256].hex() == chain['source_sha256'],
             'transition signed history must match its finalized publisher head')
    _require(accounts['request'] == stage['accounts']['request']
             and accounts['queue'] == stage['accounts']['queue']
             and accounts['config'][332:364].hex() == case['roots']['R1']
             and int.from_bytes(accounts['config'][364:372], 'little') == 1,
             'R0-to-R1 transition must preserve request/queue and finalize R1 config')
    return {'report': report, 'report_sha256': report_sha,
            'context': context, 'context_sha256': context_sha,
            'history': history, 'history_sha256': history_sha,
            'accounts': accounts, 'source_sha256': chain['source_sha256'],
            'config': config, 'config_sha256': config_sha,
            'config_path': bundle['config']['path'], 'status': status,
            'status_sha256': _pin_sha(bundle['status']),
            'status_path': bundle['status']['path'],
            'monitor': monitor, 'monitor_sha256': monitor_sha,
            'monitor_path': bundle['monitor']['path'],
            'monitor_owner': monitor_owner,
            'runtime_identity': runtime_identity}


def _verify_history(history, plan, case, expected_roots, *, final_change=None):
    _require(type(history) is dict
             and history.get('schema') == 'part5-v3-two-leaf-signed-history-v1'
             and type(history.get('checkpoints')) is list
             and len(history['checkpoints']) == len(expected_roots),
             'complete pinned two-leaf signed history required')
    source_key = _field_bytes(plan.get('source'), 'source verification key')
    publisher_key = _field_bytes(plan.get('publisher'), 'publisher verification key')
    own, other = (bytes.fromhex(case['target']['tbs_sha256']),
                  bytes.fromhex(case['unrelated']['tbs_sha256']))
    slot = case['membership']['slot']
    expected_changes = [
        [{'Issue': {'tbs_digest': list(own), 'slot': slot, 'allocation_epoch': 1}},
         {'Issue': {'tbs_digest': list(other), 'slot': slot ^ 1, 'allocation_epoch': 1}}],
        [{'Revoke': {'tbs_digest': list(other)}}],
    ]
    if len(expected_roots) == 3:
        expected_changes.append(final_change)
    _require(len(expected_changes) == len(expected_roots)
             and all(type(changes) is list for changes in expected_changes),
             'branch-specific signed history change required')
    previous_source = bytes(32)
    previous_publisher = bytes(32)
    previous_root = None
    previous_root_version = None
    previous_scope = previous_issuer = None
    previous_source_sha = None
    previous_publisher_sha = None
    for index, (checkpoint, expected_root) in enumerate(
            zip(history['checkpoints'], expected_roots)):
        _require(type(checkpoint) is dict and type(checkpoint.get('source')) is dict
                 and type(checkpoint.get('publisher')) is dict,
                 'signed source and publisher checkpoint required')
        signed, binding = checkpoint['source'], checkpoint['publisher']
        observation = signed.get('observation')
        _require(type(observation) is dict and type(binding.get('scope')) is dict
                 and type(binding.get('issuer')) is dict,
                 'signed source observation and publisher binding required')
        changes = expected_changes[index]
        _require(observation.get('sequence') == index + 1
                 and _field_bytes(observation.get('previous_digest'), 'source predecessor')
                    == previous_source
                 and observation.get('issuer_status_active') is True
                 and observation.get('changes') == changes
                 and observation.get('scope') == binding.get('scope')
                 and observation.get('issuer') == binding.get('issuer')
                 and _field_bytes(observation.get('issuer', {}).get('source_key'),
                                  'checkpoint source key') == source_key
                 and _field_bytes(binding.get('publisher_key'), 'checkpoint publisher key')
                    == publisher_key
                 and binding.get('publication_sequence') == index + 1
                 and _field_bytes(binding.get('previous_publication_digest'),
                                  'publisher predecessor') == previous_publisher
                 and _field_bytes(binding.get('root'), 'published root').hex() == expected_root,
                 'signed history order, changes, keys, or roots mismatch')
        expected_version = (0 if index == 0 else previous_root_version
                            + int(expected_root != previous_root))
        _require(binding.get('root_version') == expected_version,
                 'signed publisher root version does not match root changes')
        if previous_scope is not None:
            _require(observation['scope'] == previous_scope
                     and observation['issuer'] == previous_issuer,
                     'signed history changed enrolled source identity')
        previous_scope, previous_issuer = observation['scope'], observation['issuer']
        source_signature = _field_bytes(signed.get('signature'), 'source signature')
        _require(len(source_signature) == 64, 'Ed25519 source signature required')
        source_status = b'DYNARK-V3-SOURCE-STATUS-v1\0' + json.dumps(
            observation, separators=(',', ':'), ensure_ascii=False).encode()
        source_wire = b'DYNARK-V3-SOURCE-WIRE-v1\0' + json.dumps(
            signed, separators=(',', ':'), ensure_ascii=False).encode()
        source_sha = hashlib.sha256(source_wire).digest()
        _require(type(binding.get('source_head')) is dict
                 and binding['source_head'].get('sequence') == index + 1
                 and _field_bytes(binding['source_head'].get('digest'),
                                  'published source head') == source_sha,
                 'publisher binding must commit to this source signature')
        body = {name: binding[name] for name in (
            'scope', 'issuer', 'source_head', 'root', 'root_version',
            'publisher_key', 'publication_sequence', 'previous_publication_digest')}
        publisher_message = b'DYNARK-V3-PUBLISHER-BINDING-v1\0' + json.dumps(
            body, separators=(',', ':'), ensure_ascii=False).encode()
        publisher_wire = b'DYNARK-V3-PUBLISHER-WIRE-v1\0' + json.dumps(
            binding, separators=(',', ':'), ensure_ascii=False).encode()
        publisher_sha = hashlib.sha256(publisher_wire).digest()
        publisher_signature = _field_bytes(binding.get('signature'), 'publisher signature')
        _require(len(publisher_signature) == 64,
                 'Ed25519 publisher signature required')
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        try:
            Ed25519PublicKey.from_public_bytes(source_key).verify(
                source_signature, source_status)
            Ed25519PublicKey.from_public_bytes(publisher_key).verify(
                publisher_signature, publisher_message)
        except Exception as error:
            raise ValueError('signed source/publisher history verification failed') from error
        prior_source_sha = previous_source_sha
        previous_source_sha = source_sha.hex()
        previous_source, previous_publisher = source_sha, publisher_sha
        previous_publisher_sha = publisher_sha.hex()
        previous_root, previous_root_version = expected_root, expected_version
    return {'source_sha256': previous_source_sha,
            'publisher_sha256': previous_publisher_sha,
            'previous_source_sha256': prior_source_sha}


def _private_directory(path, label):
    path = Path(path)
    info = path.lstat()
    _require(path.is_absolute() and path.resolve(strict=True) == path
             and stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
             and stat.S_IMODE(info.st_mode) == 0o700,
             f'owner-only canonical {label} directory required')
    return path


def _verify_r0_clone(bundle, execution_config, stage_bundle, stage):
    _require(type(bundle) is dict and set(bundle) == {'receipt'},
        'Full branch requires pinned stopped R0 clone evidence')
    stage_config, stage_config_sha = stage['config'], stage['config_sha256']
    stage_status_sha, monitor_sha = stage['status_sha256'], stage['monitor_sha256']
    receipt, receipt_sha = _json(bundle['receipt'], cap=65536)
    execution_ledger = execution_config.get('ledger')
    source_ledger = stage_config.get('ledger')
    destination = _private_directory(execution_ledger, 'R0 clone')
    source = _private_directory(source_ledger, 'R0 source ledger')
    _require(source != destination and source not in destination.parents
             and destination not in source.parents,
             'R0 execution must use a separate cloned ledger')
    receipt_path = Path(bundle['receipt']['path'])
    _require(receipt_path == destination.parent / 'clone-report.json'
             and execution_config.get('heldout_r0_clone_report') == str(receipt_path)
             and execution_config.get('heldout_r0_clone_report_sha256') == receipt_sha
             and execution_config.get('prior_stage_config')
                 == stage_bundle['config']['path']
             and execution_config.get('prior_stage_config_sha256') == stage_config_sha
             and execution_config.get('prior_stage_status')
                 == stage_bundle['status']['path']
             and execution_config.get('prior_stage_status_sha256') == stage_status_sha
             and execution_config.get('prior_stage_monitor')
                 == stage_bundle['monitor']['path']
             and execution_config.get('prior_stage_monitor_sha256') == monitor_sha
             and execution_config.get('stage_root') == stage_config.get('stage_output')
             and execution_config.get('stage_report_sha256') == stage['report_sha256'],
             'Full config must pin the exact stage and heldout clone receipt')
    _require(receipt.get('schema') == 'part5-v3-heldout-r0-ledger-clone-v1'
             and receipt.get('heldout_acceptance') is False
             and receipt.get('stage_report_sha256') == stage['report_sha256']
             and receipt.get('stage_status_sha256') == stage_status_sha
             and receipt.get('stage_monitor_sha256') == monitor_sha
             and receipt.get('source') == str(source)
             and receipt.get('destination') == str(destination)
             and receipt.get('source_stable') is True
             and receipt.get('copy_identical') is True
             and receipt.get('loaded_identity_rechecked_after_restart') is False
             and receipt.get('application_effect') is False
             and type(receipt.get('excluded_stale_admin_socket')) is bool,
             'independently pinned byte-identical stopped R0 clone receipt required')
    source_rows, clone_rows = ledger_inventory(source), ledger_inventory(destination)
    tree_sha = _sha(json.dumps(source_rows, separators=(',', ':')).encode())
    _require(source_rows == clone_rows
             and receipt.get('entry_count') == len(clone_rows)
             and receipt.get('tree_sha256') == tree_sha
             and receipt.get('excluded_stale_admin_socket') == stale_admin_socket(source),
             'R0 source and execution clone inventories differ')
    return receipt_sha


def _verify_r1_clone(bundle, branch_config, transition_bundle, transition):
    _require(type(bundle) is dict and set(bundle) == {'receipt'},
             'R1 branch requires a pinned independent ledger clone receipt')
    receipt, receipt_sha = _json(bundle['receipt'], cap=65536)
    transition_config = transition['config']
    transition_source = _private_directory(transition_config.get('ledger'),
                                           'R1 source ledger')
    destination = _private_directory(branch_config.get('ledger'), 'R1 branch clone')
    _require(destination != transition_source
             and transition_source not in destination.parents
             and destination not in transition_source.parents,
             'R1 execution must use a separate cloned ledger')
    receipt_path = Path(bundle['receipt']['path'])
    _require(receipt_path == destination.parent / 'clone-report.json'
             and branch_config.get('clone_report') == str(receipt_path)
             and branch_config.get('clone_report_sha256') == receipt_sha
             and branch_config.get('transition_report_sha256')
                == transition['report_sha256']
             and branch_config.get('transition_status')
                == transition_bundle['status']['path']
             and branch_config.get('transition_status_sha256')
                == transition['status_sha256']
             and branch_config.get('transition_monitor')
                == transition_bundle['monitor']['path']
             and branch_config.get('transition_monitor_sha256')
                == transition['monitor_sha256'],
             'R1 branch config must pin its transition and clone receipt')
    _require(receipt.get('schema') == 'part5-v3-r1-ledger-clone-v1'
             and receipt.get('training_only') is True
             and receipt.get('source_stable') is True
             and receipt.get('copy_identical') is True
             and receipt.get('transition_report_sha256') == transition['report_sha256']
             and receipt.get('transition_status_sha256') == transition['status_sha256']
             and receipt.get('transition_monitor_sha256') == transition['monitor_sha256']
             and receipt.get('source') == str(transition_source)
             and receipt.get('destination') == str(destination)
             and receipt.get('loaded_identity_rechecked_after_restart') is False
             and receipt.get('application_effect') is False
             and type(receipt.get('excluded_stale_admin_socket')) is bool,
             'byte-identical stopped R1 clone receipt required')
    source_rows = ledger_inventory(transition_source)
    clone_rows = ledger_inventory(destination)
    _require(source_rows == clone_rows
             and receipt.get('entry_count') == len(clone_rows)
             and receipt.get('tree_sha256')
                == _sha(json.dumps(source_rows, separators=(',', ':')).encode())
             and receipt.get('excluded_stale_admin_socket')
                == stale_admin_socket(transition_source),
             'R1 transition source and execution clone inventories differ')
    return {'receipt_sha256': receipt_sha, 'source': str(transition_source),
            'destination': str(destination), 'tree_sha256': receipt['tree_sha256']}


def _verify_signed_source(signed_ref, enrolled_ref, plan, report, case,
                          *, expected_changes, expected_prior, expected_sequence):
    """Check the raw source signature and the report's source-wire commitment."""
    signed, _ = _json(signed_ref, cap=65536)
    enrolled, _ = _json(enrolled_ref, cap=65536)
    _require(type(plan) is dict, 'signed source requires heldout stage plan')
    observation = signed.get('observation')
    _require(type(observation) is dict and type(enrolled) is dict
             and type(enrolled.get('issuer')) is dict,
             'signed source observation and enrollment required')
    source_key = _field_bytes(plan.get('source'), 'enrolled source public key')
    _require(_field_bytes(enrolled['issuer'].get('source_key'), 'enrolled source key')
             == source_key
             and _field_bytes(observation.get('issuer', {}).get('source_key'),
                              'observation source key') == source_key
             and observation.get('issuer') == enrolled.get('issuer')
             and observation.get('scope') == enrolled.get('scope')
             and observation.get('changes') == expected_changes,
             'source signature must bind the expected issuer and exact revocation')
    if expected_prior is not None:
        _require(_field_bytes(observation.get('previous_digest'), 'prior source digest')
                 == bytes.fromhex(expected_prior),
                 'source observation does not extend the verified prior head')
    if expected_sequence is not None:
        _require(observation.get('sequence') == expected_sequence,
                 'source observation sequence does not match the verified history')
    signature = _field_bytes(signed.get('signature'), 'source signature')
    _require(len(signature) == 64, 'Ed25519 source signature required')
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    status_message = b'DYNARK-V3-SOURCE-STATUS-v1\0' + json.dumps(
        observation, separators=(',', ':'), ensure_ascii=False).encode()
    try:
        Ed25519PublicKey.from_public_bytes(source_key).verify(signature, status_message)
    except Exception as error:
        raise ValueError('heldout source signature verification failed') from error
    wire = b'DYNARK-V3-SOURCE-WIRE-v1\0' + json.dumps(
        signed, separators=(',', ':'), ensure_ascii=False).encode()
    digest = _sha(wire)
    _require(report.get('source_head_digest') == digest,
             'raw transition report does not bind its signed source wire')
    return digest


def _verify_frozen_identity(freeze, manifest):
    direct = manifest.get('frozen_files')
    bundles = manifest.get('frozen_bundles')
    _require(type(direct) is dict and set(direct) == set(FROZEN_FILE_ROLES)
             and type(bundles) is dict and set(bundles) == {'registry', 'client'},
             'all direct and bundled frozen product identities are required')
    identities = freeze['identities']
    observed = {}
    setup = None
    for role, ref in direct.items():
        if role == 'setup_manifest':
            setup, actual = _json(ref, cap=65536)
        else:
            _, actual, _ = _artifact(ref)
        _require(actual == identities[role], f'frozen {role} identity drift detected')
        relative = {
            'profile': 'circuits/credential-v3-bounded/profile.json',
            'r1cs': 'artifacts/dynark/part5/v3-compile-001/credential.r1cs',
            'witness_executable': 'artifacts/dynark/part5/v3-compile-001/credential_js/credential.wasm',
            'setup_manifest': 'artifacts/dynark/part5/v3-development-setup-001/setup-manifest.json',
            'ordinary_vk': 'artifacts/dynark/part5/v3-development-setup-001/ordinary.vk',
            'proof_runner': 'circuits/credential-v3-bounded/qualification/proof-runner-v1/target/release/credential-v3-bounded-proof-qualification-v1',
            'signer_interface': 'tools/part5/prepare_v3_request_fixture.py',
            'loaded_elf': 'artifacts/dynark/part5/application-v3-sbf-build-002/elf/zk_fresh_program.so',
        }.get(role)
        if role in ('profile', 'r1cs', 'witness_executable', 'setup_manifest',
                    'ordinary_vk', 'proof_runner', 'signer_interface', 'loaded_elf'):
            _require(Path(ref['path']) == ROOT / relative,
                     f'frozen {role} must be rehashed from its live product path')
        observed[role] = actual
    _require(type(setup) is dict
             and setup.get('schema') == 'credential-v3-bounded-setup-v1'
             and setup.get('identity', {}).get('circuit') == identities['circuit'],
             'frozen setup manifest does not bind its circuit identity')

    for role in ('registry', 'client'):
        rows = bundles[role]
        _require(type(rows) is list and rows,
                 f'frozen {role} source member inventory required')
        seen_paths = set()
        hashing = hashlib.sha256(b'part5-v3-campaign-identity-bundle-v1\0')
        for row in sorted(rows, key=lambda item: item.get('path', '')
                          if type(item) is dict else ''):
            _require(type(row) is dict and set(row) == {'path', 'artifact'}
                     and type(row['path']) is str and row['path']
                     and not Path(row['path']).is_absolute()
                     and '..' not in Path(row['path']).parts
                     and row['path'] not in seen_paths,
                     f'canonical {role} source member required')
            member_path = row['path']
            seen_paths.add(member_path)
            _require(Path(row['artifact']['path']) == ROOT / member_path,
                     f'frozen {role} member must be rehashed from its live source path')
            _, actual, raw = _artifact(row['artifact'], cap=MAX_JSON)
            hashing.update(len(member_path.encode()).to_bytes(4, 'big'))
            hashing.update(member_path.encode())
            _require(raw is not None, 'bounded frozen source bytes required')
            hashing.update(len(raw).to_bytes(8, 'big'))
            hashing.update(raw)
        observed[role] = hashing.hexdigest()
        _require(observed[role] == identities[role],
                 f'frozen {role} source bundle drift detected')

    app_manifest, _ = _json(
        manifest.get('application_source_manifest'), cap=MAX_JSON)
    app_files = manifest.get('application_source_files')
    source_pins = app_manifest.get('source_pins') if type(app_manifest) is dict else None
    _require(type(source_pins) is dict and type(app_files) is dict
             and set(source_pins) == set(app_files),
             'complete frozen application source inventory required')
    for relative_path, ref in app_files.items():
        _require(type(relative_path) is str and relative_path
                 and not Path(relative_path).is_absolute()
                 and '..' not in Path(relative_path).parts,
                 'safe application source path required')
        _require(Path(ref['path']) == ROOT / relative_path,
                 'application source must be rehashed from its live source path')
        _, actual, _ = _artifact(ref)
        _require(source_pins[relative_path] == actual,
                 'application source file differs from its frozen source manifest')
    app_sha = _sha(json.dumps(app_manifest, sort_keys=True).encode())
    _require(app_sha == identities['application_source'],
             'frozen application source manifest drift detected')
    observed['application_source'] = app_sha
    return observed


def _txs(transactions, expected, label):
    _require(type(transactions) is list and len(transactions) == len(expected),
             f'{label} exact transaction outcomes required')
    for row, (scenario, code) in zip(transactions, expected):
        _require(type(row) is dict and row.get('scenario') == scenario
                 and row.get('customError') == code
                 and ((row.get('err') is None) == (code is None)),
                 f'{label} transaction outcome mismatch')


def _verify_pre_enrollment_create(transactions, request_absent):
    """Require the heldout stage to reject Create before issuer enrollment."""
    _require(request_absent is True,
             'pre-enrollment Create must leave its request PDA absent')
    _require(type(transactions) is list and all(type(row) is dict for row in transactions),
             'pre-enrollment Create transaction journal required')
    scenarios = [row.get('scenario') for row in transactions]
    expected = ('v3-initialize', 'v3-pre-enrollment-create', 'v3-enroll', 'v3-create')
    positions = []
    for scenario in expected:
        _require(scenarios.count(scenario) == 1,
                 'pre-enrollment Create transaction order mismatch')
        positions.append(scenarios.index(scenario))
    initialize_at, pre_enrollment_at, enroll_at, create_at = positions
    _require(pre_enrollment_at == initialize_at + 1
             and pre_enrollment_at < enroll_at < create_at,
             'pre-enrollment Create must fail before enrollment')
    pre_enrollment = transactions[pre_enrollment_at]
    _require(pre_enrollment.get('customError') == 710
             and pre_enrollment.get('err') == {
                 'InstructionError': [1, {'Custom': 710}]},
             'pre-enrollment Create error mismatch')
    for position in (enroll_at, create_at):
        _require(transactions[position].get('customError') is None
                 and transactions[position].get('err') is None,
                 'enrollment and subsequent Create must succeed')


def _verify_full_transactions(transactions, pre_execute_rejection_accounts):
    """Verify the complete R0 Full execution sequence emitted by the harness."""
    expected = [
        ('v3-refresh-active-source', None),
        ('v3-bind-refreshed-head', None),
        ('v3-wrong-issuer', 713),
        ('v3-wrong-policy', 713),
        ('v3-wrong-action', 712),
        ('v3-invalid-proof', 714),
        ('v3-execute-readonly-request', 711),
        ('v3-execute-missing-final-account', 709),
        ('v3-execute-system-program-as-issuer', 710),
        ('v3-valid-full-execute', None),
        ('v3-replay-new-transaction', 707),
    ]
    _txs(transactions, expected, 'Full A')
    _require(type(pre_execute_rejection_accounts) is dict
             and set(pre_execute_rejection_accounts) == {'before_sha256', 'after_sha256'},
             'Full A pre-execute rejection account hashes required')
    before = pre_execute_rejection_accounts['before_sha256']
    after = pre_execute_rejection_accounts['after_sha256']
    _require(type(before) is list and type(after) is list
             and len(before) == len(after) == 5
             and all(_is_sha(value) for value in before + after)
             and before == after,
             'Full A rejected transactions must preserve all five accounts')
    for row, (_, code) in zip(transactions, expected):
        if code is None:
            _require(row.get('err') is None,
                     'Full A successful transaction must have no error')
            continue
        err = row.get('err')
        _require(type(err) is dict
                 and err.get('InstructionError') == [1, {'Custom': code}],
                 'Full A transaction error mismatch')


def _verify_full_rejection_account_hashes(pre_execute_rejection_accounts,
                                          finalized_accounts, stage_accounts):
    """Bind the pre-Execute snapshot to independently pinned finalized bytes."""
    _require(type(finalized_accounts) is dict and set(finalized_accounts) == set(ACCOUNT_NAMES)
             and type(stage_accounts) is dict and set(stage_accounts) == set(ACCOUNT_NAMES),
             'Full A finalized and stage account bytes required')
    expected = [_sha(finalized_accounts[name]) for name in ('config', 'issuer', 'head')]
    expected.extend(_sha(stage_accounts[name]) for name in ('request', 'queue'))
    _require(type(pre_execute_rejection_accounts) is dict
             and pre_execute_rejection_accounts.get('before_sha256') == expected
             and pre_execute_rejection_accounts.get('after_sha256') == expected,
             'Full A rejection hashes must match pinned finalized/staged account bytes')


def _validate_proof_one(bundle, mode, slot_name, case, globals_, stage,
                        transition, sources, expected_wires, case_name):
    _require(type(bundle) is dict and set(bundle) == {'receipt', 'artifacts'},
             f'{slot_name} pinned proof receipt and artifacts required')
    receipt, receipt_sha = _json(bundle['receipt'], cap=65536)
    _require(type(receipt) is dict
             and receipt.get('schema') == 'credential-v3-heldout-proof-evidence-v1'
             and receipt.get('mode') == mode
             and receipt.get('proof_mode') == ('matched-full-k1' if mode == 'full'
                                                else 'matched-anchor-k1')
             and receipt.get('freeze_sha256') == globals_['freeze_sha256']
             and receipt.get('cohort_receipt_sha256') == globals_['cohort_sha256']
             and receipt.get('case_context_sha256') == case['case_sha256']
             and receipt.get('target_variant') == case['variant']
             and receipt.get('case') == case_name
             and receipt.get('issuer_index') == case['target']['issuer_index']
             and receipt.get('holder_index') == case['target']['holder_index']
             and receipt.get('target_der_sha256') == case['target']['credential_sha256']
             and receipt.get('target_tbs_sha256') == case['target']['tbs_sha256']
             and receipt.get('issuer_public_key_sha256')
                == case['target']['issuer_public_key_sha256']
             and receipt.get('holder_public_key_sha256')
                == case['target']['holder_public_key_sha256']
             and receipt.get('membership_roots') == case['roots']
             and receipt.get('action_hash') == sources['R0']['action_hash']
             and receipt.get('node_sha256') == globals_['proof_inputs']['node']
             and receipt.get('stage_report_sha256') == stage['report_sha256']
             and receipt.get('stage_plan_sha256') == stage['plan_sha256']
             and receipt.get('transition_report_sha256') == transition['report_sha256']
             and receipt.get('proof_created') is True
             and receipt.get('application_verified') is False
             and receipt.get('validator_run') is False
             and receipt.get('application_effect') is False
             and receipt.get('complete_relation_checked') is True
             and receipt.get('live_state_authenticated') is False,
             f'{slot_name} proof receipt does not bind the heldout source/context')
    expected_sources = {name: sources[name]['receipt_ref'] for name in ('R0', 'R1')}
    _require(receipt.get('source_receipts') == expected_sources,
             f'{slot_name} proof receipt source receipt pins differ')
    proof_counts = {'proofs': 2, 'positive_checks': 2, 'altered_public_checks': 12,
                    'cross_root_checks': 2, 'ordinary_checks': 16}
    _require(receipt.get('proof_counts') == proof_counts
             and receipt.get('ordinary_verification') == {'passed': True, **proof_counts},
             f'{slot_name} proof must include the registered ordinary verification set')
    expected_tool_hashes = dict(globals_['proof_inputs'])
    expected_tool_hashes.update({
        'packet_builder': globals_['proof_source_hashes']['packet_builder'],
        'proof_helper': globals_['proof_source_hashes']['proof_helper'],
    })
    _require(receipt.get('proof_tool_hashes') == expected_tool_hashes
             and receipt.get('proof_runner_sha256') == expected_tool_hashes['proof_runner']
             and receipt.get('adapter_sha256') == expected_tool_hashes['adapter_binary']
             and receipt.get('bounded_supervisor_sha256')
                == expected_tool_hashes['bounded_supervisor']
             and receipt.get('exporter_sha256') == expected_tool_hashes['exporter']
             and receipt.get('packet_builder_sha256') == expected_tool_hashes['packet_builder']
             and receipt.get('proof_helper_sha256') == expected_tool_hashes['proof_helper']
             and receipt.get('witness_js_sha256') == expected_tool_hashes['witness_js']
             and receipt.get('relation_checker_sha256')
                == expected_tool_hashes['relation_checker'],
             f'{slot_name} proof tool identities differ from frozen input pins')
    proof_report, proof_report_sha = _json(receipt.get('proof_report'), cap=MAX_JSON)
    packet_ref = receipt.get('packet')
    packet, packet_sha = _json(packet_ref, cap=MAX_JSON)
    _require(type(packet) is dict and receipt.get('proof_source_identity')
             == packet.get('proof_source_identity'),
             f'{slot_name} proof source closure identity differs from packet')
    _require(type(receipt.get('wires')) is dict
             and set(receipt['wires']) == {'r0_full_wire', 'r1_wire'},
             f'{slot_name} proof must pin both R0 Full and R1 proof wires')
    wire_digests = {}
    expected_roots = {'r0_full_wire': case['roots']['R0'],
                      'r1_wire': case['roots']['R1']}
    for name, ref in receipt['wires'].items():
        digest = _verify_wire(ref, expected_roots[name], sources['R0']['action_hash'])
        wire_digests[name] = digest
    artifacts = bundle['artifacts']
    _require(type(artifacts) is dict and artifacts
             and artifacts == receipt.get('artifacts'),
             f'{slot_name} complete proof artifact inventory required')
    seen_artifacts = set()
    for name, ref in artifacts.items():
        _require(type(name) is str and name and name not in seen_artifacts,
                 'unique proof artifact name required')
        seen_artifacts.add(name)
        _artifact(ref)
    template = globals_['packet_template']
    frozen_ids = globals_['frozen_hashes']
    packet_fields = {name: template[name] for name in PACKET_IDENTITY_FIELDS}
    stage_pins = {
        'program_id': stage['report'].get('program'),
        'genesis_hash': stage['report'].get('genesis'),
        'loaded_elf_sha256': frozen_ids['loaded_elf'],
        'base_stage_report_sha256': stage['report_sha256'],
        'base_config_sha256': stage['config_sha256'],
        'finalized_request_sha256': sources['R0']['staged_request_sha256'],
        'request_address': stage['report'].get('request'),
        'base_finalized_slot': stage['report'].get('finalized_slot'),
        'near_state_report_sha256': transition['report_sha256'],
        'near_config_sha256': transition['config_sha256'],
        'near_finalized_slot': transition['report'].get('finalized_slot'),
        'base_root': str(int(case['roots']['R0'], 16)),
        'near_root': str(int(case['roots']['R1'], 16)),
        'action_hash': str(int(sources['R0']['action_hash'], 16)),
    }
    report_identities = {
        'package_digest': template['package_digest'],
        'proof_binary_sha256': expected_tool_hashes['proof_runner'],
        'ordinary_vk_file_sha256': frozen_ids['ordinary_vk'],
        'setup_manifest_sha256': frozen_ids['setup_manifest'],
        'proof_source_identity': packet.get('proof_source_identity'),
    }
    expected_products = {
        'setup_manifest_sha256': frozen_ids['setup_manifest'],
        'ordinary_vk_sha256': frozen_ids['ordinary_vk'],
        'r1cs_sha256': frozen_ids['r1cs'],
        'wasm_sha256': frozen_ids['witness_executable'],
        'profile_sha256': frozen_ids['profile'],
        'input_map_sha256': template['input_map_sha256'],
        'package_check_sha256': template['package_check_sha256'],
    }
    _require(all(receipt.get(name) == value for name, value in expected_products.items()),
             f'{slot_name} proof receipt differs from frozen package/key identities')
    _validate_packet_and_proof_report(
        packet, proof_report, packet_sha256=packet_sha,
        proof_mode=receipt['proof_mode'], stage_pins=stage_pins,
        packet_fields=packet_fields, artifact_refs=artifacts,
        report_identities=report_identities, proof_counts=proof_counts)
    _require(any(ref == receipt.get('proof_report') for ref in artifacts.values())
             and any(ref == packet_ref for ref in artifacts.values())
             and all(any(ref == wire for ref in artifacts.values())
                     for wire in receipt['wires'].values()),
             f'{slot_name} artifacts must cover packet, proof report, and both wires')
    _verify_proof_supervisors(receipt, mode, slot_name)
    for role, ref in expected_wires.items():
        if ref is not None:
            _require(ref == receipt['wires'][role],
                     f'{slot_name} proof wire differs from application wire')
    return {'receipt_sha256': receipt_sha, 'proof_report_sha256': proof_report_sha,
            'packet_sha256': packet_sha, 'wire_sha256': wire_digests}


def _verify_proof_supervisors(receipt, mode, label):
    witness_limits = {'runtime_seconds': 300, 'rss_bytes': 4 * 1024**3,
                      'storage_bytes': 512 * 1024**2}
    relation_limits = {'runtime_seconds': 600, 'rss_bytes': 4 * 1024**3,
                       'storage_bytes': 512 * 1024**2}
    proof_limits = {'runtime_seconds': 1800 if mode == 'full' else 3600,
                    'rss_bytes': 4 * 1024**3, 'storage_bytes': 512 * 1024**2}
    expected = {'r0-witness': witness_limits, 'r0-relation': relation_limits,
                'r1-witness': witness_limits, 'r1-relation': relation_limits,
                'proof': proof_limits, 'adapter': relation_limits}
    reports = receipt.get('supervisor_reports')
    _require(type(reports) is dict and set(reports) == set(expected),
             f'{label} complete bounded proof subprocess receipts required')
    for name, limits in expected.items():
        row = reports[name]
        _require(type(row) is dict and set(row) == {'path', 'sha256', 'limits'}
                 and row['limits'] == limits,
                 f'{label} {name} supervisor cap mismatch')
        outer = _outer({'path': row['path'], 'sha256': row['sha256']},
                       f'{label} {name} proof subprocess', expected_exit=0)
        _require(_proof_outer_limits_match(outer, limits),
                 f'{label} {name} outer cap differs from proof receipt')


def _validate_proof_bundle(bundle, branch, case, globals_, slot_data, wires):
    stage, transition = slot_data['stage'], slot_data['transition']
    sources = {'R0': slot_data['r0'], 'R1': slot_data['r1']}
    if branch == 'unrelated_full':
        _require(type(bundle) is dict and set(bundle) == {'full', 'anchor'},
                 'unrelated Full outcome requires its own Full and Anchor proof receipts')
        full_wires = {'r0_full_wire': wires['full'], 'r1_wire': wires['full_near']}
        anchor_wires = {'r0_full_wire': None, 'r1_wire': wires['anchor']}
        case_name = _proof_case_label(case, 'unrelated_compare')
        full = _validate_proof_one(bundle['full'], 'full', 'unrelated Full', case,
                                   globals_, stage, transition, sources, full_wires,
                                   case_name)
        anchor = _validate_proof_one(bundle['anchor'], 'anchor', 'unrelated Anchor', case,
                                     globals_, stage, transition, sources, anchor_wires,
                                     case_name)
        return {'full': full, 'anchor': anchor}
    mode = 'full' if branch == 'full' else 'anchor'
    expected = {'r0_full_wire': wires['full'],
                'r1_wire': wires.get('anchor')}
    if branch == 'full':
        expected['r1_wire'] = None
    return _validate_proof_one(bundle, mode, branch, case, globals_, stage,
                               transition, sources, expected,
                               _proof_case_label(case, {
                                   'full': 'positive_full',
                                   'anchor': 'unrelated_compare',
                                   'own_revocation': 'own_revocation'}[branch]))


def _verify_fresh_replay_wires(original_ref, replay_ref):
    _, _, original = _artifact(original_ref, cap=1024)
    _, _, replay = _artifact(replay_ref, cap=1024)
    _require(len(original) == len(replay) == 448
             and original[:192] == replay[:192],
             'fresh replay must retain identical six public inputs')
    _require(original[192:] != replay[192:],
             'fresh replay must use a distinct randomized proof')


def _verify_case_run_provenance(case_bundle, variant, globals_, freeze_sha,
                                cohort_sha):
    run, _ = _json(case_bundle.get('run_manifest'), cap=1024 * 1024)
    _require(type(run) is dict and run.get('schema') == RUN_SCHEMA
             and run.get('variant') == variant
             and run.get('freeze_sha256') == freeze_sha
             and run.get('cohort_sha256') == cohort_sha,
             'case run manifest must bind the exact heldout variant and cohort')
    for name in ('frozen_files', 'frozen_bundles', 'source_files', 'proof_inputs',
                 'application_source_manifest', 'application_source_files'):
        _require(run.get(name) == globals_.get(name),
                 f'case run manifest {name} differs from common frozen evidence')
    registry = globals_['frozen_bundles']['registry']
    expected_runner = {'path': str(ROOT / QUEUE_RUNNER_REL),
                       'sha256': run.get('runner_sha256')}
    _require(type(registry) is list
             and run.get('runner') == expected_runner['path']
             and _is_sha(expected_runner['sha256'])
             and any(type(row) is dict and row.get('path') == QUEUE_RUNNER_REL
                     and row.get('artifact') == expected_runner for row in registry),
             'case Rust queue runner must match the frozen registry bundle')
    journal, _ = _json(case_bundle.get('run_journal'), cap=MAX_JSON)
    canonical = _sha((json.dumps(run, sort_keys=True, separators=(',', ':'),
                                 allow_nan=False) + '\n').encode())
    steps = journal.get('steps') if type(journal) is dict else None
    _require(type(journal) is dict and journal.get('schema') == JOURNAL_SCHEMA
             and journal.get('manifest_sha256') == canonical
             and type(steps) is dict
             and type(steps.get('positive_full:proof-full-fresh-replay')) is dict
             and steps['positive_full:proof-full-fresh-replay'].get('status') == 'passed',
             'case run journal must bind its canonical manifest and fresh replay proof')
    return canonical


def _verify_branch(branch, bundle, case, globals_, slot_data, clone_destinations):
    expected_branch_keys = {'result', 'proof'}
    if branch == 'own_revocation':
        expected_branch_keys.add('current_r2_witness_rejection')
    if branch == 'full':
        expected_branch_keys.add('replay_proof')
    clone_role = 'r0_clone' if branch == 'full' else 'r1_clone'
    expected_branch_keys.add(clone_role)
    _require(type(bundle) is dict and set(bundle) == expected_branch_keys,
             f'{branch} branch evidence bundle incomplete')
    stage_bundle = slot_data['stage_bundle']
    stage = slot_data['stage']
    transition_bundle = slot_data['transition_bundle']
    transition = slot_data['transition']
    r0, r0_sha = slot_data['r0'], slot_data['r0_sha256']
    r1, r1_sha = slot_data['r1'], slot_data['r1_sha256']
    request_slot = {'full': 'A', 'unrelated_full': 'B', 'anchor': 'B',
                    'own_revocation': 'C'}[branch]
    result_bundle = bundle['result']
    expected_result_keys = {'report', 'status', 'outer', 'config', 'monitor',
                            'monitor_owner', 'wires', 'accounts'}
    if branch != 'full':
        expected_result_keys.add('signed_history')
    _require(type(result_bundle) is dict and set(result_bundle) == expected_result_keys,
             f'{branch} raw result evidence bundle incomplete')
    _require(result_bundle['outer'] == result_bundle['monitor'],
             f'{branch} outer and monitor must be the same pinned runner report')
    report, report_sha = _json(result_bundle['report'], cap=65536)
    status, _ = _json(result_bundle['status'], cap=65536)
    config, config_sha = _json(result_bundle['config'], cap=65536)
    outer = _outer(result_bundle['outer'], branch, expected_exit=1)
    monitor_owner = result_bundle['monitor_owner']
    _require(type(monitor_owner) is str and monitor_owner
             and outer.get('owner') == monitor_owner
             and type(report) is dict and type(status) is dict
             and status.get('config_sha256') == config_sha
             and _declared_limits_match(config.get('outer_limits_required'),
                                        outer.get('limits')),
             f'{branch} bounded runner/status/config identity mismatch')
    if branch == 'full':
        _verify_reviewed_local_status(
            status, scope='part5-v3-local-execute', verified_field='effect_verified',
            report_field='execute_report_sha256', report_sha256=report_sha,
            application_effect=True, effect_count=1)
        _require(report.get('schema') == 'part5-v3-local-execute-v1'
                 and report.get('passed') is True and report.get('training_only') is True
                 and report.get('proof_mode') == 'Full'
                 and report.get('application_effect') is True
                 and report.get('effect_count') == 1 and report.get('request_consumed') is True
                 and report.get('stage_report_sha256') == stage['report_sha256']
                 and report.get('stage_plan_sha256') == stage['plan_sha256']
                 and report.get('wire_sha256') == _pin_sha(result_bundle['wires'].get('full')),
                 'raw Full report must consume exactly one R0 request')
        _require(type(result_bundle['wires']) is dict
                 and set(result_bundle['wires']) == {'full', 'replay_full'},
                 'R0 Full branch must pin original and fresh replay proof wires')
        _verify_wire(result_bundle['wires']['full'], case['roots']['R0'], r0['action_hash'])
        _verify_wire(result_bundle['wires']['replay_full'], case['roots']['R0'],
                     r0['action_hash'])
        _verify_fresh_replay_wires(result_bundle['wires']['full'],
                                   result_bundle['wires']['replay_full'])
        _require(config.get('stage_report_sha256') == stage['report_sha256']
                 and config.get('stage_plan_sha256') == stage['plan_sha256']
                 and config.get('full_wire_sha256') == _pin_sha(result_bundle['wires']['full'])
                 and config.get('replay_full_wire_sha256')
                    == _pin_sha(result_bundle['wires']['replay_full'])
                 and report.get('replay_wire_sha256')
                    == _pin_sha(result_bundle['wires']['replay_full']),
                 'Full config/report wires differ from staged R0 request')
        accounts = _accounts(result_bundle, report, f'{branch} result')
        _verify_full_transactions(report.get('transactions'),
                                  report.get('pre_execute_rejection_accounts'))
        _verify_full_rejection_account_hashes(
            report.get('pre_execute_rejection_accounts'), accounts, stage['accounts'])
        clone = _verify_r0_clone(bundle['r0_clone'], config, stage_bundle, stage)
        clone_destinations.add(clone['destination'])
        current_root = case['roots']['R0']
        request_identity = r0['finalized_request_sha256']
        chain = None
    else:
        mode = {'unrelated_full': 'full', 'anchor': 'anchor',
                'own_revocation': 'own-revocation'}[branch]
        _verify_reviewed_local_status(
            status, scope='part5-v3-r1-branch', verified_field='branch_verified',
            report_field='branch_report_sha256', report_sha256=report_sha,
            application_effect=branch != 'own_revocation',
            effect_count=0 if branch == 'own_revocation' else 1, mode=mode)
        _require(report.get('registry_history_authenticated') is True
                 and report.get('allocation_history_authenticated') is True
                 and report.get('upstream_source_authentication') is True
                 and report.get('upstream_publisher_authentication') is True,
                 f'{branch} raw report must record all checked signed-history layers')
        _require(report.get('schema') == 'part5-v3-r1-branch-v1'
                 and report.get('passed') is True and report.get('training_only') is True
                 and report.get('mode') == mode
                 and report.get('stage_report_sha256') == stage['report_sha256']
                 and report.get('stage_plan_sha256') == stage['plan_sha256']
                 and report.get('transition_report_sha256') == transition['report_sha256']
                 and report.get('base_root') == case['roots']['R0']
                 and report.get('near_root') == case['roots']['R1']
                 and report.get('program') == stage['report'].get('program')
                 and report.get('genesis') == stage['report'].get('genesis')
                 and config.get('expected_genesis') == transition['report'].get('genesis')
                 and transition['report'].get('program') == stage['report'].get('program')
                 and transition['report'].get('genesis') == stage['report'].get('genesis'),
                 f'{branch} raw report must bind the independently verified transition')
        wires = result_bundle.get('wires')
        expected_wires = ({'full', 'anchor', 'full_near'} if branch == 'unrelated_full'
                          else {'full', 'anchor'})
        _require(type(wires) is dict and set(wires) == expected_wires,
                 f'{branch} exact R0 Full/R1 Anchor proof wire set required')
        _verify_wire(wires['full'], case['roots']['R0'], r0['action_hash'])
        _verify_wire(wires['anchor'], case['roots']['R1'], r1['action_hash'])
        if branch == 'unrelated_full':
            _verify_wire(wires['full_near'], case['roots']['R1'], r1['action_hash'])
        _require(r0['action_hash'] == r1['action_hash'],
                 f'{branch} comparator action must be identical across R0 and R1')
        final_change = ([] if branch in ('unrelated_full', 'anchor') else [
            {'Revoke': {'tbs_digest': list(bytes.fromhex(case['target']['tbs_sha256']))}}])
        history, history_sha = _json(result_bundle['signed_history'], cap=MAX_JSON)
        _require(report.get('signed_history_sha256') == history_sha,
                 f'{branch} report must pin its complete signed history')
        branch_roots = [case['roots']['R0'], case['roots']['R1'],
                        case['roots']['R1'] if branch in ('unrelated_full', 'anchor')
                        else case['roots']['R2']]
        chain = _verify_history(history, stage['plan'], case, branch_roots,
                                final_change=final_change)
        _require(report.get('source_head_digest') == chain['source_sha256'],
                 f'{branch} report does not bind its final signed source head')
        _require(config.get('stage_report_sha256') == stage['report_sha256']
                 and config.get('stage_plan_sha256') == stage['plan_sha256']
                 and config.get('transition_report_sha256') == transition['report_sha256']
                 and config.get('full_wire_sha256') == _pin_sha(wires['full'])
                 and config.get('anchor_wire_sha256') == _pin_sha(wires['anchor']),
                 f'{branch} config does not pin its stage/transition/proof wires')
        if branch == 'unrelated_full':
            _require(config.get('full_near_wire_sha256') == _pin_sha(wires['full_near'])
                     and report.get('application_effect') is True
                     and report.get('effect_count') == 1
                     and report.get('request_consumed') is True
                     and report.get('current_root') == case['roots']['R1'],
                     'R1 Full must consume one request at R1')
            current_root = case['roots']['R1']
            _txs(report.get('transactions'), [
                ('v3-observe-signed-current-status', None),
                ('v3-bind-current-branch-head', None),
                ('v3-stale-R0-full', 713),
                ('v3-full-R1-wrong-action', 712),
                ('v3-full-R1-invalid-proof', 714),
                ('v3-valid-full-R1', None),
                ('v3-full-R1-replay', 707)], 'unrelated Full')
        elif branch == 'anchor':
            _require(report.get('application_effect') is True
                     and report.get('effect_count') == 1
                     and report.get('request_consumed') is True
                     and report.get('current_root') == case['roots']['R1'],
                     'Anchor must consume one request at R1')
            _txs(report.get('transactions'), [
                ('v3-observe-signed-current-status', None),
                ('v3-bind-current-branch-head', None),
                ('v3-stale-R0-full', 713),
                ('v3-anchor-wrong-action', 712),
                ('v3-anchor-invalid-proof', 714),
                ('v3-valid-anchor-R1', None),
                ('v3-anchor-replay', 707)], 'Anchor')
            current_root = case['roots']['R1']
        else:
            _require(report.get('application_effect') is False
                     and report.get('effect_count') == 0
                     and report.get('request_consumed') is False
                     and report.get('current_root') == case['roots']['R2'],
                     'own-R2 revocation must leave its request unconsumed and produce R2')
            _txs(report.get('transactions'), [
                ('v3-publish-own-revocation', None),
                ('v3-observe-signed-own-revocation', None),
                ('v3-bind-current-branch-head', None),
                ('v3-stale-R0-full', 713),
                ('v3-own-revoked-R1-anchor', 713)], 'own-R2')
            current_root = case['roots']['R2']
        clone = _verify_r1_clone(bundle['r1_clone'], config,
                                 transition_bundle, transition)
        _require(clone['destination'] not in clone_destinations,
                 'each R1 outcome requires a distinct fresh ledger clone')
        clone_destinations.add(clone['destination'])
        request_identity = r1['finalized_request_sha256']

    if branch != 'full':
        accounts = _accounts(result_bundle, report, f'{branch} result')
    runtime_identity = _verify_report_runtime_identity(
        report, status, config, globals_['freeze']['identities']['loaded_elf'],
        expected_program=stage['report']['program'],
        expected_genesis=stage['report']['genesis'])
    _require(runtime_identity == stage['runtime_identity']
             and (branch == 'full'
                  or runtime_identity == transition['runtime_identity']),
             f'{branch} loaded runtime differs from its exact stage/transition chain')
    if branch != 'full':
        _require(len(accounts['head']) == 280
                 and accounts['head'][112:144].hex() == chain['publisher_sha256']
                 and accounts['head'][224:256].hex() == chain['source_sha256'],
                 f'{branch} finalized head must match signed source history')
    _require(accounts['config'][332:364].hex() == current_root,
             f'{branch} finalized config has the wrong membership root')
    if branch == 'own_revocation':
        _require(int.from_bytes(accounts['config'][364:372], 'little') == 2
                 and accounts['request'] == transition['accounts']['request']
                 and accounts['queue'] == transition['accounts']['queue'],
                 'own-R2 branch must preserve unconsumed request/queue state')
        _verify_leaf_absent(case)
    elif branch != 'full':
        _require(int.from_bytes(accounts['config'][364:372], 'little') == 1,
                 'R1 outcome must retain R1 generation')
    proof_outputs = _validate_proof_bundle(bundle['proof'], branch, case,
                                           globals_, slot_data, result_bundle['wires'])
    if branch == 'own_revocation':
        r2_witness_rejection = _verify_current_r2_witness_rejection(
            bundle['current_r2_witness_rejection'], case, globals_, slot_data,
            bundle['proof'])
    if branch == 'full':
        replay = _validate_proof_one(
            bundle['replay_proof'], 'full', 'fresh Full replay', case,
            globals_, stage, transition, {'R0': r0, 'R1': r1},
            {'r0_full_wire': result_bundle['wires']['replay_full'],
             'r1_wire': None}, _proof_case_label(case, 'positive_full'))
        proof_outputs = {'initial': proof_outputs, 'fresh_replay': replay}
    return {'branch': branch, 'request_slot': request_slot,
            'request_account_sha256': _sha(stage['accounts']['request']),
            'finalized_request_sha256': request_identity,
            'source_receipt_sha256': r0_sha,
            'r1_source_receipt_sha256': r1_sha,
            'result_report_sha256': report_sha,
            'current_root': current_root, 'runtime_identity': runtime_identity,
            'action_hash': r0['action_hash'], 'effect_count': report.get('effect_count'),
            'request_consumed': report.get('request_consumed'),
            'proof_evidence': proof_outputs,
            **({'current_r2_witness_rejection': r2_witness_rejection}
               if branch == 'own_revocation' else {})}


def _pin_sha(ref):
    _, digest, _ = _artifact(ref, cap=MAX_ARTIFACT)
    return digest


def _verify_wire(ref, expected_root, action_hash):
    _, digest, raw = _artifact(ref, cap=1024)
    _require(raw is not None and len(raw) == 448 and raw[:32].hex() == expected_root
             and raw[128:160].hex() == action_hash,
             'proof wire root/action differs from heldout source identity')
    return digest


def _verify_leaf_absent(case):
    own = bytes.fromhex(case['target']['tbs_sha256'])
    other = bytes.fromhex(case['unrelated']['tbs_sha256'])
    expected = membership_for_pair(own, other, case['membership']['slot'])
    expected.update(issuer_hash=int(case['target']['issuer_hash']),
                    policy_hash=int(case['target']['policy_hash']))
    _require(expected == case['membership'], 'heldout membership failed independent rebuild')
    siblings = case['membership']['own_revoked_siblings']
    _require(type(siblings) is list and len(siblings) == 10
             and all(type(value) is int and 0 <= value < (1 << 254)
                     for value in siblings),
             'canonical own-revoked sibling field elements required')
    slot = case['membership']['slot']

    def root(active):
        node = poseidon_leaf(own, slot, active)
        for level, sibling in enumerate(siblings):
            node = poseidon_parent((sibling, node) if (slot >> level) & 1
                                   else (node, sibling))
        return f'{node:064x}'

    _require(root(False) == case['roots']['R2'] and root(True) != case['roots']['R2'],
             'own leaf is active from finalized R2 membership root')


def _canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)
            + '\n').encode('ascii')


def _wtns_assignment(ref):
    """Read the bounded canonical v2 BN254 WTNS assignment used by this circuit."""
    path, digest, _ = _artifact(ref, cap=32 * 1024 * 1024)
    before = path.lstat()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        _require(_identity(opened) == _identity(before), 'WTNS changed at open')
        raw = stream.read(32 * 1024 * 1024 + 1)
        _require(_identity(os.fstat(stream.fileno())) == _identity(before)
                 and _identity(path.lstat()) == _identity(before)
                 and len(raw) == before.st_size and _sha(raw) == digest,
                 'WTNS changed while reading')
    _require(len(raw) == 25113548 and raw[:8] == b'wtns\x02\x00\x00\x00'
             and int.from_bytes(raw[8:12], 'little') == 2,
             'complete frozen v3 WTNS assignment required')
    offset, sections = 12, {}
    for _ in range(2):
        _require(offset + 12 <= len(raw), 'truncated WTNS section table')
        kind = int.from_bytes(raw[offset:offset + 4], 'little')
        size = int.from_bytes(raw[offset + 4:offset + 12], 'little')
        start = offset + 12
        _require(kind not in sections and start + size <= len(raw),
                 'invalid WTNS section bounds')
        sections[kind] = (start, size)
        offset = start + size
    _require(offset == len(raw) and set(sections) == {1, 2},
             'complete WTNS sections required')
    header_start, header_size = sections[1]
    _require(header_size == 40
             and int.from_bytes(raw[header_start:header_start + 4], 'little') == 32
             and int.from_bytes(raw[header_start + 4:header_start + 36], 'little')
                == 21888242871839275222246405745257275088548364400416034343698204186575808495617,
             'canonical BN254 WTNS field required')
    count = int.from_bytes(raw[header_start + 36:header_start + 40], 'little')
    assignment_start, assignment_size = sections[2]
    _require(count == 784796 and assignment_size == count * 32,
             'complete frozen v3 WTNS field assignment required')
    values = [int.from_bytes(raw[assignment_start + index * 32:
                                 assignment_start + (index + 1) * 32], 'little')
              for index in range(count)]
    _require(values[0] == 1 and all(value < 21888242871839275222246405745257275088548364400416034343698204186575808495617
                                     for value in values),
             'WTNS values must be canonical BN254 fields')
    return digest, values


def _verify_current_r2_witness_rejection(ref, case, globals_, slot_data, proof_bundle):
    """Require a pinned R2 generator rejection and counterfactual R1CS result."""
    receipt, _ = _json(ref, cap=65536)
    required = {
        'schema', 'outcome', 'r2_root', 'base_r1_root',
        'own_revoked_siblings_sha256', 'base_r1_input_sha256',
        'r1cs_sha256', 'r1cs_result_ref', 'target_credential_sha256',
        'target_tbs_sha256', 'action_hash', 'base_r1_input_ref',
        'candidate_input_ref', 'input_coordinates_ref',
        'input_coordinates_sha256', 'candidate_input_sha256',
        'witness_generator_sha256', 'relation_checker_sha256',
        'bounded_supervisor_sha256', 'generator_attempt',
        'generator_invocation_ref', 'relation_invocation_ref',
        'counterfactual_assignment', 'r1cs_result', 'r1cs_result_ref',
        'relation_supervisor',
    }
    _require(type(receipt) is dict and set(receipt) == required
             and receipt.get('schema') == 'part5-v3-r2-active-witness-rejection-v1'
             and receipt.get('outcome')
                == 'generator_rejected_plus_counterfactual_r1cs_unsatisfied',
             'current-R2 active witness requires separate generator and R1CS outcomes')

    base_input = slot_data.get('r1_input')
    _require(type(base_input) is dict and set(base_input) >= {
        'root', 'siblings', 'issuerHash', 'notBefore', 'notAfter', 'actionHash',
        'policyHash'}, 'C R1 source witness input required for R2 rejection')
    _require(type(base_input['root']) is str and base_input['root'].isdecimal()
             and str(int(base_input['root'])) == base_input['root']
             and int(base_input['root']) == int(case['roots']['R1'], 16),
             'R2 witness rejection base input must be the exact C R1 root')

    base_ref = receipt.get('base_r1_input_ref')
    candidate_ref = receipt.get('candidate_input_ref')
    _require(type(base_ref) is dict and set(base_ref) == {'path', 'sha256'}
             and type(candidate_ref) is dict and set(candidate_ref) == {'path', 'sha256'},
             'pinned base and current-R2 candidate witness inputs required')
    _, base_sha, base_raw = _artifact(base_ref, cap=65536)
    _require(base_raw == _canonical_json(base_input)
             and base_input == slot_data.get('r1_input'),
             'canonical base witness input differs from C R1 source input')
    _, candidate_sha, candidate_raw = _artifact(candidate_ref, cap=65536)
    try:
        candidate = json.loads(candidate_raw, object_pairs_hook=_unique_pairs,
                               parse_constant=lambda _: (_ for _ in ()).throw(
                                   ValueError('non-finite JSON number')))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError('canonical current-R2 candidate input required') from error
    siblings = case['membership']['own_revoked_siblings']
    candidate_expected = dict(base_input)
    candidate_expected['root'] = str(int(case['roots']['R2'], 16))
    candidate_expected['siblings'] = [str(value) for value in siblings]
    expected_base_sha = _sha(_canonical_json(base_input))
    expected_candidate_sha = _sha(_canonical_json(candidate_expected))
    _require(base_sha == expected_base_sha
             and candidate == candidate_expected
             and candidate_raw == _canonical_json(candidate)
             and candidate_sha == expected_candidate_sha
             and receipt.get('base_r1_input_sha256') == expected_base_sha
             and receipt.get('candidate_input_sha256') == expected_candidate_sha,
             'R2 candidate must preserve the C R1 input except R2 root and own-revoked path')

    source = slot_data['r1']
    _require(receipt.get('r2_root') == case['roots']['R2']
             and receipt.get('base_r1_root') == case['roots']['R1']
             and receipt.get('own_revoked_siblings_sha256') == _sha(_canonical_json(siblings))
             and receipt.get('target_credential_sha256')
                == case['target']['credential_sha256']
             and receipt.get('target_tbs_sha256') == case['target']['tbs_sha256']
             and receipt.get('action_hash') == source['action_hash']
             and int(base_input['actionHash']) == int(source['action_hash'], 16),
             'R2 active witness receipt must cross-pin membership, target, and C action')

    frozen = globals_['freeze']['identities']
    proof_inputs = globals_['proof_inputs']
    _require(receipt.get('witness_generator_sha256') == proof_inputs['witness_js']
             and receipt.get('relation_checker_sha256') == proof_inputs['relation_checker']
             and receipt.get('r1cs_sha256') == frozen['r1cs'],
             'R2 active witness tooling differs from frozen JS wrapper, checker, or R1CS')
    coordinates_ref = receipt.get('input_coordinates_ref')
    _require(type(coordinates_ref) is dict and set(coordinates_ref) == {'path', 'sha256'}
             and receipt.get('input_coordinates_sha256') == coordinates_ref['sha256'],
             'R2 input-coordinate artifact hash must be pinned')
    _, coordinates_sha, coordinates_raw = _artifact(coordinates_ref, cap=65536)
    _require(coordinates_sha == receipt['input_coordinates_sha256'],
             'R2 input-coordinate artifact SHA-256 mismatch')
    _require(coordinates_sha == globals_['packet_template']['input_map_sha256']
             and len(coordinates_raw) == 751 * 4,
             'R2 counterfactual input map must match the frozen 751-coordinate file')
    coordinates = [int.from_bytes(coordinates_raw[index:index + 4], 'little')
                   for index in range(0, len(coordinates_raw), 4)]
    _require(len(coordinates) == 751 and coordinates[:6] == [1, 2, 3, 4, 5, 6]
             and len(set(coordinates)) == len(coordinates)
             and all(0 < value < 784796 for value in coordinates)
             and len(set([coordinates[0], *coordinates[731:741]])) == 11,
             'frozen R2 coordinate map must pin distinct root and sibling wires')
    expected_coordinates = [int(candidate['root']), int(base_input['issuerHash']),
                            int(base_input['notBefore']), int(base_input['notAfter']),
                            int(base_input['actionHash']), int(base_input['policyHash'])]

    attempt = receipt.get('generator_attempt')
    witness_limits = {'runtime_seconds': 300, 'rss_bytes': 4 * 1024**3,
                      'storage_bytes': 512 * 1024**2}
    _require(type(attempt) is dict and set(attempt) == {
        'exit_code', 'output_wtns_present', 'input_sha256',
        'supervisor_ref', 'supervisor_limits'}
             and attempt.get('exit_code') == 2
             and attempt.get('output_wtns_present') is False
             and attempt.get('input_sha256') == expected_candidate_sha
             and attempt.get('supervisor_limits') == witness_limits,
             'R2 generator rejection must be a labeled no-WTNS exit 2')
    generator_outer = _outer(attempt['supervisor_ref'],
                             'current-R2 witness generator', expected_exit=2)
    _require(_proof_outer_limits_match(generator_outer, witness_limits),
             'R2 generator supervisor limits differ from frozen bounds')
    candidate_dir = Path(candidate_ref['path']).parent
    generator_report_dir = Path(attempt['supervisor_ref']['path']).parent
    generator_monitor = generator_report_dir / 'generator-monitor'
    generator_invocation = _verify_r2_invocation(
        receipt['generator_invocation_ref'], generator_monitor, generator_outer,
        [str(globals_['proof_input_paths']['node']),
         str(globals_['proof_input_paths']['witness_js']), str(candidate_dir)],
        [str(generator_monitor), str(candidate_dir)], 'R2 witness generator')
    # This is only a present-time filesystem check, not proof of historical absence.
    output_wtns = candidate_dir / 'output.wtns'
    _require(not output_wtns.exists() and not output_wtns.is_symlink(),
             'current-R2 candidate directory has a present output.wtns')

    assignment = receipt.get('counterfactual_assignment')
    _require(type(assignment) is dict and set(assignment) == {
        'label', 'base_r1_witness_ref', 'base_r1_witness_sha256',
        'patched_witness_ref', 'patched_witness_sha256'}
             and assignment.get('label')
                == 'counterfactual_r1_wtns_with_r2_public_root_and_revoked_siblings'
             and assignment.get('base_r1_witness_ref', {}).get('sha256')
                == assignment.get('base_r1_witness_sha256')
             and assignment.get('patched_witness_ref', {}).get('sha256')
                == assignment.get('patched_witness_sha256')
             and assignment.get('base_r1_witness_sha256')
                != assignment.get('patched_witness_sha256'),
             'counterfactual R1 witness assignment must be explicitly labeled and pinned')
    _, base_witness_sha, _ = _artifact(assignment['base_r1_witness_ref'],
                                        cap=32 * 1024 * 1024)
    _, patched_witness_sha, _ = _artifact(assignment['patched_witness_ref'],
                                           cap=32 * 1024 * 1024)
    _require(base_witness_sha == assignment['base_r1_witness_sha256']
             and patched_witness_sha == assignment['patched_witness_sha256'],
             'counterfactual base and patched WTNS files differ from pinned hashes')
    proof_artifacts = proof_bundle.get('artifacts') if type(proof_bundle) is dict else None
    _require(type(proof_artifacts) is dict
             and proof_artifacts.get('near/output.wtns')
                == assignment['base_r1_witness_ref'],
             'counterfactual base WTNS must equal the verified C R1 proof witness')
    _, base_values = _wtns_assignment(assignment['base_r1_witness_ref'])
    _, patched_values = _wtns_assignment(assignment['patched_witness_ref'])
    sibling_wires = coordinates[731:741]
    expected_siblings = [int(value) for value in siblings]
    _require(base_values[coordinates[0]] == int(case['roots']['R1'], 16)
             and [base_values[index] for index in sibling_wires]
                == [int(value) for value in base_input['siblings']]
             and base_values[1:7] == [int(case['roots']['R1'], 16),
                                       int(base_input['issuerHash']),
                                       int(base_input['notBefore']),
                                       int(base_input['notAfter']),
                                       int(base_input['actionHash']),
                                       int(base_input['policyHash'])]
             and patched_values[coordinates[0]] == int(case['roots']['R2'], 16)
             and [patched_values[index] for index in sibling_wires] == expected_siblings
             and patched_values[1:7] == expected_coordinates,
             'counterfactual WTNS must contain the R2 root/path and exact public request')
    changed = {coordinates[0], *sibling_wires}
    _require(all(before == after for index, (before, after) in enumerate(
        zip(base_values, patched_values)) if index not in changed),
        'counterfactual WTNS may change only the root and ten sibling assignments')

    result = receipt.get('r1cs_result')
    _require(type(result) is dict and set(result) == {
        'schema', 'status', 'scan', 'constraint_row', 'expected_public',
        'candidate_input_sha256', 'witness_sha256', 'base_r1_witness_sha256', 'r1cs_sha256',
        'relation_checker_sha256'}
             and result.get('schema') == 'part5-v3-r2-active-witness-r1cs-result-v1'
             and result.get('status') == 'unsatisfied'
             and result.get('scan') == 'first_unsatisfied_row'
             and type(result.get('constraint_row')) is int
             and 0 <= result['constraint_row'] < 793681
             and result.get('expected_public') == [str(value) for value in expected_coordinates]
             and result.get('candidate_input_sha256') == expected_candidate_sha
             and result.get('witness_sha256') == assignment['patched_witness_sha256']
             and result.get('base_r1_witness_sha256')
                == assignment['base_r1_witness_sha256']
             and result.get('r1cs_sha256') == frozen['r1cs']
             and result.get('relation_checker_sha256') == proof_inputs['relation_checker'],
             'R2 rejection must pin a frozen R1CS first-unsatisfied-row result')
    result_ref = receipt.get('r1cs_result_ref')
    result_file, result_sha, result_raw = _artifact(result_ref, cap=65536)
    _require(result_sha == result_ref.get('sha256')
             and result_sha == _sha(_canonical_json(result))
             and result_raw == _canonical_json(result),
             'pinned relation result file must exactly match canonical receipt result')

    relation = receipt.get('relation_supervisor')
    relation_limits = {'runtime_seconds': 600, 'rss_bytes': 4 * 1024**3,
                       'storage_bytes': 512 * 1024**2}
    _require(type(relation) is dict and set(relation) == {'ref', 'limits', 'exit_code'}
             and relation.get('limits') == relation_limits
             and relation.get('exit_code') == 0
             and receipt.get('bounded_supervisor_sha256')
                == proof_inputs.get('bounded_supervisor'),
             'R2 active witness relation requires the frozen bounded supervisor')
    relation_outer = _outer(relation['ref'], 'counterfactual R1CS relation', expected_exit=0)
    _require(_proof_outer_limits_match(relation_outer, relation_limits),
             'counterfactual R1CS supervisor limits differ from frozen bounds')
    relation_dir = Path(result_ref['path']).parent
    relation_monitor = Path(relation['ref']['path']).parent / 'relation-monitor'
    proof_paths = globals_['proof_input_paths']
    relation_argv = [sys.executable, '-B', str(ROOT / 'tools/part5/check_v3_r2_counterfactual.py'),
                     '--candidate-input', candidate_ref['path'],
                     '--candidate-input-sha256', candidate_ref['sha256'],
                     '--witness', assignment['patched_witness_ref']['path'],
                     '--witness-sha256', assignment['patched_witness_ref']['sha256'],
                     '--base-r1-witness', assignment['base_r1_witness_ref']['path'],
                     '--base-r1-witness-sha256', assignment['base_r1_witness_ref']['sha256'],
                     '--r1cs', str(globals_['frozen_paths']['r1cs']),
                     '--r1cs-sha256', frozen['r1cs'],
                     '--relation-checker', str(proof_paths['relation_checker']),
                     '--relation-checker-sha256', proof_inputs['relation_checker'],
                     '--output', result_ref['path']]
    _verify_r2_invocation(receipt['relation_invocation_ref'], relation_monitor,
                          relation_outer, relation_argv,
                          [str(relation_monitor), str(relation_dir)],
                          'counterfactual R1CS relation')
    return {'receipt_sha256': _pin_sha(ref), 'candidate_input_sha256': expected_candidate_sha,
            'witness_sha256': assignment['patched_witness_sha256'],
            'r1cs_constraint_row': result['constraint_row'],
            'generator_failure_cause': 'unknown; pinned wrapper suppresses diagnostics',
            'generator_output_absence_scope': 'present-time only; not historical proof',
            'generator_invocation_sha256': _pin_sha(receipt['generator_invocation_ref']),
            'relation_invocation_sha256': _pin_sha(receipt['relation_invocation_ref']),
            'generator_supervisor_sha256': _pin_sha(attempt['supervisor_ref']),
            'relation_supervisor_sha256': _pin_sha(relation['ref'])}


def _verify_r2_invocation(ref, monitor_dir, outer, argv, storage_roots, label):
    _require(type(ref) is dict and set(ref) == {'path', 'sha256'}
             and Path(ref['path']) == monitor_dir / 'invocation.json',
             f'{label} invocation reference must point to its monitor invocation.json')
    invocation, _ = _json(ref, cap=65536)
    _require(type(invocation) is dict and set(invocation) == {
        'owner', 'argv', 'cwd', 'started_at_utc', 'storage_roots'}
             and type(invocation.get('owner')) is str and invocation['owner']
             and invocation['owner'] == outer.get('owner')
             and invocation.get('argv') == argv
             and invocation.get('cwd') == str(ROOT)
             and type(invocation.get('started_at_utc')) is str
             and invocation['started_at_utc']
             and invocation.get('storage_roots') == storage_roots,
             f'{label} invocation must pin exact argv, cwd, owner, and storage roots')
    return invocation


def _validate_request_triads(branch_results, seen_finalized_requests,
                             seen_request_accounts):
    required = set(BRANCHES)
    _require(type(branch_results) is dict and set(branch_results) == required,
             'four heldout outcome branches required')
    full, unrelated_full = branch_results['full'], branch_results['unrelated_full']
    anchor, own = branch_results['anchor'], branch_results['own_revocation']
    identities = {'A': full['finalized_request_sha256'],
                  'B': unrelated_full['finalized_request_sha256'],
                  'C': own['finalized_request_sha256']}
    _require(unrelated_full['finalized_request_sha256']
                == anchor['finalized_request_sha256']
             and unrelated_full['action_hash'] == anchor['action_hash']
             and unrelated_full['request_account_sha256']
                == anchor['request_account_sha256']
             and unrelated_full['current_root'] == anchor['current_root'],
             'matched Full/Anchor outcomes must share exact request B')
    _require(len(set(identities.values())) == 3,
             'Full, matched R1, and own-revocation requests A/B/C must be distinct')
    account_ids = {full['request_account_sha256'],
                   unrelated_full['request_account_sha256'],
                   own['request_account_sha256']}
    _require(len(account_ids) == 3,
             'A/B/C must use distinct staged request accounts')
    action_ids = {full['action_hash'], unrelated_full['action_hash'],
                  own['action_hash']}
    _require(all(_is_sha(value) for value in action_ids) and len(action_ids) == 3,
             'A/B/C must use distinct action hashes; matched B outcomes share one action')
    _require(not set(identities.values()) & seen_finalized_requests
             and not account_ids & seen_request_accounts,
             'heldout request identity reused across variants')
    seen_finalized_requests.update(identities.values())
    seen_request_accounts.update(account_ids)
    return identities


def verify_manifest(manifest_path):
    manifest_path = Path(manifest_path)
    _require(manifest_path.is_absolute(), 'absolute manifest path required')
    manifest, manifest_sha256 = _read_json_path(manifest_path, cap=MAX_JSON)
    _require(type(manifest) is dict and manifest.get('schema') == MANIFEST_SCHEMA,
             'heldout acceptance manifest schema required')
    cases_raw = manifest.get('cases')
    _require(type(cases_raw) is list and len(cases_raw) == 8,
             'exactly eight heldout cases required')
    freeze, freeze_sha = _json(manifest.get('freeze_receipt'), cap=65536)
    cohort, cohort_sha = _json(manifest.get('cohort_receipt'), cap=MAX_JSON)
    by_variant = _case_cohort(freeze, freeze_sha, cohort, cohort_sha)
    cohort_provenance = _verify_cohort_generation_provenance(
        freeze, freeze_sha, cohort, by_variant,
        manifest['freeze_receipt'], manifest['cohort_receipt'])
    frozen_hashes = _verify_frozen_identity(freeze, manifest)
    cohort_import_evidence = cohort_provenance['cohort_import_evidence']
    cohort_import_evidence['frozen_client_source_bundle_sha256'] = frozen_hashes['client']
    source_files = manifest.get('source_files')
    _require(type(source_files) is dict and set(source_files) == set(SOURCE_FILE_ROLES),
             'heldout source tool/helper/exporter/bridge pins required')
    source_hashes = {}
    source_live_paths = {
        'heldout_source_tool': ROOT / 'tools/part5/prepare_v3_heldout_source.py',
        'training_helper': ROOT / 'crates/dynark-native-client/tests/support/prepare_v3_request_bound_training.py',
        'request_fixture_bridge': ROOT / 'tools/part5/prepare_v3_request_fixture.py',
        'exporter': ROOT / 'program/target/debug/examples/export_v3_request_fixture',
    }
    for role, ref in source_files.items():
        _, actual, _ = _artifact(ref)
        if role in source_live_paths:
            _require(Path(ref['path']) == source_live_paths[role],
                     f'{role} must be rehashed from its live source path')
        source_hashes[role] = actual
    client_paths = {row['path']: row['artifact'] for row in manifest['frozen_bundles']['client']}
    for role in ('heldout_source_tool', 'training_helper', 'request_fixture_bridge',
                 'exporter'):
        relative = source_live_paths[role].relative_to(ROOT).as_posix()
        _require(relative in client_paths
                 and client_paths[relative]['sha256'] == source_hashes[role],
                 f'{role} must be included in the frozen client source bundle')
    proof_inputs = manifest.get('proof_inputs')
    _require(type(proof_inputs) is dict and set(proof_inputs) == set(PROOF_INPUT_ROLES),
             'complete frozen proof/helper input map required')
    proof_input_hashes = {}
    proof_input_paths = {}
    for role, ref in proof_inputs.items():
        _, actual, _ = _artifact(ref)
        proof_input_hashes[role] = actual
        proof_input_paths[role] = Path(ref['path'])
        _require(actual == ref['sha256'], f'{role} proof input hash mismatch')
    _require(proof_input_hashes['proof_runner'] == frozen_hashes['proof_runner'],
             'proof runner must match frozen product pin')
    _verify_exporter_adapter_roles(source_hashes, proof_input_hashes, frozen_hashes)
    _require(Path(proof_inputs['exporter']['path']) == Path(source_files['exporter']['path']),
             'proof input exporter and heldout source exporter paths must be identical')
    _require(proof_input_hashes['bounded_supervisor']
             == client_paths.get('results/dynark/part5/session_runner.py', {}).get('sha256'),
             'proof bounded supervisor must be the frozen session runner')
    packet_template, _ = _json(proof_inputs['packet_template'], cap=262144)
    frozen_paths = {role: Path(ref['path']) for role, ref in manifest['frozen_files'].items()}
    for key, role in (('setup_manifest_path', 'setup_manifest'),
                      ('r1cs_path', 'r1cs'), ('wasm_path', 'witness_executable'),
                      ('profile_path', 'profile')):
        _require(packet_template.get(key) == str(frozen_paths[role]),
                 f'proof packet template {role} path differs from frozen product')
    for path_key, hash_key in (('input_map_path', 'input_map_sha256'),
                               ('package_check_path', 'package_check_sha256')):
        path_value, expected_hash = packet_template.get(path_key), packet_template.get(hash_key)
        _require(type(path_value) is str and Path(path_value).is_absolute()
                 and _is_sha(expected_hash),
                 f'proof packet template {path_key} pin required')
        _, actual, _ = _artifact({'path': path_value, 'sha256': expected_hash})
        _require(actual == expected_hash,
                 f'proof packet template {path_key} artifact drift detected')
    client_paths = {row['path']: row['artifact'] for row in manifest['frozen_bundles']['client']}
    for role in ('witness_js', 'relation_checker'):
        path = Path(proof_inputs[role]['path']).resolve(strict=True)
        relative = path.relative_to(ROOT).as_posix()
        _require(relative in client_paths
                 and client_paths[relative]['sha256'] == proof_input_hashes[role],
                 f'{role} proof helper differs from frozen client source')
    proof_source_hashes = {
        'packet_builder': client_paths.get(
            'tools/part5/build_v3_request_bound_anchor_packet.py', {}).get('sha256'),
        'proof_helper': client_paths.get(
            'tools/part5/prepare_v3_heldout_proof.py', {}).get('sha256'),
    }
    _require(all(_is_sha(value) for value in proof_source_hashes.values()),
             'frozen packet builder and heldout proof helper source pins required')
    verifier_rel = 'tools/part5/verify_v3_heldout_acceptance.py'
    _require(verifier_rel in client_paths
             and client_paths[verifier_rel]['sha256'] == _sha(Path(__file__).read_bytes()),
             'acceptance verifier must be included in the frozen client source bundle')

    globals_ = {'freeze': freeze, 'freeze_sha256': freeze_sha,
                'cohort': cohort, 'cohort_sha256': cohort_sha,
                'source_files': source_hashes,
                'proof_inputs': proof_input_hashes,
                'proof_input_paths': proof_input_paths,
                'proof_source_hashes': proof_source_hashes,
                'packet_template': packet_template,
                'frozen_hashes': frozen_hashes,
                'frozen_paths': frozen_paths}
    seen_variants, seen_requests, seen_finalized_requests, output_cases = (
        set(), set(), set(), [])
    runtime_identity = None
    for case_bundle in cases_raw:
        _require(type(case_bundle) is dict and type(case_bundle.get('variant')) is int
                 and case_bundle['variant'] in range(8)
                 and case_bundle['variant'] not in seen_variants,
                 'unique heldout variant required')
        variant = case_bundle['variant']
        seen_variants.add(variant)
        _verify_case_run_provenance(case_bundle, variant, manifest,
                                    freeze_sha, cohort_sha)
        target = by_variant[variant]
        context, case_sha = _json(case_bundle.get('case_context'), cap=16384)
        stage_context, stage_context_sha = _json(case_bundle.get('stage_context'), cap=16384)
        pair, pair_sha = _json(case_bundle.get('pair_receipt'), cap=8192)
        membership, membership_sha = _json(case_bundle.get('membership'), cap=16384)
        projection = {name: target[name] for name in (
            'variant', 'issuer_index', 'holder_index', 'credential_sha256', 'tbs_sha256',
            'issuer_public_key_sha256', 'holder_public_key_sha256', 'issuer_hash',
            'policy_hash', 'aki_sha256', 'not_before_unix', 'not_after_unix')}
        _verify_offline_provenance_flags(context, pair)
        _require(context.get('schema') == CASE_SCHEMA and context.get('heldout_acceptance') is False
                 and context.get('frozen_cohort', {}).get('freeze_sha256') == freeze_sha
                 and context.get('frozen_cohort', {}).get('cohort_receipt_sha256') == cohort_sha
                 and context.get('target') == projection
                 and context.get('pair_view', {}).get('cohort_receipt_sha256') == pair_sha
                 and context.get('pair_view', {}).get('membership_sha256') == membership_sha
                 and context.get('pair_view', {}).get('stage_context_sha256') == stage_context_sha,
                 'case context does not bind the frozen cohort/pair/stage context')
        unrelated = context.get('unrelated')
        _require(type(unrelated) is dict and unrelated.get('issuer_index') == target['issuer_index']
                 and unrelated.get('issuer_public_key_sha256') == target['issuer_public_key_sha256']
                 and unrelated.get('variant') != variant,
                 'heldout unrelated leaf must share target issuer')
        _require(pair.get('schema') == PAIR_SCHEMA and pair.get('training_only') is True
                 and pair.get('credential_sha256') == target['credential_sha256']
                 and pair.get('unrelated_credential_sha256') == unrelated.get('credential_sha256')
                 and pair.get('membership_sha256') == membership_sha,
                 'pair receipt does not bind frozen target and membership')
        _require(stage_context.get('schema') == 'part5-v3-local-training-context-v1'
                 and stage_context.get('training_only') is True
                 and stage_context.get('root') == context.get('membership', {}).get('R0')
                 and stage_context.get('initial_allocations', {}).get('membership_sha256')
                    == membership_sha,
                 'offline stage context does not match frozen pair')
        roots = context.get('membership')
        _require(type(roots) is dict and set(roots) >= {
            'R0', 'R1', 'R2', 'slot', 'unrelated_slot', 'active_siblings',
            'unrelated_siblings', 'own_revoked_siblings'}
            and all(_is_sha(roots.get(name)) for name in ('R0', 'R1', 'R2'))
            and len({roots['R0'], roots['R1'], roots['R2']}) == 3
            and membership.get('active_root') == int(roots['R0'], 16)
            and membership.get('unrelated_root') == int(roots['R1'], 16)
            and membership.get('own_revoked_root') == int(roots['R2'], 16)
            and membership.get('slot') == roots['slot']
            and membership.get('unrelated_slot') == roots['unrelated_slot']
            and membership.get('active_siblings') == roots['active_siblings']
            and membership.get('unrelated_siblings') == roots['unrelated_siblings']
            and membership.get('own_revoked_siblings') == roots['own_revoked_siblings'],
            'distinct heldout R0/R1/R2 membership roots required')
        case = {'variant': variant, 'target': target, 'unrelated': unrelated,
                'context': context, 'case_sha256': case_sha,
                'pair_sha256': pair_sha, 'stage_context': stage_context,
                'stage_context_sha256': stage_context_sha,
                'membership': membership, 'membership_sha256': membership_sha,
                'roots': {key: roots[key] for key in ('R0', 'R1', 'R2')}}
        stage_map, transition_map, source_map = (case_bundle.get('stage'),
                                                  case_bundle.get('transition'),
                                                  case_bundle.get('sources'))
        _require(type(stage_map) is dict and set(stage_map) == {'A', 'B', 'C'}
                 and type(transition_map) is dict
                 and set(transition_map) == {'A', 'B', 'C'}
                 and type(source_map) is dict and set(source_map) == {'A', 'B', 'C'},
                 'independent A/B/C stage, transition, and source chains required')
        slots = {}
        for slot in ('A', 'B', 'C'):
            stage_bundle = stage_map[slot]
            stage = _validate_stage(stage_bundle, case, frozen_hashes['loaded_elf'])
            transition_bundle = transition_map[slot]
            transition = _verify_transition(
                transition_bundle, stage, case, frozen_hashes['loaded_elf'])
            sources = source_map[slot]
            _require(type(sources) is dict and set(sources) == {'R0', 'R1'},
                     f'request {slot} needs independent R0 and R1 source receipts')
            r0, r0_sha, _ = _source(sources['R0'], 'R0', globals_, case, stage)
            r1, r1_sha, r1_files = _source(sources['R1'], 'R1', globals_, case, stage,
                                           transition['report_sha256'], r0_sha, r0)
            try:
                r1_input = json.loads(r1_files['input.json'][1],
                                      object_pairs_hook=_unique_pairs,
                                      parse_constant=lambda _: (_ for _ in ()).throw(
                                          ValueError('non-finite JSON number')))
            except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValueError('canonical C R1 witness input required') from error
            _require(type(r1_input) is dict,
                     'C R1 witness input object required')
            r0['receipt_ref'], r1['receipt_ref'] = sources['R0']['receipt'], sources['R1']['receipt']
            _require(r0['action_hash'] == r1['action_hash']
                     and r0['staged_request_sha256'] == r1['staged_request_sha256']
                     and r0['finalized_action_transport_sha256']
                        == r1['finalized_action_transport_sha256'],
                     f'request {slot} R0/R1 action transaction must be identical')
            slots[slot] = {'stage_bundle': stage_bundle, 'stage': stage,
                           'transition_bundle': transition_bundle,
                           'transition': transition, 'r0': r0, 'r0_sha256': r0_sha,
                           'r1': r1, 'r1_sha256': r1_sha,
                           'r1_input': r1_input}
        _require(len({slots[slot]['stage']['request_sha256'] for slot in ('A', 'B', 'C')}) == 3,
                 'independent A/B/C stage request accounts required')
        branches = case_bundle.get('branches')
        _require(type(branches) is dict and set(branches) == set(BRANCHES),
                 'all four application branch bundles required')
        clone_destinations = set()
        branch_results = {
            'full': _verify_branch('full', branches['full'], case, globals_,
                                   slots['A'], clone_destinations),
            'unrelated_full': _verify_branch('unrelated_full', branches['unrelated_full'],
                                   case, globals_, slots['B'], clone_destinations),
            'anchor': _verify_branch('anchor', branches['anchor'], case, globals_,
                                   slots['B'], clone_destinations),
            'own_revocation': _verify_branch('own_revocation', branches['own_revocation'],
                                   case, globals_, slots['C'], clone_destinations),
        }
        request_ids = _validate_request_triads(branch_results,
                                              seen_finalized_requests, seen_requests)
        for branch_result in branch_results.values():
            if runtime_identity is None:
                runtime_identity = branch_result['runtime_identity']
            _require(branch_result['runtime_identity'] == runtime_identity,
                     'loaded program or genesis changed across heldout sessions')
        output_cases.append({'variant': variant,
                             'target_credential_sha256': target['credential_sha256'],
                             'target_tbs_sha256': target['tbs_sha256'],
                             'issuer_index': target['issuer_index'],
                             'holder_index': target['holder_index'],
                             'roots': case['roots'], 'branches': branch_results})
    _require(seen_variants == set(range(8)), 'all eight heldout variants are required')
    return {
        'schema': OUTPUT_SCHEMA,
        'verified': True,
        'heldout_acceptance': True,
        'manifest_sha256': manifest_sha256,
        'internal_training_mode_reused': True,
        'source_drift_detected': False,
        'freeze_sha256': freeze_sha,
        'cohort_receipt_sha256': cohort_sha,
        'cohort_import_evidence': cohort_import_evidence,
        'frozen_identities': {
            'setup_manifest_sha256': frozen_hashes['setup_manifest'],
            'vk_sha256': frozen_hashes['ordinary_vk'],
            'loaded_elf_sha256': frozen_hashes['loaded_elf'],
        },
        'source_files': source_hashes,
        'counts': {'variants': 8, 'issuers': 4, 'layouts': 8,
                   'openssl_issuances': 4, 'application_branches': 32,
                   'distinct_requests': 24},
        'cases': output_cases,
    }


def write_receipt(path, receipt):
    path = Path(path)
    _require(path.is_absolute() and not path.exists() and not path.is_symlink(),
             'fresh absolute acceptance output required')
    raw = (json.dumps(receipt, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = verify_manifest(args.manifest)
    write_receipt(args.output, result)
    print(json.dumps({'schema': result['schema'], 'verified': result['verified'],
                      'cases': result['counts']['variants'],
                      'application_branches': result['counts']['application_branches']}))


if __name__ == '__main__':
    main()
