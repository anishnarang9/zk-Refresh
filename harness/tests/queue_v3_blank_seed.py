"""Pinned blank-chain seed import and measured local application deployment.

Seed creation is a separately supervised operation. Its owner may use
creation_argv() and observe_blank(), then persist config/status/monitor receipts
and call build_manifest() after the monitor has stopped. No seed is created by
importing this module. A copy receipt never claims a validator or deployment ran.
"""
import hashlib
import math
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import time

from harness.tests import queue_v3_local_prepare as base
from harness.tests.queue_v3_clone_prepared import _raw, _directory, _tree
from harness.tests.queue_v3_clone_ledger import stale_admin_socket

CREATE_SCOPE = 'part5-v3-blank-seed-create'
SCHEMA = 'part5-v3-blank-chain-seed-v1'
KIND = 'blank-seed-deploy-v1'
SYSTEM = base.b58(bytes(32))


def pin(ref, cap=65536):
    if type(ref) is not dict or set(ref) != {'path', 'sha256'}:
        raise ValueError('exact blank seed artifact pin required')
    base.prep.canonical_sha(ref['sha256'])
    raw = _raw(ref['path'], cap)
    if base.sha(raw) != ref['sha256']:
        raise ValueError('blank seed artifact pin mismatch')
    return base.decode_json(raw)


def programdata_address(program):
    """Upgradeable-loader PDA; curve membership matches compressed Edwards Y."""
    program_bytes, loader = base.key(program), base.key(base.LOADER)
    prime = 2**255 - 19
    d = -121665 * pow(121666, prime - 2, prime) % prime
    for bump in range(255, -1, -1):
        digest = hashlib.sha256(program_bytes + bytes([bump]) + loader +
                                b'ProgramDerivedAddress').digest()
        y = int.from_bytes(digest, 'little') & (2**255 - 1)
        numerator = (y * y - 1) % prime
        denominator = (d * y * y + 1) % prime
        square = numerator * pow(denominator, prime - 2, prime) % prime
        if denominator != 0 and (square == 0 or pow(square, (prime - 1) // 2, prime) == 1):
            continue
        return base.b58(digest)
    raise ValueError('ProgramData PDA derivation failed')


def resume_argv(validator, ledger):
    ledger = Path(ledger)
    if not ledger.is_absolute() or ledger.resolve() != ledger or ledger.is_symlink():
        raise ValueError('canonical blank seed ledger path required')
    return [str(validator), '--ledger', str(ledger), '--bind-address', '127.0.0.1',
            '--rpc-port', '18999', '--gossip-port', '18901', '--faucet-port', '19001',
            '--dynamic-port-range', '19002-19028', '--limit-ledger-size', '10000', '--quiet']


def creation_argv(validator, ledger, payer):
    base.key(payer)
    ledger = Path(ledger)
    if ledger.exists():
        raise ValueError('fresh blank-chain seed ledger required')
    return resume_argv(validator, ledger) + ['--reset', '--mint', payer]


def check_observation(observation, config):
    expected = {'program': config['program'], 'programdata': programdata_address(config['program']),
                'payer': config['payer']}
    if (type(observation) is not dict
            or any(observation.get(name) != value for name, value in expected.items())
            or any(observation.get(name) is not True for name in
                   ('program_absent', 'programdata_absent', 'application_accounts_empty'))
            or observation.get('payer_owner') != SYSTEM):
        raise ValueError('finalized blank application domain required')
    base.key(observation.get('genesis'))
    base.integer(observation.get('finalized_slot'), 1)
    base.integer(observation.get('program_accounts_finalized_slot'), observation['finalized_slot'])
    base.integer(observation.get('payer_lamports'), 1)


def reviewed_stop(cleanup):
    if (type(cleanup) is not dict or cleanup.get('spawned') is not True
            or cleanup.get('reaped') is not True):
        return False
    return ((cleanup.get('exit_code') == 0 and cleanup.get('graceful') is True)
            or (cleanup.get('exit_code') == -signal.SIGINT and cleanup.get('graceful') is False))


def review_monitor(monitor, owner, status, limits):
    expected_exit = 0 if status.get('status') == 'passed' else 1
    duration = monitor.get('duration_seconds')
    if (monitor.get('schema') != 1 or monitor.get('measurement') != 'bounded_complete_session'
            or monitor.get('owner') != owner or monitor.get('passed') is not (expected_exit == 0)
            or monitor.get('exit_code') != expected_exit or monitor.get('censored') is not False
            or monitor.get('stop_reason') is not None or monitor.get('runner_error_type') is not None
            or monitor.get('cleanup_remaining_owned_processes') != 0
            or monitor.get('cleanup_status_unknown') is not False
            or type(monitor.get('sample_count')) is not int or monitor['sample_count'] < 1
            or type(duration) not in (int, float) or not math.isfinite(duration) or duration <= 0):
        raise ValueError('uncensored stopped blank seed owner monitor required')
    reported = monitor.get('limits')
    expected = {'runtime_seconds': limits['runtime_seconds'],
                'owned_tree_rss_bytes': limits['rss_bytes'],
                'storage_growth_bytes': limits['storage_growth_bytes']}
    if (type(reported) is not dict or set(reported) != set(expected) | {'poll_seconds'}
            or any(type(reported[name]) not in (int, float) or reported[name] != value
                   for name, value in expected.items())
            or type(reported.get('poll_seconds')) not in (int, float)
            or not math.isfinite(reported['poll_seconds']) or reported['poll_seconds'] <= 0):
        raise ValueError('monitor resource caps differ from pinned creation/prepare contract')


def build_manifest(sources):
    """Return an immutable manifest after independently pinned creation finishes."""
    if type(sources) is not dict or set(sources) != {'config', 'status', 'monitor', 'invocation', 'monitor_owner'}:
        raise ValueError('exact blank seed creation provenance required')
    config, status, monitor = (pin(sources[name]) for name in ('config', 'status', 'monitor'))
    if (config.get('schema') != 1 or config.get('scope') != CREATE_SCOPE
            or config.get('outer_limits_required') != base.LIMITS
            or status.get('schema') != 1 or status.get('scope') != CREATE_SCOPE
            or status.get('config_sha256') != sources['config']['sha256']
            or status.get('ledger') != str(Path(config['runtime_output']) / 'ledger')
            or status.get('blank_verified') is not True
            or status.get('application_effect') is not False
            or status.get('prepared_application_accounts') is not False
            or status.get('error_type') is not None or not reviewed_stop(status.get('cleanup'))
            or status.get('status') != ('passed' if status['cleanup']['graceful'] else 'failed')
            or any(name in config for name in ('elf', 'blank_seed', 'prepared_import'))):
        raise ValueError('stopped blank-chain creation evidence required')
    base.prep.canonical_sha(config['validator_sha256'])
    base.checked(config['validator'], config['validator_sha256'], 128 * 1024 * 1024)
    review_creation_invocation(sources, config)
    check_observation(status.get('seed_observation'), config)
    review_monitor(monitor, sources['monitor_owner'], status, config['outer_limits_required'])
    ledger = _directory(status['ledger'])
    # Full restart state is required; a genesis.bin-only directory is not a seed.
    for name in ('validator-keypair.json', 'vote-account-keypair.json', 'stake-account-keypair.json'):
        _raw(ledger / name, 1024)
    count, tree = _tree(ledger)
    observation = status['seed_observation']
    return {'schema': SCHEMA, 'ledger': str(ledger), 'source_creation': sources,
            'validator_sha256': config['validator_sha256'],
            **{name: observation[name] for name in ('program', 'programdata', 'payer', 'genesis')},
            'entry_count': count, 'tree_sha256': tree,
            'genesis_file_sha256': base.sha(_raw(ledger / 'genesis.bin', 16 * 1024 * 1024)),
            'application_effect': False, 'prepared_application_accounts': False}


def review_creation_invocation(sources, config):
    owner = config.get('owner_source')
    if type(owner) is not dict or set(owner) != {'path', 'sha256'}:
        raise ValueError('pinned seed creation worker source required')
    base.checked(owner['path'], owner['sha256'], 4 * 1024 * 1024)
    manifest = config.get('owner_manifest')
    pin(manifest, 1024 * 1024)
    invocation = pin(sources['invocation'])
    runtime, control = Path(config['runtime_output']), Path(config['control_output'])
    expected = [sys.executable, owner['path'], '--manifest', manifest['path'],
                '--output-root', str(runtime.parent), '--seed-config', sources['config']['path'],
                '--seed-config-sha256', sources['config']['sha256'], '--_create-seed']
    if (set(invocation) != {'owner', 'argv', 'cwd', 'started_at_utc', 'storage_roots'}
            or invocation.get('owner') != sources['monitor_owner']
            or invocation.get('argv') != expected or invocation.get('cwd') != str(base.REPO)
            or type(invocation.get('started_at_utc')) is not str or not invocation['started_at_utc']
            or runtime.parent != control.parent or runtime == control):
        raise ValueError('seed creation owner invocation differs from pinned worker/config')
    roots = invocation.get('storage_roots')
    if (type(roots) is not list or not roots
            or any(type(value) is not str or not Path(value).is_absolute()
                   or Path(value).resolve() != Path(value) for value in roots)
            or Path(roots[0]) != Path(sources['invocation']['path']).parent
            or any(not any(path == Path(root) or Path(root) in path.parents for root in roots)
                   for path in (runtime, control))):
        raise ValueError('seed creation monitor must cover runtime and control outputs')


def review_manifest(ref, config):
    manifest = pin(ref)
    if manifest.get('schema') != SCHEMA:
        raise ValueError('explicit blank-chain seed manifest required')
    reconstructed = build_manifest(manifest.get('source_creation'))
    if (manifest != reconstructed or manifest['program'] != config['program']
            or manifest['validator_sha256'] != config['validator_sha256']):
        raise ValueError('blank-chain seed domain or inventory drift')
    return manifest


def clone(ref, destination, config):
    manifest = review_manifest(ref, config)
    source, destination = Path(manifest['ledger']), Path(destination)
    _directory(destination.parent)
    if (not destination.is_absolute() or destination.resolve() != destination
            or destination.exists() or destination.is_symlink() or destination == source
            or destination in source.parents or source in destination.parents):
        raise ValueError('fresh disjoint blank seed clone required')
    stale = stale_admin_socket(source)
    shutil.copytree(source, destination, copy_function=shutil.copy2,
                    ignore=lambda directory, names: {'admin.rpc'}
                    if stale and Path(directory) == source else set())
    expected = (manifest['entry_count'], manifest['tree_sha256'])
    if _tree(source) != expected or _tree(destination) != expected:
        raise ValueError('blank seed changed during clone or copy differs')
    return {'schema': 'part5-v3-blank-seed-import-v1', 'seed_manifest': ref,
            'source': str(source), 'destination': str(destination),
            'tree_sha256': manifest['tree_sha256'], 'entry_count': manifest['entry_count'],
            'genesis_file_sha256': manifest['genesis_file_sha256'],
            'source_stable': True, 'copy_identical': True,
            'excluded_stale_admin_socket': stale,
            'loaded_identity_rechecked_after_restart': False}


def observe_blank(rpc, proc, seed, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError('validator exited before blank-chain attestation')
        try:
            if rpc('getGenesisHash', []) != seed['genesis']:
                raise ValueError('blank seed genesis mismatch')
            result = rpc('getMultipleAccounts', [[seed['program'], seed['programdata'], seed['payer']],
                         {'encoding': 'base64', 'commitment': 'finalized'}])
            slot = base.integer(result['context']['slot'])
            if slot == 0:
                raise base.NotReady()
            values = result['value']
            if (not isinstance(values, list) or len(values) != 3
                    or values[0] is not None or values[1] is not None
                    or type(values[2]) is not dict or values[2].get('owner') != SYSTEM
                    or values[2].get('executable') is not False):
                raise ValueError('application program must be absent and deployment payer funded')
            lamports = base.integer(values[2].get('lamports'), 1)
            accounts = rpc('getProgramAccounts', [seed['program'], {'encoding': 'base64',
                           'commitment': 'finalized', 'minContextSlot': slot,
                           'withContext': True, 'dataSlice': {'offset': 0, 'length': 0}}])
            account_slot = base.integer(accounts['context']['slot'], slot)
            if accounts.get('value') != []:
                raise ValueError('blank seed must have no application-owned accounts')
            if rpc('getGenesisHash', []) != seed['genesis'] or proc.poll() is not None:
                raise ValueError('blank seed domain changed during attestation')
            observation = {name: seed[name] for name in ('genesis', 'program', 'programdata', 'payer')}
            observation.update(finalized_slot=slot, program_accounts_finalized_slot=account_slot,
                               program_absent=True, programdata_absent=True,
                               application_accounts_empty=True, payer_lamports=lamports, payer_owner=SYSTEM)
            check_observation(observation, seed)
            return observation
        except (OSError, base.NotReady):
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.1, remaining))
    raise TimeoutError('blank-chain finalized readiness deadline')


def signer(ref):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    value = pin(ref, 1024)
    if (type(value) is not list or len(value) != 64
            or any(type(byte) is not int or not 0 <= byte <= 255 for byte in value)):
        raise ValueError('canonical deployment signer required')
    raw = bytes(value)
    public = Ed25519PrivateKey.from_private_bytes(raw[:32]).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if raw[32:] != public:
        raise ValueError('deployment signer public key mismatch')
    return base.b58(public)


def admit_deployment(config):
    if not all(name in config for name in ('blank_seed', 'solana_cli', 'program_signer', 'deployment_payer')):
        raise ValueError('complete explicit blank seed deployment contract required')
    manifest = review_manifest(config['blank_seed'], config)
    cli = config['solana_cli']
    if type(cli) is not dict or set(cli) != {'path', 'sha256'}:
        raise ValueError('explicit pinned Solana CLI required')
    base.checked(cli['path'], cli['sha256'], 128 * 1024 * 1024)
    if (signer(config['program_signer']) != config['program']
            or signer(config['deployment_payer']) != manifest['payer']):
        raise ValueError('deployment signers differ from frozen program or funded seed payer')
    return manifest


def deploy_argv(config, buffer):
    return [config['solana_cli']['path'], 'program', 'deploy', config['elf'],
            '--url', base.RPC.rstrip('/'), '--ws', 'ws://127.0.0.1:19000/',
            '--keypair', config['deployment_payer']['path'],
            '--fee-payer', config['deployment_payer']['path'],
            '--upgrade-authority', config['deployment_payer']['path'],
            '--program-id', config['program_signer']['path'], '--buffer', str(buffer),
            '--commitment', 'finalized', '--use-rpc', '--final',
            '--max-sign-attempts', '1', '--output', 'json']


def deploy(config, control, validator, rpc, elf):
    """Deploy inside the preparation owner and return independently read bytes."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    manifest = admit_deployment(config)
    observation = observe_blank(rpc, validator, manifest)
    control = _directory(control)
    buffer = control / 'deployment-buffer.json'
    secret = Ed25519PrivateKey.generate()
    raw = secret.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                               serialization.NoEncryption())
    public = secret.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    base.write_new(buffer, list(raw + public))
    buffer_ref = {'path': str(buffer), 'sha256': base.sha(_raw(buffer, 1024))}
    argv = deploy_argv(config, buffer)
    invocation = {'schema': 'part5-v3-seeded-deployment-invocation-v1', 'argv': argv,
                  'blank_seed': config['blank_seed'], 'solana_cli': config['solana_cli'],
                  'program_signer': config['program_signer'], 'deployment_payer': config['deployment_payer'],
                  'elf_sha256': config['elf_sha256'], 'buffer': buffer_ref}
    path = control / 'deployment-invocation.json'
    base.write_new(path, invocation)
    invocation_ref = {'path': str(path), 'sha256': base.sha(_raw(path))}
    child = None
    started = time.monotonic()
    try:
        with (control / 'deployment.stdout.log').open('xb') as out, \
                (control / 'deployment.stderr.log').open('xb') as err:
            out_path, err_path = Path(out.name), Path(err.name)
            out_path.chmod(0o600); err_path.chmod(0o600)
            env = os.environ.copy()
            for name in ('LD_PRELOAD', 'DYLD_INSERT_LIBRARIES'):
                env.pop(name, None)
            child = subprocess.Popen(argv, cwd=base.REPO, env=env, stdin=subprocess.DEVNULL,
                                     stdout=out, stderr=err, start_new_session=False)
            deadline = time.monotonic() + 90
            while child.poll() is None:
                if validator.poll() is not None:
                    raise RuntimeError('validator exited during application deployment')
                if time.monotonic() >= deadline:
                    raise TimeoutError('local application deployment deadline')
                time.sleep(0.1)
            if child.wait(timeout=2) != 0:
                raise RuntimeError('local application deployment rejected')
        loaded = base.wait_loaded(rpc, validator, config['program'], elf, config['elf_sha256'])
        if (loaded['genesis'] != manifest['genesis'] or loaded['programdata'] != manifest['programdata']
                or loaded['program'] != manifest['program'] or loaded.get('upgrade_authority') is not None
                or loaded.get('elf_match') is not True or loaded.get('elf_sha256') != config['elf_sha256']):
            raise ValueError('finalized deployed program, ELF or seed genesis mismatch')
        return loaded, {'schema': 'part5-v3-seeded-deployment-v1', 'argv': argv,
                        'invocation': invocation_ref, 'buffer': buffer_ref,
                        'predeployment_observation': observation,
                        'loaded_program': loaded, 'exit_code': 0, 'reaped': True,
                        'finalized_elf_verified': True,
                        'elapsed_seconds': time.monotonic() - started}
    finally:
        if child is not None:
            if child.poll() is None:
                base.cleanup(child)
            else:
                child.wait(timeout=2)


def review_prepare(prior, monitor, original, config):
    """Admit measured seeded preparation; stage still reattests after restart."""
    manifest = admit_deployment(original)
    loaded = prior.get('loaded_program', {})
    if (original.get('scope') != 'part5-v3-local-prepare' or prior.get('schema') != 1
            or prior.get('scope') != original['scope'] or prior.get('preparation_kind') != KIND
            or prior.get('config_sha256') != config['prior_config_sha256']
            or prior.get('ledger') != config['ledger']
            or prior['ledger'] != str(Path(original['runtime_output']) / 'ledger')
            or prior.get('error_type') is not None or prior.get('application_effect') is not False
            or prior.get('prepared_application_accounts') is not False
            or not reviewed_stop(prior.get('cleanup'))
            or prior.get('status') != ('passed' if prior['cleanup']['graceful'] else 'failed')
            or prior.get('ledger_reuse_requires_review') is not (not prior['cleanup']['graceful'])
            or loaded.get('genesis') != manifest['genesis']
            or loaded.get('genesis') != config['expected_genesis']
            or loaded.get('program') != manifest['program'] or loaded.get('programdata') != manifest['programdata']
            or loaded.get('elf_match') is not True or loaded.get('elf_sha256') != original['elf_sha256']
            or loaded.get('upgrade_authority') is not None):
        raise ValueError('measured blank seed deployment preparation required')
    review_monitor(monitor, config['prior_monitor_owner'], prior, original['outer_limits_required'])
    imported = prior.get('seed_import', {})
    expected = {'schema': 'part5-v3-blank-seed-import-v1', 'seed_manifest': original['blank_seed'],
                'source': manifest['ledger'], 'destination': prior['ledger'],
                'tree_sha256': manifest['tree_sha256'], 'entry_count': manifest['entry_count'],
                'genesis_file_sha256': manifest['genesis_file_sha256'],
                'source_stable': True, 'copy_identical': True,
                'loaded_identity_rechecked_after_restart': False}
    if (any(imported.get(name) != value for name, value in expected.items())
            or type(imported.get('excluded_stale_admin_socket')) is not bool
            or Path(imported['source']) == Path(imported['destination'])
            or Path(imported['source']) in Path(imported['destination']).parents
            or Path(imported['destination']) in Path(imported['source']).parents
            or base.sha(_raw(Path(prior['ledger']) / 'genesis.bin', 16 * 1024 * 1024))
                != manifest['genesis_file_sha256']):
        raise ValueError('pinned independent blank seed clone provenance required')
    deployment = prior.get('deployment', {})
    control = _directory(original['control_output'])
    argv = deploy_argv(original, control / 'deployment-buffer.json')
    if (deployment.get('schema') != 'part5-v3-seeded-deployment-v1'
            or deployment.get('argv') != argv or deployment.get('exit_code') != 0
            or deployment.get('reaped') is not True or deployment.get('finalized_elf_verified') is not True
            or deployment.get('loaded_program') != loaded
            or deployment.get('invocation', {}).get('path') != str(control / 'deployment-invocation.json')
            or deployment.get('buffer', {}).get('path') != str(control / 'deployment-buffer.json')):
        raise ValueError('normal finalized deployment evidence required')
    check_observation(deployment.get('predeployment_observation'), manifest)
    if deployment['predeployment_observation']['genesis'] != manifest['genesis']:
        raise ValueError('predeployment seed genesis mismatch')
    expected_invocation = {'schema': 'part5-v3-seeded-deployment-invocation-v1', 'argv': argv,
                           'blank_seed': original['blank_seed'], 'solana_cli': original['solana_cli'],
                           'program_signer': original['program_signer'],
                           'deployment_payer': original['deployment_payer'],
                           'elf_sha256': original['elf_sha256'], 'buffer': deployment['buffer']}
    if pin(deployment['invocation']) != expected_invocation:
        raise ValueError('deployment invocation pin mismatch')
    signer(deployment['buffer'])
