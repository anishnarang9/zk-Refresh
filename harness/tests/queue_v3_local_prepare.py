#!/usr/bin/env python3
"""Fresh local v3 ELF/ledger preparation, only inside external bounded_runner.

No proof, account initialization, source enrollment or Execute is performed.
The external runner owns whole-process-tree wall/RSS/storage limits and cleanup.
A successful report requires graceful direct-child shutdown and finalized loaded
ELF bytes. The protected ledger is retained for a separately reviewed later gate.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.request

_spec = importlib.util.spec_from_file_location('v3_build_prep', Path(__file__).with_name('queue_v3_build_prep.py'))
prep = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(prep)
REPO = Path(__file__).resolve().parents[2]
LOADER = 'BPFLoaderUpgradeab1e11111111111111111111111'
RPC = 'http://127.0.0.1:18999/'
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
LIMITS = {'runtime_seconds': 180, 'rss_bytes': 4294967296, 'storage_growth_bytes': 268435456}
MAX_RESPONSE = 8 * 1024 * 1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


def b58(raw):
    number = int.from_bytes(raw, 'big')
    encoded = ''
    while number:
        number, index = divmod(number, 58)
        encoded = ALPHABET[index] + encoded
    return '1' * (len(raw) - len(raw.lstrip(b'\0'))) + encoded


def key(text):
    if not isinstance(text, str) or not 32 <= len(text) <= 44:
        raise ValueError('canonical public key required')
    value = 0
    for char in text:
        if char not in ALPHABET:
            raise ValueError('invalid public key')
        value = value * 58 + ALPHABET.index(char)
    raw = bytes(len(text) - len(text.lstrip('1'))) + value.to_bytes((value.bit_length() + 7) // 8, 'big')
    if len(raw) != 32 or b58(raw) != text:
        raise ValueError('canonical 32-byte public key required')
    return raw


def integer(value, minimum=0):
    if type(value) is not int or value < minimum or value > (1 << 64) - 1:
        raise ValueError('bounded integer required')
    return value


def checked(path, expected, cap):
    prep.canonical_sha(expected)
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError('canonical artifact path required')
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > cap:
        raise ValueError('bounded regular artifact required')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before) != identity(os.fstat(stream.fileno())):
            raise ValueError('artifact changed at open')
        data = stream.read(cap + 1)
        if identity(before) != identity(os.fstat(stream.fileno())):
            raise ValueError('artifact changed during read')
    if len(data) != before.st_size or sha(data) != expected:
        raise ValueError('artifact pin mismatch')
    return data


def unique_object(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise ValueError('duplicate JSON key')
        value[name] = item
    return value


def decode_json(raw):
    return json.loads(raw, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def rpc_result(raw, request_id):
    value = decode_json(raw)
    if (not isinstance(value, dict) or value.get('jsonrpc') != '2.0'
            or type(value.get('id')) is not int or value['id'] != request_id
            or 'error' in value or 'result' not in value):
        raise ValueError('invalid RPC envelope')
    return value['result']


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise ValueError('RPC redirect forbidden')


class LocalRpc:
    def __init__(self):
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.serial = 0

    def __call__(self, method, params):
        self.serial += 1
        body = json.dumps({'jsonrpc': '2.0', 'id': self.serial, 'method': method, 'params': params}).encode()
        request = urllib.request.Request(RPC, data=body, headers={'Content-Type': 'application/json',
                                                                 'Accept-Encoding': 'identity'})
        with self.opener.open(request, timeout=1) as response:
            if (response.status != 200 or response.headers.get_content_type() != 'application/json'
                    or response.headers.get('Content-Encoding', 'identity').lower() != 'identity'):
                raise ValueError('unexpected RPC HTTP response')
            raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ValueError('RPC response cap')
        return rpc_result(raw, self.serial)


def account_bytes(account):
    if not isinstance(account, dict):
        raise ValueError('RPC account required')
    encoded = account.get('data')
    if (not isinstance(encoded, list) or len(encoded) != 2 or encoded[1] != 'base64'
            or not isinstance(encoded[0], str) or len(encoded[0]) > MAX_RESPONSE):
        raise ValueError('canonical account encoding required')
    raw = base64.b64decode(encoded[0], validate=True)
    if base64.b64encode(raw).decode() != encoded[0]:
        raise ValueError('noncanonical base64')
    return raw


def program_link(account):
    raw = account_bytes(account)
    if (account.get('owner') != LOADER or account.get('executable') is not True
            or len(raw) != 36 or raw[:4] != (2).to_bytes(4, 'little')):
        raise ValueError('canonical upgradeable Program account required')
    return b58(raw[4:])


def loaded_identity(program, programdata, accounts, slot, elf, elf_sha256):
    key(program); key(programdata); integer(slot, 1)
    if program == programdata or program in (LOADER, b58(bytes(32))):
        raise ValueError('distinct loaded program roles required')
    if not isinstance(accounts, list) or len(accounts) != 2 or program_link(accounts[0]) != programdata:
        raise ValueError('same-batch ProgramData link mismatch')
    pd = accounts[1]
    raw = account_bytes(pd)
    if (pd.get('owner') != LOADER or pd.get('executable') is not False or len(raw) < 49
            or len(raw) > 45 + 4 * 1024 * 1024 or raw[:4] != (3).to_bytes(4, 'little')
            or int.from_bytes(raw[4:12], 'little') > slot or raw[12] not in (0, 1)):
        raise ValueError('canonical finalized ProgramData required')
    authority = b58(raw[13:45]) if raw[12] else None
    payload = prep.compare_elf_payload(elf, raw[45:], elf_sha256)
    return {'elf_match': payload['elf_match'], 'elf_sha256': elf_sha256,
            'elf_bytes': len(elf), 'program': program, 'programdata': programdata,
            'loader': LOADER, 'finalized_slot': slot, 'deployment_slot': int.from_bytes(raw[4:12], 'little'),
            'upgrade_authority': authority, 'program_account_sha256': sha(account_bytes(accounts[0])),
            'programdata_account_sha256': sha(raw), 'application_effect': False}


class NotReady(Exception):
    pass


def batch_result(result, count, minimum):
    if not isinstance(result, dict) or not isinstance(result.get('context'), dict):
        raise ValueError('RPC account context required')
    slot = integer(result['context'].get('slot'))
    values = result.get('value')
    if not isinstance(values, list) or len(values) != count:
        raise ValueError('RPC account batch count')
    if slot < minimum or any(value is None for value in values):
        raise NotReady()
    return slot, values


def wait_loaded(rpc, proc, program, elf, elf_sha256, timeout=30):
    deadline = time.monotonic() + timeout
    attempts = 0
    genesis = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError('validator exited before finalized identity')
        attempts += 1
        try:
            current = rpc('getGenesisHash', [])
            key(current)
            if genesis is not None and current != genesis:
                raise ValueError('local genesis changed')
            genesis = current
            discovery = rpc('getAccountInfo', [program, {'encoding': 'base64', 'commitment': 'finalized'}])
            if not isinstance(discovery, dict) or not isinstance(discovery.get('context'), dict):
                raise ValueError('discovery context required')
            minimum = integer(discovery['context'].get('slot'))
            if minimum == 0 or discovery.get('value') is None:
                raise NotReady()
            pd = program_link(discovery['value'])
            result = rpc('getMultipleAccounts', [[program, pd], {'encoding': 'base64',
                         'commitment': 'finalized', 'minContextSlot': minimum}])
            slot, accounts = batch_result(result, 2, minimum)
            report = loaded_identity(program, pd, accounts, slot, elf, elf_sha256)
            if rpc('getGenesisHash', []) != genesis:
                raise ValueError('local genesis changed during finalized read')
            if proc.poll() is not None:
                raise RuntimeError('validator exited during finalized identity')
            report.update({'genesis': genesis, 'attempts': attempts, 'commitment': 'finalized'})
            return report
        except (OSError, NotReady):
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.1, remaining))
    raise TimeoutError('finalized loaded-ELF readiness deadline')


def validator_argv(validator, ledger, elf, program, mint):
    key(program); key(mint)
    if program == mint or program in (LOADER, b58(bytes(32))) or mint in (LOADER, b58(bytes(32))):
        raise ValueError('distinct explicit program and mint required')
    ledger = Path(ledger)
    if not ledger.is_absolute() or ledger.resolve() != ledger or ledger.exists() or ledger.is_symlink():
        raise ValueError('fresh canonical ledger required')
    return [str(validator), '--ledger', str(ledger), '--bind-address', '127.0.0.1',
            '--rpc-port', '18999', '--gossip-port', '18901', '--faucet-port', '19001',
            '--dynamic-port-range', '19002-19028', '--limit-ledger-size', '10000', '--quiet',
            '--reset', '--mint', mint, '--bpf-program', program, str(elf)]


def ports_free():
    held = []
    try:
        for port in [18999, 19000, 19001, 18901] + list(range(19002, 19029)):
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                sock = socket.socket(socket.AF_INET, kind); held.append(sock)
                sock.bind(('127.0.0.1', port))
    finally:
        for sock in held:
            sock.close()


def cleanup(proc):
    if proc is None:
        return {'spawned': False, 'reaped': True, 'graceful': True}
    graceful = proc.poll() is None
    if proc.poll() is None:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            graceful = False
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait(timeout=2)
    else:
        proc.wait(timeout=2)
    exit_code = proc.poll()
    # Only clean validator exit zero can leave a reusable persistent ledger.
    # Receiving SIGINT alone does not establish that shutdown completed safely.
    graceful = graceful and exit_code == 0
    return {'spawned': True, 'reaped': exit_code is not None, 'graceful': graceful,
            'exit_code': exit_code}


def fresh_child(path, base):
    path = Path(path)
    if (not path.is_absolute() or not path.is_relative_to(base) or path == base
            or path.resolve() != path or path.exists() or path.is_symlink()):
        raise ValueError('fresh protected child path required')
    return path


def write_new(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())


def admit(config):
    if (config.get('schema') != 1 or config.get('scope') != 'part5-v3-local-prepare'
            or config.get('outer_limits_required') != LIMITS):
        raise ValueError('explicit bounded v3 prepare contract required')
    plan = decode_json(checked(config['build_plan'], config['build_plan_sha256'], 65536))
    if plan.get('schema') != 1 or plan.get('status') != 'prepared_only' or plan.get('cwd') != str(REPO):
        raise ValueError('reviewed v3 build plan required')
    prep.check_manifest(REPO, plan['source_manifest'])
    if prep.external_config_pins(REPO) != plan['external_cargo_config_pins']:
        raise ValueError('external Cargo config drift')
    argv = plan['argv']
    checked(argv[0], plan['builder_sha256'], 128 * 1024 * 1024)
    expected = [argv[0], '--offline', '--skip-tools-install', '--tools-version', 'v1.54',
        '--arch', 'v0', '--manifest-path', str(REPO / 'program/Cargo.toml'),
        '--sbf-out-dir', argv[argv.index('--sbf-out-dir') + 1], '-j', '1', '--', '--locked']
    if argv != expected:
        raise ValueError('reviewed build command mismatch')
    elf_path = Path(config['elf'])
    output = Path(argv[argv.index('--sbf-out-dir') + 1])
    base = REPO / 'artifacts/dynark/part5'
    if (not output.is_relative_to(base) or output.resolve() != output
            or elf_path != output / 'zk_fresh_program.so'):
        raise ValueError('ELF must be actual reviewed v3 output')
    elf = checked(elf_path, config['elf_sha256'], 4 * 1024 * 1024)
    prep.compare_elf_payload(elf, elf, config['elf_sha256'])
    checked(config['validator'], config['validator_sha256'], 128 * 1024 * 1024)
    runtime = fresh_child(config['runtime_output'], base)
    control = fresh_child(config['control_output'], base)
    if runtime.is_relative_to(control) or control.is_relative_to(runtime):
        raise ValueError('disjoint runtime and control required')
    if not runtime.name.startswith('application-v3-') or not control.name.startswith('application-v3-'):
        raise ValueError('versioned v3 output paths required')
    argv = validator_argv(config['validator'], runtime / 'ledger', elf_path, config['program'], config['mint'])
    return plan, elf, runtime, control, argv


def run(config, config_sha256):
    if os.environ.get('P5_V3_PREPARE_SCOPE') != 'local-validator-prepare':
        raise ValueError('explicit external bounded-runner scope required')
    plan, elf, runtime, control, argv = admit(config)
    started = time.monotonic(); proc = None; logs = []; handlers = {}
    old_umask = os.umask(0o077)
    status = {'schema': 1, 'scope': 'part5-v3-local-prepare', 'status': 'failed',
              'config_sha256': config_sha256, 'application_effect': False, 'devnet': False,
              'outer_limits_required': LIMITS, 'whole_tree_cleanup_authority': 'external bounded_runner'}
    def interrupted(signum, frame):
        raise InterruptedError('prepare interrupted')
    try:
        control.mkdir(mode=0o700); runtime.mkdir(mode=0o700)
        for signum in (signal.SIGINT, signal.SIGTERM):
            handlers[signum] = signal.signal(signum, interrupted)
        ports_free()
        for name in ('validator.stdout.log', 'validator.stderr.log'):
            fd = os.open(control / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            logs.append(os.fdopen(fd, 'wb'))
        write_new(control / 'invocation.json', {'validator_argv': argv,
            'source_manifest': plan['source_manifest'], 'build_plan_sha256': config['build_plan_sha256'],
            'elf_sha256': config['elf_sha256'], 'validator_sha256': config['validator_sha256'],
            'outer_limits_required': LIMITS, 'readiness_seconds': 30})
        env = os.environ.copy()
        for name in plan['environment_remove']:
            env.pop(name, None)
        env.update(plan['environment_required'])
        proc = subprocess.Popen(argv, cwd=REPO, env=env, stdin=subprocess.DEVNULL,
                                stdout=logs[0], stderr=logs[1], start_new_session=False)
        identity = wait_loaded(LocalRpc(), proc, config['program'], elf, config['elf_sha256'])
        prep.check_manifest(REPO, plan['source_manifest'])
        checked(config['elf'], config['elf_sha256'], 4 * 1024 * 1024)
        ledger = runtime / 'ledger'
        ledger_stat = ledger.lstat()
        genesis_stat = (ledger / 'genesis.bin').lstat()
        if (not stat.S_ISDIR(ledger_stat.st_mode) or ledger_stat.st_mode & 0o7777 != 0o700
                or ledger_stat.st_uid != os.getuid() or not stat.S_ISREG(genesis_stat.st_mode)
                or genesis_stat.st_mode & 0o7777 != 0o600 or genesis_stat.st_uid != os.getuid()):
            raise ValueError('owner-only persistent ledger/genesis required')
        status.update({'status': 'passed', 'loaded_program': identity, 'mint': config['mint'],
            'build_plan_sha256': config['build_plan_sha256'], 'v3_vk': plan['source_manifest']['v3_vk'],
            'source_manifest_sha256': sha(json.dumps(plan['source_manifest'], sort_keys=True).encode()),
            'ledger': str(ledger), 'prepared_application_accounts': False})
    except Exception as error:
        status.update({'error_type': type(error).__name__})
    finally:
        for signum in handlers:
            signal.signal(signum, signal.SIG_IGN)
        try:
            status['cleanup'] = cleanup(proc)
        except Exception as error:
            status['cleanup'] = {'reaped': False, 'graceful': False, 'error_type': type(error).__name__}
        if not status['cleanup'].get('graceful') or not status['cleanup'].get('reaped'):
            status['status'] = 'failed'
        status['ledger_reuse_requires_review'] = status['status'] != 'passed'
        status['elapsed_seconds'] = time.monotonic() - started
        for stream in logs:
            stream.close()
        try:
            if control.is_dir():
                write_new(control / 'status.json', status)
        finally:
            for signum, handler in handlers.items():
                signal.signal(signum, handler)
            os.umask(old_umask)
    print(json.dumps({'status': status['status'], 'report': str(control / 'status.json')}))
    return 0 if status['status'] == 'passed' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--config-sha256', required=True)
    args = parser.parse_args()
    config = decode_json(checked(args.config, args.config_sha256, 65536))
    return run(config, args.config_sha256)


if __name__ == '__main__':
    sys.exit(main())
