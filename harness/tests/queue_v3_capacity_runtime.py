"""Capacity-only signed transaction, snapshot and owned-child helpers."""
import base64
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import time

from harness.tests import queue_v3_local_execute as execute


def require(condition, message):
    if not condition:
        raise ValueError(message)


def queue(raw, config_address):
    require(len(raw) == 2090 and raw[:8] == b'DYNQUE03'
            and raw[8:40] == execute.base.key(config_address), 'exact capacity queue codec required')
    count = int.from_bytes(raw[40:42], 'big')
    require(count <= 64 and not any(raw[42+32*count:]), 'canonical bounded queue required')
    rows = [execute.base.b58(raw[42+i*32:74+i*32]) for i in range(count)]
    require(len(set(rows)) == len(rows), 'distinct queue entries required')
    return rows


def short(raw, offset):
    value = 0
    for index in range(3):
        require(offset < len(raw), 'truncated short vector')
        byte = raw[offset]
        offset += 1
        value |= (byte & 127) << (7*index)
        if byte < 128:
            require(index == 0 or byte != 0, 'canonical short vector required')
            return value, offset
    raise ValueError('bounded short vector required')


def signed_transaction(raw, signature, program, data, accounts):
    """Verify every Ed25519 signature and exact legacy application instruction."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    require(type(raw) is bytes and 0 < len(raw) <= 1232, 'bounded transaction required')
    count, offset = short(raw, 0)
    require(1 <= count <= 16 and offset+count*64+3 < len(raw), 'complete signature vector required')
    signatures = [raw[offset+i*64:offset+(i+1)*64] for i in range(count)]
    offset += count*64
    message = raw[offset:]
    required, readonly_signed, readonly_unsigned = raw[offset:offset+3]
    offset += 3
    require(required == count and readonly_signed <= count, 'legacy message signature header required')
    keys_count, offset = short(raw, offset)
    require(count <= keys_count <= 64 and readonly_unsigned <= keys_count-count
            and offset+keys_count*32+32 <= len(raw), 'complete legacy account keys required')
    keys = [raw[offset+i*32:offset+(i+1)*32] for i in range(keys_count)]
    require(len(set(keys)) == keys_count, 'unique signed message keys required')
    offset += keys_count*32+32
    for key, sig in zip(keys, signatures):
        Ed25519PublicKey.from_public_bytes(key).verify(sig, message)
    require(execute.base.b58(signatures[0]) == signature, 'transaction signature differs')
    ix_count, offset = short(raw, offset)
    require(ix_count == 2, 'exact compute-budget then application instructions required')
    instructions = []
    for _ in range(ix_count):
        require(offset < len(raw), 'missing instruction program index')
        program_index = raw[offset]
        account_count, offset = short(raw, offset+1)
        require(program_index < keys_count and offset+account_count <= len(raw), 'bounded instruction accounts')
        indexes = list(raw[offset:offset+account_count])
        offset += account_count
        size, offset = short(raw, offset)
        require(offset+size <= len(raw) and all(i < keys_count for i in indexes), 'bounded instruction data')
        instructions.append((execute.base.b58(keys[program_index]), indexes, raw[offset:offset+size]))
        offset += size
    require(offset == len(raw) and instructions[0][0] == 'ComputeBudget111111111111111111111111111111',
            'complete compute-budget transaction required')
    actual_program, indexes, actual_data = instructions[1]
    require(actual_program == program and (data is None or actual_data == data)
            and len(indexes) == len(accounts), 'exact signed application instruction required')
    for index, (address, signer, writable) in zip(indexes, accounts):
        is_signer = index < required
        is_writable = index < required-readonly_signed if is_signer else index < keys_count-readonly_unsigned
        require(execute.base.b58(keys[index]) == address and is_signer is signer
                and is_writable is writable, 'signed account order/privilege mismatch')
    return actual_data


def rpc_transaction(rpc, row, program, data, accounts, output, index):
    signature, slot = row['signature'], row['slot']
    require(type(slot) is int and slot > 0, 'positive finalized transaction slot required')
    status = rpc('getSignatureStatuses', [[signature], {'searchTransactionHistory': True}])['value'][0]
    record = rpc('getTransaction', [signature, {'encoding':'base64', 'commitment':'finalized',
                                              'maxSupportedTransactionVersion':0}])
    require(status['confirmationStatus'] == 'finalized' and status['slot'] == slot
            and record['slot'] == slot and status['err'] == record['meta']['err'] == row['rpc_error'],
            'independent finalized RPC status differs')
    raw = base64.b64decode(record['transaction'][0], validate=True)
    signed_transaction(raw, signature, program, data, accounts)
    block_time = rpc('getBlockTime', [slot])
    require(type(block_time) is int and record['blockTime'] == block_time, 'finalized transaction clock differs')
    relative = f'rpc/transaction-{index:03}.bin'
    fd = os.open(Path(output)/relative, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw)
    return {'signature':signature,'slot':slot,'finalized':True,'rpc_error':row['rpc_error'],
            'block_time':block_time,'transaction':{'path':relative,'sha256':hashlib.sha256(raw).hexdigest()}}


def supervise(config, config_pin, report_name, verify, *, staging=False):
    """Direct children only; the external bounded owner supplies full-tree cleanup."""
    root = execute.REPO/'artifacts/dynark/part5'
    output = execute.base.fresh_child(config['output_dir'],root)
    control = execute.base.fresh_child(config['control_output'],root)
    require(output != control, 'distinct private capacity roots required')
    validator = runner = None
    streams, handlers = [], {}
    status = {'schema':1,'scope':'part5-v3-queue-capacity-stage' if staging else config['scope'],
              'status':'failed','config_ref':config_pin,'output_dir':str(output),
              'candidate_verified':False,'external_finalization_required':True,
              'whole_tree_cleanup_authority':'external bounded_runner','error_type':None}
    started = time.monotonic()
    def budget():
        if time.monotonic()-started >= 3500:
            raise TimeoutError('capacity supervisor deadline')
    def interrupted(signum, frame):
        raise InterruptedError('capacity owner interrupted')
    try:
        control.mkdir(mode=0o700)
        output.mkdir(mode=0o700)
        for sig in (signal.SIGINT,signal.SIGTERM):
            handlers[sig] = signal.signal(sig,interrupted)
        for path,digest,cap in [(config['validator'],config['validator_sha256'],128*1024**2),
                                (config['runner'],config['runner_sha256'],128*1024**2),
                                (config['expected_elf'],config['expected_elf_sha256'],4*1024**2)]:
            execute.base.checked(path,digest,cap)
        execute.base.ports_free(timeout_seconds=execute.base.PORT_WAIT_SECONDS)
        argv = execute.stage.resume_argv(config['validator'],config['ledger'])
        command = [config['runner'],'root_pinned_queue_v3_queue_capacity_negative','--exact','--ignored','--test-threads=1']
        execute.base.write_new(control/'invocation.json',{'validator_argv':argv,'runner_argv':command,
            'config_ref':config_pin,'rust_config_ref':{'path':config['rust_config_path'],'sha256':config['rust_config_sha256']}})
        for name in ('validator.out','validator.err','runner.out','runner.err'):
            fd=os.open(control/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            streams.append(os.fdopen(fd,'wb'))
        env={key:value for key,value in os.environ.items() if key not in ('LD_PRELOAD','DYLD_INSERT_LIBRARIES')
             and not key.startswith('P5_V3_QUEUE_CAPACITY_')}
        validator=subprocess.Popen(argv,cwd=execute.REPO,env=env,stdin=subprocess.DEVNULL,
                                   stdout=streams[0],stderr=streams[1])
        local=execute.base.LocalRpc()
        def rpc(method,params):
            budget()
            result=local(method,params)
            budget()
            return result
        elf=execute.base.checked(config['expected_elf'],config['expected_elf_sha256'],4*1024**2)
        loaded=execute.wait_loaded_after_start(rpc,validator,config['expected_program'],elf,config['expected_elf_sha256'])
        require(loaded['genesis']==config['expected_genesis'] and loaded['elf_match'] is True,
                'capacity loaded identity differs')
        prefix='P5_V3_QUEUE_CAPACITY_STAGE' if staging else 'P5_V3_QUEUE_CAPACITY_NEGATIVE'
        env.update({prefix+'_CONFIG':config['rust_config_path'],prefix+'_CONFIG_SHA256':config['rust_config_sha256'],
                    prefix+'_SCOPE':'part5-v3-queue-capacity-stage' if staging else config['scope'],
                    'P5_QUEUE_RPC':execute.base.RPC.rstrip('/'),'P5_QUEUE_PROGRAM':config['expected_program'],
                    'P5_QUEUE_GENESIS':config['expected_genesis'],'P5_QUEUE_ELF':config['expected_elf'],
                    'P5_QUEUE_ELF_SHA256':config['expected_elf_sha256'],'P5_QUEUE_OUTPUT':str(output)})
        runner=subprocess.Popen(command,cwd=execute.REPO,env=env,stdin=subprocess.DEVNULL,
                                stdout=streams[2],stderr=streams[3])
        while runner.poll() is None:
            budget()
            require(validator.poll() is None,'validator exited during capacity owner')
            time.sleep(.1)
        require(runner.wait()==0,'capacity Rust child failed')
        raw,digest=execute.stage.snapshot_generated(output/report_name,1024*1024)
        report=execute.base.decode_json(raw)
        replay=verify(rpc,report,config,output,loaded,runner.pid)
        loaded_after=execute.wait_loaded_after_start(rpc,validator,config['expected_program'],elf,config['expected_elf_sha256'])
        execute.same_loaded(loaded,loaded_after)
        require(execute.stage.snapshot_generated(output/report_name,1024*1024)[1]==digest,
                'capacity runtime report changed during replay')
        status.update(candidate_verified=True,candidate={'path':str(output/report_name),'sha256':digest},
                      loaded_program=loaded,replay=replay)
    except Exception as error:
        status.update(error_type=type(error).__name__,error_message=str(error)[:256])
    finally:
        for sig in handlers:
            signal.signal(sig,signal.SIG_IGN)
        for name,proc in (('runner',runner),('validator',validator)):
            try:
                status[name+'_cleanup']=execute.base.cleanup(proc)
            except Exception as error:
                status[name+'_cleanup']={'spawned':proc is not None,'reaped':False,'error_type':type(error).__name__}
        for stream in streams:
            stream.close()
        status['elapsed_seconds']=time.monotonic()-started
        cleanup=(status['runner_cleanup'].get('reaped') is True
                 and status['runner_cleanup'].get('exit_code')==0
                 and status['validator_cleanup'].get('reaped') is True
                 and status['validator_cleanup'].get('exit_code')==-signal.SIGINT)
        if status['candidate_verified'] and cleanup and status['error_type'] is None and status['elapsed_seconds']<3500:
            status['status']='candidate_verified_pending_external_finalization'
        execute.base.write_new(control/'status.json',status)
        for sig,handler in handlers.items():
            signal.signal(sig,handler)
    return 0 if status['status']=='candidate_verified_pending_external_finalization' else 2
