#!/usr/bin/env python3
"""ROOT-pinned local queue launcher; external bounded_runner owns whole-tree limits.

This launcher never grants itself execution. Invoke only inside ROOT's reviewed
bounded job. No shell, daemonization, session escape, external cluster, setup or
proof job occurs here. Build, prepare and execute are separate invocations.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import urllib.request

REPO=Path('/Users/anishnarang/Zk-refresh')
BASE=REPO/'artifacts/dynark/part5'
PROGRAM='FPixV9CAxXGFiHH6udUhyTPUzposTYEf1uxmQxYc8xha'
MINT='FTeFdSfBYpZUrNXcLvodGLAFEz258bvUaKdRULbCtJ2H'
RPC='http://127.0.0.1:18999'
LEGACY_ELF=REPO/'program/target/deploy/zk_fresh_program.so'
LEGACY_ELF_SHA='12185308051b933f65dc2ff5a8c25a097ac7968385be31523327f4d196667c20'
BUILD_SOURCES=['program/Cargo.toml','program/Cargo.lock','program/src/lib.rs',
               'program/src/application_v2.rs','program/src/application_runtime_v2.rs',
               'program/src/generated_vk.rs','program/src/generated_vk_v2.rs']
RUNTIME_SOURCES=['harness/Cargo.toml','harness/Cargo.lock','harness/src/solana.rs','harness/tests/queue_v2.rs']

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args):raise ValueError('RPC redirects forbidden')


def under(path,base):
    path,base=Path(path),Path(base)
    if not path.is_absolute() or not base.is_absolute() or path==base or not path.is_relative_to(base):
        raise ValueError('protected child path required')
    if not path.resolve().is_relative_to(base.resolve()):raise ValueError('symlink escape')
    current=path
    while current!=base:
        if current.is_symlink():raise ValueError('symlink in protected path')
        current=current.parent
    return path


def check_ledger(phase,ledger):
    ledger=Path(ledger)
    if phase=='prepare':
        if ledger.exists() or ledger.is_symlink():raise ValueError('initial ledger must be absent')
    elif phase=='execute':
        if ledger.is_symlink() or not ledger.is_dir() or not (ledger/'genesis.bin').is_file():
            raise ValueError('persistent ledger genesis missing')
    else:raise ValueError('unknown validator phase')


def validator_argv(validator,ledger,elf,phase):
    check_ledger(phase,ledger)
    a=[str(validator),'--ledger',str(ledger),'--bind-address','127.0.0.1',
       '--rpc-port','18999','--gossip-port','18901','--faucet-port','19001',
       '--dynamic-port-range','19002-19028','--limit-ledger-size','10000','--quiet']
    if phase=='prepare':a+=['--reset','--mint',MINT,'--bpf-program',PROGRAM,str(elf)]
    return a


def build_argv(builder,out):
    return [str(builder),'--offline','--skip-tools-install','--tools-version','v1.54',
            '--arch','v0','--manifest-path',str(REPO/'program/Cargo.toml'),
            '--sbf-out-dir',str(out),'-j','1','--','--locked']


def checked(path,expected,cap):
    path=Path(path)
    if not path.is_absolute() or len(expected)!=64 or any(c not in '0123456789abcdef' for c in expected):
        raise ValueError('absolute artifact and canonical SHA256 required')
    before=path.lstat()
    if path.is_symlink() or not path.is_file() or before.st_size>cap:raise ValueError('artifact type/size')
    with path.open('rb') as f:
        after=os.fstat(f.fileno())
        if (before.st_dev,before.st_ino,before.st_size)!=(after.st_dev,after.st_ino,after.st_size):
            raise ValueError('artifact changed at open')
        b=f.read(cap+1)
    if len(b)!=before.st_size or hashlib.sha256(b).hexdigest()!=expected:raise ValueError('artifact pin mismatch: '+str(path))
    return b


def write_new(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w')as f:
        json.dump(value,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())


def read_small(path,cap=65536):
    p=Path(path);m=p.lstat()
    if p.is_symlink()or not p.is_file()or m.st_size>cap:raise ValueError('bounded regular JSON required')
    return json.loads(p.read_bytes())


def ports_free():
    held=[]
    try:
        for port in [18999,19000,19001,18901]+list(range(19002,19029)):
            for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
                s=socket.socket(socket.AF_INET,kind);held.append(s);s.bind(('127.0.0.1',port))
    finally:
        for s in held:s.close()


def rpc_genesis(opener):
    req=urllib.request.Request(RPC,data=b'{"jsonrpc":"2.0","id":1,"method":"getGenesisHash","params":[]}',headers={'Content-Type':'application/json'})
    with opener.open(req,timeout=1)as response:b=response.read(65537)
    if len(b)>65536:raise ValueError('readiness response cap')
    v=json.loads(b);g=v.get('result')
    if 'error'in v or not isinstance(g,str)or not 32<=len(g)<=44 or any(c not in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'for c in g):raise ValueError('invalid genesis')
    return g


def b58(raw):
    alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    number=int.from_bytes(raw,'big');encoded=''
    while number:number,index=divmod(number,58);encoded=alphabet[index]+encoded
    return '1'*(len(raw)-len(raw.lstrip(b'\0')))+encoded


def execute_expected_states(config,private):
    """Reconstruct frozen enrollment from pinned plan/profile; pin before/effect bytes."""
    p=json.loads(checked(private/'plan.json',config['plan_sha256'],16384))
    def key(name):
        value=p[name]
        if not isinstance(value,list)or len(value)!=32 or any(type(x)is not int or not 0<=x<=255 for x in value):raise ValueError('plan key shape')
        return bytes(value)
    fields=p['expected_inputs']
    if len(fields)!=5 or any(len(x)!=32 for x in fields):raise ValueError('plan public shape')
    root,issuer_hash=bytes(fields[0]),bytes(fields[1])
    circuit=bytes.fromhex('da0ad2e5e92f3879951ac3e56e077967eb5fcf6a9814839d680037d620ae9146')
    package=bytes.fromhex('04d5ad5776bea03ee014790f54c2572adde796f4d8caeacb88f8a54b0e98b6eb')
    schema=bytes.fromhex('de111be59b7a21f5e9aa757506a9ec679d892d6342c88729b6b7997c8b472611')
    profile=bytes.fromhex('eb77028b2bd1e324c6ee74c40b43739ec2ce519014f6d04aebe2ca7f82aa1f68')
    cb=b'DYNCONF2'+key('admin')+key('seed')+key('publisher')+key('genesis')+key('policy_id')+(1).to_bytes(4,'big')+circuit+package+schema+root+bytes(8)+b'\x01'
    ib=b'DYNIS2B1'+key('config')+issuer_hash+profile+(2).to_bytes(4,'big')+bytes(range(0xa0,0xb4))+bytes(12)+key('source')+b'\x01'+bytes(136)
    review=config['review_assertions']
    request=checked(private/'request-before.bin',review['request_before_sha256'],2249)
    queue=checked(private/'queue-before.bin',review['queue_before_sha256'],2090)
    if len(request)!=2249 or len(queue)!=2090 or request[183]!=1:raise ValueError('frozen finalized state shape')
    if request[:40]!=b'DYNREQ02'+key('config')or queue!=b'DYNQUE02'+key('config')+bytes(2050):raise ValueError('frozen state config/queue')
    consumed=bytearray(request);consumed[183]=2
    completed=bytearray(queue);completed[40:42]=(1).to_bytes(2,'big');completed[42:74]=key('request')
    if hashlib.sha256(consumed).hexdigest()!=review['expected_consumed_request_sha256']or hashlib.sha256(completed).hexdigest()!=review['expected_one_entry_queue_sha256']:raise ValueError('reviewed effect pin mismatch')
    if b58(key('program'))!=PROGRAM:raise ValueError('plan program mismatch')
    def account(data):return {'owner':PROGRAM,'executable':False,'data':bytes(data)}
    before={n:account(b)for n,b in [('config',cb),('issuer',ib),('request',request),('queue',queue)]}
    after={**before,'request':account(consumed),'queue':account(completed)}
    return {'before':before,'consumed':after,'context_digest':bytes.fromhex(config['context_sha256']),
            'addresses':[b58(key(n))for n in ('config','issuer_account','request','queue')]}


def issuer_bound_to_context(actual,prepared,config,context_digest):
    """Exact single synthetic observation + publisher binding; not upstream freshness."""
    if len(actual)!=309 or len(prepared)!=309 or len(config)!=309 or len(context_digest)!=32:return False
    if actual[:173]!=prepared[:173]or actual[172]!=1:return False
    prior=int.from_bytes(prepared[173:181],'big');sequence=int.from_bytes(actual[173:181],'big')
    observed=int.from_bytes(actual[213:221],'big',signed=True);expires=int.from_bytes(actual[221:229],'big',signed=True)
    if prior==(1<<64)-1 or sequence!=prior+1 or observed<0 or expires!=observed+300:return False
    digest=hashlib.sha256(b'part5-synthetic-signed-source-observation'+config[268:300]+prepared[40:72]+context_digest+actual[213:221]+prepared[173:181]).digest()
    return actual[181:213]==digest and actual[229:261]==config[268:300] and actual[261:269]==config[300:308] and actual[269:277]==actual[173:181] and actual[277:309]==digest


def execute_snapshot_ready(genesis,expected_genesis,minimum_slot,snapshots,expected_states):
    if genesis!=expected_genesis or type(minimum_slot)is not int or minimum_slot<0:return None
    for commitment in ('confirmed','finalized'):
        snapshot=snapshots.get(commitment,{})
        slot=snapshot.get('context_slot')
        if type(slot)is not int or slot<minimum_slot:return None
        accounts=snapshot.get('accounts',{})
        if set(accounts)!={'config','issuer','request','queue'}:return None
        for name,actual in accounts.items():
            expected=expected_states['before'][name]
            if not isinstance(actual,dict)or actual.get('owner')!=expected['owner']or actual.get('executable')is not False or not isinstance(actual.get('data'),bytes)or len(actual['data'])!=len(expected['data']):return None
    confirmed=snapshots['confirmed']['accounts'];finalized=snapshots['finalized']['accounts']
    # Comparing all four full byte arrays prevents mixed commitment snapshots.
    if confirmed!=finalized:return None
    if confirmed==expected_states['before']:return 'before'
    expected=expected_states['consumed']
    if any(confirmed[n]!=expected[n]for n in ('config','request','queue')):return None
    if not issuer_bound_to_context(confirmed['issuer']['data'],expected_states['before']['issuer']['data'],expected['config']['data'],expected_states['context_digest']):return None
    return 'consumed'


def require_consumed_readiness(config,mode):
    required=config.get('reconciliation_only',False)
    if type(required)is not bool:raise ValueError('reconciliation_only must be boolean')
    if required and mode!='consumed':raise ValueError('consumed-only restart cannot launch before/mixed state')


def select_runner_report(config,phase,private):
    reconciled=phase=='execute'and (private/'reconciled-report.json').exists()
    if config.get('reconciliation_only')is True:
        if not reconciled:raise ValueError('consumed-only runner did not create fresh reconciliation report')
        return 'reconciled-report.json',True
    return ('reconciled-report.json'if reconciled else 'prepare-report.json'if phase=='prepare'else 'execute-report.json'),reconciled


def validate_reconciled_report(report,config):
    review=config['review_assertions']
    if report.get('passed')is not True or type(report.get('finalized_slot'))is not int or report['finalized_slot']<0 or report.get('loaded_program',{}).get('elf_match')is not True:raise ValueError('exact finalized reconciliation evidence missing')
    if type(report.get('new_execute_transactions'))is not int or report['new_execute_transactions']!=0 or report.get('effect_count')!=1:raise ValueError('reconciliation must contain one effect and zero new Execute')
    if report.get('request_sha256')!=review['expected_consumed_request_sha256']or report.get('queue_sha256')!=review['expected_one_entry_queue_sha256']:raise ValueError('exact finalized reconciliation hashes missing/mismatched')


def execute_readiness(opener,expected_genesis,minimum_slot,expected_states,deadline,validator):
    """No runner exists until both commitments contain one exact admissible state."""
    attempts=0
    while time.monotonic()<deadline:
        if validator.poll()is not None:raise RuntimeError('validator exited before account readiness')
        attempts+=1
        items=[{'jsonrpc':'2.0','id':0,'method':'getGenesisHash','params':[]}]
        for i,commitment in enumerate(('confirmed','finalized'),1):
            items.append({'jsonrpc':'2.0','id':i,'method':'getMultipleAccounts','params':[expected_states['addresses'],{'encoding':'base64','commitment':commitment}]})
        req=urllib.request.Request(RPC,data=json.dumps(items).encode(),headers={'Content-Type':'application/json'})
        try:
            with opener.open(req,timeout=max(.01,min(1,deadline-time.monotonic())))as response:b=response.read(65537)
            if len(b)>65536:raise ValueError('account readiness response cap')
            values=json.loads(b)
            if not isinstance(values,list)or len(values)!=3:raise ValueError('readiness batch cardinality')
            by_id={v['id']:v for v in values}
            if set(by_id)!={0,1,2}:raise ValueError('readiness response IDs')
            genesis=by_id[0].get('result')
            if genesis is not None and genesis!=expected_genesis:raise ValueError('restarted genesis mismatch')
            snapshots={}
            for i,commitment in enumerate(('confirmed','finalized'),1):
                result=by_id[i].get('result')
                if not isinstance(result,dict)or not isinstance(result.get('value'),list)or len(result['value'])!=4:continue
                accounts={}
                for name,value in zip(('config','issuer','request','queue'),result['value']):
                    if value is None:accounts[name]=None;continue
                    encoding=value['data']
                    if not isinstance(encoding,list)or len(encoding)!=2 or encoding[1]!='base64':raise ValueError('readiness account encoding')
                    data=base64.b64decode(encoding[0],validate=True)
                    accounts[name]={'owner':value['owner'],'executable':value['executable'],'data':data}
                snapshots[commitment]={'context_slot':result['context']['slot'],'accounts':accounts}
            mode=execute_snapshot_ready(genesis,expected_genesis,minimum_slot,snapshots,expected_states)
            if mode is not None:
                evidence={'mode':mode,'attempts':attempts,'minimum_slot':minimum_slot,'genesis':genesis,'commitments':{}}
                for commitment,snapshot in snapshots.items():
                    evidence['commitments'][commitment]={'context_slot':snapshot['context_slot'],'accounts':{name:{'owner':v['owner'],'executable':v['executable'],'length':len(v['data']),'sha256':hashlib.sha256(v['data']).hexdigest()}for name,v in snapshot['accounts'].items()}}
                return genesis,mode,evidence
        except (OSError,TimeoutError):pass
        if time.monotonic()<deadline:time.sleep(min(.1,deadline-time.monotonic()))
    raise TimeoutError('confirmed/finalized exact account readiness deadline')


def cleanup(proc,validator=False):
    if proc is None:return {'spawned':False,'reaped':True}
    graceful=not (validator and proc.poll()is not None)
    if proc.poll()is None:
        proc.send_signal(signal.SIGINT if validator else signal.SIGTERM)
        try:proc.wait(timeout=5 if validator else 3)
        except subprocess.TimeoutExpired:
            graceful=False;proc.terminate()
            try:proc.wait(timeout=2)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=2)
    else:proc.wait()
    return {'spawned':True,'reaped':proc.poll()is not None,'graceful':graceful,'exit_code':proc.returncode}


def child_env():
    e=os.environ.copy();e.update({'CARGO_BUILD_JOBS':'1','RAYON_NUM_THREADS':'4','OMP_NUM_THREADS':'1'})
    # Do not let inherited target/output overrides rewrite legacy deployment output.
    for k in ['LD_PRELOAD','DYLD_INSERT_LIBRARIES','CARGO_TARGET_DIR','SBF_OUT_PATH','SBF_SDK_PATH','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER']:
        e.pop(k,None)
    return e


def source_pins(config,phase):
    required=BUILD_SOURCES if phase=='build'else RUNTIME_SOURCES
    pins=config['source_pins']
    if phase=='build':
        # Current lib.rs closure is the five pinned src files, with no includes,
        # alternate #[path] modules, or local build script. Fail on new inputs.
        actual={str(p.relative_to(REPO))for p in (REPO/'program/src').rglob('*.rs')}
        declared={p for p in BUILD_SOURCES if p.startswith('program/src/')}
        if actual!=declared:raise ValueError('program/src closure changed; review all module pins')
        if (REPO/'program/build.rs').exists():raise ValueError('new local build script requires explicit pin review')
        for p in actual:
            text=(REPO/p).read_text()
            if 'include!' in text or 'include_bytes!' in text or 'include_str!' in text or '#[path' in text:raise ValueError('external module/include requires source closure review')
    for p in required:
        if p not in pins:raise ValueError('missing source pin: '+p)
    for relative,digest in pins.items():
        p=REPO/relative
        if p.resolve()!=p or not p.is_relative_to(REPO):raise ValueError('source path escape')
        checked(p,digest,1024*1024)


def stack_diagnostic(stdout,stderr):
    for text in (stdout,stderr):
        text=text.lower()
        if 'stack offset' in text or ('stack frame size' in text and 'exceed' in text):return True
    return False


def run(config,config_sha):
    phase=config['phase']
    if phase not in ('build','prepare','execute'):raise ValueError('unknown phase')
    if config['schema']!=1 or config.get('program',PROGRAM)!=PROGRAM:raise ValueError('launcher contract version/program')
    if type(config.get('reconciliation_only',False))is not bool:raise ValueError('reconciliation_only must be boolean')
    if config.get('reconciliation_only')is True and phase!='execute':raise ValueError('reconciliation-only requires execute phase')
    control=under(config['control_output'],BASE)
    if control.exists():raise ValueError('fresh control output required')
    control.mkdir(mode=0o700)
    os.umask(0o077)
    status={'schema':1,'phase':phase,'status':'failed','config_sha256':config_sha,'scope':'local application development only','devnet':False}
    validator=runner=None;logs=[];started=time.monotonic();runtime=None
    old={}
    def interrupted(sig,frame):raise InterruptedError('signal '+str(sig))
    for sig in (signal.SIGINT,signal.SIGTERM):old[sig]=signal.signal(sig,interrupted)
    try:
        source_pins(config,phase)
        checked(LEGACY_ELF,LEGACY_ELF_SHA,4*1024*1024)
        if phase=='build':
            builder=config['builder'];checked(builder,config['builder_sha256'],128*1024*1024)
            out=under(config['build_output'],BASE)
            if out.exists():raise ValueError('fresh versioned SBF output required')
            out.mkdir(mode=0o700)
            argv=build_argv(builder,out/'elf')
            stdout=(control/'build.stdout.log').open('xb');stderr=(control/'build.stderr.log').open('xb');logs.extend([stdout,stderr])
            write_new(control/'invocation.json',{'argv':argv,'source_pins':config['source_pins'],'outer_limits_required':{'runtime_seconds':180,'rss_bytes':4294967296,'storage_growth_bytes':536870912}})
            runner=subprocess.Popen(argv,cwd=REPO,env=child_env(),stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=False)
            code=runner.wait(timeout=165)
            if code!=0:raise RuntimeError('SBF build failed')
            elf=out/'elf/zk_fresh_program.so';b=elf.read_bytes()
            if len(b)>4*1024*1024 or not b.startswith(b'\x7fELF'):raise ValueError('unexpected application ELF')
            # A compiler warning about exceeding the default stack is a failed gate.
            stdout.flush();stderr.flush()
            out_log=(control/'build.stdout.log').read_text(errors='replace')
            err_log=(control/'build.stderr.log').read_text(errors='replace')
            if stack_diagnostic(out_log,err_log):raise ValueError('SBF stack limit diagnostic requires review')
            checked(LEGACY_ELF,LEGACY_ELF_SHA,4*1024*1024)
            status.update({'status':'passed','elf':str(elf),'elf_bytes':len(b),'elf_sha256':hashlib.sha256(b).hexdigest(),'source_pins':config['source_pins']})
        else:
            checked(config['validator'],config['validator_sha256'],128*1024*1024)
            checked(config['runner'],config['runner_sha256'],128*1024*1024)
            checked(config['elf'],config['elf_sha256'],4*1024*1024)
            checked(config['context'],config['context_sha256'],16384)
            runtime=under(config['runtime_output'],BASE)
            ledger=runtime/'ledger';private=runtime/'private'
            if phase=='prepare':
                if runtime.exists():raise ValueError('fresh protected runtime root required')
                runtime.mkdir(mode=0o700);private.mkdir(mode=0o700)
            else:
                if runtime.is_symlink()or not runtime.is_dir()or runtime.stat().st_mode&0o777!=0o700:raise ValueError('protected existing runtime root required')
                domain=read_small(runtime/'runtime-domain.json')
                if domain['program']!=PROGRAM or domain['elf_sha256']!=config['elf_sha256']or domain['context_sha256']!=config['context_sha256']or domain['genesis']!=config['expected_genesis']:raise ValueError('persistent runtime domain mismatch')
                checked(private/'plan.json',config['plan_sha256'],16384)
                checked(config['full_wire'],config['full_wire_sha256'],416)
                prepared=read_small(private/'prepare-report.json')
                if prepared.get('passed')is not True or type(prepared.get('finalized_slot'))is not int or prepared['finalized_slot']<0:raise ValueError('finalized preparation evidence missing')
                expected_states=execute_expected_states(config,private)
                if config.get('reconciliation_only')is True:
                    if (private/'reconciled-report.json').exists():raise ValueError('fresh reconciliation report required')
                    history=config.get('historical_evidence_pins',{})
                    if set(history)!={'execute-report.json','transactions.jsonl'}:raise ValueError('frozen historical evidence pins required')
                    for name,digest in history.items():checked(private/name,digest,1024*1024)

            argv=validator_argv(config['validator'],ledger,config['elf'],phase)
            ports_free()
            for n in ['validator.stdout.log','validator.stderr.log','runner.stdout.log','runner.stderr.log']:logs.append((control/n).open('xb'))
            validator=subprocess.Popen(argv,cwd=REPO,env=child_env(),stdin=subprocess.DEVNULL,stdout=logs[0],stderr=logs[1],start_new_session=False)
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
            deadline=time.monotonic()+20;genesis=None;readiness_mode=None
            if phase=='execute':
                genesis,readiness_mode,evidence=execute_readiness(opener,config['expected_genesis'],prepared['finalized_slot'],expected_states,deadline,validator)
                require_consumed_readiness(config,readiness_mode)
                write_new(control/'account-readiness.json',evidence)
            else:
                while time.monotonic()<deadline:
                    if validator.poll()is not None:raise RuntimeError('validator exited before readiness')
                    try:genesis=rpc_genesis(opener);break
                    except (OSError,ValueError):time.sleep(0.1)
                if genesis is None:raise TimeoutError('validator readiness deadline')
            if phase=='prepare':write_new(runtime/'runtime-domain.json',{'program':PROGRAM,'genesis':genesis,'elf_sha256':config['elf_sha256'],'context_sha256':config['context_sha256']})
            e=child_env();e.update({'P5_QUEUE_SCOPE':'part5-v2-queue-local-'+phase,'P5_QUEUE_RPC':RPC,'P5_QUEUE_PROGRAM':PROGRAM,'P5_QUEUE_GENESIS':genesis,'P5_QUEUE_ELF':config['elf'],'P5_QUEUE_ELF_SHA256':config['elf_sha256'],'P5_QUEUE_OUTPUT':str(private),'P5_QUEUE_CONTEXT':config['context'],'P5_QUEUE_CONTEXT_SHA256':config['context_sha256']})
            if phase=='execute':e.update({'P5_QUEUE_RECONCILE_ONLY':'1'if readiness_mode=='consumed'else '0','P5_QUEUE_PLAN_SHA256':config['plan_sha256'],'P5_QUEUE_FULL_WIRE':config['full_wire'],'P5_QUEUE_FULL_WIRE_SHA256':config['full_wire_sha256']})
            runner_argv=[config['runner'],'root_pinned_queue_v2_'+phase,'--exact','--ignored','--test-threads=1']
            write_new(control/'invocation.json',{'validator_argv':argv,'runner_argv':runner_argv,'genesis':genesis,'elf_sha256':config['elf_sha256'],'runner_sha256':config['runner_sha256'],'outer_limits_required':{'runtime_seconds':180,'rss_bytes':4294967296,'storage_growth_bytes':268435456}})
            runner=subprocess.Popen(runner_argv,cwd=REPO,env=e,stdin=subprocess.DEVNULL,stdout=logs[2],stderr=logs[3],start_new_session=False)
            deadline=time.monotonic()+120
            while runner.poll()is None:
                if validator.poll()is not None:raise RuntimeError('validator exited during application test')
                if time.monotonic()>deadline:raise TimeoutError('application runner deadline')
                time.sleep(0.1)
            if runner.wait()!=0:raise RuntimeError('application runner failed')
            report_name,reconciled=select_runner_report(config,phase,private)
            report=read_small(private/report_name,1024*1024)
            if report.get('passed')is not True or not isinstance(report.get('finalized_slot'),int)or report.get('loaded_program',{}).get('elf_match')is not True:raise ValueError('successful finalized loaded-ELF evidence missing')
            if phase=='execute':
                if report.get('effect_count')!=1:raise ValueError('exact effect evidence missing')
                if reconciled:
                    if report.get('new_execute_transactions')!=0:raise ValueError('reconciliation sent a new Execute')
                    if config.get('reconciliation_only')is True:
                        validate_reconciled_report(report,config)
                        for name,digest in config['historical_evidence_pins'].items():checked(private/name,digest,1024*1024)

                elif report.get('publisher_binding_current')is not True or report.get('upstream_issuer_check')is not False:raise ValueError('binding/synthetic-source evidence missing')
            status.update({'status':'passed','program':PROGRAM,'genesis':genesis,'elf_sha256':config['elf_sha256'],'runner_report':str(private/report_name),'finalized_slot':report['finalized_slot']})
    except Exception as error:
        status.update({'error_type':type(error).__name__,'error':str(error)})
    finally:
        for sig in old:signal.signal(sig,signal.SIG_IGN)
        status['cleanup']={}
        for name,proc in [('runner',runner),('validator',validator)]:
            try:status['cleanup'][name]=cleanup(proc,validator=name=='validator')
            except Exception as error:status['cleanup'][name]={'reaped':False,'error':type(error).__name__};status['status']='failed'
        if validator is not None and status['cleanup'].get('validator',{}).get('graceful')is not True:status['status']='failed';status['ledger_reuse_requires_review']=True
        if status['status']!='passed'and runtime is not None:status['ledger_reuse_requires_review']=True
        status['whole_tree_cleanup_authority']='external bounded_runner; direct child reaping alone is insufficient'
        status['elapsed_seconds']=time.monotonic()-started
        for log in logs:log.close()
        write_new(control/'status.json',status)
        for sig,handler in old.items():signal.signal(sig,handler)
    print(json.dumps({'status':status['status'],'report':str(control/'status.json')}))
    return 0 if status['status']=='passed'else 1


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',required=True);p.add_argument('--config-sha256',required=True);args=p.parse_args()
    config=json.loads(checked(args.config,args.config_sha256,65536))
    return run(config,args.config_sha256)

if __name__=='__main__':sys.exit(main())
