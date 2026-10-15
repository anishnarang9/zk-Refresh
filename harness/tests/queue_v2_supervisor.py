#!/usr/bin/env python3
"""ROOT-pinned local queue launcher; external bounded_runner owns whole-tree limits.

This launcher never grants itself execution. Invoke only inside ROOT's reviewed
bounded job. No shell, daemonization, session escape, external cluster, setup or
proof job occurs here. Build, prepare and execute are separate invocations.
"""
import argparse
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
                if prepared.get('passed')is not True or not isinstance(prepared.get('finalized_slot'),int):raise ValueError('finalized preparation evidence missing')
            argv=validator_argv(config['validator'],ledger,config['elf'],phase)
            ports_free()
            for n in ['validator.stdout.log','validator.stderr.log','runner.stdout.log','runner.stderr.log']:logs.append((control/n).open('xb'))
            validator=subprocess.Popen(argv,cwd=REPO,env=child_env(),stdin=subprocess.DEVNULL,stdout=logs[0],stderr=logs[1],start_new_session=False)
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
            deadline=time.monotonic()+20;genesis=None
            while time.monotonic()<deadline:
                if validator.poll()is not None:raise RuntimeError('validator exited before readiness')
                try:genesis=rpc_genesis(opener);break
                except (OSError,ValueError):time.sleep(0.1)
            if genesis is None:raise TimeoutError('validator readiness deadline')
            if phase=='execute'and genesis!=config['expected_genesis']:raise ValueError('restarted genesis mismatch')
            if phase=='prepare':write_new(runtime/'runtime-domain.json',{'program':PROGRAM,'genesis':genesis,'elf_sha256':config['elf_sha256'],'context_sha256':config['context_sha256']})
            e=child_env();e.update({'P5_QUEUE_SCOPE':'part5-v2-queue-local-'+phase,'P5_QUEUE_RPC':RPC,'P5_QUEUE_PROGRAM':PROGRAM,'P5_QUEUE_GENESIS':genesis,'P5_QUEUE_ELF':config['elf'],'P5_QUEUE_ELF_SHA256':config['elf_sha256'],'P5_QUEUE_OUTPUT':str(private),'P5_QUEUE_CONTEXT':config['context'],'P5_QUEUE_CONTEXT_SHA256':config['context_sha256']})
            if phase=='execute':e.update({'P5_QUEUE_PLAN_SHA256':config['plan_sha256'],'P5_QUEUE_FULL_WIRE':config['full_wire'],'P5_QUEUE_FULL_WIRE_SHA256':config['full_wire_sha256']})
            runner_argv=[config['runner'],'root_pinned_queue_v2_'+phase,'--exact','--ignored','--test-threads=1']
            write_new(control/'invocation.json',{'validator_argv':argv,'runner_argv':runner_argv,'genesis':genesis,'elf_sha256':config['elf_sha256'],'runner_sha256':config['runner_sha256'],'outer_limits_required':{'runtime_seconds':180,'rss_bytes':4294967296,'storage_growth_bytes':268435456}})
            runner=subprocess.Popen(runner_argv,cwd=REPO,env=e,stdin=subprocess.DEVNULL,stdout=logs[2],stderr=logs[3],start_new_session=False)
            deadline=time.monotonic()+120
            while runner.poll()is None:
                if validator.poll()is not None:raise RuntimeError('validator exited during application test')
                if time.monotonic()>deadline:raise TimeoutError('application runner deadline')
                time.sleep(0.1)
            if runner.wait()!=0:raise RuntimeError('application runner failed')
            report_name='prepare-report.json'if phase=='prepare'else 'execute-report.json'
            reconciled=phase=='execute'and (private/'reconciled-report.json').exists()
            if reconciled:report_name='reconciled-report.json'
            report=read_small(private/report_name,1024*1024)
            if report.get('passed')is not True or not isinstance(report.get('finalized_slot'),int)or report.get('loaded_program',{}).get('elf_match')is not True:raise ValueError('successful finalized loaded-ELF evidence missing')
            if phase=='execute':
                if report.get('effect_count')!=1:raise ValueError('exact effect evidence missing')
                if reconciled:
                    if report.get('new_execute_transactions')!=0:raise ValueError('reconciliation sent a new Execute')
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
