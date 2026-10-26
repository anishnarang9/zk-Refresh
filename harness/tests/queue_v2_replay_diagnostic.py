#!/usr/bin/env python3
"""Source-reviewed, externally bounded, no-application-transaction replay observation.

The validator itself produces blocks/votes and modifies ONLY a private byte-copy.
No test runner, faucet call, transaction submission, setup, proof, reset, cloning,
or program load is invoked. A completed observation is not a persistence pass.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import time
import urllib.request

spec=importlib.util.spec_from_file_location('queue_supervisor',Path(__file__).with_name('queue_v2_supervisor.py'))
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
COMMITMENTS=('processed','confirmed','finalized')
ALLOWED=frozenset(('getGenesisHash','getSlot','getMultipleAccounts'))

def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def inventory(root):
    """Content inventory; omit only known ephemeral link/socket, never follow links."""
    out={};total=0
    for p in sorted(Path(root).rglob('*')):
        rel=str(p.relative_to(root));m=p.lstat()
        if stat.S_ISLNK(m.st_mode):
            if rel=='validator.log':continue
            raise ValueError('unexpected ledger symlink: '+rel)
        if stat.S_ISSOCK(m.st_mode) and rel=='admin.rpc':continue
        if stat.S_ISDIR(m.st_mode):continue
        if not stat.S_ISREG(m.st_mode):raise ValueError('unexpected ledger special file: '+rel)
        out[rel]={'bytes':m.st_size,'sha256':digest(p)};total+=m.st_size
        if total>40*1024*1024:raise ValueError('ledger copy exceeds reviewed 40MiB admission')
    return out,total

def rpc_item(i,method,params):
    if method not in ALLOWED:raise ValueError('nonobservational RPC forbidden')
    return {'jsonrpc':'2.0','id':i,'method':method,'params':params}

def batch(opener,items,timeout):
    req=urllib.request.Request(s.RPC,data=json.dumps(items).encode(),headers={'Content-Type':'application/json'})
    with opener.open(req,timeout=timeout) as r:b=r.read(131073)
    if len(b)>131072:raise ValueError('RPC response exceeds128KiB')
    values=json.loads(b)
    if not isinstance(values,list)or len(values)!=len(items):raise ValueError('RPC batch shape')
    ids={v['id']:v for v in values}
    if set(ids)!={i['id']for i in items}:raise ValueError('RPC response IDs')
    return ids

def account_record(value,target):
    if value is None:return {'present':False}
    data=value['data']
    if not isinstance(data,list)or len(data)!=2 or data[1]!='base64':raise ValueError('unexpected account encoding')
    b=base64.b64decode(data[0],validate=True)
    if len(b)>4096:raise ValueError('account data cap')
    h=hashlib.sha256(b).hexdigest()
    return {'present':True,'owner':value['owner'],'executable':value['executable'],'lamports':value['lamports'],
            'length':len(b),'sha256':h,'matches_expected':value['owner']==target['owner'] and value['executable'] is False and len(b)==target['length'] and h==target['sha256']}

def run(c,config_sha):
    os.umask(0o077)
    if c['schema']!=1 or c['poll_seconds']!=20:raise ValueError('diagnostic contract')
    control=s.under(c['control_output'],s.BASE)
    if control.exists():raise ValueError('fresh control required')
    control.mkdir(mode=0o700)
    source=s.under(c['source_ledger'],s.BASE)
    if source.is_symlink()or not source.is_dir():raise ValueError('source ledger absent')
    proc=None;logs=[];before=None;started=time.monotonic();old={}
    report={'schema':1,'status':'failed','config_sha256':config_sha,'application_transactions_submitted':0,
            'rpc_methods':sorted(ALLOWED),'scope':'copied-ledger replay observation; no upstream status claim',
            'persistence_verdict':'unmeasured','first_seen':{}}
    def interrupted(sig,frame):raise InterruptedError('signal '+str(sig))
    for sig in (signal.SIGINT,signal.SIGTERM):old[sig]=signal.signal(sig,interrupted)
    try:
        s.checked(c['supervisor'],c['supervisor_sha256'],1024*1024)
        if Path(c['supervisor']).resolve()!=Path(s.__file__).resolve():raise ValueError('imported supervisor mismatch')
        s.checked(c['validator'],c['validator_sha256'],128*1024*1024)
        s.checked(c['elf'],c['elf_sha256'],4*1024*1024)
        s.checked(c['plan'],c['plan_sha256'],65536)
        s.checked(source/'genesis.bin',c['genesis_bin_sha256'],16*1024*1024)
        # Stop/port check and double content inventory detect source changes. ROOT
        # must separately attest the source validator is stopped before launch.
        s.ports_free()
        before,total=inventory(source)
        if before!=c['ledger_files']:raise ValueError('source ledger inventory changed')
        s.write_new(control/'source-before.json',before)
        ledger=control/'ledger';ledger.mkdir(mode=0o700)
        for rel,record in before.items():
            src=source/rel;dst=ledger/rel;dst.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            shutil.copyfile(src,dst,follow_symlinks=False);dst.chmod(0o600)
            if src.stat().st_ino==dst.stat().st_ino and src.stat().st_dev==dst.stat().st_dev:raise ValueError('copy aliases source')
            if digest(dst)!=record['sha256']:raise ValueError('copied ledger content mismatch')
        copied,copied_bytes=inventory(ledger)
        if copied!=before or inventory(source)[0]!=before:raise ValueError('copy/source changed')
        report.update({'copied_bytes':copied_bytes,'source_regular_bytes':total,'source_ledger':str(source),'copy_ledger':str(ledger)})
        argv=s.validator_argv(c['validator'],ledger,c['elf'],'execute')
        s.write_new(control/'invocation.json',{'argv':argv,'no_runner':True,'no_reset':True,'no_program_reload':True})
        stdout=(control/'validator.stdout.log').open('xb');stderr=(control/'validator.stderr.log').open('xb');logs=[stdout,stderr]
        proc=subprocess.Popen(argv,cwd=s.REPO,env=s.child_env(),stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=False)
        poll_start=time.monotonic();end=poll_start+20
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),s.NoRedirect())
        names=('config','issuer','request','queue');keys=[c['accounts'][name]['address']for name in names]
        with (control/'samples.jsonl').open('x')as stream:
            while time.monotonic()<end:
                sample={'elapsed_seconds':time.monotonic()-poll_start}
                if proc.poll()is not None:raise RuntimeError('validator exited during observation')
                items=[rpc_item(0,'getGenesisHash',[])]
                for i,commit in enumerate(COMMITMENTS):
                    items.extend([rpc_item(1+i,'getSlot',[{'commitment':commit}]),rpc_item(4+i,'getMultipleAccounts',[keys,{'encoding':'base64','commitment':commit}])])
                try:
                    values=batch(opener,items,max(.01,min(1,end-time.monotonic())))
                    sample['rpc']={str(k):v for k,v in values.items()if k<4 or 'error'in v}
                    genesis=values[0].get('result')
                    if genesis is not None and genesis!=c['expected_genesis']:raise ValueError('genesis mismatch')
                    if genesis is not None:report['first_seen'].setdefault('genesis',{'elapsed_seconds':sample['elapsed_seconds'],'value':genesis})
                    sample['accounts']={}
                    for i,commit in enumerate(COMMITMENTS):
                        slot=values[1+i].get('result')
                        if isinstance(slot,int):report['first_seen'].setdefault('slot/'+commit,{'elapsed_seconds':sample['elapsed_seconds'],'slot':slot})
                        result=values[4+i].get('result')
                        if result is None:continue
                        vals=result['value']
                        if len(vals)!=4:raise ValueError('account cardinality')
                        sample['accounts'][commit]={'context_slot':result['context']['slot'],'values':{}}
                        for name,v in zip(names,vals):
                            r=account_record(v,c['accounts'][name]);sample['accounts'][commit]['values'][name]=r
                            if r['present']:report['first_seen'].setdefault(commit+'/'+name,{'elapsed_seconds':sample['elapsed_seconds'],'context_slot':result['context']['slot'],**r})
                except (OSError,TimeoutError)as e:sample['transport_error']=type(e).__name__
                stream.write(json.dumps(sample)+'\n');stream.flush()
                # Report hashes/metadata only, not raw account bytes.
                if time.monotonic()<end:time.sleep(min(.25,end-time.monotonic()))
        report['status']='observed';report['persistence_verdict']='review samples and exact hashes at each commitment'
    except Exception as e:report.update({'error_type':type(e).__name__,'error':str(e)})
    finally:
        for sig in old:signal.signal(sig,signal.SIG_IGN)
        try:report['cleanup']=s.cleanup(proc,validator=True)
        except Exception as e:report['cleanup']={'reaped':False,'error':type(e).__name__};report['status']='failed'
        try:
            after,_=inventory(source);s.write_new(control/'source-after.json',after)
            report['source_unchanged']=before is not None and before==after
            if not report['source_unchanged']:report['status']='failed'
        except Exception as e:report['source_check_error']=type(e).__name__;report['status']='failed'
        report['elapsed_seconds']=time.monotonic()-started
        report['whole_tree_cleanup_authority']='external bounded_runner'
        for log in logs:log.close()
        s.write_new(control/'status.json',report)
        for sig,handler in old.items():signal.signal(sig,handler)
    print(json.dumps({'status':report['status'],'report':str(control/'status.json')}))
    return 0 if report['status']=='observed'and report['cleanup'].get('reaped')else 1

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',required=True);p.add_argument('--config-sha256',required=True);args=p.parse_args()
    c=json.loads(s.checked(args.config,args.config_sha256,65536));return run(c,args.config_sha256)
if __name__=='__main__':sys.exit(main())
