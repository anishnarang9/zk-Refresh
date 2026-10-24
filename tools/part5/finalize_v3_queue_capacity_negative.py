#!/usr/bin/env python3
"""Independently reopen retained capacity facts after the complete owner exits."""
import argparse
import copy
import hashlib
import json
import math
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0,str(REPO))
from harness.tests import queue_v3_local_queue_capacity_negative as supervisor
from harness.tests import queue_v3_capacity_runtime as runtime
from tools.part5 import prepare_v3_queue_capacity_fixture as fixture
from tools.part5 import heldout_queue_capacity_evidence as evidence
from tools.part5.build_v3_campaign_packet import action

SCHEMA='part5-v3-queue-capacity-finalization-v1'
MANIFEST_SCHEMA='part5-v3-queue-capacity-finalizer-input-v1'
RUNTIME_SCHEMA='part5-v3-queue-capacity-negative-rust-report-v1'
CAPACITY_STORAGE_LIMIT_BYTES=17179869184
require=runtime.require


def number(value,integer=False):
    require(type(value) is int if integer else type(value) in (int,float), 'finite numeric measurement required')
    require(math.isfinite(value) and value>=0,'finite nonnegative measurement required')
    return value


def check_monitor(monitor,invocation,config_pin,command_path,config,*,staging=False):
    require(monitor.get('schema')==1 and monitor.get('measurement')=='bounded_complete_session'
            and monitor.get('passed') is True and type(monitor.get('exit_code')) is int and monitor['exit_code']==0
            and monitor.get('censored') is False and monitor.get('stop_reason') is None
            and monitor.get('runner_error_type') is None
            and monitor.get('cleanup_status_unknown') is False
            and type(monitor.get('cleanup_remaining_owned_processes')) is int
            and monitor['cleanup_remaining_owned_processes']==0
            and type(monitor.get('owner')) is str and bool(monitor['owner'])
            and monitor['owner']==invocation.get('owner'), 'successful complete external owner cleanup required')
    argv=invocation.get('argv',[])
    require(len(argv)==6 and argv[1:]==[str(command_path),'--config',config_pin['path'],
                                      '--config-sha256',config_pin['sha256']]
            and Path(argv[0]).is_absolute() and invocation.get('cwd')==str(REPO),
            'external owner must bind exact capacity command/config')
    bounds=monitor.get('limits',{})
    expected_runtime=config.get('proof_owner_limit_seconds',3600) if config.get('phase')=='proofs' else 3600
    require(bounds.get('runtime_seconds')==expected_runtime
            and bounds.get('owned_tree_rss_bytes')==4294967296
            and number(bounds.get('storage_growth_bytes'),True)>0
            and number(bounds.get('poll_seconds'))<=.25, 'exact declared capacity owner limits required')
    if config.get('phase')!='proofs':
        require(bounds['storage_growth_bytes']==CAPACITY_STORAGE_LIMIT_BYTES,'capacity fill/stage storage ceiling differs')
    duration=number(monitor.get('duration_seconds'))
    require(0<duration<=bounds['runtime_seconds'],'owner wall bound exceeded')
    roots=[Path(p) for p in invocation.get('storage_roots',[])]
    require(roots and all(p.is_absolute() and p.resolve()==p for p in roots)
            and all(not(p==q or p in q.parents or q in p.parents) for i,p in enumerate(roots) for q in roots[i+1:]),
            'disjoint canonical measured storage roots required')
    measured=[config['output_dir']]
    if config.get('phase')=='clone': measured += [config['ledger']]
    elif config.get('phase')!='proofs': measured += [config['control_output'],config['ledger']]
    require(all(any(Path(p)==root or root in Path(p).parents for root in roots) for p in measured),
            'owner omitted mutable capacity storage')
    samples=monitor.get('samples')
    require(type(samples) is list and samples and type(monitor.get('sample_count')) is int
            and monitor['sample_count']==len(samples),
            'external resource samples required')
    previous=-1
    for row in samples:
        elapsed=number(row['elapsed_seconds'])
        require(previous<=elapsed<=duration,'external sample chronology differs')
        previous=elapsed
        for key in ('owned_process_count','owned_tree_rss_bytes','storage_growth_bytes'):
            number(row[key],True)
    require(any(row['owned_process_count']>0 for row in samples),'external owner observed no child')
    for name,peak,bound in [('owned_tree_rss_bytes','sampled_peak_owned_tree_rss_bytes','owned_tree_rss_bytes'),
                            ('storage_growth_bytes','sampled_peak_storage_growth_bytes','storage_growth_bytes')]:
        require(number(monitor.get(peak),True)==max(row[name] for row in samples)<=bounds[bound],
                'external sampled peak exceeds declared bound')
    return {'wall_limit_seconds':bounds['runtime_seconds'],'rss_limit_bytes':bounds['owned_tree_rss_bytes'],
            'storage_limit_bytes':bounds['storage_growth_bytes'],'wall_seconds':duration,
            'peak_owned_rss_bytes':monitor['sampled_peak_owned_tree_rss_bytes'],
            'storage_growth_bytes':monitor['sampled_peak_storage_growth_bytes'],'ownership_known':True,
            'cleanup_complete':True,'remaining_owned_processes':0}


def snapshot(root,reference,cap=1048576):
    raw=evidence._snapshot(reference,Path(root))
    require(len(raw)<=cap,'snapshot size cap exceeded')
    path=Path(root)/reference['path']
    supervisor._read_pinned(path,reference['sha256'],cap,'private capacity snapshot',private=True)
    return raw


def account_metas(stage,request):
    return [(stage[name] if name!='request' else request,False,index>=3)
            for index,name in enumerate(supervisor.ACCOUNT_NAMES)]


def _precondition_bytes(raw,conditions,wire,program,stage,request_address):
    c,i,h,r,q=raw
    require(len(c)==381 and c[:8]==b'DYNCONF3' and c[380]==1
            and len(i)==374 and i[:8]==b'DYNISS03' and i[172]==1 and i[357]==1
            and len(h)==280 and h[:8]==b'DYNHEAD3'
            and len(r)==2249 and r[:8]==b'DYNREQ03' and r[183]==1,
            'enabled canonical finalized capacity account codecs required')
    u=lambda b:int.from_bytes(b,'big')
    observed,expires,now=u(i[213:221]),u(i[221:229]),conditions['now']
    require(0<=observed<=now<expires<=observed+300 and now<u(r[170:178])
            and conditions['observed_at']==observed and conditions['expires_at']==expires
            and conditions['request_deadline']==u(r[170:178]),'clean capacity status/deadline clocks differ')
    config_key=supervisor.execute.base.key(stage['config'])
    require(i[8:40]==config_key and r[8:40]==config_key and h[8:40]==config_key
            and h[40:72]==supervisor.execute.base.key(stage['issuer']) and h[72:104]==c[72:104]
            and i[229:261]==h[176:208]==c[332:364]
            and i[261:269]==h[208:216]==c[364:372]
            and i[269:277]==h[216:224]==i[173:181]
            and i[277:309]==h[224:256]==i[181:213]
            and i[349:357]==h[256:264]==c[372:380]
            and i[358:366]==i[366:374]==h[264:272]
            and observed<=u(h[272:280])<=now,'current bound issuer/head epochs or source differ')
    expected=[int.from_bytes(c[332:364],'big'),int.from_bytes(r[104:136],'big'),
              int.from_bytes(wire[64:96],'big'),int.from_bytes(wire[96:128],'big'),
              int(action(c,r,{'program':list(supervisor.execute.base.key(program))})),
              int.from_bytes(c[136:168],'big')]
    actual=[int.from_bytes(wire[j:j+32],'big') for j in range(0,192,32)]
    require(actual==expected and expected[2]<=now<expected[3], 'complete Full wire statement differs from exact action')
    require(r[184]==2 and r[182]==2,'exact two request relevant accounts required')
    for index,address in enumerate((request_address,stage['queue'])):
        offset=185+65*index
        require(r[offset:offset+32]==supervisor.execute.base.key(address) and r[offset+32]==2
                and r[offset+33:offset+65]==supervisor.execute.base.key(program),
                'exact relevant account owner/order/privileges differ')
    return True


def check_refresh_history(staged, final, report, signed, executions):
    """Replay signed refresh arguments from pinned staged account bytes."""
    state={name:bytearray(staged[name]) for name in ('config','issuer','head')}
    c,i,h=(state[name] for name in ('config','issuer','head'))
    require(len(c)==381 and c[:8]==b'DYNCONF3' and len(i)==374
            and i[:8]==b'DYNISS03' and len(h)==280 and h[:8]==b'DYNHEAD3',
            'canonical staged refresh accounts required')
    u=lambda b:int.from_bytes(b,'big')
    def be(n):
        require(type(n) is int and 0<=n<2**63,'refresh clock/sequence integer required')
        return n.to_bytes(8,'big')
    refreshes=report['refresh_transactions']
    require(type(refreshes) is list and refreshes and len(refreshes)==len(signed),
            'complete signed refresh history required')
    windows=[]
    prior_slot=-1
    for refresh,checked in zip(refreshes,signed):
        observed,expires=refresh['observed_at'],refresh['expires_at']
        require(type(observed) is int and type(expires) is int
                and observed>u(i[213:221]) and expires==observed+300,
                'refresh clock must advance in exact 300-second windows')
        sequence=u(i[173:181])+1
        digest=hashlib.sha256(b'part5-v3-queue-capacity-source-v1'+c[332:364]
            +i[40:72]+i[181:213]+be(sequence)+be(observed)).digest()
        envelope=hashlib.sha256(b'part5-v3-queue-capacity-head-v1'+c[332:364]
            +h[112:144]+digest+be(observed)).digest()
        source=(b'\x51\x03'+c[372:380]+i[358:366]+i[173:181]+be(sequence)
                +digest+b'\x01'+be(observed)+be(expires))
        bind=(b'\x51\x0d\x01'+c[372:380]+i[358:366]+c[332:364]+c[364:372]
              +be(sequence)+digest+h[104:112]+h[112:144]
              +be(u(h[104:112])+1)+envelope)
        require(checked['source_data']==source,'signed source refresh arguments differ')
        require(checked['bind_data']==bind,'signed head refresh arguments differ')
        for role in ('source','bind'):
            result=checked[role+'_result']
            require(all(result[k]==refresh[role][k] for k in ('signature','slot','rpc_error'))
                    and result['finalized'] is True and result['rpc_error'] is None,
                    'signed refresh finalized metadata differs')
            require(type(result['slot']) is int and result['slot']>=prior_slot,
                    'refresh slot chronology differs')
            prior_slot=result['slot']
            require(type(result['block_time']) is int and observed<=result['block_time']<expires,
                    'refresh clock outside signed window')
        i[173:181]=be(sequence);i[181:213]=digest
        i[213:221]=be(observed);i[221:229]=be(expires)
        i[229:261]=c[332:364];i[261:269]=c[364:372]
        i[269:277]=be(sequence);i[277:309]=digest
        i[349:357]=c[372:380];i[357]=1;i[366:374]=i[358:366]
        h[104:112]=be(u(h[104:112])+1)
        h[144:176]=h[112:144];h[112:144]=envelope
        h[176:208]=c[332:364];h[208:216]=c[364:372]
        h[216:224]=be(sequence);h[224:256]=digest
        h[256:264]=c[372:380];h[264:272]=i[358:366]
        h[272:280]=be(checked['bind_result']['block_time'])
        windows.append((checked['source_result']['slot'],prior_slot,observed,expires))
    require(all(bytes(state[name])==final[name] for name in state),
            'refresh replay differs from final account bytes')
    rows=report['fill_history']+[dict(report['rejected_request'],
        preconditions=report['preconditions'],execution_now=report['execution_now'],
        account_slots=report['account_slots'])]
    require(len(rows)==65 and len(executions)==65,'all 65 refresh clock executions required')
    previous=-1
    for row,execution in zip(rows,executions):
        slots=row['account_slots'];slot=row['slot']
        require(type(slot) is int and slot>=previous and execution['slot']==slot
                and type(slots['before']) is int and type(slots['after']) is int
                and slots['before']<=slot<=slots['after'],'refresh slot execution chronology differs')
        previous=slot
        active=[w for w in windows if w[0]<=slot]
        require(active and active[-1][1]<=slots['before'],
                'refresh slot must precede associated account observation')
        _,_,observed,expires=active[-1]
        conditions=row['preconditions'];now=conditions['now'];executed=row['execution_now']
        require(conditions['observed_at']==observed and conditions['expires_at']==expires
                and type(now) is int and type(executed) is int
                and type(execution['block_time']) is int and executed==execution['block_time']
                and observed<=now<=executed<expires
                and executed<conditions['request_deadline'],
                'execution refresh clock differs from active signed window')
    require(windows[-1][1]<=rows[-1]['account_slots']['before'],
            'refresh slot after final rejection')


def replay_runtime(report,config,output,*,rpc=None,loaded=None,runner_pid=None,rechecks=None):
    """Pure replay after exit, or independent RPC replay while owner is still live."""
    require(report.get('schema')==RUNTIME_SCHEMA and report.get('scope')==supervisor.SCOPE
            and report.get('external_finalization_required') is True
            and report.get('successful_fill_count')==64 and report.get('queue_capacity')==64
            and report.get('full_proofs_verified_in_rust')==65
            and report.get('rejection_application_effect') is False
            and report.get('setup_application_effect') is True,'complete authentic runtime capacity report required')
    for key in ('cohort_id','cohort_freeze_sha256','cohort_manifest_sha256','stage_report_sha256','clone_receipt_sha256'):
        require(report.get(key)==config[key],'capacity runtime identity pin differs')
    for key,expected in [('program',config['expected_program']),('genesis',config['expected_genesis']),
                         ('genesis_sha256',config['expected_genesis_sha256']),('inputs',config['inputs']),
                         ('fixture_manifest',{'path':config['fixture_manifest'],'sha256':config['fixture_manifest_sha256']}),
                         ('rust_config_sha256',config['rust_config_sha256'])]:
        require(report.get(key)==expected,'capacity runtime configured input differs')
    require(report.get('loaded_program')==report.get('loaded_program_after')
            and report['loaded_program'].get('elf_match') is True
            and report['loaded_program'].get('elf_sha256')==config['expected_elf_sha256'], 'capacity loaded identity drift')
    if loaded is not None:
        supervisor.execute.same_loaded(loaded,report['loaded_program'])
    if runner_pid is not None:
        require(report['runner_observations']['pid']==runner_pid,'capacity child PID differs')
    stage=supervisor.execute.pinned_json(config['stage_report'],config['stage_report_sha256'])
    fixture_doc=fixture.doc({'path':config['fixture_manifest'],'sha256':config['fixture_manifest_sha256']})
    require(fixture_doc['inputs']==config['inputs'],'fixture ordered inputs differ')
    staged={name:supervisor._read_pinned(Path(config['stage_report']).parent/(name+'.bin'),
        stage['account_sha256'][index],4096,'staged refresh account',private=True)
        for index,name in enumerate(('config','issuer','head'))}
    require(supervisor.execute.base.key(fixture_doc['signers']['source']['public_key'])==staged['issuer'][140:172]
            and supervisor.execute.base.key(fixture_doc['signers']['publisher']['public_key'])
                ==staged['config'][72:104]==staged['head'][72:104],
            'refresh signers must match pinned staged authorities')
    tx_rows=[]
    executions=[]
    def tx(row,data,metas):
        index=len(tx_rows)
        if rpc is not None:
            result=runtime.rpc_transaction(rpc,row,config['expected_program'],data,metas,output,index)
        else:
            require(type(rechecks) is list and index<len(rechecks),'complete retained RPC rechecks required')
            result=rechecks[index]
            require(all(result[name]==row[name] for name in ('signature','slot','rpc_error'))
                    and result['finalized'] is True,'retained finalized transaction metadata differs')
            raw=snapshot(output,result['transaction'],1232)
            runtime.signed_transaction(raw,row['signature'],config['expected_program'],data,metas)
        tx_rows.append(result)
        return result
    require(len(report.get('request_finalizations',[]))==65 and len(report.get('fill_history',[]))==64,
            '65 request finalizations and 64 fills required')
    for row,finalized in zip(config['inputs'],report['request_finalizations']):
        require(finalized['rpc_error'] is None,'request Finalize must succeed')
        request=supervisor._read_pinned(row['request_account'],row['request_sha256'],2249,'prepared request',private=True)
        creator=supervisor.execute.base.b58(request[40:72])
        tx(finalized,b'\x51\x05',[(creator,True,False),(stage['config'],False,False),(row['request_address'],False,True)])
        proof_receipt=fixture.doc({'path':row['proof_receipt'],'sha256':row['proof_receipt_sha256']})
        wire=supervisor._read_pinned(row['full_wire'],row['full_wire_sha256'],448,'Full wire',private=True)
        fixture.check_proof_receipt(proof_receipt,row,wire)
    fills=[]
    expected=[]
    previous_queue=None
    for index,(row,fill) in enumerate(zip(config['inputs'],report['fill_history'])):
        require(fill['request_address']==row['request_address'] and fill['finalized'] is True and fill['consumed'] is True,
                'exact finalized fill order required')
        refs=fill['snapshots']
        before_request=snapshot(output,refs['request_before'],2249)
        after_request=snapshot(output,refs['request_after'],2249)
        before_queue=snapshot(output,refs['queue_before'],2090)
        after_queue=snapshot(output,refs['queue_after'],2090)
        require(hashlib.sha256(before_request).hexdigest()==row['request_sha256']
                and before_request[183]==1 and after_request[183]==2
                and before_request[:183]+before_request[184:]==after_request[:183]+after_request[184:],
                'fill must only consume the exact pinned request')
        require(runtime.queue(before_queue,stage['config'])==expected
                and (previous_queue is None or previous_queue==before_queue), 'exact contiguous queue prefix required')
        expected.append(row['request_address'])
        require(runtime.queue(after_queue,stage['config'])==expected and fill['queue_after_addresses']==expected,
                'one exact distinct queue append required')
        previous_queue=after_queue
        for name,raw in [('request_before',before_request),('request_after',after_request),
                         ('queue_before',before_queue),('queue_after',after_queue)]:
            require(fill[name+'_sha256']==hashlib.sha256(raw).hexdigest(),'fill snapshot digest differs')
        wire=supervisor._read_pinned(row['full_wire'],row['full_wire_sha256'],448,'fill wire',private=True)
        executions.append(tx({'signature':fill['signature'],'slot':fill['slot'],'rpc_error':None},b'\x51\x07'+wire,
           account_metas(stage,row['request_address'])))
        fills.append({key:copy.deepcopy(fill[key]) for key in ('request_address','signature','slot','finalized',
            'consumed','queue_after_addresses','request_before_sha256','request_after_sha256','queue_before_sha256','queue_after_sha256')})
    rejected=report['rejected_request']
    supervisor.checks.check_execute_error(rejected['rpc_error'],708)
    require(rejected['request_address']==config['inputs'][64]['request_address']
            and rejected['finalized'] is True and rejected['consumed'] is False,'exact distinct 65th request required')
    before=[]
    snapshots=[]
    for index,(name,row) in enumerate(zip(supervisor.ACCOUNT_NAMES,report['snapshots'])):
        require(row['name']==name and row['address']==(rejected['request_address'] if name=='request' else stage[name]),
                'five exact ordered snapshot addresses required')
        b=snapshot(output,row['before']);a=snapshot(output,row['after'])
        require(b==a,'capacity rejection changed application bytes')
        before.append(b)
        snapshots.append({key:row[key] for key in ('name','before','after')})
    require(len(before)==5 and runtime.queue(before[4],stage['config'])==expected
            and previous_queue==before[4] and report['before_queue_addresses']==report['after_queue_addresses']==expected,
            '64 exact queue entries must persist across rejection')
    row=config['inputs'][64]
    wire=supervisor._read_pinned(row['full_wire'],row['full_wire_sha256'],448,'rejected Full wire',private=True)
    _precondition_bytes(before,report['preconditions'],wire,config['expected_program'],stage,rejected['request_address'])
    executions.append(tx(rejected,b'\x51\x07'+wire,account_metas(stage,rejected['request_address'])))
    signed_refreshes=[]
    # The final active source and head refreshes are authenticated by their own
    # signed instructions. No claim about upstream production issuer security.
    for refresh in report['refresh_transactions']:
        checked={}
        for role,opcode in [('source',3),('bind',13)]:
            row=refresh[role]
            require(row['rpc_error'] is None,'refresh transaction must succeed')
            if role=='source':
                metas=[(fixture_doc['signers']['source']['public_key'],True,False),
                       (stage['config'],False,False),(stage['issuer'],False,True)]
            else:
                metas=[(fixture_doc['signers']['publisher']['public_key'],True,True),
                       (stage['config'],False,False),(stage['issuer'],False,True),(stage['head'],False,True),
                       ('11111111111111111111111111111111',False,False)]
            result=tx(row,None,metas)
            raw=snapshot(output,result['transaction'],1232)
            actual=runtime.signed_transaction(raw,row['signature'],config['expected_program'],None,metas)
            require(actual[:2]==bytes([0x51,opcode]),'refresh must use authentic observation/head opcode')
            checked[role+'_data']=actual
            checked[role+'_result']=result
        signed_refreshes.append(checked)
    check_refresh_history(staged,dict(zip(supervisor.ACCOUNT_NAMES,before)),report,signed_refreshes,executions)
    if rpc is None:
        require(len(rechecks)==len(tx_rows),'unexpected retained RPC rechecks')
    if rpc is not None:
        hashes=[hashlib.sha256(raw).hexdigest() for raw in before]
        stage_live={**stage,'request':rejected['request_address']}
        supervisor.execute.finalized_accounts(rpc,stage_live,report['account_slots']['after'],
            config['expected_program'],hashes,[len(raw) for raw in before])
    projected={'schema':evidence.SCHEMA,'identities':supervisor._expected_identities(config),'fill_history':fills,
               'before_queue_addresses':expected,'after_queue_addresses':expected,'rejected_request':rejected,
               'preconditions':report['preconditions'],'snapshots':snapshots}
    return projected,tx_rows


def check_bounded_receipts(receipt, config, index):
    """Reopen all four offline processes and bind them to the pinned producer."""
    bounded=receipt.get('bounded')
    require(type(bounded) is dict and set(bounded)=={'witness','relation','proof','adapter'},
            'exact four bounded proof process receipts required')
    names=('proof_runner','adapter','node','witness_js','relation_checker')
    require(receipt.get('tools')=={name:config[name] for name in names},
            'pinned producer tool references differ')
    for name in (*names,'bounded_supervisor'):
        fixture.read(config[name],512*1024**2)
    work=Path(config['output_dir'])/f'proof-{index:02}'
    training=work/'training'
    commands={
        'witness':[config['node']['path'],config['witness_js']['path'],str(training)],
        'relation':[sys.executable,'-B',config['relation_checker']['path'],'check',str(training)],
        'proof':[config['proof_runner']['path'],fixture.MODE,receipt['packet']['path'],
                 receipt['packet']['sha256'],str(work/'full-proof')],
        'adapter':[config['adapter']['path'],'private_campaign_final_wire_passes_adapter_and_program_host',
                   '--exact','--ignored','--test-threads=1']}
    for name in ('witness','relation','proof','adapter'):
        step=bounded[name]
        require(type(step) is dict and set(step)=={'path','sha256','monitor','wall_seconds','limits'},
                'complete bounded process receipt required')
        report=fixture.doc({'path':step['path'],'sha256':step['sha256']})
        invocation=fixture.doc(fixture.ref(Path(step['monitor'])/'invocation.json'))
        label=f'{index:02}-'+('full' if name=='proof' else name)
        prefix=f'heldout-v3-{label}-'
        owner=invocation.get('owner')
        require(type(owner) is str and owner.startswith(prefix) and len(owner)==len(prefix)+10
                and all(c in '0123456789abcdef' for c in owner[len(prefix):])
                and report.get('owner')==owner
                and invocation.get('argv')==commands[name]
                and invocation.get('cwd')==str(REPO)
                and invocation.get('storage_roots')==[config['output_dir']],
                'offline proof process invocation provenance differs')
        require(report.get('schema')==1 and report.get('passed') is True
                and type(report.get('exit_code')) is int and report['exit_code']==0
                and report.get('stop_reason') is None and report.get('runner_error_type') is None
                and report.get('cleanup_status_unknown') is False
                and type(report.get('cleanup_remaining_owned_processes')) is int
                and report['cleanup_remaining_owned_processes']==0,
                'offline proof child cleanup incomplete')
        limits=getattr(fixture.proof,{'proof':'FULL'}.get(name,name.upper())+'_LIMITS')
        expected={'runtime_seconds':limits['runtime_seconds'],'owned_tree_rss_bytes':limits['rss_bytes'],
                  'storage_growth_bytes':limits['storage_bytes'],'poll_seconds':.25}
        require(step['limits']==limits and report.get('limits')==expected,
                'offline proof process limits differ')
        duration=number(report.get('duration_seconds'))
        require(0<duration<=limits['runtime_seconds'] and duration<=number(step['wall_seconds']),
                'offline proof process duration differs')
        require(report.get('environment')=={'RAYON_NUM_THREADS':'4','OMP_NUM_THREADS':'1','TZ':'UTC'},
                'offline proof process environment differs')
        samples=report.get('samples')
        require(type(samples) is list and samples and type(report.get('sample_count')) is int
                and report['sample_count']==len(samples),'offline proof resource samples required')
        previous=-1
        for row in samples:
            elapsed=number(row.get('elapsed_seconds'))
            require(previous<=elapsed<=duration,'offline proof sample chronology differs')
            previous=elapsed
            for key in ('owned_process_count','owned_tree_rss_bytes','storage_growth_bytes'):
                number(row.get(key),True)
        require(any(row['owned_process_count']>0 for row in samples),'offline proof owner observed no child')
        for key,peak in (('owned_tree_rss_bytes','sampled_peak_owned_tree_rss_bytes'),
                         ('storage_growth_bytes','sampled_peak_storage_growth_bytes')):
            require(number(report.get(peak),True)==max(row[key] for row in samples)<=expected[key],
                    'offline proof sampled peak exceeds declared bound')


def check_clone_owner(manifest, config, preparation, proof_config, stage_config):
    roles=('clone_config','clone_monitor','clone_invocation','clone_report')
    require(all(type(manifest.get(role)) is dict and set(manifest[role])==fixture.REFERENCE_FIELDS
                for role in roles),'complete pinned clone owner evidence required')
    clone_config=fixture.doc(manifest['clone_config'])
    report=fixture.doc(manifest['clone_report'])
    monitor=fixture.doc(manifest['clone_monitor'])
    invocation=fixture.doc(manifest['clone_invocation'])
    require(clone_config.get('schema')==fixture.SCHEMA and clone_config.get('phase')=='clone',
            'explicit clone producer phase required')
    require(manifest['clone_report']=={'path':config['clone_receipt'],'sha256':config['clone_receipt_sha256']}
            and clone_config.get('preparation_receipt')=={'path':config['preparation_receipt'],
                                                        'sha256':config['preparation_receipt_sha256']}
            and all(clone_config.get(key)==proof_config[key] for key in
                    ('stage_config','stage_status','stage_monitor','stage_invocation','preparation_report','baseline_stage_report'))
            and clone_config.get('proof_monitor')==manifest['proof_monitor']
            and clone_config.get('proof_invocation')==manifest['proof_invocation'],
            'clone owner disconnected from exact prepared fixture')
    source,destination=Path(stage_config['ledger']),Path(config['ledger'])
    require(source.is_absolute() and destination.is_absolute() and source.resolve()==source
            and destination.resolve()==destination and source.name==destination.name=='ledger'
            and source!=destination and source not in destination.parents and destination not in source.parents
            and clone_config.get('ledger')==str(destination)
            and clone_config.get('output_dir')==str(destination.parent)
            and Path(manifest['clone_report']['path'])==destination.parent/'clone-report.json',
            'clone source/destination ownership differs')
    limits={'runtime_seconds':3600,'owned_tree_rss_bytes':4294967296,
            'storage_growth_bytes':CAPACITY_STORAGE_LIMIT_BYTES,'poll_seconds':.25}
    require(report.get('schema')=='part5-v3-queue-capacity-prepared-ledger-clone-v1'
            and report.get('config_ref')==manifest['clone_config']
            and report.get('clone_owner_required') is True and report.get('cost_included') is False
            and report.get('owner_limits')==limits and monitor.get('limits')==limits
            and report.get('source')==str(source) and report.get('destination')==str(destination)
            and report.get('source_stable') is True and report.get('copy_identical') is True
            and type(report.get('excluded_stale_admin_socket')) is bool
            and report.get('loaded_identity_rechecked_after_restart') is False
            and report.get('application_effect') is False
            and all(report.get(key)==config[key] for key in
                    ('stage_report_sha256','stage_status_sha256','preparation_receipt_sha256'))
            and report.get('fixture_manifest_sha256')==preparation['fixture_manifest']['sha256'],
            'clone report provenance differs')
    # The loaded destination has advanced; reopen the retained, stopped source
    # against the exact inventory digest checked before loading that destination.
    rows=fixture.inventory(source)
    digest=hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest()
    require(type(report.get('entry_count')) is int and report['entry_count']==len(rows)
            and report.get('tree_sha256')==clone_config.get('source_tree_sha256')==digest,
            'retained prepared clone inventory differs')
    genesis=[row for row in rows if row[0]=='genesis.bin']
    require(len(genesis)==1 and genesis[0][1]=='file' and genesis[0][3]==config['expected_genesis_sha256'],
            'retained clone genesis differs')
    return check_monitor(monitor,invocation,manifest['clone_config'],Path(fixture.__file__),clone_config)


def finalize(manifest):
    require(type(manifest) is dict and manifest.get('schema')==MANIFEST_SCHEMA,'explicit capacity finalizer manifest required')
    config=fixture.doc(manifest['config'])
    candidate=fixture.doc(manifest['candidate'])
    status=fixture.doc(manifest['supervisor_status'])
    require(status.get('status')=='candidate_verified_pending_external_finalization'
            and status.get('candidate_verified') is True and status.get('candidate')==manifest['candidate']
            and status.get('config_ref')==manifest['config'],'verified supervisor candidate provenance required')
    monitor,invocation=fixture.doc(manifest['monitor']),fixture.doc(manifest['monitor_invocation'])
    owner=check_monitor(monitor,invocation,manifest['config'],Path(supervisor.__file__),config)
    output=Path(config['output_dir'])
    recheck_pin=status['replay']
    rechecks=fixture.doc(recheck_pin)
    projected,_=replay_runtime(candidate,config,output,rechecks=rechecks['transactions'])
    projected['owner']=owner
    result=evidence.validate_report(projected,output,supervisor._expected_identities(config))
    preparation=fixture.doc({'path':config['preparation_receipt'],'sha256':config['preparation_receipt_sha256']})
    require(preparation['fixture_manifest']=={'path':config['fixture_manifest'],'sha256':config['fixture_manifest_sha256']}
            and len(preparation['proof_receipts'])==65,'prepared fixture and 65 individual proofs required')
    proof_config=fixture.doc(preparation['config_ref'])
    proof_owner=check_monitor(fixture.doc(manifest['proof_monitor']),fixture.doc(manifest['proof_invocation']),
                  preparation['config_ref'],Path(fixture.__file__),proof_config)
    stage_config=fixture.doc(proof_config['stage_config'])
    stage_owner=check_monitor(fixture.doc(proof_config['stage_monitor']),fixture.doc(proof_config['stage_invocation']),
                  proof_config['stage_config'],Path(fixture.__file__),stage_config,staging=True)
    clone_owner=check_clone_owner(manifest,config,preparation,proof_config,stage_config)
    # Reopen all proof artifacts and independent proof/adapter process receipts.
    for index,(row,pin) in enumerate(zip(config['inputs'],preparation['proof_receipts'])):
        receipt=fixture.doc(pin)
        wire=fixture.read(receipt['wire'],448)
        fixture.check_proof_receipt(receipt,row,wire)
        packet=fixture.doc(receipt['packet'])
        proof_report=fixture.doc(receipt['proof_report'])
        fixture.check_single_full_report(proof_report,receipt['packet'],packet,receipt['tools']['proof_runner']['sha256'])
        for name in ('witness','input','public','training_receipt'):
            fixture.read(receipt[name],32*1024**2)
        check_bounded_receipts(receipt,proof_config,index)
    return {'schema':SCHEMA,'passed':True,'scope':supervisor.SCOPE,
            **{role:manifest[role] for role in ('config','candidate','supervisor_status','monitor','monitor_invocation',
                                               'proof_monitor','proof_invocation','clone_config','clone_monitor','clone_invocation','clone_report')},
            'fixture_manifest':preparation['fixture_manifest'],
            'preparation_receipt':{'path':config['preparation_receipt'],'sha256':config['preparation_receipt_sha256']},
            'evidence_report':projected,'evidence_dir':str(output),'report_consistency':result,
            'setup_cost_seconds':stage_owner['wall_seconds']+proof_owner['wall_seconds']+clone_owner['wall_seconds'],
            'clone_owner_seconds':clone_owner['wall_seconds'],
            'stage_owner_seconds':stage_owner['wall_seconds'],'proof_owner_seconds':proof_owner['wall_seconds'],
            'loaded_owner_seconds':owner['wall_seconds'],'loaded_run_established':True,
            'heldout_acceptance_established':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',required=True,type=Path)
    parser.add_argument('--manifest-sha256',required=True)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    result=finalize(fixture.doc({'path':str(args.manifest),'sha256':args.manifest_sha256}))
    fixture.write(args.output,result)


if __name__=='__main__':
    main()
