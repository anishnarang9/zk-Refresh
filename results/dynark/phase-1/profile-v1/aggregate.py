"""Read retained E4 evidence; emit scrubbed aggregates without rerunning cryptography."""
import collections, datetime, hashlib, json, pathlib, re, statistics, subprocess
ROOT=pathlib.Path.cwd(); RAW=ROOT/'artifacts/dynark/phase-1/profile-v1'; OUT=ROOT/'results/dynark/phase-1/profile-v1'
def read(p): return json.loads(p.read_text())
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def save(n,v): (OUT/n).write_text(json.dumps(v,indent=2)+'\n')
r=read(RAW/'report.json'); w=read(RAW/'watchdog.json')
assert r['status']=='complete' and w['stop'] is None
freeze=read(ROOT/'results/dynark/phase-1/baseline-freeze.json')
mis=[]
for e in freeze['entries']:
 p=ROOT/e['path']
 if sha(p)!=e['sha256'] or oct(p.stat().st_mode&0o777)!=e['mode']:mis.append(e['path'])
assert len(freeze['entries'])==165 and not mis
pcheck=[]
e2=read(ROOT/'results/dynark/phase-1/e2-report.json')
for k in ['updating_key','cache','ordinary_vk','initial_proof','before_public','after_public']:
 v=e2['retained_artifacts'][k];p=ROOT/'artifacts/dynark/phase-1/near-e2-v1'/v['path'];assert sha(p)==v['sha256'] and p.stat().st_mode&0o777==0o600;pcheck.append(k)
for e in e2['input_identity']:assert sha(ROOT/e['path'])==e['sha256']
identities={}
for name,path in [('e4_source','experiments/dynark/proof-probe/src/bin/phase1-profile.rs'),('e4_binary','experiments/dynark/proof-probe/target/release/phase1-profile'),('e2_source','experiments/dynark/proof-probe/src/bin/phase1-baseline.rs'),('e2_binary','experiments/dynark/proof-probe/target/release/phase1-baseline'),('e2_report','results/dynark/phase-1/e2-report.json'),('e2_summary','results/dynark/phase-1/e2-summary.json')]:identities[name]={'path':path,'sha256':sha(ROOT/path)}
assert identities['e4_source']['sha256']==r['source_sha256'] and identities['e4_binary']['sha256']==r['binary_sha256']
assert identities['e2_source']['sha256']=='2cfc91338433ca8f022196325cb70d506673efc12b0ebf7b89049e0e7551b529'
assert identities['e2_binary']['sha256']=='ac864557c42fff1cd680da3b7f793e9b35660601b4f61f0300a6ac9f8e84837f'
# Native sample counts are per-thread sampled contexts. Subtract DIRECT children,
# then classify each positive self count once; inclusive nodes are never added.
def family(s,anc):
 if any(x in s for x in ['__wait4','__psynch_cvwait','__ulock_wait','__semwait_signal','pthread_cond_wait','mach_msg','semaphore_wait']):return 'blocked_wait'
 if 'elementwise_product_f_g' in anc:return 'group_elementwise_products'
 if 'convolution_f_g' in anc:return 'group_convolution_fft'
 if 'convolution_f_f' in anc:return 'field_convolution'
 if 'compute_quotient' in anc:return 'field_quotient'
 if 'improved_lagrange_sparse_get' in anc:return 'sparse_lagrange_mapping'
 if 'inner_product_sparse_f_dense_g' in anc:return 'group_sparse_projection_combine'
 if 'msm' in anc or 'VariableBaseMSM' in anc:return 'multiscalar_multiplication'
 if 'update_dynark' in anc:return 'other_update'
 if 'create_proof_with_assignment' in anc:return 'other_full'
 if 'Projective' in anc and any(t in anc for t in ['ifft','fft','butterfly']):return 'group_fft_other_context'
 return 'other_nonwait'
def parse(p):
 lines=p.read_text().splitlines();active=False;stack=[];nodes=[];roots=[];thread_index=-1
 for line in lines:
  if line.strip()=='Call graph:':active=True;continue
  if not active:continue
  if line.startswith('Total number in stack'):break
  m=re.match(r'^([ +:|!]*)(\d+) (.*)',line)
  if not m:continue
  dep=len(m[1]);count=int(m[2]);s=m[3]
  while stack and nodes[stack[-1]]['depth']>=dep:stack.pop()
  if not stack:thread_index+=1;roots.append(count)
  anc=(nodes[stack[-1]]['anc']+' '+s) if stack else s
  node={'depth':dep,'count':count,'self':count,'symbol':s,'anc':anc,'thread':thread_index}
  if stack:nodes[stack[-1]]['self']-=count
  nodes.append(node);stack.append(len(nodes)-1)
 totals=collections.Counter();thread_totals=collections.defaultdict(collections.Counter)
 for n in nodes:
  assert n['self']>=0, (p.name,n['symbol'])
  if n['self']:
   f=family(n['symbol'],n['anc']);totals[f]+=n['self'];thread_totals[n['thread']][f]+=n['self']
 assert sum(totals.values())==sum(roots)
 return {'file':p.name,'sha256':sha(p),'thread_count':len(roots),'root_context_counts':roots,'all_thread_context_denominator':sum(roots),'self_count_conservation':True,'family_self_counts':dict(totals),'nonwait_context_denominator':sum(roots)-totals['blocked_wait'],'per_thread_family_self_counts':{str(k):dict(v) for k,v in thread_totals.items()}}
stack_reports=[parse(p) for p in sorted(RAW.glob('*-sample.txt'))]
agg=collections.Counter()
for s in stack_reports:
 if s['file'].startswith('private-preparation-'):agg.update(s['family_self_counts'])
proof={}
for mode,v in r['proof_diagnostics'].items():
 resources=[s['proof'] for s in v['samples']]
 proof[mode]={'count':len(resources),'median_wall_ms':statistics.median(x['wall_ms'] for x in resources),'max_requested_live_peak_bytes':max(x['requested_live_peak_bytes'] for x in resources),'max_requested_peak_above_start_bytes':max(x['requested_peak_above_start_bytes'] for x in resources),'median_allocated_requested_bytes':statistics.median(x['allocated_requested_bytes'] for x in resources),'allocation_calls_range':[min(x['allocation_calls'] for x in resources),max(x['allocation_calls'] for x in resources)],'native_sample':v['sample_command']}
permissions=[]
for p in [RAW,*RAW.rglob('*')]:
 expected=0o700 if p.is_dir() else 0o600
 if p.stat().st_mode&0o777!=expected:permissions.append(str(p.relative_to(ROOT)))
assert not permissions
ps=subprocess.run(['ps','-axo','pid=,pgid=,command='],capture_output=True,text=True,check=True).stdout.splitlines()
owned=[]
for line in ps:
 parts=line.split(None,2)
 if len(parts)>=3 and (parts[0] in [str(r['pid']),str(w['watchdog_pid'])] or parts[1]==str(r['pid'])):owned.append(line)
assert not owned
child=r['witness_child'];nonblocked=sum(agg.values())-agg['blocked_wait']
child_time_text=(RAW/'witness-time-stderr.log').read_text()
child_time_match=re.search(r'([0-9.]+) real\s+([0-9.]+) user\s+([0-9.]+) sys',child_time_text)
assert child_time_match
child_time={'real_seconds':float(child_time_match[1]),'user_seconds':float(child_time_match[2]),'system_seconds':float(child_time_match[3]),'precision_note':'Darwin time -l prints hundredths of a second.'}
summary={'schema':1,'experiment':'E4','status':'complete','created_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'workspace':str(ROOT),'total_wall_ms':r['total_wall_ms'],'limits':r['limits'],'threads':r['threads'],'timing_classification':'Instrumented diagnostics only; fair E2 benchmark remains unchanged.','identities':identities,'stages':r['stages'],'proof_diagnostics':proof,'census':r['census'],'retained_requested_live_at_stage_end':{k:v['requested_live_after_bytes'] for k,v in r['stages'].items()},'retained_object_attribution':{'method':'Observed net requested-live differences around sequential object loading; includes stage instrumentation. Exact per-object capacities below are structural estimates.','updating_key_including_pk_net_bytes':r['stages']['load_updating_key_including_pk']['requested_live_after_bytes']-r['stages']['load_updating_key_including_pk']['requested_live_before_bytes'],'private_cache_net_bytes':r['stages']['load_private_cache']['requested_live_after_bytes']-r['stages']['load_private_cache']['requested_live_before_bytes'],'new_private_projection_net_bytes':r['stages']['private_preparation_once']['requested_live_after_bytes']-r['stages']['private_preparation_once']['requested_live_before_bytes'],'structural_estimates':r['structural_estimates']},'witness_child':{'exit_code':child['exit_code'],'direct_time':child_time,'wall_ms':child['parent_stage']['wall_ms'],'direct_max_rss_bytes':child['direct_max_rss_bytes'],'sampled_max_node_rss_bytes':max(v[1] for s in child['samples'] for v in s['witness_descendants']),'witness_hash_matches':child['witness_hash_matches'],'sample_count':len(child['samples']),'max_rss_units':child['max_rss_units']},'projection_equality':r['projection_equality'],'correctness':r['correctness'],'correctness_counts':{'full_proofs_verified':proof['full']['count'],'update_proofs_verified':proof['update']['count'],'stale_root_rejections':sum(v['count'] for v in proof.values()),'wrong_action_rejections':sum(v['count'] for v in proof.values()),'additional_reprepared_update_verified':1,'additional_regenerated_witness_update_verified':1,'anchor_verified':1},'native_sampling':{'method':'10-second windows at nominal1ms sample interval;13 preparation windows start about60seconds apart across746.360second stage. Counts are sampled per-thread contexts, including blocked threads; not exact CPU percentages, allocation attribution, or full-stage kernel percentages.','preparation_windows':r['private_preparation_samples'],'parsed_windows':stack_reports,'private_preparation_family_self_counts':dict(agg),'private_preparation_nonwait_denominator':nonblocked,'private_preparation_all_thread_denominator':sum(agg.values()),'caveat':'Each node self count is inclusive count minus direct children. Families partition self counts; blocked waits remain separate. Gaps between preparation windows are unsampled.','tree_self_conservation_all_windows':all(x['self_count_conservation'] for x in stack_reports)},'allocator_final_conservation':r['allocator_final_conservation'],'watchdog':{'stop':w['stop'],'last_elapsed_seconds':w['samples'][-1]['elapsed_seconds'],'max_parent_rss_bytes':max(x['parent_rss_bytes'] for x in w['samples']),'max_owned_child_rss_bytes':max(x['max_owned_child_rss_bytes'] for x in w['samples']),'max_retained_bytes':max(x['retained_bytes'] for x in w['samples']),'sample_count':len(w['samples'])},'preservation_after_independent_check':{'baseline_entries_checked':165,'hash_and_mode_mismatches':0,'retained_e2_package_and_inputs_match':True,'protected_permission_mismatches':0,'owned_live_jobs':0},'limitations':r['limitations']}
save('summary.json',summary)
# Scrub path-bearing commands, input/private package hashes and raw PID samples.
scrub={k:v for k,v in r.items() if k not in ['argv','input_identities','package_identities','pid','witness_child']};scrub['witness_child']=summary['witness_child'];save('report.json',scrub)
print(json.dumps({'status':summary['status'],'summary_sha256':sha(OUT/'summary.json'),'stack_windows':len(stack_reports),'private_family_counts':dict(agg),'nonwait':nonblocked,'preservation':summary['preservation_after_independent_check']},indent=2))
