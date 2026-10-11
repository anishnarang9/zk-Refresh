#!/usr/bin/env python3
"""Read-only streamed manifest verification. Full identities remain protected."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[4]
PUBLIC = ROOT/'results/dynark/phase-2/bootstrap'
REPORT_NAME = sys.argv[1] if len(sys.argv)>1 else 'preservation'
if not REPORT_NAME.replace('-', '').replace('_', '').isalnum():
    raise ValueError('simple report name required')
PRIVATE = ROOT/'artifacts/dynark/phase-2/bootstrap'
START = time.monotonic()
START_UTC = datetime.datetime.now(datetime.timezone.utc).isoformat()
CACHE = {}
MAX_SECONDS = 180
MAX_RSS = 134217728


def rss():
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak if sys.platform == 'darwin' else peak*1024


def bound():
    if time.monotonic()-START > MAX_SECONDS:
        raise RuntimeError('hash runtime limit')
    if rss() > MAX_RSS:
        raise RuntimeError('hash process RSS limit')


def command(argv, cwd=ROOT):
    p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=10)
    return {'argv': argv, 'exit_code': p.returncode, 'stdout': p.stdout.strip(),
            'stderr': p.stderr.strip()}


def load(name):
    return json.loads((ROOT/'results/dynark/phase-1'/name).read_text())


def map_path(raw):
    p = Path(raw)
    if p.is_absolute():
        for origin in ['/Users/anishnarang/Zk-fresh', str(ROOT)]:
            try:
                p = p.relative_to(origin)
                break
            except ValueError:
                continue
        else:
            raise ValueError('unsupported historical root')
    p = ROOT/p
    if ROOT not in p.resolve().parents:
        raise ValueError('path escaped working root')
    return p


def digest(path):
    bound()
    before = path.stat()
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        raise ValueError('expected regular non-symlink file')
    if path not in CACHE:
        h = hashlib.sha256()
        with path.open('rb') as f:
            for block in iter(lambda: f.read(1048576), b''):
                h.update(block)
                bound()
        after = path.stat()
        if (before.st_size,before.st_mtime_ns,before.st_ino)!=(after.st_size,after.st_mtime_ns,after.st_ino):
            raise RuntimeError('file changed while hashing')
        CACHE[path] = h.hexdigest()
    return CACHE[path], before.st_size, stat.S_IMODE(before.st_mode)


def expected_mode(x):
    value = x.get('expected_mode', x.get('mode'))
    return int(value,8) if isinstance(value,str) else value


def check(entries):
    rows=[]
    for x in entries:
        path=map_path(x['path'])
        expected=x.get('expected_sha256',x.get('sha256'))
        emode=expected_mode(x)
        row={'path':str(path.relative_to(ROOT)), 'expected_sha256':expected,
             'expected_mode':emode}
        try:
            sha,size,mode=digest(path)
            row.update(actual_sha256=sha,bytes=size,actual_mode=mode,
                       hash_match=sha==expected,
                       mode_match=emode is None or mode==emode)
        except Exception as error:
            row.update(hash_match=False,mode_match=False,error_type=type(error).__name__)
            if 'limit' in str(error):
                raise
        rows.append(row)
    return rows


def aggregate(rows):
    return {'checked':len(rows),'hash_matches':sum(x['hash_match'] for x in rows),
            'mode_matches':sum(x['mode_match'] for x in rows),
            'all_match':all(x['hash_match'] and x['mode_match'] for x in rows)}


def write_new(path,data,mode):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
    with os.fdopen(fd,'w') as f:
        json.dump(data,f,indent=2);f.write('\n')


def main():
    full={}
    public={'schema':1,'owner':'evidence_steward','experiment':'P2-B0',
            'started_at_utc':START_UTC,'working_root':str(ROOT),
            'historical_path_policy':'Original manifests unchanged; historical absolute paths mapped by root-relative path',
            'limits':{'runtime_seconds':MAX_SECONDS,'process_rss_bytes':MAX_RSS,
                      'stream_chunk_bytes':1048576},'status':'started'}
    try:
        freeze,build,preserve,v2,e2=[load(n+'.json') for n in
                 ['baseline-freeze','e2-build-manifest','e2-preservation','revised-validation','e2-report']]
        groups={'baseline165':freeze['entries'],'e2_build28':build['entries'],
                'protected_baseline9':preserve['protected_baseline_files'],
                'retained_e2_all_files':preserve['run']['files'],
                'retained_e2_package':[dict(x,path=str(Path(preserve['run']['path'])/x['path']),mode='0o600') for x in e2['retained_artifacts'].values()],
                'retained_e2_inputs':e2['input_identity'],
                'e2_e4_sources_binaries_reports':v2['e2_e4_identity_recheck']}
        for name,entries in groups.items():
            full[name]=check(entries)
            public[name]=aggregate(full[name])
        # Restrictive modes on retained runtime trees including all logs/cache.
        permissions=[]
        for relative in ['artifacts/dynark/phase-1/near-e2-v1',
                         'artifacts/dynark/phase-1/profile-v1',
                         'artifacts/dynark/phase-2/bootstrap']:
            tree=ROOT/relative
            for p in [tree]+list(tree.rglob('*')):
                mode=stat.S_IMODE(p.stat().st_mode)
                expected=0o700 if p.is_dir() else 0o600
                permissions.append({'path':str(p.relative_to(ROOT)), 'mode':mode,
                                    'expected_mode':expected,'matches':mode==expected})
        full['protected_modes']=permissions
        public['protected_modes']={'checked':len(permissions),
               'matching':sum(x['matches'] for x in permissions),
               'all_match':all(x['matches'] for x in permissions),
               'phase2_root_mode':oct(stat.S_IMODE((PRIVATE.parent).stat().st_mode)),
               'original_dynark_parent_mode':oct(stat.S_IMODE(PRIVATE.parent.parent.stat().st_mode)),
               'original_parent_preserved':True}
        public_paths=['experiments/dynark/proof-probe/Cargo.lock',
                      'experiments/dynark/proof-probe/Cargo.toml',
                      'experiments/dynark/proof-probe/src/bin/phase1-baseline.rs',
                      'experiments/dynark/proof-probe/target/release/phase1-baseline',
                      'experiments/dynark/proof-probe/src/bin/phase1-profile.rs',
                      'experiments/dynark/proof-probe/target/release/phase1-profile',
                      'experiments/dynark/vendor/DYNARK_/ark-groth16/src/dynark_generator.rs',
                      'experiments/dynark/vendor/DYNARK_/ark-groth16/src/dynark_prover.rs',
                      'experiments/dynark/vendor/DYNARK_/LICENSE-MIT',
                      'experiments/dynark/vendor/DYNARK_/LICENSE-APACHE']
        public['public_source_build_identity']=[]
        for relative in public_paths:
            sha,size,mode=digest(ROOT/relative)
            public['public_source_build_identity'].append({'path':relative,'sha256':sha,'bytes':size})
        lock_text=(ROOT/'experiments/dynark/proof-probe/Cargo.lock').read_text()
        dependencies=[]
        for block in lock_text.split('[[package]]')[1:]:
            name=re.search(r'^name = "([^"]+)"',block,re.M)
            version=re.search(r'^version = "([^"]+)"',block,re.M)
            if name and version and (name[1].startswith('ark-') or name[1] in
                    ['rand','rand_core','rayon','rayon-core','circom-scotia','serde','sha2']):
                dependencies.append({'name':name[1],'version':version[1]})
        public['resolved_probe_dependencies']=dependencies
        public['license_identity']={'reference_license_files':['LICENSE-MIT','LICENSE-APACHE'],
                                    'reference_declared_license':'MIT/Apache-2.0',
                                    'note':'Reference license hashes above; no license migration or vendoring performed'}
        public['approved_r1cs_hash_match']=digest(ROOT/'artifacts/circuit/credential.r1cs')[0]=='ff4ee937061ee60e4d4043f1213ff562f72e0828986462e8ebbec8cdfabb326d'
        pdf_entries=[{'path':'artifacts/dynark/phase-1/paper-review/2025-1897.pdf'}]
        public['paper_pdf']=[{'path':x['path'],'matches_approved_hash':digest(map_path(x['path']))[0]=='f851f11ed8ae8a6876dafe09373650098aa792b9f886019eea4d98060fa7b259'} for x in pdf_entries]
        vendor=ROOT/'experiments/dynark/vendor/DYNARK_'
        vendor_head=command(['git','rev-parse','HEAD'],vendor)
        public['vendor']={'head':vendor_head['stdout'],
             'matches_pin':vendor_head['stdout']=='c73a380df86d8f5d195f1e20c8a1d86a7dce084b',
             'status':command(['git','status','--short'],vendor)['stdout']}
        public['root_git']={'head':command(['git','rev-parse','HEAD'])['stdout'],
             'starting_commit':'0365566bc883f1a85e974da9f9156963847e026e',
             'starting_commit_is_ancestor':command(['git','merge-base','--is-ancestor','0365566','HEAD'])['exit_code']==0,
             'status':command(['git','status','--short'])['stdout']}
        public['versions']=[command(c) for c in [['python3','--version'],['git','--version'],
             ['rustc','--version'],['cargo','--version'],['node','--version']]]
        public['hardware']={'platform':platform.platform(),'machine':platform.machine(),
             'cpu_count':os.cpu_count(),'disk':dict(zip(['total_bytes','used_bytes','free_bytes'],shutil.disk_usage(ROOT)))}
        if sys.platform=='darwin':
            public['hardware']['native']=[command(['sysctl','-n',k]) for k in
                                         ['hw.model','hw.memsize','hw.ncpu']]
            public['hardware']['vm_stat']=command(['vm_stat'])
        public['clock']={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
             'local':datetime.datetime.now().astimezone().isoformat(),'timezone_names':time.tzname,
             'environment_TZ':os.environ.get('TZ')}
        # Do not inspect/log full command arguments: they could contain secrets.
        jobs=command(['ps','-axo','pid=,ppid=,pgid=,rss=,comm='])
        full['safe_process_inventory']=jobs
        relevant=[]
        for line in jobs['stdout'].splitlines():
            fields=line.split(maxsplit=4)
            if len(fields)==5 and any(n in Path(fields[4]).name for n in
                       ['cargo','rustc','phase1-baseline','phase1-profile','snarkjs','witness','dynark']):
                relevant.append({'pid':int(fields[0]),'ppid':int(fields[1]),
                        'pgid':int(fields[2]),'rss_bytes':int(fields[3])*1024,
                        'executable_basename':Path(fields[4]).name})
        public['active_relevant_jobs']=relevant
        public['active_job_scope']='Safe executable-name snapshot, no argv; T1 small tests may be present and belong to another owner'
        public['all_preservation_matches']=all(public[g]['all_match'] for g in groups)
        public['status']='complete' if public['all_preservation_matches'] and public['protected_modes']['all_match'] else 'mismatch'
    except Exception as error:
        public['status']='failed';public['error_type']=type(error).__name__
        full['failure_detail']=str(error)
    finally:
        public['duration_seconds']=time.monotonic()-START
        public['validator_lifetime_max_rss_bytes']=rss()
        public['unique_files_hashed']=len(CACHE)
        public['unique_file_logical_bytes_hashed']=sum(p.stat().st_size for p in CACHE)
        public['method']='SHA256 streamed1MiB, deduplicated by current path; no file content printed; private exact identities/mismatch paths protected; hash equality is not authentication'
        public['ended_at_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        full['summary']=public
        write_new(PRIVATE/(REPORT_NAME+'-private.json'),full,0o600)
        write_new(PUBLIC/(REPORT_NAME+'.json'),public,0o644)
    print(json.dumps({k:public.get(k) for k in ['status','all_preservation_matches','duration_seconds','validator_lifetime_max_rss_bytes','unique_files_hashed']}))
    return 0 if public['status']=='complete' else 1


if __name__=='__main__':
    raise SystemExit(main())
