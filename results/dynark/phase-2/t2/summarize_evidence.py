#!/usr/bin/env python3
"""Scrubbed T2 correctness identities from fixed synthetic fixture/test output."""
from pathlib import Path
import hashlib, json, re, stat, subprocess, tomllib
ROOT = Path(__file__).resolve().parents[4]
OUT = ROOT / 'results/dynark/phase-2/t2'
PRIVATE = ROOT / 'artifacts/dynark/phase-2/t2/final-small-gate-v3'
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2) + '\n')
stdout = (PRIVATE / 'stdout.log').read_text()
stderr = (PRIVATE / 'stderr.log').read_text()
runner = json.loads((OUT / 'final-small-gate-v3.json').read_text())
assert runner['passed'] and runner['exit_code'] == 0
counts = [int(x) for x in re.findall(r'test result: ok\. (\d+) passed;', stdout)]
assert counts == [6, 2, 3, 12]
files = []
for path in sorted((ROOT / 'crates/dynark-bn254').rglob('*')):
    if not path.is_file() or 'target' in path.relative_to(ROOT).parts or path.name == '.DS_Store':
        continue
    files.append({'path':str(path.relative_to(ROOT)), 'sha256':sha(path), 'bytes':path.stat().st_size})
source_digest = hashlib.sha256(''.join(f"{x['path']}\0{x['sha256']}\n" for x in files).encode()).hexdigest()
binaries = []
for name in re.findall(r'^\s+Running .*? \((crates/[^)]+)\)', stderr, re.M):
    path = ROOT / name
    binaries.append({'path':name, 'sha256':sha(path), 'bytes':path.stat().st_size})
assert len(binaries) == 4
fixtures = []
for line in stdout.splitlines():
    if line.startswith('T2_FIXTURE '):
        data = dict(piece.split('=', 1) for piece in line.split()[1:])
        for key in ['v', 'rows', 'k', 'N']: data[key] = int(data[key])
        fixtures.append(data)
assert len(fixtures) == 4
old = json.loads((ROOT / 'results/dynark/phase-2/t1/identities.json').read_text())
old_files = {x['path']: x['sha256'] for x in old['files']}
unchanged = [x for x in files if '/vendor/' in x['path'] or x['path'].endswith(('Cargo.lock','Cargo.toml','src/full.rs','src/randomness.rs','tests/full_conformance.rs'))]
assert all(x['sha256'] == old_files[x['path']] for x in unchanged)
lock = tomllib.loads((ROOT/'crates/dynark-bn254/Cargo.lock').read_text())
save('identities.json', {
    'root_head_at_report':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
    'reference_pin':subprocess.check_output(['git','-C','experiments/dynark/vendor/DYNARK_','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
    'source_digest_convention':'SHA256(sorted path + NUL + file SHA256 + newline), entire product crate excluding target and .DS_Store; includes separately owned T3 bin as context',
    'source_tree_digest':source_digest, 'files':files, 'test_executables':binaries,
    'resolved_packages':[{'name':x['name'],'version':x['version'],'source':x.get('source','local')} for x in lock['package']],
    'same_as_accepted_t1_manifest':{'verified_file_count':len(unchanged),'all_unchanged':True},
    'synthetic_fixtures':fixtures,
    'fixture_limits':'tiny public relation; setup StdRng seed82, test-only explicit base r13/s19 target r23/s29. Descriptor r1cs/witness/profile tags are placeholders, not authenticated executables or artifacts. Matrix/circuit/PK/VK/package digests identify actual runtime fixture objects.',
    'content_identity_not_authentication':True})
time = re.search(r'([0-9.]+) real\s+([0-9.]+) user\s+([0-9.]+) sys',stderr)
assert time
trial_notes = {
    'red-1':'Expected missing new API compile failure before implementation.',
    'gate-1':'Compile failure: ZERO trait import; no arithmetic gate ran.',
    'gate-2':'Compile failure in independent schoolbook oracle borrow; no runtime gate.',
    'gate-3':'Algebra/snapshot/randomized tests passed; delta fixture expected3/2/1 was incorrect. Row3 also touched, corrected to4/3/2; parent independently confirmed.',
    'gate-4':'Initial20tests passed.', 'gate-5':'22tests passed after received-snapshot/section bounds and fused cross scheduling.',
    'gate-6':'22tests rerun on gate5 source after a local text-edit script failed to match a formatted line; no new gate claim.',
    'gate-7':'22tests passed including explicit audit import route and bounded LimitedFile.',
    'final-small-gate':'23tests passed including complete binding negatives.',
    'final-small-gate-v2':'23tests passed after fixed-reader/counts temporary vector accounting.',
    'final-small-gate-v3':'23tests passed on final frozen source/docs.'}
trials = []
for name, note in trial_notes.items():
    report=json.loads((OUT/f'{name}.json').read_text())
    trials.append({'report':f'results/dynark/phase-2/t2/{name}.json','passed':report['passed'],'exit_code':report['exit_code'],'stop_reason':report['stop_reason'],'wall_runner_seconds':report['duration_seconds'],'sample_count':report['sample_count'],'sampled_peak_tree_rss_bytes':report['sampled_peak_owned_tree_rss_bytes'],'sampled_peak_storage_growth_bytes':report['sampled_peak_storage_growth_bytes'],'note':note})
modes = {'directories_700':all(stat.S_IMODE(p.stat().st_mode)==0o700 for p in (ROOT/'artifacts/dynark/phase-2/t2').rglob('*') if p.is_dir()),'files_600':all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in (ROOT/'artifacts/dynark/phase-2/t2').rglob('*') if p.is_file())}
assert all(modes.values())
save('small-gate-summary.json', {
    'status':'small_correctness_gate_passed_pending_independent_review_and_credential_authorization',
    'source_tree_digest':source_digest, 'gate':'results/dynark/phase-2/t2/final-small-gate-v3.json',
    'counts':{'library':6,'anchored_integration':2,'delta_import':3,'unchanged_t1':12,'total':23},
    'command':['/usr/bin/time','-l','cargo','test','--locked','--manifest-path','crates/dynark-bn254/Cargo.toml','--lib','--test','delta_contract','--test','anchored_conformance','--test','full_conformance','--','--nocapture'],
    'environment':{'RAYON_NUM_THREADS':'4','CARGO_BUILD_JOBS':'2'},
    'limits':runner['limits'], 'metrics':{
        'runner_wall_seconds':runner['duration_seconds'],'child_time_wall_seconds':float(time[1]),
        'child_time_user_cpu_seconds':float(time[2]),'child_time_system_cpu_seconds':float(time[3]),
        'child_time_cpu_total_seconds':float(time[2])+float(time[3]),
        'sampled_owned_process_tree_peak_rss_bytes':runner['sampled_peak_owned_tree_rss_bytes'],
        'bsd_time_maximum_resident_set_size_bytes':int(re.search(r'(\d+)\s+maximum resident set size',stderr)[1]),
        'sampled_positive_logical_storage_growth_bytes':runner['sampled_peak_storage_growth_bytes'],
        'sample_count':runner['sample_count'],'heap_allocation_measurement':None},
    'metric_limits':'Whole build+tests correctness run; CPU includes compile/tests. ps sampled live-tree RSS sums shared pages and excludes runner/ps; BSD time RSS is a distinct OS rusage measure. Storage positive logical growth includes target+private logs, excludes original target baseline and can miss deleted-file peaks. Structural bounds exclude allocator metadata/fragmentation. No performance or credential-scale claim.',
    'algebra':'4 shapes x6 satisfying pairs. Exact schoolbook polynomial quotient/remainder plus encoded qA/qB/diagonal/cross/quotient-change, and common test-r/s A/B1/B2/C equality. Separate randomized ordinary verifier checks. Includes private-only t/product and unused auxiliary for v>N.',
    'cross_work':'One fused |dA|*|dB| field-pair loop;2*(pairs-diagonal_overlap) weight terms; |dA|+|dB|+diagonal_overlap group scalar multiplication calls. Counts are structural source work, not measured curve operations. Explicit pair cap; no hidden full fallback.',
    'security':'Caller entropy/setup provenance/legacy context association are external. Legacy expected digests authenticate only externally trusted content, not absent credential/action/generation labels or ceremony honesty. New action binding requires new anchor. No deterministic/raw-blinder successful public proof API, no credential-scale loading/setup/proof, no T4/T5/T6 promotion.',
    'private_output_modes':modes,'trials':trials})
print(json.dumps({'tests':sum(counts),'source_tree_digest':source_digest,'runner_wall_seconds':runner['duration_seconds'],'sampled_tree_rss_bytes':runner['sampled_peak_owned_tree_rss_bytes'],'storage_growth_bytes':runner['sampled_peak_storage_growth_bytes'],'cpu_total_seconds':float(time[2])+float(time[3]),'private_modes':modes}))
