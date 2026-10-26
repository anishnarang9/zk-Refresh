"""Prepare a private, ROOT-pinned v3 proof packet; no witness/proof generation.

Every original input scalar is matched to a complete WTNS coordinate using the
one frozen compiler symbol map. Credential/action identities are derived again
by the Rust runner after complete relation validation, never trusted as labels.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from tools.part5 import credential_profile as p

FR=p.FR
PUBLIC_NAMES=p.PUBLIC_NAMES
ARRAYS=[('tbs',672),('issuerModulus',17),('issuerSignature',17),('holderSignature',17),('siblings',10),('pathIndices',10)]
ASSIGNMENT_FIELDS=784796
REPO=Path(__file__).resolve().parents[2]
SETUP_SHA='d31f82e3f147e31b30074b3a570a9d7945c5e1f5d3f3dd74172801abbe984918'
PACKAGE_REPORT_SHA='4a8d521fc0890d10878932c67f39629b673dc4f537082b167c4f873bb0212c81'
PACKAGE_SHA='61d941890d823433468048dd1bd91da80c1bf7e1b3d2b6f5d509077a47ed06c8'
SYMBOLS_SHA='d2d66e238bdc0a731c86c1897c2978d23908dcc19460582cc873dc2d41e5dbf0'
R1CS_SHA='976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888'
WASM_SHA='fbf73cff59660574add16ba8acafe824a9d57e0c91f23557b6462979b85c9aa6'
TRAINING_REPORT_SHA='1878dff43be66019b077c1398805e044e659238b6e74800904e66c803241d044'


def required_symbols():
    result=['main.'+x for x in PUBLIC_NAMES+['layout','slot']]
    for name,count in ARRAYS:result.extend(f'main.{name}[{i}]' for i in range(count))
    return result


def scalar(value):
    if type(value) is not str or not re.fullmatch(r'0|[1-9][0-9]*',value) or len(value)>77 or int(value)>=FR:
        raise ValueError('noncanonical scalar input')
    return int(value)


def flatten_inputs(inputs):
    if type(inputs) is not dict or set(inputs)!=set(PUBLIC_NAMES+['layout','slot']+[x[0] for x in ARRAYS]):
        raise ValueError('exact input keys required')
    out={'main.'+key:scalar(inputs[key]) for key in PUBLIC_NAMES+['layout','slot']}
    for key,count in ARRAYS:
        if type(inputs[key]) is not list or len(inputs[key])!=count:raise ValueError('input array shape')
        out.update({f'main.{key}[{i}]':scalar(value) for i,value in enumerate(inputs[key])})
    return out


def map_from_lines(lines):
    wanted=set(required_symbols());out={};seen=set()
    for line in lines:
        fields=line.rstrip('\n').split(',',3)
        if len(fields)!=4:raise ValueError('compiler symbol line')
        name=fields[3]
        if name not in wanted:continue
        index=int(fields[1])
        if name in out or not 0<index<ASSIGNMENT_FIELDS or index in seen:raise ValueError('ambiguous/eliminated input coordinate')
        out[name]=index;seen.add(index)
    if set(out)!=wanted or any(out['main.'+name]!=i for i,name in enumerate(PUBLIC_NAMES,1)):
        raise ValueError('complete input map and exact public order required')
    return out


def received(path,cap,expected=None,retain=True,private=True):
    path=Path(path)
    before=path.lstat()
    if (not stat.S_ISREG(before.st_mode) or path.is_symlink() or before.st_uid!=os.getuid()
        or stat.S_IMODE(before.st_mode) not in ((0o600,) if private else (0o600,0o644)) or before.st_size>cap):
        raise ValueError('artifact type/owner/mode/size')
    digest=hashlib.sha256();parts=[];count=0
    with path.open('rb') as source:
        opened=os.fstat(source.fileno())
        if (opened.st_ino,opened.st_dev)!=(before.st_ino,before.st_dev):raise ValueError('artifact open changed')
        while chunk:=source.read(1024*1024):
            count+=len(chunk)
            if count>cap:raise ValueError('artifact grew beyond bound')
            digest.update(chunk)
            if retain:parts.append(chunk)
        after=os.fstat(source.fileno())
    if (count,after.st_size,after.st_mtime_ns)!=(before.st_size,before.st_size,before.st_mtime_ns):raise ValueError('artifact changed while reading')
    sha=digest.hexdigest()
    if expected is not None and sha!=expected:raise ValueError('trusted artifact digest mismatch')
    return sha,b''.join(parts)


def verify_wtns_input_link(path,flat,mapping,expected_count=ASSIGNMENT_FIELDS):
    with Path(path).open('rb') as source:
        header=source.read(76)
        expected=(b'wtns'+(2).to_bytes(4,'little')+(2).to_bytes(4,'little')+(1).to_bytes(4,'little')+
            (40).to_bytes(8,'little')+(32).to_bytes(4,'little')+FR.to_bytes(32,'little')+
            expected_count.to_bytes(4,'little')+(2).to_bytes(4,'little')+(32*expected_count).to_bytes(8,'little'))
        if header!=expected or os.fstat(source.fileno()).st_size!=76+32*expected_count:raise ValueError('canonical WTNS header/size')
        if int.from_bytes(source.read(32),'little')!=1:raise ValueError('constant one')
        if set(flat)!=set(mapping):raise ValueError('input map completeness')
        for name,index in mapping.items():
            if not 0<index<expected_count:raise ValueError('input witness coordinate')
            source.seek(76+32*index)
            if int.from_bytes(source.read(32),'little')!=flat[name]:raise ValueError('input-to-WTNS coordinate mismatch')


def write_json(path,value):
    encoded=(json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
    if len(encoded)>65536:raise ValueError('private JSON envelope bound')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as target:target.write(encoded);target.flush();os.fsync(target.fileno())


def prepare(args):
    if args.private_out.exists():raise FileExistsError('fresh private output required')
    _,raw=received(args.assignments,65536,args.assignments_sha)
    assignments=json.loads(raw)
    if assignments.get('schema')!='credential-v3-bounded-private-assignments-v1' or assignments.get('synthetic_only') is not True:
        raise ValueError('private assignments schema')
    rows=assignments['assignments'];by_name={item['name']:item for item in rows}
    if len(by_name)!=len(rows) or not 2<=len(rows)<=32 or len(rows)%2:raise ValueError('bounded unique assignment pairs')
    prefix='credential' if args.cohort=='training-v1' else 'holdout'
    n=len(rows)//2
    if args.cohort=='training-v1' and n!=9:raise ValueError('exact nine training pairs')
    names=[f'{prefix}_{i}' for i in range(n)]
    if set(by_name)!={name+suffix for name in names for suffix in ('','_unrelated_refresh')}:raise ValueError('exact cohort names')
    report_path=Path(assignments['accepted_suite_path']).absolute()
    report_sha,raw=received(report_path,65536,assignments['accepted_suite_sha256'])
    report=json.loads(raw)
    if args.cohort=='training-v1' and report_sha!=TRAINING_REPORT_SHA:raise ValueError('original training relation receipt')
    if report.get('passed') is not True or report.get('r1cs_sha256')!=R1CS_SHA or report.get('wasm_sha256')!=WASM_SHA:
        raise ValueError('accepted exact relation receipt')
    accepted={case['name'] for case in report['cases'] if case['expected']=='accept' and case['passed'] is True}
    if accepted!=set(by_name):raise ValueError('accepted report assignment names')
    frozen=None
    if args.cohort=='heldout-v1':
        if not args.freeze_receipt or not args.freeze_sha:raise ValueError('heldout freeze receipt required')
        _,raw=received(args.freeze_receipt,65536,args.freeze_sha)
        frozen=json.loads(raw)
        if (frozen.get('schema')!='credential-v3-frozen-holdout-boundary-v1' or frozen.get('setup_manifest_sha256')!=SETUP_SHA
            or frozen.get('package_digest')!=PACKAGE_SHA or type(frozen.get('frozen_at_unix_ns')) is not int
            or frozen.get('input_preparer_sha256')!=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()):
            raise ValueError('heldout freeze context')
    compile_root=REPO/'artifacts/dynark/part5/v3-compile-001'
    symbols=compile_root/'credential.sym'
    received(symbols,256*1024*1024,SYMBOLS_SHA,False,False)
    with symbols.open() as source:mapping=map_from_lines(source)
    received(symbols,256*1024*1024,SYMBOLS_SHA,False,False)
    pairs=[]
    for name in names:
        pair={'name':name}
        for role,suffix,version in [('base','',1),('near','_unrelated_refresh',2)]:
            label=name+suffix;row=by_name[label]
            wtns=Path(row['wtns_path']).absolute();public=Path(row['public_path']).absolute()
            if wtns!=report_path.parent/(label+'.wtns') or public!=report_path.parent/(label+'-public.json'):
                raise ValueError('exact protected witness paths')
            received(wtns,32*1024*1024,row['wtns_sha256'],False)
            _,raw=received(public,65536,row['public_sha256']);expected_public=json.loads(raw)
            input_path=(args.input_root/(label+'.input.json')).absolute()
            input_sha,raw=received(input_path,65536)
            inputs=json.loads(raw);flat=flatten_inputs(inputs)
            if expected_public!=[inputs[k] for k in PUBLIC_NAMES]:raise ValueError('exact input public values')
            verify_wtns_input_link(wtns,flat,mapping)
            if frozen and input_path.stat().st_ctime_ns<=frozen['frozen_at_unix_ns']:raise ValueError('heldout inputs precede freeze')
            # Host parsing rejects out-of-profile bytes too; circuit validation is
            # still the authority, and native proof admission checks every row.
            p.parse_tbs(bytes(int(x) for x in inputs['tbs']))
            pair[role]={**row,'wtns_path':str(wtns),'public_path':str(public),
                'input_path':str(input_path),'input_sha256':input_sha,'root_version':version,
                'issuer_version':1,'policy_version':1,'allocation_epoch':1}
        pairs.append(pair)
    setup=REPO/'artifacts/dynark/part5/v3-development-setup-001/setup-manifest.json'
    package_report=REPO/'artifacts/dynark/part5/v3-package-check-001/package-check-report.json'
    received(setup,65536,SETUP_SHA);received(package_report,65536,PACKAGE_REPORT_SHA)
    args.private_out.mkdir(parents=True,mode=0o700)
    map_path=args.private_out/'symbol-input-map.json'
    write_json(map_path,{'schema':'credential-v3-bounded-input-wire-map-v1','symbols_sha256':SYMBOLS_SHA,
        'assignment_fields':ASSIGNMENT_FIELDS,'coordinates':mapping})
    map_sha=hashlib.sha256(map_path.read_bytes()).hexdigest()
    packet={'schema':'credential-v3-bounded-proof-contexts-v1','synthetic_only':True,'cohort':args.cohort,
        'package_digest':PACKAGE_SHA,'input_preparer_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'setup_manifest_path':str(setup),'setup_manifest_sha256':SETUP_SHA,
        'package_check_path':str(package_report),'package_check_sha256':PACKAGE_REPORT_SHA,
        'r1cs_path':str(compile_root/'credential.r1cs'),'wasm_path':str(compile_root/'credential_js/credential.wasm'),
        'profile_path':str(REPO/'circuits/credential-v3-bounded/profile.json'),
        'input_map_path':str(map_path.absolute()),'input_map_sha256':map_sha,'pairs':pairs,
        'pilot_pair':'credential_8' if args.cohort=='training-v1' else names[0]}
    if frozen:packet.update(freeze_receipt_path=str(args.freeze_receipt.absolute()),freeze_receipt_sha256=args.freeze_sha)
    write_json(args.private_out/'packet.json',packet)
    # Safe summary; no credential fingerprints, assignments or private values.
    print(json.dumps({'proof_packet_prepared':True,'pairs':n,'cohort':args.cohort,'proofs_executed':False}))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assignments',type=Path,required=True)
    parser.add_argument('--assignments-sha',required=True)
    parser.add_argument('--input-root',type=Path,required=True)
    parser.add_argument('--private-out',type=Path,required=True)
    parser.add_argument('--cohort',choices=['training-v1','heldout-v1'],required=True)
    parser.add_argument('--freeze-receipt',type=Path)
    parser.add_argument('--freeze-sha')
    args=parser.parse_args()
    args.input_root=args.input_root.absolute();args.private_out=args.private_out.absolute()
    prepare(args)
if __name__=='__main__':main()
