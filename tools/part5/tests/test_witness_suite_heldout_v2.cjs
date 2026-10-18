'use strict';
// Only tiny fixtures and rejected CLI preflight paths; never instantiate real WASM.
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const suite=require('../witness_suite_heldout_v2.cjs');
const cases=()=>suite.NAMES.map(name=>({name,expect:'accept',family:'synthetic'}));
function input() {
    return Object.fromEntries([
        ...['root','issuerHash','notBefore','notAfter','actionHash','policyHash','layout','slot'].map(n=>[n,'0']),
        ...Object.entries({tbs:672,issuerModulus:17,issuerSignature:17,holderSignature:17,siblings:10,pathIndices:10})
            .map(([n,count])=>[n,Array(count).fill('0')]),
    ]);
}
function fixture(fn) {
    const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'heldout-suite-'))); fs.chmodSync(root,0o700);
    return Promise.resolve().then(()=>fn(root)).finally(()=>fs.rmSync(root,{recursive:true,force:true}));
}
test('exact sixteen accepted pair names and canonical order',()=>{
    assert.deepEqual(suite.manifest(cases().reverse()).map(v=>v.name),suite.NAMES);
    for(const mutate of [v=>v.pop(),v=>v.push(v[0]),v=>v[0].expect='reject',
        v=>v[0].name='holdout_8',v=>v[1].name=v[0].name,v=>v[0].extra=true,
        v=>v[0].family='',v=>v[0].name='../escape']) {
        const value=cases(); mutate(value); assert.throws(()=>suite.manifest(value));
    }
});
test('strict field scalar and array input schema',()=>{
    suite.canonicalInputs(input());
    for(const mutate of [v=>v.extra='0',v=>delete v.root,v=>v.root=0,v=>v.root='01',
        v=>v.root='-1',v=>v.root='21888242871839275222246405745257275088548364400416034343698204186575808495617',
        v=>v.tbs.pop(),v=>v.siblings[0]=null,v=>v.layout=['0']]) {
        const v=input(); mutate(v); assert.throws(()=>suite.canonicalInputs(v));
    }
});
test('duplicate JSON fields including escaped names rejected',()=>{
    assert.deepEqual(suite.parseJSON('{"a":[{"b":"x"}]}'),{a:[{b:'x'}]});
    for(const raw of ['{"a":1,"a":2}','{"a":{"b":1,"b":2}}','{"a":1,"\\u0061":2}', '{"a":NaN}'])
        assert.throws(()=>suite.parseJSON(raw));
});
test('exact full relation census required',()=>{
    const good={satisfied:true,constraints_checked:793681,assignment_fields:784796,matrix_entries:4257583,max_row_terms:64};
    assert.deepEqual(suite.census(good),good);
    for(const patch of [{satisfied:false},{constraints_checked:1},{assignment_fields:1},{matrix_entries:1},
        {max_row_terms:4097},{max_row_terms:1.5},{extra:1}]) assert.throws(()=>suite.census({...good,...patch}));
});
test('small artifact identity and file boundaries reject',()=>fixture(root=>{
    const file=path.join(root,'small'); fs.writeFileSync(file,'tiny',{mode:0o600});
    assert.throws(()=>suite.identity(file,suite.PINS.wasm),/identity/);
    assert.throws(()=>suite.read(file,3),/bounded/);
    fs.chmodSync(file,0o644); assert.throws(()=>suite.read(file,100),/bounded/);
    fs.chmodSync(file,0o600); const link=path.join(root,'link'); fs.symlinkSync(file,link);
    assert.throws(()=>suite.read(link,100),/canonical/);
    fs.unlinkSync(link); fs.linkSync(file,link); assert.throws(()=>suite.read(file,100),/bounded/);
}));
test('invalid compile path preserves private failed report and retry cannot overwrite',()=>fixture(async root=>{
    const inputRoot=path.join(root,'input'), out=path.join(root,'out'); fs.mkdirSync(inputRoot,{mode:0o700});
    await assert.rejects(suite.main(['/wrong',inputRoot,out,'python3','/wrong','/wrong']),/exact-v2/);
    const reportPath=path.join(out,'report.json'), before=fs.readFileSync(reportPath);
    const report=JSON.parse(before); assert.equal(report.passed,false); assert.equal(report.accepted_count,0);
    assert.equal(fs.statSync(out).mode&0o777,0o700); assert.equal(fs.statSync(reportPath).mode&0o777,0o600);
    await assert.rejects(suite.main(['/wrong',inputRoot,out,'python3','/wrong','/wrong']),/fresh/);
    assert.deepEqual(fs.readFileSync(reportPath),before);
}));
