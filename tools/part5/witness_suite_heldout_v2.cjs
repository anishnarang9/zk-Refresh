'use strict';
// Source-only runner. Runtime use requires the separately authorized resource monitor.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {spawnSync} = require('node:child_process');
const REPO = path.resolve(__dirname, '../..');
const COMPILE = path.join(REPO, 'artifacts/dynark/part5/v3-compile-002');
const PINS = Object.freeze({
    wasm: 'fbf73cff59660574add16ba8acafe824a9d57e0c91f23557b6462979b85c9aa6',
    calculator: 'cc2d37b2cff2a589dd86f8636f1a1dc9fe4a854550b021aa0cea2e235d14e942',
    r1cs: '976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888',
});
const PUBLIC = ['root','issuerHash','notBefore','notAfter','actionHash','policyHash'];
const ARRAYS = {tbs:672, issuerModulus:17, issuerSignature:17, holderSignature:17, siblings:10, pathIndices:10};
const NAMES = Array.from({length:8}, (_, i) => [`holdout_${i}`, `holdout_${i}_unrelated_refresh`]).flat();
const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const JSON_CAP = 65536, COMPILE_CAP = 512*1024*1024, WTNS_CAP = 32*1024*1024;
function exact(value, keys) {
    if (!value || typeof value !== 'object' || Array.isArray(value) ||
        Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')) throw Error('exact-fields');
}
function parseJSON(raw) {
    // Parse first for grammar; scan the same tokens to reject duplicate object keys.
    const value = JSON.parse(raw);
    const tokens = raw.match(/"(?:[^"\\]|\\.)*"|[{}\[\]:,]|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/g);
    let i=0;
    function walk(depth) {
        if (depth>8) throw Error('json-depth');
        const token=tokens[i++];
        if (token==='{') {
            const seen=new Set();
            if (tokens[i]==='}') { i++; return; }
            do {
                const key=JSON.parse(tokens[i++]);
                if (seen.has(key)) throw Error('duplicate-json-field');
                seen.add(key); i++; walk(depth+1);
            } while(tokens[i++ ]===',');
        } else if(token==='[') {
            if(tokens[i]===']') { i++; return; }
            do { walk(depth+1); } while(tokens[i++]===',');
        }
    }
    walk(0);
    return value;
}
function directory(p) {
    const s=fs.lstatSync(p);
    if (!path.isAbsolute(p) || fs.realpathSync(p)!==p || !s.isDirectory() ||
        s.uid!==process.getuid() || (s.mode&0o777)!==0o700) throw Error('private-directory');
}
function read(p, cap, privateFile=true) {
    if (!path.isAbsolute(p) || fs.realpathSync(p)!==p) throw Error('canonical-file');
    const before=fs.lstatSync(p);
    if(!before.isFile() || before.nlink!==1 || before.uid!==process.getuid() ||
       ![...(privateFile?[0o600]:[0o600,0o644])].includes(before.mode&0o777) ||
       before.size<=0 || before.size>cap) throw Error('bounded-owner-file');
    const fd=fs.openSync(p, fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
    try {
        const opened=fs.fstatSync(fd), raw=Buffer.alloc(before.size);
        if(opened.ino!==before.ino || opened.dev!==before.dev) throw Error('file-replaced');
        let offset=0;
        while(offset<raw.length) {
            const n=fs.readSync(fd,raw,offset,raw.length-offset,null);
            if(!n) throw Error('short-file'); offset+=n;
        }
        const after=fs.fstatSync(fd), current=fs.lstatSync(p);
        for(const key of ['dev','ino','size','mtimeMs','ctimeMs'])
            if(before[key]!==after[key] || before[key]!==current[key]) throw Error('file-changed');
        return raw;
    } finally { fs.closeSync(fd); }
}
function identity(p, pin) {
    const raw=read(p,COMPILE_CAP);
    if(crypto.createHash('sha256').update(raw).digest('hex')!==pin) throw Error('compiled-artifact-identity');
    return raw;
}
function canonicalInputs(inputs) {
    exact(inputs,[...PUBLIC,'layout','slot',...Object.keys(ARRAYS)]);
    function scalar(v) {
        if(typeof v!=='string' || v.length>77 || !/^(0|[1-9][0-9]*)$/.test(v) || BigInt(v)>=FR)
            throw Error('noncanonical-input-scalar');
    }
    for(const key of [...PUBLIC,'layout','slot']) scalar(inputs[key]);
    for(const [key,count] of Object.entries(ARRAYS)) {
        if(!Array.isArray(inputs[key]) || inputs[key].length!==count) throw Error('input-array-shape');
        inputs[key].forEach(scalar);
    }
}
function manifest(cases) {
    if(!Array.isArray(cases) || cases.length!==16) throw Error('sixteen-accepted-cases');
    const seen=new Set();
    for(const item of cases) {
        exact(item,['name','expect','family']);
        if(!NAMES.includes(item.name) || seen.has(item.name) || item.expect!=='accept' ||
            typeof item.family!=='string' || !/^[A-Za-z0-9_-]{1,80}$/.test(item.family)) throw Error('heldout-case-envelope');
        seen.add(item.name);
    }
    return NAMES.map(name=>cases.find(item=>item.name===name));
}
function census(v) {
    exact(v,['satisfied','constraints_checked','assignment_fields','matrix_entries','max_row_terms']);
    if(v.satisfied!==true || v.constraints_checked!==793681 || v.assignment_fields!==784796 ||
       v.matrix_entries!==4257583 || !Number.isInteger(v.max_row_terms) || v.max_row_terms<0 || v.max_row_terms>4096)
        throw Error('complete-relation-census');
    return v;
}
function write(p, raw, fresh=true) {
    if(raw.length>JSON_CAP && !p.endsWith('.wtns')) throw Error('json-output-bound');
    fs.writeFileSync(p,raw,{flag:fresh?'wx':'w',mode:0o600});
}
async function main(args=process.argv.slice(2)) {
    if(args.length!==6) throw Error('usage: witness_suite_heldout_v2.cjs COMPILE INPUT_ROOT OUTPUT PYTHON CHECKER R1CS');
    const [compile,input,out,python,checker,r1cs]=args;
    process.umask(0o077);
    directory(input); directory(path.dirname(out));
    if(!path.isAbsolute(out) || path.resolve(out)!==out || fs.existsSync(out) ||
       fs.realpathSync(path.dirname(out))!==path.dirname(out)) throw Error('fresh-canonical-output');
    fs.mkdirSync(out,{mode:0o700}); directory(out);
    const report={schema:'credential-v3-bounded-witness-qualification-v1',passed:false,
        r1cs_sha256:PINS.r1cs,wasm_sha256:PINS.wasm,host_admission_bypassed:true,
        setup_or_proofs_executed:false,outputs_private:true,cases:[],accepted_count:0,rejected_count:0};
    const reportPath=path.join(out,'report.json');
    const save=()=>write(reportPath,JSON.stringify(report,null,2)+'\n',false);
    save();
    try {
        if(compile!==COMPILE || r1cs!==path.join(COMPILE,'credential.r1cs') ||
           checker!==path.join(REPO,'tools/part5/witness_check.py')) throw Error('exact-v2-artifact-paths');
        directory(compile); directory(path.join(compile,'credential_js'));
        const cases=manifest(parseJSON(read(path.join(input,'cases.json'),JSON_CAP).toString('utf8')));
        const expectedFiles=new Set(['cases.json',...NAMES.map(n=>n+'.input.json')]);
        const entries=fs.readdirSync(input);
        if(entries.length!==expectedFiles.size || entries.some(n=>!expectedFiles.has(n))) throw Error('exact-input-directory-entries');
        const inputs=new Map(cases.map(item=>{
            const v=parseJSON(read(path.join(input,item.name+'.input.json'),JSON_CAP).toString('utf8'));
            canonicalInputs(v); return [item.name,v];
        }));
        const wasm=identity(path.join(compile,'credential_js/credential.wasm'),PINS.wasm);
        identity(r1cs,PINS.r1cs);
        const calculator=identity(path.join(compile,'credential_js/witness_calculator.js'),PINS.calculator);
        const calculatorPath=path.join(out,'witness_calculator.cjs');
        write(calculatorPath,calculator);
        const wc=await require(calculatorPath)(wasm,{sanityCheck:true});
        for(const item of cases) {
            const values=inputs.get(item.name), start=process.hrtime.bigint();
            const result={name:item.name,expected:'accept',family:item.family,passed:false,witness_elapsed_ms:0};
            report.cases.push(result); save();
            let generated;
            try { generated=await wc.calculateWTNSBin(values,1); }
            finally { result.witness_elapsed_ms=Number(process.hrtime.bigint()-start)/1e6; save(); }
            if(!(generated instanceof Uint8Array) || generated.length<=0 || generated.length>WTNS_CAP) throw Error('bounded-wtns');
            const witness=path.join(out,item.name+'.wtns'), statement=path.join(out,item.name+'-public.json');
            write(witness,generated); generated=undefined;
            write(statement,JSON.stringify(PUBLIC.map(n=>values[n]))+'\n');
            const checkedAt=process.hrtime.bigint();
            const check=spawnSync(python,['-B',checker,'--check-witness',witness,'--r1cs',r1cs,'--expected-public',statement],
                {timeout:60000,maxBuffer:JSON_CAP,encoding:'utf8'});
            result.complete_relation_check_ms=Number(process.hrtime.bigint()-checkedAt)/1e6;
            if(check.error || check.signal || check.status!==0) throw Error('full-r1cs-check-failed');
            result.validation=census(parseJSON(check.stdout)); result.passed=true;
            report.accepted_count++; save();
        }
        report.passed=true; save();
        console.log(JSON.stringify({passed:true,accepted_count:16,rejected_count:0}));
    } catch(error) { report.passed=false; save(); throw error; }
}
module.exports={manifest,canonicalInputs,census,parseJSON,read,identity,directory,PINS,NAMES,main};
if(require.main===module) main().catch(()=>{
    console.error('heldout-v2 witness qualification failed; inspect protected finite report');
    process.exitCode=1;
});
