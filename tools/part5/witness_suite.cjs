'use strict';
// Qualification only. ROOT's external monitor enforces aggregate RSS/wall/output.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {spawnSync} = require('node:child_process');
const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const PUBLIC = ['root','issuerHash','notBefore','notAfter','actionHash','policyHash'];
const WASM = 'fbf73cff59660574add16ba8acafe824a9d57e0c91f23557b6462979b85c9aa6';
const CALCULATOR = 'cc2d37b2cff2a589dd86f8636f1a1dc9fe4a854550b021aa0cea2e235d14e942';
const R1CS = '976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888';
function digest(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }
function canonicalInputs(inputs) {
    function check(value) {
        if (Array.isArray(value)) return value.forEach(check);
        if (typeof value!=='string' || !/^(0|[1-9][0-9]*)$/.test(value) || BigInt(value)>=FR)
            throw new Error('noncanonical-input-scalar');
    }
    Object.values(inputs).forEach(check);
}
function assertionRejection(error) {
    if (!String(error.message).includes('Assert Failed')) throw new Error('unexpected-witness-error');
    return 'circuit_assertion';
}
function loadCalculator(calculator,out) {
    if (digest(calculator)!==CALCULATOR) throw new Error('calculator-identity');
    const target=path.resolve(out,'witness_calculator.cjs');
    fs.writeFileSync(target,fs.readFileSync(calculator),{flag:'wx',mode:0o600});
    return require(target);
}
async function main() {
    if (process.argv.length!==8) throw new Error('usage: witness_suite.cjs COMPILE CORPUS_DIR OUTPUT PYTHON CHECKER R1CS');
    const [compile,corpusDir,out,python,checker,r1cs]=process.argv.slice(2);
    process.umask(0o077);
    if (fs.existsSync(out)) throw new Error('output-exists');
    fs.mkdirSync(out,{mode:0o700});
    const wasm=path.join(compile,'credential_js','credential.wasm');
    const calculator=path.join(compile,'credential_js','witness_calculator.js');
    if (digest(wasm)!==WASM || digest(r1cs)!==R1CS) throw new Error('compiled-artifact-identity');
    const manifestPath=path.join(corpusDir,'cases.json');
    if (fs.statSync(manifestPath).size>65536) throw new Error('manifest-size');
    const corpus=JSON.parse(fs.readFileSync(manifestPath,'utf8'));
    if (!Array.isArray(corpus) || corpus.length!==52 || corpus.filter(x=>x.expect==='accept').length!==18)
        throw new Error('expected-corpus-shape');
    const builder=loadCalculator(calculator,out);
    const wc=await builder(fs.readFileSync(wasm),{sanityCheck:true});
    const report={schema:'credential-v3-bounded-witness-qualification-v1',passed:false,
        r1cs_sha256:R1CS,wasm_sha256:WASM,host_admission_bypassed:true,
        setup_or_proofs_executed:false,outputs_private:true,cases:[]};
    const reportPath=path.join(out,'report.json');
    const save=()=>fs.writeFileSync(reportPath,JSON.stringify(report,null,2)+'\n',{mode:0o600});
    save();
    const seen=new Set();
    for (const item of corpus) {
        if (!/^[A-Za-z0-9_]+$/.test(item.name) || seen.has(item.name) || !['accept','reject'].includes(item.expect))
            throw new Error('case-envelope');
        seen.add(item.name);
        const inputPath=path.join(corpusDir,item.name+'.input.json');
        if (fs.statSync(inputPath).size>65536) throw new Error('input-size');
        const inputs=JSON.parse(fs.readFileSync(inputPath,'utf8'));
        canonicalInputs(inputs);
        const start=process.hrtime.bigint();
        let generated,rejection;
        try { generated=await wc.calculateWTNSBin(inputs,1); }
        catch(error) { rejection=assertionRejection(error); }
        const result={name:item.name,expected:item.expect,family:item.family,
            witness_elapsed_ms:Number(process.hrtime.bigint()-start)/1e6};
        if (item.expect==='reject') {
            result.rejection=rejection||'unexpected_acceptance';
            result.passed=Boolean(rejection);
        } else if (rejection) {
            result.rejection=rejection; result.passed=false;
        } else {
            const witness=path.join(out,item.name+'.wtns');
            const statement=path.join(out,item.name+'-public.json');
            fs.writeFileSync(witness,generated,{flag:'wx',mode:0o600});
            fs.writeFileSync(statement,JSON.stringify(PUBLIC.map(name=>inputs[name])),{flag:'wx',mode:0o600});
            const checkedAt=process.hrtime.bigint();
            const check=spawnSync(python,['-B',checker,'--check-witness',witness,'--r1cs',r1cs,
                '--expected-public',statement],{timeout:60000,maxBuffer:65536,encoding:'utf8'});
            if (check.error || check.signal || check.status!==0) {
                result.passed=false; result.rejection='full-r1cs-check-failed';
            } else {
                result.validation=JSON.parse(check.stdout);
                result.passed=result.validation.satisfied===true;
            }
            result.complete_relation_check_ms=Number(process.hrtime.bigint()-checkedAt)/1e6;
        }
        generated=undefined;
        report.cases.push(result); save();
        if (!result.passed) throw new Error('qualification-case-failed');
    }
    report.passed=true;
    report.accepted_count=report.cases.filter(x=>x.expected==='accept').length;
    report.rejected_count=report.cases.filter(x=>x.expected==='reject').length;
    save();
    console.log(JSON.stringify({passed:true,accepted_count:report.accepted_count,rejected_count:report.rejected_count}));
}
module.exports={canonicalInputs,assertionRejection,loadCalculator};
if (require.main===module) main().catch(()=>{
    console.error('v3 witness qualification failed; inspect protected finite report');
    process.exitCode=1;
});
