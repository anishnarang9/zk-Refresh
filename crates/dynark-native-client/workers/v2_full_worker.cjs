'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const SHAPE = {root:0,issuerHash:0,notBefore:0,notAfter:0,actionHash:0,tbs:656,issuerModulus:17,issuerSignature:17,holderSignature:17,slot:0,siblings:10,pathIndices:10};
function scalar(value, bound = FR) {
    if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value) || value.length > 77 || BigInt(value) >= bound) throw new Error('input');
}
function validateInput(input) {
    if (!input || Array.isArray(input) || typeof input !== 'object' || Object.keys(input).length !== Object.keys(SHAPE).length) throw new Error('shape');
    for (const [key, length] of Object.entries(SHAPE)) {
        if (!Object.hasOwn(input, key)) throw new Error('shape');
        const bound = key === 'tbs' ? 256n : key === 'pathIndices' ? 2n : key === 'slot' ? 1024n : /Modulus|Signature/.test(key) ? (1n << 121n) : FR;
        if (length) {
            if (!Array.isArray(input[key]) || input[key].length !== length) throw new Error('shape');
            input[key].forEach(value => scalar(value, bound));
        } else scalar(input[key], bound);
    }
}
function readPinned(filename, expected, maximum) {
    const meta=fs.lstatSync(filename);
    if (!meta.isFile() || meta.size > maximum) throw new Error('artifact');
    const bytes=fs.readFileSync(filename);
    if (bytes.length > maximum || crypto.createHash('sha256').update(bytes).digest('hex') !== expected) throw new Error('artifact');
    return bytes;
}
async function main() {
    if (process.argv.length !== 5) throw new Error('invocation');
    const [directory, wasm, calculator]=process.argv.slice(2);
    if (![directory,wasm,calculator].every(path.isAbsolute)) throw new Error('path');
    process.umask(0o077);
    const bytes=fs.readFileSync(path.join(directory,'target.json'));
    if (!bytes.length || bytes.length > 65536) throw new Error('input');
    let input;
    try { input=JSON.parse(bytes.toString('utf8')); validateInput(input); }
    catch (_) { process.exitCode=2; return; }
    const source=readPinned(calculator,'cc2d37b2cff2a589dd86f8636f1a1dc9fe4a854550b021aa0cea2e235d14e942',1024*1024);
    const wasmBytes=readPinned(wasm,'050084646eef2aa3bf827e4486f7aebe11483b4b4f1fd7785f146e6c8b36d760',16*1024*1024);
    // Circom's .js is CommonJS beneath a type:module repository. Load an exact
    // protected .cjs snapshot so resolution cannot accidentally select v1 code.
    const copy=path.join(directory,'calculator.cjs');
    fs.writeFileSync(copy,source,{flag:'wx',mode:0o600});
    const calculatorBuilder=require(copy);
    const engine=await calculatorBuilder(wasmBytes,{sanityCheck:true});
    const output=await engine.calculateWTNSBin(input,1);
    if (output.byteLength !== 24611532) throw new Error('output');
    fs.writeFileSync(path.join(directory,'output.wtns'),output,{flag:'wx',mode:0o600});
}
module.exports={validateInput};
if (require.main === module) main().catch(() => {process.exitCode=1;});
