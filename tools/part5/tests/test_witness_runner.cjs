'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const target = path.resolve(__dirname,'../witness_suite.cjs');
assert.ok(fs.existsSync(target),'v3 bounded witness runner missing');
const runner = require(target);
const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
assert.doesNotThrow(()=>runner.canonicalInputs({root:String(FR-1n),array:['0','1']}));
for (const value of [1,'01','-1',String(FR),'1.0'])
    assert.throws(()=>runner.canonicalInputs({root:value}));
assert.equal(runner.assertionRejection(new Error('Error: Assert Failed.')),'circuit_assertion');
assert.throws(()=>runner.assertionRejection(new Error('memory access out of bounds')));
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'v3-calculator-test-'));
try {
    const compile=path.resolve(__dirname,'../../../artifacts/dynark/part5/v3-compile-001/credential_js/witness_calculator.js');
    const builder=runner.loadCalculator(compile,dir);
    assert.equal(typeof builder,'function'); // no WASM instantiation or witness generation
    assert.equal(fs.statSync(path.join(dir,'witness_calculator.cjs')).mode & 0o777,0o600);
} finally { fs.rmSync(dir,{recursive:true,force:true}); }
console.log('v3 witness runner tests passed; no WASM instantiated');
