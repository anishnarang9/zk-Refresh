'use strict';
const assert = require('node:assert/strict');
const { validateInput } = require('../workers/v2_full_worker.cjs');
function input() {
    return Object.fromEntries(['root','issuerHash','notBefore','notAfter','actionHash','slot'].map(k => [k,'0']).concat(
        [['tbs',Array(656).fill('0')], ['issuerModulus',Array(17).fill('0')],
        ['issuerSignature',Array(17).fill('0')], ['holderSignature',Array(17).fill('0')],
        ['siblings',Array(10).fill('0')], ['pathIndices',Array(10).fill('0')]]));
}
validateInput(input());
for (const value of ['01','-1','1e1',1,'21888242871839275222246405745257275088548364400416034343698204186575808495617']) {
    const bad=input(); bad.root=value; assert.throws(() => validateInput(bad));
}
for (const change of [x=>x.extra='1',x=>delete x.root,x=>x.tbs.pop(),x=>x.pathIndices[0]='2',x=>x.tbs[0]='256',x=>x.slot='1024',x=>x.issuerModulus[0]=(2n**121n).toString()]) {
    const bad=input(); change(bad); assert.throws(() => validateInput(bad));
}
console.log('v2 Full input canonicality and shape checks passed');
