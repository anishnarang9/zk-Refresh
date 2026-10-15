'use strict';
const fs = require('node:fs');
const path = require('node:path');

async function main() {
    if (process.argv.length !== 5) throw new Error('invocation');
    const [directory, wasm, calculator] = process.argv.slice(2);
    if (![directory, wasm, calculator].every(path.isAbsolute)) throw new Error('absolute_paths');
    const inputBytes = fs.readFileSync(path.join(directory, 'target.json'));
    if (!inputBytes.length || inputBytes.length > 65536) throw new Error('input_bound');
    const witnessCalculator = require(calculator);
    const engine = await witnessCalculator(fs.readFileSync(wasm));
    const output = await engine.calculateWTNSBin(JSON.parse(inputBytes.toString('utf8')), 0);
    if (output.byteLength !== 20594092) throw new Error('output_bound');
    const fd = fs.openSync(path.join(directory, 'output.wtns'), 'wx', 0o600);
    try { fs.writeFileSync(fd, output); } finally { fs.closeSync(fd); }
}
main().catch(() => { process.exitCode = 1; });
