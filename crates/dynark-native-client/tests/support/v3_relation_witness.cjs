'use strict';
// Test-only complete v3 calculator invocation. No proof/setup/cache is created.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const ROOT = path.resolve(__dirname, '../../../..');
const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const SHAPE = {root:0, issuerHash:0, notBefore:0, notAfter:0, actionHash:0,
    policyHash:0, layout:0, slot:0, tbs:672, issuerModulus:17,
    issuerSignature:17, holderSignature:17, siblings:10, pathIndices:10};
const WASM_SHA = 'fbf73cff59660574add16ba8acafe824a9d57e0c91f23557b6462979b85c9aa6';
const CALCULATOR_SHA = 'cc2d37b2cff2a589dd86f8636f1a1dc9fe4a854550b021aa0cea2e235d14e942';

function identity(metadata) {
    return [metadata.dev, metadata.ino, metadata.mode, metadata.uid, metadata.nlink,
        metadata.size, metadata.mtimeNs, metadata.ctimeNs].join(':');
}
function readChecked(filename, maximum, expected, privateFile) {
    const before = fs.lstatSync(filename, {bigint:true});
    if (!before.isFile() || before.size <= 0n || before.size > BigInt(maximum)
        || (privateFile && ((before.mode & 0o7777n) !== 0o600n
            || before.uid !== BigInt(process.getuid()) || before.nlink !== 1n))) throw new Error();
    const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    try {
        if (identity(fs.fstatSync(fd, {bigint:true})) !== identity(before)) throw new Error();
        // Fixed allocation/read bounds even if the file grows after lstat.
        const bytes = Buffer.alloc(Number(before.size) + 1);
        let count = 0;
        while (count < bytes.length) {
            const n = fs.readSync(fd, bytes, count, bytes.length - count, null);
            if (!n) break;
            count += n;
        }
        const value = bytes.subarray(0, count);
        if (count !== Number(before.size) || identity(fs.fstatSync(fd, {bigint:true})) !== identity(before)
            || (expected && crypto.createHash('sha256').update(value).digest('hex') !== expected)) throw new Error();
        return value;
    } finally { fs.closeSync(fd); }
}
function writePrivate(filename, bytes) {
    const fd = fs.openSync(filename, fs.constants.O_WRONLY | fs.constants.O_CREAT
        | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    try {
        fs.writeFileSync(fd, bytes);
        const metadata = fs.fstatSync(fd, {bigint:true});
        if (!metadata.isFile() || (metadata.mode & 0o7777n) !== 0o600n
            || metadata.uid !== BigInt(process.getuid()) || metadata.nlink !== 1n
            || metadata.size !== BigInt(bytes.byteLength)) throw new Error();
    } finally { fs.closeSync(fd); }
}
function scalar(value, maximum) {
    if (typeof value !== 'string' || value.length > 77 || !/^(0|[1-9][0-9]*)$/.test(value)
        || BigInt(value) >= maximum) throw new Error();
}
function validate(input) {
    if (!input || Array.isArray(input) || typeof input !== 'object'
        || Object.keys(input).length !== 14) throw new Error();
    for (const [name, count] of Object.entries(SHAPE)) {
        if (!Object.hasOwn(input, name)) throw new Error();
        const bound = name === 'tbs' ? 256n : name === 'pathIndices' ? 2n
            : name === 'layout' ? 8n : name === 'slot' ? 1024n
            : /Modulus|Signature/.test(name) ? 1n << 121n : FR;
        if (count) {
            if (!Array.isArray(input[name]) || input[name].length !== count) throw new Error();
            input[name].forEach(value => scalar(value, bound));
        } else scalar(input[name], bound);
    }
}
async function main() {
    if (process.argv.length !== 3) throw new Error();
    const directory = process.argv[2];
    const metadata = fs.lstatSync(directory, {bigint:true});
    if (!path.isAbsolute(directory) || fs.realpathSync(directory) !== directory
        || !metadata.isDirectory() || (metadata.mode & 0o7777n) !== 0o700n
        || metadata.uid !== BigInt(process.getuid())) throw new Error();
    process.umask(0o077);
    const raw = readChecked(path.join(directory, 'input.json'), 65536, null, true);
    const input = JSON.parse(raw.toString('ascii'));
    validate(input);
    const compile = path.join(ROOT, 'artifacts/dynark/part5/v3-compile-001/credential_js');
    const wasm = readChecked(path.join(compile, 'credential.wasm'), 16 * 1024 * 1024, WASM_SHA, false);
    const calculator = readChecked(path.join(compile, 'witness_calculator.js'), 1024 * 1024, CALCULATOR_SHA, false);
    const snapshot = path.join(directory, 'calculator.cjs');
    writePrivate(snapshot, calculator);
    // CommonJS snapshot is exact authenticated bytes in a fresh 0700 directory.
    const builder = require(snapshot);
    const engine = await builder(wasm, {sanityCheck:true});
    const output = await engine.calculateWTNSBin(input, 1);
    if (output.byteLength !== 25113548) throw new Error();
    writePrivate(path.join(directory, 'output.wtns'), output);
}
main().catch(() => { process.exitCode = 2; });
