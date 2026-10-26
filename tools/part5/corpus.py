"""Generate private v3 qualification inputs without certificate-specific source.

Cryptography.x509 and OpenSSL independently encode eligible DER. No keys are
retained. Returned inputs/witness material are private and must remain ignored.
Full/Anchor proof qualification is a separate, resource-granted stage.
"""
import argparse
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import NameOID, ObjectIdentifier

from tools.part5 import credential_profile as p
from tools.part5.poseidon import poseidon


def root_for(inputs, active=1):
    constants = p.REPO/'node_modules/circomlib/circuits/poseidon_constants.circom'
    digest = hashlib.sha256(bytes(inputs['tbs'])).digest()
    node = poseidon([p.LEAF_DOMAIN,int.from_bytes(digest[:16],'big'),int.from_bytes(digest[16:],'big'),inputs['slot'],active],constants)
    for level,sibling in enumerate(inputs['siblings']):
        node = poseidon([sibling,node] if inputs['slot'] >> level & 1 else [node,sibling],constants)
    return node


def x509_certificate(issuer,holder,variant):
    """Independent DER encoder; never calls p.build_tbs or a template byte editor."""
    kind = _ASN1Type.PrintableString if variant & 1 else _ASN1Type.UTF8String
    issuer_len,subject_len = (24,40) if variant & 4 else (40,24)
    name = lambda text: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,text,_type=kind)])
    cert = (x509.CertificateBuilder().issuer_name(name(f'Issuer {variant}'.ljust(issuer_len,'A')))
        .subject_name(name(f'Holder {variant}'.ljust(subject_len,'B'))).public_key(holder.public_key())
        .serial_number((1 << 120)+variant*12345+17)
        .not_valid_before(datetime.datetime(2026,1,variant+1,tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2028,2,variant+1,tzinfo=datetime.timezone.utc)))
    aki = hashlib.sha256(issuer.public_key().public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).digest()[:20]
    exts = [
        (x509.AuthorityKeyIdentifier(aki,None,None),False),
        (x509.KeyUsage(True,False,False,False,False,False,False,None,None),True),
        (x509.BasicConstraints(False,None),True),
        (x509.ExtendedKeyUsage([ObjectIdentifier(p.TEST_OIDS['purpose'])]),True),
        (x509.UnrecognizedExtension(ObjectIdentifier(p.TEST_OIDS['organization']),b'\x04\x10'+bytes([variant+1])*16),True),
        (x509.UnrecognizedExtension(ObjectIdentifier(p.TEST_OIDS['group']),b'\x04\x20'+bytes([variant+2])*32),True)]
    for value,critical in reversed(exts) if variant & 2 else exts:
        cert = cert.add_extension(value,critical)
    return cert.sign(issuer,hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def openssl_certificate(issuer,holder):
    """Encode a source-independent canonical variant with OpenSSL in a private temp dir."""
    with tempfile.TemporaryDirectory(prefix='dynark-v3-corpus-') as directory:
        d = Path(directory)
        for name,key in [('issuer',issuer),('holder',holder)]:
            target = d/(name+'.pem')
            # Restrict permissions before writing any temporary synthetic private key.
            target.touch(mode=0o600)
            target.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        config = ('[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN='+'O'*24+
            '\n[ext]\nsubjectKeyIdentifier=none\nauthorityKeyIdentifier=keyid\n'
            'keyUsage=critical,digitalSignature\nbasicConstraints=critical,CA:FALSE\n'
            'extendedKeyUsage=critical,'+p.TEST_OIDS['purpose']+'\n'+p.TEST_OIDS['organization']+
            '=critical,DER:04:10:'+bytes([91]*16).hex(':')+'\n'+p.TEST_OIDS['group']+
            '=critical,DER:04:20:'+bytes([92]*32).hex(':')+'\n')
        (d/'openssl.cnf').write_text(config)
        def run(*args):
            subprocess.run(['openssl',*args],cwd=d,check=True,capture_output=True,timeout=30)
        run('req','-new','-x509','-key','issuer.pem','-subj','/CN='+'C'*40,'-days','365',
            '-out','issuer.crt','-sha256','-addext','subjectKeyIdentifier=hash')
        run('req','-new','-key','holder.pem','-config','openssl.cnf','-out','holder.csr')
        run('x509','-req','-in','holder.csr','-CA','issuer.crt','-CAkey','issuer.pem',
            '-set_serial','0x11223344556677889900112233445566','-days','365','-sha256',
            '-extfile','openssl.cnf','-extensions','ext','-outform','DER','-out','holder.der')
        return (d/'holder.der').read_bytes()


def generate_corpus(include_openssl=True):
    issuers = [rsa.generate_private_key(public_exponent=65537,key_size=2048) for _ in range(2)]
    holders = [rsa.generate_private_key(public_exponent=65537,key_size=2048) for _ in range(3)]
    cases = []
    for index in range(8+int(include_openssl)):
        issuer,holder = issuers[index%2],holders[index%3]
        der = x509_certificate(issuer,holder,index) if index < 8 else openssl_certificate(issuer,holder)
        modulus = issuer.public_key().public_numbers().n
        parsed = p.admit_certificate(der,modulus)
        action = (12345+index).to_bytes(32,'big')
        signature = holder.sign(action,padding.PKCS1v15(),hashes.SHA256())
        inputs = p.credential_witness_material(parsed,modulus,action,signature)
        inputs['issuerHash'],inputs['policyHash'] = p.public_bindings(parsed,modulus)
        inputs.update(slot=7+index,siblings=[17+j+index for j in range(10)],
            pathIndices=[((7+index)>>j)&1 for j in range(10)])
        inputs['root'] = root_for(inputs)
        key_digest = hashlib.sha256(parsed['holder_modulus'].to_bytes(256,'big')).hexdigest()
        common = dict(generator='cryptography.x509' if index < 8 else 'openssl',holder_key_digest=key_digest)
        name = f'credential_{index}'
        cases.append(dict(name=name,expect='accept',family='credential',inputs=inputs,**common))
        near = copy.deepcopy(inputs)
        near['siblings'][0] += 1
        near['root'] = root_for(near)
        cases.append(dict(name=name+'_unrelated_refresh',expect='accept',family='unrelated_refresh',
            anchor_pair=name,inputs=near,**common))
        revoked = copy.deepcopy(inputs)
        revoked['root'] = root_for(revoked,active=0)
        cases.append(dict(name=name+'_own_revoked',expect='reject',family='own_revocation',inputs=revoked,**common))
        wrong_policy = copy.deepcopy(inputs)
        wrong_policy['policyHash'] = (wrong_policy['policyHash']+1)%p.FR
        cases.append(dict(name=name+'_wrong_public_policy',expect='reject',family='wrong_policy_binding',inputs=wrong_policy,**common))
        if index == 0:
            # Bypass host import deliberately: real issuer signatures authenticate
            # malformed eligibility, so only circuit profile constraints reject.
            tbs = parsed['tbs']
            mutations = [
                ('invalid_cn', parsed['offsets']['issuer_cn'], b'@'),
                ('invalid_purpose', tbs.index(p.oid_der(p.TEST_OIDS['purpose']))+4, b'\x00'),
                ('invalid_key_usage', tbs.index(bytes.fromhex('03020780'))+3, b'\x00'),
                ('invalid_serial', parsed['offsets']['serial'], b'\x00'),
            ]
            for suffix,at,value in mutations:
                changed = tbs[:at]+value+tbs[at+len(value):]
                bad = copy.deepcopy(inputs)
                bad['tbs'] = list(changed)
                bad['issuerSignature'] = p.rsa_limbs(int.from_bytes(issuer.sign(changed,padding.PKCS1v15(),hashes.SHA256()),'big'))
                bad['root'] = root_for(bad)
                cases.append(dict(name=name+'_'+suffix,expect='reject',family='signed_profile_bypass',inputs=bad,**common))
            for field,key in [('organization','policyHash'),('aki','issuerHash')]:
                changed = bytearray(tbs)
                changed[parsed['offsets'][field]] ^= 1
                bad = copy.deepcopy(inputs)
                bad['tbs'] = list(changed)
                bad['issuerSignature'] = p.rsa_limbs(int.from_bytes(issuer.sign(bytes(changed),padding.PKCS1v15(),hashes.SHA256()),'big'))
                bad['root'] = root_for(bad)
                cases.append(dict(name=name+'_signed_'+field+'_old_binding',expect='reject',
                    family='signed_binding_bypass',inputs=bad,**common))
            wrong_layout = copy.deepcopy(inputs)
            wrong_layout['layout'] = 8
            cases.append(dict(name=name+'_invalid_layout',expect='reject',family='invalid_layout',inputs=wrong_layout,**common))
        wrong_issuer = copy.deepcopy(inputs)
        wrong_issuer['issuerHash'] = (wrong_issuer['issuerHash']+1)%p.FR
        cases.append(dict(name=name+'_wrong_public_issuer',expect='reject',family='wrong_issuer_binding',inputs=wrong_issuer,**common))
    return cases


def canonical_strings(value):
    """Serialize field inputs without JavaScript's lossy JSON-number conversion."""
    if type(value) is int:
        if not 0 <= value < p.FR:
            raise ValueError('noncanonical input scalar')
        return str(value)
    if type(value) is list:
        return [canonical_strings(item) for item in value]
    if type(value) is dict:
        return {key:canonical_strings(item) for key,item in value.items()}
    raise ValueError('input scalars must be canonical integers')


def write_corpus(directory,cases):
    directory=Path(directory)
    directory.mkdir(parents=True,mode=0o700)
    for case in cases:
        target=directory/(case['name']+'.input.json')
        with open(target,'x',opener=lambda path,flags: os.open(path,flags,0o600)) as output:
            output.write(json.dumps(canonical_strings(case['inputs']),sort_keys=True)+'\n')
    manifest=[{k:v for k,v in item.items() if k not in ('inputs','holder_key_digest')} for item in cases]
    with open(directory/'cases.json','x',opener=lambda path,flags: os.open(path,flags,0o600)) as output:
        output.write(json.dumps(manifest,indent=2)+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-out',type=Path,required=True)
    parser.add_argument('--without-openssl',action='store_true')
    args=parser.parse_args()
    if args.private_out.exists():
        raise SystemExit('refusing to overwrite private corpus')
    cases=generate_corpus(not args.without_openssl)
    write_corpus(args.private_out,cases)
    print(json.dumps({'cases':len(cases),'accept':sum(x['expect']=='accept' for x in cases),
        'reject':sum(x['expect']=='reject' for x in cases),'private_output_written':True}))

if __name__ == '__main__': main()
