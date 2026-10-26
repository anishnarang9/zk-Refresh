"""Bounded v3 DER admission and circuit-shape source generator.

No imported certificate changes generated circuit source. Eight declared layouts
share a fixed length. Imported offsets come from strict structural DER parsing.
Issuer eligibility and policy allowlists are checked by the application using
public issuerHash and policyHash; this module cannot assert current enrollment.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import uuid

FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617
POLICY_DOMAIN = 2026101503
LEAF_DOMAIN = 2026101504
# Defaults are generator examples, never frozen eligibility constants.
ORGANIZATION = bytes.fromhex('00112233445566778899aabbccddeeff')
GROUP = bytes(range(32))
TEST_OIDS = {
    'organization': '2.25.' + str(uuid.UUID('4ac22ada-9404-4e18-8797-6bc72de5b5a1').int),
    'group': '2.25.' + str(uuid.UUID('876c9ee7-7a77-4df3-8ad7-bd81a82081f4').int),
    'purpose': '2.25.' + str(uuid.UUID('15bf19b5-78cd-4e83-b5e8-19cb0f8fd032').int),
}
SHA256_RSA_ALGORITHM = bytes.fromhex('300d06092a864886f70d01010b0500')
RSA_ALGORITHM = bytes.fromhex('300d06092a864886f70d0101010500')
PUBLIC_NAMES = ['root', 'issuerHash', 'notBefore', 'notAfter', 'actionHash', 'policyHash']
NAME_CHARACTERS = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '-."
REPO = Path(__file__).resolve().parents[2]

class ProfileError(ValueError):
    """Certificate is outside the supported bounded v3 profile."""


def tlv(tag, value):
    n = len(value)
    width = (n.bit_length()+7)//8
    return bytes([tag]) + (bytes([n]) if n < 128 else bytes([128+width])+n.to_bytes(width,'big')) + value


def oid_der(text):
    arcs = [int(x) for x in text.split('.')]
    out = bytearray()
    for n in [40*arcs[0]+arcs[1]]+arcs[2:]:
        digits = [n & 127]
        n >>= 7
        while n:
            digits.append(128+(n & 127))
            n >>= 7
        out.extend(reversed(digits))
    return tlv(6, bytes(out))


class DER:
    """One shallow, bounded canonical DER reader; no BER or recursive fallback."""
    def __init__(self, data, start=0, end=None):
        self.data, self.at, self.end = data, start, len(data) if end is None else end

    def read(self, tag):
        start = self.at
        if self.at+2 > self.end or self.data[self.at] != tag:
            raise ProfileError('unexpected DER tag or truncated header')
        first = self.data[self.at+1]
        self.at += 2
        if first < 128:
            length = first
        else:
            width = first & 127
            if width not in (1,2) or self.at+width > self.end or self.data[self.at] == 0:
                raise ProfileError('noncanonical or unbounded DER length')
            length = int.from_bytes(self.data[self.at:self.at+width], 'big')
            self.at += width
            if length < 128 or (width == 2 and length < 256):
                raise ProfileError('nonminimal DER length')
        content = self.at
        self.at += length
        if self.at > self.end:
            raise ProfileError('DER content exceeds parent')
        return start, content, self.at

    def child(self, tag):
        _, start, end = self.read(tag)
        return DER(self.data, start, end)

    def value(self, tag):
        _, start, end = self.read(tag)
        return self.data[start:end], start

    def exact(self, encoded):
        if self.data[self.at:self.at+len(encoded)] != encoded or self.at+len(encoded) > self.end:
            raise ProfileError('unsupported DER algorithm/profile bytes')
        self.at += len(encoded)

    def finish(self):
        if self.at != self.end:
            raise ProfileError('unexpected or duplicate DER fields')


def utc_epoch(value):
    if not re.fullmatch(rb'[0-4][0-9][0-9]{10}Z', value):
        raise ProfileError('UTCTime 2000-2049 required')
    parts = [int(value[i:i+2]) for i in range(0,12,2)]
    try:
        return int(datetime.datetime(2000+parts[0], *parts[1:], tzinfo=datetime.timezone.utc).timestamp())
    except ValueError as e:
        raise ProfileError('invalid calendar date') from e


def check_modulus(n):
    if type(n) is not int or n.bit_length() != 2048 or not n & 1:
        raise ProfileError('odd exactly 2048-bit RSA modulus required')
    return n


def verify_rsa(modulus, message, signature):
    check_modulus(modulus)
    if len(signature) != 256 or int.from_bytes(signature,'big') >= modulus:
        raise ProfileError('noncanonical RSA signature')
    digest_info = bytes.fromhex('3031300d060960864801650304020105000420')+hashlib.sha256(message).digest()
    expected = b'\x00\x01'+b'\xff'*(253-len(digest_info))+b'\x00'+digest_info
    if pow(int.from_bytes(signature,'big'),65537,modulus).to_bytes(256,'big') != expected:
        raise ProfileError('RSA signature verification failed')


def _name(parent):
    name = parent.child(0x30)
    rdn = name.child(0x31)
    attr = rdn.child(0x30)
    attr.exact(oid_der('2.5.4.3'))
    if attr.at >= attr.end or attr.data[attr.at] not in (0x0c, 0x13):
        raise ProfileError('CN UTF8String/PrintableString required')
    tag = attr.data[attr.at]
    value, at = attr.value(tag)
    if any(x not in NAME_CHARACTERS for x in value):
        raise ProfileError('unsupported name characters')
    attr.finish(); rdn.finish(); name.finish()
    return value, at, tag


def parse_tbs(tbs):
    if type(tbs) is not bytes or len(tbs) != 672:
        raise ProfileError('unsupported bounded TBS length')
    outer = DER(tbs)
    body = outer.child(0x30)
    outer.finish()
    body.exact(b'\xa0\x03\x02\x01\x02')
    serial, serial_at = body.value(2)
    if len(serial) != 16 or not 1 <= serial[0] <= 127:
        raise ProfileError('canonical positive 16-byte serial required')
    body.exact(SHA256_RSA_ALGORITHM)
    issuer, issuer_at, issuer_tag = _name(body)
    validity = body.child(0x30)
    before, before_at = validity.value(0x17)
    after, after_at = validity.value(0x17)
    validity.finish()
    before_epoch, after_epoch = utc_epoch(before), utc_epoch(after)
    if before_epoch > after_epoch:
        raise ProfileError('inverted validity')
    subject, subject_at, subject_tag = _name(body)
    if (len(issuer),len(subject)) not in ((40,24),(24,40)) or issuer_tag != subject_tag:
        raise ProfileError('unsupported name layout')
    spki = body.child(0x30)
    spki.exact(RSA_ALGORITHM)
    bitstring = spki.child(3)
    bitstring.exact(b'\x00')
    key = bitstring.child(0x30)
    modulus, modulus_at = key.value(2)
    if len(modulus) != 257 or modulus[0] != 0:
        raise ProfileError('canonical signed RSA modulus required')
    holder_modulus = check_modulus(int.from_bytes(modulus[1:],'big'))
    key.exact(b'\x02\x03\x01\x00\x01')
    key.finish(); bitstring.finish(); spki.finish()
    extensions = body.child(0xa3).child(0x30)
    # The wrapper is known to end with the extension sequence by exact re-encoding below.
    expected = [oid_der(x) for x in ('2.5.29.35','2.5.29.15','2.5.29.19','2.5.29.37', TEST_OIDS['organization'], TEST_OIDS['group'])]
    order, values, positions = [], {}, {}
    while extensions.at < extensions.end:
        ext = extensions.child(0x30)
        oid_start, _, oid_end = ext.read(6)
        oid = tbs[oid_start:oid_end]
        if oid not in expected or oid in order:
            raise ProfileError('unknown or duplicate extension')
        order.append(oid)
        critical = oid != expected[0]
        if critical:
            ext.exact(b'\x01\x01\xff')
        value, at = ext.value(4)
        ext.finish()
        values[oid] = value
        positions[oid] = at
    body.finish()
    if order not in (expected, list(reversed(expected))):
        raise ProfileError('unsupported extension order')
    aki, ku, bc, eku, organization, group = (values[x] for x in expected)
    if (len(aki) != 24 or aki[:4] != b'\x30\x16\x80\x14' or ku != b'\x03\x02\x07\x80'
        or bc != b'\x30\x00' or eku != tlv(0x30,oid_der(TEST_OIDS['purpose']))
        or len(organization) != 18 or organization[:2] != b'\x04\x10'
        or len(group) != 34 or group[:2] != b'\x04\x20'):
        raise ProfileError('unsupported authorization extension value')
    variant = int(issuer_tag == 0x13) + 2*int(order == list(reversed(expected))) + 4*int(len(issuer) == 24)
    offsets = dict(serial=serial_at, not_before=before_at, not_after=after_at, issuer_cn=issuer_at,
                   subject_cn=subject_at, modulus=modulus_at+1, aki=positions[expected[0]]+4,
                   organization=positions[expected[4]]+2, group=positions[expected[5]]+2)
    result = dict(tbs=tbs, variant=variant, offsets=offsets, issuer_cn=issuer, subject_cn=subject,
                  serial=serial, holder_modulus=holder_modulus, not_before=before_epoch, not_after=after_epoch,
                  organization=organization[2:], group=group[2:], aki=aki[4:], tbs_digest=hashlib.sha256(tbs).digest())
    # Re-encoding ensures no wrapper trailing fields or unvalidated signed bytes survive.
    canonical = build_tbs(holder_modulus, variant, serial, before, after, issuer, subject, aki[4:], organization[2:],group[2:])
    if tbs != canonical:
        raise ProfileError('noncanonical bounded DER')
    return result


def admit_certificate(certificate, enrolled_issuer_modulus):
    if type(certificate) is not bytes or len(certificate) > 1024:
        raise ProfileError('bounded DER certificate required')
    outer = DER(certificate)
    body = outer.child(0x30)
    outer.finish()
    start, _, end = body.read(0x30)
    tbs = certificate[start:end]
    body.exact(SHA256_RSA_ALGORITHM)
    signature, _ = body.value(3)
    body.finish()
    if len(signature) != 257 or signature[0] != 0:
        raise ProfileError('canonical RSA signature BIT STRING required')
    result = parse_tbs(tbs)
    verify_rsa(enrolled_issuer_modulus,tbs,signature[1:])
    result['issuer_signature'] = signature[1:]
    return result


def build_tbs(modulus, variant=0, serial=b'\x11'*16, before=b'260101000000Z', after=b'280101000000Z',
              issuer=None, subject=None, aki=b'\x22'*20, organization=ORGANIZATION, group=GROUP):
    """Profile-shape constructor, never called with imported bytes for circuit generation."""
    check_modulus(modulus)
    if variant not in range(8):
        raise ProfileError('unsupported layout selector')
    issuer_len, subject_len = (24,40) if variant & 4 else (40,24)
    issuer = b'I'*issuer_len if issuer is None else issuer
    subject = b'H'*subject_len if subject is None else subject
    tag = 0x13 if variant & 1 else 0x0c
    name = lambda value: tlv(0x30,tlv(0x31,tlv(0x30,oid_der('2.5.4.3')+tlv(tag,value))))
    ext = lambda oid, value, critical: tlv(0x30,oid_der(oid)+(b'\x01\x01\xff' if critical else b'')+tlv(4,value))
    extensions = [ext('2.5.29.35',tlv(0x30,tlv(0x80,aki)),False),
        ext('2.5.29.15',b'\x03\x02\x07\x80',True),ext('2.5.29.19',b'\x30\x00',True),
        ext('2.5.29.37',tlv(0x30,oid_der(TEST_OIDS['purpose'])),True),
        ext(TEST_OIDS['organization'],tlv(4,organization),True),ext(TEST_OIDS['group'],tlv(4,group),True)]
    spki = tlv(0x30,RSA_ALGORITHM+tlv(3,b'\x00'+tlv(0x30,tlv(2,b'\x00'+modulus.to_bytes(256,'big'))+b'\x02\x03\x01\x00\x01')))
    return tlv(0x30,b'\xa0\x03\x02\x01\x02'+tlv(2,serial)+SHA256_RSA_ALGORITHM+name(issuer)+
        tlv(0x30,tlv(0x17,before)+tlv(0x17,after))+name(subject)+spki+
        tlv(0xa3,tlv(0x30,b''.join(reversed(extensions) if variant & 2 else extensions))))


def rsa_limbs(value):
    if type(value) is not int or not 0 <= value < 1 << 2048:
        raise ProfileError('RSA integer out of bounds')
    return [(value >> (121*i)) & ((1 << 121)-1) for i in range(17)]


def credential_witness_material(parsed, issuer_modulus, action, holder_signature):
    if type(action) is not bytes or len(action) != 32 or int.from_bytes(action,'big') >= FR:
        raise ProfileError('canonical action field required')
    admitted = parse_tbs(parsed['tbs'])
    verify_rsa(issuer_modulus,admitted['tbs'],parsed['issuer_signature'])
    verify_rsa(admitted['holder_modulus'],action,holder_signature)
    return {'tbs':list(admitted['tbs']), 'layout':admitted['variant'],
        'issuerModulus':rsa_limbs(issuer_modulus), 'issuerSignature':rsa_limbs(int.from_bytes(parsed['issuer_signature'],'big')),
        'holderSignature':rsa_limbs(int.from_bytes(holder_signature,'big')),
        'notBefore':admitted['not_before'], 'notAfter':admitted['not_after'], 'actionHash':int.from_bytes(action,'big')}


def public_bindings(parsed, issuer_modulus):
    from tools.part5.poseidon import poseidon
    constants = REPO/'node_modules/circomlib/circuits/poseidon_constants.circom'
    limbs = rsa_limbs(check_modulus(issuer_modulus))
    key_hash = poseidon([poseidon(limbs[:8],constants),poseidon(limbs[8:],constants)],constants)
    issuer_hash = poseidon([2026101505,key_hash,int.from_bytes(parsed['aki'],'big')],constants)
    policy_hash = poseidon([POLICY_DOMAIN,int.from_bytes(parsed['organization'],'big'),
        int.from_bytes(parsed['group'][:16],'big'),int.from_bytes(parsed['group'][16:],'big')],constants)
    return issuer_hash, policy_hash


def shapes():
    """Derive fixed profile layouts structurally from eight abstract examples."""
    result = []
    for variant in range(8):
        tbs = build_tbs((1 << 2047) | 1, variant)
        parsed = parse_tbs(tbs)
        lengths = dict(serial=16,not_before=13,not_after=13,modulus=256,aki=20,
            organization=16,group=32,issuer_cn=len(parsed['issuer_cn']),subject_cn=len(parsed['subject_cn']))
        dynamic = set()
        name_positions = set()
        for name, length in lengths.items():
            positions = set(range(parsed['offsets'][name],parsed['offsets'][name]+length))
            dynamic |= positions
            if name.endswith('_cn'):
                name_positions |= positions
        result.append((tbs, parsed['offsets'], dynamic, name_positions))
    return result


def circom_profile():
    lines = ['pragma circom 2.2.3;', '// Generated from bounded profile shapes; never from imported certificates.',
        'function TBS_LEN() { return 672; }']
    fields = ['serial','not_before','not_after','modulus','organization','group','aki']
    for name, column in [('ProfileByte',0),('IsDynamic',2),('IsName',3)]:
        lines.append(f'function {name}(shape,i) {{')
        for index,(tbs,offsets,dynamic,names) in enumerate(shapes()):
            values = list(tbs) if column == 0 else [int(i in (dynamic if column == 2 else names)) for i in range(len(tbs))]
            lines.append(f'    if (shape == {index}) {{ var values[672] = [{",".join(map(str,values))}]; return values[i]; }}')
        lines.append('    return 0;\n}')
    lines.append('function ProfileOffset(shape,field) {')
    for index,(_,offsets,_,_) in enumerate(shapes()):
        lines.append(f'    if (shape == {index}) {{ var values[7] = [{",".join(str(offsets[field]) for field in fields)}]; return values[field]; }}')
    lines.append('    return 0;\n}')
    return '\n'.join(lines)+'\n'


def profile_description():
    entries = []
    for variant,(tbs,offsets,dynamic,_) in enumerate(shapes()):
        entries.append(dict(layout=variant,issuer_cn_length=24 if variant & 4 else 40,
            subject_cn_length=40 if variant & 4 else 24, name_tags='PrintableString' if variant & 1 else 'UTF8String',
            extension_order='reverse' if variant & 2 else 'forward',offsets=offsets,
            static_mask_sha256=hashlib.sha256(bytes(int(i not in dynamic) for i in range(len(tbs)))).hexdigest()))
    return {'profile':'credential-v3-bounded-der-v1','development_only':True,'qualification':'source-only-no-compiled-setup-or-proof',
        'tbs_length':672,'certificate_length':952,'layouts':entries,'name_characters':NAME_CHARACTERS.decode('ascii'),
        'serial':'canonical positive exactly 16 octets; first octet 1..127',
        'validity':'canonical UTCTime 2000-2049, real calendar, inclusive endpoints',
        'rsa':{'bits':2048,'exponent':65537,'digest':'SHA256','padding':'PKCS1-v1_5'},
        'test_only_oids':TEST_OIDS,'organization_bytes':16,'group_bytes':32,'aki_bytes':20,
        'mixed_name_tags':False,'all_other_extensions':'reject','tree_depth':10,'leaf_domain':LEAF_DOMAIN,
        'schema':{'name':'credential-v3-bounded-six-public-fields-v1','ordered_public_inputs':PUBLIC_NAMES,
            'issuerHash':'Poseidon(3)(2026101505,Poseidon(2)(Poseidon(8)(issuerLimbs[0:8]),Poseidon(9)(issuerLimbs[8:17])),bigEndian160(signedAKI))',
            'policyHash':'Poseidon(4)(2026101503,bigEndian128(signedOrganization),bigEndian128(signedGroup[0:16]),bigEndian128(signedGroup[16:32]))',
            'leaf':'Poseidon(5)(2026101504,SHA256(TBS)_high128,SHA256(TBS)_low128,slot,1)',
            'action':'SHA256 of canonical 32-byte big-endian Fr, RSA-PKCS1-v1_5 signed'},
        'eligibility':'application enables exact issuerHash+policyHash+profile+circuit; circuit authenticates all signed policy and AKI bytes; CN descriptive',
        'excluded':['general PKIX chains','GeneralizedTime','RSA-PSS','alternate exponents','unknown or duplicate extensions',
            'arbitrary name lengths','mixed UTF8String and PrintableString names','real token signer qualification','incremental witness qualification']}


def write_profile(directory):
    directory = Path(directory)
    directory.mkdir(parents=True,exist_ok=True)
    (directory/'profile.circom').write_text(circom_profile())
    (directory/'profile.json').write_text(json.dumps(profile_description(),indent=2,sort_keys=True)+'\n')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write-profile',type=Path,required=True)
    write_profile(parser.parse_args().write_profile)
