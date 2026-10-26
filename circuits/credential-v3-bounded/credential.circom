pragma circom 2.2.3;
include "@zk-email/circuits/lib/rsa.circom";
include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/poseidon.circom";
include "./utc.circom";
include "./profile.circom";

// All eligible shapes share one relation. The circuit authenticates signed policy
// and AKI bytes; application enrollment checks issuerHash+policyHash.
template BoundedNameByte() {
    signal input value;
    signal output valid;
    component lower[3];
    component upper[3];
    signal range[3];
    var low[3] = [48,65,97];
    var high[3] = [57,90,122];
    for (var i = 0; i < 3; i++) {
        lower[i] = LessEqThan(8);
        upper[i] = LessEqThan(8);
        lower[i].in[0] <== low[i]; lower[i].in[1] <== value;
        upper[i].in[0] <== value; upper[i].in[1] <== high[i];
        range[i] <== lower[i].out * upper[i].out;
    }
    component symbol[4];
    var codes[4] = [32,39,45,46];
    var sum = range[0]+range[1]+range[2];
    for (var i = 0; i < 4; i++) {
        symbol[i] = IsEqual();
        symbol[i].in[0] <== value; symbol[i].in[1] <== codes[i];
        sum += symbol[i].out;
    }
    valid <== sum;
}
template CredentialV3Bounded() {
    signal input root;
    signal input issuerHash;
    signal input notBefore;
    signal input notAfter;
    signal input actionHash;
    signal input policyHash;
    signal input layout;
    signal input tbs[TBS_LEN()];
    signal input issuerModulus[17];
    signal input issuerSignature[17];
    signal input holderSignature[17];
    signal input slot;
    signal input siblings[10];
    signal input pathIndices[10];

    component selected[8];
    var selectorSum = 0;
    for (var shape = 0; shape < 8; shape++) {
        selected[shape] = IsEqual();
        selected[shape].in[0] <== layout;
        selected[shape].in[1] <== shape;
        selectorSum += selected[shape].out;
    }
    selectorSum === 1;
    component bytes[TBS_LEN()];
    component certificateHash = Sha256(TBS_LEN()*8);
    component nameByte[TBS_LEN()];
    for (var i = 0; i < TBS_LEN(); i++) {
        bytes[i] = Num2Bits(8);
        bytes[i].in <== tbs[i];
        var anyName = 0;
        for (var shape = 0; shape < 8; shape++) {
            var dynamicByte = IsDynamic(shape,i);
            var expected = ProfileByte(shape,i);
            if (dynamicByte == 0) selected[shape].out * (tbs[i]-expected) === 0;
            anyName += IsName(shape,i);
        }
        if (anyName > 0) {
            nameByte[i] = BoundedNameByte();
            nameByte[i].value <== tbs[i];
            for (var shape = 0; shape < 8; shape++) {
                var nameAt = IsName(shape,i);
                if (nameAt == 1) selected[shape].out * (nameByte[i].valid-1) === 0;
            }
        }
        for (var bit = 0; bit < 8; bit++) certificateHash.in[i*8+bit] <== bytes[i].out[7-bit];
    }

    // Each field is selected from structurally derived, frozen profile offsets.
    signal logical[7][256];
    signal terms[7][256][8];
    var lengths[7] = [16,13,13,256,16,32,20];
    for (var field = 0; field < 7; field++) {
        for (var i = 0; i < 256; i++) {
            var sum = 0;
            for (var shape = 0; shape < 8; shape++) {
                if (i < lengths[field]) terms[field][i][shape] <== selected[shape].out * tbs[ProfileOffset(shape,field)+i];
                else terms[field][i][shape] <== 0;
                sum += terms[field][i][shape];
            }
            logical[field][i] <== sum;
        }
    }
    component serialBits = Num2Bits(8);
    serialBits.in <== logical[0][0];
    serialBits.out[7] === 0;
    component serialZero = IsZero();
    serialZero.in <== logical[0][0];
    serialZero.out === 0;
    component before = UTCTimeV2();
    component after = UTCTimeV2();
    for (var i = 0; i < 13; i++) {
        before.bytes[i] <== logical[1][i];
        after.bytes[i] <== logical[2][i];
    }
    before.epoch === notBefore;
    after.epoch === notAfter;
    component orderedValidity = LessEqThan(32);
    orderedValidity.in[0] <== notBefore;
    orderedValidity.in[1] <== notAfter;
    orderedValidity.out === 1;
    var organization = 0;
    var groupHi = 0;
    var groupLo = 0;
    var aki = 0;
    for (var i = 0; i < 16; i++) {
        organization += logical[4][i] * 2**(8*(15-i));
        groupHi += logical[5][i] * 2**(8*(15-i));
        groupLo += logical[5][i+16] * 2**(8*(15-i));
    }
    for (var i = 0; i < 20; i++) aki += logical[6][i] * 2**(8*(19-i));
    component policyBinding = Poseidon(4);
    policyBinding.inputs[0] <== 2026101503;
    policyBinding.inputs[1] <== organization;
    policyBinding.inputs[2] <== groupHi;
    policyBinding.inputs[3] <== groupLo;
    policyBinding.out === policyHash;

    component issuerBits[17];
    for (var i = 0; i < 17; i++) {
        issuerBits[i] = Num2Bits(121);
        issuerBits[i].in <== issuerModulus[i];
    }
    issuerBits[0].out[0] === 1;
    issuerBits[2047\121].out[2047%121] === 1;
    for (var i = 2048; i < 17*121; i++) issuerBits[i\121].out[i%121] === 0;

    // The 0x00 sign prefix and exponent65537 are fixed signed DER bytes.
    component holderBytes[256];
    for (var i = 0; i < 256; i++) {
        holderBytes[i] = Num2Bits(8);
        holderBytes[i].in <== logical[3][i];
    }
    holderBytes[0].out[7] === 1;
    holderBytes[255].out[0] === 1;
    signal holderModulus[17];
    for (var limb = 0; limb < 17; limb++) {
        var expression = 0;
        for (var bit = 0; bit < 121; bit++) {
            var position = limb*121+bit;
            if (position < 2048) expression += holderBytes[255-(position\8)].out[position%8] * 2**bit;
        }
        holderModulus[limb] <== expression;
    }
    component issuerLow = Poseidon(8);
    component issuerHigh = Poseidon(9);
    for (var i = 0; i < 8; i++) issuerLow.inputs[i] <== issuerModulus[i];
    for (var i = 0; i < 9; i++) issuerHigh.inputs[i] <== issuerModulus[i+8];
    component issuerKeyBinding = Poseidon(2);
    issuerKeyBinding.inputs[0] <== issuerLow.out;
    issuerKeyBinding.inputs[1] <== issuerHigh.out;
    component issuerBinding = Poseidon(3);
    issuerBinding.inputs[0] <== 2026101505;
    issuerBinding.inputs[1] <== issuerKeyBinding.out;
    issuerBinding.inputs[2] <== aki;
    issuerBinding.out === issuerHash;

    // Dependency verifies signature range and the complete SHA256 EMSA block.
    component issuance = RSAVerifier65537(121,17);
    component ownership = RSAVerifier65537(121,17);
    component actionBits = Num2Bits_strict();
    actionBits.in <== actionHash;
    component actionDigest = Sha256(256);
    for (var bit = 0; bit < 256; bit++) {
        if (bit < 2) actionDigest.in[bit] <== 0;
        else actionDigest.in[bit] <== actionBits.out[255-bit];
    }
    for (var limb = 0; limb < 17; limb++) {
        var certificateMessage = 0;
        var actionMessage = 0;
        for (var bit = 0; bit < 121; bit++) {
            var position = limb*121+bit;
            if (position < 256) {
                certificateMessage += certificateHash.out[255-position] * 2**bit;
                actionMessage += actionDigest.out[255-position] * 2**bit;
            }
        }
        issuance.message[limb] <== certificateMessage;
        issuance.signature[limb] <== issuerSignature[limb];
        issuance.modulus[limb] <== issuerModulus[limb];
        ownership.message[limb] <== actionMessage;
        ownership.signature[limb] <== holderSignature[limb];
        ownership.modulus[limb] <== holderModulus[limb];
    }

    var digestHi = 0;
    var digestLo = 0;
    for (var bit = 0; bit < 128; bit++) {
        digestHi += certificateHash.out[bit] * 2**(127-bit);
        digestLo += certificateHash.out[128+bit] * 2**(127-bit);
    }
    component slotBits = Num2Bits(10);
    slotBits.in <== slot;
    component leaf = Poseidon(5);
    leaf.inputs[0] <== 2026101504;
    leaf.inputs[1] <== digestHi;
    leaf.inputs[2] <== digestLo;
    leaf.inputs[3] <== slot;
    leaf.inputs[4] <== 1;
    component path[10];
    signal nodes[11];
    nodes[0] <== leaf.out;
    for (var level = 0; level < 10; level++) {
        pathIndices[level] === slotBits.out[level];
        path[level] = Poseidon(2);
        path[level].inputs[0] <== nodes[level] + pathIndices[level] * (siblings[level]-nodes[level]);
        path[level].inputs[1] <== siblings[level] + pathIndices[level] * (nodes[level]-siblings[level]);
        nodes[level+1] <== path[level].out;
    }
    nodes[10] === root;
}
component main {public [root,issuerHash,notBefore,notAfter,actionHash,policyHash]} = CredentialV3Bounded();
