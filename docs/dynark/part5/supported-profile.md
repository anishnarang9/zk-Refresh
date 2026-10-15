# Supported credential profile: bounded X.509 successor

The candidate product population is `credential-v3-bounded-der-v1`. It admits
previously unseen credentials with different issuer and holder keys, serials,
dates, names, AKIs, organizations and groups under one circuit shape. It is a
**development profile** until full proof, application and frozen-artifact
acceptance gates pass. The original `credential-v2-dev` certificate is a
fixed-template integration fixture and is outside this successor profile.

## Exact admission rules

| Area | Supported | Clear rejection |
| --- | --- | --- |
| Encoding and lengths | Canonical DER X.509 v3; exactly 952 certificate bytes and 672 signed TBS bytes. | BER, nonminimal lengths, trailing fields, extra/missing/duplicate fields or other sizes. |
| Issuance and holder keys | Independent RSA-2048 keys, odd exactly 2048-bit moduli, exponent 65537. Issuer and holder signatures use SHA-256 with complete PKCS#1 v1.5 EMSA. | RSA-PSS, alternate exponent/size/digest, invalid signatures or noncanonical signature integers. |
| Serial | Positive, canonical, exactly 16 content bytes; first byte 1–127. | Other sizes, negative values or unnecessary sign bytes. |
| Validity | Real UTC calendar dates in canonical UTCTime, years 2000–2049; inclusive ordered endpoints. Execution clock must lie inside. | GeneralizedTime, impossible dates, inverted bounds, out-of-range execution time. |
| Names | One CN RDN in each name. Issuer/subject value lengths are 40/24 or 24/40 bytes; both values use UTF8String or both PrintableString. Allowed ASCII characters are letters, digits, space, apostrophe, hyphen and period. | Other attributes, name lengths, characters, or mixed string tags. |
| Extensions | Exactly six mandatory extensions in declared forward or reverse order: noncritical AKI[20], critical digitalSignature-only keyUsage, critical empty end-entity basicConstraints, critical dedicated application EKU, critical opaque organization[16], critical opaque group[32]. | Unknown, duplicate, missing or alternate-order extensions; changed criticality or malformed values. |
| Registry | Depth-10 Poseidon tree and versioned active leaf commitment to signed TBS digest and slot. | Noncurrent root, revoked leaf, wrong path, unsupported depth/domain. |

The extension OIDs in `circuits/credential-v3-bounded/profile.json` are
**test-only** identifiers. A real issuer, purpose and authorization field
policy requires a reviewed profile revision; an individual certificate within
this profile does not. The circuit constrains the DER shape and signed
eligibility bytes. Import offsets come from structural DER parsing and an
exact re-encoding check, while the circuit's eight layout offset tables derive only from
the declared abstract layouts. There is no per-certificate offset edit.

## Issuer trust and public statement

The six ordered public fields are `[root, issuerHash, notBefore, notAfter,
actionHash, policyHash]`. `issuerHash` commits to the enrolled RSA modulus and
the signed AKI. `policyHash` commits to the signed organization and group
bytes. The authority must explicitly enroll the CA key and AKI association,
validate its chain/purpose under the selected policy, and enable the exact
`(issuerHash, policyHash, profile, circuit)` tuple. The program must also
require enabled, fresh authenticated issuer status and the current published
root. A valid signature from an unenrolled issuer is ineligible. The signed CN
is descriptive and grants no authority by itself.

The holder signs SHA-256 of the canonical 32-byte big-endian `actionHash`
field. The application must reconstruct that hash from the immutable request
and actual ordered accounts. A root-only change permits a new proof only while
the credential remains active, eligible, within validity and linked to the
same exact action. Own revocation blocks authorization.

One frozen circuit/profile and one matching public setup package may be reused
for all eligible certificates. Per-certificate witnesses, holder signing
capabilities, private caches, Merkle membership and action/nonce state remain
separate. A changed profile or six-field schema requires a new circuit/key and
versioned application adapter. The five-field v2 application key cannot verify
this successor.

## Current qualification boundary

Circom 2.2.3 compiled the frozen source to a 793,681-constraint R1CS with six
public fields, SHA-256
`976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888`.
The source corpus covers eight layouts plus an OpenSSL-issued variation, two
issuers and three holders, and explicit malformed/ineligible cases. Python
admission tests and the compiled 52-case witness/relation corpus passed: all
18 complete positive witnesses satisfied every R1CS row, and 34 negative cases
were rejected. Nine retained credential pairs then shared one development
setup and public package for 27 independently randomized Full proofs and 207
ordinary verification checks. The DYNARK Anchor pilot, actual v3 registry,
client and application authorization, and frozen unseen-credential acceptance
are tracked separately. No incremental witness path is exposed for this profile.

The first independent OpenSSL credential subsequently passed one Anchor
refreshed proof and eight ordinary checks under the same public setup. Its
public preparation took 732.500 seconds, private preparation 704.394 seconds,
and refresh with verification 0.922 seconds. This single pilot supports
correctness for that case, not a corpus-wide speed or short-session claim.
Application authorization and the frozen unseen-credential gate remain open.
