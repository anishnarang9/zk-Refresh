# Bounded multi-credential X.509 relation v3

This is a new development profile. It preserves the v2 circuit and keys. Source, Python admission tests and the first bounded Circom compilation
exist. Complete-witness corpus validation, setup, Full/Anchor proofs, application
integration and a frozen-artifact unseen-certificate gate are still required. No v2 identity, setup, witness map or performance claim transfers.

## Supported DER family

Each certificate is canonical DER v3, 952 bytes total with 672 signed TBS bytes.
Issuer and holder RSA keys are independent odd 2048-bit moduli with exponent
65537. Certificate issuance and holder authorization use SHA-256 and complete
PKCS#1 v1.5 EMSA verification. A canonical positive serial occupies exactly 16
content octets with first octet 1..127. Validity uses canonical UTCTime in
2000–2049, real calendar dates and ordered inclusive endpoints. The application
checks execution time.

Both names are single CN RDNs. Their values vary over the ASCII letters, digits,
space, apostrophe, hyphen and period. The exact allowed length pairs are issuer
40/subject24 and issuer24/subject40. Both names use UTF8String, or both use
PrintableString; mixed tags are rejected. Name values identify no trust authority.

Six mandatory extensions occur in forward or reverse order. Forward order is
AKI (noncritical), digitalSignature-only keyUsage (critical), end-entity empty
basicConstraints (critical), dedicated test application EKU (critical), opaque
organization[16] (critical), opaque group[32] (critical). AKI[20], organization
and group vary between credentials. There is no fixed issuer key, holder key,
issuer/subject name, AKI, organization, group, serial or date. Unknown, duplicate,
missing or other reordered extensions, extra name attributes, other algorithms,
GeneralizedTime and nonminimal DER lengths are rejected. Test-only OIDs are
listed in `profile.json`.

The eight layouts combine two name length pairs, two coupled name tags and two
extension orders. Their shared TBS length avoids variable SHA padding while
admitting different validity/subject/extension offsets. Every offset in imported material is
found by structural DER parsing. The static circuit offsets come from the
**declared abstract profile shapes**, never an imported certificate or byte search.
The profile generator is deterministic and does not consume a corpus file.

## Public statement and issuer eligibility

The ordered public fields are
`[root, issuerHash, notBefore, notAfter, actionHash, policyHash]` under
`credential-v3-bounded-six-public-fields-v1`. These are incompatible with five-field
v2 verification keys and program instructions.

All byte integers below are unsigned big endian. RSA limbs are 17 little-endian
121-bit limbs with bits beyond 2047 constrained zero. Define:

```
issuerKeyHash = Poseidon(2)(Poseidon(8)(issuerLimbs[0:8]),
                            Poseidon(9)(issuerLimbs[8:17]))
issuerHash = Poseidon(3)(2026101505, issuerKeyHash, uint160(signedAKI))
policyHash = Poseidon(4)(2026101503, uint128(signedOrganization),
                         uint128(signedGroup[0:16]), uint128(signedGroup[16:32]))
leaf = Poseidon(5)(2026101504, SHA256(TBS)_high128, SHA256(TBS)_low128, slot, 1)
```

The circuit constrains the entire selected DER shape, signed eligibility bytes,
validity, holder key, exact enrolled issuer modulus+AKI binding, issuance
signature, holder action signature and depth-10 active Merkle path. A prover who
bypasses host admission must still satisfy all these constraints. Poseidon
constants are those pinned by `tools/part5/poseidon.py`.

The application authority enables an exact `(issuerHash, policyHash, profile,
circuit)` tuple. It must bind that issuerHash to the enrolled CA key and AKI,
check CA enrollment/chain policy outside this relation, and enforce enabled/fresh
status, current root, execution validity and the exact action. A mathematically
valid certificate with an unknown issuer tuple or unenabled policy is not an
application authorization. AKI need not equal SHA1(key): enrollment deliberately
binds the explicit signed identifier to the issuer key. The descriptive issuer
CN is signed but contributes no enrollment authority.

The holder signs SHA-256 of the canonical 32-byte big-endian actionHash Fr value.
Changing the action invalidates holder authorization. The application must
reconstruct its action-v2 digest from actual request data and ordered accounts.

## Tooling and qualification

From the repository root:

```
python3 -m unittest discover -s tools/part5/tests -v
python3 -m tools.part5.credential_profile --write-profile circuits/credential-v3-bounded
python3 -m tools.part5.corpus --private-out /absolute/ignored/private/directory
```

The corpus independently encodes eight varied certificates with
`cryptography.x509`, two issuer keys and three holder keys, and a ninth with the
OpenSSL CLI. Keys are synthetic and discarded. It includes unrelated-root
refresh pairs, own-revocation roots, incorrect public bindings and issuer-signed
malformed policy/DER inputs that deliberately bypass admission. Private input
JSON and witnesses must stay ignored; report only aggregate evidence.

Compiler/setup/prover jobs require ROOT's resource grant. Compile the one fixed
`credential.circom` with the repository's Circom 2.2.3 and `-l node_modules`.
Use one separately identified Original BN254 setup for every corpus and unseen
certificate. Full and Anchor-refreshed proofs must pass independent ordinary and
matching application checks. Incremental witness generation, Dynamic, Selective
and automatic mode selection remain disabled. Compilation does not establish relation satisfaction or soundness. No product
readiness is claimed by the Python tests or this source review.

## First frozen compilation, October 15, 2026

The granted Circom 2.2.3 invocation produced `--r1cs --wasm --sym` with
`-l node_modules`, exiting 0. Compiler wall time was 19.52 seconds; the
external monitor recorded 20.079 seconds including process handling. The exact
maximum resident set size was 2,421,866,496 bytes, sampled aggregate peak RSS
was 2,336,800,768 bytes and peak memory footprint was 2,774,305,864 bytes.
Generated output before the report occupied 406,736,531 bytes, within the
300-second/4-GiB-RSS/1-GiB-output grant. Frozen source hashes remained unchanged.

| Item | Observed value |
| --- | --- |
| Total constraints | 793,681 (759,354 nonlinear + 34,327 linear) |
| Wires | 784,796 |
| Public / private input fields | 6 / 745 |
| R1CS bytes | 169,075,640 |
| R1CS SHA-256 | `976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888` |
| WASM bytes | 9,994,325 |
| WASM SHA-256 | `fbf73cff59660574add16ba8acafe824a9d57e0c91f23557b6462979b85c9aa6` |
| Calculator SHA-256 | `cc2d37b2cff2a589dd86f8636f1a1dc9fe4a854550b021aa0cea2e235d14e942` |

Primary private evidence is
`artifacts/dynark/part5/v3-compile-001/compile-report.json`, with the exact
compiler stdout/stderr and source-freeze receipt beside it. The immutable
`profile.json` retains its pre-compilation qualification label; this dated
compilation evidence describes the newer measured state. No setup identity
or verification key exists from this compilation.

The proposed next gate is described in
`tools/part5/WITNESS-PROPOSAL.md`. The runner checks the pinned WASM/R1CS,
sends the corpus directly to the actual compiled witness calculator and checks
every positive assignment against every R1CS row using an independent streaming
checker. Canonical input JSON uses decimal strings, preserving 254-bit field
values across JavaScript JSON parsing. Qualification requires a separate ROOT
grant and has not run merely because its helper tests pass.
