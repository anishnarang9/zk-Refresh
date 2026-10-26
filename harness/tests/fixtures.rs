use openssl::{hash::MessageDigest, pkey::PKey, sign::Verifier};
use zk_fresh_benchmark::fixtures::{create_fixtures, field_from_decimal, validate_profile};

#[test]
fn rust_certificates_match_the_compiled_profile_and_have_real_signatures() {
    let fixtures = create_fixtures(2, 1_791_000_000, 1_791_086_400).unwrap();
    let issuer = PKey::public_key_from_pem(fixtures.issuer.public_key.as_bytes()).unwrap();
    for credential in &fixtures.credentials {
        validate_profile(&credential.tbs).unwrap();
        assert_eq!(credential.tbs.len(), 439);
        let mut verifier = Verifier::new(MessageDigest::sha256(), &issuer).unwrap();
        verifier.update(&credential.tbs).unwrap();
        assert!(verifier.verify(&credential.signature).unwrap());
        let mut changed = credential.tbs.clone();
        changed[135] ^= 1;
        assert!(validate_profile(&changed).is_err());
        for first in [0, 128] {
            let mut changed = credential.tbs.clone();
            changed[11] = first;
            assert!(validate_profile(&changed).is_err());
        }
    }
}

#[test]
fn field_encoding_rejects_noncanonical_values() {
    let field = field_from_decimal("123").unwrap();
    assert_eq!(field[31], 123);
    assert!(field[..31].iter().all(|byte| *byte == 0));
    assert!(field_from_decimal(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617"
    )
    .is_err());
    assert!(field_from_decimal("-1").is_err());
}
