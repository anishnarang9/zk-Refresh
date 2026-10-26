//! First source-authentication RED; public synthetic Ed25519 fixtures only.
use credential_registry::v3::protocol::{
    CurrentHead, EnrolledSource, PublisherBinding, SignedSource, SourceHead, SOURCE_SIGN_TAG,
};
use credential_registry::Error;
use openssl::{
    pkey::{Id, PKey},
    sign::Verifier,
};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("vectors/v3-source-auth-v1.json")).unwrap()
}
fn decode_hex(value: &Value) -> Vec<u8> {
    let s = value.as_str().unwrap();
    assert_eq!(s.len() % 2, 0);
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}
fn row(v: &Value, index: usize) -> (SignedSource, EnrolledSource, SourceHead, i64) {
    let r = &v["issuers"][index];
    (
        serde_json::from_value(r["signed_source"].clone()).unwrap(),
        serde_json::from_value(r["enrolled_source"].clone()).unwrap(),
        serde_json::from_value(r["previous_head"].clone()).unwrap(),
        r["now"].as_i64().unwrap(),
    )
}

#[test]
fn independent_v3_enrolled_source_signature_is_accepted() {
    let v = fixture();
    let (source, enrolled, previous, now) = row(&v, 0);
    let bytes = decode_hex(&v["issuers"][0]["signing_bytes_hex"]);
    let mut expected = SOURCE_SIGN_TAG.to_vec();
    expected.extend(serde_json::to_vec(&source.observation).unwrap());
    assert_eq!(bytes, expected, "independent canonical signing preimage");
    let key = PKey::public_key_from_raw_bytes(&enrolled.issuer.source_key, Id::ED25519).unwrap();
    assert!(
        Verifier::new_without_digest(&key)
            .unwrap()
            .verify_oneshot(&source.signature, &bytes)
            .unwrap(),
        "independent signature fixture must be real"
    );
    assert_eq!(
        source.verify(&enrolled, &previous, now).map(|_| ()),
        Ok(()),
        "independent v3 source with exact enrollment/scope must authenticate"
    );
}

#[test]
fn separate_issuers_have_separate_keys_and_sequence_heads() {
    let v = fixture();
    let (a, ea, ha, now) = row(&v, 0);
    let (b, eb, hb, _) = row(&v, 1);
    assert_ne!(ea.issuer.source_key, eb.issuer.source_key);
    assert_ne!(ea.issuer.issuer_account, eb.issuer.issuer_account);
    assert_ne!(a.observation.sequence, b.observation.sequence);
    assert!(a.verify(&eb, &hb, now).is_err());
    assert!(b.verify(&ea, &ha, now).is_err());
    assert_eq!(a.verify(&ea, &ha, now).map(|_| ()), Ok(()));
    assert_eq!(b.verify(&eb, &hb, now).map(|_| ()), Ok(()));
}

#[test]
fn epoch_evidence_scope_key_and_signature_mutations_reject() {
    let v = fixture();
    let (base, enrolled, previous, now) = row(&v, 0);
    for field in 0..8 {
        let mut s = base.clone();
        match field {
            0 => s.observation.scope.config_eligibility_epoch += 1,
            1 => s.observation.issuer.issuer_eligibility_epoch += 1,
            2 => s.observation.issuer.enrollment_evidence_version += 1,
            3 => s.observation.issuer.evidence_digest[0] ^= 1,
            4 => s.observation.scope.policy_hash[0] ^= 1,
            5 => s.observation.scope.config[0] ^= 1,
            6 => s.observation.issuer.source_key[0] ^= 1,
            _ => s.signature[0] ^= 1,
        }
        assert!(s.verify(&enrolled, &previous, now).is_err());
    }
}

#[test]
fn replay_gap_stale_unobserved_and_disabled_authority_reject() {
    let v = fixture();
    let (source, enrolled, previous, now) = row(&v, 0);
    for sequence in [0, previous.sequence, source.observation.sequence + 1] {
        let mut wrong = source.clone();
        wrong.observation.sequence = sequence;
        assert!(wrong.verify(&enrolled, &previous, now).is_err());
    }
    assert!(source
        .verify(&enrolled, &previous, source.observation.valid_until + 1)
        .is_err());
    let mut wrong = previous.clone();
    wrong.digest[0] ^= 1;
    assert!(source.verify(&enrolled, &wrong, now).is_err());
    for field in 0..2 {
        let mut disabled = enrolled.clone();
        if field == 0 {
            disabled.config_enabled = false;
        } else {
            disabled.issuer_enabled = false;
        }
        assert!(source.verify(&disabled, &previous, now).is_err());
    }
}

#[test]
fn genuinely_resigned_scope_epoch_and_sequence_mismatches_reject() {
    let v = fixture();
    let (_, enrolled, previous, now) = row(&v, 0);
    for negative in v["resigned_negatives"].as_array().unwrap() {
        let source: SignedSource =
            serde_json::from_value(negative["signed_source"].clone()).unwrap();
        let bytes = decode_hex(&negative["signing_bytes_hex"]);
        let mut expected = if negative["name"] == "v2_signing_domain" {
            b"DYNARK-SOURCE-STATUS-v1\0".to_vec()
        } else {
            SOURCE_SIGN_TAG.to_vec()
        };
        expected.extend(serde_json::to_vec(&source.observation).unwrap());
        assert_eq!(bytes, expected, "independent resigned preimage");
        let key =
            PKey::public_key_from_raw_bytes(&source.observation.issuer.source_key, Id::ED25519)
                .unwrap();
        assert!(Verifier::new_without_digest(&key)
            .unwrap()
            .verify_oneshot(&source.signature, &bytes)
            .unwrap());
        // The fixture generator re-signs every mutation. These checks cannot
        // pass merely because an altered observation retained an old signature.
        assert!(
            source.verify(&enrolled, &previous, now).is_err(),
            "resigned mismatch admitted: {}",
            negative["name"]
        );
    }
}

#[test]
fn publisher_current_head_boundary_is_fail_closed_in_this_source_only_slice() {
    let v = fixture();
    let binding: PublisherBinding = serde_json::from_value(v["publisher_binding"].clone()).unwrap();
    let head: CurrentHead = serde_json::from_value(v["current_head"].clone()).unwrap();
    assert_eq!(
        binding.require_current(&head, 150),
        Err(Error::Authentication)
    );
}
