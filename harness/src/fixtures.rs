use anyhow::{ensure, Context, Result};
use chrono::{DateTime, Datelike, Utc};
use num_bigint::BigUint;
use openssl::{
    asn1::{Asn1Integer, Asn1Time, Asn1Type},
    bn::BigNum,
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    sign::Signer,
    x509::{X509NameBuilder, X509},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};
pub type Field = [u8; 32];
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Issuer {
    pub public_key: String,
    pub private_key: String,
    #[serde(deserialize_with = "decode_binary")]
    pub modulus: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    pub pem: String,
    #[serde(deserialize_with = "decode_binary")]
    pub tbs: Vec<u8>,
    #[serde(deserialize_with = "decode_binary")]
    pub signature: Vec<u8>,
    #[serde(deserialize_with = "decode_binary")]
    pub serial: Vec<u8>,
    #[serde(deserialize_with = "decode_binary")]
    pub holder_modulus: Vec<u8>,
    pub public_key: String,
    pub private_key: String,
    pub organization: String,
    pub not_before: i64,
    pub not_after: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fixtures {
    pub issuer: Issuer,
    pub credentials: Vec<Credential>,
    pub not_before: i64,
    pub not_after: i64,
}
fn decode_binary<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<u8>, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    serde_json::from_value(value.get("data").cloned().unwrap_or(value))
        .map_err(serde::de::Error::custom)
}
pub fn create_fixtures(count: usize, not_before: i64, not_after: i64) -> Result<Fixtures> {
    ensure!(
        (1..=1024).contains(&count),
        "Credential count must be 1-1024"
    );
    ensure!(not_before < not_after, "Invalid validity interval");
    for value in [not_before, not_after] {
        let date: DateTime<Utc> =
            DateTime::from_timestamp(value, 0).context("Invalid timestamp")?;
        ensure!(
            (2000..=2049).contains(&date.year()),
            "Profile supports years 2000-2049"
        );
    }
    let issuer_key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let mut issuer_name = X509NameBuilder::new()?;
    issuer_name.append_entry_by_text_with_type(
        "CN",
        "ZK Fresh Test Issuer",
        Asn1Type::PRINTABLESTRING,
    )?;
    let issuer_name = issuer_name.build();
    let issuer = Issuer {
        public_key: String::from_utf8(issuer_key.public_key_to_pem()?)?,
        private_key: String::from_utf8(issuer_key.private_key_to_pem_pkcs8()?)?,
        modulus: issuer_key.rsa()?.n().to_vec(),
    };
    let mut credentials = Vec::with_capacity(count);
    for index in 0..count {
        let holder = PKey::from_rsa(Rsa::generate(2048)?)?;
        let mut subject = X509NameBuilder::new()?;
        subject.append_entry_by_text_with_type("CN", "holder", Asn1Type::PRINTABLESTRING)?;
        subject.append_entry_by_text_with_type("O", "ZK Fresh", Asn1Type::PRINTABLESTRING)?;
        let subject = subject.build();
        let serial = (BigUint::from(1u8) << 124usize) + BigUint::from(index);
        let serial = serial.to_bytes_be();
        let serial_bn = BigNum::from_slice(&serial)?;
        let serial_asn1 = Asn1Integer::from_bn(&serial_bn)?;
        let before = Asn1Time::from_unix(not_before)?;
        let after = Asn1Time::from_unix(not_after)?;
        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_serial_number(&serial_asn1)?;
        builder.set_issuer_name(&issuer_name)?;
        builder.set_subject_name(&subject)?;
        builder.set_pubkey(&holder)?;
        builder.set_not_before(&before)?;
        builder.set_not_after(&after)?;
        builder.sign(&issuer_key, MessageDigest::sha256())?;
        let cert = builder.build();
        let der = cert.to_der()?;
        let (outer, _) = der_content(&der, 0)?;
        let (_, end) = der_content(&der, outer)?;
        let tbs = der[outer..end].to_vec();
        validate_profile(&tbs)?;
        credentials.push(Credential {
            pem: String::from_utf8(cert.to_pem()?)?,
            tbs,
            signature: cert.signature().as_slice().to_vec(),
            serial,
            holder_modulus: holder.rsa()?.n().to_vec(),
            public_key: String::from_utf8(holder.public_key_to_pem()?)?,
            private_key: String::from_utf8(holder.private_key_to_pem_pkcs8()?)?,
            organization: "ZK Fresh".into(),
            not_before,
            not_after,
        });
    }
    Ok(Fixtures {
        issuer,
        credentials,
        not_before,
        not_after,
    })
}
fn der_content(bytes: &[u8], start: usize) -> Result<(usize, usize)> {
    ensure!(bytes.get(start) == Some(&0x30), "Expected DER sequence");
    let first = *bytes.get(start + 1).context("Incomplete DER length")?;
    let mut content = start + 2;
    let len = if first < 128 {
        first as usize
    } else {
        let width = (first & 127) as usize;
        ensure!((1..=4).contains(&width), "Invalid DER length");
        let mut length = 0usize;
        for _ in 0..width {
            length = (length << 8) + *bytes.get(content).context("Incomplete DER length")? as usize;
            content += 1;
        }
        length
    };
    ensure!(content + len <= bytes.len(), "Truncated DER value");
    Ok((content, content + len))
}
pub fn validate_profile(tbs: &[u8]) -> Result<()> {
    let profile: serde_json::Value =
        serde_json::from_str(include_str!("data/legacy-static-x509-profile.json"))?;
    let template: Vec<u8> = serde_json::from_value(profile["template"].clone())?;
    ensure!(tbs.len() == 439, "Unsupported certificate profile length");
    for index in 0..439 {
        if !((11..27).contains(&index)
            || (79..92).contains(&index)
            || (94..107).contains(&index)
            || (178..434).contains(&index))
        {
            ensure!(
                tbs[index] == template[index],
                "Unsupported profile at byte {index}"
            );
        }
    }
    ensure!(tbs[11] > 0 && tbs[11] < 128, "Unsupported serial profile");
    ensure!(
        tbs[178] >= 128 && tbs[433] & 1 == 1,
        "Unsupported RSA modulus profile"
    );
    for start in [79, 94] {
        ensure!(
            tbs[start..start + 12].iter().all(u8::is_ascii_digit) && tbs[start + 12] == b'Z',
            "Unsupported date profile"
        );
        let text = std::str::from_utf8(&tbs[start..start + 13])?;
        let year = std::str::from_utf8(&tbs[start..start + 2])?.parse::<u32>()?;
        ensure!(year <= 49, "Unsupported date year");
        chrono::NaiveDateTime::parse_from_str(&format!("20{text}"), "%Y%m%d%H%M%SZ")
            .context("Invalid certificate date")?;
    }
    Ok(())
}
pub fn field_decimal(value: &Field) -> String {
    num_bigint::BigUint::from_bytes_be(value).to_string()
}
pub fn scalar_modulus() -> BigUint {
    BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .unwrap()
}
pub fn field_from_decimal(value: &str) -> Result<Field> {
    let number = BigUint::parse_bytes(value.as_bytes(), 10).context("Invalid field integer")?;
    ensure!(number < scalar_modulus(), "Noncanonical field");
    field_from_biguint(&number)
}
pub fn field_from_biguint(value: &BigUint) -> Result<Field> {
    ensure!(value < &scalar_modulus(), "Noncanonical field");
    let bytes = value.to_bytes_be();
    let mut output = [0; 32];
    output[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(output)
}
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub fn limbs(bytes: &[u8]) -> Result<Vec<String>> {
    let mut value = BigUint::from_bytes_be(bytes);
    let mask = (BigUint::from(1u8) << 121usize) - BigUint::from(1u8);
    let mut result = Vec::with_capacity(17);
    for _ in 0..17 {
        result.push((&value & &mask).to_string());
        value >>= 121;
    }
    ensure!(
        value == BigUint::from(0u8),
        "RSA integer exceeds circuit capacity"
    );
    Ok(result)
}
pub fn ownership_signature(credential: &Credential, action: &Field) -> Result<Vec<u8>> {
    let key = PKey::private_key_from_pem(credential.private_key.as_bytes())?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
    signer.update(action)?;
    Ok(signer.sign_to_vec()?)
}
pub fn load_fixtures() -> Result<Fixtures> {
    Ok(serde_json::from_slice(&fs::read(
        "artifacts/fixtures.json",
    )?)?)
}
pub fn write_json(path: impl AsRef<Path>, value: &impl Serialize, private: bool) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(if private { 0o600 } else { 0o644 })
        .open(path)?;
    if private {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    Ok(())
}
pub fn write_profile() -> Result<()> {
    let profile: serde_json::Value =
        serde_json::from_str(include_str!("data/legacy-static-x509-profile.json"))?;
    let template: Vec<u8> = serde_json::from_value(profile["template"].clone())?;
    let flags: Vec<u8> = (0..439)
        .map(|index| {
            u8::from(
                (11..27).contains(&index)
                    || (79..92).contains(&index)
                    || (94..107).contains(&index)
                    || (178..434).contains(&index),
            )
        })
        .collect();
    fs::create_dir_all("circuits/generated")?;
    fs::write("circuits/generated/profile.circom", format!("pragma circom 2.2.3;\nfunction TBS_LEN() {{ return 439; }}\nfunction SERIAL_OFFSET() {{ return 11; }}\nfunction NOT_BEFORE_OFFSET() {{ return 79; }}\nfunction NOT_AFTER_OFFSET() {{ return 94; }}\nfunction MODULUS_OFFSET() {{ return 178; }}\nfunction ProfileByte(i) {{ var bytes[439] = {}; return bytes[i]; }}\nfunction IsDynamic(i) {{ var flags[439] = {}; return flags[i]; }}\n",serde_json::to_string(&template)?,serde_json::to_string(&flags)?))?;
    Ok(())
}
