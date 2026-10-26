//! Versioned Original BN254 setup and six-field package qualification.
//! Fresh suite and input-pin digests are supplied by an external reviewer.
#![forbid(unsafe_code)]
use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use dynark_bn254::{
    import, public_schema_digest, CircuitDescriptor, Limits, PackageIdentity, PublicPackage,
    Reduction,
};
use rand::rngs::OsRng;
use serde::{
    de::{MapAccess, SeqAccess, Visitor},
    Deserialize,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs::{self, File, OpenOptions},
    io::{BufWriter, Cursor, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    str::FromStr,
    time::Instant,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const ASSIGNMENT_FIELDS: usize = 784_796;
const ROWS: usize = 793_681;
const ENTRIES: usize = 4_257_583;
const N: usize = 1_048_576;
const FOUR_GIB: usize = 4 * 1024 * 1024 * 1024;
const MAX_INPUT_PINS_BYTES: u64 = 64 * 1024;
const MAX_PINNED_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
const PUBLIC_FIELDS: [&str; 6] = [
    "root",
    "issuerHash",
    "notBefore",
    "notAfter",
    "actionHash",
    "policyHash",
];
const R1CS_SHA: &str = "976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888";
const WASM_SHA: &str = "fbf73cff59660574add16ba8acafe824a9d57e0c91f23557b6462979b85c9aa6";
const PROFILE_SHA: &str = "2e5d26564fb055e70cff924c4cb6e296509030b8c0062130f86ad5af783f7918";
const SEMANTIC_SCHEMA: &str = "eabfaa2d95e4abc9126b87a04e94397091c103891e92dbaefaafba79cf3b26d4";
const CIRCUIT_SOURCE_ID: &str = "48d051e16dd1773b1831d9960a4a7f5a1fb6afd153ec2d87493696deb145d901";
const INPUT_PINS_SCHEMA: &str = "part5-v3-fresh-package-input-pins-v2";
const SEMANTIC_HASHES: [(&str, &str); 6] = [
    ("r1cs_sha256", R1CS_SHA),
    ("wasm_sha256", WASM_SHA),
    ("profile_sha256", PROFILE_SHA),
    ("semantic_schema_sha256", SEMANTIC_SCHEMA),
    ("circuit_source_sha256", CIRCUIT_SOURCE_ID),
    (
        "symbol_map_sha256",
        "d2d66e238bdc0a731c86c1897c2978d23908dcc19460582cc873dc2d41e5dbf0",
    ),
];

fn required(value: bool, reason: &'static str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(reason.into())
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn unhex(text: &str) -> Result<[u8; 32]> {
    required(
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "digest encoding",
    )?;
    let mut result = [0u8; 32];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)?;
    }
    Ok(result)
}
fn bounded_file(path: &Path, cap: u64, private: bool, owner: u32) -> Result<File> {
    let received = fs::symlink_metadata(path)?;
    required(
        received.is_file() && !received.file_type().is_symlink() && received.len() <= cap,
        "artifact type/size",
    )?;
    if private {
        required(
            received.permissions().mode() & 0o777 == 0o600 && received.uid() == owner,
            "private artifact permissions/owner",
        )?;
    } else {
        // Public profile and compiler outputs are pinned, nonsecret artifacts.
        // 0644 is expected for checked-in profile/Circom outputs; 0600 is allowed.
        required(
            matches!(received.permissions().mode() & 0o777, 0o600 | 0o644)
                && received.uid() == owner,
            "public artifact permissions/owner",
        )?;
    }
    let file = File::open(path)?;
    let opened = file.metadata()?;
    required(
        opened.ino() == received.ino()
            && opened.dev() == received.dev()
            && opened.len() == received.len(),
        "artifact changed at open",
    )?;
    Ok(file)
}
fn hash_file(path: &Path, cap: u64, private: bool, owner: u32) -> Result<[u8; 32]> {
    let mut file = bounded_file(path, cap, private, owner)?;
    let length = file.metadata()?.len();
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut consumed = 0u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        consumed += count as u64;
        required(consumed <= length, "artifact grew during hashing")?;
        hash.update(&buffer[..count]);
    }
    required(
        consumed == length && file.metadata()?.len() == length,
        "artifact length changed",
    )?;
    Ok(hash.finalize().into())
}
fn pinned(path: &Path, expected: &str, cap: u64, private: bool, owner: u32) -> Result<()> {
    required(
        hash_file(path, cap, private, owner)? == unhex(expected)?,
        "artifact digest mismatch",
    )
}
fn received_bytes(
    path: &Path,
    digest: &str,
    cap: u64,
    private: bool,
    owner: u32,
) -> Result<Vec<u8>> {
    let file = bounded_file(path, cap, private, owner)?;
    let mut bytes = Vec::new();
    file.take(cap + 1).read_to_end(&mut bytes)?;
    required(
        bytes.len() as u64 <= cap,
        "received artifact allocation cap",
    )?;
    required(
        <[u8; 32]>::from(Sha256::digest(&bytes)) == unhex(digest)?,
        "received artifact digest",
    )?;
    Ok(bytes)
}
fn public_bytes(path: &Path, cap: u64, owner: u32) -> Result<Vec<u8>> {
    required(path.is_absolute(), "absolute public input required")?;
    required(
        fs::canonicalize(path)? == path,
        "canonical nonsymlink public input required",
    )?;
    let before_path = fs::symlink_metadata(path)?;
    let mut file = bounded_file(path, cap, false, owner)?;
    let before = file.metadata()?;
    required(before.len() > 0, "nonempty public input required")?;
    let mut bytes = Vec::new();
    (&mut file).take(cap + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let after_path = fs::symlink_metadata(path)?;
    required(bytes.len() as u64 <= cap, "public input allocation cap")?;
    for (left, right) in [(&before, &after), (&before_path, &after_path)] {
        required(
            left.dev() == right.dev()
                && left.ino() == right.ino()
                && left.len() == right.len()
                && left.mtime() == right.mtime()
                && left.mtime_nsec() == right.mtime_nsec()
                && left.ctime() == right.ctime()
                && left.ctime_nsec() == right.ctime_nsec(),
            "public input changed during read",
        )?;
    }
    required(bytes.len() as u64 == before.len(), "public input length")?;
    Ok(bytes)
}
fn exact_fields(value: &Value, expected: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or("expected object")?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    required(actual == expected, "unknown or missing record fields")
}
fn valid_sha(value: &Value) -> Result<&str> {
    let digest = value.as_str().ok_or("SHA-256 string required")?;
    unhex(digest)?;
    Ok(digest)
}
fn valid_release(value: &Value) -> Result<()> {
    let release = value.as_str().ok_or("toolchain release string required")?;
    required(release.len() <= 64, "bounded toolchain release identifier")?;
    let version = release.strip_prefix('v').unwrap_or(release);
    let (numbers, suffix) = match version.split_once('-') {
        Some((numbers, suffix)) => (numbers, Some(suffix)),
        None => (version, None),
    };
    let parts = numbers.split('.').collect::<Vec<_>>();
    required(parts.len() == 3, "semantic release version required")?;
    for part in parts {
        required(
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part == "0" || !part.starts_with('0')),
            "semantic release version required",
        )?;
    }
    if let Some(suffix) = suffix {
        required(
            !suffix.is_empty()
                && suffix
                    .split(|character| character == '.' || character == '-')
                    .all(|part| {
                        !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_alphanumeric())
                    }),
            "bounded prerelease identifier required",
        )?;
    }
    Ok(())
}
fn public_source_path(value: &Value) -> Result<std::path::PathBuf> {
    let text = value.as_str().ok_or("public source path required")?;
    required(
        !text.is_empty()
            && text.len() <= 240
            && text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_./-".contains(&byte))
            && text.split('/').all(|part| {
                !part.is_empty() && part != "." && part != ".." && !part.starts_with('.')
            }),
        "invalid public source path",
    )?;
    let path = std::path::PathBuf::from(text);
    required(!path.is_absolute(), "relative public source path required")?;
    let root_config = matches!(
        text,
        "package.json" | "package-lock.json" | "Cargo.toml" | "Cargo.lock" | "rust-toolchain.toml"
    );
    let direct_profile = text == "circuits/credential-v3-bounded/profile.json";
    let in_prefix = [
        "circuits/credential-v3-bounded/",
        "tools/part5/",
        "harness/tests/",
        "program/src/",
    ]
    .iter()
    .any(|prefix| text.starts_with(prefix));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let source = matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("circom" | "rs" | "py" | "cjs")
    ) || matches!(file_name, "Cargo.toml" | "Cargo.lock");
    required(
        root_config || direct_profile || (in_prefix && source),
        "only public source/config references are allowed",
    )?;
    Ok(path)
}
fn repo_root() -> Result<std::path::PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../");
    let root = fs::canonicalize(root)?;
    required(root.is_dir(), "repository directory required")?;
    Ok(root)
}
fn validate_input_pins(value: &Value, owner: u32) -> Result<()> {
    exact_fields(
        value,
        &[
            "schema",
            "source_commit",
            "toolchain",
            "semantic_hashes",
            "census",
            "ordered_public_inputs",
            "reviewed_suite",
            "public_repo_files",
        ],
    )?;
    required(
        text(value, "schema")? == INPUT_PINS_SCHEMA,
        "input-pins schema",
    )?;
    let source_commit = text(value, "source_commit")?;
    required(
        source_commit.len() == 40
            && source_commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "40-character source commit required",
    )?;

    let toolchain = &value["toolchain"];
    exact_fields(
        toolchain,
        &[
            "circom_version",
            "node_version",
            "rustc_version",
            "cargo_version",
            "circom_binary_sha256",
        ],
    )?;
    for name in [
        "circom_version",
        "node_version",
        "rustc_version",
        "cargo_version",
    ] {
        valid_release(&toolchain[name])?;
    }
    valid_sha(&toolchain["circom_binary_sha256"])?;

    let semantic = &value["semantic_hashes"];
    exact_fields(
        semantic,
        &[
            "r1cs_sha256",
            "wasm_sha256",
            "profile_sha256",
            "semantic_schema_sha256",
            "circuit_source_sha256",
            "symbol_map_sha256",
        ],
    )?;
    for (name, expected) in SEMANTIC_HASHES {
        required(
            valid_sha(&semantic[name])? == expected,
            "accepted semantic identity mismatch",
        )?;
    }

    let census = &value["census"];
    exact_fields(
        census,
        &[
            "assignment_fields",
            "constraints",
            "matrix_entries",
            "domain_size",
        ],
    )?;
    for (name, expected) in [
        ("assignment_fields", ASSIGNMENT_FIELDS as u64),
        ("constraints", ROWS as u64),
        ("matrix_entries", ENTRIES as u64),
        ("domain_size", N as u64),
    ] {
        required(
            census[name].as_u64() == Some(expected),
            "exact relation census required",
        )?;
    }

    let public_inputs = value["ordered_public_inputs"]
        .as_array()
        .ok_or("public-input order")?;
    required(
        public_inputs.len() == PUBLIC_FIELDS.len()
            && public_inputs
                .iter()
                .zip(PUBLIC_FIELDS)
                .all(|(actual, expected)| actual.as_str() == Some(expected)),
        "exact public input order required",
    )?;

    let suite = &value["reviewed_suite"];
    exact_fields(
        suite,
        &[
            "report_sha256",
            "total_count",
            "accepted_count",
            "rejected_count",
        ],
    )?;
    valid_sha(&suite["report_sha256"])?;
    for (name, expected) in [
        ("total_count", 52),
        ("accepted_count", 18),
        ("rejected_count", 34),
    ] {
        required(
            suite[name].as_u64() == Some(expected),
            "exact 52-case suite census required",
        )?;
    }

    let files = value["public_repo_files"]
        .as_array()
        .ok_or("public file references")?;
    required(
        files.len() <= 128,
        "bounded public file reference list required",
    )?;
    let root = repo_root()?;
    let mut previous = String::new();
    let mut pinned = Vec::with_capacity(files.len());
    for reference in files {
        exact_fields(reference, &["path", "sha256"])?;
        let path_text = text(reference, "path")?;
        let relative = public_source_path(&reference["path"])?;
        required(
            path_text > previous.as_str(),
            "public references must be sorted and distinct",
        )?;
        previous = path_text.to_owned();
        let digest = valid_sha(&reference["sha256"])?;
        if path_text == "circuits/credential-v3-bounded/profile.json" {
            required(
                digest == PROFILE_SHA,
                "public profile reference differs from accepted pin",
            )?;
        }
        let source = root.join(relative);
        required(
            fs::canonicalize(&source)? == source,
            "canonical public source required",
        )?;
        let bytes = public_bytes(&source, MAX_PINNED_SOURCE_BYTES, owner)?;
        required(
            hex(&Sha256::digest(&bytes)) == digest,
            "current public source digest mismatch",
        )?;
        pinned.push((source, digest.to_owned()));
    }
    for (source, digest) in pinned {
        let bytes = public_bytes(&source, MAX_PINNED_SOURCE_BYTES, owner)?;
        required(
            hex(&Sha256::digest(&bytes)) == digest,
            "public source changed during verification",
        )?;
    }
    Ok(())
}
struct StrictJson(Value);
impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StrictJsonVisitor;
        impl<'de> Visitor<'de> for StrictJsonVisitor {
            type Value = StrictJson;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
            }
            fn visit_unit<E>(self) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictJson(Value::Null))
            }
            fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictJson(Value::Bool(value)))
            }
            fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictJson(Value::Number(value.into())))
            }
            fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictJson(Value::Number(value.into())))
            }
            fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let number = serde_json::Number::from_f64(value)
                    .ok_or_else(|| E::custom("non-finite JSON number"))?;
                Ok(StrictJson(Value::Number(number)))
            }
            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictJson(Value::String(value.to_owned())))
            }
            fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictJson(Value::String(value)))
            }
            fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(StrictJson(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(StrictJson(Value::Array(values)))
            }
            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(<A::Error as serde::de::Error>::custom(
                            "duplicate JSON object key",
                        ));
                    }
                    let StrictJson(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(StrictJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}
fn parse_strict_json(bytes: &[u8]) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let StrictJson(value) = StrictJson::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}
fn authenticated_input_pins(bytes: &[u8], expected_digest: &str) -> Result<Value> {
    unhex(expected_digest)?;
    required(
        !bytes.is_empty()
            && bytes.len() as u64 <= MAX_INPUT_PINS_BYTES
            && hex(&Sha256::digest(bytes)) == expected_digest,
        "input-pins byte digest mismatch",
    )?;
    parse_strict_json(bytes)
}
fn verify_input_pins(path: &Path, expected_digest: &str, owner: u32) -> Result<Value> {
    let bytes = public_bytes(path, MAX_INPUT_PINS_BYTES, owner)?;
    let value = authenticated_input_pins(&bytes, expected_digest)?;
    validate_input_pins(&value, owner)?;
    required(
        public_bytes(path, MAX_INPUT_PINS_BYTES, owner)? == bytes,
        "input-pins record changed during verification",
    )?;
    Ok(value)
}
fn json_file(path: &Path, digest: &str, owner: u32) -> Result<Value> {
    let bytes = received_bytes(path, digest, 65536, true, owner)?;
    parse_strict_json(&bytes)
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or("manifest string field".into())
}
fn private_file(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}
fn save_json(path: &Path, value: &Value) -> Result<()> {
    let file = private_file(path)?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(())
}
fn save<T: CanonicalSerialize>(path: &Path, value: &T) -> Result<String> {
    let file = private_file(path)?;
    let mut writer = BufWriter::new(file);
    value.serialize_compressed(&mut writer)?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(hex(&hash_file(
        path,
        512 * 1024 * 1024,
        true,
        writer.get_ref().metadata()?.uid(),
    )?))
}
fn event(out: &Path, stage: &'static str, started: Instant) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(out.join("events.jsonl"))?;
    serde_json::to_writer(
        &mut file,
        &json!({"stage": stage, "elapsed_ms": started.elapsed().as_secs_f64()*1000.0}),
    )?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
fn output(path: &Path) -> Result<u32> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    let metadata = path.metadata()?;
    required(
        metadata.permissions().mode() & 0o777 == 0o700,
        "private output directory",
    )?;
    private_file(&path.join("events.jsonl"))?.sync_all()?;
    Ok(metadata.uid())
}
fn binary_hash(owner: u32) -> Result<String> {
    let path = std::env::current_exe()?;
    let meta = fs::symlink_metadata(&path)?;
    required(
        meta.is_file()
            && !meta.file_type().is_symlink()
            && meta.uid() == owner
            && meta.len() <= 64 * 1024 * 1024
            && meta.permissions().mode() & 0o022 == 0,
        "binary metadata",
    )?;
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    required(
        opened.ino() == meta.ino() && opened.dev() == meta.dev(),
        "binary changed at open",
    )?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut count = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        required(count <= meta.len(), "binary grew")?;
        hasher.update(&buffer[..n]);
    }
    required(
        count == meta.len() && file.metadata()?.len() == meta.len(),
        "binary changed length",
    )?;
    Ok(hex(&hasher.finalize()))
}
fn decode_witness(
    bytes: &[u8],
    expected_count: usize,
) -> std::result::Result<Vec<Fr>, &'static str> {
    if expected_count < 7 || expected_count > ASSIGNMENT_FIELDS || bytes.len() > 32 * 1024 * 1024 {
        return Err("WTNS size/count bound");
    }
    let count_bytes = (expected_count as u32).to_le_bytes();
    let expected_bytes = expected_count
        .checked_mul(32)
        .and_then(|size| size.checked_add(76))
        .ok_or("WTNS length overflow")?;
    if bytes.len() != expected_bytes
        || &bytes[..4] != b"wtns"
        || bytes[4..8] != 2u32.to_le_bytes()
        || bytes[8..12] != 2u32.to_le_bytes()
        || bytes[12..16] != 1u32.to_le_bytes()
        || bytes[16..24] != 40u64.to_le_bytes()
        || bytes[24..28] != 32u32.to_le_bytes()
        || bytes[28..60] != Fr::MODULUS.to_bytes_le()
        || bytes[60..64] != count_bytes
        || bytes[64..68] != 2u32.to_le_bytes()
        || bytes[68..76] != ((expected_count * 32) as u64).to_le_bytes()
    {
        return Err("canonical WTNS header/sections");
    }
    let mut result = Vec::with_capacity(expected_count);
    for chunk in bytes[76..].chunks_exact(32) {
        result.push(Fr::deserialize_compressed(chunk).map_err(|_| "noncanonical WTNS field")?);
    }
    if result[0] != Fr::ONE {
        return Err("WTNS constant one");
    }
    Ok(result)
}
fn encoded(values: &[Fr]) -> Result<Vec<[u8; 32]>> {
    values
        .iter()
        .map(|value| {
            let mut bytes = [0u8; 32];
            value.serialize_compressed(&mut bytes[..])?;
            Ok(bytes)
        })
        .collect()
}

fn limits() -> Limits {
    Limits {
        max_domain: N,
        max_assignment: ASSIGNMENT_FIELDS,
        max_matrix_entries: 4_500_000,
        max_delta_entries: 8192,
        max_pair_work: 11_000_000,
        max_allocation_bytes: FOUR_GIB,
    }
}
fn imports() -> import::ImportLimits {
    import::ImportLimits {
        operation: limits(),
        max_file_bytes: 192 * 1024 * 1024,
        max_section_bytes: 160 * 1024 * 1024,
        max_sections: 3,
        max_row_entries: 4096,
    }
}
fn fixed_descriptor() -> Result<CircuitDescriptor> {
    let names = PUBLIC_FIELDS.map(str::to_owned).to_vec();
    Ok(CircuitDescriptor {
        r1cs_artifact_digest: unhex(R1CS_SHA)?,
        witness_executable_digest: unhex(WASM_SHA)?,
        profile_digest: unhex(PROFILE_SHA)?,
        public_schema_digest: public_schema_digest(&names),
        public_schema: names,
        reduction: Reduction::Original,
    })
}
fn private_directory(path: &Path, owner: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    required(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == owner
            && metadata.permissions().mode() & 0o777 == 0o700,
        "protected directory",
    )
}
fn descriptor(r1cs: &Path, wasm: &Path, profile: &Path, owner: u32) -> Result<CircuitDescriptor> {
    let root = r1cs.parent().ok_or("compile root")?;
    private_directory(root, owner)?;
    required(
        wasm.parent().and_then(Path::parent) == Some(root),
        "shared compile directory",
    )?;
    let wasm_directory = fs::symlink_metadata(wasm.parent().ok_or("WASM directory")?)?;
    required(
        wasm_directory.is_dir()
            && !wasm_directory.file_type().is_symlink()
            && wasm_directory.uid() == owner,
        "WASM directory metadata",
    )?;
    pinned(r1cs, R1CS_SHA, 192 * 1024 * 1024, false, owner)?;
    pinned(wasm, WASM_SHA, 16 * 1024 * 1024, false, owner)?;
    pinned(profile, PROFILE_SHA, 65536, false, owner)?;
    fixed_descriptor()
}
fn identity_json(id: PackageIdentity) -> Value {
    json!({"matrix":hex(&id.matrix_digest),"circuit":hex(&id.circuit_digest),"pk":hex(&id.proving_key_digest),
        "engine_extended_vk":hex(&id.verifying_key_digest),"package":hex(&id.package_digest)})
}
fn parse_identity(value: &Value) -> Result<PackageIdentity> {
    Ok(PackageIdentity {
        matrix_digest: unhex(text(value, "matrix")?)?,
        circuit_digest: unhex(text(value, "circuit")?)?,
        proving_key_digest: unhex(text(value, "pk")?)?,
        verifying_key_digest: unhex(text(value, "engine_extended_vk")?)?,
        package_digest: unhex(text(value, "package")?)?,
    })
}
fn parse_public(value: &Value) -> Result<Vec<Fr>> {
    let fields = value.as_array().ok_or("expected public array")?;
    required(fields.len() == 6, "expected six public fields")?;
    fields
        .iter()
        .map(|item| {
            let value = item.as_str().ok_or("public decimal string")?;
            required(
                !value.is_empty()
                    && value.len() <= 77
                    && value.bytes().all(|x| x.is_ascii_digit())
                    && (value == "0" || !value.starts_with('0')),
                "canonical public decimal",
            )?;
            let scalar = Fr::from_str(value).map_err(|_| "public field bound")?;
            required(scalar.to_string() == value, "canonical public field")?;
            Ok(scalar)
        })
        .collect()
}
fn expected_public(path: &Path, digest: &str, owner: u32) -> Result<Vec<Fr>> {
    parse_public(&json_file(path, digest, owner)?)
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 80
        && name.bytes().all(|x| x.is_ascii_alphanumeric() || x == b'_')
}
fn expected_suite_cases() -> BTreeMap<String, (&'static str, &'static str)> {
    let mut expected = BTreeMap::new();
    for i in 0..9 {
        let base = format!("credential_{i}");
        expected.insert(base.clone(), ("accept", "credential"));
        expected.insert(
            format!("{base}_unrelated_refresh"),
            ("accept", "unrelated_refresh"),
        );
        expected.insert(format!("{base}_own_revoked"), ("reject", "own_revocation"));
        expected.insert(
            format!("{base}_wrong_public_policy"),
            ("reject", "wrong_policy_binding"),
        );
        expected.insert(
            format!("{base}_wrong_public_issuer"),
            ("reject", "wrong_issuer_binding"),
        );
        if i == 0 {
            for suffix in [
                "_invalid_cn",
                "_invalid_purpose",
                "_invalid_key_usage",
                "_invalid_serial",
            ] {
                expected.insert(
                    format!("{base}{suffix}"),
                    ("reject", "signed_profile_bypass"),
                );
            }
            for suffix in [
                "_signed_organization_old_binding",
                "_signed_aki_old_binding",
            ] {
                expected.insert(
                    format!("{base}{suffix}"),
                    ("reject", "signed_binding_bypass"),
                );
            }
            expected.insert(
                format!("{base}_invalid_layout"),
                ("reject", "invalid_layout"),
            );
        }
    }
    expected
}
fn validate_case_time(value: &Value) -> Result<()> {
    required(
        value
            .as_f64()
            .is_some_and(|elapsed| elapsed.is_finite() && elapsed >= 0.0),
        "suite case timing",
    )
}
fn validate_suite(value: &Value) -> Result<BTreeSet<String>> {
    exact_fields(
        value,
        &[
            "schema",
            "passed",
            "r1cs_sha256",
            "wasm_sha256",
            "host_admission_bypassed",
            "setup_or_proofs_executed",
            "outputs_private",
            "cases",
            "accepted_count",
            "rejected_count",
        ],
    )?;
    required(
        text(value, "schema")? == "credential-v3-bounded-witness-qualification-v1"
            && value["passed"] == true
            && value["host_admission_bypassed"] == true
            && value["setup_or_proofs_executed"] == false
            && value["outputs_private"] == true
            && text(value, "r1cs_sha256")? == R1CS_SHA
            && text(value, "wasm_sha256")? == WASM_SHA
            && value["accepted_count"].as_u64() == Some(18)
            && value["rejected_count"].as_u64() == Some(34),
        "accepted suite context",
    )?;
    let cases = value["cases"].as_array().ok_or("suite cases")?;
    let expected = expected_suite_cases();
    required(
        cases.len() == 52 && expected.len() == 52,
        "exact registered 52-case suite",
    )?;
    let mut seen = BTreeSet::new();
    let mut accepted = BTreeSet::new();
    let mut rejected = 0;
    for item in cases {
        required(item.is_object(), "suite case object required")?;
        let name = text(item, "name")?;
        required(
            valid_name(name) && seen.insert(name.to_owned()) && item["passed"] == true,
            "unique passed suite case",
        )?;
        let (expected_outcome, expected_family) = expected
            .get(name)
            .ok_or("unregistered witness suite case")?;
        required(
            text(item, "expected")? == *expected_outcome
                && text(item, "family")? == *expected_family,
            "registered suite case expectation and family",
        )?;
        validate_case_time(&item["witness_elapsed_ms"])?;
        match *expected_outcome {
            "accept" => {
                exact_fields(
                    item,
                    &[
                        "name",
                        "expected",
                        "family",
                        "witness_elapsed_ms",
                        "validation",
                        "passed",
                        "complete_relation_check_ms",
                    ],
                )?;
                let v = &item["validation"];
                exact_fields(
                    v,
                    &[
                        "satisfied",
                        "constraints_checked",
                        "assignment_fields",
                        "matrix_entries",
                        "max_row_terms",
                    ],
                )?;
                required(
                    v["satisfied"] == true
                        && v["constraints_checked"].as_u64() == Some(ROWS as u64)
                        && v["assignment_fields"].as_u64() == Some(ASSIGNMENT_FIELDS as u64)
                        && v["matrix_entries"].as_u64() == Some(ENTRIES as u64)
                        && v["max_row_terms"].as_u64().is_some_and(|x| x <= 4096),
                    "complete suite relation census",
                )?;
                validate_case_time(&item["complete_relation_check_ms"])?;
                accepted.insert(name.to_owned());
            }
            "reject" => {
                exact_fields(
                    item,
                    &[
                        "name",
                        "expected",
                        "family",
                        "witness_elapsed_ms",
                        "rejection",
                        "passed",
                    ],
                )?;
                required(
                    text(item, "rejection")? == "circuit_assertion",
                    "suite negative rejection class",
                )?;
                rejected += 1;
            }
            _ => return Err("suite expectation".into()),
        }
    }
    let expected_accepted = expected
        .iter()
        .filter_map(|(name, (outcome, _))| (*outcome == "accept").then_some(name.to_owned()))
        .collect::<BTreeSet<_>>();
    let expected_names = expected.keys().cloned().collect::<BTreeSet<_>>();
    required(
        seen == expected_names && accepted == expected_accepted && rejected == 34,
        "exact registered accepted and negative cases",
    )?;
    Ok(accepted)
}
fn accepted_suite(
    path: &Path,
    digest: &str,
    input_pins: &Value,
    owner: u32,
) -> Result<BTreeSet<String>> {
    validate_suite_pin(input_pins, digest)?;
    required(
        path.is_absolute() && fs::canonicalize(path)? == path,
        "canonical absolute suite report required",
    )?;
    private_directory(path.parent().ok_or("suite parent")?, owner)?;
    validate_suite(&json_file(path, digest, owner)?)
}
fn pinned_suite_digest(input_pins: &Value) -> Result<&str> {
    valid_sha(&input_pins["reviewed_suite"]["report_sha256"])
}
fn validate_suite_pin(input_pins: &Value, supplied_digest: &str) -> Result<()> {
    required(
        pinned_suite_digest(input_pins)? == supplied_digest,
        "suite digest differs from externally pinned input record",
    )
}
// Compiler-embedded source/lock hashes describe build provenance only. They
// are not independent trust anchors: ROOT authenticates the executable and
// setup/input receipts outside the imported package. Reload checks them below.
fn context_manifest(input_pins_sha: &str, suite_sha: &str) -> Value {
    let names = PUBLIC_FIELDS.map(str::to_owned).to_vec();
    json!({"schema":"credential-v3-bounded-setup-v2","development_only":true,"admitted":false,
        "curve":"BN254","reduction":"Original","circuit_source_identity":CIRCUIT_SOURCE_ID,
        "launcher_src_sha256":hex(&Sha256::digest(include_bytes!("main.rs"))),
        "package_manifest_sha256":hex(&Sha256::digest(include_bytes!("../Cargo.toml"))),
        "package_lock_sha256":hex(&Sha256::digest(include_bytes!("../Cargo.lock"))),
        "semantic_schema_sha256":SEMANTIC_SCHEMA,"public_schema_sha256":hex(&public_schema_digest(&names)),
        "ordered_public_inputs":names,"r1cs_sha256":R1CS_SHA,"wasm_sha256":WASM_SHA,"profile_sha256":PROFILE_SHA,
        "input_pins_sha256":input_pins_sha,"accepted_suite_sha256":suite_sha,"constraints":ROWS,"matrix_entries":ENTRIES,
        "assignment_fields":ASSIGNMENT_FIELDS,"instance_fields_including_one":7,"ordinary_vk_ic_count":7,"domain":N,
        "ordinary_vk_tagged_digest":Value::Null,"six_field_adapter_qualified":false})
}
fn validate_context(value: &Value, input_pins_sha: &str, suite_sha: &str) -> Result<()> {
    let expected = context_manifest(input_pins_sha, suite_sha);
    for (key, field) in expected.as_object().ok_or("context object")? {
        required(
            value.get(key) == Some(field),
            "exact setup context/schema/reduction",
        )?;
    }
    Ok(())
}
fn match_public_values(values: &[Fr], public: &[Fr]) -> Result<()> {
    required(
        values.len() >= 7 && public.len() == 6 && values[1..7] == *public,
        "exact six witness public coordinates",
    )
}
fn fixture(spec: &Value, owner: u32, suite_parent: &Path) -> Result<(Vec<Fr>, Vec<Fr>)> {
    let name = text(spec, "name")?;
    required(valid_name(name), "assignment name")?;
    let path = Path::new(text(spec, "wtns_path")?);
    let public_path = Path::new(text(spec, "public_path")?);
    required(
        path == suite_parent.join(format!("{name}.wtns"))
            && public_path == suite_parent.join(format!("{name}-public.json")),
        "accepted assignment artifact paths",
    )?;
    let bytes = received_bytes(
        path,
        text(spec, "wtns_sha256")?,
        32 * 1024 * 1024,
        true,
        owner,
    )?;
    let values = decode_witness(&bytes, ASSIGNMENT_FIELDS)?;
    let public = expected_public(public_path, text(spec, "public_sha256")?, owner)?;
    match_public_values(&values, &public)?;
    Ok((values, public))
}
fn named_options(args: &[String], expected: &[&str]) -> Result<BTreeMap<String, String>> {
    required(
        args.len() == expected.len() * 2,
        "all named options are required exactly once",
    )?;
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    let mut options = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        let name = pair[0].strip_prefix("--").ok_or("named option required")?;
        required(expected.contains(name), "unknown named option")?;
        required(
            options.insert(name.to_owned(), pair[1].clone()).is_none(),
            "duplicate named option",
        )?;
    }
    required(options.len() == expected.len(), "missing named option")?;
    Ok(options)
}
fn option<'a>(options: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str> {
    options
        .get(name)
        .map(String::as_str)
        .ok_or("missing named option".into())
}
fn setup(args: &[String]) -> Result<()> {
    let options = named_options(
        args.get(2..).ok_or("setup arguments")?,
        &[
            "r1cs",
            "wasm",
            "profile",
            "suite-report",
            "suite-sha256",
            "input-pins",
            "input-pins-sha256",
            "output",
        ],
    )?;
    let suite_path = Path::new(option(&options, "suite-report")?);
    let suite_parent = suite_path.parent().ok_or("suite parent")?;
    let owner = fs::metadata(suite_parent)?.uid();
    let input_pins_path = Path::new(option(&options, "input-pins")?);
    let input_pins_sha = option(&options, "input-pins-sha256")?;
    let input_pins = verify_input_pins(input_pins_path, input_pins_sha, owner)?;
    let suite_sha = option(&options, "suite-sha256")?;
    accepted_suite(suite_path, suite_sha, &input_pins, owner)?;
    let d = descriptor(
        Path::new(option(&options, "r1cs")?),
        Path::new(option(&options, "wasm")?),
        Path::new(option(&options, "profile")?),
        owner,
    )?;
    let out = Path::new(option(&options, "output")?);
    required(output(out)? == owner, "output owner")?;
    let all = Instant::now();
    let t = Instant::now();
    let matrices = import::read_r1cs(Path::new(option(&options, "r1cs")?), imports())?;
    required(
        matrices.num_constraints == ROWS
            && matrices.num_instance_variables == 7
            && matrices.num_instance_variables + matrices.num_witness_variables
                == ASSIGNMENT_FIELDS
            && matrices.a_num_non_zero + matrices.b_num_non_zero + matrices.c_num_non_zero
                == ENTRIES,
        "exact compiled census",
    )?;
    event(out, "r1cs_import", t)?;
    let t = Instant::now();
    let (pk, _, _) = dynark::Groth16::<Bn254>::groth16_setup_dynark(matrices.clone(), &mut OsRng)?;
    event(out, "one_time_development_setup", t)?;
    let t = Instant::now();
    let id = PublicPackage::inspect_identity(&matrices, &d, &pk)?;
    let vk = ordinary::VerifyingKey::<Bn254> {
        alpha_g1: pk.vk.alpha_g1,
        beta_g2: pk.vk.beta_g2,
        gamma_g2: pk.vk.gamma_g2,
        delta_g2: pk.vk.delta_g2,
        gamma_abc_g1: pk.vk.t_v_g1.clone(),
    };
    required(vk.gamma_abc_g1.len() == 7, "six-field ordinary VK IC")?;
    let pk_sha = save(&out.join("development.pk"), &pk)?;
    let vk_sha = save(&out.join("ordinary.vk"), &vk)?;
    event(out, "inspect_and_save_shared_keys", t)?;
    let mut manifest = context_manifest(input_pins_sha, suite_sha);
    manifest["identity"] = identity_json(id);
    manifest["pk_file_sha256"] = json!(pk_sha);
    manifest["ordinary_vk_file_sha256"] = json!(vk_sha);
    manifest["binary_sha256"] = json!(binary_hash(owner)?);
    manifest["accepted_suite_path"] = json!(suite_path.to_str().ok_or("suite path text")?);
    manifest["input_pins_path"] = json!(input_pins_path.to_str().ok_or("input-pins path text")?);
    manifest["provenance"]=json!("one-time OS-CSPRNG trusted development setup; no production ceremony or secure erasure claim");
    manifest["secret_scalars_written"] = json!(false);
    manifest["elapsed_ms"] = json!(all.elapsed().as_secs_f64() * 1000.0);
    save_json(&out.join("setup-manifest.json"), &manifest)?;
    File::open(out)?.sync_all()?;
    println!("{{\"stage\":\"v3_shared_development_setup_v2_complete\",\"admitted\":false}}");
    Ok(())
}
fn decode_authenticated_pk(
    bytes: &[u8],
    expected_digest: &str,
) -> Result<dynark::ProvingKey<Bn254>> {
    // expected_digest comes from ROOT's externally authenticated setup manifest,
    // never from the received key. Recheck at this boundary before unchecked
    // codec parsing; the caller must immediately pass the result to
    // PublicPackage::new for its full pk.check(), dimensions and identity checks.
    required(
        bytes.len() <= 512 * 1024 * 1024
            && <[u8; 32]>::from(Sha256::digest(bytes)) == unhex(expected_digest)?,
        "authenticated PK digest",
    )?;
    let mut reader = Cursor::new(bytes);
    let pk = dynark::ProvingKey::<Bn254>::deserialize_compressed_unchecked(&mut reader)?;
    required(reader.position() == bytes.len() as u64, "PK trailing bytes")?;
    Ok(pk)
}
fn check_package(args: &[String]) -> Result<()> {
    let options = named_options(
        args.get(2..).ok_or("check-package arguments")?,
        &[
            "r1cs",
            "wasm",
            "profile",
            "setup-manifest",
            "setup-manifest-sha256",
            "assignments",
            "assignments-sha256",
            "input-pins",
            "input-pins-sha256",
            "output",
        ],
    )?;
    let setup_path = Path::new(option(&options, "setup-manifest")?);
    let setup_parent = setup_path.parent().ok_or("setup parent")?;
    let owner = fs::metadata(setup_parent)?.uid();
    private_directory(setup_parent, owner)?;
    let input_pins_path = Path::new(option(&options, "input-pins")?);
    let input_pins_sha = option(&options, "input-pins-sha256")?;
    let input_pins = verify_input_pins(input_pins_path, input_pins_sha, owner)?;
    let suite_sha = valid_sha(&input_pins["reviewed_suite"]["report_sha256"])?;
    // Expected manifest hashes are authority inputs from ROOT's external receipt.
    // Do not derive them from these imported manifests.
    let manifest = json_file(
        setup_path,
        option(&options, "setup-manifest-sha256")?,
        owner,
    )?;
    validate_context(&manifest, input_pins_sha, suite_sha)?;
    required(
        text(&manifest, "binary_sha256")? == binary_hash(owner)?,
        "same reviewed setup/package binary",
    )?;
    required(
        text(&manifest, "input_pins_path")?
            == input_pins_path.to_str().ok_or("input-pins path text")?,
        "same externally pinned v2 inputs",
    )?;
    let expected_id = parse_identity(&manifest["identity"])?;
    let input = json_file(
        Path::new(option(&options, "assignments")?),
        option(&options, "assignments-sha256")?,
        owner,
    )?;
    required(
        text(&input, "schema")? == "credential-v3-bounded-private-assignments-v1"
            && input["synthetic_only"] == true,
        "accepted assignments manifest schema",
    )?;
    let suite_path = Path::new(text(&input, "accepted_suite_path")?);
    required(
        text(&manifest, "accepted_suite_path")? == suite_path.to_str().ok_or("suite path text")?
            && text(&input, "accepted_suite_sha256")? == suite_sha,
        "same accepted suite path",
    )?;
    let names = accepted_suite(suite_path, suite_sha, &input_pins, owner)?;
    let cases = input["assignments"].as_array().ok_or("assignment list")?;
    required(cases.len() == 18, "all eighteen accepted assignments")?;
    let mut seen = BTreeSet::new();
    for case in cases {
        required(
            seen.insert(text(case, "name")?.to_owned()),
            "unique assignment name",
        )?;
    }
    required(seen == names, "all and only accepted assignments")?;
    let d = descriptor(
        Path::new(option(&options, "r1cs")?),
        Path::new(option(&options, "wasm")?),
        Path::new(option(&options, "profile")?),
        owner,
    )?;
    let out = Path::new(option(&options, "output")?);
    required(output(out)? == owner, "output owner")?;
    let all = Instant::now();
    let t = Instant::now();
    let matrices = import::read_r1cs(Path::new(option(&options, "r1cs")?), imports())?;
    required(
        matrices.num_constraints == ROWS
            && matrices.num_instance_variables == 7
            && matrices.num_instance_variables + matrices.num_witness_variables
                == ASSIGNMENT_FIELDS
            && matrices.a_num_non_zero + matrices.b_num_non_zero + matrices.c_num_non_zero
                == ENTRIES,
        "exact compiled census",
    )?;
    let pk_bytes = received_bytes(
        &setup_parent.join("development.pk"),
        text(&manifest, "pk_file_sha256")?,
        512 * 1024 * 1024,
        true,
        owner,
    )?;
    let pk = decode_authenticated_pk(&pk_bytes, text(&manifest, "pk_file_sha256")?)?;
    drop(pk_bytes);
    // First and only key-validation/admission step after authenticated decoding.
    // No use of this decoded key is permitted before PublicPackage::new calls
    // inspect_identity -> key_check -> pk.check(), then verifies exact identity.
    let package = PublicPackage::new(matrices, d, pk, expected_id)?;
    required(
        package.shape().constraint_rows == ROWS
            && package.shape().assignment_len == ASSIGNMENT_FIELDS
            && package.shape().instance_len == 7
            && package.shape().domain_size == N,
        "exact package shape",
    )?;
    let vk_bytes = received_bytes(
        &setup_parent.join("ordinary.vk"),
        text(&manifest, "ordinary_vk_file_sha256")?,
        4096,
        true,
        owner,
    )?;
    let mut vk_reader = Cursor::new(&vk_bytes);
    let vk = ordinary::VerifyingKey::<Bn254>::deserialize_compressed(&mut vk_reader)?;
    required(
        vk_reader.position() == vk_bytes.len() as u64 && vk.gamma_abc_g1.len() == 7,
        "canonical seven-IC ordinary VK",
    )?;
    let mut projected = Vec::new();
    package
        .ordinary_verifying_key()
        .serialize_compressed(&mut projected)?;
    required(
        projected == vk_bytes,
        "ordinary VK equals exact engine package projection",
    )?;
    event(out, "authenticate_and_load_one_public_package", t)?;
    let mut publics = BTreeMap::new();
    for case in cases {
        let t = Instant::now();
        let (values, public) = fixture(case, owner, suite_path.parent().ok_or("suite parent")?)?;
        let canonical = encoded(&values)?;
        drop(values);
        let validated = package.validate_assignment(&canonical, &public)?;
        drop(validated);
        drop(canonical);
        required(
            package.identity() == expected_id,
            "shared package identity unchanged",
        )?;
        publics.insert(text(case, "name")?.to_owned(), public);
        event(out, "complete_assignment_validated", t)?;
    }
    for i in 0..9 {
        let base = publics
            .get(&format!("credential_{i}"))
            .ok_or("base assignment")?;
        let near = publics
            .get(&format!("credential_{i}_unrelated_refresh"))
            .ok_or("near assignment")?;
        required(
            base[1..] == near[1..] && base[0] != near[0],
            "same-action root-only public pairs",
        )?;
    }
    let report = json!({"schema":"credential-v3-bounded-public-package-check-v2","passed":true,"development_only":true,
        "identity":identity_json(package.identity()),"ordinary_vk_file_sha256":text(&manifest,"ordinary_vk_file_sha256")?,
        "input_pins_sha256":input_pins_sha,"accepted_suite_sha256":suite_sha,
        "semantic_schema_sha256":SEMANTIC_SCHEMA,"public_schema_sha256":hex(&public_schema_digest(&PUBLIC_FIELDS.map(str::to_owned))),
        "constraints":ROWS,"matrix_entries":ENTRIES,"assignment_fields":ASSIGNMENT_FIELDS,
        "accepted_complete_assignments":18,"root_refresh_pairs":9,"public_package_loads":1,"ordinary_vk_ic_count":7,
        "single_shared_package":true,"setup_or_proofs_executed":false,"six_field_adapter_qualified":false,
        "elapsed_ms":all.elapsed().as_secs_f64()*1000.0,"admitted":false});
    save_json(&out.join("package-check-report.json"), &report)?;
    File::open(out)?.sync_all()?;
    println!(
        "{{\"stage\":\"v3_shared_public_package_checked_v2\",\"assignments\":18,\"admitted\":false}}"
    );
    Ok(())
}
fn run() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build_global()?;
    match args.get(1).map(String::as_str) {
        Some("setup") => setup(&args),
        Some("check-package") => check_package(&args),
        _ => Err("expected explicit setup or check-package mode; proofs disabled".into()),
    }
}
fn main() {
    if run().is_err() {
        eprintln!("v3 qualification failed; inspect protected stage receipt");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{BigInteger, PrimeField};

    fn fixture(values: &[[u8; 32]]) -> Vec<u8> {
        let mut bytes = b"wtns".to_vec();
        bytes.extend(2u32.to_le_bytes());
        bytes.extend(2u32.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.extend(40u64.to_le_bytes());
        bytes.extend(32u32.to_le_bytes());
        bytes.extend(Fr::MODULUS.to_bytes_le());
        bytes.extend((values.len() as u32).to_le_bytes());
        bytes.extend(2u32.to_le_bytes());
        bytes.extend(((values.len() * 32) as u64).to_le_bytes());
        for value in values {
            bytes.extend(value);
        }
        bytes
    }

    #[test]
    fn canonical_v3_wtns_round_trip_and_six_public_coordinates() {
        assert_eq!(PUBLIC_FIELDS.len(), 6);
        assert_eq!(ASSIGNMENT_FIELDS, 784_796);
        let mut values = [[0u8; 32]; 8];
        for (i, item) in values.iter_mut().enumerate() {
            item[0] = (i + 1) as u8;
        }
        let decoded = decode_witness(&fixture(&values), 8)
            .expect("canonical v3 WTNS must decode all six public coordinates");
        assert_eq!(decoded, (1u64..=8).map(Fr::from).collect::<Vec<_>>());
        assert_eq!(
            &decoded[1..7],
            &(2u64..=7).map(Fr::from).collect::<Vec<_>>()
        );
    }
    #[test]
    fn malformed_and_noncanonical_wtns_rejected() {
        let mut values = [[0u8; 32]; 8];
        values[0][0] = 1;
        let valid = fixture(&values);
        for index in [0usize, 4, 8, 12, 16, 24, 28, 60, 64, 68] {
            let mut wrong = valid.clone();
            wrong[index] ^= 1;
            assert!(decode_witness(&wrong, 8).is_err());
        }
        for length in [0usize, 3, 15, 75, valid.len() - 1] {
            assert!(decode_witness(&valid[..length], 8).is_err());
        }
        assert!(decode_witness(&valid, usize::MAX).is_err());
        assert!(decode_witness(&valid, 7).is_err());
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(decode_witness(&trailing, 8).is_err());
        values[0][0] = 0;
        assert!(decode_witness(&fixture(&values), 8).is_err());
        values[0][0] = 1;
        values[6].copy_from_slice(&Fr::MODULUS.to_bytes_le());
        assert!(decode_witness(&fixture(&values), 8).is_err());
    }

    #[test]
    fn public_statement_requires_six_canonical_scalars_in_order() {
        let input = json!(["1", "2", "3", "4", "5", "6"]);
        let fields = parse_public(&input).unwrap();
        assert_eq!(fields, (1u64..=6).map(Fr::from).collect::<Vec<_>>());
        assert!(parse_public(&json!(["1", "2", "3", "4", "5"])).is_err());
        for bad in [
            json!(1),
            json!("01"),
            json!("-1"),
            json!(Fr::MODULUS.to_string()),
        ] {
            let mut input = input.clone();
            input[5] = bad;
            assert!(parse_public(&input).is_err());
        }
    }

    fn accepted_suite() -> Value {
        let mut cases = Vec::new();
        for i in 0..9 {
            let base = format!("credential_{i}");
            for (name, family) in [
                (base.clone(), "credential"),
                (format!("{base}_unrelated_refresh"), "unrelated_refresh"),
            ] {
                cases.push(json!({"name":name,"expected":"accept","family":family,
                    "witness_elapsed_ms":1.0,"passed":true,
                    "validation":{"satisfied":true,"constraints_checked":ROWS,"assignment_fields":ASSIGNMENT_FIELDS,
                    "matrix_entries":ENTRIES,"max_row_terms":1634},"complete_relation_check_ms":1.0}));
            }
            for (suffix, family) in [
                ("_own_revoked", "own_revocation"),
                ("_wrong_public_policy", "wrong_policy_binding"),
            ] {
                cases.push(
                    json!({"name":format!("{base}{suffix}"),"expected":"reject","family":family,
                    "witness_elapsed_ms":1.0,"passed":true,"rejection":"circuit_assertion"}),
                );
            }
            if i == 0 {
                for suffix in [
                    "_invalid_cn",
                    "_invalid_purpose",
                    "_invalid_key_usage",
                    "_invalid_serial",
                ] {
                    cases.push(json!({"name":format!("{base}{suffix}"),"expected":"reject","family":"signed_profile_bypass",
                        "witness_elapsed_ms":1.0,"passed":true,"rejection":"circuit_assertion"}));
                }
                for suffix in [
                    "_signed_organization_old_binding",
                    "_signed_aki_old_binding",
                ] {
                    cases.push(json!({"name":format!("{base}{suffix}"),"expected":"reject","family":"signed_binding_bypass",
                        "witness_elapsed_ms":1.0,"passed":true,"rejection":"circuit_assertion"}));
                }
                cases.push(json!({"name":format!("{base}_invalid_layout"),"expected":"reject","family":"invalid_layout",
                    "witness_elapsed_ms":1.0,"passed":true,"rejection":"circuit_assertion"}));
            }
            cases.push(json!({"name":format!("{base}_wrong_public_issuer"),"expected":"reject","family":"wrong_issuer_binding",
                "witness_elapsed_ms":1.0,"passed":true,"rejection":"circuit_assertion"}));
        }
        json!({"schema":"credential-v3-bounded-witness-qualification-v1","passed":true,
            "r1cs_sha256":R1CS_SHA,"wasm_sha256":WASM_SHA,"host_admission_bypassed":true,
            "setup_or_proofs_executed":false,"outputs_private":true,
            "accepted_count":18,"rejected_count":34,"cases":cases})
    }

    #[test]
    fn setup_requires_complete_accepted_suite_and_relation_census() {
        let valid = accepted_suite();
        let names = validate_suite(&valid).unwrap();
        assert_eq!(names.len(), 18);
        for key in ["passed", "host_admission_bypassed"] {
            let mut bad = valid.clone();
            bad[key] = json!(false);
            assert!(validate_suite(&bad).is_err());
        }
        for key in ["r1cs_sha256", "wasm_sha256", "schema"] {
            let mut bad = valid.clone();
            bad[key] = json!("incorrect");
            assert!(validate_suite(&bad).is_err());
        }
        for key in ["accepted_count", "rejected_count"] {
            let mut bad = valid.clone();
            bad[key] = json!(0);
            assert!(validate_suite(&bad).is_err());
        }
        for key in [
            "satisfied",
            "constraints_checked",
            "assignment_fields",
            "matrix_entries",
        ] {
            let mut bad = valid.clone();
            bad["cases"][0]["validation"][key] = json!(0);
            assert!(validate_suite(&bad).is_err());
        }
        let mut bad = valid.clone();
        bad["cases"][0]["name"] = json!("../escape");
        assert!(validate_suite(&bad).is_err());
        let mut bad = valid.clone();
        bad["cases"][1]["name"] = bad["cases"][0]["name"].clone();
        assert!(validate_suite(&bad).is_err());
        let mut bad = valid;
        let negative = bad["cases"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|case| case["expected"] == "reject")
            .unwrap();
        negative["rejection"] = json!("unexpected_runtime_error");
        assert!(validate_suite(&bad).is_err());
    }

    #[test]
    fn suite_requires_private_output_attestation() {
        let mut bad = accepted_suite();
        bad.as_object_mut().unwrap().remove("outputs_private");
        assert!(validate_suite(&bad).is_err());
    }

    #[test]
    fn suite_rejects_malformed_or_unknown_case_fields_and_families() {
        let valid = accepted_suite();
        let mut missing_family = valid.clone();
        missing_family["cases"][0]
            .as_object_mut()
            .unwrap()
            .remove("family");
        assert!(validate_suite(&missing_family).is_err());

        let mut unknown_field = valid.clone();
        unknown_field["cases"][0]["unexpected"] = json!(true);
        assert!(validate_suite(&unknown_field).is_err());

        let mut wrong_family = valid;
        wrong_family["cases"][0]["family"] = json!("unknown_family");
        assert!(validate_suite(&wrong_family).is_err());
    }

    #[test]
    fn suite_rejects_substituted_negative_case_coverage() {
        let mut bad = accepted_suite();
        bad["cases"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|case| case["name"] == "credential_1_own_revoked")
            .unwrap()["name"] = json!("credential_1_fake_negative");
        assert!(validate_suite(&bad).is_err());
    }

    #[test]
    fn all_five_identity_digests_are_canonical() {
        let id = PackageIdentity {
            matrix_digest: [1; 32],
            circuit_digest: [2; 32],
            proving_key_digest: [3; 32],
            verifying_key_digest: [4; 32],
            package_digest: [5; 32],
        };
        assert_eq!(parse_identity(&identity_json(id)).unwrap(), id);
        for key in ["matrix", "circuit", "pk", "engine_extended_vk", "package"] {
            let mut bad = identity_json(id);
            bad[key] = json!("00");
            assert!(parse_identity(&bad).is_err());
        }
    }

    #[test]
    fn descriptor_has_six_names_original_and_distinct_from_v2() {
        let d = fixed_descriptor().unwrap();
        assert_eq!(d.public_schema, PUBLIC_FIELDS.map(str::to_owned).to_vec());
        assert_eq!(d.reduction, Reduction::Original);
        assert_ne!(
            d.public_schema_digest,
            public_schema_digest(
                &PUBLIC_FIELDS[..5]
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            )
        );
    }

    #[test]
    fn setup_manifest_rejects_five_field_or_changed_v2_context() {
        let input_pins_sha = "11".repeat(32);
        let suite_sha = "22".repeat(32);
        let valid = context_manifest(&input_pins_sha, &suite_sha);
        validate_context(&valid, &input_pins_sha, &suite_sha).unwrap();
        for (key, value) in [
            ("instance_fields_including_one", json!(6)),
            ("reduction", json!("InstanceAugmentedA")),
            ("profile_sha256", json!("00")),
            ("semantic_schema_sha256", json!("00")),
            ("public_schema_sha256", json!("00")),
            ("ordinary_vk_ic_count", json!(6)),
            ("launcher_src_sha256", json!("00")),
            ("package_manifest_sha256", json!("00")),
            ("package_lock_sha256", json!("00")),
            ("constraints", json!(0)),
        ] {
            let mut bad = valid.clone();
            bad[key] = value;
            assert!(validate_context(&bad, &input_pins_sha, &suite_sha).is_err());
        }
        let mut bad = valid;
        bad["ordered_public_inputs"][5] = json!("unboundPolicy");
        assert!(validate_context(&bad, &input_pins_sha, &suite_sha).is_err());
        let bad_suite = context_manifest(&input_pins_sha, &"33".repeat(32));
        assert!(validate_context(&bad_suite, &input_pins_sha, &suite_sha).is_err());
        let bad_pins = context_manifest(&"44".repeat(32), &suite_sha);
        assert!(validate_context(&bad_pins, &input_pins_sha, &suite_sha).is_err());
    }

    #[test]
    fn pinned_loader_checks_digest_mode_size_symlink_and_canonical_public() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("v3-loader-test-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let owner = dir.metadata().unwrap().uid();
        let file = dir.join("public.json");
        let data = br#"["1","2","3","4","5","6"]"#;
        private_file(&file).unwrap().write_all(data).unwrap();
        let hash = hex(&Sha256::digest(data));
        assert!(expected_public(&file, &hash, owner).is_ok());
        assert!(received_bytes(&file, &"00".repeat(32), 65536, true, owner).is_err());
        assert!(received_bytes(&file, &hash, 1, true, owner).is_err());
        let link = dir.join("alias");
        symlink(&file, &link).unwrap();
        assert!(received_bytes(&link, &hash, 65536, true, owner).is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(expected_public(&file, &hash, owner).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn interleaved_fresh_suite_case_order_is_supported() {
        let mut interleaved = accepted_suite();
        let cases = interleaved["cases"].as_array_mut().unwrap();
        let rejected = cases.remove(18);
        cases.insert(1, rejected);
        assert_eq!(validate_suite(&interleaved).unwrap().len(), 18);
        interleaved["cases"].as_array_mut().unwrap().reverse();
        assert_eq!(validate_suite(&interleaved).unwrap().len(), 18);
    }

    fn valid_input_pins() -> Value {
        json!({
            "schema": INPUT_PINS_SCHEMA,
            "source_commit": "1".repeat(40),
            "toolchain": {
                "circom_version": "2.2.3", "node_version": "v22.14.0",
                "rustc_version": "1.90.0-nightly", "cargo_version": "1.90.0",
                "circom_binary_sha256": "a".repeat(64)
            },
            "semantic_hashes": {
                "r1cs_sha256": R1CS_SHA, "wasm_sha256": WASM_SHA, "profile_sha256": PROFILE_SHA,
                "semantic_schema_sha256": SEMANTIC_SCHEMA, "circuit_source_sha256": CIRCUIT_SOURCE_ID,
                "symbol_map_sha256": SEMANTIC_HASHES[5].1
            },
            "census": {
                "assignment_fields": ASSIGNMENT_FIELDS, "constraints": ROWS,
                "matrix_entries": ENTRIES, "domain_size": N
            },
            "ordered_public_inputs": PUBLIC_FIELDS,
            "reviewed_suite": {
                "report_sha256": "b".repeat(64), "total_count": 52,
                "accepted_count": 18, "rejected_count": 34
            },
            "public_repo_files": []
        })
    }

    #[test]
    fn v2_input_pins_require_exact_semantics_and_accept_fresh_external_suite_identity() {
        let valid = valid_input_pins();
        let owner = fs::metadata(repo_root().unwrap()).unwrap().uid();
        validate_input_pins(&valid, owner).unwrap();
        let reviewed_suite_sha = "b".repeat(64);
        assert_eq!(pinned_suite_digest(&valid).unwrap(), reviewed_suite_sha);
        assert!(validate_suite_pin(&valid, &reviewed_suite_sha).is_ok());
        assert!(validate_suite_pin(&valid, &"c".repeat(64)).is_err());

        let mut bad = valid.clone();
        bad["reviewed_suite"]["accepted_count"] = json!(17);
        assert!(validate_input_pins(&bad, owner).is_err());
        let mut bad = valid.clone();
        bad["semantic_hashes"]["r1cs_sha256"] = json!("c".repeat(64));
        assert!(validate_input_pins(&bad, owner).is_err());
        let mut bad = valid.clone();
        bad["ordered_public_inputs"][5] = json!("policy");
        assert!(validate_input_pins(&bad, owner).is_err());
        let mut bad = valid.clone();
        bad["extra"] = json!(true);
        assert!(validate_input_pins(&bad, owner).is_err());
    }

    #[test]
    fn input_pins_bytes_are_authenticated_before_json_is_parsed() {
        let malformed = b"{";
        let wrong = authenticated_input_pins(malformed, &"0".repeat(64)).unwrap_err();
        assert_eq!(wrong.to_string(), "input-pins byte digest mismatch");
        let digest = hex(&Sha256::digest(malformed));
        assert!(authenticated_input_pins(malformed, &digest).is_err());
        let raw = serde_json::to_vec(&valid_input_pins()).unwrap();
        let digest = hex(&Sha256::digest(&raw));
        assert!(authenticated_input_pins(&raw, &digest).is_ok());
        assert!(authenticated_input_pins(&raw, &"0".repeat(64)).is_err());
        let duplicate = br#"{"schema":"part5-v3-fresh-package-input-pins-v2","schema":"other"}"#;
        let duplicate_digest = hex(&Sha256::digest(duplicate));
        assert!(authenticated_input_pins(duplicate, &duplicate_digest).is_err());
    }

    #[test]
    fn input_pin_public_paths_and_toolchain_versions_are_bounded() {
        assert!(public_source_path(&json!(
            "circuits/credential-v3-bounded/qualification/prover-v2/src/main.rs"
        ))
        .is_ok());
        for path in [
            "../../private.wtns",
            "artifacts/private/report.json",
            "circuits/credential-v3-bounded/.hidden.rs",
            "circuits/credential-v3-bounded/source.txt",
        ] {
            assert!(public_source_path(&json!(path)).is_err());
        }
        for version in ["2.2.3", "v22.14.0", "1.90.0-nightly.2025.01"] {
            assert!(valid_release(&json!(version)).is_ok());
        }
        for version in ["01.2.3", "1.2", "1.2.3-", "1.2.3..nightly", "v1.2.3!"] {
            assert!(valid_release(&json!(version)).is_err());
        }
    }

    #[test]
    fn named_cli_options_reject_unknown_duplicate_and_missing_values() {
        let valid = vec![
            "--r1cs".to_owned(),
            "r.r1cs".to_owned(),
            "--wasm".to_owned(),
            "w.wasm".to_owned(),
        ];
        assert_eq!(named_options(&valid, &["r1cs", "wasm"]).unwrap().len(), 2);
        let duplicate = vec![
            "--r1cs".to_owned(),
            "a".to_owned(),
            "--r1cs".to_owned(),
            "b".to_owned(),
        ];
        assert!(named_options(&duplicate, &["r1cs", "wasm"]).is_err());
        let unknown = vec![
            "--other".to_owned(),
            "x".to_owned(),
            "--wasm".to_owned(),
            "y".to_owned(),
        ];
        assert!(named_options(&unknown, &["r1cs", "wasm"]).is_err());
        assert!(named_options(&valid[..2], &["r1cs", "wasm"]).is_err());
    }

    #[test]
    fn witness_statement_binds_all_six_coordinates_including_policy() {
        let values = (1u64..=8).map(Fr::from).collect::<Vec<_>>();
        let expected = values[1..7].to_vec();
        match_public_values(&values, &expected).unwrap();
        for i in 0..6 {
            let mut wrong = expected.clone();
            wrong[i] += Fr::ONE;
            assert!(match_public_values(&values, &wrong).is_err());
        }
        assert!(match_public_values(&values, &expected[..5]).is_err());
    }

    #[test]
    fn public_profile_mode_644_is_accepted_only_with_the_static_pin() {
        let profile = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../circuits/credential-v3-bounded/profile.json");
        let owner = fs::metadata(&profile).unwrap().uid();
        assert!(pinned(&profile, PROFILE_SHA, 65536, false, owner).is_ok());
        assert!(pinned(&profile, &"00".repeat(32), 65536, false, owner).is_err());
        assert!(pinned(&profile, PROFILE_SHA, 65536, true, owner).is_err());
    }
    #[test]
    fn authenticated_pk_decoder_requires_pin_and_exact_bytes_before_admission() {
        // This tiny, dimensionally invalid key is codec data, not a setup.
        let tiny = dynark::ProvingKey::<Bn254> {
            vk: dynark::VerifyingKey::default(),
            beta_g1: Default::default(),
            delta_g1: Default::default(),
            u_g1: vec![],
            v_g1: vec![],
            v_g2: vec![],
            tau_powers_g1: vec![],
            t_p_g1: vec![],
        };
        let mut bytes = Vec::new();
        tiny.serialize_compressed(&mut bytes).unwrap();
        let expected = hex(&Sha256::digest(&bytes));
        let decoded = decode_authenticated_pk(&bytes, &expected).unwrap();
        assert_eq!(decoded, tiny); // Decode success alone deliberately does not admit a package.
        let wrong = decode_authenticated_pk(&[0xff; 64], &expected).unwrap_err();
        assert_eq!(wrong.to_string(), "authenticated PK digest");
        bytes.push(0);
        let trailing_digest = hex(&Sha256::digest(&bytes));
        let trailing = decode_authenticated_pk(&bytes, &trailing_digest).unwrap_err();
        assert_eq!(trailing.to_string(), "PK trailing bytes");
    }
}
