//! Runtime package identity. The expected record digest comes from the caller,
//! never from the received setup or package-check manifests.
use crate::artifacts::*;
use serde::{
    de::{MapAccess, SeqAccess, Visitor},
    Deserialize,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    sync::OnceLock,
};

const RECORD_SCHEMA: &str = "part5-v3-fresh-package-output-pins-v2";
const RECORD_RELATIVE: &str = "docs/dynark/part5/v3-fresh-package-v2-package-pins.json";
const INPUT_RELATIVE: &str = "docs/dynark/part5/v3-fresh-package-v2-input-pins.json";
const SETUP_CRATE: &str = "circuits/credential-v3-bounded/qualification/prover-v2";
static CURRENT: OnceLock<PackagePins> = OnceLock::new();

pub(crate) struct PackagePins {
    pub(crate) record_sha: String,
    pub(crate) input_pins_sha: String,
    pub(crate) suite_sha: String,
    pub(crate) setup_manifest_sha: String,
    pub(crate) package_check_sha: String,
    pub(crate) ordinary_vk_file_sha: String,
    pub(crate) proving_key_sha: String,
    pub(crate) package_sha: String,
    pub(crate) setup_binary_sha: String,
    pub(crate) setup_source_sha: String,
    pub(crate) setup_manifest_source_sha: String,
    pub(crate) setup_lock_sha: String,
    pub(crate) setup_path: PathBuf,
    pub(crate) package_check_path: PathBuf,
    pub(crate) identity: Value,
}

#[cfg(test)]
pub(crate) fn current() -> &'static PackagePins {
    CURRENT.get_or_init(|| {
        let mut pins = PackagePins::from_record(&tests::record(), &"f".repeat(64)).unwrap();
        pins.suite_sha = "0".repeat(64);
        pins
    })
}

#[cfg(not(test))]
pub(crate) fn current() -> &'static PackagePins {
    CURRENT
        .get()
        .expect("externally pinned v2 package required before any proof")
}

pub(crate) fn install(pins: PackagePins) -> Result<()> {
    required(
        CURRENT.set(pins).is_ok(),
        "package pins may be installed only once",
    )
}

fn exact(value: &Value, fields: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or("record object required")?;
    let names = fields.iter().copied().collect::<BTreeSet<_>>();
    required(
        object.keys().map(String::as_str).collect::<BTreeSet<_>>() == names,
        "exact package record fields required",
    )
}

fn canonical_sha(value: &str) -> Result<()> {
    unhex(value).map(|_| ())
}

fn repo_root() -> Result<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .ok_or("repository root")?;
    Ok(root.to_path_buf())
}

pub(crate) fn input_pins_path() -> Result<PathBuf> {
    Ok(repo_root()?.join(INPUT_RELATIVE))
}

fn relative_path(value: &str) -> Result<&Path> {
    required(
        !value.is_empty()
            && value.len() <= 300
            && value
                .split('/')
                .all(|part| !part.is_empty() && !part.starts_with('.'))
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/')),
        "bounded repository path required",
    )?;
    let path = Path::new(value);
    required(
        path.components()
            .all(|part| matches!(part, Component::Normal(_)))
            && !path.is_absolute(),
        "canonical relative repository path required",
    )?;
    Ok(path)
}

fn public_source_path(path: &str) -> bool {
    if matches!(
        path,
        "package.json"
            | "package-lock.json"
            | "Cargo.toml"
            | "Cargo.lock"
            | "rust-toolchain.toml"
            | "circuits/credential-v3-bounded/profile.json"
    ) {
        return true;
    }
    let allowed = path.starts_with("circuits/credential-v3-bounded/")
        || path.starts_with("tools/part5/")
        || path.starts_with("harness/tests/")
        || path.starts_with("program/src/");
    let source = matches!(
        Path::new(path).extension().and_then(|s| s.to_str()),
        Some("circom" | "rs" | "py" | "cjs")
    ) || matches!(
        Path::new(path).file_name().and_then(|s| s.to_str()),
        Some("Cargo.toml" | "Cargo.lock")
    );
    allowed && source
}

fn reference(
    value: &Value,
    expected_path: Option<&str>,
    filename: Option<&str>,
) -> Result<(String, String)> {
    exact(value, &["path", "sha256"])?;
    let path = text(value, "path")?;
    relative_path(path)?;
    if let Some(expected) = expected_path {
        required(path == expected, "exact v2 reference path required")?;
    }
    if let Some(name) = filename {
        required(
            Path::new(path).file_name().and_then(|v| v.to_str()) == Some(name),
            "exact v2 artifact filename required",
        )?;
    }
    let sha = text(value, "sha256")?;
    canonical_sha(sha)?;
    Ok((path.to_owned(), sha.to_owned()))
}

fn private_output_path(path: &str) -> Result<()> {
    required(
        path.starts_with("artifacts/dynark/part5/"),
        "private v2 output path required",
    )
}

fn verify_setup_launcher_file(
    path: &Path,
    expected: &str,
    cap: u64,
    allowed_modes: &[u32],
    owner: u32,
) -> Result<()> {
    required(
        path.canonicalize()?.as_path() == path,
        "canonical setup launcher file required",
    )?;
    let before = fs::symlink_metadata(path)?;
    required(
        before.is_file()
            && !before.file_type().is_symlink()
            && before.uid() == owner
            && allowed_modes.contains(&(before.permissions().mode() & 0o777))
            && before.len() > 0
            && before.len() <= cap,
        "bounded reviewed setup launcher file required",
    )?;
    let mut file = fs::File::open(path)?;
    let opened = file.metadata()?;
    required(
        opened.dev() == before.dev()
            && opened.ino() == before.ino()
            && opened.len() == before.len(),
        "setup launcher changed at open",
    )?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut read = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        read += n as u64;
        required(
            read <= cap && read <= before.len(),
            "setup launcher size changed",
        )?;
        hash.update(&buf[..n]);
    }
    let after = file.metadata()?;
    let final_path = fs::symlink_metadata(path)?;
    required(
        read == before.len()
            && after.dev() == before.dev()
            && after.ino() == before.ino()
            && after.len() == before.len()
            && final_path.dev() == before.dev()
            && final_path.ino() == before.ino()
            && final_path.len() == before.len()
            && after.mtime_nsec() == before.mtime_nsec()
            && after.mtime() == before.mtime()
            && final_path.mtime_nsec() == before.mtime_nsec()
            && final_path.mtime() == before.mtime()
            && hex(&hash.finalize()) == expected,
        "setup launcher byte identity changed",
    )
}

struct StrictJson(Value);
impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictJson;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON without duplicate object keys")
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(Value::Null))
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                v: bool,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(Value::Bool(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(Value::from(v)))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(Value::from(v)))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| StrictJson(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite number"))
            }
            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(Value::from(v)))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictJson(Value::from(v)))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(StrictJson(v)) = a.next_element()? {
                    out.push(v);
                }
                Ok(StrictJson(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut out = serde_json::Map::new();
                while let Some(key) = a.next_key::<String>()? {
                    if out.contains_key(&key) {
                        return Err(<A::Error as serde::de::Error>::custom("duplicate JSON key"));
                    }
                    let StrictJson(v) = a.next_value()?;
                    out.insert(key, v);
                }
                Ok(StrictJson(Value::Object(out)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

fn strict_json(raw: &[u8]) -> Result<Value> {
    let mut de = serde_json::Deserializer::from_slice(raw);
    let StrictJson(value) = StrictJson::deserialize(&mut de)?;
    de.end()?;
    Ok(value)
}

fn decode_record(raw: &[u8], expected_sha: &str) -> Result<PackagePins> {
    canonical_sha(expected_sha)?;
    required(
        !raw.is_empty() && raw.len() <= 65536 && hex(&Sha256::digest(raw)) == expected_sha,
        "external package record digest required",
    )?;
    let record = strict_json(raw)?;
    PackagePins::from_record(&record, expected_sha)
}

fn validate_input_context(input: &Value, record: &Value) -> Result<String> {
    exact(
        input,
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
        input["schema"] == "part5-v3-fresh-package-input-pins-v2"
            && input["source_commit"] == record["source_commit"]
            && input["semantic_hashes"] == record["semantic_hashes"]
            && input["census"] == record["census"]
            && input["ordered_public_inputs"] == record["ordered_public_inputs"],
        "same reviewed v2 input context required",
    )?;
    exact(
        &input["toolchain"],
        &[
            "circom_version",
            "node_version",
            "rustc_version",
            "cargo_version",
            "circom_binary_sha256",
        ],
    )?;
    canonical_sha(text(&input["toolchain"], "circom_binary_sha256")?)?;
    for field in [
        "circom_version",
        "node_version",
        "rustc_version",
        "cargo_version",
    ] {
        let version = text(&input["toolchain"], field)?;
        required(
            !version.is_empty()
                && version.len() <= 64
                && version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+')),
            "bounded reviewed toolchain version required",
        )?;
    }
    let suite = &input["reviewed_suite"];
    exact(
        suite,
        &[
            "report_sha256",
            "total_count",
            "accepted_count",
            "rejected_count",
        ],
    )?;
    required(
        suite["total_count"] == 52
            && suite["accepted_count"] == 18
            && suite["rejected_count"] == 34,
        "exact 52-case reviewed suite census required",
    )?;
    let sha = text(suite, "report_sha256")?;
    canonical_sha(sha)?;
    let files = input["public_repo_files"]
        .as_array()
        .ok_or("public source pin list")?;
    required(
        files.len() <= 128,
        "bounded public source pin list required",
    )?;
    let mut previous = "";
    for file in files {
        exact(file, &["path", "sha256"])?;
        let path = text(file, "path")?;
        relative_path(path)?;
        required(
            path > previous && public_source_path(path),
            "ordered public source references required",
        )?;
        let file_sha = text(file, "sha256")?;
        canonical_sha(file_sha)?;
        if path == "circuits/credential-v3-bounded/profile.json" {
            required(
                file_sha == PROFILE_SHA,
                "public profile source differs from accepted profile",
            )?;
        }
        previous = path;
    }
    Ok(sha.to_owned())
}

impl PackagePins {
    fn from_record(record: &Value, record_sha: &str) -> Result<Self> {
        exact(
            record,
            &[
                "schema",
                "source_commit",
                "input_pins",
                "setup_manifest",
                "package_check_report",
                "ordinary_vk",
                "proving_key",
                "package_identity",
                "setup_launcher",
                "semantic_hashes",
                "census",
                "ordered_public_inputs",
            ],
        )?;
        required(
            text(record, "schema")? == RECORD_SCHEMA,
            "v2 output record schema required",
        )?;
        let commit = text(record, "source_commit")?;
        required(
            commit.len() == 40
                && commit
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "lowercase source commit required",
        )?;
        let semantic = &record["semantic_hashes"];
        exact(
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
        for (field, want) in [
            ("r1cs_sha256", R1CS_SHA),
            ("wasm_sha256", WASM_SHA),
            ("profile_sha256", PROFILE_SHA),
            ("semantic_schema_sha256", SEMANTIC_SCHEMA),
            ("circuit_source_sha256", CIRCUIT_SOURCE_ID),
            ("symbol_map_sha256", SYMBOLS_SHA),
        ] {
            required(
                text(semantic, field)? == want,
                "accepted v3 semantic identity required",
            )?;
        }
        required(
            record["census"]
                == json!({"assignment_fields":ASSIGNMENT_FIELDS,"constraints":ROWS,
                  "matrix_entries":ENTRIES,"domain_size":N})
                && record["ordered_public_inputs"] == json!(PUBLIC_FIELDS),
            "accepted v3 relation census and public order required",
        )?;
        let (_, input_pins_sha) = reference(&record["input_pins"], Some(INPUT_RELATIVE), None)?;
        let (setup_relative, setup_manifest_sha) =
            reference(&record["setup_manifest"], None, Some("setup-manifest.json"))?;
        let (report_relative, package_check_sha) = reference(
            &record["package_check_report"],
            None,
            Some("package-check-report.json"),
        )?;
        let (vk_relative, ordinary_vk_file_sha) =
            reference(&record["ordinary_vk"], None, Some("ordinary.vk"))?;
        let (pk_relative, proving_key_sha) =
            reference(&record["proving_key"], None, Some("development.pk"))?;
        for path in [
            &setup_relative,
            &report_relative,
            &vk_relative,
            &pk_relative,
        ] {
            private_output_path(path)?;
        }
        required(
            Path::new(&setup_relative).parent() == Path::new(&vk_relative).parent()
                && Path::new(&setup_relative).parent() == Path::new(&pk_relative).parent(),
            "one private v2 setup output directory required",
        )?;
        let identity = &record["package_identity"];
        exact(
            identity,
            &["matrix", "circuit", "pk", "engine_extended_vk", "package"],
        )?;
        for field in ["matrix", "circuit", "pk", "engine_extended_vk", "package"] {
            canonical_sha(text(identity, field)?)?;
        }
        let launcher = &record["setup_launcher"];
        exact(launcher, &["binary", "source", "manifest", "lock"])?;
        let (_, setup_binary_sha) = reference(
            &launcher["binary"],
            Some(&format!(
                "{SETUP_CRATE}/target/release/credential-v3-bounded-qualification-v2"
            )),
            None,
        )?;
        let (_, setup_source_sha) = reference(
            &launcher["source"],
            Some(&format!("{SETUP_CRATE}/src/main.rs")),
            None,
        )?;
        let (_, setup_manifest_source_sha) = reference(
            &launcher["manifest"],
            Some(&format!("{SETUP_CRATE}/Cargo.toml")),
            None,
        )?;
        let (_, setup_lock_sha) = reference(
            &launcher["lock"],
            Some(&format!("{SETUP_CRATE}/Cargo.lock")),
            None,
        )?;
        let root = repo_root()?;
        let setup_path = root.join(&setup_relative);
        let package_check_path = root.join(&report_relative);
        Ok(Self {
            record_sha: record_sha.to_owned(),
            input_pins_sha,
            suite_sha: String::new(),
            setup_manifest_sha,
            package_check_sha,
            ordinary_vk_file_sha,
            proving_key_sha,
            package_sha: text(identity, "package")?.to_owned(),
            setup_binary_sha,
            setup_source_sha,
            setup_manifest_source_sha,
            setup_lock_sha,
            setup_path,
            package_check_path,
            identity: identity.clone(),
        })
    }
}

pub(crate) fn load_record(path: &Path, expected_sha: &str, owner: u32) -> Result<PackagePins> {
    let expected = repo_root()?.join(RECORD_RELATIVE);
    required(
        path == expected.as_path() && path.canonicalize()?.as_path() == path,
        "exact canonical v2 package record path required",
    )?;
    let raw = received_bytes(path, expected_sha, 65536, false, owner)?;
    let mut pins = decode_record(&raw, expected_sha)?;
    let record = strict_json(&raw)?;
    let root = repo_root()?;
    let setup = record["setup_launcher"]
        .as_object()
        .ok_or("setup launcher")?;
    for (field, cap, modes) in [
        ("binary", 256 * 1024 * 1024, &[0o700, 0o755][..]),
        ("source", 8 * 1024 * 1024, &[0o600, 0o644][..]),
        ("manifest", 8 * 1024 * 1024, &[0o600, 0o644][..]),
        ("lock", 8 * 1024 * 1024, &[0o600, 0o644][..]),
    ] {
        let relative = text(&setup[field], "path")?;
        let digest = text(&setup[field], "sha256")?;
        verify_setup_launcher_file(&root.join(relative), digest, cap, modes, owner)?;
    }
    let input_file = root.join(INPUT_RELATIVE);
    let input_raw = received_bytes(&input_file, &pins.input_pins_sha, 65536, false, owner)?;
    let input = strict_json(&input_raw)?;
    pins.suite_sha = validate_input_context(&input, &record)?;
    for file in input["public_repo_files"]
        .as_array()
        .ok_or("public source list")?
    {
        verify_setup_launcher_file(
            &root.join(text(file, "path")?),
            text(file, "sha256")?,
            8 * 1024 * 1024,
            &[0o600, 0o644],
            owner,
        )?;
    }
    required(
        received_bytes(path, expected_sha, 65536, false, owner)? == raw
            && received_bytes(&input_file, &pins.input_pins_sha, 65536, false, owner)? == input_raw,
        "v2 pin records changed during verification",
    )?;
    Ok(pins)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub(super) fn record() -> Value {
        let h = |digit: &str| digit.repeat(64);
        let reference = |path: &str, digit: &str| json!({"path": path, "sha256": h(digit)});
        json!({
            "schema": "part5-v3-fresh-package-output-pins-v2",
            "source_commit": "a".repeat(40),
            "input_pins": reference("docs/dynark/part5/v3-fresh-package-v2-input-pins.json", "1"),
            "setup_manifest": reference("artifacts/dynark/part5/v3-development-setup-002/setup-manifest.json", "2"),
            "package_check_report": reference("artifacts/dynark/part5/v3-package-check-002/package-check-report.json", "3"),
            "ordinary_vk": reference("artifacts/dynark/part5/v3-development-setup-002/ordinary.vk", "4"),
            "proving_key": reference("artifacts/dynark/part5/v3-development-setup-002/development.pk", "5"),
            "package_identity": {"matrix":h("6"), "circuit":h("7"), "pk":h("8"), "engine_extended_vk":h("9"), "package":h("a")},
            "setup_launcher": {
                "binary": reference("circuits/credential-v3-bounded/qualification/prover-v2/target/release/credential-v3-bounded-qualification-v2", "b"),
                "source": reference("circuits/credential-v3-bounded/qualification/prover-v2/src/main.rs", "c"),
                "manifest": reference("circuits/credential-v3-bounded/qualification/prover-v2/Cargo.toml", "d"),
                "lock": reference("circuits/credential-v3-bounded/qualification/prover-v2/Cargo.lock", "e"),
            },
            "semantic_hashes": {
                "r1cs_sha256":R1CS_SHA, "wasm_sha256":WASM_SHA,
                "profile_sha256":PROFILE_SHA, "semantic_schema_sha256":SEMANTIC_SCHEMA,
                "circuit_source_sha256":CIRCUIT_SOURCE_ID,
                "symbol_map_sha256":SYMBOLS_SHA,
            },
            "census":{"assignment_fields":ASSIGNMENT_FIELDS,"constraints":ROWS,
                      "matrix_entries":ENTRIES,"domain_size":N},
            "ordered_public_inputs":PUBLIC_FIELDS,
        })
    }

    #[test]
    fn record_needs_separate_byte_pin_and_exact_v2_shape() {
        let raw = serde_json::to_vec(&record()).unwrap();
        let expected = hex(&Sha256::digest(&raw));
        assert!(decode_record(&raw, &expected).is_ok());
        assert!(decode_record(&raw, &"f".repeat(64)).is_err());
        let mut old = record();
        old["schema"] = json!("part5-v3-fresh-package-output-pins-v1");
        let raw = serde_json::to_vec(&old).unwrap();
        assert!(decode_record(&raw, &hex(&Sha256::digest(&raw))).is_err());
        let mut extra = record();
        extra["private_assignments"] = json!("leak");
        let raw = serde_json::to_vec(&extra).unwrap();
        assert!(decode_record(&raw, &hex(&Sha256::digest(&raw))).is_err());
    }

    #[test]
    fn record_rejects_duplicate_json_and_noncanonical_refs() {
        let raw = br#"{"schema":"first","schema":"second"}"#;
        assert!(decode_record(raw, &hex(&Sha256::digest(raw))).is_err());
        let mut bad = record();
        bad["setup_manifest"]["path"] = json!("../private/setup-manifest.json");
        let raw = serde_json::to_vec(&bad).unwrap();
        assert!(decode_record(&raw, &hex(&Sha256::digest(&raw))).is_err());
    }

    #[test]
    fn input_record_must_match_output_context_and_exact_reviewed_suite() {
        let output = record();
        let mut input = json!({
            "schema":"part5-v3-fresh-package-input-pins-v2",
            "source_commit":output["source_commit"],
            "toolchain":{"circom_version":"2.2.3","node_version":"v22.14.0",
                         "rustc_version":"1.90.0","cargo_version":"1.90.0",
                         "circom_binary_sha256":"f".repeat(64)},
            "semantic_hashes":output["semantic_hashes"],"census":output["census"],
            "ordered_public_inputs":output["ordered_public_inputs"],
            "reviewed_suite":{"report_sha256":"0".repeat(64),
                              "total_count":52,"accepted_count":18,"rejected_count":34},
            "public_repo_files":[]
        });
        assert_eq!(
            validate_input_context(&input, &output).unwrap(),
            "0".repeat(64)
        );
        input["reviewed_suite"]["rejected_count"] = json!(33);
        assert!(validate_input_context(&input, &output).is_err());
        input["reviewed_suite"]["rejected_count"] = json!(34);
        input["source_commit"] = json!("b".repeat(40));
        assert!(validate_input_context(&input, &output).is_err());
        input["source_commit"] = output["source_commit"].clone();
        input["public_repo_files"] = json!([{"path":"circuits/credential-v3-bounded/private.json",
                                            "sha256":"1".repeat(64)}]);
        assert!(validate_input_context(&input, &output).is_err());
    }
}
