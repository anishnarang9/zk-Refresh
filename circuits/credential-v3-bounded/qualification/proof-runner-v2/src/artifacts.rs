//! Authenticated imports adapted from the accepted frozen v3 setup runner.
use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use dynark_bn254::{
    import, public_schema_digest, CircuitDescriptor, Limits, PackageIdentity, PublicPackage,
    Reduction,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::{BufWriter, Cursor, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    str::FromStr,
    time::Instant,
};

pub(crate) type Result<T> = std::result::Result<T, Box<dyn Error>>;
pub(crate) const ASSIGNMENT_FIELDS: usize = 784_796;
pub(crate) const ROWS: usize = 793_681;
pub(crate) const ENTRIES: usize = 4_257_583;
pub(crate) const N: usize = 1_048_576;
pub(crate) const FOUR_GIB: usize = 4 * 1024 * 1024 * 1024;
pub(crate) const PUBLIC_FIELDS: [&str; 6] = [
    "root",
    "issuerHash",
    "notBefore",
    "notAfter",
    "actionHash",
    "policyHash",
];
pub(crate) const R1CS_SHA: &str =
    "976e9a76356ad015f0e4c587ccd79bba601b5caf80817b561aa4ca5442656888";
pub(crate) const WASM_SHA: &str =
    "fbf73cff59660574add16ba8acafe824a9d57e0c91f23557b6462979b85c9aa6";
pub(crate) const PROFILE_SHA: &str =
    "2e5d26564fb055e70cff924c4cb6e296509030b8c0062130f86ad5af783f7918";
pub(crate) const SEMANTIC_SCHEMA: &str =
    "eabfaa2d95e4abc9126b87a04e94397091c103891e92dbaefaafba79cf3b26d4";
pub(crate) const CIRCUIT_SOURCE_ID: &str =
    "48d051e16dd1773b1831d9960a4a7f5a1fb6afd153ec2d87493696deb145d901";
pub(crate) const SYMBOLS_SHA: &str =
    "d2d66e238bdc0a731c86c1897c2978d23908dcc19460582cc873dc2d41e5dbf0";

pub(crate) fn required(value: bool, reason: &'static str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(reason.into())
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn unhex(text: &str) -> Result<[u8; 32]> {
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

pub(crate) fn bounded_file(path: &Path, cap: u64, private: bool, owner: u32) -> Result<File> {
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

pub(crate) fn hash_file(path: &Path, cap: u64, private: bool, owner: u32) -> Result<[u8; 32]> {
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

pub(crate) fn pinned(
    path: &Path,
    expected: &str,
    cap: u64,
    private: bool,
    owner: u32,
) -> Result<()> {
    required(
        hash_file(path, cap, private, owner)? == unhex(expected)?,
        "artifact digest mismatch",
    )
}

pub(crate) fn received_bytes(
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

pub(crate) fn json_file(path: &Path, digest: &str, owner: u32) -> Result<Value> {
    let bytes = received_bytes(path, digest, 65536, true, owner)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or("manifest string field".into())
}

pub(crate) fn exact_fields(
    value: &Value,
    fields: &[&str],
    description: &'static str,
) -> Result<()> {
    let object = value.as_object().ok_or("manifest object required")?;
    let names = fields
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    required(
        object
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            == names,
        description,
    )
}

pub(crate) fn private_file(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}

pub(crate) fn save_json(path: &Path, value: &Value) -> Result<()> {
    let file = private_file(path)?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(())
}

pub(crate) fn save<T: CanonicalSerialize>(path: &Path, value: &T) -> Result<String> {
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

pub(crate) fn event(out: &Path, stage: &'static str, started: Instant) -> Result<()> {
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

/// Durable stage receipts keep paid work observable if a later operation stops.
pub(crate) fn case_event(
    out: &Path,
    name: &str,
    stage: &'static str,
    started: Instant,
) -> Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .open(out.join("events.jsonl"))?;
    serde_json::to_writer(
        &mut file,
        &json!({"case":name,"stage":stage,
        "elapsed_ms":started.elapsed().as_secs_f64()*1000.0}),
    )?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn output(path: &Path) -> Result<u32> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    let metadata = path.metadata()?;
    required(
        metadata.permissions().mode() & 0o777 == 0o700,
        "private output directory",
    )?;
    private_file(&path.join("events.jsonl"))?.sync_all()?;
    Ok(metadata.uid())
}

pub(crate) fn binary_hash(owner: u32) -> Result<String> {
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

pub(crate) fn decode_witness(
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

pub(crate) fn encoded(values: &[Fr]) -> Result<Vec<[u8; 32]>> {
    values
        .iter()
        .map(|value| {
            let mut bytes = [0u8; 32];
            value.serialize_compressed(&mut bytes[..])?;
            Ok(bytes)
        })
        .collect()
}

pub(crate) fn limits() -> Limits {
    Limits {
        max_domain: N,
        max_assignment: ASSIGNMENT_FIELDS,
        max_matrix_entries: 4_500_000,
        max_delta_entries: 8192,
        max_pair_work: 11_000_000,
        max_allocation_bytes: FOUR_GIB,
    }
}

pub(crate) fn imports() -> import::ImportLimits {
    import::ImportLimits {
        operation: limits(),
        max_file_bytes: 192 * 1024 * 1024,
        max_section_bytes: 160 * 1024 * 1024,
        max_sections: 3,
        max_row_entries: 4096,
    }
}

pub(crate) fn fixed_descriptor() -> Result<CircuitDescriptor> {
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

pub(crate) fn private_directory(path: &Path, owner: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    required(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == owner
            && metadata.permissions().mode() & 0o777 == 0o700,
        "protected directory",
    )
}

pub(crate) fn descriptor(
    r1cs: &Path,
    wasm: &Path,
    profile: &Path,
    owner: u32,
) -> Result<CircuitDescriptor> {
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

pub(crate) fn identity_json(id: PackageIdentity) -> Value {
    json!({"matrix":hex(&id.matrix_digest),"circuit":hex(&id.circuit_digest),"pk":hex(&id.proving_key_digest),
        "engine_extended_vk":hex(&id.verifying_key_digest),"package":hex(&id.package_digest)})
}

pub(crate) fn parse_identity(value: &Value) -> Result<PackageIdentity> {
    Ok(PackageIdentity {
        matrix_digest: unhex(text(value, "matrix")?)?,
        circuit_digest: unhex(text(value, "circuit")?)?,
        proving_key_digest: unhex(text(value, "pk")?)?,
        verifying_key_digest: unhex(text(value, "engine_extended_vk")?)?,
        package_digest: unhex(text(value, "package")?)?,
    })
}

pub(crate) fn parse_public(value: &Value) -> Result<Vec<Fr>> {
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

pub(crate) fn expected_public(path: &Path, digest: &str, owner: u32) -> Result<Vec<Fr>> {
    parse_public(&json_file(path, digest, owner)?)
}

pub(crate) fn match_public_values(values: &[Fr], public: &[Fr]) -> Result<()> {
    required(
        values.len() >= 7 && public.len() == 6 && values[1..7] == *public,
        "exact six witness public coordinates",
    )
}

pub(crate) fn decode_authenticated_pk(
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
pub(crate) fn suite_sha() -> &'static str {
    &crate::pins::current().suite_sha
}
pub(crate) fn setup_manifest_sha() -> &'static str {
    &crate::pins::current().setup_manifest_sha
}
pub(crate) fn package_check_sha() -> &'static str {
    &crate::pins::current().package_check_sha
}
pub(crate) fn package_sha() -> &'static str {
    &crate::pins::current().package_sha
}
pub(crate) fn setup_binary_sha() -> &'static str {
    &crate::pins::current().setup_binary_sha
}
pub(crate) fn setup_source_sha() -> &'static str {
    &crate::pins::current().setup_source_sha
}
pub(crate) fn setup_manifest_source_sha() -> &'static str {
    &crate::pins::current().setup_manifest_source_sha
}
pub(crate) fn setup_lock_sha() -> &'static str {
    &crate::pins::current().setup_lock_sha
}
pub(crate) fn ordinary_vk_file_sha() -> &'static str {
    &crate::pins::current().ordinary_vk_file_sha
}

pub(crate) fn validate_setup(value: &Value) -> Result<PackageIdentity> {
    exact_fields(
        value,
        &[
            "schema",
            "development_only",
            "admitted",
            "curve",
            "reduction",
            "circuit_source_identity",
            "launcher_src_sha256",
            "package_manifest_sha256",
            "package_lock_sha256",
            "semantic_schema_sha256",
            "public_schema_sha256",
            "ordered_public_inputs",
            "r1cs_sha256",
            "wasm_sha256",
            "profile_sha256",
            "input_pins_sha256",
            "accepted_suite_sha256",
            "constraints",
            "matrix_entries",
            "assignment_fields",
            "instance_fields_including_one",
            "ordinary_vk_ic_count",
            "domain",
            "ordinary_vk_tagged_digest",
            "six_field_adapter_qualified",
            "identity",
            "pk_file_sha256",
            "ordinary_vk_file_sha256",
            "binary_sha256",
            "accepted_suite_path",
            "input_pins_path",
            "provenance",
            "secret_scalars_written",
            "elapsed_ms",
        ],
        "exact setup manifest v2 fields required",
    )?;
    let names = PUBLIC_FIELDS.map(str::to_owned).to_vec();
    let pins = crate::pins::current();
    let expected = json!({"schema":"credential-v3-bounded-setup-v2","development_only":true,"admitted":false,
        "curve":"BN254","reduction":"Original","circuit_source_identity":CIRCUIT_SOURCE_ID,
        "semantic_schema_sha256":SEMANTIC_SCHEMA,"public_schema_sha256":hex(&public_schema_digest(&names)),
        "ordered_public_inputs":names,"r1cs_sha256":R1CS_SHA,"wasm_sha256":WASM_SHA,"profile_sha256":PROFILE_SHA,
        "input_pins_sha256":pins.input_pins_sha.as_str(),"accepted_suite_sha256":suite_sha(),"constraints":ROWS,"matrix_entries":ENTRIES,
        "assignment_fields":ASSIGNMENT_FIELDS,"instance_fields_including_one":7,"ordinary_vk_ic_count":7,"domain":N,
        "binary_sha256":setup_binary_sha(),"launcher_src_sha256":setup_source_sha(),
        "package_manifest_sha256":setup_manifest_source_sha(),"package_lock_sha256":setup_lock_sha(),
        "ordinary_vk_file_sha256":ordinary_vk_file_sha(),"pk_file_sha256":pins.proving_key_sha.as_str(),
        "ordinary_vk_tagged_digest":null,"six_field_adapter_qualified":false,
        "secret_scalars_written":false});
    for (key, want) in expected.as_object().ok_or("setup object")? {
        required(
            value.get(key) == Some(want),
            "reviewed v2 setup provenance/context",
        )?;
    }
    required(
        !text(value, "accepted_suite_path")?.is_empty(),
        "accepted suite reference required",
    )?;
    let id = parse_identity(&value["identity"])?;
    required(
        hex(&id.package_digest) == package_sha() && &value["identity"] == &pins.identity &&
        text(value,"input_pins_path")? == crate::pins::input_pins_path()?.to_str().ok_or("input-pins path")? &&
        text(value,"provenance")? == "one-time OS-CSPRNG trusted development setup; no production ceremony or secure erasure claim" &&
        value["elapsed_ms"].as_f64().is_some_and(|ms| ms.is_finite() && ms >= 0.0),
        "accepted reviewed v2 public package",
    )?;
    Ok(id)
}

pub(crate) fn load_package(packet: &Value, owner: u32, out: &Path) -> Result<PublicPackage> {
    let pins = crate::pins::current();
    required(
        text(packet, "setup_manifest_sha256")? == setup_manifest_sha()
            && text(packet, "package_check_sha256")? == package_check_sha()
            && text(packet, "package_digest")? == package_sha()
            && Path::new(text(packet, "setup_manifest_path")?) == pins.setup_path.as_path()
            && Path::new(text(packet, "package_check_path")?) == pins.package_check_path.as_path(),
        "external accepted setup/report pins",
    )?;
    let setup_path = Path::new(text(packet, "setup_manifest_path")?);
    let setup_parent = setup_path.parent().ok_or("setup parent")?;
    private_directory(setup_parent, owner)?;
    private_directory(
        pins.package_check_path
            .parent()
            .ok_or("package-check parent")?,
        owner,
    )?;
    required(
        setup_path.canonicalize()?.as_path() == setup_path
            && pins.package_check_path.canonicalize()? == pins.package_check_path,
        "canonical v2 private output paths required",
    )?;
    let manifest = json_file(setup_path, setup_manifest_sha(), owner)?;
    let expected = validate_setup(&manifest)?;
    let admitted = json_file(&pins.package_check_path, package_check_sha(), owner)?;
    exact_fields(
        &admitted,
        &[
            "schema",
            "passed",
            "development_only",
            "identity",
            "ordinary_vk_file_sha256",
            "input_pins_sha256",
            "accepted_suite_sha256",
            "semantic_schema_sha256",
            "public_schema_sha256",
            "constraints",
            "matrix_entries",
            "assignment_fields",
            "accepted_complete_assignments",
            "root_refresh_pairs",
            "public_package_loads",
            "ordinary_vk_ic_count",
            "single_shared_package",
            "setup_or_proofs_executed",
            "six_field_adapter_qualified",
            "elapsed_ms",
            "admitted",
        ],
        "exact package-check report v2 fields required",
    )?;
    required(
        admitted["schema"] == "credential-v3-bounded-public-package-check-v2"
            && admitted["passed"] == true
            && admitted["development_only"] == true
            && admitted["admitted"] == false
            && admitted["single_shared_package"] == true
            && admitted["accepted_complete_assignments"].as_u64() == Some(18)
            && admitted["root_refresh_pairs"].as_u64() == Some(9)
            && admitted["public_package_loads"].as_u64() == Some(1)
            && admitted["ordinary_vk_ic_count"].as_u64() == Some(7)
            && admitted["setup_or_proofs_executed"] == false
            && admitted["six_field_adapter_qualified"] == false
            && admitted["input_pins_sha256"].as_str() == Some(pins.input_pins_sha.as_str())
            && admitted["accepted_suite_sha256"] == suite_sha()
            && admitted["semantic_schema_sha256"] == SEMANTIC_SCHEMA
            && admitted["public_schema_sha256"]
                == hex(&public_schema_digest(&PUBLIC_FIELDS.map(str::to_owned)))
            && admitted["constraints"].as_u64() == Some(ROWS as u64)
            && admitted["matrix_entries"].as_u64() == Some(ENTRIES as u64)
            && admitted["assignment_fields"].as_u64() == Some(ASSIGNMENT_FIELDS as u64)
            && admitted["ordinary_vk_file_sha256"] == ordinary_vk_file_sha()
            && admitted["elapsed_ms"]
                .as_f64()
                .is_some_and(|ms| ms.is_finite() && ms >= 0.0)
            && parse_identity(&admitted["identity"])? == expected,
        "accepted package check",
    )?;
    let t = Instant::now();
    let d = descriptor(
        Path::new(text(packet, "r1cs_path")?),
        Path::new(text(packet, "wasm_path")?),
        Path::new(text(packet, "profile_path")?),
        owner,
    )?;
    let m = import::read_r1cs(Path::new(text(packet, "r1cs_path")?), imports())?;
    required(
        m.num_constraints == ROWS
            && m.num_instance_variables == 7
            && m.num_instance_variables + m.num_witness_variables == ASSIGNMENT_FIELDS
            && m.a_num_non_zero + m.b_num_non_zero + m.c_num_non_zero == ENTRIES,
        "exact compiled census",
    )?;
    let bytes = received_bytes(
        &setup_parent.join("development.pk"),
        &pins.proving_key_sha,
        512 * 1024 * 1024,
        true,
        owner,
    )?;
    let pk = decode_authenticated_pk(&bytes, &pins.proving_key_sha)?;
    drop(bytes);
    // No decoded key use before this full subgroup/dimension/identity admission.
    let package = PublicPackage::new(m, d, pk, expected)?;
    let raw = received_bytes(
        &setup_parent.join("ordinary.vk"),
        ordinary_vk_file_sha(),
        4096,
        true,
        owner,
    )?;
    let mut reader = Cursor::new(&raw);
    let vk = ordinary::VerifyingKey::<Bn254>::deserialize_compressed(&mut reader)?;
    required(
        reader.position() == raw.len() as u64 && vk.gamma_abc_g1.len() == 7,
        "canonical seven-IC VK",
    )?;
    let mut projected = Vec::new();
    package
        .ordinary_verifying_key()
        .serialize_compressed(&mut projected)?;
    required(raw == projected, "same ordinary VK projection")?;
    event(out, "one_public_package_loaded", t)?;
    Ok(package)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn toy_wtns() -> Vec<u8> {
        let values = (1u64..=8).map(Fr::from).collect::<Vec<_>>();
        let mut out = b"wtns".to_vec();
        out.extend(2u32.to_le_bytes());
        out.extend(2u32.to_le_bytes());
        out.extend(1u32.to_le_bytes());
        out.extend(40u64.to_le_bytes());
        out.extend(32u32.to_le_bytes());
        out.extend(Fr::MODULUS.to_bytes_le());
        out.extend(8u32.to_le_bytes());
        out.extend(2u32.to_le_bytes());
        out.extend(256u64.to_le_bytes());
        for value in values {
            value.serialize_compressed(&mut out).unwrap();
        }
        out
    }
    #[test]
    fn canonical_full_wtns_format_and_all_six_publics() {
        let raw = toy_wtns();
        let decoded = decode_witness(&raw, 8).unwrap();
        match_public_values(&decoded, &decoded[1..7]).unwrap();
        let mut wrong = decoded[1..7].to_vec();
        wrong[5] += Fr::ONE;
        assert!(match_public_values(&decoded, &wrong).is_err());
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(decode_witness(&trailing, 8).is_err());
        for i in [0usize, 4, 8, 12, 16, 24, 28, 60, 64, 68, 76] {
            let mut bad = raw.clone();
            bad[i] ^= 1;
            assert!(decode_witness(&bad, 8).is_err());
        }
        let mut bad = raw;
        bad[76 + 6 * 32..76 + 7 * 32].copy_from_slice(&Fr::MODULUS.to_bytes_le());
        assert!(decode_witness(&bad, 8).is_err());
    }
    #[test]
    fn fresh_v2_setup_context_is_validated_without_historical_artifacts() {
        let pins = crate::pins::current();
        let names = PUBLIC_FIELDS.map(str::to_owned).to_vec();
        let value = json!({"schema":"credential-v3-bounded-setup-v2","development_only":true,"admitted":false,
            "curve":"BN254","reduction":"Original","circuit_source_identity":CIRCUIT_SOURCE_ID,
            "semantic_schema_sha256":SEMANTIC_SCHEMA,"public_schema_sha256":hex(&public_schema_digest(&names)),
            "ordered_public_inputs":names,"r1cs_sha256":R1CS_SHA,"wasm_sha256":WASM_SHA,"profile_sha256":PROFILE_SHA,
            "input_pins_sha256":pins.input_pins_sha,"accepted_suite_sha256":suite_sha(),
            "constraints":ROWS,"matrix_entries":ENTRIES,"assignment_fields":ASSIGNMENT_FIELDS,
            "instance_fields_including_one":7,"ordinary_vk_ic_count":7,"domain":N,
            "binary_sha256":setup_binary_sha(),"launcher_src_sha256":setup_source_sha(),
            "package_manifest_sha256":setup_manifest_source_sha(),"package_lock_sha256":setup_lock_sha(),
            "ordinary_vk_file_sha256":ordinary_vk_file_sha(),"pk_file_sha256":pins.proving_key_sha,
            "ordinary_vk_tagged_digest":null,"six_field_adapter_qualified":false,
            "secret_scalars_written":false,"identity":pins.identity,"accepted_suite_path":"reviewed-suite.json",
            "input_pins_path":crate::pins::input_pins_path().unwrap(),
            "provenance":"one-time OS-CSPRNG trusted development setup; no production ceremony or secure erasure claim",
            "elapsed_ms":1.25});
        assert_eq!(
            hex(&validate_setup(&value).unwrap().package_digest),
            package_sha()
        );
        for key in [
            "launcher_src_sha256",
            "package_manifest_sha256",
            "package_lock_sha256",
            "binary_sha256",
            "input_pins_sha256",
            "accepted_suite_sha256",
            "pk_file_sha256",
            "ordinary_vk_file_sha256",
            "profile_sha256",
        ] {
            let mut wrong = value.clone();
            wrong[key] = json!("new proof binary/source is not setup provenance");
            assert!(validate_setup(&wrong).is_err());
        }
        let mut wrong_identity = value.clone();
        wrong_identity["identity"]["package"] = json!("f".repeat(64));
        assert!(validate_setup(&wrong_identity).is_err());
        let mut extra = value.clone();
        extra["unexpected"] = json!(true);
        assert!(validate_setup(&extra).is_err());
        let mut missing = value.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("accepted_suite_path");
        assert!(validate_setup(&missing).is_err());
        let mut empty_suite_path = value.clone();
        empty_suite_path["accepted_suite_path"] = json!("");
        assert!(validate_setup(&empty_suite_path).is_err());
        let mut non_string_suite_path = value.clone();
        non_string_suite_path["accepted_suite_path"] = json!(false);
        assert!(validate_setup(&non_string_suite_path).is_err());
    }
    #[test]
    fn exact_json_fields_reject_unknown_and_missing_names() {
        let fields = ["schema", "passed"];
        let valid = json!({"schema":"v2","passed":true});
        assert!(exact_fields(&valid, &fields, "exact fields").is_ok());
        let extra = json!({"schema":"v2","passed":true,"extra":false});
        assert!(exact_fields(&extra, &fields, "exact fields").is_err());
        let missing = json!({"schema":"v2"});
        assert!(exact_fields(&missing, &fields, "exact fields").is_err());
    }
    #[test]
    fn pk_hash_gate_and_trailing_bytes_before_full_admission() {
        let key = dynark::ProvingKey::<Bn254> {
            vk: dynark::VerifyingKey::default(),
            beta_g1: Default::default(),
            delta_g1: Default::default(),
            u_g1: vec![],
            v_g1: vec![],
            v_g2: vec![],
            tau_powers_g1: vec![],
            t_p_g1: vec![],
        };
        let mut raw = Vec::new();
        key.serialize_compressed(&mut raw).unwrap();
        let sha = hex(&Sha256::digest(&raw));
        assert!(decode_authenticated_pk(&raw, &sha).is_ok());
        assert_eq!(
            decode_authenticated_pk(&[0xff; 64], &sha)
                .unwrap_err()
                .to_string(),
            "authenticated PK digest"
        );
        raw.push(0);
        let sha = hex(&Sha256::digest(&raw));
        assert_eq!(
            decode_authenticated_pk(&raw, &sha).unwrap_err().to_string(),
            "PK trailing bytes"
        );
    }
    #[test]
    fn private_loader_rejects_unpinned_symlink_oversize_and_public_mode() {
        use std::os::unix::fs::symlink;
        let dir =
            std::env::temp_dir().join(format!("v3-proof-artifact-test-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let owner = dir.metadata().unwrap().uid();
        let path = dir.join("inputs.json");
        private_file(&path).unwrap().write_all(b"[]").unwrap();
        let sha = hex(&Sha256::digest(b"[]"));
        assert!(json_file(&path, &sha, owner).is_ok());
        assert!(json_file(&path, &"00".repeat(32), owner).is_err());
        assert!(received_bytes(&path, &sha, 1, true, owner).is_err());
        let link = dir.join("link");
        symlink(&path, &link).unwrap();
        assert!(json_file(&link, &sha, owner).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(json_file(&path, &sha, owner).is_err());
        assert!(pinned(&path, &sha, 64, false, owner).is_ok());
        fs::remove_dir_all(dir).unwrap();
    }
}
