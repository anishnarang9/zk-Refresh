//! Public-only, pinned v3 ordinary VK projection. No setup, proof, credential,
//! witness or secret key is read. ROOT must supervise any execution separately.
//! Output is exactly896 bytes: alpha64 || beta128 || gamma128 || delta128 || IC7*64.
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use dynark_solana_adapter::v3;
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

const RAW_SHA: &str = "87edb4608c2140f3c7fddc8503e49b68931cda973711ce2c831bd44f1b98a875";
const TAGGED_SHA: &str = "2f9b770ff51ac399619a3127ddb32efad67697402f10c4549441a3578e4f9a4e";
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn be<F: PrimeField>(value: F) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}
// Exact adapter encoding: g1(non-negated alpha/IC)=x||y; infinity IC0=zero64.
fn g1(point: &G1Affine) -> [u8; 64] {
    if point.is_zero() {
        return [0; 64];
    }
    let mut out = [0; 64];
    out[..32].copy_from_slice(&be(point.x));
    out[32..].copy_from_slice(&be(point.y));
    out
}
// Exact adapter encoding: G2 x.c1||x.c0||y.c1||y.c0, canonical BE Fq.
fn g2(point: &G2Affine) -> [u8; 128] {
    let mut out = [0; 128];
    for (chunk, value) in out
        .chunks_exact_mut(32)
        .zip([point.x.c1, point.x.c0, point.y.c1, point.y.c0])
    {
        chunk.copy_from_slice(&be(value));
    }
    out
}
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        return Err("usage: export_v3_vk ABSOLUTE_PINNED_ORDINARY_VK ABSOLUTE_FRESH_OUTPUT".into());
    }
    let input = Path::new(&args[1]);
    let output = Path::new(&args[2]);
    if !input.is_absolute() || !output.is_absolute() {
        return Err("input/output must be absolute".into());
    }
    let meta = fs::symlink_metadata(input)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() != 456 {
        return Err("input must be a regular nonsymlink456-byte ordinary VK".into());
    }
    let mut raw = Vec::with_capacity(457);
    File::open(input)?.take(457).read_to_end(&mut raw)?;
    if raw.len() != 456 || hex(&Sha256::digest(&raw)) != RAW_SHA {
        return Err("pinned raw ordinary VK mismatch".into());
    }
    // Guard the only variable allocation before invoking Ark deserialization.
    if raw[224..232] != 7u64.to_le_bytes() {
        return Err("ordinary VK must have exactly seven IC points".into());
    }
    let mut cursor = raw.as_slice();
    let vk = ordinary::VerifyingKey::<Bn254>::deserialize_compressed(&mut cursor)
        .map_err(|_| "canonical ordinary VK deserialization failed")?;
    if !cursor.is_empty() || vk.gamma_abc_g1.len() != 7 {
        return Err("ordinary VK dimensions/trailing data mismatch".into());
    }
    let mut roundtrip = Vec::with_capacity(456);
    vk.serialize_compressed(&mut roundtrip)
        .map_err(|_| "ordinary VK reserialization failed")?;
    if roundtrip != raw {
        return Err("ordinary VK encoding is not canonical".into());
    }
    // Adapter validates all points/subgroups, dimensions and the exact v3 tag.
    let tagged = v3::ordinary_vk_digest(&vk).map_err(|_| "adapter VK validation failed")?;
    if hex(&tagged) != TAGGED_SHA {
        return Err("pinned tagged ordinary VK mismatch".into());
    }
    let mut coordinates = Vec::with_capacity(896);
    coordinates.extend(g1(&vk.alpha_g1));
    for point in [&vk.beta_g2, &vk.gamma_g2, &vk.delta_g2] {
        coordinates.extend(g2(point));
    }
    for point in &vk.gamma_abc_g1 {
        coordinates.extend(g1(point));
    }
    if coordinates.len() != 896 {
        return Err("coordinate projection length mismatch".into());
    }
    // Recompute the commitment from emitted bytes independently of the adapter
    // serializer so sign/component/order changes cannot silently pass extraction.
    let mut independently_tagged = Sha256::new();
    independently_tagged.update(v3::ORDINARY_VK_TAG);
    independently_tagged.update(6u32.to_be_bytes());
    independently_tagged.update(7u32.to_be_bytes());
    independently_tagged.update(&coordinates);
    let projected_digest: [u8; 32] = independently_tagged.finalize().into();
    if projected_digest != tagged {
        return Err("projected canonical coordinates do not match adapter digest".into());
    }
    let parent = output.parent().ok_or("missing output parent")?;
    let parent_meta = fs::symlink_metadata(parent)?;
    if !parent_meta.is_dir()
        || parent_meta.file_type().is_symlink()
        || parent_meta.permissions().mode() & 0o777 != 0o700
    {
        return Err("output parent must be an existing nonsymlink0700 directory".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)?;
    file.write_all(&coordinates)?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
