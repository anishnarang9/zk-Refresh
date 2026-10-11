//! Bounded Circom R1CS/WTNS and legacy E2 arkworks artifacts.
//! Expected legacy digests must come from a trusted manifest outside the imported files.
//! Content hashes identify supplied data; they are not setup provenance or application authority.
use crate::{
    anchored::{AnchorCore, MaterialInner},
    Anchor, AnchorBinding, CircuitDescriptor, Error, Limits, PackageIdentity, PublicPackage,
    UpdatingMaterial, ValidatedAssignment,
};
use ark_bn254::{Bn254, Fr, G1Affine, G1Projective as G1, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Radix2EvaluationDomain};
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::CanonicalDeserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufReader, Cursor, Read, Seek, SeekFrom},
    path::Path,
    sync::Arc,
};

#[derive(Clone, Copy, Debug)]
/// Structural caps count known buffers/vectors; allocator metadata and fragmentation are excluded.
pub struct ImportLimits {
    pub operation: Limits,
    pub max_file_bytes: u64,
    pub max_section_bytes: u64,
    pub max_sections: usize,
    pub max_row_entries: usize,
}
impl ImportLimits {
    pub fn small() -> Self {
        Self {
            operation: Limits::small(),
            max_file_bytes: 16 * 1024 * 1024,
            max_section_bytes: 8 * 1024 * 1024,
            max_sections: 8,
            max_row_entries: 4096,
        }
    }
}
fn io(e: std::io::Error) -> Error {
    Error::Io(e)
}
fn u32le<R: Read>(r: &mut R) -> Result<usize, Error> {
    let mut b = [0; 4];
    r.read_exact(&mut b).map_err(io)?;
    Ok(u32::from_le_bytes(b) as usize)
}
fn u64le<R: Read>(r: &mut R) -> Result<u64, Error> {
    let mut b = [0; 8];
    r.read_exact(&mut b).map_err(io)?;
    Ok(u64::from_le_bytes(b))
}
fn count<R: Read>(r: &mut R) -> Result<usize, Error> {
    usize::try_from(u64le(r)?).map_err(|_| Error::Bound("count address space"))
}
fn field<R: Read>(r: &mut R, coordinate: usize) -> Result<Fr, Error> {
    let mut b = [0; 32];
    r.read_exact(&mut b).map_err(io)?;
    Fr::deserialize_compressed(&b[..]).map_err(|_| Error::NonCanonicalField { coordinate })
}
struct LimitedFile {
    file: File,
    length: u64,
    position: u64,
}
impl Read for LimitedFile {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        if b.is_empty() {
            return Ok(0);
        }
        if self.position == self.length {
            if self.file.metadata()?.len() != self.length {
                return Err(std::io::Error::other("changed file length"));
            }
            return Ok(0);
        }
        let want = b
            .len()
            .min(usize::try_from(self.length - self.position).unwrap_or(usize::MAX));
        let n = self.file.read(&mut b[..want])?;
        self.position += n as u64;
        Ok(n)
    }
}
impl Seek for LimitedFile {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        let target = match position {
            SeekFrom::Start(x) => Some(x),
            SeekFrom::Current(x) => self.position.checked_add_signed(x),
            SeekFrom::End(x) => self.length.checked_add_signed(x),
        }
        .ok_or_else(|| std::io::Error::other("seek overflow"))?;
        if target > self.length {
            return Err(std::io::Error::other("seek exceeds received length"));
        }
        self.position = self.file.seek(SeekFrom::Start(target))?;
        Ok(self.position)
    }
}
fn open(path: &Path, l: ImportLimits) -> Result<BufReader<LimitedFile>, Error> {
    let f = File::open(path).map_err(io)?;
    let metadata = f.metadata().map_err(io)?;
    let length = metadata.len();
    if !metadata.is_file() || length > l.max_file_bytes {
        return Err(Error::Bound("file bytes/type"));
    }
    if l.operation.max_allocation_bytes < 8192 {
        return Err(Error::Bound("buffered reader allocation"));
    }
    Ok(BufReader::new(LimitedFile {
        file: f,
        length,
        position: 0,
    }))
}
fn exact_end<R: Read>(r: &mut R) -> Result<(), Error> {
    let mut b = [0; 1];
    if r.read(&mut b).map_err(io)? != 0 {
        return Err(Error::Import("trailing bytes"));
    }
    Ok(())
}
fn skip(r: &mut BufReader<LimitedFile>, n: usize) -> Result<(), Error> {
    let end = r
        .stream_position()
        .map_err(io)?
        .checked_add(n as u64)
        .ok_or(Error::Bound("skip overflow"))?;
    if end > r.get_ref().length {
        return Err(Error::Import("truncated vector"));
    }
    r.seek(SeekFrom::Start(end)).map_err(io)?;
    Ok(())
}
fn charge(total: &mut usize, count: usize, size: usize, l: ImportLimits) -> Result<(), Error> {
    *total = total
        .checked_add(
            count
                .checked_mul(size)
                .ok_or(Error::Bound("allocation overflow"))?,
        )
        .ok_or(Error::Bound("allocation overflow"))?;
    if *total > l.operation.max_allocation_bytes {
        return Err(Error::Bound("import allocation"));
    }
    Ok(())
}

fn sections(
    r: &mut Cursor<Vec<u8>>,
    magic: &[u8; 4],
    version: usize,
    l: ImportLimits,
) -> Result<BTreeMap<usize, (u64, u64)>, Error> {
    let mut tag = [0; 4];
    r.read_exact(&mut tag).map_err(io)?;
    if &tag != magic || u32le(r)? != version {
        return Err(Error::Import("magic/version"));
    }
    let n = u32le(r)?;
    if n > l.max_sections {
        return Err(Error::Bound("section count"));
    }
    if (magic == b"wtns" && n != 2) || (magic == b"r1cs" && !(2..=3).contains(&n)) {
        return Err(Error::Import("supported section count"));
    }
    let len = r.get_ref().len() as u64;
    let mut index_bytes = r.get_ref().len();
    charge(&mut index_bytes, n, 256, l)?;
    let mut out = BTreeMap::new();
    for _ in 0..n {
        let kind = u32le(r)?;
        if (magic == b"wtns" && !matches!(kind, 1 | 2))
            || (magic == b"r1cs" && !matches!(kind, 1 | 2 | 3))
        {
            return Err(Error::Import("section kind"));
        }
        let size = u64le(r)?;
        let pos = r.stream_position().map_err(io)?;
        if size > l.max_section_bytes {
            return Err(Error::Bound("section bytes"));
        }
        let end = pos
            .checked_add(size)
            .ok_or(Error::Bound("section overflow"))?;
        if end > len {
            return Err(Error::Import("section exceeds file"));
        }
        if out.insert(kind, (pos, size)).is_some() {
            return Err(Error::Import("duplicate section"));
        }
        r.seek(SeekFrom::Start(end)).map_err(io)?;
    }
    if r.stream_position().map_err(io)? != len {
        return Err(Error::Import("trailing sections"));
    }
    Ok(out)
}
fn section(
    r: &mut Cursor<Vec<u8>>,
    s: &BTreeMap<usize, (u64, u64)>,
    kind: usize,
) -> Result<(u64, u64), Error> {
    let x = *s.get(&kind).ok_or(Error::Import("missing section"))?;
    r.seek(SeekFrom::Start(x.0)).map_err(io)?;
    Ok(x)
}
fn bn_header<R: Read>(r: &mut R) -> Result<(), Error> {
    if u32le(r)? != 32 {
        return Err(Error::Import("field width"));
    }
    let mut b = [0; 32];
    r.read_exact(&mut b).map_err(io)?;
    if b.as_slice() != Fr::MODULUS.to_bytes_le() {
        return Err(Error::Import("field modulus"));
    }
    Ok(())
}

/// Parse canonical witness values, then charge full public correspondence and satisfaction checks.
pub fn read_wtns(
    path: &Path,
    p: &PublicPackage,
    expected_public: &[Fr],
    l: ImportLimits,
) -> Result<ValidatedAssignment, Error> {
    l.operation.package(p)?;
    let mut r = received(path, None, l)?;
    let s = sections(&mut r, b"wtns", 2, l)?;
    if s.len() != 2 {
        return Err(Error::Import("WTNS sections"));
    }
    let (_, hsize) = section(&mut r, &s, 1)?;
    if hsize != 40 {
        return Err(Error::Import("WTNS header length"));
    }
    bn_header(&mut r)?;
    let n = u32le(&mut r)?;
    if n != p.shape().assignment_len {
        return Err(Error::AssignmentCount);
    }
    let (_, size) = section(&mut r, &s, 2)?;
    if size != n.checked_mul(32).ok_or(Error::Bound("witness length"))? as u64 {
        return Err(Error::Import("WTNS value length"));
    }
    let mut total = r.get_ref().len();
    charge(&mut total, s.len(), 256, l)?;
    charge(&mut total, n, std::mem::size_of::<Fr>(), l)?;
    let mut values = Vec::with_capacity(n);
    for i in 0..n {
        values.push(field(&mut r, i)?);
    }
    p.validate_values(values, expected_public)
}

/// Two-pass constraint import: every count/index/encoding is checked before row storage allocation.
pub fn read_r1cs(path: &Path, l: ImportLimits) -> Result<ConstraintMatrices<Fr>, Error> {
    read_r1cs_received(received(path, None, l)?, l)
}
fn read_r1cs_received(
    mut r: Cursor<Vec<u8>>,
    l: ImportLimits,
) -> Result<ConstraintMatrices<Fr>, Error> {
    let s = sections(&mut r, b"r1cs", 1, l)?;
    if s.keys().any(|k| !matches!(k, 1 | 2 | 3)) {
        return Err(Error::Import("R1CS section kind"));
    }
    let (_, hsize) = section(&mut r, &s, 1)?;
    if hsize != 64 {
        return Err(Error::Import("R1CS header length"));
    }
    bn_header(&mut r)?;
    let v = u32le(&mut r)?;
    let outputs = u32le(&mut r)?;
    let public = u32le(&mut r)?;
    let private = u32le(&mut r)?;
    let labels = u64le(&mut r)?;
    let n = u32le(&mut r)?;
    let k = outputs
        .checked_add(public)
        .and_then(|x| x.checked_add(1))
        .ok_or(Error::Bound("instance overflow"))?;
    if k > v || private > v - k || v == 0 || n == 0 {
        return Err(Error::Shape("R1CS counts"));
    }
    if v > l.operation.max_assignment || n > l.operation.max_domain {
        return Err(Error::Bound("R1CS counts"));
    }
    if let Some((pos, size)) = s.get(&3) {
        if *size != v.checked_mul(8).ok_or(Error::Bound("wire map"))? as u64 {
            return Err(Error::Import("wire map length"));
        }
        r.seek(SeekFrom::Start(*pos)).map_err(io)?;
        for _ in 0..v {
            if u64le(&mut r)? >= labels {
                return Err(Error::Import("wire label"));
            }
        }
    }
    let (start, size) = section(&mut r, &s, 2)?;
    let end = start + size;
    if n > usize::try_from(size / 12).map_err(|_| Error::Bound("constraint bytes"))? {
        return Err(Error::Import("constraint count exceeds bytes"));
    }
    let mut counts = [0usize; 3];
    let mut allocated = r.get_ref().len();
    charge(&mut allocated, s.len(), 256, l)?;
    charge(
        &mut allocated,
        n,
        3 * std::mem::size_of::<Vec<(Fr, usize)>>(),
        l,
    )?;
    charge(
        &mut allocated,
        v,
        3 * std::mem::size_of::<Vec<(usize, Fr)>>() + std::mem::size_of::<usize>(),
        l,
    )?;
    for _ in 0..n {
        for total in &mut counts {
            let terms = u32le(&mut r)?;
            if terms > l.max_row_entries {
                return Err(Error::Bound("row entries"));
            }
            *total = total
                .checked_add(terms)
                .ok_or(Error::Bound("entry count overflow"))?;
            charge(&mut allocated, terms, std::mem::size_of::<(Fr, usize)>(), l)?;
            if counts_sum_exceeds(*total, l.operation.max_matrix_entries) {
                return Err(Error::Bound("matrix entries"));
            }
            let remaining = end
                .checked_sub(r.stream_position().map_err(io)?)
                .ok_or(Error::Import("constraint section overrun"))?;
            if terms as u64 > remaining / 36 {
                return Err(Error::Import("row exceeds section"));
            }
            for _ in 0..terms {
                let j = u32le(&mut r)?;
                if j >= v {
                    return Err(Error::Matrix("column bound"));
                }
                field(&mut r, j)?;
            }
        }
    }
    let entries = counts
        .iter()
        .try_fold(0usize, |x, y| x.checked_add(*y))
        .ok_or(Error::Bound("entry overflow"))?;
    if entries > l.operation.max_matrix_entries {
        return Err(Error::Bound("matrix entries"));
    }
    if r.stream_position().map_err(io)? != end {
        return Err(Error::Import("constraint trailing bytes"));
    }
    r.seek(SeekFrom::Start(start)).map_err(io)?;
    let mut second_allocated = r.get_ref().len();
    charge(&mut second_allocated, s.len(), 256, l)?;
    charge(
        &mut second_allocated,
        n,
        3 * std::mem::size_of::<Vec<(Fr, usize)>>(),
        l,
    )?;
    let mut second_counts = [0usize; 3];
    let mut matrices: [Vec<Vec<(Fr, usize)>>; 3] = std::array::from_fn(|_| Vec::with_capacity(n));
    for _ in 0..n {
        for (index, matrix) in matrices.iter_mut().enumerate() {
            let terms = u32le(&mut r)?;
            // Repeat bounds on the allocation pass: an input changed after preflight is still bounded.
            if terms > l.max_row_entries {
                return Err(Error::Bound("row entries"));
            }
            second_counts[index] = second_counts[index]
                .checked_add(terms)
                .ok_or(Error::Bound("entry overflow"))?;
            if second_counts
                .iter()
                .try_fold(0usize, |x, y| x.checked_add(*y))
                .ok_or(Error::Bound("entry overflow"))?
                > l.operation.max_matrix_entries
            {
                return Err(Error::Bound("matrix entries"));
            }
            charge(
                &mut second_allocated,
                terms,
                std::mem::size_of::<(Fr, usize)>(),
                l,
            )?;
            let mut row = Vec::with_capacity(terms);
            for _ in 0..terms {
                let j = u32le(&mut r)?;
                if j >= v {
                    return Err(Error::Matrix("column bound"));
                }
                row.push((field(&mut r, j)?, j));
            }
            matrix.push(row);
        }
    }
    if second_counts != counts || r.stream_position().map_err(io)? != end {
        return Err(Error::Import("changed constraint stream"));
    }
    let [a, b, c] = matrices;
    Ok(ConstraintMatrices {
        num_instance_variables: k,
        num_witness_variables: v - k,
        num_constraints: n,
        a_num_non_zero: counts[0],
        b_num_non_zero: counts[1],
        c_num_non_zero: counts[2],
        a,
        b,
        c,
    })
}
fn counts_sum_exceeds(n: usize, max: usize) -> bool {
    n > max
}

struct Hashed<R> {
    reader: R,
    hash: Sha256,
    remaining: u64,
}
impl<R: Read> Read for Hashed<R> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        if b.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut extra = [0; 1];
            if self.reader.read(&mut extra)? != 0 {
                return Err(std::io::Error::other("received byte cap"));
            }
            return Ok(0);
        }
        let want = b
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let n = self.reader.read(&mut b[..want])?;
        self.remaining -= n as u64;
        self.hash.update(&b[..n]);
        Ok(n)
    }
}
fn hash_bounded<R: Read>(r: &mut R, max: u64) -> Result<[u8; 32], Error> {
    let mut hash = Sha256::new();
    let mut bytes = [0; 8192];
    let mut consumed = 0u64;
    loop {
        let remaining = max
            .checked_sub(consumed)
            .ok_or(Error::Bound("received file bytes"))?;
        let want = usize::try_from(remaining.min(bytes.len() as u64)).unwrap_or(bytes.len());
        if want == 0 {
            let mut extra = [0; 1];
            if r.read(&mut extra).map_err(io)? != 0 {
                return Err(Error::Bound("received file bytes"));
            }
            break;
        }
        let n = r.read(&mut bytes[..want]).map_err(io)?;
        if n == 0 {
            break;
        }
        consumed = consumed
            .checked_add(n as u64)
            .ok_or(Error::Bound("received file bytes"))?;
        hash.update(&bytes[..n]);
    }
    Ok(hash.finalize().into())
}
fn snapshot<R: Read>(
    mut reader: R,
    declared: u64,
    l: ImportLimits,
) -> Result<Cursor<Vec<u8>>, Error> {
    let n = usize::try_from(declared).map_err(|_| Error::Bound("received file address space"))?;
    if declared > l.max_file_bytes
        || n.checked_add(8192)
            .ok_or(Error::Bound("received allocation overflow"))?
            > l.operation.max_allocation_bytes
    {
        return Err(Error::Bound("received file bytes/allocation"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(n)
        .map_err(|_| Error::Bound("received allocation"))?;
    bytes.resize(n, 0);
    reader.read_exact(&mut bytes).map_err(io)?;
    let mut extra = [0; 1];
    if reader.read(&mut extra).map_err(io)? != 0 {
        return Err(Error::Bound("changed received file length"));
    }
    Ok(Cursor::new(bytes))
}
fn received(
    path: &Path,
    expected: Option<[u8; 32]>,
    l: ImportLimits,
) -> Result<Cursor<Vec<u8>>, Error> {
    let reader = open(path, l)?;
    let declared = reader.get_ref().length;
    let cursor = snapshot(reader, declared, l)?;
    if let Some(expected) = expected {
        if <[u8; 32]>::from(Sha256::digest(cursor.get_ref())) != expected {
            return Err(Error::IdentityMismatch);
        }
    }
    Ok(cursor)
}
fn trusted(
    path: &Path,
    digest: [u8; 32],
    l: ImportLimits,
) -> Result<BufReader<LimitedFile>, Error> {
    let mut r = open(path, l)?;
    if hash_bounded(&mut r, l.max_file_bytes)? != digest {
        return Err(Error::IdentityMismatch);
    }
    r.seek(SeekFrom::Start(0)).map_err(io)?;
    Ok(r)
}
fn domain<R: Read>(r: &mut R, n: usize) -> Result<GeneralEvaluationDomain<Fr>, Error> {
    let d = GeneralEvaluationDomain::<Fr>::deserialize_compressed(r)?;
    let expected = GeneralEvaluationDomain::Radix2(
        Radix2EvaluationDomain::<Fr>::new(n).ok_or(Error::Shape("legacy domain"))?,
    );
    if d != expected {
        return Err(Error::Key("legacy domain"));
    }
    Ok(d)
}
fn vector<T: CanonicalDeserialize, R: Read>(r: &mut R, n: usize) -> Result<Vec<T>, Error> {
    if count(r)? != n {
        return Err(Error::Import("legacy vector length"));
    }
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(T::deserialize_compressed(&mut *r)?);
    }
    Ok(v)
}
fn scan_vec(
    r: &mut BufReader<LimitedFile>,
    n: usize,
    width: usize,
    memory: usize,
    total: &mut usize,
    l: ImportLimits,
) -> Result<(), Error> {
    if count(r)? != n {
        return Err(Error::Import("legacy vector length"));
    }
    charge(total, n, memory, l)?;
    skip(
        r,
        n.checked_mul(width)
            .ok_or(Error::Bound("serialized vector"))?,
    )
}
fn pk_prefix<R: Read>(
    r: &mut R,
    rows: usize,
    k: usize,
    v: usize,
    n: usize,
) -> Result<GeneralEvaluationDomain<Fr>, Error> {
    if count(r)? != rows || count(r)? != k || count(r)? != v - k {
        return Err(Error::Key("legacy key dimensions"));
    }
    domain(r, n)
}
fn read_pk<R: Read>(
    r: &mut R,
    rows: usize,
    k: usize,
    v: usize,
    n: usize,
) -> Result<dynark::ProvingKey<Bn254>, Error> {
    let d = pk_prefix(r, rows, k, v, n)?;
    let alpha_g1 = G1Affine::deserialize_compressed(&mut *r)?;
    let beta_g2 = G2Affine::deserialize_compressed(&mut *r)?;
    let gamma_g2 = G2Affine::deserialize_compressed(&mut *r)?;
    let delta_g2 = G2Affine::deserialize_compressed(&mut *r)?;
    let t_v_g1 = vector(r, k)?;
    let beta_g1 = G1Affine::deserialize_compressed(&mut *r)?;
    let delta_g1 = G1Affine::deserialize_compressed(&mut *r)?;
    Ok(dynark::ProvingKey {
        vk: dynark::VerifyingKey {
            num_constraints: rows,
            num_instance: k,
            num_witness: v - k,
            domain: d,
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            t_v_g1,
        },
        beta_g1,
        delta_g1,
        u_g1: vector(r, v)?,
        v_g1: vector(r, v)?,
        v_g2: vector(r, v)?,
        tau_powers_g1: vector(r, n - 1)?,
        t_p_g1: vector(r, v - k)?,
    })
}
fn scan_columns(
    r: &mut BufReader<LimitedFile>,
    v: usize,
    n: usize,
    total: &mut usize,
    l: ImportLimits,
) -> Result<(), Error> {
    if count(r)? != v {
        return Err(Error::Import("legacy columns"));
    }
    let mut entries = 0usize;
    charge(total, v, std::mem::size_of::<Vec<(usize, Fr)>>(), l)?;
    for _ in 0..v {
        let len = count(r)?;
        entries = entries
            .checked_add(len)
            .ok_or(Error::Bound("column entries"))?;
        if entries > l.operation.max_matrix_entries {
            return Err(Error::Bound("column entries"));
        }
        charge(total, len, std::mem::size_of::<(usize, Fr)>(), l)?;
        for _ in 0..len {
            if count(r)? >= n {
                return Err(Error::Matrix("legacy row index"));
            }
            field(r, 0)?;
        }
    }
    Ok(())
}
fn columns_check<R: Read>(r: &mut R, expected: &[Vec<(usize, Fr)>], v: usize) -> Result<(), Error> {
    if count(r)? != v {
        return Err(Error::Import("legacy columns"));
    }
    for column in expected {
        if count(r)? != column.len() {
            return Err(Error::Matrix("legacy column length"));
        }
        for (i, c) in column {
            if count(r)? != *i || field(r, 0)? != *c {
                return Err(Error::Matrix("legacy column content"));
            }
        }
    }
    Ok(())
}
/// Import the exact E2 serialized UpdatingKey, consuming its embedded PK into one shared package.
/// Caller must authenticate both expected package identity and expected UK digest externally.
pub fn read_legacy_package(
    r1cs: &Path,
    uk: &Path,
    descriptor: CircuitDescriptor,
    expected: PackageIdentity,
    expected_uk_digest: [u8; 32],
    l: ImportLimits,
) -> Result<(PublicPackage, UpdatingMaterial), Error> {
    legacy_package(r1cs, uk, descriptor, Some(expected), expected_uk_digest, l)
}
/// Development/audit bootstrap from externally authenticated legacy R1CS/UK content.
/// The returned candidate identity must be recorded/reviewed before strict replay.
/// Trusted content digests do not prove an honest setup ceremony or executable semantics.
pub fn audit_legacy_package(
    r1cs: &Path,
    uk: &Path,
    descriptor: CircuitDescriptor,
    expected_uk_digest: [u8; 32],
    l: ImportLimits,
) -> Result<(PublicPackage, UpdatingMaterial), Error> {
    legacy_package(r1cs, uk, descriptor, None, expected_uk_digest, l)
}
fn legacy_package(
    r1cs: &Path,
    uk: &Path,
    descriptor: CircuitDescriptor,
    expected: Option<PackageIdentity>,
    expected_uk_digest: [u8; 32],
    l: ImportLimits,
) -> Result<(PublicPackage, UpdatingMaterial), Error> {
    let matrices =
        read_r1cs_received(received(r1cs, Some(descriptor.r1cs_artifact_digest), l)?, l)?;
    let v = matrices.num_instance_variables + matrices.num_witness_variables;
    let k = matrices.num_instance_variables;
    let rows = match descriptor.reduction {
        crate::Reduction::Original => matrices.num_constraints,
        crate::Reduction::InstanceAugmentedA => matrices
            .num_constraints
            .checked_add(k)
            .ok_or(Error::Bound("reduction rows"))?,
    };
    let n = rows
        .checked_next_power_of_two()
        .ok_or(Error::Bound("domain overflow"))?;
    if n > l.operation.max_domain {
        return Err(Error::Bound("domain"));
    }
    let mut r = trusted(uk, expected_uk_digest, l)?;
    pk_prefix(&mut r, rows, k, v, n)?;
    skip(&mut r, 32 + 3 * 64)?;
    let mut total = 8192;
    charge(
        &mut total,
        n,
        3 * std::mem::size_of::<Vec<(Fr, usize)>>(),
        l,
    )?;
    charge(
        &mut total,
        v,
        3 * std::mem::size_of::<Vec<(usize, Fr)>>() + std::mem::size_of::<usize>(),
        l,
    )?;
    for entries in [
        matrices.a_num_non_zero,
        matrices.b_num_non_zero,
        matrices.c_num_non_zero,
    ] {
        charge(
            &mut total,
            entries,
            2 * std::mem::size_of::<(Fr, usize)>(),
            l,
        )?;
    }
    scan_vec(
        &mut r,
        k,
        32,
        std::mem::size_of::<G1Affine>(),
        &mut total,
        l,
    )?;
    skip(&mut r, 64)?;
    for (len, width, memory) in [
        (v, 32, std::mem::size_of::<G1Affine>()),
        (v, 32, std::mem::size_of::<G1Affine>()),
        (v, 64, std::mem::size_of::<G2Affine>()),
        (n - 1, 32, std::mem::size_of::<G1Affine>()),
        (v - k, 32, std::mem::size_of::<G1Affine>()),
        (n, 32, std::mem::size_of::<G1>()),
        (n, 32, std::mem::size_of::<Fr>()),
        (n, 32, std::mem::size_of::<Fr>()),
        (n, 32, std::mem::size_of::<G1>()),
        (n, 32, std::mem::size_of::<Fr>()),
        (n, 32, std::mem::size_of::<Fr>()),
    ] {
        scan_vec(&mut r, len, width, memory, &mut total, l)?;
    }
    scan_columns(&mut r, v, rows, &mut total, l)?;
    scan_columns(&mut r, v, rows, &mut total, l)?;
    exact_end(&mut r)?;
    r.seek(SeekFrom::Start(0)).map_err(io)?;
    let mut r = Hashed {
        reader: r,
        hash: Sha256::new(),
        remaining: l.max_file_bytes,
    };
    let pk = read_pk(&mut r, rows, k, v, n)?;
    let expected = match expected {
        Some(expected) => expected,
        None => PublicPackage::inspect_identity(&matrices, &descriptor, &pk)?,
    };
    let package = PublicPackage::new(matrices, descriptor, pk, expected)?;
    l.operation.package(&package)?;
    let lagrange = vector(&mut r, n)?;
    let weights: Vec<Fr> = vector(&mut r, n)?;
    let reverse: Vec<Fr> = vector(&mut r, n)?;
    let diagonal = vector(&mut r, n)?;
    let transformed: Vec<Fr> = vector(&mut r, n)?;
    let reverse_transformed: Vec<Fr> = vector(&mut r, n)?;
    for (i, x) in package.0.domain.elements().enumerate() {
        let w = if i == 0 {
            Fr::from(0u64)
        } else {
            x * (Fr::ONE - x)
                .inverse()
                .ok_or(Error::Key("root denominator"))?
                * package.0.domain.size_inv()
        };
        if weights[i] != w || reverse[(n - i) % n] != w {
            return Err(Error::Key("legacy root weights"));
        }
    }
    if package.0.domain.fft(&weights) != transformed
        || package.0.domain.fft(&reverse) != reverse_transformed
    {
        return Err(Error::Key("legacy transformed weights"));
    }
    columns_check(&mut r, &package.0.columns[0], v)?;
    columns_check(&mut r, &package.0.columns[1], v)?;
    exact_end(&mut r)?;
    if <[u8; 32]>::from(r.hash.finalize()) != expected_uk_digest {
        return Err(Error::IdentityMismatch);
    }
    let material = UpdatingMaterial(Arc::new(MaterialInner {
        package: package.identity(),
        lagrange,
        weights,
        diagonal,
    }));
    Ok((package, material))
}

/// Trusted E2 cache import. Retained projections are authenticated by the caller's expected digest.
/// No silent projection regeneration occurs; full witness validation and anchor proof verification do.
/// Legacy E2 bytes contain no credential/action/generation labels. The external trusted manifest
/// must associate this digest with the intended package, exact validated witness/public statement,
/// and supplied initial binding. Hash matching alone cannot authenticate absent labels.
pub fn read_legacy_anchor(
    path: &Path,
    p: &PublicPackage,
    uk: &UpdatingMaterial,
    assignment: ValidatedAssignment,
    binding: AnchorBinding,
    expected_cache_digest: [u8; 32],
    l: ImportLimits,
) -> Result<Anchor, Error> {
    l.operation.package(p)?;
    uk.check(p)?;
    binding.package_check(p)?;
    if binding.anchor_state != [0; 32] || assignment.package != p.identity() {
        return Err(Error::AnchorBinding);
    }
    let n = p.shape().domain_size;
    let mut r = trusted(path, expected_cache_digest, l)?;
    domain(&mut r, n)?;
    if count(&mut r)? != p.shape().instance_len {
        return Err(Error::Import("cache instance"));
    }
    field(&mut r, 0)?;
    field(&mut r, 0)?;
    let mut total = 8192;
    scan_vec(&mut r, n, 32, std::mem::size_of::<G1>(), &mut total, l)?;
    scan_vec(&mut r, n, 32, std::mem::size_of::<G1>(), &mut total, l)?;
    skip(&mut r, 32 + 32 + 64 + 32)?;
    exact_end(&mut r)?;
    r.seek(SeekFrom::Start(0)).map_err(io)?;
    let mut r = Hashed {
        reader: r,
        hash: Sha256::new(),
        remaining: l.max_file_bytes,
    };
    domain(&mut r, n)?;
    if count(&mut r)? != p.shape().instance_len {
        return Err(Error::Import("cache instance"));
    }
    let blinder_r = field(&mut r, 0)?;
    let s = field(&mut r, 0)?;
    let q_a = vector(&mut r, n)?;
    let q_b = vector(&mut r, n)?;
    let a_g1 = G1Affine::deserialize_compressed(&mut r)?;
    let b_g1 = G1Affine::deserialize_compressed(&mut r)?;
    let b_g2 = G2Affine::deserialize_compressed(&mut r)?;
    let c_g1 = G1Affine::deserialize_compressed(&mut r)?;
    exact_end(&mut r)?;
    if <[u8; 32]>::from(r.hash.finalize()) != expected_cache_digest {
        return Err(Error::IdentityMismatch);
    }
    let scalars = assignment
        .values
        .iter()
        .map(|x| x.into_bigint())
        .collect::<Vec<_>>();
    let pk = &p.0.pk;
    use ark_ec::VariableBaseMSM;
    if a_g1.into_group()
        != pk.vk.alpha_g1.into_group()
            + G1::msm_bigint(&pk.u_g1, &scalars)
            + pk.delta_g1 * blinder_r
        || b_g1.into_group()
            != pk.beta_g1.into_group() + G1::msm_bigint(&pk.v_g1, &scalars) + pk.delta_g1 * s
        || b_g2.into_group()
            != pk.vk.beta_g2.into_group()
                + ark_bn254::G2Projective::msm_bigint(&pk.v_g2, &scalars)
                + pk.vk.delta_g2 * s
    {
        return Err(Error::Import("cache witness/randomizer binding"));
    }
    let proof = ordinary::Proof::<Bn254> {
        a: a_g1,
        b: b_g2,
        c: c_g1,
    };
    if !ordinary::Groth16::<Bn254>::verify_proof(
        &ordinary::prepare_verifying_key(&p.ordinary_verifying_key()),
        &proof,
        &assignment.values[1..p.shape().instance_len],
    )
    .map_err(Error::Arithmetic)?
    {
        return Err(Error::Import("cache proof"));
    }
    let (a, b, _) = dynark::utils::lagrange_of_dense_vec(&p.0.matrices, &assignment.values)
        .map_err(Error::Arithmetic)?;
    Anchor::from_parts(
        binding,
        AnchorCore {
            assignment,
            a,
            b,
            a_g1: a_g1.into_group(),
            b_g1: b_g1.into_group(),
            b_g2: b_g2.into_group(),
            c_g1: c_g1.into_group(),
            r: blinder_r,
            s,
        },
        q_a,
        q_b,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixture as fixture;
    struct Growing {
        received: usize,
    }
    impl Read for Growing {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            b.fill(0);
            self.received += b.len();
            Ok(b.len())
        }
    }
    #[test]
    fn growing_reader_is_stopped_at_received_bound_and_section_index_is_bounded() {
        let mut r = Growing { received: 0 };
        assert!(matches!(
            hash_bounded(&mut r, 17),
            Err(Error::Bound("received file bytes"))
        ));
        assert_eq!(r.received, 18);
        let mut r = Growing { received: 0 };
        assert!(matches!(
            snapshot(&mut r, 17, ImportLimits::small()),
            Err(Error::Bound("changed received file length"))
        ));
        assert_eq!(r.received, 18);
        let mut bytes = b"r1cs".to_vec();
        bytes.extend(1u32.to_le_bytes());
        bytes.extend(100u32.to_le_bytes());
        for k in 1u32..=100 {
            bytes.extend(k.to_le_bytes());
            bytes.extend(0u64.to_le_bytes());
        }
        let mut l = ImportLimits::small();
        l.max_sections = usize::MAX;
        l.operation.max_allocation_bytes = bytes.len();
        let mut cursor = Cursor::new(bytes);
        assert!(matches!(
            sections(&mut cursor, b"r1cs", 1, l),
            Err(Error::Import("supported section count"))
        ));
        let bytes = fixture::r1cs_bytes(&fixture::relation(5));
        let mut l = ImportLimits::small();
        l.operation.max_allocation_bytes = bytes.len();
        assert!(matches!(
            read_r1cs_received(Cursor::new(bytes), l),
            Err(Error::Bound("import allocation"))
        ));
    }
    #[test]
    fn exact_received_snapshot_survives_file_mutation_and_rejects_same_matrix_changed_header() {
        let dir = fixture::tempdir();
        let path = dir.join("received.r1cs");
        let bytes = fixture::r1cs_bytes(&fixture::relation(5));
        std::fs::write(&path, &bytes).unwrap();
        let expected: [u8; 32] = Sha256::digest(&bytes).into();
        let captured = received(&path, Some(expected), ImportLimits::small()).unwrap();
        let mut substituted = bytes.clone();
        substituted[76..84].copy_from_slice(&55u64.to_le_bytes());
        std::fs::write(&path, &substituted).unwrap();
        let m = read_r1cs_received(captured, ImportLimits::small()).unwrap();
        assert_eq!(m.a, fixture::relation(5).a);
        assert!(read_r1cs(&path, ImportLimits::small()).is_ok());
        assert!(matches!(
            received(&path, Some(expected), ImportLimits::small()),
            Err(Error::IdentityMismatch)
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
