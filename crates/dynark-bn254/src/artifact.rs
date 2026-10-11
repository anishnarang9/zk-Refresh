use crate::Error;
use ark_bn254::{Bn254, Fr};
use ark_ec::AffineRepr;
use ark_ff::Field;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Radix2EvaluationDomain};
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use sha2::{Digest, Sha256};
use std::{io::Write, sync::Arc};

/// The exact row reduction, including instance coordinate zero when augmented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reduction {
    Original,
    InstanceAugmentedA,
}

/// Supplied artifact digests identify metadata; they do not authenticate an executable or setup.
#[derive(Clone, Debug)]
pub struct CircuitDescriptor {
    pub r1cs_artifact_digest: [u8; 32],
    pub witness_executable_digest: [u8; 32],
    pub profile_digest: [u8; 32],
    pub public_schema_digest: [u8; 32],
    pub public_schema: Vec<String>,
    pub reduction: Reduction,
}

/// Distinct raw row, reduced row, assignment, instance (including one), and padded sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    pub constraint_rows: usize,
    pub reduction_rows: usize,
    pub assignment_len: usize,
    pub instance_len: usize,
    pub domain_size: usize,
}

/// Content commitments to one exact relation/reduction and canonical PK/VK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackageIdentity {
    pub matrix_digest: [u8; 32],
    pub circuit_digest: [u8; 32],
    pub proving_key_digest: [u8; 32],
    pub verifying_key_digest: [u8; 32],
    pub package_digest: [u8; 32],
}

pub(crate) struct PackageInner {
    pub(crate) identity: PackageIdentity,
    pub(crate) shape: Shape,
    pub(crate) matrices: ConstraintMatrices<Fr>,
    pub(crate) pk: dynark::ProvingKey<Bn254>,
    pub(crate) domain: GeneralEvaluationDomain<Fr>,
}

/// One immutable allocation owns the PK and reduced matrices. Clones share that allocation.
#[derive(Clone)]
pub struct PublicPackage(pub(crate) Arc<PackageInner>);

/// Private canonical assignment, created only after all statement and relation checks.
/// Deliberately has no deserializer, field accessor, Debug, or public constructor.
pub struct ValidatedAssignment {
    pub(crate) package: PackageIdentity,
    pub(crate) values: Vec<Fr>,
}

struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn canonical_digest<T: CanonicalSerialize>(tag: &[u8], value: &T) -> Result<[u8; 32], Error> {
    let mut w = HashWriter(Sha256::new());
    w.0.update(tag);
    value.serialize_compressed(&mut w)?;
    Ok(w.0.finalize().into())
}
fn number(h: &mut Sha256, n: usize) {
    h.update((n as u64).to_le_bytes());
}

/// Canonical schema commitment: count and length-prefixed ordered UTF-8 names.
pub fn public_schema_digest(names: &[String]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"dynark-bn254/public-schema/v1");
    number(&mut h, names.len());
    for name in names {
        number(&mut h, name.len());
        h.update(name.as_bytes());
    }
    h.finalize().into()
}

fn shape(m: &ConstraintMatrices<Fr>, d: &CircuitDescriptor) -> Result<Shape, Error> {
    if m.num_instance_variables == 0 || m.num_constraints == 0 {
        return Err(Error::Shape("zero instance/constraint count"));
    }
    let v = m
        .num_instance_variables
        .checked_add(m.num_witness_variables)
        .ok_or(Error::Shape("assignment overflow"))?;
    let rows = match d.reduction {
        Reduction::Original => m.num_constraints,
        Reduction::InstanceAugmentedA => m
            .num_constraints
            .checked_add(m.num_instance_variables)
            .ok_or(Error::Shape("row overflow"))?,
    };
    let n = rows
        .checked_next_power_of_two()
        .ok_or(Error::Shape("domain overflow"))?;
    if n < 2 || Radix2EvaluationDomain::<Fr>::new(n).is_none() {
        return Err(Error::Shape("unsupported radix-two domain"));
    }
    if d.public_schema.len() != m.num_instance_variables - 1
        || d.public_schema_digest != public_schema_digest(&d.public_schema)
    {
        return Err(Error::Schema("count or digest"));
    }
    for (i, name) in d.public_schema.iter().enumerate() {
        if name.is_empty() || d.public_schema[..i].contains(name) {
            return Err(Error::Schema("empty or duplicate name"));
        }
    }
    for (matrix, declared) in [
        (&m.a, m.a_num_non_zero),
        (&m.b, m.b_num_non_zero),
        (&m.c, m.c_num_non_zero),
    ] {
        if matrix.len() != m.num_constraints {
            return Err(Error::Matrix("row count"));
        }
        let mut count = 0usize;
        for row in matrix {
            count = count
                .checked_add(row.len())
                .ok_or(Error::Matrix("entry count overflow"))?;
            for (_, j) in row {
                if *j >= v {
                    return Err(Error::Matrix("column bound"));
                }
            }
        }
        if count != declared {
            return Err(Error::Matrix("entry count"));
        }
    }
    Ok(Shape {
        constraint_rows: m.num_constraints,
        reduction_rows: rows,
        assignment_len: v,
        instance_len: m.num_instance_variables,
        domain_size: n,
    })
}

fn key_check(
    pk: &dynark::ProvingKey<Bn254>,
    s: Shape,
    domain: &GeneralEvaluationDomain<Fr>,
) -> Result<(), Error> {
    if pk.vk.num_constraints != s.reduction_rows
        || pk.vk.num_instance != s.instance_len
        || pk.vk.num_witness != s.assignment_len - s.instance_len
        || pk.vk.domain != *domain
    {
        return Err(Error::Key("dimensions/domain"));
    }
    if pk.u_g1.len() != s.assignment_len
        || pk.v_g1.len() != s.assignment_len
        || pk.v_g2.len() != s.assignment_len
        || pk.t_p_g1.len() != s.assignment_len - s.instance_len
        || pk.vk.t_v_g1.len() != s.instance_len
        || pk.tau_powers_g1.len() != s.domain_size - 1
    {
        return Err(Error::Key("query lengths"));
    }
    pk.check()
        .map_err(|_| Error::Key("invalid curve/subgroup encoding"))?;
    if pk.vk.gamma_g2.is_zero() || pk.vk.delta_g2.is_zero() || pk.delta_g1.is_zero() {
        return Err(Error::Key("degenerate denominator"));
    }
    Ok(())
}

impl PublicPackage {
    /// Derive identities for development/audit. This does not establish trustworthy setup provenance.
    /// Production callers supply a separately authenticated expected identity to `new`.
    pub fn inspect_identity(
        m: &ConstraintMatrices<Fr>,
        descriptor: &CircuitDescriptor,
        pk: &dynark::ProvingKey<Bn254>,
    ) -> Result<PackageIdentity, Error> {
        let s = shape(m, descriptor)?;
        let domain = GeneralEvaluationDomain::Radix2(
            Radix2EvaluationDomain::<Fr>::new(s.domain_size).ok_or(Error::Shape("domain"))?,
        );
        key_check(pk, s, &domain)?;
        let mut mh = HashWriter(Sha256::new());
        mh.0.update(b"dynark-bn254/matrices/v1");
        for n in [s.constraint_rows, s.assignment_len, s.instance_len] {
            number(&mut mh.0, n);
        }
        for matrix in [&m.a, &m.b, &m.c] {
            for row in matrix {
                number(&mut mh.0, row.len());
                for (coefficient, j) in row {
                    number(&mut mh.0, *j);
                    coefficient.serialize_compressed(&mut mh)?;
                }
            }
        }
        let matrix_digest: [u8; 32] = mh.0.finalize().into();
        let mut ch = Sha256::new();
        ch.update(b"dynark-bn254/circuit/v1;curve=BN254;domain=radix2;roots=omega^i;quotient=seven-transform;encoding=ark-compressed-v0.5");
        ch.update(matrix_digest);
        for digest in [
            descriptor.r1cs_artifact_digest,
            descriptor.witness_executable_digest,
            descriptor.profile_digest,
            descriptor.public_schema_digest,
        ] {
            ch.update(digest);
        }
        ch.update([match descriptor.reduction {
            Reduction::Original => 0,
            Reduction::InstanceAugmentedA => 1,
        }]);
        for n in [
            s.constraint_rows,
            s.reduction_rows,
            s.assignment_len,
            s.instance_len,
            s.domain_size,
        ] {
            number(&mut ch, n);
        }
        domain.serialize_compressed(&mut HashForward(&mut ch))?;
        let circuit_digest = ch.finalize().into();
        let proving_key_digest = canonical_digest(b"dynark-bn254/pk/v1", pk)?;
        let verifying_key_digest = canonical_digest(b"dynark-bn254/vk/v1", &pk.vk)?;
        let mut ph = Sha256::new();
        ph.update(b"dynark-bn254/package/v1");
        for digest in [circuit_digest, proving_key_digest, verifying_key_digest] {
            ph.update(digest);
        }
        Ok(PackageIdentity {
            matrix_digest,
            circuit_digest,
            proving_key_digest,
            verifying_key_digest,
            package_digest: ph.finalize().into(),
        })
    }

    /// Consume one PK and relation after checking them against a trusted expected content identity.
    /// Computing `expected` from these same untrusted inputs is only a development workflow.
    pub fn new(
        mut matrices: ConstraintMatrices<Fr>,
        descriptor: CircuitDescriptor,
        pk: dynark::ProvingKey<Bn254>,
        expected: PackageIdentity,
    ) -> Result<Self, Error> {
        let identity = Self::inspect_identity(&matrices, &descriptor, &pk)?;
        if identity != expected {
            return Err(Error::IdentityMismatch);
        }
        let s = shape(&matrices, &descriptor)?;
        if descriptor.reduction == Reduction::InstanceAugmentedA {
            for i in 0..s.instance_len {
                matrices.a.push(vec![(Fr::ONE, i)]);
                matrices.b.push(vec![]);
                matrices.c.push(vec![]);
            }
            matrices.num_constraints = s.reduction_rows;
            matrices.a_num_non_zero = matrices
                .a_num_non_zero
                .checked_add(s.instance_len)
                .ok_or(Error::Matrix("augmentation overflow"))?;
        }
        let domain = pk.vk.domain;
        Ok(Self(Arc::new(PackageInner {
            identity,
            shape: s,
            matrices,
            pk,
            domain,
        })))
    }
    pub fn identity(&self) -> PackageIdentity {
        self.0.identity
    }
    pub fn shape(&self) -> Shape {
        self.0.shape
    }
    pub fn shares_storage_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    /// Independent ordinary-verifier VK; copies only the small instance query, never the PK.
    pub fn ordinary_verifying_key(&self) -> ordinary::VerifyingKey<Bn254> {
        let vk = &self.0.pk.vk;
        ordinary::VerifyingKey {
            alpha_g1: vk.alpha_g1,
            beta_g2: vk.beta_g2,
            gamma_g2: vk.gamma_g2,
            delta_g2: vk.delta_g2,
            gamma_abc_g1: vk.t_v_g1.clone(),
        }
    }
    /// All fields use exactly 32 canonical little-endian bytes; public values exclude one.
    /// Full matrix-wide satisfaction is charged to this validation, before any proof randomness.
    pub fn validate_assignment(
        &self,
        encodings: &[[u8; 32]],
        expected_public: &[Fr],
    ) -> Result<ValidatedAssignment, Error> {
        if encodings.len() != self.0.shape.assignment_len {
            return Err(Error::AssignmentCount);
        }
        if expected_public.len() != self.0.shape.instance_len - 1 {
            return Err(Error::PublicStatement);
        }
        let values = encodings
            .iter()
            .enumerate()
            .map(|(coordinate, b)| {
                Fr::deserialize_compressed(&b[..])
                    .map_err(|_| Error::NonCanonicalField { coordinate })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if values[0] != Fr::ONE {
            return Err(Error::ConstantOne);
        }
        if values[1..self.0.shape.instance_len] != *expected_public {
            return Err(Error::PublicStatement);
        }
        for row in 0..self.0.shape.reduction_rows {
            let evaluate =
                |terms: &[(Fr, usize)]| terms.iter().map(|(c, j)| *c * values[*j]).sum::<Fr>();
            let m = &self.0.matrices;
            if evaluate(&m.a[row]) * evaluate(&m.b[row]) != evaluate(&m.c[row]) {
                return Err(Error::Unsatisfied { row });
            }
        }
        Ok(ValidatedAssignment {
            package: self.0.identity,
            values,
        })
    }
}
struct HashForward<'a>(&'a mut Sha256);
impl Write for HashForward<'_> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.update(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
