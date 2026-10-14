use crate::{
    randomness, AnchorBinding, Error, Limits, PackageIdentity, ProofStatement, PublicPackage,
    Transition, ValidatedAssignment,
};
use ark_bn254::{Fr, G1Projective as G1, G2Projective as G2};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, PrimeField, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::CanonicalSerialize;
use dynark::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
use rand::{CryptoRng, RngCore};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::{io::Write, sync::Arc};

pub(crate) struct MaterialInner {
    pub(crate) package: PackageIdentity,
    pub(crate) lagrange: Vec<G1>,
    pub(crate) weights: Vec<Fr>,
    pub(crate) diagonal: Vec<G1>,
}
/// Immutable public updating tables; owns no duplicate PK. Clones share all table allocations.
#[derive(Clone)]
pub struct UpdatingMaterial(pub(crate) Arc<MaterialInner>);
fn convolution_g(domain: &GeneralEvaluationDomain<Fr>, a: &[Fr], b: &[G1]) -> Vec<G1> {
    let af = domain.fft(a);
    let mut bf = domain.fft(b);
    for (x, y) in bf.iter_mut().zip(af) {
        *x *= y;
    }
    domain.ifft_in_place(&mut bf);
    bf
}
fn convolution_f(domain: &GeneralEvaluationDomain<Fr>, a: &[Fr], b: &[Fr]) -> Vec<Fr> {
    let af = domain.fft(a);
    let mut bf = domain.fft(b);
    for (x, y) in bf.iter_mut().zip(af) {
        *x *= y;
    }
    domain.ifft_in_place(&mut bf);
    bf
}
impl UpdatingMaterial {
    pub fn prepare(p: &PublicPackage, limits: Limits) -> Result<Self, Error> {
        limits.package(p)?;
        let n = p.shape().domain_size;
        let domain = &p.0.domain;
        let mut h =
            p.0.pk
                .tau_powers_g1
                .iter()
                .map(|x| x.into_group())
                .collect::<Vec<_>>();
        h.push(G1::zero());
        domain.ifft_in_place(&mut h);
        let mut weights = vec![Fr::from(0u64); n];
        for (i, x) in domain.elements().enumerate().skip(1) {
            weights[i] = x
                * (Fr::ONE - x)
                    .inverse()
                    .ok_or(Error::Key("root kernel denominator"))?
                * domain.size_inv();
        }
        let sum = weights.iter().copied().sum::<Fr>();
        let mut diagonal = convolution_g(domain, &weights, &h);
        for (d, l) in diagonal.iter_mut().zip(&h) {
            *d = -(*d + *l * sum);
        }
        Ok(Self(Arc::new(MaterialInner {
            package: p.identity(),
            lagrange: h,
            weights,
            diagonal,
        })))
    }
    pub fn shares_storage_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub(crate) fn check(&self, p: &PublicPackage) -> Result<(), Error> {
        let n = p.shape().domain_size;
        if self.0.package != p.identity()
            || self.0.lagrange.len() != n
            || self.0.weights.len() != n
            || self.0.diagonal.len() != n
        {
            return Err(Error::UpdatingPackage);
        }
        Ok(())
    }
    pub(crate) fn project(&self, p: &PublicPackage, a: &[Fr]) -> Vec<G1> {
        let domain = &p.0.domain;
        let n = p.shape().domain_size;
        let al = a
            .iter()
            .zip(&self.0.lagrange)
            .map(|(x, l)| *l * *x)
            .collect::<Vec<_>>();
        let mut result = convolution_g(domain, &self.0.weights, &al);
        let reverse = (0..n)
            .map(|i| self.0.weights[(n - i) % n])
            .collect::<Vec<_>>();
        let scalar = convolution_f(domain, &reverse, a);
        for i in 0..n {
            result[i] += self.0.lagrange[i] * scalar[i] + self.0.diagonal[i] * a[i];
        }
        result
    }
    /// Quadratic sparse oracle. T4 can replace this call while preserving exact inputs/diagonal.
    pub(crate) fn cross(
        &self,
        a: &[(usize, Fr)],
        b: &[(usize, Fr)],
        cap: usize,
    ) -> Result<G1, Error> {
        if a.len()
            .checked_mul(b.len())
            .ok_or(Error::Bound("cross pair overflow"))?
            > cap
        {
            return Err(Error::Bound("cross pair work"));
        }
        let n = self.0.weights.len();
        if a.len() > n || b.len() > n {
            return Err(Error::Bound("cross support"));
        }
        if a.iter().chain(b).any(|(i, _)| *i >= n) {
            return Err(Error::DeltaCoordinate);
        }
        let mut left = vec![Fr::from(0u64); a.len()];
        let mut right = vec![Fr::from(0u64); b.len()];
        let mut result = G1::zero();
        // One fused quadratic field loop, with linear group arithmetic as in the reference.
        for (ai, (i, x)) in a.iter().enumerate() {
            for (bj, (j, y)) in b.iter().enumerate() {
                if i == j {
                    result += self.0.diagonal[*i] * (*x * *y);
                } else {
                    left[ai] += *y * self.0.weights[(n + j - i) % n];
                    right[bj] += *x * self.0.weights[(n + i - j) % n];
                }
            }
        }
        for ((i, x), coefficient) in a.iter().zip(left) {
            result += self.0.lagrange[*i] * (*x * coefficient);
        }
        for ((j, y), coefficient) in b.iter().zip(right) {
            result += self.0.lagrange[*j] * (*y * coefficient);
        }
        Ok(result)
    }
}

// Capture is separate from eager projection construction for future selectively prepared modes.
pub(crate) struct AnchorCore {
    pub(crate) assignment: ValidatedAssignment,
    pub(crate) a: Vec<Fr>,
    pub(crate) b: Vec<Fr>,
    pub(crate) a_g1: G1,
    pub(crate) b_g1: G1,
    pub(crate) b_g2: G2,
    pub(crate) c_g1: G1,
    pub(crate) r: Fr,
    pub(crate) s: Fr,
}
pub(crate) fn capture(
    p: &PublicPackage,
    assignment: ValidatedAssignment,
    r: Fr,
    s: Fr,
) -> Result<AnchorCore, Error> {
    if assignment.package != p.identity() {
        return Err(Error::AssignmentPackage);
    }
    let (a, b, c) = dynark::utils::lagrange_of_dense_vec(&p.0.matrices, &assignment.values)
        .map_err(Error::Arithmetic)?;
    let quotient = LibsnarkReduction::compute_quotient::<Fr, GeneralEvaluationDomain<Fr>>(
        &p.0.domain,
        a.clone(),
        b.clone(),
        c,
    )
    .map_err(Error::Arithmetic)?;
    let n = p.shape().domain_size;
    if quotient.len() != n || !quotient[n - 1].is_zero() {
        return Err(Error::QuotientDegree);
    }
    let scalar = |x: &[Fr]| x.iter().map(|f| f.into_bigint()).collect::<Vec<_>>();
    let assignment_scalar = scalar(&assignment.values);
    let pk = &p.0.pk;
    let a_g1 = pk.vk.alpha_g1.into_group()
        + G1::msm_bigint(&pk.u_g1, &assignment_scalar)
        + pk.delta_g1 * r;
    let b_g1 =
        pk.beta_g1.into_group() + G1::msm_bigint(&pk.v_g1, &assignment_scalar) + pk.delta_g1 * s;
    let b_g2 = pk.vk.beta_g2.into_group()
        + G2::msm_bigint(&pk.v_g2, &assignment_scalar)
        + pk.vk.delta_g2 * s;
    let c_g1 = a_g1 * s + b_g1 * r - pk.delta_g1 * (r * s)
        + G1::msm_bigint(&pk.t_p_g1, &assignment_scalar[p.shape().instance_len..])
        + G1::msm_bigint(&pk.tau_powers_g1, &scalar(&quotient[..n - 1]));
    Ok(AnchorCore {
        assignment,
        a,
        b,
        a_g1,
        b_g1,
        b_g2,
        c_g1,
        r,
        s,
    })
}
/// Sensitive immutable witness/projection/proof state. No raw-state or scalar accessor/serializer.
pub struct Anchor {
    pub(crate) binding: AnchorBinding,
    pub(crate) core: AnchorCore,
    pub(crate) q_a: Vec<G1>,
    pub(crate) q_b: Vec<G1>,
}
struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.update(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Anchor {
    pub fn create<R: RngCore + CryptoRng + ?Sized>(
        p: &PublicPackage,
        uk: &UpdatingMaterial,
        assignment: ValidatedAssignment,
        binding: AnchorBinding,
        limits: Limits,
        rng: &mut R,
    ) -> Result<Self, Error> {
        limits.package(p)?;
        binding.package_check(p)?;
        uk.check(p)?;
        if binding.anchor_state != [0; 32] {
            return Err(Error::AnchorBinding);
        }
        if assignment.package != p.identity() {
            return Err(Error::AssignmentPackage);
        }
        let (r, s) = randomness::blinders(rng)?;
        let core = capture(p, assignment, r, s)?;
        let q_a = uk.project(p, &core.a);
        let q_b = uk.project(p, &core.b);
        Self::from_parts(binding, core, q_a, q_b)
    }
    pub(crate) fn from_parts(
        mut binding: AnchorBinding,
        core: AnchorCore,
        q_a: Vec<G1>,
        q_b: Vec<G1>,
    ) -> Result<Self, Error> {
        binding.anchor_state = [0; 32];
        let mut anchor = Self {
            binding,
            core,
            q_a,
            q_b,
        };
        anchor.binding.anchor_state = anchor.state_commitment()?;
        Ok(anchor)
    }
    /// Opaque exact-anchor token is computed once, including the hidden randomizers.
    pub fn binding(&self) -> AnchorBinding {
        self.binding
    }
    fn state_commitment(&self) -> Result<[u8; 32], Error> {
        let mut h = HashWriter(Sha256::new());
        h.0.update(b"dynark-bn254/immutable-anchor/v1");
        for d in [
            self.binding.package.package_digest,
            self.binding.credential,
            self.binding.action,
        ] {
            h.0.update(d);
        }
        h.0.update((self.binding.domain_size as u64).to_le_bytes());
        h.0.update(self.binding.generation.to_le_bytes());
        self.core.assignment.values.serialize_compressed(&mut h)?;
        self.core.a.serialize_compressed(&mut h)?;
        self.core.b.serialize_compressed(&mut h)?;
        for g in [&self.core.a_g1, &self.core.b_g1, &self.core.c_g1] {
            g.serialize_compressed(&mut h)?;
        }
        self.core.b_g2.serialize_compressed(&mut h)?;
        self.core.r.serialize_compressed(&mut h)?;
        self.core.s.serialize_compressed(&mut h)?;
        self.q_a.serialize_compressed(&mut h)?;
        self.q_b.serialize_compressed(&mut h)?;
        Ok(h.0.finalize().into())
    }
    pub fn update<R: RngCore + CryptoRng + ?Sized>(
        &self,
        p: &PublicPackage,
        uk: &UpdatingMaterial,
        t: &Transition,
        limits: Limits,
        rng: &mut R,
    ) -> Result<ProofStatement, Error> {
        limits.package(p)?;
        uk.check(p)?;
        self.binding.package_check(p)?;
        if t.base != self.binding {
            return Err(Error::AnchorBinding);
        }
        let prepared = t.validate_target(p, &self.core.assignment)?;
        if prepared
            .rows
            .a
            .len()
            .checked_mul(prepared.rows.b.len())
            .ok_or(Error::Bound("cross pair overflow"))?
            > limits.max_pair_work
        {
            return Err(Error::Bound("cross pair work"));
        }
        let (r, s) = randomness::blinders(rng)?;
        let (a, _, b, c) =
            self.update_components(p, uk, t, &prepared.rows, r, s, limits.max_pair_work)?;
        Ok(ProofStatement {
            proof: ordinary::Proof {
                a: a.into_affine(),
                b: b.into_affine(),
                c: c.into_affine(),
            },
            public_values: prepared.target.values[1..p.shape().instance_len].to_vec(),
            package: p.identity(),
            generation: t.generation,
        })
    }
    fn update_components(
        &self,
        p: &PublicPackage,
        uk: &UpdatingMaterial,
        t: &Transition,
        rows: &crate::RowDeltas,
        r: Fr,
        s: Fr,
        cap: usize,
    ) -> Result<(G1, G1, G2, G1), Error> {
        let pk = &p.0.pk;
        let (da, db1, db2, private) = t.delta.par_iter().fold(
            || (G1::zero(), G1::zero(), G2::zero(), G1::zero()),
            |(mut a, mut b1, mut b2, mut private), (j, x)| {
                a += pk.u_g1[*j] * *x;
                b1 += pk.v_g1[*j] * *x;
                b2 += pk.v_g2[*j] * *x;
                if *j >= p.shape().instance_len {
                    private += pk.t_p_g1[*j - p.shape().instance_len] * *x;
                }
                (a, b1, b2, private)
            },
        ).reduce(
            || (G1::zero(), G1::zero(), G2::zero(), G1::zero()),
            |a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2, a.3 + b.3),
        );
        let a = self.core.a_g1 + pk.delta_g1 * (r - self.core.r) + da;
        let b1 = self.core.b_g1 + pk.delta_g1 * (s - self.core.s) + db1;
        let b2 = self.core.b_g2 + pk.vk.delta_g2 * (s - self.core.s) + db2;
        let mut quotient = uk.cross(&rows.a, &rows.b, cap)?;
        quotient += rows.a.par_iter().map(|(i, x)| self.q_b[*i] * *x).sum::<G1>();
        quotient += rows.b.par_iter().map(|(i, x)| self.q_a[*i] * *x).sum::<G1>();
        let c = self.core.c_g1 + a * s - self.core.a_g1 * self.core.s + b1 * r
            - self.core.b_g1 * self.core.r
            - pk.delta_g1 * (r * s - self.core.r * self.core.s)
            + private
            + quotient;
        Ok((a, b1, b2, c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixture as fixture;
    use crate::Reduction;
    use ark_bn254::Bn254;
    fn polynomial(p: &PublicPackage, eval: &[Fr]) -> Vec<Fr> {
        p.0.domain.ifft(eval)
    }
    // Independent schoolbook multiplication and division by X^N-1; no vendor quotient routine.
    fn quotient(a: &[Fr], b: &[Fr], c: &[Fr], n: usize) -> (Vec<Fr>, Vec<Fr>) {
        let mut f = vec![Fr::from(0u64); 2 * n - 1];
        for (i, x) in a.iter().enumerate() {
            for (j, y) in b.iter().enumerate() {
                f[i + j] += *x * *y;
            }
        }
        for (i, x) in c.iter().enumerate() {
            f[i] -= x;
        }
        let mut q = vec![Fr::from(0u64); n - 1];
        for i in (n..f.len()).rev() {
            let coefficient = f[i];
            q[i - n] = coefficient;
            f[i - n] += coefficient;
            f[i] = Fr::from(0u64);
        }
        (q, f[..n].to_vec())
    }
    fn encode(p: &PublicPackage, q: &[Fr]) -> G1 {
        G1::msm_bigint(
            &p.0.pk.tau_powers_g1,
            &q.iter().map(|x| x.into_bigint()).collect::<Vec<_>>(),
        )
    }
    fn snapshot(a: &Anchor) -> Vec<u8> {
        let mut out = Vec::new();
        a.core
            .assignment
            .values
            .serialize_compressed(&mut out)
            .unwrap();
        a.core.a.serialize_compressed(&mut out).unwrap();
        a.core.b.serialize_compressed(&mut out).unwrap();
        a.core.a_g1.serialize_compressed(&mut out).unwrap();
        a.core.b_g1.serialize_compressed(&mut out).unwrap();
        a.core.b_g2.serialize_compressed(&mut out).unwrap();
        a.core.c_g1.serialize_compressed(&mut out).unwrap();
        a.core.r.serialize_compressed(&mut out).unwrap();
        a.core.s.serialize_compressed(&mut out).unwrap();
        a.q_a.serialize_compressed(&mut out).unwrap();
        a.q_b.serialize_compressed(&mut out).unwrap();
        out.extend(a.binding.anchor_state);
        out
    }
    fn anchor(p: &PublicPackage, u: &UpdatingMaterial, z: &[Fr]) -> Anchor {
        let values = p
            .validate_assignment(&fixture::bytes(z), &z[1..p.shape().instance_len])
            .unwrap();
        let core = capture(p, values, Fr::from(13), Fr::from(19)).unwrap();
        let qa = u.project(p, &core.a);
        let qb = u.project(p, &core.b);
        Anchor::from_parts(AnchorBinding::new(p, [1; 32], [2; 32], 7), core, qa, qb).unwrap()
    }
    #[test]
    fn dense_polynomial_projection_cross_and_all_raw_components_equal() {
        for v in [5, 11] {
            for reduction in [Reduction::Original, Reduction::InstanceAugmentedA] {
                let p = fixture::package(v, reduction);
                let u = UpdatingMaterial::prepare(&p, Limits::small()).unwrap();
                let n = p.shape().domain_size;
                let hex = |d: [u8; 32]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
                let id = p.identity();
                println!("T2_FIXTURE v={} reduction={:?} rows={} k={} N={} r1cs={} witness={} profile={} schema={} matrix={} circuit={} pk={} vk={} package={}",v,reduction,p.shape().constraint_rows,p.shape().instance_len,n,hex([11;32]),hex([12;32]),hex([13;32]),hex(fixture::descriptor(reduction).public_schema_digest),hex(id.matrix_digest),hex(id.circuit_digest),hex(id.proving_key_digest),hex(id.verifying_key_digest),hex(id.package_digest));
                for (w, t, wn, tn) in [
                    (3, 2, 4, 1),
                    (4, 1, 3, 2),
                    (3, 2, 3, 2),
                    (3, 2, 2, 3),
                    (3, 2, 5, 4),
                    (3, 2, 3, 4),
                ] {
                    let z = fixture::assignment(v, w, t);
                    let mut target = fixture::assignment(v, wn, tn);
                    if v > n && wn == w && tn != t {
                        target[v - 1] = Fr::from(37);
                    }
                    let a = anchor(&p, &u, &z);
                    let before = snapshot(&a);
                    let ap = polynomial(&p, &a.core.a);
                    let bp = polynomial(&p, &a.core.b);
                    for (i, x) in p.0.domain.elements().enumerate() {
                        let inv = x.inverse().unwrap();
                        let mut power = Fr::ONE;
                        let li = (0..n)
                            .map(|_| {
                                let c = power * p.0.domain.size_inv();
                                power *= inv;
                                c
                            })
                            .collect::<Vec<_>>();
                        assert_eq!(a.q_a[i], encode(&p, &quotient(&ap, &li, &[], n).0));
                        assert_eq!(a.q_b[i], encode(&p, &quotient(&bp, &li, &[], n).0));
                        assert_eq!(u.0.diagonal[i], encode(&p, &quotient(&li, &li, &[], n).0));
                    }
                    let mut raw = z
                        .iter()
                        .zip(&target)
                        .enumerate()
                        .skip(1)
                        .map(|(j, (x, y))| (j, fixture::bytes(&[*y - *x])[0]))
                        .collect::<Vec<_>>();
                    raw.push((2, fixture::bytes(&[Fr::ONE])[0]));
                    raw.push((2, fixture::bytes(&[-Fr::ONE])[0]));
                    let tr =
                        Transition::new(&p, a.binding(), 8, &raw, &target[1..2], Limits::small())
                            .unwrap();
                    let prepared = tr.validate_target(&p, &a.core.assignment).unwrap();
                    let mut da = vec![Fr::from(0u64); n];
                    let mut db = da.clone();
                    for (i, x) in &prepared.rows.a {
                        da[*i] = *x;
                    }
                    for (i, x) in &prepared.rows.b {
                        db[*i] = *x;
                    }
                    let dap = polynomial(&p, &da);
                    let dbp = polynomial(&p, &db);
                    assert_eq!(
                        u.cross(&prepared.rows.a, &prepared.rows.b, 65536).unwrap(),
                        encode(&p, &quotient(&dap, &dbp, &[], n).0)
                    );
                    let (ta, tb, tc) =
                        dynark::utils::lagrange_of_dense_vec(&p.0.matrices, &target).unwrap();
                    let (target_q, remainder) = quotient(
                        &polynomial(&p, &ta),
                        &polynomial(&p, &tb),
                        &polynomial(&p, &tc),
                        n,
                    );
                    assert!(remainder.iter().all(Zero::is_zero));
                    let (_, _, bc) =
                        dynark::utils::lagrange_of_dense_vec(&p.0.matrices, &z).unwrap();
                    let base_q = quotient(&ap, &bp, &polynomial(&p, &bc), n).0;
                    let mut correction =
                        u.cross(&prepared.rows.a, &prepared.rows.b, 65536).unwrap();
                    for (i, x) in &prepared.rows.a {
                        correction += a.q_b[*i] * *x;
                    }
                    for (i, x) in &prepared.rows.b {
                        correction += a.q_a[*i] * *x;
                    }
                    let difference = target_q
                        .iter()
                        .zip(&base_q)
                        .map(|(x, y)| *x - *y)
                        .collect::<Vec<_>>();
                    assert_eq!(correction, encode(&p, &difference));
                    let (r, s) = (Fr::from(23), Fr::from(29));
                    let components = a
                        .update_components(&p, &u, &tr, &prepared.rows, r, s, 65536)
                        .unwrap();
                    let full = dynark::Groth16::<Bn254>::create_proof_with_assignment(
                        &p.0.pk,
                        r,
                        s,
                        &target_q,
                        &target[..2],
                        &target[2..],
                    )
                    .unwrap();
                    assert_eq!(components.0.into_affine(), full.a_g1);
                    assert_eq!(components.2.into_affine(), full.b_g2);
                    assert_eq!(components.3.into_affine(), full.c_g1);
                    let expected_b1 = p.0.pk.beta_g1.into_group()
                        + G1::msm_bigint(
                            &p.0.pk.v_g1,
                            &target.iter().map(|x| x.into_bigint()).collect::<Vec<_>>(),
                        )
                        + p.0.pk.delta_g1 * s;
                    assert_eq!(components.1, expected_b1);
                    assert_eq!(snapshot(&a), before);
                }
            }
        }
    }
    #[test]
    fn binding_negatives_preflight_without_entropy_and_preserve_all_state() {
        let p = fixture::package(5, Reduction::Original);
        let u = UpdatingMaterial::prepare(&p, Limits::small()).unwrap();
        let z = fixture::assignment(5, 3, 2);
        let a = anchor(&p, &u, &z);
        let before = snapshot(&a);
        let binding = a.binding();
        let mut variants = vec![binding; 6];
        variants[0].credential = [9; 32];
        variants[1].generation = 6;
        variants[2].anchor_state = [7; 32];
        variants[3].package.proving_key_digest = [8; 32];
        variants[4].domain_size = 16;
        variants[5].action = [10; 32];
        for variant in variants {
            let mut t = Transition::new(&p, binding, 8, &[], &z[1..2], Limits::small()).unwrap();
            t.base = variant;
            let mut rng = FailSecond { draw: 0 };
            assert!(matches!(
                a.update(&p, &u, &t, Limits::small(), &mut rng),
                Err(Error::AnchorBinding)
            ));
            assert_eq!(rng.draw, 0);
            assert_eq!(a.binding(), binding);
            assert_eq!(snapshot(&a), before);
        }
        let other = fixture::package(11, Reduction::Original);
        let wrong = UpdatingMaterial::prepare(&other, Limits::small()).unwrap();
        let t = Transition::new(&p, binding, 8, &[], &z[1..2], Limits::small()).unwrap();
        let mut rng = FailSecond { draw: 0 };
        assert!(matches!(
            a.update(&p, &wrong, &t, Limits::small(), &mut rng),
            Err(Error::UpdatingPackage)
        ));
        assert_eq!(rng.draw, 0);
        assert_eq!(snapshot(&a), before);
    }
    struct FailSecond {
        draw: usize,
    }
    impl CryptoRng for FailSecond {}
    impl RngCore for FailSecond {
        fn next_u32(&mut self) -> u32 {
            panic!("infallible")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("infallible")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("infallible")
        }
        fn try_fill_bytes(&mut self, b: &mut [u8]) -> Result<(), rand::Error> {
            self.draw += 1;
            if self.draw == 2 {
                return Err(rand::Error::new(std::io::Error::other("test failure")));
            }
            b.fill(0);
            b[0] = 3;
            Ok(())
        }
    }
    #[test]
    fn snapshot_equal_on_second_entropy_draw_pair_cap_and_binding_failures() {
        let p = fixture::package(5, Reduction::Original);
        let u = UpdatingMaterial::prepare(&p, Limits::small()).unwrap();
        let z = fixture::assignment(5, 3, 2);
        let a = anchor(&p, &u, &z);
        let before = snapshot(&a);
        let target = fixture::assignment(5, 4, 3);
        let raw = z
            .iter()
            .zip(&target)
            .enumerate()
            .skip(1)
            .map(|(j, (x, y))| (j, fixture::bytes(&[*y - *x])[0]))
            .collect::<Vec<_>>();
        let t = Transition::new(&p, a.binding(), 8, &raw, &target[1..2], Limits::small()).unwrap();
        assert!(matches!(
            a.update(&p, &u, &t, Limits::small(), &mut FailSecond { draw: 0 }),
            Err(Error::Entropy { draw: 1, .. })
        ));
        assert_eq!(snapshot(&a), before);
        let mut limits = Limits::small();
        limits.max_pair_work = 0;
        assert!(matches!(
            a.update(&p, &u, &t, limits, &mut FailSecond { draw: 0 }),
            Err(Error::Bound("cross pair work"))
        ));
        assert_eq!(snapshot(&a), before);
        let b = anchor(&p, &u, &fixture::assignment(5, 4, 3));
        assert!(matches!(
            b.update(&p, &u, &t, Limits::small(), &mut rand::rngs::OsRng),
            Err(Error::AnchorBinding)
        ));
        assert_eq!(snapshot(&a), before);
        let _ = a
            .update(&p, &u, &t, Limits::small(), &mut rand::rngs::OsRng)
            .unwrap();
        assert_eq!(snapshot(&a), before);
    }
}

#[cfg(test)]
mod import_tests {
    use super::*;
    use crate::{
        import::{audit_legacy_package, read_legacy_anchor, read_legacy_package, ImportLimits},
        test_fixture as fixture, Reduction,
    };
    use ark_bn254::Bn254;
    fn digest(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }
    fn save(path: &std::path::Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    #[test]
    fn matching_trusted_legacy_e2_layout_roundtrips_and_rejects_malformed_counts() {
        let original = fixture::package(5, Reduction::Original);
        let z = fixture::assignment(5, 3, 2);
        let u = UpdatingMaterial::prepare(&original, Limits::small()).unwrap();
        let va = original
            .validate_assignment(&fixture::bytes(&z), &z[1..2])
            .unwrap();
        let core = capture(&original, va, Fr::from(13), Fr::from(19)).unwrap();
        let legacy = dynark::Groth16::<Bn254>::generate_updating_keys(
            &original.0.matrices,
            &original.0.domain,
            &original.0.pk,
        )
        .unwrap();
        assert_eq!(legacy.lagrange_truncated, u.0.lagrange);
        assert_eq!(legacy.w, u.0.weights);
        assert_eq!(legacy.p, u.0.diagonal);
        let cache = dynark::Cache::<Bn254> {
            domain: original.0.domain,
            num_instance: 2,
            r: core.r,
            s: core.s,
            q_a: u.project(&original, &core.a),
            q_b: u.project(&original, &core.b),
            a_g1: core.a_g1.into_affine(),
            b_g1: core.b_g1.into_affine(),
            b_g2: core.b_g2.into_affine(),
            c_g1: core.c_g1.into_affine(),
        };
        let mut ukbytes = Vec::new();
        legacy.serialize_compressed(&mut ukbytes).unwrap();
        let mut cachebytes = Vec::new();
        cache.serialize_compressed(&mut cachebytes).unwrap();
        let rb = fixture::r1cs_bytes(&original.0.matrices);
        let dir = fixture::tempdir();
        let rp = dir.join("circuit.r1cs");
        let up = dir.join("updating-key.bin");
        let cp = dir.join("retained-cache.bin");
        save(&rp, &rb);
        save(&up, &ukbytes);
        save(&cp, &cachebytes);
        let mut d = fixture::descriptor(Reduction::Original);
        d.r1cs_artifact_digest = digest(&rb);
        let expected =
            PublicPackage::inspect_identity(&original.0.matrices, &d, &original.0.pk).unwrap();
        let (p, imported) = read_legacy_package(
            &rp,
            &up,
            d.clone(),
            expected,
            digest(&ukbytes),
            ImportLimits::small(),
        )
        .unwrap();
        let (audited, audited_material) =
            audit_legacy_package(&rp, &up, d.clone(), digest(&ukbytes), ImportLimits::small())
                .unwrap();
        assert_eq!(audited.identity(), p.identity());
        assert_eq!(audited_material.0.lagrange, imported.0.lagrange);
        assert!(matches!(
            audit_legacy_package(&rp, &up, d.clone(), [0; 32], ImportLimits::small()),
            Err(Error::IdentityMismatch)
        ));
        assert_eq!(imported.0.lagrange, u.0.lagrange);
        assert_eq!(imported.0.diagonal, u.0.diagonal);
        assert!(p.shares_storage_with(&p.clone()));
        assert!(imported.shares_storage_with(&imported.clone()));
        let assignment = p
            .validate_assignment(&fixture::bytes(&z), &z[1..2])
            .unwrap();
        let a = read_legacy_anchor(
            &cp,
            &p,
            &imported,
            assignment,
            AnchorBinding::new(&p, [1; 32], [2; 32], 7),
            digest(&cachebytes),
            ImportLimits::small(),
        )
        .unwrap();
        let target = fixture::assignment(5, 4, 1);
        let raw = z
            .iter()
            .zip(&target)
            .enumerate()
            .skip(1)
            .map(|(j, (x, y))| (j, fixture::bytes(&[*y - *x])[0]))
            .collect::<Vec<_>>();
        let t = Transition::new(&p, a.binding(), 8, &raw, &target[1..2], Limits::small()).unwrap();
        let proof = a
            .update(&p, &imported, &t, Limits::small(), &mut rand::rngs::OsRng)
            .unwrap();
        assert!(fixture::verify(&p, &proof.proof, &target[1..2]));
        assert!(matches!(
            read_legacy_package(
                &rp,
                &up,
                d.clone(),
                expected,
                [0; 32],
                ImportLimits::small()
            ),
            Err(Error::IdentityMismatch)
        ));
        let mut invalid = ukbytes.clone();
        invalid[485..493].copy_from_slice(&u64::MAX.to_le_bytes());
        save(&up, &invalid);
        assert!(matches!(
            read_legacy_package(
                &rp,
                &up,
                d.clone(),
                expected,
                digest(&invalid),
                ImportLimits::small()
            ),
            Err(Error::Import(_))
        ));
        let mut invalid = ukbytes.clone();
        invalid[261..293].fill(255);
        save(&up, &invalid);
        assert!(read_legacy_package(
            &rp,
            &up,
            d.clone(),
            expected,
            digest(&invalid),
            ImportLimits::small()
        )
        .is_err());
        let mut invalid = ukbytes;
        invalid.push(0);
        save(&up, &invalid);
        assert!(matches!(
            read_legacy_package(
                &rp,
                &up,
                d,
                expected,
                digest(&invalid),
                ImportLimits::small()
            ),
            Err(Error::Import(_))
        ));
        let mut invalid_cache = cache.clone();
        invalid_cache.b_g1 = original.0.pk.delta_g1;
        let mut bytes = Vec::new();
        invalid_cache.serialize_compressed(&mut bytes).unwrap();
        save(&cp, &bytes);
        let assignment = p
            .validate_assignment(&fixture::bytes(&z), &z[1..2])
            .unwrap();
        assert!(matches!(
            read_legacy_anchor(
                &cp,
                &p,
                &imported,
                assignment,
                AnchorBinding::new(&p, [1; 32], [2; 32], 7),
                digest(&bytes),
                ImportLimits::small()
            ),
            Err(Error::Import("cache witness/randomizer binding"))
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
#[cfg(test)]
#[path = "../tests/private/anchored_parallel.rs"]
mod parallel_tests;
