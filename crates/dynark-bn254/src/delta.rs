use crate::{Error, PackageIdentity, PublicPackage, ValidatedAssignment};
use ark_bn254::Fr;
use ark_ff::Zero;
use ark_serialize::CanonicalDeserialize;
use std::collections::BTreeMap;

/// Explicit operation ceilings. Counts and estimated vector storage are checked before allocation.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_domain: usize,
    pub max_assignment: usize,
    pub max_matrix_entries: usize,
    pub max_delta_entries: usize,
    pub max_pair_work: usize,
    pub max_allocation_bytes: usize,
}
impl Limits {
    pub fn small() -> Self {
        Self {
            max_domain: 1024,
            max_assignment: 1024,
            max_matrix_entries: 16384,
            max_delta_entries: 4096,
            max_pair_work: 65536,
            max_allocation_bytes: 16 * 1024 * 1024,
        }
    }
    pub(crate) fn package(self, p: &PublicPackage) -> Result<(), Error> {
        let s = p.shape();
        let m = &p.0.matrices;
        if s.domain_size > self.max_domain || s.assignment_len > self.max_assignment {
            return Err(Error::Bound("domain/assignment"));
        }
        let entries = m
            .a_num_non_zero
            .checked_add(m.b_num_non_zero)
            .and_then(|x| x.checked_add(m.c_num_non_zero))
            .ok_or(Error::Bound("matrix entries"))?;
        if entries > self.max_matrix_entries {
            return Err(Error::Bound("matrix entries"));
        }
        // Conservative structural ceiling includes FFT/projection scratch, assignment and row vectors.
        let bytes = s
            .domain_size
            .checked_mul(2048)
            .and_then(|x| {
                s.assignment_len
                    .checked_mul(1024)
                    .and_then(|y| x.checked_add(y))
            })
            .and_then(|x| entries.checked_mul(192).and_then(|y| x.checked_add(y)))
            .ok_or(Error::Bound("allocation overflow"))?;
        if bytes > self.max_allocation_bytes {
            return Err(Error::Bound("operation allocation"));
        }
        Ok(())
    }
}

/// Public/audit binding; content commitments do not establish application authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorBinding {
    pub package: PackageIdentity,
    pub domain_size: usize,
    pub credential: [u8; 32],
    pub action: [u8; 32],
    pub generation: u64,
    pub anchor_state: [u8; 32],
}
impl AnchorBinding {
    pub fn new(p: &PublicPackage, credential: [u8; 32], action: [u8; 32], generation: u64) -> Self {
        Self {
            package: p.identity(),
            domain_size: p.shape().domain_size,
            credential,
            action,
            generation,
            anchor_state: [0; 32],
        }
    }
    pub(crate) fn package_check(&self, p: &PublicPackage) -> Result<(), Error> {
        if self.package != p.identity() || self.domain_size != p.shape().domain_size {
            return Err(Error::AnchorBinding);
        }
        Ok(())
    }
}

/// Exact named transition from an immutable base. Delta values use canonical LE field encodings.
/// This mathematical same-action API does not authorize a different application action.
pub struct Transition {
    pub(crate) base: AnchorBinding,
    pub(crate) generation: u64,
    pub(crate) delta: Vec<(usize, Fr)>,
    expected_public: Vec<Fr>,
    limits: Limits,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MatrixTouch {
    pub touched_entries: usize,
    pub touched_rows: usize,
    pub nonzero_rows: usize,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransitionStats {
    pub a: MatrixTouch,
    pub b: MatrixTouch,
    pub c: MatrixTouch,
    pub full_validation_entries: usize,
    pub quadratic_pair_visits: usize,
    pub off_diagonal_weight_terms: usize,
    pub cross_group_scalar_muls: usize,
}
#[derive(Default)]
pub struct RowDeltas {
    pub a: Vec<(usize, Fr)>,
    pub b: Vec<(usize, Fr)>,
    pub c: Vec<(usize, Fr)>,
}
pub struct PreparedTransition {
    pub(crate) target: ValidatedAssignment,
    pub(crate) rows: RowDeltas,
    stats: TransitionStats,
}
impl PreparedTransition {
    pub fn stats(&self) -> TransitionStats {
        self.stats
    }
    pub fn row_deltas(&self) -> &RowDeltas {
        &self.rows
    }
}
impl Transition {
    pub fn new(
        p: &PublicPackage,
        base: AnchorBinding,
        generation: u64,
        raw: &[(usize, [u8; 32])],
        expected_public: &[Fr],
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.package(p)?;
        base.package_check(p)?;
        if generation <= base.generation {
            return Err(Error::Generation);
        }
        if expected_public.len() != p.shape().instance_len - 1 {
            return Err(Error::PublicStatement);
        }
        if raw.len() > limits.max_delta_entries
            || raw
                .len()
                .checked_mul(128)
                .ok_or(Error::Bound("delta allocation"))?
                > limits.max_allocation_bytes
        {
            return Err(Error::Bound("delta entries"));
        }
        // Reject an attempted constant mutation even if two attempts would cancel.
        for (j, b) in raw {
            if *j >= p.shape().assignment_len {
                return Err(Error::DeltaCoordinate);
            }
            if *j == 0
                && Fr::deserialize_compressed(&b[..])
                    .map_err(|_| Error::NonCanonicalField { coordinate: *j })?
                    != Fr::from(0u64)
            {
                return Err(Error::ConstantMutation);
            }
        }
        let mut sums = BTreeMap::<usize, Fr>::new();
        for (j, b) in raw {
            let x = Fr::deserialize_compressed(&b[..])
                .map_err(|_| Error::NonCanonicalField { coordinate: *j })?;
            *sums.entry(*j).or_default() += x;
        }
        let delta = sums.into_iter().filter(|(_, x)| !x.is_zero()).collect();
        Ok(Self {
            base,
            generation,
            delta,
            expected_public: expected_public.to_vec(),
            limits,
        })
    }
    pub fn normalized_count(&self) -> usize {
        self.delta.len()
    }
    pub fn validate_target(
        &self,
        p: &PublicPackage,
        assignment: &ValidatedAssignment,
    ) -> Result<PreparedTransition, Error> {
        self.limits.package(p)?;
        self.base.package_check(p)?;
        if assignment.package != p.identity() {
            return Err(Error::AssignmentPackage);
        }
        let mut values = assignment.values.clone();
        for (j, d) in &self.delta {
            values[*j] += d;
        }
        let target = p.validate_values(values, &self.expected_public)?;
        let gather = |columns: &Vec<Vec<(usize, Fr)>>| {
            let mut accumulated = BTreeMap::<usize, Fr>::new();
            let mut stats = MatrixTouch::default();
            for (j, d) in &self.delta {
                for (i, c) in &columns[*j] {
                    stats.touched_entries += 1;
                    *accumulated.entry(*i).or_default() += *c * *d;
                }
            }
            stats.touched_rows = accumulated.len();
            let out = accumulated
                .into_iter()
                .filter(|(_, x)| !x.is_zero())
                .collect::<Vec<_>>();
            stats.nonzero_rows = out.len();
            (out, stats)
        };
        let (a, sa) = gather(&p.0.columns[0]);
        let (b, sb) = gather(&p.0.columns[1]);
        let (c, sc) = gather(&p.0.columns[2]);
        let m = &p.0.matrices;
        let full_validation_entries = m.a_num_non_zero + m.b_num_non_zero + m.c_num_non_zero;
        let quadratic_pair_visits = a
            .len()
            .checked_mul(b.len())
            .ok_or(Error::Bound("cross pair overflow"))?;
        let diagonal_overlap = a
            .iter()
            .filter(|(i, _)| b.binary_search_by_key(i, |x| x.0).is_ok())
            .count();
        let off_diagonal_weight_terms = quadratic_pair_visits
            .checked_sub(diagonal_overlap)
            .and_then(|x| x.checked_mul(2))
            .ok_or(Error::Bound("cross work overflow"))?;
        let cross_group_scalar_muls = a
            .len()
            .checked_add(b.len())
            .and_then(|x| x.checked_add(diagonal_overlap))
            .ok_or(Error::Bound("cross group work overflow"))?;
        Ok(PreparedTransition {
            target,
            rows: RowDeltas { a, b, c },
            stats: TransitionStats {
                a: sa,
                b: sb,
                c: sc,
                full_validation_entries,
                quadratic_pair_visits,
                off_diagonal_weight_terms,
                cross_group_scalar_muls,
            },
        })
    }
}
