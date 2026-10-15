use crate::{Error, Limits, PublicPackage, UpdatingMaterial};
use ark_bn254::{Fr, G1Projective as G1};
use ark_ff::AdditiveGroup;
use ark_poly::EvaluationDomain;
use rayon::prelude::*;
use std::{mem::size_of, sync::Arc};

pub(crate) type Map = Arc<Vec<(usize, Fr)>>;

/// Shared public tables. Preparation is paid once; clones share all allocations.
#[derive(Clone)]
pub struct ReconstructionMaterial(pub(crate) Arc<Tables>);
pub(crate) struct Tables {
    pub(crate) package: crate::PackageIdentity,
    pub(crate) uk: UpdatingMaterial,
    pub(crate) roots: Vec<Fr>,
    forward: Vec<Fr>,
    reverse: Vec<Fr>,
    inverse_n: Fr,
    pub(crate) public_bytes: usize,
    public_scan_entries: usize,
}
impl ReconstructionMaterial {
    pub fn prepare(
        p: &PublicPackage,
        uk: &UpdatingMaterial,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.package(p)?;
        uk.check(p)?;
        let n = p.shape().domain_size;
        let bytes = n
            .checked_mul(3 * size_of::<Fr>())
            .ok_or(Error::Bound("public tables"))?;
        if bytes > limits.max_allocation_bytes {
            return Err(Error::Bound("public tables"));
        }
        let mut roots = reserved(n)?;
        roots.extend(p.0.domain.elements());
        let mut forward = reserved(n)?;
        forward.extend_from_slice(&uk.0.weights);
        p.0.domain.fft_in_place(&mut forward);
        let mut reverse = reserved(n)?;
        reverse.extend((0..n).map(|i| uk.0.weights[(n - i) % n]));
        p.0.domain.fft_in_place(&mut reverse);
        let tablebytes = roots
            .capacity()
            .checked_add(forward.capacity())
            .and_then(|x| x.checked_add(reverse.capacity()))
            .and_then(|x| x.checked_mul(size_of::<Fr>()))
            .ok_or(Error::Bound("public table capacities"))?;
        let (basebytes, public_scan_entries) = package_bytes(p, uk)?;
        if tablebytes > limits.max_allocation_bytes {
            return Err(Error::Bound("actual public table capacities"));
        }
        let public_bytes = basebytes
            .checked_add(tablebytes)
            .ok_or(Error::Bound("shared public bytes"))?;
        Ok(Self(Arc::new(Tables {
            package: p.identity(),
            uk: uk.clone(),
            roots,
            forward,
            reverse,
            inverse_n: p.0.domain.size_inv(),
            public_bytes,
            public_scan_entries,
        })))
    }
    pub fn shares_storage_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub fn structural_bytes(&self) -> usize {
        (self.0.roots.capacity() + self.0.forward.capacity() + self.0.reverse.capacity())
            * size_of::<Fr>()
    }
    pub fn preparation_field_elements(&self) -> usize {
        3 * self.0.roots.len()
    }
    pub fn preparation_fft_butterflies(&self) -> usize {
        self.0.roots.len() * self.0.roots.len().ilog2() as usize
    }
    pub fn preparation_structural_scan_entries(&self) -> usize {
        self.0.public_scan_entries
    }
    pub(crate) fn check(&self, p: &PublicPackage) -> Result<(), Error> {
        let n = p.shape().domain_size;
        if self.0.package != p.identity()
            || self.0.roots.len() != n
            || self.0.forward.len() != n
            || self.0.reverse.len() != n
        {
            return Err(Error::UpdatingPackage);
        }
        self.0.uk.check(p)
    }
}

#[cfg(test)]
impl Tables {
    // Arithmetic-only fixtures: these unused key vectors are not proof/preparation evidence.
    pub(crate) fn parallel_test(n: usize) -> Self {
        use ark_poly::GeneralEvaluationDomain;
        let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();
        assert_eq!(domain.size(), n);
        let package = crate::PackageIdentity {
            matrix_digest: [0; 32],
            circuit_digest: [0; 32],
            proving_key_digest: [0; 32],
            verifying_key_digest: [0; 32],
            package_digest: [0; 32],
        };
        Self {
            package,
            uk: UpdatingMaterial(Arc::new(crate::anchored::MaterialInner {
                package,
                lagrange: vec![G1::ZERO; n],
                diagonal: vec![G1::ZERO; n],
                weights: vec![Fr::ZERO; n],
            })),
            roots: domain.elements().collect(),
            forward: vec![Fr::ZERO; n],
            reverse: vec![Fr::ZERO; n],
            inverse_n: domain.size_inv(),
            public_bytes: n * (2 * size_of::<G1>() + 4 * size_of::<Fr>()),
            public_scan_entries: 0,
        }
    }
}
fn package_bytes(p: &PublicPackage, uk: &UpdatingMaterial) -> Result<(usize, usize), Error> {
    let mut bytes = 0usize;
    let mut scan = 0usize;
    let pk = &p.0.pk;
    let mut add = |count: usize, size: usize| -> Result<(), Error> {
        bytes = bytes
            .checked_add(
                count
                    .checked_mul(size)
                    .ok_or(Error::Bound("public capacity bytes"))?,
            )
            .ok_or(Error::Bound("public capacity bytes"))?;
        Ok(())
    };
    for count in [uk.0.lagrange.capacity(), uk.0.diagonal.capacity()] {
        add(count, size_of::<G1>())?;
    }
    add(uk.0.weights.capacity(), size_of::<Fr>())?;
    for count in [
        pk.u_g1.capacity(),
        pk.v_g1.capacity(),
        pk.t_p_g1.capacity(),
        pk.tau_powers_g1.capacity(),
        pk.vk.t_v_g1.capacity(),
    ] {
        add(count, size_of::<ark_bn254::G1Affine>())?;
    }
    add(pk.v_g2.capacity(), size_of::<ark_bn254::G2Affine>())?;
    for matrix in [&p.0.matrices.a, &p.0.matrices.b, &p.0.matrices.c] {
        add(matrix.capacity(), size_of::<Vec<(Fr, usize)>>())?;
        for row in matrix {
            add(row.capacity(), size_of::<(Fr, usize)>())?;
            scan = scan
                .checked_add(1)
                .ok_or(Error::Bound("public scan count"))?;
        }
    }
    for columns in &p.0.columns {
        add(columns.capacity(), size_of::<Vec<(usize, Fr)>>())?;
        for col in columns {
            add(col.capacity(), size_of::<(usize, Fr)>())?;
            scan = scan
                .checked_add(1)
                .ok_or(Error::Bound("public scan count"))?;
        }
    }
    Ok((bytes, scan))
}
pub(crate) fn reserved<T>(n: usize) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| Error::Bound("allocation reservation"))?;
    Ok(v)
}
pub(crate) fn work(n: usize) -> Result<usize, Error> {
    if n < 2 || !n.is_power_of_two() {
        return Err(Error::Shape("reconstruction domain"));
    }
    n.checked_mul(19)
        .and_then(|x| {
            n.checked_mul(4 * n.ilog2() as usize)
                .and_then(|y| x.checked_add(y))
        })
        .and_then(|x| x.checked_add(1))
        .ok_or(Error::Bound("reconstruction work"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconstructionPhase {
    InitialReadyAlias,
    Materialize,
    Prepare,
    Forward,
    Pointwise,
    Inverse,
    Scale,
    Integrate,
    Ready,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkEvent {
    Action(ReconstructionPhase),
    Write {
        phase: ReconstructionPhase,
        ordinal: u8,
    },
    Promotion,
    Header,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Roles {
    pub(crate) active_g: [usize; 2],
    pub(crate) active_f: [usize; 2],
    pub(crate) build_g: [usize; 2],
    pub(crate) build_f: [usize; 2],
}
impl Default for Roles {
    fn default() -> Self {
        Self {
            active_g: [0, 1],
            active_f: [0, 1],
            build_g: [2, 3],
            build_f: [2, 3],
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Cursor {
    pub(crate) phase: ReconstructionPhase,
    pub(crate) done: usize,
    pub(crate) group_scalar_calls: u64,
    pub(crate) field_mul_calls: u64,
    stream: usize,
    index: usize,
    stage: usize,
    overlay: [usize; 2],
}
impl Cursor {
    pub(crate) fn alias(w: usize) -> Self {
        Self {
            phase: ReconstructionPhase::InitialReadyAlias,
            done: w,
            group_scalar_calls: 0,
            field_mul_calls: 0,
            stream: 0,
            index: 0,
            stage: 0,
            overlay: [0, 0],
        }
    }
    pub(crate) fn frozen() -> Self {
        Self {
            phase: ReconstructionPhase::Materialize,
            done: 1,
            group_scalar_calls: 0,
            field_mul_calls: 0,
            stream: 0,
            index: 0,
            stage: 0,
            overlay: [0, 0],
        }
    }
    pub(crate) fn ready(&self) -> bool {
        matches!(
            self.phase,
            ReconstructionPhase::Ready | ReconstructionPhase::InitialReadyAlias
        )
    }
    fn next_phase(&mut self, phase: ReconstructionPhase) {
        self.phase = phase;
        self.stream = 0;
        self.index = 0;
        self.stage = 0;
    }
}
#[derive(Clone)]
pub(crate) struct Builder {
    pub(crate) generation: u64,
    pub(crate) distance: u64,
    pub(crate) token: [u8; 32],
    pub(crate) source: [usize; 2],
    pub(crate) overlays: [Map; 2],
    pub(crate) pending: [Map; 2],
    pub(crate) cursor: Cursor,
}

pub(crate) struct Pool {
    pub(crate) g: [Vec<G1>; 4],
    pub(crate) f: [Vec<Fr>; 6],
    pub(crate) n: usize,
}
impl Pool {
    pub(crate) fn bytes(&self) -> usize {
        self.g
            .iter()
            .map(|v| (v.capacity(), size_of::<G1>()))
            .chain(self.f.iter().map(|v| (v.capacity(), size_of::<Fr>())))
            .try_fold(0usize, |sum, (n, size)| {
                sum.checked_add(n.checked_mul(size)?)
            })
            .unwrap_or(usize::MAX)
    }
    pub(crate) fn validate(&self, r: &Roles, b: &Builder) -> Result<(), Error> {
        let mut g = [false; 4];
        let mut f = [false; 4];
        for slot in r.active_g.into_iter().chain(r.build_g) {
            if slot >= 4 || g[slot] {
                return Err(Error::Bound("physical group roles"));
            }
            g[slot] = true;
        }
        for slot in r.active_f.into_iter().chain(r.build_f) {
            if slot >= 4 || f[slot] {
                return Err(Error::Bound("physical field roles"));
            }
            f[slot] = true;
        }
        if b.source != r.active_f
            || self.g.iter().any(|v| v.len() != self.n)
            || self.f.iter().any(|v| v.len() != self.n)
        {
            return Err(Error::Bound("physical source/length"));
        }
        Ok(())
    }
}

/// Original values are keyed by physical cells, so role recycling cannot lose preimages.
pub(crate) struct Journal {
    pub(crate) marks: Vec<u64>,
    gv: Vec<G1>,
    gi: Vec<usize>,
    fv: Vec<Fr>,
    fi: Vec<usize>,
    pub(crate) saturated: bool,
    pub(crate) group_logs: usize,
    pub(crate) field_logs: usize,
}
impl Journal {
    pub(crate) fn empty(marks: Vec<u64>) -> Self {
        Self {
            marks,
            gv: Vec::new(),
            gi: Vec::new(),
            fv: Vec::new(),
            fi: Vec::new(),
            saturated: false,
            group_logs: 0,
            field_logs: 0,
        }
    }
    pub(crate) fn bytes(&self) -> usize {
        [
            (self.marks.capacity(), 8),
            (self.gv.capacity(), size_of::<G1>()),
            (self.gi.capacity(), size_of::<usize>()),
            (self.fv.capacity(), size_of::<Fr>()),
            (self.fi.capacity(), size_of::<usize>()),
        ]
        .into_iter()
        .try_fold(0usize, |sum, (n, size)| {
            sum.checked_add(n.checked_mul(size)?)
        })
        .unwrap_or(usize::MAX)
    }
    pub(crate) fn planned_bytes(&self, n: usize, k: usize) -> Result<usize, Error> {
        let twice = k.checked_mul(2).ok_or(Error::Bound("journal actions"))?;
        let ug = n
            .checked_mul(4)
            .ok_or(Error::Bound("group slots"))?
            .min(twice);
        let uf = n
            .checked_mul(6)
            .ok_or(Error::Bound("field slots"))?
            .min(twice);
        let mut bytes = 0usize;
        for (count, size) in [
            (self.gv.capacity().max(ug), size_of::<G1>()),
            (self.gi.capacity().max(ug), size_of::<usize>()),
            (self.fv.capacity().max(uf), size_of::<Fr>()),
            (self.fi.capacity().max(uf), size_of::<usize>()),
            (self.marks.capacity(), 8),
        ] {
            bytes = bytes
                .checked_add(
                    count
                        .checked_mul(size)
                        .ok_or(Error::Bound("journal bytes"))?,
                )
                .ok_or(Error::Bound("journal bytes"))?;
        }
        Ok(bytes)
    }
    pub(crate) fn reserve(&mut self, n: usize, k: usize, cap: usize) -> Result<(), Error> {
        if !self.gi.is_empty() || !self.fi.is_empty() {
            return Err(Error::Busy);
        }
        if self.planned_bytes(n, k)? > cap {
            return Err(Error::Bound("journal bytes"));
        }
        let twice = k.checked_mul(2).ok_or(Error::Bound("journal actions"))?;
        let ug = n
            .checked_mul(4)
            .ok_or(Error::Bound("group slots"))?
            .min(twice);
        let uf = n
            .checked_mul(6)
            .ok_or(Error::Bound("field slots"))?
            .min(twice);
        // Reserve replacements without changing retained storage on any failed reservation.
        let gv = if self.gv.capacity() < ug {
            Some(reserved::<G1>(ug)?)
        } else {
            None
        };
        let gi = if self.gi.capacity() < ug {
            Some(reserved::<usize>(ug)?)
        } else {
            None
        };
        let fv = if self.fv.capacity() < uf {
            Some(reserved::<Fr>(uf)?)
        } else {
            None
        };
        let fi = if self.fi.capacity() < uf {
            Some(reserved::<usize>(uf)?)
        } else {
            None
        };
        let bytes = self
            .marks
            .capacity()
            .checked_mul(8)
            .and_then(|x| {
                gv.as_ref()
                    .unwrap_or(&self.gv)
                    .capacity()
                    .checked_mul(size_of::<G1>())
                    .and_then(|y| x.checked_add(y))
            })
            .and_then(|x| {
                gi.as_ref()
                    .unwrap_or(&self.gi)
                    .capacity()
                    .checked_mul(size_of::<usize>())
                    .and_then(|y| x.checked_add(y))
            })
            .and_then(|x| {
                fv.as_ref()
                    .unwrap_or(&self.fv)
                    .capacity()
                    .checked_mul(size_of::<Fr>())
                    .and_then(|y| x.checked_add(y))
            })
            .and_then(|x| {
                fi.as_ref()
                    .unwrap_or(&self.fi)
                    .capacity()
                    .checked_mul(size_of::<usize>())
                    .and_then(|y| x.checked_add(y))
            })
            .ok_or(Error::Bound("actual journal capacity"))?;
        if bytes > cap {
            return Err(Error::Bound("actual journal capacity"));
        }
        if let Some(v) = gv {
            self.gv = v;
        }
        if let Some(v) = gi {
            self.gi = v;
        }
        if let Some(v) = fv {
            self.fv = v;
        }
        if let Some(v) = fi {
            self.fi = v;
        }
        Ok(())
    }
    pub(crate) fn reservation_peak_bytes(&self, n: usize, k: usize) -> Result<usize, Error> {
        let twice = k.checked_mul(2).ok_or(Error::Bound("journal actions"))?;
        let ug = n
            .checked_mul(4)
            .ok_or(Error::Bound("group slots"))?
            .min(twice);
        let uf = n
            .checked_mul(6)
            .ok_or(Error::Bound("field slots"))?
            .min(twice);
        let mut bytes = self.planned_bytes(n, k)?;
        for (cap, want, size) in [
            (self.gv.capacity(), ug, size_of::<G1>()),
            (self.gi.capacity(), ug, size_of::<usize>()),
            (self.fv.capacity(), uf, size_of::<Fr>()),
            (self.fi.capacity(), uf, size_of::<usize>()),
        ] {
            if cap < want {
                bytes = bytes
                    .checked_add(
                        cap.checked_mul(size)
                            .ok_or(Error::Bound("journal replacement peak"))?,
                    )
                    .ok_or(Error::Bound("journal replacement peak"))?;
            }
        }
        Ok(bytes)
    }
    fn marked(&self, key: usize) -> Result<bool, Error> {
        self.marks
            .get(key / 64)
            .map(|x| x & (1u64 << (key % 64)) != 0)
            .ok_or(Error::Bound("journal mark index"))
    }
    fn mark(&mut self, key: usize) {
        self.marks[key / 64] |= 1u64 << (key % 64);
    }
    fn group(&mut self, p: &Pool, slot: usize, i: usize) -> Result<(), Error> {
        if slot >= 4 || i >= p.n {
            return Err(Error::Bound("group cell"));
        }
        let key = slot * p.n + i;
        if !self.marked(key)? {
            if self.gv.len() == self.gv.capacity() || self.gi.len() == self.gi.capacity() {
                return Err(Error::Bound("group journal capacity"));
            }
            self.gv.push(p.g[slot][i]);
            self.gi.push(key);
            self.mark(key);
            if let Some(value) = self.group_logs.checked_add(1) {
                self.group_logs = value;
            } else {
                self.saturated = true;
            }
        }
        Ok(())
    }
    fn field(&mut self, p: &Pool, slot: usize, i: usize) -> Result<(), Error> {
        if slot >= 6 || i >= p.n {
            return Err(Error::Bound("field cell"));
        }
        let key = slot * p.n + i;
        let mark = 4 * p.n + key;
        if !self.marked(mark)? {
            if self.fv.len() == self.fv.capacity() || self.fi.len() == self.fi.capacity() {
                return Err(Error::Bound("field journal capacity"));
            }
            self.fv.push(p.f[slot][i]);
            self.fi.push(key);
            self.mark(mark);
            if let Some(value) = self.field_logs.checked_add(1) {
                self.field_logs = value;
            } else {
                self.saturated = true;
            }
        }
        Ok(())
    }
    pub(crate) fn finish(&mut self, p: &mut Pool, rollback: bool) -> usize {
        let count = self.gi.len() + self.fi.len();
        for (&key, &value) in self.gi.iter().zip(&self.gv) {
            if rollback {
                p.g[key / p.n][key % p.n] = value;
            }
            self.marks[key / 64] &= !(1u64 << (key % 64));
        }
        for (&key, &value) in self.fi.iter().zip(&self.fv) {
            if rollback {
                p.f[key / p.n][key % p.n] = value;
            }
            let mark = 4 * p.n + key;
            self.marks[mark / 64] &= !(1u64 << (mark % 64));
        }
        self.gi.clear();
        self.gv.clear();
        self.fi.clear();
        self.fv.clear();
        count
    }
    #[cfg(test)]
    pub(crate) fn lengths(&self) -> (usize, usize) {
        (self.gi.len(), self.fi.len())
    }
    #[cfg(test)]
    pub(crate) fn parallel_test_one_group_cell(n: usize) -> Self {
        let mut journal = Self::empty(vec![0; (10 * n).div_ceil(64)]);
        journal.gv = reserved(1).unwrap();
        journal.gi = reserved(1).unwrap();
        assert_eq!(journal.gv.capacity(), 1);
        assert_eq!(journal.gi.capacity(), 1);
        journal
    }
}
fn observe(observer: &mut impl FnMut(WorkEvent) -> bool, event: WorkEvent) -> Result<(), Error> {
    if observer(event) {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
fn group_writes(
    p: &mut Pool,
    j: &mut Journal,
    phase: ReconstructionPhase,
    cells: &[(usize, usize, G1)],
    o: &mut impl FnMut(WorkEvent) -> bool,
) -> Result<(), Error> {
    for &(slot, i, _) in cells {
        j.group(p, slot, i)?;
    }
    for (ordinal, &(slot, i, value)) in cells.iter().enumerate() {
        p.g[slot][i] = value;
        observe(
            o,
            WorkEvent::Write {
                phase,
                ordinal: ordinal as u8,
            },
        )?;
    }
    Ok(())
}
fn field_writes(
    p: &mut Pool,
    j: &mut Journal,
    phase: ReconstructionPhase,
    cells: &[(usize, usize, Fr)],
    o: &mut impl FnMut(WorkEvent) -> bool,
) -> Result<(), Error> {
    for &(slot, i, _) in cells {
        j.field(p, slot, i)?;
    }
    for (ordinal, &(slot, i, value)) in cells.iter().enumerate() {
        p.f[slot][i] = value;
        observe(
            o,
            WorkEvent::Write {
                phase,
                ordinal: ordinal as u8,
            },
        )?;
    }
    Ok(())
}

pub(crate) const GROUP_BATCH_LEN: usize = 8192;

#[cfg(test)]
std::thread_local! {
    static JOINED_GROUP_BATCHES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
pub(crate) fn parallel_test_joined_batches() -> u64 {
    JOINED_GROUP_BATCHES.with(std::cell::Cell::get)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GroupBatchPlan {
    phase: ReconstructionPhase,
    n: usize,
    slot: usize,
    stream: usize,
    stage: usize,
    start: usize,
    len: usize,
}

#[derive(Default, Debug)]
pub(crate) struct BatchWork {
    pub(crate) attempted_actions: usize,
    pub(crate) requested_group_calls: u64,
    pub(crate) published_actions: usize,
    pub(crate) scratch_capacity_bytes: usize,
}

pub(crate) fn group_batch_plan(
    p: &Pool,
    r: &Roles,
    b: &Builder,
    t: &Tables,
    budget: usize,
    len: usize,
) -> Result<Option<GroupBatchPlan>, Error> {
    if len == 0 || budget < len {
        return Ok(None);
    }
    let c = &b.cursor;
    let tail = match c.phase {
        ReconstructionPhase::Forward | ReconstructionPhase::Inverse
            if c.stage > 0 && c.stream < 2 =>
        {
            p.n / 2
        }
        ReconstructionPhase::Scale if c.stream < 2 => p.n,
        _ => return Ok(None),
    };
    p.validate(r, b)?;
    validate_cursor(c, p.n, &b.overlays)?;
    if t.roots.len() != p.n {
        return Err(Error::Bound("batch root table length"));
    }
    if c.index.checked_add(len).is_none_or(|end| end > tail) {
        return Ok(None);
    }
    Ok(Some(GroupBatchPlan {
        phase: c.phase,
        n: p.n,
        slot: r.build_g[c.stream],
        stream: c.stream,
        stage: c.stage,
        start: c.index,
        len,
    }))
}

pub(crate) fn group_batch(
    p: &mut Pool,
    j: &mut Journal,
    r: &Roles,
    b: &mut Builder,
    t: &Tables,
    plan: GroupBatchPlan,
    scratch_room: usize,
    o: &mut impl FnMut(WorkEvent) -> bool,
    work: &mut BatchWork,
) -> Result<bool, Error> {
    *work = BatchWork::default();
    if group_batch_plan(p, r, b, t, plan.len, plan.len)? != Some(plan) {
        return Err(Error::Bound("batch plan binding"));
    }
    let requested = plan
        .len
        .checked_mul(size_of::<[G1; 2]>())
        .ok_or(Error::Bound("batch scratch bytes"))?;
    if requested > scratch_room {
        return Ok(false);
    }
    let mut values = Vec::new();
    if values.try_reserve_exact(plan.len).is_err() {
        return Ok(false);
    }
    let actual = values
        .capacity()
        .checked_mul(size_of::<[G1; 2]>())
        .ok_or(Error::Bound("actual batch scratch bytes"))?;
    if actual > scratch_room {
        return Ok(false);
    }
    values.resize(plan.len, [G1::ZERO; 2]);
    values.par_iter_mut().enumerate().for_each(|(offset, out)| {
        let i = plan.start + offset;
        if plan.phase == ReconstructionPhase::Scale {
            *out = [p.g[plan.slot][i] * t.inverse_n, G1::ZERO];
        } else {
            let len = 1usize << plan.stage;
            let half = len / 2;
            let jj = i % half;
            let left = (i / half) * len + jj;
            let exponent = jj * (plan.n / len);
            let root = t.roots[if plan.phase == ReconstructionPhase::Inverse {
                (plan.n - exponent) % plan.n
            } else {
                exponent
            }];
            let u = p.g[plan.slot][left];
            let v = p.g[plan.slot][left + half] * root;
            *out = [u + v, u - v];
        }
    });
    // These requested calls have joined even if publication subsequently fails.
    work.attempted_actions = plan.len;
    work.requested_group_calls = plan.len as u64;
    work.scratch_capacity_bytes = actual;
    #[cfg(test)]
    JOINED_GROUP_BATCHES.with(|count| count.set(count.get().checked_add(1).unwrap()));
    for (offset, value) in values.iter().enumerate() {
        let i = plan.start + offset;
        let next_done = b
            .cursor
            .done
            .checked_add(1)
            .ok_or(Error::Bound("cursor work"))?;
        let next_groups = b
            .cursor
            .group_scalar_calls
            .checked_add(1)
            .ok_or(Error::Bound("cursor group calls"))?;
        observe(o, WorkEvent::Action(plan.phase))?;
        if plan.phase == ReconstructionPhase::Scale {
            group_writes(p, j, plan.phase, &[(plan.slot, i, value[0])], o)?;
        } else {
            let len = 1usize << plan.stage;
            let half = len / 2;
            let left = (i / half) * len + i % half;
            group_writes(
                p,
                j,
                plan.phase,
                &[
                    (plan.slot, left, value[0]),
                    (plan.slot, left + half, value[1]),
                ],
                o,
            )?;
        }
        let c = &mut b.cursor;
        c.done = next_done;
        c.group_scalar_calls = next_groups;
        c.index += 1;
        if plan.phase == ReconstructionPhase::Scale {
            if c.index == plan.n {
                c.index = 0;
                c.stream += 1;
                if c.stream == 4 {
                    c.next_phase(ReconstructionPhase::Integrate);
                }
            }
        } else if c.index == plan.n / 2 {
            c.index = 0;
            c.stage += 1;
            if c.stage > plan.n.ilog2() as usize {
                c.stage = 0;
                c.stream += 1;
                if c.stream == 4 {
                    c.next_phase(if plan.phase == ReconstructionPhase::Inverse {
                        ReconstructionPhase::Scale
                    } else {
                        ReconstructionPhase::Pointwise
                    });
                }
            }
        }
        work.published_actions += 1;
    }
    drop(values);
    Ok(true)
}
/// One action is exactly one reviewed joint row, stream element, visit or butterfly.
pub(crate) fn step(
    p: &mut Pool,
    j: &mut Journal,
    r: &Roles,
    b: &mut Builder,
    t: &Tables,
    o: &mut impl FnMut(WorkEvent) -> bool,
) -> Result<(), Error> {
    p.validate(r, b)?;
    validate_cursor(&b.cursor, p.n, &b.overlays)?;
    if b.cursor.ready() {
        return Ok(());
    }
    let n = p.n;
    let c = &mut b.cursor;
    let phase = c.phase;
    let i = c.index;
    observe(o, WorkEvent::Action(phase))?;
    match phase {
        ReconstructionPhase::Materialize => {
            let mut values = [Fr::ZERO; 2];
            for side in 0..2 {
                values[side] = p.f[b.source[side]][i];
                if let Some(&(row, value)) = b.overlays[side].get(c.overlay[side]) {
                    if row < i || row >= n {
                        return Err(Error::Bound("snapshot overlay cursor"));
                    }
                    if row == i {
                        values[side] += value;
                        c.overlay[side] += 1;
                    }
                }
            }
            field_writes(
                p,
                j,
                phase,
                &[(r.build_f[0], i, values[0]), (r.build_f[1], i, values[1])],
                o,
            )?;
            c.index += 1;
            if c.index == n {
                if c.overlay[0] != b.overlays[0].len() || c.overlay[1] != b.overlays[1].len() {
                    return Err(Error::Bound("snapshot overlay tail"));
                }
                c.next_phase(ReconstructionPhase::Prepare);
            }
        }
        ReconstructionPhase::Prepare => {
            let a = p.f[r.build_f[0]][i];
            let bb = p.f[r.build_f[1]][i];
            // All four preimages precede the first store, including the other value kind.
            j.group(p, r.build_g[0], i)?;
            j.group(p, r.build_g[1], i)?;
            j.field(p, 4, i)?;
            j.field(p, 5, i)?;
            c.group_scalar_calls += 2;
            group_writes(
                p,
                j,
                phase,
                &[
                    (r.build_g[0], i, t.uk.0.lagrange[i] * a),
                    (r.build_g[1], i, t.uk.0.lagrange[i] * bb),
                ],
                o,
            )?;
            field_writes(p, j, phase, &[(4, i, a), (5, i, bb)], o)?;
            c.index += 1;
            if c.index == n {
                c.next_phase(ReconstructionPhase::Forward);
            }
        }
        ReconstructionPhase::Forward | ReconstructionPhase::Inverse => {
            let inverse = phase == ReconstructionPhase::Inverse;
            let group = c.stream < 2;
            let slot = if group {
                r.build_g[c.stream]
            } else {
                c.stream + 2
            };
            if c.stage == 0 {
                let reverse = i.reverse_bits() >> (usize::BITS - n.ilog2());
                if i < reverse {
                    if group {
                        group_writes(
                            p,
                            j,
                            phase,
                            &[(slot, i, p.g[slot][reverse]), (slot, reverse, p.g[slot][i])],
                            o,
                        )?;
                    } else {
                        field_writes(
                            p,
                            j,
                            phase,
                            &[(slot, i, p.f[slot][reverse]), (slot, reverse, p.f[slot][i])],
                            o,
                        )?;
                    }
                }
                c.index += 1;
                if c.index == n {
                    c.index = 0;
                    c.stage = 1;
                }
            } else {
                let len = 1usize << c.stage;
                let half = len / 2;
                let base = (i / half) * len;
                let jj = i % half;
                let left = base + jj;
                let right = left + half;
                let exponent = jj * (n / len);
                let root = t.roots[if inverse {
                    (n - exponent) % n
                } else {
                    exponent
                }];
                if group {
                    let u = p.g[slot][left];
                    let v = p.g[slot][right] * root;
                    c.group_scalar_calls += 1;
                    group_writes(p, j, phase, &[(slot, left, u + v), (slot, right, u - v)], o)?;
                } else {
                    let u = p.f[slot][left];
                    let v = p.f[slot][right] * root;
                    c.field_mul_calls += 1;
                    field_writes(p, j, phase, &[(slot, left, u + v), (slot, right, u - v)], o)?;
                }
                c.index += 1;
                if c.index == n / 2 {
                    c.index = 0;
                    c.stage += 1;
                    if c.stage > n.ilog2() as usize {
                        c.stage = 0;
                        c.stream += 1;
                        if c.stream == 4 {
                            c.next_phase(if inverse {
                                ReconstructionPhase::Scale
                            } else {
                                ReconstructionPhase::Pointwise
                            });
                        }
                    }
                }
            }
        }
        ReconstructionPhase::Pointwise | ReconstructionPhase::Scale => {
            let group = c.stream < 2;
            let slot = if group {
                r.build_g[c.stream]
            } else {
                c.stream + 2
            };
            let scalar = if phase == ReconstructionPhase::Scale {
                t.inverse_n
            } else if group {
                t.forward[i]
            } else {
                t.reverse[i]
            };
            if group {
                c.group_scalar_calls += 1;
                group_writes(p, j, phase, &[(slot, i, p.g[slot][i] * scalar)], o)?;
            } else {
                c.field_mul_calls += 1;
                field_writes(p, j, phase, &[(slot, i, p.f[slot][i] * scalar)], o)?;
            }
            c.index += 1;
            if c.index == n {
                c.index = 0;
                c.stream += 1;
                if c.stream == 4 {
                    c.next_phase(if phase == ReconstructionPhase::Scale {
                        ReconstructionPhase::Integrate
                    } else {
                        ReconstructionPhase::Inverse
                    });
                }
            }
        }
        ReconstructionPhase::Integrate => {
            let a = p.g[r.build_g[0]][i]
                + t.uk.0.lagrange[i] * p.f[4][i]
                + t.uk.0.diagonal[i] * p.f[r.build_f[0]][i];
            let bb = p.g[r.build_g[1]][i]
                + t.uk.0.lagrange[i] * p.f[5][i]
                + t.uk.0.diagonal[i] * p.f[r.build_f[1]][i];
            c.group_scalar_calls += 4;
            group_writes(
                p,
                j,
                phase,
                &[(r.build_g[0], i, a), (r.build_g[1], i, bb)],
                o,
            )?;
            c.index += 1;
            if c.index == n {
                c.next_phase(ReconstructionPhase::Ready);
            }
        }
        ReconstructionPhase::InitialReadyAlias | ReconstructionPhase::Ready => return Ok(()),
    }
    c.done = c.done.checked_add(1).ok_or(Error::Bound("cursor work"))?;
    Ok(())
}

pub(crate) fn validate_cursor(c: &Cursor, n: usize, maps: &[Map; 2]) -> Result<(), Error> {
    let neighbors = std::array::from_fn(|side| {
        let i = c.overlay[side];
        [
            i.checked_sub(1)
                .and_then(|j| maps[side].get(j))
                .map(|x| x.0),
            maps[side].get(i).map(|x| x.0),
        ]
    });
    validate_cursor_metadata(c, n, [maps[0].len(), maps[1].len()], neighbors)
}
pub(crate) fn validate_cursor_metadata(
    c: &Cursor,
    n: usize,
    lengths: [usize; 2],
    neighbors: [[Option<usize>; 2]; 2],
) -> Result<(), Error> {
    let w = work(n)?;
    let k = n.ilog2() as usize;
    if c.done > w || c.overlay[0] > lengths[0] || c.overlay[1] > lengths[1] {
        return Err(Error::Bound("reconstruction cursor"));
    }
    let transform = n
        .checked_add(n.checked_mul(k).ok_or(Error::Bound("cursor work"))? / 2)
        .ok_or(Error::Bound("cursor work"))?;
    let forward = 1 + 2 * n;
    let pointwise = forward + 4 * transform;
    let inverse = pointwise + 4 * n;
    let scale = inverse + 4 * transform;
    let integrate = scale + 4 * n;
    let expected = match c.phase {
        ReconstructionPhase::Materialize
        | ReconstructionPhase::Prepare
        | ReconstructionPhase::Integrate => {
            if c.index >= n || c.stream != 0 || c.stage != 0 {
                return Err(Error::Bound("row cursor"));
            }
            (match c.phase {
                ReconstructionPhase::Materialize => 1,
                ReconstructionPhase::Prepare => 1 + n,
                _ => integrate,
            }) + c.index
        }
        ReconstructionPhase::Pointwise | ReconstructionPhase::Scale => {
            if c.index >= n || c.stream >= 4 || c.stage != 0 {
                return Err(Error::Bound("element cursor"));
            }
            (if c.phase == ReconstructionPhase::Scale {
                scale
            } else {
                pointwise
            }) + c.stream * n
                + c.index
        }
        ReconstructionPhase::Forward | ReconstructionPhase::Inverse => {
            if c.stream >= 4 || c.stage > k || c.index >= if c.stage == 0 { n } else { n / 2 } {
                return Err(Error::Bound("FFT cursor"));
            }
            (if c.phase == ReconstructionPhase::Forward {
                forward
            } else {
                inverse
            }) + c.stream * transform
                + if c.stage == 0 {
                    c.index
                } else {
                    n + (c.stage - 1) * (n / 2) + c.index
                }
        }
        ReconstructionPhase::InitialReadyAlias | ReconstructionPhase::Ready => {
            if c.index != 0 || c.stream != 0 || c.stage != 0 {
                return Err(Error::Bound("ready cursor"));
            }
            w
        }
    };
    if expected != c.done {
        return Err(Error::Bound("cursor action count"));
    }
    for side in 0..2 {
        let consumed = c.overlay[side];
        if c.phase == ReconstructionPhase::InitialReadyAlias {
            if lengths[side] != 0 || consumed != 0 {
                return Err(Error::Bound("alias overlay"));
            }
        } else if c.phase == ReconstructionPhase::Materialize {
            if consumed > 0 && neighbors[side][0].is_some_and(|row| row >= c.index)
                || consumed < lengths[side] && neighbors[side][1].is_some_and(|row| row < c.index)
            {
                return Err(Error::Bound("overlay cursor prefix"));
            }
        } else if consumed != lengths[side] {
            return Err(Error::Bound("unconsumed overlay"));
        }
    }
    // work(n) bounds these intermediate products. Count only actual scalar calls,
    // excluding the bit-reversal stage, and validate before any mutation.
    let nk = n * k;
    let butterflies = nk / 2;
    let partial = if c.stage == 0 {
        0
    } else {
        (c.stage - 1) * (n / 2) + c.index
    };
    let fft_g = c.stream.min(2) * butterflies + if c.stream < 2 { partial } else { 0 };
    let fft_f = c.stream.saturating_sub(2) * butterflies + if c.stream >= 2 { partial } else { 0 };
    let elements_g = c.stream.min(2) * n + if c.stream < 2 { c.index } else { 0 };
    let elements_f = c.stream.saturating_sub(2) * n + if c.stream >= 2 { c.index } else { 0 };
    let (g, f) = match c.phase {
        ReconstructionPhase::InitialReadyAlias | ReconstructionPhase::Materialize => (0, 0),
        ReconstructionPhase::Prepare => (2 * c.index, 0),
        ReconstructionPhase::Forward => (2 * n + fft_g, fft_f),
        ReconstructionPhase::Pointwise => (2 * n + nk + elements_g, nk + elements_f),
        ReconstructionPhase::Inverse => (4 * n + nk + fft_g, 2 * n + nk + fft_f),
        ReconstructionPhase::Scale => (4 * n + 2 * nk + elements_g, 2 * n + 2 * nk + elements_f),
        ReconstructionPhase::Integrate => (6 * n + 2 * nk + 4 * c.index, 4 * n + 2 * nk),
        ReconstructionPhase::Ready => (10 * n + 2 * nk, 4 * n + 2 * nk),
    };
    if u64::try_from(g).ok() != Some(c.group_scalar_calls)
        || u64::try_from(f).ok() != Some(c.field_mul_calls)
    {
        return Err(Error::Bound("cursor scalar counts"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/private/reconstruction_private.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/private/reconstruction_pilot.rs"]
mod pilot;

impl Cursor {
    pub(crate) fn persistence_parts(&self) -> [usize; 5] {
        [
            self.stream,
            self.index,
            self.stage,
            self.overlay[0],
            self.overlay[1],
        ]
    }
    pub(crate) fn persistence_new(
        phase: ReconstructionPhase,
        done: usize,
        group_scalar_calls: u64,
        field_mul_calls: u64,
        p: [usize; 5],
    ) -> Self {
        Self {
            phase,
            done,
            group_scalar_calls,
            field_mul_calls,
            stream: p[0],
            index: p[1],
            stage: p[2],
            overlay: [p[3], p[4]],
        }
    }
}
impl Journal {
    pub(crate) fn persistence_clean(&self) -> bool {
        self.gv.is_empty()
            && self.gi.is_empty()
            && self.fv.is_empty()
            && self.fi.is_empty()
            && self.marks.iter().all(|x| *x == 0)
    }
}
impl ReconstructionMaterial {
    pub(crate) fn persistence_commitments(
        &self,
        p: &PublicPackage,
    ) -> Result<[[u8; 32]; 3], Error> {
        use crate::persistence::{identity_values, HashWriter};
        use ark_serialize::CanonicalSerialize;
        use sha2::{Digest, Sha256};
        self.check(p)?;
        let n = p.shape().domain_size;
        let mut h = HashWriter(Sha256::new());
        h.0.update(b"dynark-bn254/persistence-domain/v1");
        p.0.domain.serialize_compressed(&mut h)?;
        let domain = h.0.finalize().into();
        let mut h = HashWriter(Sha256::new());
        h.0.update(b"dynark-bn254/persistence-uk/v1");
        for d in identity_values(p.identity()) {
            h.0.update(d);
        }
        h.0.update((n as u64).to_le_bytes());
        for g in self.0.uk.0.lagrange.iter().chain(&self.0.uk.0.diagonal) {
            g.serialize_compressed(&mut h)?;
        }
        for f in &self.0.uk.0.weights {
            f.serialize_compressed(&mut h)?;
        }
        let uk: [u8; 32] = h.0.finalize().into();
        let mut h = HashWriter(Sha256::new());
        h.0.update(b"dynark-bn254/persistence-tables/v1");
        for d in identity_values(p.identity()) {
            h.0.update(d);
        }
        h.0.update(uk);
        h.0.update(1u16.to_le_bytes());
        h.0.update((n as u64).to_le_bytes());
        for f in self
            .0
            .roots
            .iter()
            .chain(&self.0.forward)
            .chain(&self.0.reverse)
        {
            f.serialize_compressed(&mut h)?;
        }
        self.0.inverse_n.serialize_compressed(&mut h)?;
        Ok([domain, uk, h.0.finalize().into()])
    }
}
