use crate::{
    anchored::{capture, AnchorCore},
    randomness,
    reconstruction::{self, Builder, Cursor, Journal, Map, Pool, Roles},
    Anchor, AnchorBinding, Error, Limits, ProofStatement, PublicPackage, ReconstructionMaterial,
    ReconstructionPhase, Transition, ValidatedAssignment, WorkEvent,
};
use ark_bn254::{Fr, G1Projective as G1, G2Projective as G2};
use ark_ec::CurveGroup;
use ark_ff::{AdditiveGroup, Zero};
use ark_serialize::CanonicalSerialize;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::{io::Write, mem::size_of, sync::Arc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapPolicy {
    Reject,
    FullOnly,
}
/// Structural vector capacities, not allocator/RSS limits. Global includes shared public vectors.
#[derive(Clone, Copy, Debug)]
pub struct DynamicConfig {
    pub threshold: u64,
    pub operation: Limits,
    pub max_row_support: usize,
    pub max_total_pair_visits: usize,
    pub max_private_bytes: usize,
    pub max_global_bytes: usize,
    pub max_journal_bytes: usize,
    pub max_transaction_actions: usize,
    pub cap_policy: CapPolicy,
}
impl DynamicConfig {
    pub fn small() -> Self {
        Self {
            threshold: 8,
            operation: Limits::small(),
            max_row_support: 1024,
            max_total_pair_visits: 1_000_000,
            max_private_bytes: 32 * 1024 * 1024,
            max_global_bytes: 64 * 1024 * 1024,
            max_journal_bytes: 16 * 1024 * 1024,
            max_transaction_actions: 1_000_000,
            cap_policy: CapPolicy::Reject,
        }
    }
    fn check(&self, p: &PublicPackage) -> Result<(), Error> {
        self.operation.package(p)?;
        if self.threshold == 0 || self.threshold.checked_mul(4).is_none() {
            return Err(Error::Bound("dynamic threshold"));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DynamicStatus {
    Preparing,
    DynamicReady,
    Busy,
    FullOnly,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparationProgress {
    pub completed: usize,
    pub total: usize,
    pub ready: bool,
}
#[derive(Debug)]
pub enum UpdateProgress {
    Pending { completed: usize, remaining: usize },
    Committed(ProofStatement),
}
/// Aggregate public operation counts; never contains witness values, row identities or raw proof.
/// Lifetime counters saturate, without affecting exact scheduler state. Validation and map
/// counts cover successful stages; failed-call CPU time is measured by the external harness.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorkLedger {
    pub saturated: bool,
    pub initialization_actions: u64,
    pub adopted_cells: u64,
    pub header_actions: u64,
    pub attempted_reconstruction_actions: u64,
    pub committed_reconstruction_actions: u64,
    pub attempted_group_scalar_calls: u64,
    pub attempted_field_mul_calls: u64,
    pub committed_group_scalar_calls: u64,
    pub committed_field_mul_calls: u64,
    pub validation_entries: u64,
    pub assignment_copied_elements: u64,
    pub map_merge_elements: u64,
    pub quadratic_pair_visits: u64,
    pub group_preimages: u64,
    pub field_preimages: u64,
    pub mark_clear_visits: u64,
    pub rollback_cells: u64,
    pub full_fallbacks: u64,
    pub completed_distinct_snapshots: u64,
}
fn telemetry_add(counter: &mut u64, amount: u64, saturated: &mut bool) {
    match counter.checked_add(amount) {
        Some(value) => *counter = value,
        None => {
            *counter = u64::MAX;
            *saturated = true;
        }
    }
}
#[derive(Clone)]
struct Current {
    assignment: Arc<ValidatedAssignment>,
    binding: AnchorBinding,
    a: G1,
    b1: G1,
    b2: G2,
    c: G1,
    r: Fr,
    s: Fr,
}
impl Current {
    fn from_core(core: AnchorCore, binding: AnchorBinding) -> (Self, Vec<Fr>, Vec<Fr>) {
        (
            Self {
                assignment: Arc::new(core.assignment),
                binding,
                a: core.a_g1,
                b1: core.b_g1,
                b2: core.b_g2,
                c: core.c_g1,
                r: core.r,
                s: core.s,
            },
            core.a,
            core.b,
        )
    }
    fn statement(&self, p: &PublicPackage) -> Result<ProofStatement, Error> {
        let mut public_values = reconstruction::reserved(p.shape().instance_len - 1)?;
        public_values.extend_from_slice(&self.assignment.values[1..p.shape().instance_len]);
        Ok(ProofStatement {
            proof: ordinary::Proof {
                a: self.a.into_affine(),
                b: self.b2.into_affine(),
                c: self.c.into_affine(),
            },
            public_values,
            package: p.identity(),
            generation: self.binding.generation,
        })
    }
}
#[derive(Clone)]
struct Active {
    generation: u64,
    distance: u64,
    token: [u8; 32],
    maps: [Map; 2],
}
#[derive(Clone)]
struct Root {
    current: Current,
    active: Option<Active>,
    builder: Option<Builder>,
    roles: Roles,
    t: u64,
    distance: u64,
}
struct Pending {
    root: Root,
    proof: ProofStatement,
    remaining: usize,
    total: usize,
    crossing: bool,
    promoted: bool,
    full: bool,
    rebuilt: u64,
    empty: Map,
    group_calls: u64,
    field_calls: u64,
}

pub struct DynamicPreparation {
    package: PublicPackage,
    tables: ReconstructionMaterial,
    config: DynamicConfig,
    pool: Pool,
    current: Current,
    marks: Vec<u64>,
    position: usize,
    total: usize,
    ledger: WorkLedger,
}
impl DynamicPreparation {
    /// Consume an anchor: its private dense buffers have a single recyclable owner.
    pub fn adopt(
        p: &PublicPackage,
        tables: &ReconstructionMaterial,
        anchor: Anchor,
        config: DynamicConfig,
    ) -> Result<Self, Error> {
        config.check(p)?;
        tables.check(p)?;
        anchor.binding.package_check(p)?;
        let n = p.shape().domain_size;
        if anchor.q_a.len() != n
            || anchor.q_b.len() != n
            || anchor.core.a.len() != n
            || anchor.core.b.len() != n
        {
            return Err(Error::Bound("anchor buffer dimensions"));
        }
        let markwords = n
            .checked_mul(10)
            .and_then(|x| x.checked_add(63))
            .map(|x| x / 64)
            .ok_or(Error::Bound("mark words"))?;
        let mut expected = size_of::<Root>() + size_of::<Pending>();
        for (count, size) in [
            (anchor.q_a.capacity(), size_of::<G1>()),
            (anchor.q_b.capacity(), size_of::<G1>()),
            (anchor.core.a.capacity(), size_of::<Fr>()),
            (anchor.core.b.capacity(), size_of::<Fr>()),
            (
                n.checked_mul(2).ok_or(Error::Bound("workspace groups"))?,
                size_of::<G1>(),
            ),
            (
                n.checked_mul(4).ok_or(Error::Bound("workspace fields"))?,
                size_of::<Fr>(),
            ),
            (markwords, 8),
            (anchor.core.assignment.values.capacity(), size_of::<Fr>()),
        ] {
            expected = expected
                .checked_add(
                    count
                        .checked_mul(size)
                        .ok_or(Error::Bound("initial capacity bytes"))?,
                )
                .ok_or(Error::Bound("initial capacity bytes"))?;
        }
        if markwords.checked_mul(8).ok_or(Error::Bound("mark bytes"))? > config.max_journal_bytes {
            return Err(Error::Bound("initial mark bytes"));
        }
        check_bytes(config, expected, public_bytes(p, tables)?)?;
        let (current, a, b) = Current::from_core(anchor.core, anchor.binding);
        let pool = Pool {
            g: [
                anchor.q_a,
                anchor.q_b,
                reconstruction::reserved(n)?,
                reconstruction::reserved(n)?,
            ],
            f: [
                a,
                b,
                reconstruction::reserved(n)?,
                reconstruction::reserved(n)?,
                reconstruction::reserved(n)?,
                reconstruction::reserved(n)?,
            ],
            n,
        };
        let marks = reconstruction::reserved(markwords)?;
        if marks
            .capacity()
            .checked_mul(8)
            .ok_or(Error::Bound("actual mark bytes"))?
            > config.max_journal_bytes
        {
            return Err(Error::Bound("actual mark bytes"));
        }
        let private = pool
            .bytes()
            .checked_add(marks.capacity() * 8)
            .and_then(|x| x.checked_add(current.assignment.values.capacity() * size_of::<Fr>()))
            .and_then(|x| x.checked_add(size_of::<Root>() + size_of::<Pending>()))
            .ok_or(Error::Bound("initial private bytes"))?;
        check_bytes(config, private, public_bytes(p, tables)?)?;
        let total = n
            .checked_mul(6)
            .and_then(|x| x.checked_add(markwords))
            .ok_or(Error::Bound("initialization actions"))?;
        Ok(Self {
            package: p.clone(),
            tables: tables.clone(),
            config,
            pool,
            current,
            marks,
            position: 0,
            total,
            ledger: WorkLedger {
                adopted_cells: (4 * n) as u64,
                ..WorkLedger::default()
            },
        })
    }
    pub fn advance_preparation(&mut self, budget: usize) -> PreparationProgress {
        let end = self.total.min(self.position.saturating_add(budget));
        let n = self.pool.n;
        while self.position < end {
            let i = self.position;
            if i < 2 * n {
                self.pool.g[2 + i / n].push(G1::zero());
            } else if i < 6 * n {
                self.pool.f[2 + (i - 2 * n) / n].push(Fr::ZERO);
            } else {
                self.marks.push(0);
            }
            self.position += 1;
            telemetry_add(
                &mut self.ledger.initialization_actions,
                1,
                &mut self.ledger.saturated,
            );
        }
        PreparationProgress {
            completed: self.position,
            total: self.total,
            ready: self.position == self.total,
        }
    }
    pub fn finish(self) -> Result<DynamicState, Error> {
        if self.position != self.total {
            return Err(Error::NotReady);
        }
        let empty = Arc::new(Vec::new());
        let w = reconstruction::work(self.pool.n)?;
        let binding = self.current.binding;
        let root = Root {
            current: self.current,
            active: Some(Active {
                generation: binding.generation,
                distance: 0,
                token: binding.anchor_state,
                maps: [empty.clone(), empty.clone()],
            }),
            builder: Some(Builder {
                generation: binding.generation,
                distance: 0,
                token: binding.anchor_state,
                source: [0, 1],
                overlays: [empty.clone(), empty.clone()],
                pending: [empty.clone(), empty],
                cursor: Cursor::alias(w),
            }),
            roles: Roles::default(),
            t: 0,
            distance: 0,
        };
        Ok(DynamicState {
            package: self.package,
            tables: self.tables,
            config: self.config,
            pool: Some(self.pool),
            journal: Journal::empty(self.marks),
            root,
            pending: None,
            ledger: self.ledger,
        })
    }
}

/// Serial owner. A pending target exposes no partial cache/proof and retains one whole-call journal.
pub struct DynamicState {
    package: PublicPackage,
    tables: ReconstructionMaterial,
    config: DynamicConfig,
    pool: Option<Pool>,
    journal: Journal,
    root: Root,
    pending: Option<Pending>,
    ledger: WorkLedger,
}
impl DynamicState {
    pub fn status(&self) -> DynamicStatus {
        if self.pending.is_some() {
            DynamicStatus::Busy
        } else if self.root.active.is_none() {
            DynamicStatus::FullOnly
        } else {
            DynamicStatus::DynamicReady
        }
    }
    pub fn binding(&self) -> Result<AnchorBinding, Error> {
        if self.pending.is_some() {
            Err(Error::Busy)
        } else {
            Ok(self.root.current.binding)
        }
    }
    pub fn accepted_distance(&self) -> u64 {
        self.root.distance
    }
    pub fn cycle_credit(&self) -> u64 {
        self.root.t
    }
    pub fn ledger(&self) -> WorkLedger {
        self.ledger
    }
    pub fn phase(&self) -> Result<ReconstructionPhase, Error> {
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        self.root
            .builder
            .as_ref()
            .map(|x| x.cursor.phase)
            .ok_or(Error::NotReady)
    }
    pub fn reconstruction_work(&self) -> Result<usize, Error> {
        reconstruction::work(self.package.shape().domain_size)
    }
    pub fn reconstruction_completed(&self) -> Result<usize, Error> {
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        self.root
            .builder
            .as_ref()
            .map(|b| b.cursor.done)
            .ok_or(Error::NotReady)
    }
    pub fn retained_journal_bytes(&self) -> usize {
        self.journal.bytes()
    }
    pub fn private_structural_bytes(&self) -> Result<usize, Error> {
        private_bytes(
            self.pool.as_ref(),
            &self.journal,
            &self.root,
            self.pending.as_ref().map(|p| &p.root),
        )?
        .checked_add(
            self.pending
                .as_ref()
                .map_or(0, |p| p.proof.public_values.capacity() * size_of::<Fr>()),
        )
        .ok_or(Error::Bound("pending statement bytes"))
    }
    pub fn shared_public_structural_bytes(&self) -> Result<usize, Error> {
        public_bytes(&self.package, &self.tables)
    }
    pub fn snapshot_bindings(&self) -> Result<(AnchorBinding, AnchorBinding), Error> {
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        let active = self.root.active.as_ref().ok_or(Error::NotReady)?;
        let builder = self.root.builder.as_ref().ok_or(Error::NotReady)?;
        let mut a = self.root.current.binding;
        let mut b = a;
        a.generation = active.generation;
        a.anchor_state = active.token;
        b.generation = builder.generation;
        b.anchor_state = builder.token;
        Ok((a, b))
    }
    pub fn snapshot_distances(&self) -> Result<(u64, u64), Error> {
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        Ok((
            self.root.active.as_ref().ok_or(Error::NotReady)?.distance,
            self.root.builder.as_ref().ok_or(Error::NotReady)?.distance,
        ))
    }

    pub fn begin_update<R: RngCore + CryptoRng + ?Sized>(
        &mut self,
        t: &Transition,
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        let p = &self.package;
        self.config.check(p)?;
        self.tables.check(p)?;
        if t.base != self.root.current.binding {
            return Err(Error::AnchorBinding);
        }
        if t.normalized_count() > self.config.operation.max_delta_entries {
            return Err(Error::Bound("engine normalized delta entries"));
        }
        if let (Some(pool), Some(builder)) = (&self.pool, &self.root.builder) {
            pool.validate(&self.root.roles, builder)?;
            reconstruction::validate_cursor(&builder.cursor, pool.n, &builder.overlays)?;
        }
        let validation_peak = private_bytes(self.pool.as_ref(), &self.journal, &self.root, None)?
            .checked_add(validation_allocation_bound(p, t)?)
            .ok_or(Error::Bound("target validation peak"))?;
        check_bytes(self.config, validation_peak, public_bytes(p, &self.tables)?)?;
        let prepared = t.validate_target(p, &self.root.current.assignment)?;
        telemetry_add(
            &mut self.ledger.validation_entries,
            prepared.stats().full_validation_entries as u64,
            &mut self.ledger.saturated,
        );
        telemetry_add(
            &mut self.ledger.assignment_copied_elements,
            p.shape().assignment_len as u64,
            &mut self.ledger.saturated,
        );
        let d = t.normalized_count() as u64;
        let distance = self
            .root
            .distance
            .checked_add(d)
            .ok_or(Error::Bound("accepted distance"))?;
        let mut target = Some(prepared.target);
        let rows = prepared.rows;
        let row_bytes = rows
            .a
            .capacity()
            .checked_add(rows.b.capacity())
            .and_then(|x| x.checked_add(rows.c.capacity()))
            .and_then(|x| x.checked_mul(size_of::<(usize, Fr)>()))
            .ok_or(Error::Bound("row delta bytes"))?;
        let target_bytes = target
            .as_ref()
            .unwrap()
            .values
            .capacity()
            .checked_mul(size_of::<Fr>())
            .ok_or(Error::Bound("target capacity"))?;
        let mut next = self.root.clone();
        next.distance = distance;
        let mut crossing = false;
        let mut after = 0;
        let mut k = 0;
        let mut cap_error = None;
        if d > self.config.threshold {
            cap_error = Some(Error::Bound("transition distance"));
        }
        if self.root.active.is_none() {
            cap_error = Some(Error::NotReady);
        }
        if cap_error.is_none() && d > 0 {
            let staged = (|| -> Result<(), Error> {
                let allocation = map_allocation_bound(&next, &rows, self.config.max_row_support)?;
                let stage_peak =
                    private_bytes(self.pool.as_ref(), &self.journal, &self.root, Some(&next))?
                        .checked_add(target_bytes)
                        .and_then(|x| x.checked_add(row_bytes))
                        .and_then(|x| x.checked_add(allocation))
                        .ok_or(Error::Bound("map staging peak"))?;
                check_bytes(self.config, stage_peak, public_bytes(p, &self.tables)?)?;
                let active = next.active.as_mut().ok_or(Error::NotReady)?;
                if distance
                    .checked_sub(active.distance)
                    .ok_or(Error::Generation)?
                    > self.config.threshold * 4
                {
                    cap_error = Some(Error::Bound("active snapshot distance"));
                }
                let merge_count =
                    active.maps[0].len() + active.maps[1].len() + rows.a.len() + rows.b.len();
                let merged_a = merge(&active.maps[0], &rows.a, self.config.max_row_support)?;
                let merged_b = merge(&active.maps[1], &rows.b, self.config.max_row_support)?;
                let pairs = pair_work(&merged_a, &rows.b)?
                    .checked_add(pair_work(&rows.a, &active.maps[1])?)
                    .ok_or(Error::Bound("total pair visits"))?;
                if pairs > self.config.max_total_pair_visits
                    || pairs > self.config.operation.max_pair_work
                {
                    cap_error = Some(Error::Bound("total cross pair work"));
                }
                telemetry_add(
                    &mut self.ledger.map_merge_elements,
                    merge_count as u64,
                    &mut self.ledger.saturated,
                );
                active.maps = [Arc::new(merged_a), Arc::new(merged_b)];
                let builder = next.builder.as_mut().ok_or(Error::NotReady)?;
                let pa = merge(&builder.pending[0], &rows.a, self.config.max_row_support)?;
                let pb = merge(&builder.pending[1], &rows.b, self.config.max_row_support)?;
                telemetry_add(
                    &mut self.ledger.map_merge_elements,
                    (builder.pending[0].len()
                        + builder.pending[1].len()
                        + rows.a.len()
                        + rows.b.len()) as u64,
                    &mut self.ledger.saturated,
                );
                builder.pending = [Arc::new(pa), Arc::new(pb)];
                let sum = next.t.checked_add(d).ok_or(Error::Bound("cycle credit"))?;
                let w = reconstruction::work(p.shape().domain_size)?;
                crossing = sum >= self.config.threshold;
                if crossing {
                    after = quota(w, sum - self.config.threshold, self.config.threshold)?
                        .saturating_sub(1);
                    k = w
                        .saturating_sub(builder.cursor.done)
                        .checked_add(1)
                        .and_then(|x| x.checked_add(after))
                        .ok_or(Error::Bound("transaction work"))?;
                    next.t = sum - self.config.threshold;
                } else {
                    k = quota(w, sum, self.config.threshold)?.saturating_sub(builder.cursor.done);
                    next.t = sum;
                }
                if k > self.config.max_transaction_actions {
                    cap_error = Some(Error::Bound("transaction actions"));
                }
                Ok(())
            })();
            if let Err(e) = staged {
                match e {
                    Error::Bound(_) | Error::NotReady => cap_error = Some(e),
                    _ => return Err(e),
                }
            }
        }
        // Target allocation and full fallback scratch are bounded before entropy or group correction.
        let mut private =
            private_bytes(self.pool.as_ref(), &self.journal, &self.root, Some(&next))?
                .checked_add(target_bytes)
                .and_then(|x| x.checked_add(row_bytes))
                .and_then(|x| x.checked_add(cross_scratch_bytes(&next, &self.root, &rows)?))
                .and_then(|x| {
                    x.checked_add((p.shape().instance_len - 1).checked_mul(size_of::<Fr>())?)
                })
                .ok_or(Error::Bound("target private bytes"))?;
        if let Some(pool) = &self.pool {
            let planned = self.journal.planned_bytes(pool.n, k)?;
            if planned > self.config.max_journal_bytes {
                cap_error = Some(Error::Bound("journal bytes"));
            }
            let peak = self.journal.reservation_peak_bytes(pool.n, k)?;
            private = private
                .checked_sub(self.journal.bytes())
                .and_then(|x| x.checked_add(peak))
                .ok_or(Error::Bound("private journal bytes"))?;
        }
        if let Err(e) = check_bytes(self.config, private, public_bytes(p, &self.tables)?) {
            cap_error = Some(e);
        }
        let full = cap_error.is_some();
        if full && self.config.cap_policy == CapPolicy::Reject && self.root.active.is_some() {
            return Err(cap_error.unwrap());
        }
        if full {
            // Release candidate map allocations before preparing a full proof.
            next = self.root.clone();
            next.distance = distance;
            let scratch = full_scratch_bytes(p)?;
            let bytes = private_bytes(self.pool.as_ref(), &self.journal, &self.root, None)?
                .checked_add(target_bytes)
                .and_then(|x| x.checked_add(scratch))
                .and_then(|x| x.checked_add(row_bytes))
                .ok_or(Error::Bound("full peak"))?;
            check_bytes(self.config, bytes, public_bytes(p, &self.tables)?)?;
            k = 0;
            crossing = false;
        }
        let (r, s) = randomness::blinders(rng)?;
        let current = if full {
            let core = capture(p, target.take().unwrap(), r, s)?;
            let (mut current, _, _) = Current::from_core(core, self.root.current.binding);
            current.binding.generation = t.generation;
            next.active = None;
            next.builder = None;
            next.t = 0;
            current
        } else {
            let pool = self.pool.as_ref().ok_or(Error::NotReady)?;
            let uk = &self.tables.0.uk;
            let pk = &p.0.pk;
            let old = &self.root.current;
            let mut a = old.a + pk.delta_g1 * (r - old.r);
            let mut b1 = old.b1 + pk.delta_g1 * (s - old.s);
            let mut b2 = old.b2 + pk.vk.delta_g2 * (s - old.s);
            let mut private_linear = G1::zero();
            for &(j, x) in &t.delta {
                a += pk.u_g1[j] * x;
                b1 += pk.v_g1[j] * x;
                b2 += pk.v_g2[j] * x;
                if j >= p.shape().instance_len {
                    private_linear += pk.t_p_g1[j - p.shape().instance_len] * x;
                }
            }
            let mut quotient = G1::zero();
            for &(i, x) in &rows.a {
                quotient += pool.g[self.root.roles.active_g[1]][i] * x;
            }
            for &(i, x) in &rows.b {
                quotient += pool.g[self.root.roles.active_g[0]][i] * x;
            }
            if d > 0 {
                let alpha = &next.active.as_ref().unwrap().maps[0];
                let beta = &self.root.active.as_ref().unwrap().maps[1];
                let pairs = pair_work(alpha, &rows.b)? + pair_work(&rows.a, beta)?;
                quotient += uk.cross(alpha, &rows.b, self.config.max_total_pair_visits)?;
                quotient += uk.cross(&rows.a, beta, self.config.max_total_pair_visits)?;
                telemetry_add(
                    &mut self.ledger.quadratic_pair_visits,
                    pairs as u64,
                    &mut self.ledger.saturated,
                );
            }
            let c = old.c + a * s - old.a * old.s + b1 * r
                - old.b1 * old.r
                - pk.delta_g1 * (r * s - old.r * old.s)
                + private_linear
                + quotient;
            let mut binding = old.binding;
            binding.generation = t.generation;
            Current {
                assignment: Arc::new(target.take().unwrap()),
                binding,
                a,
                b1,
                b2,
                c,
                r,
                s,
            }
        };
        next.current = current;
        next.current.binding.anchor_state =
            transition_token(&self.root.current.binding, t, &next.current, p)?;
        let proof = next.current.statement(p)?;
        let empty = Arc::new(Vec::new());
        // All fallible target/proof obligations and whole-call reservation precede pool mutation.
        if !full {
            let without =
                private_bytes(self.pool.as_ref(), &self.journal, &self.root, Some(&next))?
                    .checked_sub(self.journal.bytes())
                    .and_then(|x| x.checked_add(proof.public_values.capacity() * size_of::<Fr>()))
                    .ok_or(Error::Bound("reservation available bytes"))?;
            let cap = journal_available(self.config, without, public_bytes(p, &self.tables)?)?;
            self.journal
                .reserve(self.pool.as_ref().ok_or(Error::NotReady)?.n, k, cap)?;
        }
        let actual = private_bytes(self.pool.as_ref(), &self.journal, &self.root, Some(&next))?
            .checked_add(proof.public_values.capacity() * size_of::<Fr>())
            .ok_or(Error::Bound("statement capacity bytes"))?;
        check_bytes(self.config, actual, public_bytes(p, &self.tables)?)?;
        self.pending = Some(Pending {
            root: next,
            proof,
            remaining: k,
            total: k,
            crossing,
            promoted: false,
            full,
            rebuilt: 0,
            empty,
            group_calls: 0,
            field_calls: 0,
        });
        Ok(())
    }
    pub fn advance_update(&mut self, budget: usize) -> Result<UpdateProgress, Error> {
        self.advance_update_with(budget, |_| false)
    }
    pub fn advance_update_with(
        &mut self,
        budget: usize,
        mut cancel: impl FnMut(WorkEvent) -> bool,
    ) -> Result<UpdateProgress, Error> {
        let mut pending = self.pending.take().ok_or(Error::NotReady)?;
        if budget == 0 {
            let progress = UpdateProgress::Pending {
                completed: pending.total - pending.remaining,
                remaining: pending.remaining,
            };
            self.pending = Some(pending);
            return Ok(progress);
        }
        let attempt = advance_pending(
            &mut pending,
            self.pool.as_mut(),
            &mut self.journal,
            &self.tables,
            budget,
            &mut cancel,
            &mut self.ledger,
        );
        if let Err(error) = attempt {
            self.ledger.group_preimages = self.journal.group_logs as u64;
            self.ledger.field_preimages = self.journal.field_logs as u64;
            self.ledger.saturated |= self.journal.saturated;
            if let Some(pool) = self.pool.as_mut() {
                let cells = self.journal.finish(pool, true);
                telemetry_add(
                    &mut self.ledger.rollback_cells,
                    cells as u64,
                    &mut self.ledger.saturated,
                );
                telemetry_add(
                    &mut self.ledger.mark_clear_visits,
                    cells as u64,
                    &mut self.ledger.saturated,
                );
            }
            return Err(error);
        }
        if pending.remaining > 0 {
            let progress = UpdateProgress::Pending {
                completed: pending.total - pending.remaining,
                remaining: pending.remaining,
            };
            self.pending = Some(pending);
            return Ok(progress);
        }
        if let Some(pool) = self.pool.as_mut() {
            let cells = self.journal.finish(pool, false);
            telemetry_add(
                &mut self.ledger.mark_clear_visits,
                cells as u64,
                &mut self.ledger.saturated,
            );
        }
        telemetry_add(
            &mut self.ledger.committed_reconstruction_actions,
            pending.total as u64,
            &mut self.ledger.saturated,
        );
        telemetry_add(
            &mut self.ledger.committed_group_scalar_calls,
            pending.group_calls,
            &mut self.ledger.saturated,
        );
        telemetry_add(
            &mut self.ledger.committed_field_mul_calls,
            pending.field_calls,
            &mut self.ledger.saturated,
        );
        telemetry_add(
            &mut self.ledger.completed_distinct_snapshots,
            pending.rebuilt,
            &mut self.ledger.saturated,
        );
        if pending.full {
            self.pool = None;
            self.journal = Journal::empty(Vec::new());
            telemetry_add(
                &mut self.ledger.full_fallbacks,
                1,
                &mut self.ledger.saturated,
            );
        }
        self.root = pending.root;
        Ok(UpdateProgress::Committed(pending.proof))
    }
    pub fn cancel_update(&mut self) -> Result<(), Error> {
        if self.pending.take().is_none() {
            return Err(Error::NotReady);
        }
        if let Some(pool) = self.pool.as_mut() {
            let cells = self.journal.finish(pool, true);
            telemetry_add(
                &mut self.ledger.rollback_cells,
                cells as u64,
                &mut self.ledger.saturated,
            );
            telemetry_add(
                &mut self.ledger.mark_clear_visits,
                cells as u64,
                &mut self.ledger.saturated,
            );
        }
        Ok(())
    }
    pub fn update<R: RngCore + CryptoRng + ?Sized>(
        &mut self,
        t: &Transition,
        rng: &mut R,
    ) -> Result<ProofStatement, Error> {
        self.begin_update(t, rng)?;
        match self.advance_update(usize::MAX)? {
            UpdateProgress::Committed(proof) => Ok(proof),
            UpdateProgress::Pending { .. } => Err(Error::NotReady),
        }
    }
    /// Optional maintenance commits only its own bounded progress, never promotes a snapshot.
    pub fn advance(&mut self, budget: usize) -> Result<usize, Error> {
        self.advance_with(budget, |_| false)
    }
    pub fn advance_with(
        &mut self,
        budget: usize,
        mut cancel: impl FnMut(WorkEvent) -> bool,
    ) -> Result<usize, Error> {
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        if budget == 0 {
            return Ok(0);
        }
        if let (Some(pool), Some(builder)) = (&self.pool, &self.root.builder) {
            pool.validate(&self.root.roles, builder)?;
            reconstruction::validate_cursor(&builder.cursor, pool.n, &builder.overlays)?;
        }
        let mut next = self.root.clone();
        let builder = next.builder.as_mut().ok_or(Error::NotReady)?;
        let k = budget.min(
            self.reconstruction_work()?
                .saturating_sub(builder.cursor.done),
        );
        if k == 0 {
            return Ok(0);
        }
        if k > self.config.max_transaction_actions {
            return Err(Error::Bound("maintenance actions"));
        }
        let pool = self.pool.as_mut().ok_or(Error::NotReady)?;
        let planned = self.journal.reservation_peak_bytes(pool.n, k)?;
        let private = private_bytes(Some(pool), &self.journal, &self.root, Some(&next))?
            .checked_sub(self.journal.bytes())
            .and_then(|x| x.checked_add(planned))
            .ok_or(Error::Bound("maintenance bytes"))?;
        check_bytes(
            self.config,
            private,
            public_bytes(&self.package, &self.tables)?,
        )?;
        let without = private_bytes(Some(pool), &self.journal, &self.root, Some(&next))?
            .checked_sub(self.journal.bytes())
            .ok_or(Error::Bound("maintenance reservation"))?;
        let cap = journal_available(
            self.config,
            without,
            public_bytes(&self.package, &self.tables)?,
        )?;
        self.journal.reserve(pool.n, k, cap)?;
        let builder = next.builder.as_mut().unwrap();
        let (mut group_calls, mut field_calls) = (0u64, 0u64);
        let result = (|| {
            for _ in 0..k {
                telemetry_add(
                    &mut self.ledger.attempted_reconstruction_actions,
                    1,
                    &mut self.ledger.saturated,
                );
                let before = (
                    builder.cursor.group_scalar_calls,
                    builder.cursor.field_mul_calls,
                );
                let step = reconstruction::step(
                    pool,
                    &mut self.journal,
                    &next.roles,
                    builder,
                    &self.tables.0,
                    &mut cancel,
                );
                let g = builder.cursor.group_scalar_calls - before.0;
                let f = builder.cursor.field_mul_calls - before.1;
                telemetry_add(
                    &mut self.ledger.attempted_group_scalar_calls,
                    g,
                    &mut self.ledger.saturated,
                );
                telemetry_add(
                    &mut self.ledger.attempted_field_mul_calls,
                    f,
                    &mut self.ledger.saturated,
                );
                group_calls = group_calls
                    .checked_add(g)
                    .ok_or(Error::Bound("maintenance group calls"))?;
                field_calls = field_calls
                    .checked_add(f)
                    .ok_or(Error::Bound("maintenance field calls"))?;
                step?;
            }
            Ok(())
        })();
        self.ledger.group_preimages = self.journal.group_logs as u64;
        self.ledger.field_preimages = self.journal.field_logs as u64;
        self.ledger.saturated |= self.journal.saturated;
        let failed = result.is_err();
        let cells = self.journal.finish(pool, failed);
        telemetry_add(
            &mut self.ledger.mark_clear_visits,
            cells as u64,
            &mut self.ledger.saturated,
        );
        if failed {
            telemetry_add(
                &mut self.ledger.rollback_cells,
                cells as u64,
                &mut self.ledger.saturated,
            );
            return result.map(|_| 0);
        }
        self.root = next;
        telemetry_add(
            &mut self.ledger.committed_reconstruction_actions,
            k as u64,
            &mut self.ledger.saturated,
        );
        telemetry_add(
            &mut self.ledger.committed_group_scalar_calls,
            group_calls,
            &mut self.ledger.saturated,
        );
        telemetry_add(
            &mut self.ledger.committed_field_mul_calls,
            field_calls,
            &mut self.ledger.saturated,
        );
        Ok(k)
    }
    /// Explicit holder/action invalidation always stages a fully validated, paid ordinary proof.
    pub fn full_for_binding<R: RngCore + CryptoRng + ?Sized>(
        &mut self,
        assignment: ValidatedAssignment,
        credential: [u8; 32],
        action: [u8; 32],
        generation: u64,
        rng: &mut R,
    ) -> Result<ProofStatement, Error> {
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        if assignment.package != self.package.identity() {
            return Err(Error::AssignmentPackage);
        }
        if generation <= self.root.current.binding.generation {
            return Err(Error::Generation);
        }
        let bytes = private_bytes(self.pool.as_ref(), &self.journal, &self.root, None)?
            .checked_add(assignment.values.capacity() * size_of::<Fr>())
            .and_then(|x| x.checked_add(full_scratch_bytes(&self.package).ok()?))
            .ok_or(Error::Bound("full invalidation peak"))?;
        check_bytes(
            self.config,
            bytes,
            public_bytes(&self.package, &self.tables)?,
        )?;
        let (r, s) = randomness::blinders(rng)?;
        let core = capture(&self.package, assignment, r, s)?;
        let (mut current, _, _) = Current::from_core(
            core,
            AnchorBinding::new(&self.package, credential, action, generation),
        );
        current.binding.anchor_state =
            full_token(&self.root.current.binding, &current, &self.package)?;
        let proof = current.statement(&self.package)?;
        self.root.current = current;
        self.root.active = None;
        self.root.builder = None;
        self.root.t = 0;
        self.pool = None;
        self.journal = Journal::empty(Vec::new());
        telemetry_add(
            &mut self.ledger.full_fallbacks,
            1,
            &mut self.ledger.saturated,
        );
        Ok(proof)
    }
}

fn advance_pending(
    p: &mut Pending,
    pool: Option<&mut Pool>,
    journal: &mut Journal,
    tables: &ReconstructionMaterial,
    budget: usize,
    o: &mut impl FnMut(WorkEvent) -> bool,
    ledger: &mut WorkLedger,
) -> Result<(), Error> {
    if p.full || p.remaining == 0 {
        return Ok(());
    }
    let pool = pool.ok_or(Error::NotReady)?;
    let mut left = budget;
    while left > 0 && p.remaining > 0 {
        let builder = p.root.builder.as_mut().ok_or(Error::NotReady)?;
        if p.crossing && !p.promoted && builder.cursor.ready() {
            let alias = builder.cursor.phase == ReconstructionPhase::InitialReadyAlias;
            if !alias {
                std::mem::swap(&mut p.root.roles.active_g, &mut p.root.roles.build_g);
                std::mem::swap(&mut p.root.roles.active_f, &mut p.root.roles.build_f);
                p.rebuilt += 1;
            }
            p.root.active = Some(Active {
                generation: builder.generation,
                distance: builder.distance,
                token: builder.token,
                maps: builder.pending.clone(),
            });
            if o(WorkEvent::Promotion) {
                return Err(Error::Cancelled);
            }
            let active = p.root.active.as_ref().unwrap();
            let empty = p.empty.clone();
            p.root.builder = Some(Builder {
                generation: p.root.current.binding.generation,
                distance: p.root.distance,
                token: p.root.current.binding.anchor_state,
                source: p.root.roles.active_f,
                overlays: active.maps.clone(),
                pending: [empty.clone(), empty],
                cursor: Cursor::frozen(),
            });
            telemetry_add(&mut ledger.header_actions, 1, &mut ledger.saturated);
            telemetry_add(
                &mut ledger.attempted_reconstruction_actions,
                1,
                &mut ledger.saturated,
            );
            p.remaining -= 1;
            left -= 1;
            p.promoted = true;
            if o(WorkEvent::Header) {
                return Err(Error::Cancelled);
            }
        } else {
            telemetry_add(
                &mut ledger.attempted_reconstruction_actions,
                1,
                &mut ledger.saturated,
            );
            let before = (
                builder.cursor.group_scalar_calls,
                builder.cursor.field_mul_calls,
            );
            let step = reconstruction::step(pool, journal, &p.root.roles, builder, &tables.0, o);
            let g = builder.cursor.group_scalar_calls - before.0;
            let f = builder.cursor.field_mul_calls - before.1;
            telemetry_add(
                &mut ledger.attempted_group_scalar_calls,
                g,
                &mut ledger.saturated,
            );
            telemetry_add(
                &mut ledger.attempted_field_mul_calls,
                f,
                &mut ledger.saturated,
            );
            p.group_calls = p
                .group_calls
                .checked_add(g)
                .ok_or(Error::Bound("maintenance group calls"))?;
            p.field_calls = p
                .field_calls
                .checked_add(f)
                .ok_or(Error::Bound("maintenance field calls"))?;
            step?;
            p.remaining -= 1;
            left -= 1;
        }
    }
    ledger.group_preimages = journal.group_logs as u64;
    ledger.field_preimages = journal.field_logs as u64;
    ledger.saturated |= journal.saturated;
    Ok(())
}
fn quota(w: usize, u: u64, b: u64) -> Result<usize, Error> {
    if u > b || b == 0 {
        return Err(Error::Bound("quota range"));
    }
    let x = (w as u128)
        .checked_mul(u as u128)
        .ok_or(Error::Bound("quota multiplication"))?
        / (b as u128);
    usize::try_from(x).map_err(|_| Error::Bound("quota address space"))
}
fn pair_work(a: &[(usize, Fr)], b: &[(usize, Fr)]) -> Result<usize, Error> {
    a.len()
        .checked_mul(b.len())
        .ok_or(Error::Bound("pair visits"))
}
fn validation_allocation_bound(p: &PublicPackage, t: &Transition) -> Result<usize, Error> {
    let mut bytes = p
        .shape()
        .assignment_len
        .checked_mul(size_of::<Fr>())
        .ok_or(Error::Bound("target validation allocation"))?;
    for columns in &p.0.columns {
        let mut touched = 0usize;
        for &(j, _) in &t.delta {
            touched = touched
                .checked_add(columns.get(j).ok_or(Error::DeltaCoordinate)?.len())
                .ok_or(Error::Bound("target row fanout"))?;
        }
        let support = touched.min(p.shape().domain_size);
        // Conservative std BTree node+output-vector scratch estimate, with a root-node allowance.
        let scratch = support
            .checked_mul(256)
            .and_then(|x| x.checked_add(if support == 0 { 0 } else { 768 }))
            .ok_or(Error::Bound("target row scratch"))?;
        bytes = bytes
            .checked_add(scratch)
            .ok_or(Error::Bound("target row scratch"))?;
    }
    Ok(bytes)
}
fn map_allocation_bound(root: &Root, rows: &crate::RowDeltas, cap: usize) -> Result<usize, Error> {
    let active = root.active.as_ref().ok_or(Error::NotReady)?;
    let builder = root.builder.as_ref().ok_or(Error::NotReady)?;
    let mut bytes = 0usize;
    for (map, delta) in [
        (&active.maps[0], &rows.a),
        (&active.maps[1], &rows.b),
        (&builder.pending[0], &rows.a),
        (&builder.pending[1], &rows.b),
    ] {
        let entries = map
            .len()
            .checked_add(delta.len())
            .ok_or(Error::Bound("staged map entries"))?
            .min(cap);
        bytes = bytes
            .checked_add(
                entries
                    .checked_mul(size_of::<(usize, Fr)>())
                    .ok_or(Error::Bound("staged map bytes"))?,
            )
            .ok_or(Error::Bound("staged map bytes"))?;
    }
    Ok(bytes)
}
fn merge(a: &[(usize, Fr)], b: &[(usize, Fr)], cap: usize) -> Result<Vec<(usize, Fr)>, Error> {
    let count = a
        .len()
        .checked_add(b.len())
        .ok_or(Error::Bound("map merge"))?;
    let mut out = reconstruction::reserved(count.min(cap))?;
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        let pair = if j == b.len() || (i < a.len() && a[i].0 < b[j].0) {
            let x = a[i];
            i += 1;
            x
        } else if i == a.len() || b[j].0 < a[i].0 {
            let x = b[j];
            j += 1;
            x
        } else {
            let x = (a[i].0, a[i].1 + b[j].1);
            i += 1;
            j += 1;
            x
        };
        if !pair.1.is_zero() {
            if out.len() == cap {
                return Err(Error::Bound("row support"));
            }
            out.push(pair);
        }
    }
    Ok(out)
}
fn check_bytes(c: DynamicConfig, private: usize, public: usize) -> Result<(), Error> {
    if private > c.max_private_bytes {
        return Err(Error::Bound("private structural bytes"));
    }
    if private
        .checked_add(public)
        .ok_or(Error::Bound("global structural bytes"))?
        > c.max_global_bytes
    {
        return Err(Error::Bound("global structural bytes"));
    }
    Ok(())
}
fn journal_available(c: DynamicConfig, without: usize, public: usize) -> Result<usize, Error> {
    let private = c
        .max_private_bytes
        .checked_sub(without)
        .ok_or(Error::Bound("private journal availability"))?;
    let global = c
        .max_global_bytes
        .checked_sub(public)
        .and_then(|x| x.checked_sub(without))
        .ok_or(Error::Bound("global journal availability"))?;
    Ok(c.max_journal_bytes.min(private).min(global))
}
fn private_bytes(
    pool: Option<&Pool>,
    journal: &Journal,
    old: &Root,
    next: Option<&Root>,
) -> Result<usize, Error> {
    let mut bytes = pool
        .map_or(0, Pool::bytes)
        .checked_add(journal.bytes())
        .and_then(|x| x.checked_add(size_of::<Root>() + size_of::<Pending>()))
        .ok_or(Error::Bound("private bytes"))?;
    let mut maps: [Option<&Map>; 12] = [None; 12];
    let mut count = 0;
    for root in [Some(old), next].into_iter().flatten() {
        if let Some(active) = &root.active {
            for map in &active.maps {
                maps[count] = Some(map);
                count += 1;
            }
        }
        if let Some(builder) = &root.builder {
            for map in builder.overlays.iter().chain(&builder.pending) {
                maps[count] = Some(map);
                count += 1;
            }
        }
    }
    for i in 0..count {
        let map = maps[i].unwrap();
        if !(0..i).any(|j| Arc::ptr_eq(map, maps[j].unwrap())) {
            bytes = bytes
                .checked_add(map.capacity() * size_of::<(usize, Fr)>())
                .ok_or(Error::Bound("map bytes"))?;
        }
    }
    bytes = bytes
        .checked_add(old.current.assignment.values.capacity() * size_of::<Fr>())
        .ok_or(Error::Bound("assignment bytes"))?;
    if let Some(next) = next {
        if !Arc::ptr_eq(&old.current.assignment, &next.current.assignment) {
            bytes = bytes
                .checked_add(next.current.assignment.values.capacity() * size_of::<Fr>())
                .ok_or(Error::Bound("target assignment bytes"))?;
        }
    }
    Ok(bytes)
}
fn public_bytes(p: &PublicPackage, t: &ReconstructionMaterial) -> Result<usize, Error> {
    if t.0.package != p.identity() {
        return Err(Error::UpdatingPackage);
    }
    Ok(t.0.public_bytes)
}
fn cross_scratch_bytes(next: &Root, old: &Root, rows: &crate::RowDeltas) -> Option<usize> {
    let active = next.active.as_ref();
    let base = old.active.as_ref();
    let a = active
        .map_or(0, |x| x.maps[0].len())
        .checked_add(rows.b.len())?;
    let b = rows
        .a
        .len()
        .checked_add(base.map_or(0, |x| x.maps[1].len()))?;
    a.max(b).checked_mul(size_of::<Fr>())
}
fn full_scratch_bytes(p: &PublicPackage) -> Result<usize, Error> {
    // Conservative dense rows + quotient FFT/MSM scratch, in addition to the live private pool.
    p.shape()
        .domain_size
        .checked_mul(2048)
        .and_then(|x| {
            p.shape()
                .assignment_len
                .checked_mul(128)
                .and_then(|y| x.checked_add(y))
        })
        .ok_or(Error::Bound("full scratch bytes"))
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
fn hash_binding(h: &mut HashWriter, b: &AnchorBinding) {
    for digest in [
        b.package.matrix_digest,
        b.package.circuit_digest,
        b.package.proving_key_digest,
        b.package.verifying_key_digest,
        b.package.package_digest,
        b.credential,
        b.action,
        b.anchor_state,
    ] {
        h.0.update(digest);
    }
    h.0.update((b.domain_size as u64).to_le_bytes());
    h.0.update(b.generation.to_le_bytes());
}
fn hash_current(h: &mut HashWriter, c: &Current, p: &PublicPackage) -> Result<(), Error> {
    hash_binding(h, &c.binding);
    let public = &c.assignment.values[1..p.shape().instance_len];
    h.0.update((public.len() as u64).to_le_bytes());
    for x in public {
        x.serialize_compressed(&mut *h)?;
    }
    for g in [&c.a, &c.b1, &c.c] {
        g.serialize_compressed(&mut *h)?;
    }
    c.b2.serialize_compressed(&mut *h)?;
    c.r.serialize_compressed(&mut *h)?;
    c.s.serialize_compressed(&mut *h)?;
    Ok(())
}
fn transition_token(
    base: &AnchorBinding,
    t: &Transition,
    c: &Current,
    p: &PublicPackage,
) -> Result<[u8; 32], Error> {
    let mut h = HashWriter(Sha256::new());
    h.0.update(b"dynark-bn254/dynamic-transition/v1");
    hash_binding(&mut h, base);
    h.0.update((t.delta.len() as u64).to_le_bytes());
    for &(i, x) in &t.delta {
        h.0.update((i as u64).to_le_bytes());
        x.serialize_compressed(&mut h)?;
    }
    hash_current(&mut h, c, p)?;
    Ok(h.0.finalize().into())
}
fn full_token(base: &AnchorBinding, c: &Current, p: &PublicPackage) -> Result<[u8; 32], Error> {
    let mut h = HashWriter(Sha256::new());
    h.0.update(b"dynark-bn254/dynamic-full-binding/v1");
    hash_binding(&mut h, base);
    h.0.update((c.assignment.values.len() as u64).to_le_bytes());
    for x in &c.assignment.values {
        x.serialize_compressed(&mut h)?;
    }
    hash_current(&mut h, c, p)?;
    Ok(h.0.finalize().into())
}

#[cfg(test)]
#[path = "../tests/private/dynamic_private.rs"]
mod tests;

// Internal codec owns no public raw-state access.
pub(crate) mod persistence_codec;
