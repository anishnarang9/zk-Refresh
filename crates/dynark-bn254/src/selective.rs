//! Bounded immutable-anchor direct entries. Private entry values are never exported.
//! FullOnly is latched; explicit reload loses cache reuse, not the external session ledger.
use crate::{
    anchored::{capture, AnchorCore},
    randomness, AnchorBinding, Error, Limits, ProofStatement, PublicPackage, RowDeltas, Transition,
    UpdatingMaterial, ValidatedAssignment,
};
use ark_bn254::{Fr, G1Projective as G1};
use ark_ec::CurveGroup;
use ark_ff::Zero;
use ark_serialize::CanonicalSerialize;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Write, mem::size_of, sync::Arc};

const CACHE: usize = 4;
const MISSES: usize = 2;
const ATTEMPTS: usize = 8;

/// Ceilings do not authorize work on an unsupported relation or change the fixed 4/2/8 policy.
#[derive(Clone, Copy, Debug)]
pub struct SelectiveConfig {
    pub operation: Limits,
    pub max_anchor_delta_entries: usize,
    pub max_touched_entries: usize,
    pub max_chunk_actions: usize,
    /// These row/group/field ceilings cover direct-entry materialization only.
    /// Correction is bounded separately, and full calls bound their declared MSM/FFT work.
    pub max_call_row_visits: usize,
    pub max_call_group_calls: usize,
    pub max_call_field_muls: usize,
    pub max_session_row_visits: usize,
    pub max_session_group_calls: usize,
    pub max_session_field_muls: usize,
    pub max_session_pair_visits: usize,
    pub max_correction_group_calls: usize,
    pub max_full_calls: usize,
    pub max_update_calls: usize,
    pub max_private_bytes: usize,
    pub max_total_bytes: usize,
}
impl SelectiveConfig {
    pub fn small() -> Self {
        Self {
            operation: Limits::small(),
            max_anchor_delta_entries: 1024,
            max_touched_entries: 16384,
            max_chunk_actions: 1024,
            max_call_row_visits: 2048,
            max_call_group_calls: 2050,
            max_call_field_muls: 4092,
            max_session_row_visits: 8192,
            max_session_group_calls: 8200,
            max_session_field_muls: 16368,
            max_session_pair_visits: 65536,
            max_correction_group_calls: 16384,
            max_full_calls: 256,
            max_update_calls: 1024,
            max_private_bytes: 32 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
        }
    }
    fn check(&self, p: &PublicPackage) -> Result<(), Error> {
        self.operation.package(p)?;
        if self.max_chunk_actions == 0 {
            return Err(Error::Bound("selective chunk actions"));
        }
        bytes(self.max_full_calls, full_inputs(p)?)?;
        bytes(self.max_full_calls, p.shape().assignment_len)?;
        bytes(self.max_update_calls, self.max_correction_group_calls)?;
        Ok(())
    }
}

/// Counts are aggregate only. Full/MSM/correction/validation/copy/touch reservations
/// conservatively charge dispatches including errors; validation can fail before a
/// reserved gather runs. Entry row/group/field counters record actual operations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SelectiveStats {
    pub attempts_started: usize,
    pub entry_rows: usize,
    pub entry_group_calls: usize,
    pub entry_field_muls: usize,
    pub entry_group_adds: usize,
    pub entry_field_adds: usize,
    pub entries_completed: usize,
    pub correction_group_calls_reserved: usize,
    pub correction_g2_calls_reserved: usize,
    pub correction_field_muls_reserved: usize,
    pub quadratic_pair_visits: usize,
    pub full_calls_started: usize,
    pub full_g1_msm_inputs_reserved: usize,
    pub full_g2_msm_inputs_reserved: usize,
    pub validation_entries_reserved: usize,
    pub assignment_copied_elements_reserved: usize,
    pub current_a_touched_entries_reserved: usize,
    pub current_b_touched_entries_reserved: usize,
    pub current_c_touched_entries_reserved: usize,
    pub anchor_delta_scanned_elements: usize,
    pub anchor_touched_entries_reserved: usize,
    pub accepted_updates: usize,
    pub updates_started: usize,
    pub cancellations: usize,
    pub reloads: usize,
}

/// An opaque caller-held ledger for one evaluation. It is neither Clone nor serializable.
/// Retain this object across an explicit reload/restart; losing it starts a new cold session,
/// rather than establishing durable resource accounting or rollback resistance.
pub struct SelectiveLedger {
    identity: Arc<()>,
    context: AnchorBinding,
    stats: SelectiveStats,
}
impl SelectiveLedger {
    pub fn stats(&self) -> SelectiveStats {
        self.stats
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectiveStatus {
    Selective,
    Busy,
    FullOnly,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectiveFullReason {
    Demand,
    Misses,
    Attempts,
    EntryWork,
    AnchorDelta,
    TouchedEntries,
    PairWork,
    CorrectionWork,
    AlreadyFull,
    BindingChanged,
    Reload,
}
pub enum SelectiveProgress {
    Pending {
        completed: usize,
        total: usize,
    },
    Committed {
        proof: ProofStatement,
        mode: SelectiveStatus,
        reason: Option<SelectiveFullReason>,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Projection {
    A,
    B,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Key {
    kind: Projection,
    row: usize,
}
#[derive(Clone, Copy)]
struct Entry {
    key: Key,
    value: G1,
    last_used: u64,
}
struct Frozen {
    core: AnchorCore,
    binding: AnchorBinding,
}
struct Current {
    assignment: ValidatedAssignment,
    binding: AnchorBinding,
    proof: ProofStatement,
}
struct EntryTask {
    key: Key,
    next: usize,
    finish: usize,
    started: bool,
    group: G1,
    scalar: Fr,
}
impl EntryTask {
    fn new(key: Key) -> Self {
        Self {
            key,
            next: 0,
            finish: 0,
            started: false,
            group: G1::zero(),
            scalar: Fr::zero(),
        }
    }
}
struct Pending {
    target: ValidatedAssignment,
    binding: AnchorBinding,
    delta: Vec<(usize, Fr)>,
    rows: RowDeltas,
    keys: [Option<Key>; CACHE],
    missing: [Option<Key>; MISSES],
    slots: [usize; MISSES],
    task: Option<EntryTask>,
    task_index: usize,
    staged: [Option<Entry>; MISSES],
    missing_count: usize,
    completed: usize,
    total: usize,
    r: Fr,
    s: Fr,
    tick: u64,
    statement: Option<ProofStatement>,
    output_public: Vec<Fr>,
    reason: Option<SelectiveFullReason>,
}

/// Serial owner; only complete committed proofs/bindings remain visible while an update is pending.
pub struct SelectiveState {
    package: PublicPackage,
    uk: UpdatingMaterial,
    config: SelectiveConfig,
    public_bytes: usize,
    anchor: Option<Frozen>,
    current: Current,
    cache: [Option<Entry>; CACHE],
    tick: u64,
    pending: Option<Pending>,
    session: Arc<()>,
    #[cfg(test)]
    fault_after_actions: Option<usize>,
}
impl SelectiveState {
    pub fn create<R: RngCore + CryptoRng + ?Sized>(
        p: &PublicPackage,
        uk: &UpdatingMaterial,
        assignment: ValidatedAssignment,
        binding: AnchorBinding,
        config: SelectiveConfig,
        rng: &mut R,
    ) -> Result<(Self, ProofStatement, SelectiveLedger), Error> {
        config.check(p)?;
        uk.check(p)?;
        binding.package_check(p)?;
        if binding.anchor_state != [0; 32] {
            return Err(Error::AnchorBinding);
        }
        if assignment.package != p.identity() {
            return Err(Error::AssignmentPackage);
        }
        let mut ledger = SelectiveLedger {
            identity: Arc::new(()),
            context: binding,
            stats: SelectiveStats::default(),
        };
        full_preflight(p, config, &ledger)?;
        let public_bytes = public_bytes(p, uk)?;
        let initial = add(
            bytes(assignment.values.capacity(), size_of::<Fr>())?,
            bytes(p.shape().assignment_len, size_of::<Fr>())?,
        )?;
        let initial_fixed = add(
            add(size_of::<Self>(), size_of::<SelectiveLedger>())?,
            add(size_of::<AnchorCore>(), bytes(2, size_of::<usize>())?)?,
        )?;
        let initial_extra = add(
            initial_fixed,
            bytes(
                add(
                    bytes(p.shape().domain_size, 2)?,
                    bytes(p.shape().instance_len - 1, 2)?,
                )?,
                size_of::<Fr>(),
            )?,
        )?;
        check_memory(
            config,
            public_bytes,
            add(add(initial, initial_extra)?, full_scratch(p)?)?,
        )?;
        let current_values = copy_fields(&assignment.values)?;
        let current_public = copy_fields(&assignment.values[1..p.shape().instance_len])?;
        let output_public = copy_fields(&current_public)?;
        let initial_peak = add(
            add(
                add(
                    bytes(assignment.values.capacity(), size_of::<Fr>())?,
                    bytes(current_values.capacity(), size_of::<Fr>())?,
                )?,
                bytes(
                    add(current_public.capacity(), output_public.capacity())?,
                    size_of::<Fr>(),
                )?,
            )?,
            add(
                add(full_scratch(p)?, initial_fixed)?,
                bytes(bytes(p.shape().domain_size, 2)?, size_of::<Fr>())?,
            )?,
        )?;
        check_memory(config, public_bytes, initial_peak)?;
        let (r, s) = randomness::blinders(rng)?;
        full_ticket(p, config, &mut ledger)?;
        let core = capture(p, assignment, r, s)?;
        let mut binding = binding;
        binding.anchor_state = core_token(&core, binding)?;
        ledger.context = binding;
        let proof = statement(&core, binding, current_public);
        let output = ProofStatement {
            proof: proof.proof.clone(),
            public_values: output_public,
            package: proof.package,
            generation: proof.generation,
        };
        ledger.stats.assignment_copied_elements_reserved = p.shape().assignment_len;
        let state = Self {
            package: p.clone(),
            uk: uk.clone(),
            config,
            public_bytes,
            anchor: Some(Frozen { core, binding }),
            current: Current {
                assignment: ValidatedAssignment {
                    package: p.identity(),
                    values: current_values,
                },
                binding,
                proof,
            },
            cache: [None; CACHE],
            tick: 0,
            pending: None,
            session: ledger.identity.clone(),
            #[cfg(test)]
            fault_after_actions: None,
        };
        check_memory(config, public_bytes, state.private_structural_bytes()?)?;
        Ok((state, output, ledger))
    }
    pub fn status(&self) -> SelectiveStatus {
        if self.pending.is_some() {
            SelectiveStatus::Busy
        } else if self.anchor.is_some() {
            SelectiveStatus::Selective
        } else {
            SelectiveStatus::FullOnly
        }
    }
    pub fn binding(&self) -> AnchorBinding {
        self.current.binding
    }
    pub fn current_proof(&self) -> &ProofStatement {
        &self.current.proof
    }
    pub fn cache_len(&self) -> usize {
        self.cache.iter().flatten().count()
    }
    pub fn shared_public_structural_bytes(&self) -> usize {
        self.public_bytes
    }
    pub fn private_structural_bytes(&self) -> Result<usize, Error> {
        let mut n = add(
            size_of::<Self>(),
            add(size_of::<SelectiveLedger>(), 2 * size_of::<usize>())?,
        )?;
        n = add(
            n,
            bytes(self.current.assignment.values.capacity(), size_of::<Fr>())?,
        )?;
        n = add(
            n,
            bytes(self.current.proof.public_values.capacity(), size_of::<Fr>())?,
        )?;
        if let Some(a) = &self.anchor {
            n = add(n, core_bytes(&a.core)?)?;
        }
        if let Some(p) = &self.pending {
            n = add(n, size_of::<Pending>())?;
            n = add(n, bytes(p.target.values.capacity(), size_of::<Fr>())?)?;
            n = add(n, bytes(p.delta.capacity(), size_of::<(usize, Fr)>())?)?;
            for v in [&p.rows.a, &p.rows.b, &p.rows.c] {
                n = add(n, bytes(v.capacity(), size_of::<(usize, Fr)>())?)?;
            }
            n = add(n, bytes(p.output_public.capacity(), size_of::<Fr>())?)?;
            if let Some(s) = &p.statement {
                n = add(n, bytes(s.public_values.capacity(), size_of::<Fr>())?)?;
            }
        }
        Ok(n)
    }
    fn ledger_check(&self, l: &SelectiveLedger) -> Result<(), Error> {
        if !Arc::ptr_eq(&self.session, &l.identity) || l.context != self.current.binding {
            Err(Error::AnchorBinding)
        } else {
            Ok(())
        }
    }
    pub fn begin_update<R: RngCore + CryptoRng + ?Sized>(
        &mut self,
        t: &Transition,
        l: &mut SelectiveLedger,
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        self.ledger_check(l)?;
        self.config.check(&self.package)?;
        self.uk.check(&self.package)?;
        if t.base != self.current.binding {
            return Err(Error::AnchorBinding);
        }
        if l.stats.updates_started >= self.config.max_update_calls {
            return Err(Error::Bound("selective update calls"));
        }
        self.current.binding.package_check(&self.package)?;
        if let Some(anchor) = &self.anchor {
            anchor.binding.package_check(&self.package)?;
            if anchor.binding.credential != t.base.credential
                || anchor.binding.action != t.base.action
                || anchor.core.a.len() != self.package.shape().domain_size
                || anchor.core.b.len() != self.package.shape().domain_size
            {
                return Err(Error::AnchorBinding);
            }
        }
        if t.normalized_count() > self.config.operation.max_delta_entries {
            return Err(Error::Bound("selective current delta entries"));
        }
        for &(j, x) in &t.delta {
            if j >= self.package.shape().assignment_len {
                return Err(Error::DeltaCoordinate);
            }
            if j == 0 && !x.is_zero() {
                return Err(Error::ConstantMutation);
            }
        }
        let p = &self.package;
        let base = self.private_structural_bytes()?;
        check_memory(
            self.config,
            self.public_bytes,
            add(base, validation_bound(p, t)?)?,
        )?;
        checked_bump(&mut l.stats.updates_started, 1)?;
        validation_ticket(p, current_touches(p, t)?, l)?;
        let prepared = t.validate_target(p, &self.current.assignment)?;
        // Current->target gathering was paid by T2. Drop it before allocating anchor-relative outputs.
        let target = prepared.target;
        drop(prepared.rows);
        let target_bytes = bytes(target.values.capacity(), size_of::<Fr>())?;
        let mut reason = if self.anchor.is_none() {
            Some(SelectiveFullReason::AlreadyFull)
        } else {
            None
        };
        let mut delta = Vec::new();
        let mut rows = RowDeltas::default();
        let mut keys = [None; CACHE];
        let mut missing = [None; MISSES];
        let mut missing_count = 0;
        let mut pairs = 0;
        if let Some(anchor) = &self.anchor {
            // Compare the complete immutable anchor to the validated target on every call.
            checked_bump(
                &mut l.stats.anchor_delta_scanned_elements,
                p.shape().assignment_len,
            )?;
            let count = anchor
                .core
                .assignment
                .values
                .iter()
                .zip(&target.values)
                .filter(|(a, b)| a != b)
                .count();
            if count > self.config.max_anchor_delta_entries {
                reason = Some(SelectiveFullReason::AnchorDelta);
            }
            if reason.is_none() {
                check_memory(
                    self.config,
                    self.public_bytes,
                    add(
                        add(base, target_bytes)?,
                        bytes(count, size_of::<(usize, Fr)>())?,
                    )?,
                )?;
                delta = reserved(count)?;
                checked_bump(
                    &mut l.stats.anchor_delta_scanned_elements,
                    p.shape().assignment_len,
                )?;
                for (i, (a, b)) in anchor
                    .core
                    .assignment
                    .values
                    .iter()
                    .zip(&target.values)
                    .enumerate()
                {
                    if a != b {
                        if i == 0 {
                            return Err(Error::ConstantMutation);
                        }
                        delta.push((i, *b - *a));
                    }
                }
                let (touch, alloc) = anchor_gather_bound(p, &delta)?;
                if touch > self.config.max_touched_entries {
                    reason = Some(SelectiveFullReason::TouchedEntries);
                }
                if reason.is_none() {
                    let peak = add(
                        add(
                            add(base, target_bytes)?,
                            bytes(delta.capacity(), size_of::<(usize, Fr)>())?,
                        )?,
                        alloc,
                    )?;
                    check_memory(self.config, self.public_bytes, peak)?;
                    checked_bump(&mut l.stats.anchor_touched_entries_reserved, touch)?;
                    rows.a = gather(&p.0.columns[0], &delta)?;
                    rows.b = gather(&p.0.columns[1], &delta)?;
                    let demand = add(rows.a.len(), rows.b.len())?;
                    if demand > CACHE {
                        reason = Some(SelectiveFullReason::Demand);
                    }
                    if reason.is_none() {
                        let mut ix = 0;
                        for &(row, _) in &rows.b {
                            keys[ix] = Some(Key {
                                kind: Projection::A,
                                row,
                            });
                            ix += 1;
                        }
                        for &(row, _) in &rows.a {
                            keys[ix] = Some(Key {
                                kind: Projection::B,
                                row,
                            });
                            ix += 1;
                        }
                        let mut cold_count = 0;
                        for &key in keys.iter().flatten() {
                            if !self.cache.iter().flatten().any(|e| e.key == key) {
                                if cold_count < MISSES {
                                    missing[cold_count] = Some(key);
                                }
                                cold_count += 1;
                            }
                        }
                        if cold_count > MISSES {
                            reason = Some(SelectiveFullReason::Misses);
                        } else {
                            missing_count = cold_count;
                        }
                        pairs = bytes(rows.a.len(), rows.b.len())?;
                        if pairs > self.config.operation.max_pair_work
                            || add(l.stats.quadratic_pair_visits, pairs)?
                                > self.config.max_session_pair_visits
                        {
                            reason = Some(SelectiveFullReason::PairWork);
                        }
                        if reason.is_none()
                            && add(l.stats.attempts_started, missing_count)? > ATTEMPTS
                        {
                            reason = Some(SelectiveFullReason::Attempts);
                        }
                        if reason.is_none()
                            && !entry_budget(
                                self.config,
                                l.stats,
                                p.shape().domain_size,
                                missing_count,
                            )?
                        {
                            reason = Some(SelectiveFullReason::EntryWork);
                        }
                        let private = delta
                            .iter()
                            .filter(|(i, _)| *i >= p.shape().instance_len)
                            .count();
                        let diagonal = rows
                            .a
                            .iter()
                            .filter(|(i, _)| rows.b.binary_search_by_key(i, |x| x.0).is_ok())
                            .count();
                        let correction = add(
                            add(add(bytes(delta.len(), 2)?, private)?, 7)?,
                            add(bytes(demand, 2)?, diagonal)?,
                        )?;
                        if correction > self.config.max_correction_group_calls {
                            reason = Some(SelectiveFullReason::CorrectionWork);
                        }
                    }
                }
            }
        }
        if reason.is_some() {
            delta = Vec::new();
            rows = RowDeltas::default();
            keys = [None; CACHE];
            missing = [None; MISSES];
            missing_count = 0;
        }
        let mut staged_bytes = add(base, target_bytes)?;
        staged_bytes = add(
            staged_bytes,
            bytes(delta.capacity(), size_of::<(usize, Fr)>())?,
        )?;
        for v in [&rows.a, &rows.b] {
            staged_bytes = add(staged_bytes, bytes(v.capacity(), size_of::<(usize, Fr)>())?)?;
        }
        staged_bytes = add(staged_bytes, size_of::<Pending>())?;
        staged_bytes = add(
            staged_bytes,
            bytes(p.shape().instance_len - 1, 2 * size_of::<Fr>())?,
        )?;
        staged_bytes = add(
            staged_bytes,
            bytes(add(rows.a.len(), rows.b.len())?, size_of::<Fr>())?,
        )?;
        if reason.is_some() {
            staged_bytes = add(
                staged_bytes,
                add(
                    full_scratch(p)?,
                    bytes(p.shape().assignment_len, size_of::<Fr>())?,
                )?,
            )?;
            full_preflight(p, self.config, l)?;
        }
        check_memory(self.config, self.public_bytes, staged_bytes)?;
        let output_public = copy_fields(&target.values[1..p.shape().instance_len])?;
        let mut current_public = copy_fields(&output_public)?;
        let tick = self
            .tick
            .checked_add(1)
            .ok_or(Error::Bound("selective LRU clock"))?;
        let slots = cache_slots(&self.cache, &keys, missing_count)?;
        let total = add(bytes(missing_count, add(p.shape().domain_size, 2)?)?, 1)?;
        let mut full_copy = if reason.is_some() {
            Some(ValidatedAssignment {
                package: target.package,
                values: copy_fields(&target.values)?,
            })
        } else {
            None
        };
        if full_copy.is_some() {
            checked_bump(
                &mut l.stats.assignment_copied_elements_reserved,
                p.shape().assignment_len,
            )?;
        }
        let mut actual_stage = add(add(base, target_bytes)?, size_of::<Pending>())?;
        actual_stage = add(
            actual_stage,
            bytes(delta.capacity(), size_of::<(usize, Fr)>())?,
        )?;
        for v in [&rows.a, &rows.b] {
            actual_stage = add(actual_stage, bytes(v.capacity(), size_of::<(usize, Fr)>())?)?;
        }
        actual_stage = add(
            actual_stage,
            bytes(
                add(output_public.capacity(), current_public.capacity())?,
                size_of::<Fr>(),
            )?,
        )?;
        if let Some(copy) = &full_copy {
            actual_stage = add(
                actual_stage,
                bytes(copy.values.capacity(), size_of::<Fr>())?,
            )?;
        }
        if reason.is_some() {
            actual_stage = add(actual_stage, full_scratch(p)?)?;
        } else {
            actual_stage = add(
                actual_stage,
                bytes(add(rows.a.len(), rows.b.len())?, size_of::<Fr>())?,
            )?;
        }
        check_memory(self.config, self.public_bytes, actual_stage)?;
        let (r, s) = randomness::blinders(rng)?;
        let mut binding = self.current.binding;
        binding.generation = t.generation;
        binding.anchor_state = transition_token(
            binding,
            self.current.binding.anchor_state,
            &t.delta,
            &current_public,
            r,
            s,
        )?;
        let full_statement = if reason.is_some() {
            full_ticket(p, self.config, l)?;
            let core = capture(p, full_copy.take().unwrap(), r, s)?;
            Some(statement(
                &core,
                binding,
                std::mem::take(&mut current_public),
            ))
        } else {
            None
        };
        let mut pending = Pending {
            target,
            binding,
            delta,
            rows,
            keys,
            missing,
            slots,
            task: None,
            task_index: 0,
            staged: [None; MISSES],
            missing_count,
            completed: 0,
            total,
            r,
            s,
            tick,
            statement: full_statement,
            output_public,
            reason,
        };
        if pending.reason.is_none() {
            // The second public vector was allocated before entropy; retain it in the staged statement.
            pending.statement = Some(ProofStatement {
                proof: self.current.proof.proof.clone(),
                public_values: current_public,
                package: p.identity(),
                generation: t.generation,
            });
        }
        self.pending = Some(pending);
        let actual = self.private_structural_bytes()?;
        if let Err(e) = check_memory(self.config, self.public_bytes, actual) {
            self.pending = None;
            return Err(e);
        }
        let _ = pairs;
        Ok(())
    }
    pub fn advance_update(
        &mut self,
        budget: usize,
        l: &mut SelectiveLedger,
    ) -> Result<SelectiveProgress, Error> {
        self.ledger_check(l)?;
        if budget > self.config.max_chunk_actions {
            return Err(Error::Bound("selective chunk actions"));
        }
        let pending = self.pending.as_ref().ok_or(Error::NotReady)?;
        if budget == 0 {
            return Ok(SelectiveProgress::Pending {
                completed: pending.completed,
                total: pending.total,
            });
        }
        match self.advance_inner(budget, l) {
            Ok(x) => Ok(x),
            Err(e) => {
                self.pending = None;
                checked_bump(&mut l.stats.cancellations, 1)?;
                Err(e)
            }
        }
    }
    fn advance_inner(
        &mut self,
        budget: usize,
        l: &mut SelectiveLedger,
    ) -> Result<SelectiveProgress, Error> {
        let n = self.package.shape().domain_size;
        for _ in 0..budget {
            let pending = self.pending.as_mut().ok_or(Error::NotReady)?;
            #[cfg(test)]
            if self.fault_after_actions == Some(pending.completed) {
                return Err(Error::Cancelled);
            }
            if pending.reason.is_some() || pending.task_index == pending.missing_count {
                if pending.reason.is_none() {
                    let anchor = self.anchor.as_ref().ok_or(Error::NotReady)?;
                    let (a, b1, b2, c) = correct(
                        &self.package,
                        &self.uk,
                        &anchor.core,
                        pending,
                        &self.cache,
                        self.config,
                        l,
                    )?;
                    let s = pending.statement.as_mut().ok_or(Error::NotReady)?;
                    s.proof = ordinary::Proof {
                        a: a.into_affine(),
                        b: b2.into_affine(),
                        c: c.into_affine(),
                    };
                    let _ = b1;
                }
                pending.completed = add(pending.completed, 1)?;
                if pending.completed != pending.total {
                    return Err(Error::Bound("selective action cursor"));
                }
                checked_bump(&mut l.stats.accepted_updates, 1)?;
                if pending.reason == Some(SelectiveFullReason::Reload) {
                    checked_bump(&mut l.stats.reloads, 1)?;
                }
                let mut pending = self.pending.take().unwrap();
                let proof = pending.statement.take().ok_or(Error::NotReady)?;
                let output = ProofStatement {
                    proof: proof.proof.clone(),
                    public_values: pending.output_public,
                    package: proof.package,
                    generation: proof.generation,
                };
                if pending.reason.is_some() {
                    self.anchor = None;
                    self.cache = [None; CACHE];
                } else {
                    for e in self.cache.iter_mut().flatten() {
                        if pending.keys.contains(&Some(e.key)) {
                            e.last_used = pending.tick;
                        }
                    }
                    for i in 0..pending.missing_count {
                        self.cache[pending.slots[i]] = pending.staged[i].take();
                    }
                }
                self.tick = pending.tick;
                l.context = pending.binding;
                self.current = Current {
                    assignment: pending.target,
                    binding: pending.binding,
                    proof,
                };
                let mode = if self.anchor.is_some() {
                    SelectiveStatus::Selective
                } else {
                    SelectiveStatus::FullOnly
                };
                return Ok(SelectiveProgress::Committed {
                    proof: output,
                    mode,
                    reason: pending.reason,
                });
            }
            let anchor = self.anchor.as_ref().ok_or(Error::NotReady)?;
            if pending.task.is_none() {
                pending.task = Some(EntryTask::new(
                    pending.missing[pending.task_index].ok_or(Error::NotReady)?,
                ));
            }
            let task = pending.task.as_mut().unwrap();
            if !task.started {
                if l.stats.attempts_started >= ATTEMPTS {
                    return Err(Error::Bound("selective attempts"));
                }
                checked_bump(&mut l.stats.attempts_started, 1)?;
                task.started = true;
            }
            let values = match task.key.kind {
                Projection::A => &anchor.core.a,
                Projection::B => &anchor.core.b,
            };
            entry_step(task, values, &self.uk, n, l)?;
            pending.completed = add(pending.completed, 1)?;
            if task.next == n && task.finish == 2 {
                pending.staged[pending.task_index] = Some(Entry {
                    key: task.key,
                    value: task.group,
                    last_used: pending.tick,
                });
                pending.task_index = add(pending.task_index, 1)?;
                pending.task = None;
                checked_bump(&mut l.stats.entries_completed, 1)?;
            }
        }
        let p = self.pending.as_ref().unwrap();
        Ok(SelectiveProgress::Pending {
            completed: p.completed,
            total: p.total,
        })
    }
    pub fn cancel_update(&mut self, l: &mut SelectiveLedger) -> Result<(), Error> {
        self.ledger_check(l)?;
        if self.pending.is_none() {
            return Err(Error::NotReady);
        }
        checked_bump(&mut l.stats.cancellations, 1)?;
        self.pending = None;
        Ok(())
    }
    pub fn update<R: RngCore + CryptoRng + ?Sized>(
        &mut self,
        t: &Transition,
        l: &mut SelectiveLedger,
        rng: &mut R,
    ) -> Result<ProofStatement, Error> {
        self.begin_update(t, l, rng)?;
        loop {
            if let SelectiveProgress::Committed { proof, .. } =
                self.advance_update(self.config.max_chunk_actions, l)?
            {
                return Ok(proof);
            }
        }
    }
    /// Stage a fresh validated full proof in a new holder/action context. No old selective value is reused.
    pub fn begin_full_for_binding<R: RngCore + CryptoRng + ?Sized>(
        &mut self,
        assignment: ValidatedAssignment,
        credential: [u8; 32],
        action: [u8; 32],
        generation: u64,
        l: &mut SelectiveLedger,
        rng: &mut R,
    ) -> Result<(), Error> {
        if generation <= self.current.binding.generation {
            return Err(Error::Generation);
        }
        let binding = AnchorBinding::new(&self.package, credential, action, generation);
        self.begin_full(
            assignment,
            binding,
            SelectiveFullReason::BindingChanged,
            l,
            rng,
        )
    }
    /// A reload request intentionally loses selective reuse on positive commit. Zero remains a no-op.
    pub fn begin_reload<R: RngCore + CryptoRng + ?Sized>(
        &mut self,
        l: &mut SelectiveLedger,
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        self.ledger_check(l)?;
        let base = self.private_structural_bytes()?;
        let extra = bytes(self.current.assignment.values.capacity(), size_of::<Fr>())?;
        check_memory(
            self.config,
            self.public_bytes,
            add(add(base, extra)?, full_scratch(&self.package)?)?,
        )?;
        checked_bump(
            &mut l.stats.assignment_copied_elements_reserved,
            self.package.shape().assignment_len,
        )?;
        let a = ValidatedAssignment {
            package: self.current.assignment.package,
            values: copy_fields(&self.current.assignment.values)?,
        };
        self.begin_full(a, self.current.binding, SelectiveFullReason::Reload, l, rng)
    }
    fn begin_full<R: RngCore + CryptoRng + ?Sized>(
        &mut self,
        assignment: ValidatedAssignment,
        mut binding: AnchorBinding,
        reason: SelectiveFullReason,
        l: &mut SelectiveLedger,
        rng: &mut R,
    ) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        self.ledger_check(l)?;
        self.config.check(&self.package)?;
        binding.package_check(&self.package)?;
        if assignment.package != self.package.identity() {
            return Err(Error::AssignmentPackage);
        }
        if l.stats.updates_started >= self.config.max_update_calls {
            return Err(Error::Bound("selective update calls"));
        }
        full_preflight(&self.package, self.config, l)?;
        let peak = add(
            add(
                self.private_structural_bytes()?,
                bytes(assignment.values.capacity(), size_of::<Fr>())?,
            )?,
            add(
                add(full_scratch(&self.package)?, size_of::<Pending>())?,
                bytes(
                    add(
                        self.package.shape().assignment_len,
                        bytes(self.package.shape().instance_len - 1, 2)?,
                    )?,
                    size_of::<Fr>(),
                )?,
            )?,
        )?;
        check_memory(self.config, self.public_bytes, peak)?;
        checked_bump(&mut l.stats.updates_started, 1)?;
        validation_ticket(&self.package, [0; 3], l)?;
        let public = copy_fields(&assignment.values[1..self.package.shape().instance_len])?;
        let output_public = copy_fields(&public)?;
        let copied = copy_fields(&assignment.values)?;
        let target = self.package.validate_values(copied, &public)?;
        let actual_peak = add(
            add(
                add(
                    self.private_structural_bytes()?,
                    bytes(assignment.values.capacity(), size_of::<Fr>())?,
                )?,
                bytes(target.values.capacity(), size_of::<Fr>())?,
            )?,
            add(
                add(full_scratch(&self.package)?, size_of::<Pending>())?,
                bytes(
                    add(public.capacity(), output_public.capacity())?,
                    size_of::<Fr>(),
                )?,
            )?,
        )?;
        check_memory(self.config, self.public_bytes, actual_peak)?;
        let tick = self
            .tick
            .checked_add(1)
            .ok_or(Error::Bound("selective LRU clock"))?;
        let (r, s) = randomness::blinders(rng)?;
        full_ticket(&self.package, self.config, l)?;
        let core = capture(&self.package, assignment, r, s)?;
        binding.anchor_state = core_token(&core, binding)?;
        let proof = statement(&core, binding, public);
        self.pending = Some(Pending {
            target,
            binding,
            delta: Vec::new(),
            rows: RowDeltas::default(),
            keys: [None; CACHE],
            missing: [None; MISSES],
            slots: [0; MISSES],
            task: None,
            task_index: 0,
            staged: [None; MISSES],
            missing_count: 0,
            completed: 0,
            total: 1,
            r,
            s,
            tick,
            statement: Some(proof),
            output_public,
            reason: Some(reason),
        });
        Ok(())
    }
    /// Cold-engine recovery deliberately takes full mode. This preserves only an externally retained
    /// evaluation ledger, not authenticated cached state or application freshness. Drop the old
    /// engine first; a caller retaining it must account for that external allocation separately.
    pub fn full_after_restart<R: RngCore + CryptoRng + ?Sized>(
        p: &PublicPackage,
        uk: &UpdatingMaterial,
        assignment: ValidatedAssignment,
        mut binding: AnchorBinding,
        config: SelectiveConfig,
        l: &mut SelectiveLedger,
        rng: &mut R,
    ) -> Result<(Self, ProofStatement), Error> {
        config.check(p)?;
        uk.check(p)?;
        binding.package_check(p)?;
        if l.context != binding {
            return Err(Error::AnchorBinding);
        }
        if assignment.package != p.identity() {
            return Err(Error::AssignmentPackage);
        }
        full_preflight(p, config, l)?;
        let public_bytes = public_bytes(p, uk)?;
        check_memory(
            config,
            public_bytes,
            add(
                bytes(assignment.values.capacity(), 2 * size_of::<Fr>())?,
                add(
                    add(
                        full_scratch(p)?,
                        add(size_of::<Self>(), size_of::<SelectiveLedger>())?,
                    )?,
                    bytes(bytes(p.shape().instance_len - 1, 2)?, size_of::<Fr>())?,
                )?,
            )?,
        )?;
        validation_ticket(p, [0; 3], l)?;
        let public = copy_fields(&assignment.values[1..p.shape().instance_len])?;
        let output_public = copy_fields(&public)?;
        let target = p.validate_values(copy_fields(&assignment.values)?, &public)?;
        let actual_peak = add(
            add(
                bytes(
                    add(assignment.values.capacity(), target.values.capacity())?,
                    size_of::<Fr>(),
                )?,
                bytes(
                    add(public.capacity(), output_public.capacity())?,
                    size_of::<Fr>(),
                )?,
            )?,
            add(
                full_scratch(p)?,
                add(size_of::<Self>(), size_of::<SelectiveLedger>())?,
            )?,
        )?;
        check_memory(config, public_bytes, actual_peak)?;
        let (r, s) = randomness::blinders(rng)?;
        full_ticket(p, config, l)?;
        let core = capture(p, assignment, r, s)?;
        binding.anchor_state = core_token(&core, binding)?;
        let proof = statement(&core, binding, public);
        let output = ProofStatement {
            proof: proof.proof.clone(),
            public_values: output_public,
            package: proof.package,
            generation: proof.generation,
        };
        checked_bump(&mut l.stats.reloads, 1)?;
        l.context = binding;
        let state = Self {
            package: p.clone(),
            uk: uk.clone(),
            config,
            public_bytes,
            anchor: None,
            current: Current {
                assignment: target,
                binding,
                proof,
            },
            cache: [None; CACHE],
            tick: 0,
            pending: None,
            session: l.identity.clone(),
            #[cfg(test)]
            fault_after_actions: None,
        };
        Ok((state, output))
    }
}

fn entry_step(
    t: &mut EntryTask,
    a: &[Fr],
    uk: &UpdatingMaterial,
    n: usize,
    l: &mut SelectiveLedger,
) -> Result<(), Error> {
    if a.len() != n || t.key.row >= n || t.next > n || t.finish > 2 {
        return Err(Error::Bound("selective entry cursor"));
    }
    if t.next < n {
        let j = t.next;
        let i = t.key.row;
        checked_bump(&mut l.stats.entry_rows, 1)?;
        if i != j {
            let ij = if i >= j { i - j } else { n - (j - i) };
            let ji = if j >= i { j - i } else { n - (i - j) };
            checked_bump(&mut l.stats.entry_field_muls, 2)?;
            checked_bump(&mut l.stats.entry_group_calls, 1)?;
            checked_bump(&mut l.stats.entry_group_adds, 1)?;
            checked_bump(&mut l.stats.entry_field_adds, 1)?;
            t.group += uk.0.lagrange[j] * (a[j] * uk.0.weights[ij]);
            t.scalar += a[j] * uk.0.weights[ji];
        }
        t.next = add(t.next, 1)?;
    } else if t.finish < 2 {
        checked_bump(&mut l.stats.entry_group_calls, 1)?;
        checked_bump(&mut l.stats.entry_group_adds, 1)?;
        if t.finish == 0 {
            t.group += uk.0.lagrange[t.key.row] * t.scalar;
        } else {
            t.group += uk.0.diagonal[t.key.row] * a[t.key.row];
        }
        t.finish = add(t.finish, 1)?;
    } else {
        return Err(Error::Bound("selective completed entry"));
    }
    Ok(())
}
fn correct(
    p: &PublicPackage,
    uk: &UpdatingMaterial,
    core: &AnchorCore,
    x: &Pending,
    cache: &[Option<Entry>; CACHE],
    c: SelectiveConfig,
    l: &mut SelectiveLedger,
) -> Result<(G1, G1, ark_bn254::G2Projective, G1), Error> {
    let find = |kind, row| -> Result<G1, Error> {
        let key = Key { kind, row };
        cache
            .iter()
            .chain(x.staged.iter())
            .flatten()
            .find(|e| e.key == key)
            .map(|e| e.value)
            .ok_or(Error::Bound("selective typed entry"))
    };
    // Validate every lookup before group work, including its A/B orientation.
    for &(i, _) in &x.rows.a {
        find(Projection::B, i)?;
    }
    for &(i, _) in &x.rows.b {
        find(Projection::A, i)?;
    }
    let pairs = bytes(x.rows.a.len(), x.rows.b.len())?;
    let diagonal = x
        .rows
        .a
        .iter()
        .filter(|(i, _)| x.rows.b.binary_search_by_key(i, |v| v.0).is_ok())
        .count();
    let private = x
        .delta
        .iter()
        .filter(|(i, _)| *i >= p.shape().instance_len)
        .count();
    let count = add(
        add(add(bytes(x.delta.len(), 2)?, private)?, 7)?,
        add(bytes(add(x.rows.a.len(), x.rows.b.len())?, 2)?, diagonal)?,
    )?;
    if count > c.max_correction_group_calls {
        return Err(Error::Bound("selective correction calls"));
    }
    checked_bump(&mut l.stats.correction_group_calls_reserved, count)?;
    checked_bump(
        &mut l.stats.correction_g2_calls_reserved,
        add(x.delta.len(), 1)?,
    )?;
    checked_bump(
        &mut l.stats.correction_field_muls_reserved,
        add(
            add(bytes(pairs, 2)?, add(x.rows.a.len(), x.rows.b.len())?)?,
            5,
        )?,
    )?;
    checked_bump(&mut l.stats.quadratic_pair_visits, pairs)?;
    let pk = &p.0.pk;
    let mut a = core.a_g1 + pk.delta_g1 * (x.r - core.r);
    let mut b1 = core.b_g1 + pk.delta_g1 * (x.s - core.s);
    let mut b2 = core.b_g2 + pk.vk.delta_g2 * (x.s - core.s);
    let mut private = G1::zero();
    for &(i, d) in &x.delta {
        a += pk.u_g1[i] * d;
        b1 += pk.v_g1[i] * d;
        b2 += pk.v_g2[i] * d;
        if i >= p.shape().instance_len {
            private += pk.t_p_g1[i - p.shape().instance_len] * d;
        }
    }
    let mut quotient = uk.cross(&x.rows.a, &x.rows.b, c.operation.max_pair_work)?;
    for &(i, d) in &x.rows.a {
        quotient += find(Projection::B, i)? * d;
    }
    for &(i, d) in &x.rows.b {
        quotient += find(Projection::A, i)? * d;
    }
    let c1 = core.c_g1 + a * x.s - core.a_g1 * core.s + b1 * x.r
        - core.b_g1 * core.r
        - pk.delta_g1 * (x.r * x.s - core.r * core.s)
        + private
        + quotient;
    Ok((a, b1, b2, c1))
}
fn entry_budget(
    c: SelectiveConfig,
    s: SelectiveStats,
    n: usize,
    missing: usize,
) -> Result<bool, Error> {
    let rows = bytes(missing, n)?;
    let groups = bytes(missing, add(n, 1)?)?;
    let fields = bytes(bytes(missing, 2)?, n - 1)?;
    Ok(rows <= c.max_call_row_visits
        && groups <= c.max_call_group_calls
        && fields <= c.max_call_field_muls
        && add(s.entry_rows, rows)? <= c.max_session_row_visits
        && add(s.entry_group_calls, groups)? <= c.max_session_group_calls
        && add(s.entry_field_muls, fields)? <= c.max_session_field_muls)
}
fn cache_slots(
    cache: &[Option<Entry>; CACHE],
    keys: &[Option<Key>; CACHE],
    count: usize,
) -> Result<[usize; MISSES], Error> {
    let mut out = [0; MISSES];
    for i in 0..count {
        let mut best = None;
        for (j, e) in cache.iter().enumerate() {
            if out[..i].contains(&j) || e.is_some_and(|e| keys.contains(&Some(e.key))) {
                continue;
            }
            let age = e.map_or(0, |e| e.last_used);
            if best.is_none_or(|(_, old)| age < old) {
                best = Some((j, age));
            }
        }
        out[i] = best.ok_or(Error::Bound("selective pinned cache"))?.0;
    }
    Ok(out)
}
fn full_preflight(p: &PublicPackage, c: SelectiveConfig, l: &SelectiveLedger) -> Result<(), Error> {
    c.operation.package(p)?;
    if l.stats.full_calls_started >= c.max_full_calls {
        return Err(Error::Bound("selective full calls"));
    }
    add(l.stats.full_g1_msm_inputs_reserved, full_inputs(p)?)?;
    add(
        l.stats.full_g2_msm_inputs_reserved,
        p.shape().assignment_len,
    )?;
    Ok(())
}
fn full_ticket(
    p: &PublicPackage,
    c: SelectiveConfig,
    l: &mut SelectiveLedger,
) -> Result<(), Error> {
    full_preflight(p, c, l)?;
    checked_bump(&mut l.stats.full_calls_started, 1)?;
    checked_bump(&mut l.stats.full_g1_msm_inputs_reserved, full_inputs(p)?)?;
    checked_bump(
        &mut l.stats.full_g2_msm_inputs_reserved,
        p.shape().assignment_len,
    )?;
    Ok(())
}
fn full_inputs(p: &PublicPackage) -> Result<usize, Error> {
    add(
        add(
            bytes(p.shape().assignment_len, 2)?,
            p.shape().assignment_len - p.shape().instance_len,
        )?,
        p.shape().domain_size - 1,
    )
}
fn matrix_entries(p: &PublicPackage) -> Result<usize, Error> {
    let m = &p.0.matrices;
    add(add(m.a_num_non_zero, m.b_num_non_zero)?, m.c_num_non_zero)
}
fn current_touches(p: &PublicPackage, t: &Transition) -> Result<[usize; 3], Error> {
    let mut touched = [0; 3];
    for (matrix, columns) in p.0.columns.iter().enumerate() {
        for &(j, _) in &t.delta {
            touched[matrix] = add(
                touched[matrix],
                columns.get(j).ok_or(Error::DeltaCoordinate)?.len(),
            )?;
        }
    }
    Ok(touched)
}
// Reserve the complete streaming validation and every possible T2 gather before dispatch.
// A rejected public statement/early unsatisfied row can use less than this reservation.
fn validation_ticket(
    p: &PublicPackage,
    touches: [usize; 3],
    l: &mut SelectiveLedger,
) -> Result<(), Error> {
    let mut next = l.stats;
    checked_bump(&mut next.validation_entries_reserved, matrix_entries(p)?)?;
    checked_bump(
        &mut next.assignment_copied_elements_reserved,
        p.shape().assignment_len,
    )?;
    checked_bump(&mut next.current_a_touched_entries_reserved, touches[0])?;
    checked_bump(&mut next.current_b_touched_entries_reserved, touches[1])?;
    checked_bump(&mut next.current_c_touched_entries_reserved, touches[2])?;
    l.stats = next;
    Ok(())
}
fn statement(core: &AnchorCore, b: AnchorBinding, public_values: Vec<Fr>) -> ProofStatement {
    ProofStatement {
        proof: ordinary::Proof {
            a: core.a_g1.into_affine(),
            b: core.b_g2.into_affine(),
            c: core.c_g1.into_affine(),
        },
        public_values,
        package: b.package,
        generation: b.generation,
    }
}
fn gather(columns: &[Vec<(usize, Fr)>], delta: &[(usize, Fr)]) -> Result<Vec<(usize, Fr)>, Error> {
    let mut sums = BTreeMap::<usize, Fr>::new();
    for &(j, d) in delta {
        for &(i, c) in &columns[j] {
            *sums.entry(i).or_default() += c * d;
        }
    }
    let mut out = reserved(sums.len())?;
    out.extend(sums.into_iter().filter(|(_, v)| !v.is_zero()));
    Ok(out)
}
fn anchor_gather_bound(p: &PublicPackage, delta: &[(usize, Fr)]) -> Result<(usize, usize), Error> {
    let mut count = 0;
    let mut alloc = 0;
    for columns in &p.0.columns[..2] {
        let mut touched = 0;
        for &(j, _) in delta {
            touched = add(touched, columns[j].len())?;
        }
        count = add(count, touched)?;
        // Bound each tree plus its output, and the earlier output retained during the next gather.
        alloc = add(
            alloc,
            add(
                bytes(
                    touched.min(p.shape().domain_size),
                    256 + size_of::<(usize, Fr)>(),
                )?,
                768,
            )?,
        )?;
    }
    Ok((count, alloc))
}
fn validation_bound(p: &PublicPackage, t: &Transition) -> Result<usize, Error> {
    let mut out = bytes(p.shape().assignment_len, size_of::<Fr>())?;
    for columns in &p.0.columns {
        let mut touched = 0;
        for &(j, _) in &t.delta {
            touched = add(touched, columns.get(j).ok_or(Error::DeltaCoordinate)?.len())?;
        }
        // Include a doubling output Vec alongside all earlier outputs and tree nodes.
        out = add(
            out,
            add(
                bytes(
                    touched.min(p.shape().domain_size),
                    256 + 2 * size_of::<(usize, Fr)>(),
                )?,
                768,
            )?,
        )?;
    }
    // Complete relation validation itself is a streaming dot product, not an N-field result.
    Ok(out)
}
fn full_scratch(p: &PublicPackage) -> Result<usize, Error> {
    add(
        bytes(p.shape().domain_size, 2048)?,
        bytes(p.shape().assignment_len, 128)?,
    )
}
fn core_bytes(c: &AnchorCore) -> Result<usize, Error> {
    add(
        size_of::<AnchorCore>(),
        bytes(
            add(
                add(c.assignment.values.capacity(), c.a.capacity())?,
                c.b.capacity(),
            )?,
            size_of::<Fr>(),
        )?,
    )
}
fn check_memory(c: SelectiveConfig, public: usize, private: usize) -> Result<(), Error> {
    if private > c.max_private_bytes {
        return Err(Error::Bound("selective private bytes"));
    }
    if add(private, public)? > c.max_total_bytes {
        return Err(Error::Bound("selective total bytes"));
    }
    Ok(())
}
fn public_bytes(p: &PublicPackage, uk: &UpdatingMaterial) -> Result<usize, Error> {
    let mut out = add(
        add(
            size_of::<crate::artifact::PackageInner>(),
            size_of::<crate::anchored::MaterialInner>(),
        )?,
        bytes(4, size_of::<usize>())?, // both shared Arc allocation headers
    )?;
    for v in [&uk.0.lagrange, &uk.0.diagonal] {
        out = add(out, bytes(v.capacity(), size_of::<G1>())?)?;
    }
    out = add(out, bytes(uk.0.weights.capacity(), size_of::<Fr>())?)?;
    let pk = &p.0.pk;
    for v in [
        &pk.u_g1,
        &pk.v_g1,
        &pk.t_p_g1,
        &pk.tau_powers_g1,
        &pk.vk.t_v_g1,
    ] {
        out = add(out, bytes(v.capacity(), size_of::<ark_bn254::G1Affine>())?)?;
    }
    out = add(
        out,
        bytes(pk.v_g2.capacity(), size_of::<ark_bn254::G2Affine>())?,
    )?;
    for matrix in [&p.0.matrices.a, &p.0.matrices.b, &p.0.matrices.c] {
        out = add(
            out,
            bytes(matrix.capacity(), size_of::<Vec<(Fr, usize)>>())?,
        )?;
        for row in matrix {
            out = add(out, bytes(row.capacity(), size_of::<(Fr, usize)>())?)?;
        }
    }
    for columns in &p.0.columns {
        out = add(
            out,
            bytes(columns.capacity(), size_of::<Vec<(usize, Fr)>>())?,
        )?;
        for col in columns {
            out = add(out, bytes(col.capacity(), size_of::<(usize, Fr)>())?)?;
        }
    }
    Ok(out)
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
fn hash_binding(h: &mut Sha256, b: AnchorBinding) {
    for d in [
        b.package.matrix_digest,
        b.package.circuit_digest,
        b.package.proving_key_digest,
        b.package.verifying_key_digest,
        b.package.package_digest,
        b.credential,
        b.action,
    ] {
        h.update(d);
    }
    h.update((b.domain_size as u64).to_le_bytes());
    h.update(b.generation.to_le_bytes());
}
fn core_token(c: &AnchorCore, b: AnchorBinding) -> Result<[u8; 32], Error> {
    let mut h = HashWriter(Sha256::new());
    h.0.update(b"dynark-bn254/selective-anchor/v1");
    hash_binding(&mut h.0, b);
    c.assignment.values.serialize_compressed(&mut h)?;
    c.a.serialize_compressed(&mut h)?;
    c.b.serialize_compressed(&mut h)?;
    c.a_g1.serialize_compressed(&mut h)?;
    c.b_g1.serialize_compressed(&mut h)?;
    c.b_g2.serialize_compressed(&mut h)?;
    c.c_g1.serialize_compressed(&mut h)?;
    c.r.serialize_compressed(&mut h)?;
    c.s.serialize_compressed(&mut h)?;
    Ok(h.0.finalize().into())
}
fn transition_token(
    b: AnchorBinding,
    old: [u8; 32],
    delta: &[(usize, Fr)],
    public: &[Fr],
    r: Fr,
    s: Fr,
) -> Result<[u8; 32], Error> {
    let mut h = HashWriter(Sha256::new());
    h.0.update(b"dynark-bn254/selective-transition/v1");
    hash_binding(&mut h.0, b);
    h.0.update(old);
    h.0.update((delta.len() as u64).to_le_bytes());
    for &(i, d) in delta {
        h.0.update((i as u64).to_le_bytes());
        d.serialize_compressed(&mut h)?;
    }
    h.0.update((public.len() as u64).to_le_bytes());
    for f in public {
        f.serialize_compressed(&mut h)?;
    }
    r.serialize_compressed(&mut h)?;
    s.serialize_compressed(&mut h)?;
    Ok(h.0.finalize().into())
}
fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b)
        .ok_or(Error::Bound("selective arithmetic overflow"))
}
fn bytes(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b)
        .ok_or(Error::Bound("selective arithmetic overflow"))
}
fn checked_bump(a: &mut usize, b: usize) -> Result<(), Error> {
    *a = add(*a, b)?;
    Ok(())
}
fn reserved<T>(n: usize) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| Error::Bound("selective allocation"))?;
    Ok(v)
}
fn copy_fields(a: &[Fr]) -> Result<Vec<Fr>, Error> {
    let mut out = reserved(a.len())?;
    out.extend_from_slice(a);
    Ok(out)
}

#[cfg(test)]
#[path = "../tests/private/selective_private.rs"]
mod tests;
