use super::*;
use crate::persistence::{
    self as p, wire::*, AdmissionMetrics, ExpectedContext, LoadPolicy, PersistenceError,
};
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use zeroize::{Zeroize, Zeroizing};
type PResult<T> = p::Result<T>;
pub(crate) fn package(s: &DynamicState) -> &PublicPackage {
    &s.package
}
pub(crate) fn tables(s: &DynamicState) -> &ReconstructionMaterial {
    &s.tables
}
pub(crate) struct HeaderMeta {
    pub(crate) binding: AnchorBinding,
    pub(crate) mode: u8,
    pub(crate) active_generation: u64,
    pub(crate) builder_generation: u64,
    pub(crate) config: [u8; 32],
    pub(crate) statement: [u8; 32],
}
fn statement(p: &PublicPackage, b: &AnchorBinding, values: &[Fr]) -> PResult<[u8; 32]> {
    let mut h = p::HashWriter(Sha256::new());
    h.0.update(b"dynark-bn254/persistence-public/v1");
    h.0.update(p.identity().package_digest);
    h.0.update(b.generation.to_le_bytes());
    h.0.update((values.len() as u64).to_le_bytes());
    for f in values {
        f.serialize_compressed(&mut h).map_err(Error::from)?;
    }
    Ok(h.0.finalize().into())
}
fn config(c: DynamicConfig) -> [u8; 128] {
    let mut out = [0; 128];
    put16(&mut out, 0, 1);
    put16(&mut out, 2, 128);
    out[4] = if c.cap_policy == CapPolicy::Reject {
        0
    } else {
        1
    };
    put16(&mut out, 6, 1);
    put64(&mut out, 8, c.threshold);
    for (j, x) in [
        c.operation.max_domain,
        c.operation.max_assignment,
        c.operation.max_matrix_entries,
        c.operation.max_delta_entries,
        c.operation.max_pair_work,
        c.operation.max_allocation_bytes,
        c.max_row_support,
        c.max_total_pair_visits,
        c.max_private_bytes,
        c.max_global_bytes,
        c.max_journal_bytes,
        c.max_transaction_actions,
    ]
    .iter()
    .enumerate()
    {
        put64(&mut out, 16 + 8 * j, *x as u64);
    }
    out
}
pub(crate) fn header_meta(s: &DynamicState) -> PResult<HeaderMeta> {
    let binding = s.binding()?;
    Ok(HeaderMeta {
        binding,
        mode: if s.root.active.is_some() { 1 } else { 2 },
        active_generation: s.root.active.as_ref().map_or(0, |x| x.generation),
        builder_generation: s.root.builder.as_ref().map_or(0, |x| x.generation),
        config: digest(b"dynark-bn254/persistence-config/v1", &config(s.config)),
        statement: statement(
            &s.package,
            &binding,
            &s.root.current.assignment.values[1..s.package.shape().instance_len],
        )?,
    })
}
fn maps(s: &DynamicState) -> ([Option<&Map>; 6], usize) {
    match (&s.root.active, &s.root.builder) {
        (Some(a), Some(b)) => (
            [
                Some(&a.maps[0]),
                Some(&a.maps[1]),
                Some(&b.overlays[0]),
                Some(&b.overlays[1]),
                Some(&b.pending[0]),
                Some(&b.pending[1]),
            ],
            6,
        ),
        _ => ([None; 6], 0),
    }
}
fn map_ids(s: &DynamicState) -> ([u8; 6], [Option<&Map>; 6], usize) {
    let (refs, len) = maps(s);
    let mut ids = [255; 6];
    let mut objects = [None; 6];
    let mut k = 0;
    for j in 0..len {
        let map = refs[j].unwrap();
        let id = (0..k)
            .find(|&i| Arc::ptr_eq(map, objects[i].unwrap()))
            .unwrap_or_else(|| {
                objects[k] = Some(map);
                k += 1;
                k - 1
            });
        ids[j] = id as u8;
    }
    (ids, objects, k)
}
fn phase_tag(phase: ReconstructionPhase) -> u8 {
    match phase {
        ReconstructionPhase::InitialReadyAlias => 0,
        ReconstructionPhase::Materialize => 1,
        ReconstructionPhase::Prepare => 2,
        ReconstructionPhase::Forward => 3,
        ReconstructionPhase::Pointwise => 4,
        ReconstructionPhase::Inverse => 5,
        ReconstructionPhase::Scale => 6,
        ReconstructionPhase::Integrate => 7,
        ReconstructionPhase::Ready => 8,
    }
}
fn phase(x: u8) -> PResult<ReconstructionPhase> {
    Ok(match x {
        0 => ReconstructionPhase::InitialReadyAlias,
        1 => ReconstructionPhase::Materialize,
        2 => ReconstructionPhase::Prepare,
        3 => ReconstructionPhase::Forward,
        4 => ReconstructionPhase::Pointwise,
        5 => ReconstructionPhase::Inverse,
        6 => ReconstructionPhase::Scale,
        7 => ReconstructionPhase::Integrate,
        8 => ReconstructionPhase::Ready,
        _ => return Err(PersistenceError::Unsupported("cursor phase")),
    })
}
fn cursor_bytes(c: &Cursor) -> [u8; 96] {
    let mut b = [0; 96];
    put16(&mut b, 0, 1);
    put16(&mut b, 2, 96);
    b[4] = phase_tag(c.phase);
    put64(&mut b, 8, c.done as u64);
    put64(&mut b, 16, c.group_scalar_calls);
    put64(&mut b, 24, c.field_mul_calls);
    for (j, x) in c.persistence_parts().iter().enumerate() {
        put64(&mut b, 32 + 8 * j, *x as u64);
    }
    b
}
fn ledger_values(l: WorkLedger) -> [u64; 19] {
    [
        l.initialization_actions,
        l.adopted_cells,
        l.header_actions,
        l.attempted_reconstruction_actions,
        l.committed_reconstruction_actions,
        l.attempted_group_scalar_calls,
        l.attempted_field_mul_calls,
        l.committed_group_scalar_calls,
        l.committed_field_mul_calls,
        l.validation_entries,
        l.assignment_copied_elements,
        l.map_merge_elements,
        l.quadratic_pair_visits,
        l.group_preimages,
        l.field_preimages,
        l.mark_clear_visits,
        l.rollback_cells,
        l.full_fallbacks,
        l.completed_distinct_snapshots,
    ]
}
fn ledger(a: [u64; 19], saturated: bool) -> WorkLedger {
    WorkLedger {
        saturated,
        initialization_actions: a[0],
        adopted_cells: a[1],
        header_actions: a[2],
        attempted_reconstruction_actions: a[3],
        committed_reconstruction_actions: a[4],
        attempted_group_scalar_calls: a[5],
        attempted_field_mul_calls: a[6],
        committed_group_scalar_calls: a[7],
        committed_field_mul_calls: a[8],
        validation_entries: a[9],
        assignment_copied_elements: a[10],
        map_merge_elements: a[11],
        quadratic_pair_visits: a[12],
        group_preimages: a[13],
        field_preimages: a[14],
        mark_clear_visits: a[15],
        rollback_cells: a[16],
        full_fallbacks: a[17],
        completed_distinct_snapshots: a[18],
    }
}
fn root_bytes(s: &DynamicState, k: usize, ids: [u8; 6]) -> PResult<[u8; 256]> {
    let r = &s.root;
    let mut b = [0; 256];
    put16(&mut b, 0, 1);
    put16(&mut b, 2, 256);
    b[4] = if r.active.is_some() { 1 } else { 2 };
    b[5] = if r.active.is_some() { 3 } else { 0 };
    put64(&mut b, 8, r.distance);
    put64(&mut b, 16, r.t);
    put64(
        &mut b,
        24,
        reconstruction::work(s.package.shape().domain_size)? as u64,
    );
    if let (Some(a), Some(builder)) = (&r.active, &r.builder) {
        for (offset, x) in [
            (32, a.generation),
            (40, a.distance),
            (80, builder.generation),
            (88, builder.distance),
        ] {
            put64(&mut b, offset, x);
        }
        b[48..80].copy_from_slice(&a.token);
        b[96..128].copy_from_slice(&builder.token);
        for (j, x) in builder.source.iter().enumerate() {
            b[136 + j] = *x as u8;
        }
        let n = s.package.shape().domain_size;
        put64(&mut b, 152, n as u64);
        put64(&mut b, 160, mark_words(n)? as u64);
    } else {
        b[136..138].fill(255);
    }
    for (j, x) in r
        .roles
        .active_g
        .into_iter()
        .chain(r.roles.build_g)
        .chain(r.roles.active_f)
        .chain(r.roles.build_f)
        .enumerate()
    {
        b[128 + j] = u8::try_from(x).map_err(|_| PersistenceError::Malformed("role host"))?;
    }
    b[138..144].copy_from_slice(&ids);
    b[144] = k as u8;
    Ok(b)
}
fn mark_words(n: usize) -> PResult<usize> {
    Ok(p::add(p::mul(n, 10)?, 63)? / 64)
}
fn write_value<T: CanonicalSerialize>(x: &T, b: &mut [u8]) -> PResult<()> {
    if x.compressed_size() != b.len() {
        return Err(PersistenceError::Unsupported("canonical width"));
    }
    x.serialize_compressed(b).map_err(Error::from)?;
    Ok(())
}
#[derive(Clone, Copy, Default)]
struct Section {
    offset: usize,
    len: usize,
    count: usize,
}
#[derive(Clone, Copy, Default)]
struct MapWire {
    offset: usize,
    count: usize,
}
struct Scan {
    sections: [Section; 9],
    maps: [MapWire; 6],
    k: usize,
    ids: [u8; 6],
    roles: Roles,
    cursor: Option<Cursor>,
    decoded: usize,
    scratch: usize,
}
fn sized(b: &[u8], len: usize) -> PResult<()> {
    if b.len() != len || u16_at(b, 0)? != 1 || u16_at(b, 2)? != len as u16 {
        return Err(PersistenceError::Malformed("section version/size"));
    }
    Ok(())
}
fn sections(b: &[u8]) -> PResult<[Section; 9]> {
    if b.len() < 320
        || &b[..8] != b"DYNARKS1"
        || u16_at(b, 8)? != 1
        || u16_at(b, 10)? != 32
        || u16_at(b, 12)? != 9
        || u64_at(b, 16)? != b.len() as u64
    {
        return Err(PersistenceError::Malformed("payload framing"));
    }
    zero(b, 14, 16)?;
    zero(b, 24, 32)?;
    let mut out = [Section::default(); 9];
    let mut end = 320;
    for (j, s) in out.iter_mut().enumerate() {
        let i = 32 + 32 * j;
        if u16_at(b, i)? != (j + 1) as u16 || u16_at(b, i + 2)? != 1 {
            return Err(PersistenceError::Unsupported("section tags/version"));
        }
        zero(b, i + 4, i + 8)?;
        *s = Section {
            count: count(b, i + 8)?,
            offset: count(b, i + 16)?,
            len: count(b, i + 24)?,
        };
        if s.offset != end {
            return Err(PersistenceError::Malformed("section contiguity"));
        }
        end = p::add(end, s.len)?;
        if end > b.len() {
            return Err(PersistenceError::Malformed("section bounds"));
        }
    }
    if end != b.len() {
        return Err(PersistenceError::Malformed("payload EOF"));
    }
    Ok(out)
}
fn section<'a>(b: &'a [u8], s: Section) -> &'a [u8] {
    &b[s.offset..s.offset + s.len]
}
fn permutation(a: &[u8]) -> bool {
    let mut seen = [false; 4];
    for &x in a {
        if x >= 4 || seen[x as usize] {
            return false;
        }
        seen[x as usize] = true;
    }
    true
}
fn scan(
    b: &[u8],
    h: &[u8; 1024],
    pkg: &PublicPackage,
    tables: &ReconstructionMaterial,
    c: &ExpectedContext,
    policy: &LoadPolicy,
    m: &mut AdmissionMetrics,
) -> PResult<Scan> {
    let sections = sections(b)?;
    let dynamic = h[36] == 1;
    let n = c.shape.domain_size;
    let v = c.shape.assignment_len;
    let root = section(b, sections[0]);
    let conf = section(b, sections[1]);
    let account = section(b, sections[2]);
    sized(root, 256)?;
    sized(conf, 128)?;
    sized(account, 192)?;
    if conf != config(policy.config)
        || digest(b"dynark-bn254/persistence-config/v1", conf) != bytes::<32>(h, 848)?
    {
        return Err(PersistenceError::Trust("reload configuration"));
    }
    policy.config.check(pkg)?;
    for (start, end) in [(6, 8), (145, 152), (168, 256)] {
        zero(root, start, end)?;
    }
    zero(account, 6, 8)?;
    zero(account, 176, 192)?;
    if account[4] > 1
        || account[5] > 1
        || root[4] != h[36]
        || root[5] != if dynamic { 3 } else { 0 }
        || u64_at(root, 24)? != reconstruction::work(n)? as u64
    {
        return Err(PersistenceError::Malformed("root/accounting"));
    }
    if !permutation(&root[128..132]) || !permutation(&root[132..136]) {
        return Err(PersistenceError::Malformed("role permutation"));
    }
    let roles = Roles {
        active_g: [root[128] as usize, root[129] as usize],
        build_g: [root[130] as usize, root[131] as usize],
        active_f: [root[132] as usize, root[133] as usize],
        build_f: [root[134] as usize, root[135] as usize],
    };
    let k = root[144] as usize;
    let ids: [u8; 6] = root[138..144].try_into().unwrap();
    let expected_counts = [
        1,
        1,
        1,
        v,
        1,
        k,
        if dynamic { p::mul(n, 4)? } else { 0 },
        if dynamic { p::mul(n, 6)? } else { 0 },
        usize::from(dynamic),
    ];
    let expected_lengths = [
        Some(256),
        Some(128),
        Some(192),
        Some(p::mul(v, 32)?),
        Some(224),
        None,
        Some(if dynamic { p::mul(n, 128)? } else { 0 }),
        Some(if dynamic { p::mul(n, 192)? } else { 0 }),
        Some(if dynamic { 96 } else { 0 }),
    ];
    for j in 0..9 {
        if sections[j].count != expected_counts[j]
            || expected_lengths[j].is_some_and(|x| x != sections[j].len)
        {
            return Err(PersistenceError::Malformed("section count/length"));
        }
    }
    let mut objects = [MapWire::default(); 6];
    let mut entries = 0;
    let mut cursor = None;
    if dynamic {
        if !(1..=6).contains(&k)
            || root[136..138] != [roles.active_f[0] as u8, roles.active_f[1] as u8]
            || count(root, 152)? != n
            || count(root, 160)? != mark_words(n)?
        {
            return Err(PersistenceError::Malformed("pool/source"));
        }
        let mut discovered = 0usize;
        for &id in &ids {
            if id as usize > discovered || id as usize >= k {
                return Err(PersistenceError::Malformed("map reference"));
            }
            if id as usize == discovered {
                discovered += 1;
            }
        }
        if discovered != k {
            return Err(PersistenceError::Malformed("unreferenced map"));
        }
        let maps = section(b, sections[5]);
        let mut pos = 0;
        for (j, obj) in objects.iter_mut().enumerate().take(k) {
            if maps.get(pos) != Some(&(j as u8)) {
                return Err(PersistenceError::Malformed("map ID"));
            }
            zero(maps, pos + 1, p::add(pos, 8)?)?;
            let len = count(maps, p::add(pos, 8)?)?;
            if len > policy.config.max_row_support || len > n {
                return Err(PersistenceError::Bound("map support"));
            }
            pos = p::add(pos, 16)?;
            *obj = MapWire {
                offset: p::add(sections[5].offset, pos)?,
                count: len,
            };
            let end = p::add(pos, p::mul(len, 40)?)?;
            if end > maps.len() {
                return Err(PersistenceError::Malformed("map length"));
            }
            entries = p::add(entries, len)?;
            pos = end;
        }
        if pos != maps.len() {
            return Err(PersistenceError::Malformed("map EOF"));
        }
        let logical = ids
            .iter()
            .try_fold(0usize, |a, id| p::add(a, objects[*id as usize].count))?;
        if entries > policy.max_map_scan || logical > policy.max_map_scan {
            return Err(PersistenceError::Bound("distinct/logical map scan"));
        }
        for object in objects.iter().take(k) {
            let mut previous = None;
            for j in 0..object.count {
                m.map_scan_entries = p::add(m.map_scan_entries, 1)?;
                let pos = object.offset + 40 * j;
                let index = count(b, pos)?;
                if index >= n
                    || previous.is_some_and(|old| index <= old)
                    || b[pos + 8..pos + 40].iter().all(|x| *x == 0)
                {
                    return Err(PersistenceError::Malformed("map index/order/zero"));
                }
                previous = Some(index);
            }
        }
        let cb = section(b, sections[8]);
        sized(cb, 96)?;
        zero(cb, 5, 8)?;
        zero(cb, 72, 96)?;
        let parts = [
            count(cb, 32)?,
            count(cb, 40)?,
            count(cb, 48)?,
            count(cb, 56)?,
            count(cb, 64)?,
        ];
        let cur = Cursor::persistence_new(
            phase(cb[4])?,
            count(cb, 8)?,
            u64_at(cb, 16)?,
            u64_at(cb, 24)?,
            parts,
        );
        let overlays = [objects[ids[2] as usize], objects[ids[3] as usize]];
        let mut neighbors = [[None; 2]; 2];
        for side in 0..2 {
            let used = parts[3 + side];
            if used > overlays[side].count {
                return Err(PersistenceError::Malformed("overlay count"));
            }
            if used > 0 {
                neighbors[side][0] = Some(count(b, overlays[side].offset + 40 * (used - 1))?);
            }
            if used < overlays[side].count {
                neighbors[side][1] = Some(count(b, overlays[side].offset + 40 * used)?);
            }
        }
        reconstruction::validate_cursor_metadata(
            &cur,
            n,
            [overlays[0].count, overlays[1].count],
            neighbors,
        )?;
        let distance = u64_at(root, 8)?;
        let credit = u64_at(root, 16)?;
        let ag = u64_at(root, 32)?;
        let ad = u64_at(root, 40)?;
        let bg = u64_at(root, 80)?;
        let bd = u64_at(root, 88)?;
        let generation = u64_at(h, 120)?;
        let threshold = policy.config.threshold;
        if credit >= threshold
            || credit != distance % threshold
            || ad > bd
            || bd > distance
            || ag > bg
            || bg > generation
            || distance - ad > threshold * 4
            || ag != u64_at(h, 128)?
            || bg != u64_at(h, 136)?
        {
            return Err(PersistenceError::Malformed("scheduler namespace"));
        }
        if cur.phase == ReconstructionPhase::InitialReadyAlias {
            if distance >= threshold
                || ad != 0
                || bd != 0
                || ag != bg
                || bytes::<32>(root, 48)? != bytes::<32>(root, 96)?
            {
                return Err(PersistenceError::Malformed("alias metadata"));
            }
        } else if bd < distance - credit {
            return Err(PersistenceError::Malformed("builder freeze distance"));
        }
        for (gen, token, refs) in [
            (ag, bytes::<32>(root, 48)?, [ids[0], ids[1]]),
            (bg, bytes::<32>(root, 96)?, [ids[4], ids[5]]),
        ] {
            if gen == generation
                && (token != bytes::<32>(h, 432)?
                    || refs.iter().any(|id| objects[*id as usize].count != 0))
            {
                return Err(PersistenceError::Malformed("same-generation correction"));
            }
        }
        cursor = Some(cur);
    } else {
        zero(root, 32, 128)?;
        if u64_at(root, 16)? != 0
            || root[136..144] != [255; 8]
            || k != 0
            || u64_at(root, 152)? != 0
            || u64_at(root, 160)? != 0
            || sections[5].len != 0
            || account[5] != 0
            || u64_at(account, 160)? != 0
            || u64_at(account, 168)? != 0
        {
            return Err(PersistenceError::Malformed("FullOnly absent state"));
        }
    }
    let logical = if dynamic {
        ids.iter()
            .try_fold(0usize, |a, id| p::add(a, objects[*id as usize].count))?
    } else {
        0
    };
    check_work_counts(pkg, dynamic, entries, logical, policy)?;
    let decoded = p::add(
        p::add(
            if dynamic { p::mul(n, 576)? } else { 0 },
            p::mul(v, size_of::<Fr>())?,
        )?,
        p::add(
            p::mul(entries, size_of::<(usize, Fr)>())?,
            if dynamic {
                p::mul(mark_words(n)?, 8)?
            } else {
                0
            },
        )?,
    )?;
    let decoded = p::add(decoded, size_of::<Root>() + size_of::<Pending>() + 2048)?;
    let scratch = p::add(1024 * 1024, p::mul(c.shape.instance_len, 256)?)?;
    let peak = p::add(
        p::add(p::add(decoded, scratch)?, m.buffer_capacity.max(b.len()))?,
        policy.old_live_bytes,
    )?;
    policy.peak(peak, tables.0.public_bytes)?;
    m.private_peak = peak;
    Ok(Scan {
        sections,
        maps: objects,
        k,
        ids,
        roles,
        cursor,
        decoded,
        scratch,
    })
}
// Metadata-only bounds shared by save before allocation/normalization and
// the complete authenticated framing scan before decoded allocations.
fn check_work_counts(
    pkg: &PublicPackage,
    dynamic: bool,
    entries: usize,
    logical: usize,
    policy: &LoadPolicy,
) -> PResult<()> {
    if entries > policy.max_map_scan || logical > policy.max_map_scan {
        return Err(PersistenceError::Bound("distinct/logical map scan"));
    }
    let n = pkg.shape().domain_size;
    let v = pkg.shape().assignment_len;
    let groups = p::add(if dynamic { p::mul(n, 4)? } else { 0 }, 4)?;
    let fields = p::add(
        p::add(if dynamic { p::mul(n, 6)? } else { 0 }, v)?,
        p::add(entries, 2)?,
    )?;
    let scalar = p::add(p::mul(v, 3)?, 3)?;
    let matrices = &pkg.0.matrices;
    let matrix_entries = p::add(
        p::add(matrices.a_num_non_zero, matrices.b_num_non_zero)?,
        matrices.c_num_non_zero,
    )?;
    if groups > policy.max_group_checks
        || fields > policy.max_field_checks
        || scalar > policy.max_group_scalar_calls
        || p::mul(matrix_entries, 4)? > policy.max_matrix_entries
    {
        return Err(PersistenceError::Bound("decode/validation work"));
    }
    Ok(())
}
fn canonical<T: CanonicalDeserialize + CanonicalSerialize>(
    b: &[u8],
    group: bool,
    m: &mut AdmissionMetrics,
) -> PResult<T> {
    if group {
        m.group_checks = p::add(m.group_checks, 1)?;
    } else {
        m.field_checks = p::add(m.field_checks, 1)?;
    }
    let x = T::deserialize_compressed(b)
        .map_err(|_| PersistenceError::Malformed("canonical curve/subgroup/field"))?;
    let mut out = [0; 64];
    if b.len() > 64 {
        return Err(PersistenceError::Unsupported("canonical size"));
    }
    write_value(&x, &mut out[..b.len()])?;
    if out[..b.len()] != *b {
        return Err(PersistenceError::Malformed("noncanonical encoding"));
    }
    m.canonical_bytes = p::add(m.canonical_bytes, b.len())?;
    Ok(x)
}
fn validate_current(s: &DynamicState, public: &[Fr], m: &mut AdmissionMetrics) -> PResult<()> {
    let c = &s.root.current;
    let pkg = &s.package;
    let pk = &pkg.0.pk;
    let values = &c.assignment.values;
    if values.len() != pkg.shape().assignment_len
        || values[0] != Fr::ONE
        || values[1..pkg.shape().instance_len] != *public
    {
        return Err(PersistenceError::Malformed("assignment/public"));
    }
    let matrices = &pkg.0.matrices;
    for row in 0..pkg.shape().reduction_rows {
        let ev = |terms: &[(Fr, usize)]| terms.iter().map(|(x, j)| *x * values[*j]).sum::<Fr>();
        m.row_entries = p::add(
            m.row_entries,
            matrices.a[row].len() + matrices.b[row].len() + matrices.c[row].len(),
        )?;
        if ev(&matrices.a[row]) * ev(&matrices.b[row]) != ev(&matrices.c[row]) {
            return Err(PersistenceError::Malformed("assignment satisfaction"));
        }
    }
    let mut a = pk.vk.alpha_g1.into_group() + pk.delta_g1 * c.r;
    let mut b1 = pk.beta_g1.into_group() + pk.delta_g1 * c.s;
    let mut b2 = pk.vk.beta_g2.into_group() + pk.vk.delta_g2 * c.s;
    for (j, x) in values.iter().enumerate() {
        a += pk.u_g1[j] * *x;
        b1 += pk.v_g1[j] * *x;
        b2 += pk.v_g2[j] * *x;
    }
    m.group_scalar_calls = p::add(m.group_scalar_calls, p::add(p::mul(values.len(), 3)?, 3)?)?;
    if (a, b1, b2) != (c.a, c.b1, c.b2) {
        return Err(PersistenceError::Malformed("raw assignment/blinders"));
    }
    let proof = ordinary::Proof::<Bn254> {
        a: c.a.into_affine(),
        b: c.b2.into_affine(),
        c: c.c.into_affine(),
    };
    if !ordinary::Groth16::<Bn254>::verify_proof(
        &ordinary::prepare_verifying_key(&pkg.ordinary_verifying_key()),
        &proof,
        public,
    )
    .map_err(Error::Arithmetic)?
    {
        return Err(PersistenceError::Malformed("ordinary proof"));
    }
    if let (Some(active), Some(builder), Some(pool)) = (&s.root.active, &s.root.builder, &s.pool) {
        pool.validate(&s.root.roles, builder)?;
        reconstruction::validate_cursor(&builder.cursor, pool.n, &builder.overlays)?;
        for side in 0..2 {
            let (mut ai, mut oi, mut pi) = (0, 0, 0);
            let parts = builder.cursor.persistence_parts();
            for row in 0..pool.n {
                let take = |map: &Map, i: &mut usize| {
                    if map.get(*i).is_some_and(|x| x.0 == row) {
                        let x = map[*i].1;
                        *i += 1;
                        x
                    } else {
                        Fr::ZERO
                    }
                };
                let ac = take(&active.maps[side], &mut ai);
                let ov = take(&builder.overlays[side], &mut oi);
                let pending = take(&builder.pending[side], &mut pi);
                if ov + pending != ac {
                    return Err(PersistenceError::Malformed("overlay/pending relation"));
                }
                let current = if row < pkg.shape().reduction_rows {
                    let terms = if side == 0 {
                        &matrices.a[row]
                    } else {
                        &matrices.b[row]
                    };
                    m.row_entries = p::add(m.row_entries, terms.len())?;
                    terms.iter().map(|(x, j)| *x * values[*j]).sum::<Fr>()
                } else {
                    Fr::ZERO
                };
                let source = pool.f[s.root.roles.active_f[side]][row];
                if source + ac != current {
                    return Err(PersistenceError::Malformed("active row/map relation"));
                }
                if builder.cursor.phase != ReconstructionPhase::InitialReadyAlias
                    && (builder.cursor.phase != ReconstructionPhase::Materialize || row < parts[1])
                {
                    let frozen = pool.f[s.root.roles.build_f[side]][row];
                    if frozen != source + ov || frozen + pending != current {
                        return Err(PersistenceError::Malformed("materialized row relation"));
                    }
                }
            }
        }
    }
    Ok(())
}
pub(crate) fn encode(
    s: &DynamicState,
    c: &ExpectedContext,
    policy: &LoadPolicy,
    m: &mut AdmissionMetrics,
) -> PResult<Zeroizing<Vec<u8>>> {
    if s.pending.is_some() || !s.journal.persistence_clean() {
        return Err(PersistenceError::Engine(Error::Busy));
    }
    c.check(&s.package, &s.tables)?;
    if s.config.threshold != policy.config.threshold || config(s.config) != config(policy.config) {
        return Err(PersistenceError::Trust("save configuration"));
    }
    let n = c.shape.domain_size;
    let dynamic = s.root.active.is_some();
    if dynamic && (s.pool.is_none() || s.root.builder.is_none())
        || !dynamic && (s.pool.is_some() || s.root.builder.is_some())
    {
        return Err(PersistenceError::Malformed("committed mode"));
    }
    let (ids, objects, k) = map_ids(s);
    let mut map_len = 0;
    let mut entries = 0;
    for obj in objects.into_iter().take(k) {
        let len = obj.unwrap().len();
        entries = p::add(entries, len)?;
        map_len = p::add(map_len, p::add(16, p::mul(len, 40)?)?)?;
    }
    let (refs, logical_len) = maps(s);
    let logical = refs
        .into_iter()
        .take(logical_len)
        .try_fold(0usize, |a, obj| p::add(a, obj.unwrap().len()))?;
    check_work_counts(&s.package, dynamic, entries, logical, policy)?;
    let meta = header_meta(s)?;
    if meta.binding.credential != c.credential
        || meta.binding.action != c.action
        || s.root.current.assignment.package != c.identity
    {
        return Err(PersistenceError::Trust("save holder/action scope"));
    }
    let lengths = [
        256,
        128,
        192,
        p::mul(c.shape.assignment_len, 32)?,
        224,
        map_len,
        if dynamic { p::mul(n, 128)? } else { 0 },
        if dynamic { p::mul(n, 192)? } else { 0 },
        if dynamic { 96 } else { 0 },
    ];
    let counts = [
        1,
        1,
        1,
        c.shape.assignment_len,
        1,
        k,
        if dynamic { p::mul(n, 4)? } else { 0 },
        if dynamic { p::mul(n, 6)? } else { 0 },
        usize::from(dynamic),
    ];
    let total = lengths.iter().try_fold(320usize, |a, x| p::add(a, *x))?;
    if p::add(total, 1040)? > policy.max_record_bytes {
        return Err(PersistenceError::Bound("encoded record"));
    }
    let scratch = p::add(1024 * 1024, p::mul(c.shape.instance_len, 256)?)?;
    let peak = p::add(
        p::add(p::add(s.private_structural_bytes()?, total)?, scratch)?,
        policy.old_live_bytes,
    )?;
    policy.peak(peak, s.tables.0.public_bytes)?;
    let mut bytes = Zeroizing::new(p::reserve::<u8>(total)?);
    m.buffer_capacity = bytes.capacity();
    policy.peak(
        p::add(peak, bytes.capacity().saturating_sub(total))?,
        s.tables.0.public_bytes,
    )?;
    bytes.resize(total, 0);
    bytes[..8].copy_from_slice(b"DYNARKS1");
    put16(&mut bytes, 8, 1);
    put16(&mut bytes, 10, 32);
    put16(&mut bytes, 12, 9);
    put64(&mut bytes, 16, total as u64);
    let mut secs = [Section::default(); 9];
    let mut pos = 320;
    for j in 0..9 {
        let i = 32 + 32 * j;
        put16(&mut bytes, i, (j + 1) as u16);
        put16(&mut bytes, i + 2, 1);
        put64(&mut bytes, i + 8, counts[j] as u64);
        put64(&mut bytes, i + 16, pos as u64);
        put64(&mut bytes, i + 24, lengths[j] as u64);
        secs[j] = Section {
            offset: pos,
            len: lengths[j],
            count: counts[j],
        };
        pos += lengths[j];
    }
    bytes[secs[0].offset..secs[0].offset + 256].copy_from_slice(&root_bytes(s, k, ids)?);
    bytes[secs[1].offset..secs[1].offset + 128].copy_from_slice(&config(s.config));
    let a = &mut bytes[secs[2].offset..secs[2].offset + 192];
    put16(a, 0, 1);
    put16(a, 2, 192);
    a[4] = u8::from(s.ledger.saturated);
    a[5] = u8::from(s.journal.saturated);
    for (j, x) in ledger_values(s.ledger).iter().enumerate() {
        put64(a, 8 + 8 * j, *x);
    }
    put64(a, 160, s.journal.group_logs as u64);
    put64(a, 168, s.journal.field_logs as u64);
    for (j, x) in s.root.current.assignment.values.iter().enumerate() {
        write_value(
            x,
            &mut bytes[secs[3].offset + 32 * j..secs[3].offset + 32 * j + 32],
        )?;
    }
    let ccur = &s.root.current;
    let raw = &mut bytes[secs[4].offset..secs[4].offset + 224];
    write_value(&ccur.a, &mut raw[..32])?;
    write_value(&ccur.b1, &mut raw[32..64])?;
    write_value(&ccur.b2, &mut raw[64..128])?;
    write_value(&ccur.c, &mut raw[128..160])?;
    write_value(&ccur.r, &mut raw[160..192])?;
    write_value(&ccur.s, &mut raw[192..224])?;
    let mut pos = secs[5].offset;
    for (j, obj) in objects.into_iter().enumerate().take(k) {
        let obj = obj.unwrap();
        bytes[pos] = j as u8;
        put64(&mut bytes, pos + 8, obj.len() as u64);
        pos += 16;
        for &(i, x) in obj.iter() {
            put64(&mut bytes, pos, i as u64);
            write_value(&x, &mut bytes[pos + 8..pos + 40])?;
            pos += 40;
        }
    }
    if let Some(pool) = &s.pool {
        let mut pos = secs[6].offset;
        for slot in &pool.g {
            for x in slot {
                write_value(x, &mut bytes[pos..pos + 32])?;
                pos += 32;
            }
        }
        let mut pos = secs[7].offset;
        for slot in &pool.f {
            for x in slot {
                write_value(x, &mut bytes[pos..pos + 32])?;
                pos += 32;
            }
        }
    }
    if let Some(builder) = &s.root.builder {
        bytes[secs[8].offset..secs[8].offset + 96].copy_from_slice(&cursor_bytes(&builder.cursor));
    }
    let mut h = [0; 1024];
    h[36] = meta.mode;
    put64(&mut h, 120, meta.binding.generation);
    put64(&mut h, 128, meta.active_generation);
    put64(&mut h, 136, meta.builder_generation);
    h[432..464].copy_from_slice(&meta.binding.anchor_state);
    h[848..880].copy_from_slice(&meta.config);
    scan(&bytes, &h, &s.package, &s.tables, c, policy, m)?;
    validate_current(
        s,
        &s.root.current.assignment.values[1..s.package.shape().instance_len],
        m,
    )?;
    m.private_peak = m.private_peak.max(peak);
    m.canonical_bytes = p::add(m.canonical_bytes, total)?;
    Ok(bytes)
}
struct Quarantine(Option<DynamicState>);
impl Drop for Quarantine {
    fn drop(&mut self) {
        if let Some(s) = self.0.as_mut() {
            wipe_borrowed(s);
        }
    }
}
pub(crate) fn decode(
    b: &[u8],
    h: &[u8; 1024],
    pkg: &PublicPackage,
    tables: &ReconstructionMaterial,
    context: &ExpectedContext,
    policy: &LoadPolicy,
    public: &[Fr],
    m: &mut AdmissionMetrics,
) -> PResult<DynamicState> {
    context.check(pkg, tables)?;
    if public.len() != pkg.shape().instance_len - 1 {
        return Err(PersistenceError::Trust("expected public length"));
    }
    if expected_statement(pkg, u64_at(h, 120)?, public)? != bytes::<32>(h, 880)? {
        return Err(PersistenceError::Trust("expected public digest"));
    }
    let scan = scan(b, h, pkg, tables, context, policy, m)?;
    let mut actual = size_of::<Root>() + size_of::<Pending>() + 2048;
    let mut values = Zeroizing::new(p::reserve::<Fr>(pkg.shape().assignment_len)?);
    m.decoded_allocations += 1;
    actual = p::add(actual, p::mul(values.capacity(), size_of::<Fr>())?)?;
    let requested_peak = p::add(
        p::add(
            p::add(scan.decoded, scan.scratch)?,
            m.buffer_capacity.max(b.len()),
        )?,
        policy.old_live_bytes,
    )?;
    policy.peak(
        p::add(
            requested_peak,
            values.capacity().saturating_sub(pkg.shape().assignment_len) * size_of::<Fr>(),
        )?,
        tables.0.public_bytes,
    )?;
    let assignment = section(b, scan.sections[3]);
    for i in 0..pkg.shape().assignment_len {
        values.push(canonical::<Fr>(&assignment[32 * i..32 * i + 32], false, m)?);
    }
    // Check before moving ownership into the existing opaque validated constructor;
    // failed admissions keep the owned values in the zeroizing quarantine.
    if values[0] != Fr::ONE || values[1..pkg.shape().instance_len] != *public {
        return Err(PersistenceError::Malformed("assignment/public"));
    }
    for row in 0..pkg.shape().reduction_rows {
        let ev = |terms: &[(Fr, usize)]| terms.iter().map(|(x, j)| *x * values[*j]).sum::<Fr>();
        let mat = &pkg.0.matrices;
        m.row_entries = p::add(
            m.row_entries,
            mat.a[row].len() + mat.b[row].len() + mat.c[row].len(),
        )?;
        if ev(&mat.a[row]) * ev(&mat.b[row]) != ev(&mat.c[row]) {
            return Err(PersistenceError::Malformed("assignment satisfaction"));
        }
    }
    let mat = &pkg.0.matrices;
    m.row_entries = p::add(
        m.row_entries,
        p::add(
            p::add(mat.a_num_non_zero, mat.b_num_non_zero)?,
            mat.c_num_non_zero,
        )?,
    )?;
    let mut validated = SensitiveAssignment(Some(
        pkg.validate_values(std::mem::take(&mut *values), public)?,
    ));
    let raw = section(b, scan.sections[4]);
    let a = canonical::<G1Affine>(&raw[..32], true, m)?.into_group();
    let b1 = canonical::<G1Affine>(&raw[32..64], true, m)?.into_group();
    let b2 = canonical::<G2Affine>(&raw[64..128], true, m)?.into_group();
    let c = canonical::<G1Affine>(&raw[128..160], true, m)?.into_group();
    let r = canonical::<Fr>(&raw[160..192], false, m)?;
    let s = canonical::<Fr>(&raw[192..224], false, m)?;
    let binding = AnchorBinding {
        package: pkg.identity(),
        domain_size: pkg.shape().domain_size,
        credential: context.credential,
        action: context.action,
        generation: u64_at(h, 120)?,
        anchor_state: bytes::<32>(h, 432)?,
    };
    let root = section(b, scan.sections[0]);
    let acc = section(b, scan.sections[2]);
    let mut counters = [0; 19];
    for (j, x) in counters.iter_mut().enumerate() {
        *x = u64_at(acc, 8 + 8 * j)?;
    }
    let mut state = Quarantine(Some(DynamicState {
        package: pkg.clone(),
        tables: tables.clone(),
        config: policy.config,
        pool: None,
        journal: Journal::empty(Vec::new()),
        root: Root {
            current: Current {
                assignment: Arc::new(validated.0.take().unwrap()),
                binding,
                a,
                b1,
                b2,
                c,
                r,
                s,
            },
            active: None,
            builder: None,
            roles: scan.roles,
            t: u64_at(root, 16)?,
            distance: u64_at(root, 8)?,
        },
        pending: None,
        ledger: ledger(counters, acc[4] == 1),
    }));
    let state_ref = state.0.as_mut().unwrap();
    let mut objects = MapObjects(std::array::from_fn(|_| None));
    for j in 0..scan.k {
        let obj = scan.maps[j];
        let mut entries = Zeroizing::new(p::reserve::<(usize, Fr)>(obj.count)?);
        m.decoded_allocations += 1;
        actual = p::add(
            actual,
            p::mul(entries.capacity(), size_of::<(usize, Fr)>())?,
        )?;
        let peak = p::add(
            p::add(
                p::add(actual, scan.scratch)?,
                m.buffer_capacity.max(b.len()),
            )?,
            policy.old_live_bytes,
        )?;
        policy.peak(peak, tables.0.public_bytes)?;
        for i in 0..obj.count {
            let pos = obj.offset + 40 * i;
            let x = canonical::<Fr>(&b[pos + 8..pos + 40], false, m)?;
            if x.is_zero() {
                return Err(PersistenceError::Malformed("zero map"));
            }
            entries.push((count(b, pos)?, x));
        }
        objects.0[j] = Some(Arc::new(std::mem::take(&mut *entries)));
    }
    if scan.k != 0 {
        let get = |j: usize| objects.0[scan.ids[j] as usize].as_ref().unwrap().clone();
        state_ref.root.active = Some(Active {
            generation: u64_at(root, 32)?,
            distance: u64_at(root, 40)?,
            token: bytes::<32>(root, 48)?,
            maps: [get(0), get(1)],
        });
        state_ref.root.builder = Some(Builder {
            generation: u64_at(root, 80)?,
            distance: u64_at(root, 88)?,
            token: bytes::<32>(root, 96)?,
            source: state_ref.root.roles.active_f,
            overlays: [get(2), get(3)],
            pending: [get(4), get(5)],
            cursor: scan.cursor.unwrap(),
        });
        drop(objects);
        let n = pkg.shape().domain_size;
        let g = p::reserve::<G1>(n)?;
        let f = p::reserve::<Fr>(n)?;
        let pool = Pool {
            n,
            g: [g, p::reserve(n)?, p::reserve(n)?, p::reserve(n)?],
            f: [
                f,
                p::reserve(n)?,
                p::reserve(n)?,
                p::reserve(n)?,
                p::reserve(n)?,
                p::reserve(n)?,
            ],
        };
        m.decoded_allocations += 10;
        actual = p::add(actual, pool.bytes())?;
        let mut marks = p::reserve::<u64>(mark_words(n)?)?;
        m.decoded_allocations += 1;
        actual = p::add(actual, p::mul(marks.capacity(), 8)?)?;
        let peak = p::add(
            p::add(
                p::add(actual, scan.scratch)?,
                m.buffer_capacity.max(b.len()),
            )?,
            policy.old_live_bytes,
        )?;
        policy.peak(peak, tables.0.public_bytes)?;
        m.private_peak = m.private_peak.max(peak);
        state_ref.pool = Some(pool);
        let pool = state_ref.pool.as_mut().unwrap();
        let mut pos = scan.sections[6].offset;
        for slot in &mut pool.g {
            for _ in 0..n {
                slot.push(canonical::<G1Affine>(&b[pos..pos + 32], true, m)?.into_group());
                pos += 32;
            }
        }
        let mut pos = scan.sections[7].offset;
        for slot in &mut pool.f {
            for _ in 0..n {
                slot.push(canonical::<Fr>(&b[pos..pos + 32], false, m)?);
                pos += 32;
            }
        }
        marks.resize(mark_words(n)?, 0);
        state_ref.journal = Journal::empty(marks);
        state_ref.journal.saturated = acc[5] == 1;
        state_ref.journal.group_logs = count(acc, 160)?;
        state_ref.journal.field_logs = count(acc, 168)?;
    }
    validate_current(state_ref, public, m)?;
    if statement(pkg, &binding, public)? != bytes::<32>(h, 880)? {
        return Err(PersistenceError::Trust("public digest"));
    }
    Ok(state.0.take().unwrap())
}
pub(crate) fn wipe(mut s: DynamicState) {
    wipe_borrowed(&mut s);
}
pub(crate) fn wipe_borrowed(s: &mut DynamicState) {
    if let Some(pool) = s.pool.as_mut() {
        for slot in &mut pool.g {
            slot.zeroize();
        }
        for slot in &mut pool.f {
            slot.zeroize();
        }
    }
    if let Some(v) = Arc::get_mut(&mut s.root.current.assignment) {
        v.values.zeroize();
    }
    s.root.current.a.zeroize();
    s.root.current.b1.zeroize();
    s.root.current.b2.zeroize();
    s.root.current.c.zeroize();
    s.root.current.r.zeroize();
    s.root.current.s.zeroize();
    let a = s.root.active.take();
    let b = s.root.builder.take();
    let maps: [Option<Map>; 6] = match (a, b) {
        (Some(a), Some(b)) => {
            let [a0, a1] = a.maps;
            let [o0, o1] = b.overlays;
            let [p0, p1] = b.pending;
            [Some(a0), Some(a1), Some(o0), Some(o1), Some(p0), Some(p1)]
        }
        _ => std::array::from_fn(|_| None),
    };
    for map in maps.into_iter().flatten() {
        if let Ok(mut values) = Arc::try_unwrap(map) {
            values.zeroize();
        }
    }
}
#[cfg(test)]
#[path = "../../tests/private/persistence_private.rs"]
mod tests;

struct SensitiveAssignment(Option<ValidatedAssignment>);
impl Drop for SensitiveAssignment {
    fn drop(&mut self) {
        if let Some(v) = self.0.as_mut() {
            v.values.zeroize();
        }
    }
}
struct MapObjects([Option<Map>; 6]);
impl Drop for MapObjects {
    fn drop(&mut self) {
        for map in &mut self.0 {
            if let Some(map) = map.take() {
                if let Ok(mut values) = Arc::try_unwrap(map) {
                    values.zeroize();
                }
            }
        }
    }
}

pub(crate) fn expected_statement(
    pkg: &PublicPackage,
    generation: u64,
    public: &[Fr],
) -> PResult<[u8; 32]> {
    if public.len() != pkg.shape().instance_len - 1 {
        return Err(PersistenceError::Trust("expected public length"));
    }
    statement(
        pkg,
        &AnchorBinding::new(pkg, [0; 32], [0; 32], generation),
        public,
    )
}
