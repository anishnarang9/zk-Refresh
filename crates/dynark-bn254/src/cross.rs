//! Independent finite-part Trummer kernel; the paper omits this fast algorithm.
//! Conversion and tree construction are paid per call. No proof randomness,
//! setup, witness validation or package trust policy is implemented here.
use crate::Error;
use ark_bn254::{Fr, G1Projective as G1};
use ark_ff::{batch_inversion, AdditiveGroup, Field, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Radix2EvaluationDomain};
use std::{collections::BTreeMap, mem::size_of};

#[derive(Clone, Copy, Debug)]
pub struct CrossLimits {
    pub max_domain: usize,
    /// Total raw entries before combining duplicates.
    pub max_input_entries: usize,
    pub max_union_support: usize,
    pub max_fft_size: usize,
    /// Conservative simultaneously live structural bytes, including temporaries.
    /// This is not measured heap/RSS or a runtime OOM recovery guarantee.
    pub max_allocation_bytes: usize,
    pub max_pair_visits: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrossMethod {
    Quadratic,
    Fast,
    /// Caller-forced bounded fallback; no measured crossover policy is implied.
    FastOrQuadratic,
}
/// Diagnostic callbacks receive only boundaries, never scalar/index/material data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrossPhase {
    Preflight,
    Normalize,
    Nodes,
    ProductTree,
    Numerators,
    Derivatives,
    RemainderEvaluation,
    FinitePart,
    Quadratic,
    Collect,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrossPhaseEvent {
    Start,
    End,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrossStats {
    pub input_entries_a: usize,
    pub input_entries_b: usize,
    pub nonzero_a: usize,
    pub nonzero_b: usize,
    pub union_support: usize,
    pub diagonal_overlap: usize,
    pub quadratic_pair_visits: usize,
    pub polynomial_multiplications: usize,
    pub polynomial_divisions: usize,
    pub derivative_evaluations: usize,
    pub fft_calls: usize,
    pub fft_max_size: usize,
    pub fft_total_elements: usize,
    pub preflight_allocation_bytes: usize,
    pub group_scalar_muls: usize,
    pub used_method: CrossMethod,
    pub bounded_fallback: bool,
}
/// Sensitive coefficients in sorted distinct domain-index order. Material
/// identity is the owning proof boundary's responsibility.
pub struct CrossCoefficients {
    pub domain_size: usize,
    pub indices: Vec<usize>,
    pub lagrange: Vec<Fr>,
    pub diagonal: Vec<Fr>,
    pub stats: CrossStats,
}
fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b)
        .ok_or(Error::Bound("cross allocation overflow"))
}
fn mul(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b)
        .ok_or(Error::Bound("cross allocation overflow"))
}
fn ceiling(bytes: usize, limits: CrossLimits) -> Result<usize, Error> {
    if bytes > limits.max_allocation_bytes {
        Err(Error::Bound("cross allocation"))
    } else {
        Ok(bytes)
    }
}
fn vector<T>(len: usize) -> Result<Vec<T>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(len)
        .map_err(|_| Error::Bound("cross allocation reservation"))?;
    Ok(out)
}
fn zeros(len: usize) -> Result<Vec<Fr>, Error> {
    let mut out = vector(len)?;
    out.resize(len, Fr::ZERO);
    Ok(out)
}
fn copy(poly: &[Fr]) -> Result<Vec<Fr>, Error> {
    let mut out = vector(poly.len())?;
    out.extend_from_slice(poly);
    Ok(out)
}
fn trim(poly: &mut Vec<Fr>) {
    while poly.last().is_some_and(Zero::is_zero) {
        poly.pop();
    }
}
fn normalize(raw: &[(usize, Fr)]) -> Vec<(usize, Fr)> {
    let mut values = BTreeMap::<usize, Fr>::new();
    for (i, value) in raw {
        *values.entry(*i).or_default() += value;
    }
    values.into_iter().filter(|(_, x)| !x.is_zero()).collect()
}
struct Aligned {
    indices: Vec<usize>,
    a: Vec<Fr>,
    b: Vec<Fr>,
}
fn align(a: &[(usize, Fr)], b: &[(usize, Fr)]) -> Result<Aligned, Error> {
    let capacity = add(a.len(), b.len())?;
    let mut indices = vector(capacity)?;
    let mut av = vector(capacity)?;
    let mut bv = vector(capacity)?;
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        if j == b.len() || (i < a.len() && a[i].0 < b[j].0) {
            indices.push(a[i].0);
            av.push(a[i].1);
            bv.push(Fr::ZERO);
            i += 1;
        } else if i == a.len() || b[j].0 < a[i].0 {
            indices.push(b[j].0);
            av.push(Fr::ZERO);
            bv.push(b[j].1);
            j += 1;
        } else {
            indices.push(a[i].0);
            av.push(a[i].1);
            bv.push(b[j].1);
            i += 1;
            j += 1;
        }
    }
    Ok(Aligned {
        indices,
        a: av,
        b: bv,
    })
}
/// Checked conservative convolution size, callable without allocation.
pub fn required_fft_size(support: usize) -> Result<usize, Error> {
    if support <= 1 {
        return Ok(0);
    }
    // Covers product coefficients and full (not truncated) Newton products.
    add(support, 1)?
        .checked_mul(2)
        .and_then(|x| x.checked_sub(1))
        .and_then(usize::checked_next_power_of_two)
        .ok_or(Error::Bound("cross FFT overflow"))
}
fn fast_preflight(s: usize, base: usize, limits: CrossLimits) -> Result<usize, Error> {
    let fft = required_fft_size(s)?;
    if fft > limits.max_fft_size || (fft > 0 && Radix2EvaluationDomain::<Fr>::new(fft).is_none()) {
        return Err(Error::Bound("cross FFT domain"));
    }
    let levels = if s <= 1 {
        1
    } else {
        (s - 1).ilog2() as usize + 2
    };
    // D tree <= (s+1)(levels+1) fields. Recursive paired numerator construction,
    // four remainder traversals, derivatives, inversion and output use O(s*levels)
    // live fields. 96 fields/node/level deliberately dominates those vectors;
    // 24*fft fields additionally covers live Newton/reversal/FFT temporaries.
    // Tree headers (<=2s-1) and raw normalization storage are separately counted.
    let fields = mul(mul(add(s, 1)?, add(levels, 1)?)?, 96)?;
    let bytes = add(base, mul(add(fields, mul(fft, 24)?)?, size_of::<Fr>())?)?;
    ceiling(add(bytes, mul(mul(s, 2)?, size_of::<Node>())?)?, limits)
}
fn quadratic_preflight(
    a: usize,
    b: usize,
    s: usize,
    base: usize,
    limits: CrossLimits,
) -> Result<usize, Error> {
    let pairs = a
        .checked_mul(b)
        .ok_or(Error::Bound("cross pair overflow"))?;
    if pairs > limits.max_pair_visits {
        return Err(Error::Bound("cross pair work"));
    }
    ceiling(
        add(
            base,
            mul(add(s, 1)?, 16 * size_of::<Fr>() + 8 * size_of::<usize>())?,
        )?,
        limits,
    )
}
pub fn cross_coefficients(
    domain: &GeneralEvaluationDomain<Fr>,
    weights: &[Fr],
    a: &[(usize, Fr)],
    b: &[(usize, Fr)],
    method: CrossMethod,
    limits: CrossLimits,
) -> Result<CrossCoefficients, Error> {
    cross_coefficients_observed(domain, weights, a, b, method, limits, |_, _| {})
}
/// Same arithmetic as the ordinary no-op wrapper. Diagnostic callback execution,
/// allocation and panic/error behavior are outside engine guarantees. A typed
/// early failure can leave its last phase open.
pub fn cross_coefficients_observed<F: FnMut(CrossPhase, CrossPhaseEvent)>(
    domain: &GeneralEvaluationDomain<Fr>,
    weights: &[Fr],
    a: &[(usize, Fr)],
    b: &[(usize, Fr)],
    method: CrossMethod,
    limits: CrossLimits,
    mut observer: F,
) -> Result<CrossCoefficients, Error> {
    observer(CrossPhase::Preflight, CrossPhaseEvent::Start);
    let n = domain.size();
    if n < 2 || !n.is_power_of_two() || !matches!(domain, GeneralEvaluationDomain::Radix2(_)) {
        return Err(Error::Shape("cross radix-two domain"));
    }
    if n > limits.max_domain {
        return Err(Error::Bound("cross domain"));
    }
    // The owner authenticates the exact prepared/imported table; do not scan or
    // recompute all N public weights on a sparse call.
    if weights.len() != n || !weights[0].is_zero() {
        return Err(Error::Shape("cross weights"));
    }
    let raw = add(a.len(), b.len())?;
    if raw > limits.max_input_entries {
        return Err(Error::Bound("cross input entries"));
    }
    // Check raw map/normalized/aligned storage before normalization allocations.
    let base = ceiling(add(mul(raw, 512)?, 512)?, limits)?;
    if a.iter().chain(b).any(|(i, _)| *i >= n) {
        return Err(Error::DeltaCoordinate);
    }
    let raw_a = a.len();
    let raw_b = b.len();
    observer(CrossPhase::Preflight, CrossPhaseEvent::End);
    observer(CrossPhase::Normalize, CrossPhaseEvent::Start);
    let a = normalize(a);
    let b = normalize(b);
    let aligned = align(&a, &b)?;
    let s = aligned.indices.len();
    observer(CrossPhase::Normalize, CrossPhaseEvent::End);
    observer(CrossPhase::Preflight, CrossPhaseEvent::Start);
    if s > limits.max_union_support {
        return Err(Error::Bound("cross union support"));
    }
    let mut used = method;
    let mut fallback = false;
    let allocation = if method == CrossMethod::Quadratic {
        quadratic_preflight(a.len(), b.len(), s, base, limits)?
    } else {
        match fast_preflight(s, base, limits) {
            Ok(bytes) => {
                used = CrossMethod::Fast;
                bytes
            }
            Err(Error::Bound("cross FFT domain" | "cross allocation"))
                if method == CrossMethod::FastOrQuadratic =>
            {
                used = CrossMethod::Quadratic;
                fallback = true;
                quadratic_preflight(a.len(), b.len(), s, base, limits)?
            }
            Err(error) => return Err(error),
        }
    };
    let overlap = aligned
        .a
        .iter()
        .zip(&aligned.b)
        .filter(|(x, y)| !x.is_zero() && !y.is_zero())
        .count();
    observer(CrossPhase::Preflight, CrossPhaseEvent::End);
    let mut stats = CrossStats {
        input_entries_a: raw_a,
        input_entries_b: raw_b,
        nonzero_a: a.len(),
        nonzero_b: b.len(),
        union_support: s,
        diagonal_overlap: overlap,
        quadratic_pair_visits: 0,
        polynomial_multiplications: 0,
        polynomial_divisions: 0,
        derivative_evaluations: 0,
        fft_calls: 0,
        fft_max_size: 0,
        fft_total_elements: 0,
        preflight_allocation_bytes: allocation,
        group_scalar_muls: 0,
        used_method: used,
        bounded_fallback: fallback,
    };
    let (convolution_a, convolution_b) = if used == CrossMethod::Quadratic {
        observer(CrossPhase::Quadratic, CrossPhaseEvent::Start);
        let result = quadratic(&aligned, weights, &mut stats)?;
        observer(CrossPhase::Quadratic, CrossPhaseEvent::End);
        result
    } else {
        observer(CrossPhase::Nodes, CrossPhaseEvent::Start);
        let mut nodes = vector(s)?;
        for i in &aligned.indices {
            nodes.push(domain.element(*i));
        }
        observer(CrossPhase::Nodes, CrossPhaseEvent::End);
        fast(
            &aligned,
            &nodes,
            domain.size_inv(),
            limits,
            &mut stats,
            &mut observer,
        )?
    };
    observer(CrossPhase::Collect, CrossPhaseEvent::Start);
    let mut lagrange = vector(s)?;
    let mut diagonal = vector(s)?;
    for i in 0..s {
        lagrange.push(aligned.a[i] * convolution_b[i] + aligned.b[i] * convolution_a[i]);
        diagonal.push(aligned.a[i] * aligned.b[i]);
    }
    stats.group_scalar_muls = lagrange
        .iter()
        .chain(&diagonal)
        .filter(|x| !x.is_zero())
        .count();
    let result = CrossCoefficients {
        domain_size: n,
        indices: aligned.indices,
        lagrange,
        diagonal,
        stats,
    };
    observer(CrossPhase::Collect, CrossPhaseEvent::End);
    Ok(result)
}
fn quadratic(
    aligned: &Aligned,
    weights: &[Fr],
    stats: &mut CrossStats,
) -> Result<(Vec<Fr>, Vec<Fr>), Error> {
    let s = aligned.indices.len();
    let n = weights.len();
    let mut ca = zeros(s)?;
    let mut cb = zeros(s)?;
    let mut a_positions = vector(s)?;
    let mut b_positions = vector(s)?;
    for i in 0..s {
        if !aligned.a[i].is_zero() {
            a_positions.push(i);
        }
        if !aligned.b[i].is_zero() {
            b_positions.push(i);
        }
    }
    // Fused A-by-B field loop, followed by linear group encoding. Only the
    // convolution slots multiplied by a nonzero local partner are needed.
    for i in a_positions {
        for j in &b_positions {
            let j = *j;
            stats.quadratic_pair_visits += 1;
            if i != j {
                let row_i = aligned.indices[i];
                let row_j = aligned.indices[j];
                cb[i] += aligned.b[j] * weights[(n + row_j - row_i) % n];
                ca[j] += aligned.a[i] * weights[(n + row_i - row_j) % n];
            }
        }
    }
    Ok((ca, cb))
}
struct Node {
    denominator: Vec<Fr>,
    start: usize,
    children: Option<(usize, usize)>,
}
struct Arithmetic<'a> {
    limits: CrossLimits,
    stats: &'a mut CrossStats,
}
impl Arithmetic<'_> {
    fn multiply(&mut self, a: &[Fr], b: &[Fr]) -> Result<Vec<Fr>, Error> {
        self.stats.polynomial_multiplications += 1;
        if a.is_empty() || b.is_empty() {
            return Ok(Vec::new());
        }
        let len = add(a.len(), b.len())?
            .checked_sub(1)
            .ok_or(Error::Bound("cross polynomial length"))?;
        if a.len() == 1 || b.len() == 1 {
            let (p, scalar) = if a.len() == 1 { (b, a[0]) } else { (a, b[0]) };
            let mut result = copy(p)?;
            for x in &mut result {
                *x *= scalar;
            }
            trim(&mut result);
            return Ok(result);
        }
        let size = len
            .checked_next_power_of_two()
            .ok_or(Error::Bound("cross FFT overflow"))?;
        if size > self.limits.max_fft_size {
            return Err(Error::Bound("cross FFT domain"));
        }
        let domain =
            Radix2EvaluationDomain::<Fr>::new(size).ok_or(Error::Bound("cross FFT domain"))?;
        let mut af = zeros(size)?;
        let mut bf = zeros(size)?;
        af[..a.len()].copy_from_slice(a);
        bf[..b.len()].copy_from_slice(b);
        domain.fft_in_place(&mut af);
        domain.fft_in_place(&mut bf);
        for (x, y) in af.iter_mut().zip(bf) {
            *x *= y;
        }
        domain.ifft_in_place(&mut af);
        self.stats.fft_calls = add(self.stats.fft_calls, 3)?;
        self.stats.fft_max_size = self.stats.fft_max_size.max(size);
        self.stats.fft_total_elements = add(self.stats.fft_total_elements, mul(size, 3)?)?;
        af.truncate(len);
        trim(&mut af);
        Ok(af)
    }
    fn reciprocal(&mut self, f: &[Fr], length: usize) -> Result<Vec<Fr>, Error> {
        if length == 0 {
            return Ok(Vec::new());
        }
        let inv = f
            .first()
            .and_then(|x| x.inverse())
            .ok_or(Error::Key("cross reciprocal constant"))?;
        let mut g = vec![inv];
        while g.len() < length {
            let next = mul(g.len(), 2)?.min(length);
            let mut fg = self.multiply(&f[..f.len().min(next)], &g)?;
            fg.resize(next, Fr::ZERO);
            fg.truncate(next);
            for x in &mut fg {
                *x = -*x;
            }
            fg[0] += Fr::from(2);
            // g_new=g(2-fg) mod X^next doubles the exact inverse prefix.
            let mut grown = self.multiply(&g, &fg)?;
            grown.resize(next, Fr::ZERO);
            grown.truncate(next);
            g = grown;
        }
        Ok(g)
    }
    fn remainder(&mut self, f: &[Fr], divisor: &[Fr]) -> Result<Vec<Fr>, Error> {
        self.stats.polynomial_divisions += 1;
        if divisor.is_empty() {
            return Err(Error::Key("cross zero divisor"));
        }
        if f.len() < divisor.len() {
            return copy(f);
        }
        let quotient_len = f.len() - divisor.len() + 1;
        let mut reversed_divisor = copy(divisor)?;
        reversed_divisor.reverse();
        let reciprocal = self.reciprocal(&reversed_divisor, quotient_len)?;
        let mut reversed_f = copy(&f[f.len() - quotient_len..])?;
        reversed_f.reverse();
        let mut reversed_q = self.multiply(&reversed_f, &reciprocal)?;
        reversed_q.resize(quotient_len, Fr::ZERO);
        reversed_q.truncate(quotient_len);
        reversed_q.reverse();
        let product = self.multiply(&reversed_q, divisor)?;
        let mut remainder = zeros(divisor.len() - 1)?;
        for i in 0..remainder.len() {
            remainder[i] = f[i] - product.get(i).copied().unwrap_or(Fr::ZERO);
        }
        trim(&mut remainder);
        Ok(remainder)
    }
}
fn tree(
    nodes: &[Fr],
    start: usize,
    end: usize,
    out: &mut Vec<Node>,
    op: &mut Arithmetic<'_>,
) -> Result<usize, Error> {
    let (denominator, children) = if end - start == 1 {
        (vec![-nodes[start], Fr::ONE], None)
    } else {
        let mid = start + (end - start) / 2;
        let left = tree(nodes, start, mid, out, op)?;
        let right = tree(nodes, mid, end, out, op)?;
        (
            op.multiply(&out[left].denominator, &out[right].denominator)?,
            Some((left, right)),
        )
    };
    let index = out.len();
    out.push(Node {
        denominator,
        start,
        children,
    });
    Ok(index)
}
fn numerator(
    tree: &[Node],
    root: usize,
    a: &[Fr],
    b: &[Fr],
    nodes: &[Fr],
    op: &mut Arithmetic<'_>,
) -> Result<(Vec<Fr>, Vec<Fr>), Error> {
    let node = &tree[root];
    let Some((left, right)) = node.children else {
        return Ok((
            vec![a[node.start] * nodes[node.start]],
            vec![b[node.start] * nodes[node.start]],
        ));
    };
    let (al, bl) = numerator(tree, left, a, b, nodes, op)?;
    let (ar, br) = numerator(tree, right, a, b, nodes, op)?;
    let merge = |l: &[Fr], r: &[Fr], op: &mut Arithmetic<'_>| -> Result<Vec<Fr>, Error> {
        let mut p = op.multiply(l, &tree[right].denominator)?;
        let q = op.multiply(r, &tree[left].denominator)?;
        p.resize(p.len().max(q.len()), Fr::ZERO);
        for (x, y) in p.iter_mut().zip(q) {
            *x += y;
        }
        trim(&mut p);
        Ok(p)
    };
    Ok((merge(&al, &ar, op)?, merge(&bl, &br, op)?))
}
fn derivative(p: &[Fr]) -> Result<Vec<Fr>, Error> {
    let mut out = vector(p.len().saturating_sub(1))?;
    for (i, x) in p.iter().enumerate().skip(1) {
        out.push(*x * Fr::from(i as u64));
    }
    trim(&mut out);
    Ok(out)
}
fn evaluate(
    tree: &[Node],
    root: usize,
    polynomial: &[Fr],
    out: &mut [Fr],
    op: &mut Arithmetic<'_>,
) -> Result<(), Error> {
    let node = &tree[root];
    let remainder = op.remainder(polynomial, &node.denominator)?;
    if let Some((left, right)) = node.children {
        evaluate(tree, left, &remainder, out, op)?;
        evaluate(tree, right, &remainder, out, op)?;
    } else {
        out[node.start] = remainder.first().copied().unwrap_or(Fr::ZERO);
    }
    Ok(())
}
fn fast<F: FnMut(CrossPhase, CrossPhaseEvent)>(
    aligned: &Aligned,
    nodes: &[Fr],
    n_inv: Fr,
    limits: CrossLimits,
    stats: &mut CrossStats,
    observer: &mut F,
) -> Result<(Vec<Fr>, Vec<Fr>), Error> {
    let s = nodes.len();
    if s <= 1 {
        return Ok((zeros(s)?, zeros(s)?));
    }
    let mut op = Arithmetic { limits, stats };
    observer(CrossPhase::ProductTree, CrossPhaseEvent::Start);
    let mut product_tree = vector(
        mul(s, 2)?
            .checked_sub(1)
            .ok_or(Error::Bound("cross tree nodes"))?,
    )?;
    let root = tree(nodes, 0, s, &mut product_tree, &mut op)?;
    observer(CrossPhase::ProductTree, CrossPhaseEvent::End);
    observer(CrossPhase::Numerators, CrossPhaseEvent::Start);
    let (pa, pb) = numerator(&product_tree, root, &aligned.a, &aligned.b, nodes, &mut op)?;
    observer(CrossPhase::Numerators, CrossPhaseEvent::End);
    observer(CrossPhase::Derivatives, CrossPhaseEvent::Start);
    let d1 = derivative(&product_tree[root].denominator)?;
    let d2 = derivative(&d1)?;
    let pa1 = derivative(&pa)?;
    let pb1 = derivative(&pb)?;
    observer(CrossPhase::Derivatives, CrossPhaseEvent::End);
    observer(CrossPhase::RemainderEvaluation, CrossPhaseEvent::Start);
    let mut d1v = zeros(s)?;
    let mut d2v = zeros(s)?;
    let mut pav = zeros(s)?;
    let mut pbv = zeros(s)?;
    for (poly, out) in [
        (&d1, &mut d1v),
        (&d2, &mut d2v),
        (&pa1, &mut pav),
        (&pb1, &mut pbv),
    ] {
        evaluate(&product_tree, root, poly, out, &mut op)?;
        op.stats.derivative_evaluations += s;
    }
    observer(CrossPhase::RemainderEvaluation, CrossPhaseEvent::End);
    observer(CrossPhase::FinitePart, CrossPhaseEvent::Start);
    if d1v.iter().any(Zero::is_zero) {
        return Err(Error::Key("cross distinct nodes"));
    }
    batch_inversion(&mut d1v);
    let half = Fr::from(2)
        .inverse()
        .ok_or(Error::Key("cross characteristic two"))?;
    for i in 0..s {
        let factor = d1v[i] * n_inv;
        pav[i] = (pav[i] - aligned.a[i] * nodes[i] * d2v[i] * half) * factor;
        pbv[i] = (pbv[i] - aligned.b[i] * nodes[i] * d2v[i] * half) * factor;
    }
    observer(CrossPhase::FinitePart, CrossPhaseEvent::End);
    Ok((pav, pbv))
}
/// Checks dimensions and coefficient shape. Material identity is checked by owner.
pub fn encode_cross(c: &CrossCoefficients, lagrange: &[G1], diagonal: &[G1]) -> Result<G1, Error> {
    let s = c.indices.len();
    if c.domain_size < 2
        || !c.domain_size.is_power_of_two()
        || lagrange.len() != c.domain_size
        || diagonal.len() != c.domain_size
        || c.lagrange.len() != s
        || c.diagonal.len() != s
        || s > c.domain_size
        || c.stats.union_support != s
    {
        return Err(Error::Shape("cross encoding dimensions"));
    }
    if c.indices.iter().any(|i| *i >= c.domain_size) || c.indices.windows(2).any(|w| w[0] >= w[1]) {
        return Err(Error::DeltaCoordinate);
    }
    let mut result = G1::zero();
    for (slot, i) in c.indices.iter().enumerate() {
        if !c.lagrange[slot].is_zero() {
            result += lagrange[*i] * c.lagrange[slot];
        }
        if !c.diagonal[slot].is_zero() {
            result += diagonal[*i] * c.diagonal[slot];
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};

    fn limits() -> CrossLimits {
        CrossLimits {
            max_domain: 1024,
            max_input_entries: 4096,
            max_union_support: 1024,
            max_fft_size: 4096,
            max_allocation_bytes: 64 * 1024 * 1024,
            max_pair_visits: 1_000_000,
        }
    }
    fn empty_stats() -> CrossStats {
        let d = GeneralEvaluationDomain::<Fr>::new(8).unwrap();
        cross_coefficients(&d, &[Fr::ZERO; 8], &[], &[], CrossMethod::Fast, limits())
            .unwrap()
            .stats
    }
    fn charge(total: &mut usize, a: usize, b: usize) {
        let pairs = a.checked_mul(b).unwrap();
        assert!(pairs <= 1_000_000);
        *total = total.checked_add(pairs).unwrap();
        assert!(*total <= 1_000_000); // Separate unit-test subtotal; suite stays below 20m.
    }
    #[test]
    fn reciprocal_and_remainder_match_independent_schoolbook() {
        const SEED: u64 = 0x7434_6469_7669_6431;
        let mut rng = rand::rngs::StdRng::seed_from_u64(SEED);
        let mut stats = empty_stats();
        let mut op = Arithmetic {
            limits: limits(),
            stats: &mut stats,
        };
        let mut pairs = 0;
        let mut cases = 0;
        for size in [2, 3, 4, 5, 8, 13, 16, 25, 32, 47, 64] {
            for _ in 0..4 {
                let mut f = (0..size)
                    .map(|_| Fr::from(rng.gen_range(0..17u64)))
                    .collect::<Vec<_>>();
                f[0] = Fr::from(rng.gen_range(1..17u64));
                let reciprocal = op.reciprocal(&f, size).unwrap();
                charge(&mut pairs, size, size);
                let mut product = vec![Fr::ZERO; 2 * size - 1];
                for (i, x) in f.iter().enumerate() {
                    for (j, y) in reciprocal.iter().enumerate() {
                        product[i + j] += *x * *y;
                    }
                }
                assert_eq!(product[0], Fr::ONE);
                assert!(product[1..size].iter().all(Zero::is_zero));
                let divisor_len = rng.gen_range(2..=size);
                let mut divisor = (0..divisor_len)
                    .map(|_| Fr::from(rng.gen_range(0..17u64)))
                    .collect::<Vec<_>>();
                divisor[divisor_len - 1] = Fr::from(rng.gen_range(1..17u64));
                let got = op.remainder(&f, &divisor).unwrap();
                charge(&mut pairs, size, divisor_len);
                let mut expected = f.clone();
                let inv = divisor.last().unwrap().inverse().unwrap();
                for k in (divisor_len - 1..size).rev() {
                    let factor = expected[k] * inv;
                    for j in 0..divisor_len {
                        expected[k + 1 - divisor_len + j] -= factor * divisor[j];
                    }
                }
                expected.truncate(divisor_len - 1);
                trim(&mut expected);
                assert_eq!(got, expected);
                cases += 1;
            }
        }
        assert!(matches!(op.reciprocal(&[Fr::ZERO], 1), Err(Error::Key(_))));
        assert!(matches!(op.remainder(&[Fr::ONE], &[]), Err(Error::Key(_))));
        assert_eq!(op.remainder(&[Fr::ONE], &[Fr::ONE]).unwrap(), vec![]);
        println!("T4_DIVISION seed={SEED} cases={cases} oracle_pair_visits={pairs}");
    }
    #[test]
    fn finite_part_vectors_include_slots_with_zero_local_partners() {
        const SEED: u64 = 0x7434_7472_756d_6d31;
        let mut rng = rand::rngs::StdRng::seed_from_u64(SEED);
        let mut pairs = 0;
        let mut cases = 0;
        for n in [2, 4, 8, 16, 32, 64] {
            let d = GeneralEvaluationDomain::<Fr>::new(n).unwrap();
            for s in [1, n / 2, n - 1, n] {
                let aligned = Aligned {
                    indices: (0..s).collect(),
                    a: (0..s).map(|_| Fr::from(rng.gen_range(0..7u64))).collect(),
                    b: (0..s).map(|_| Fr::from(rng.gen_range(0..7u64))).collect(),
                };
                let nodes = (0..s).map(|i| d.element(i)).collect::<Vec<_>>();
                let mut stats = empty_stats();
                let got = fast(
                    &aligned,
                    &nodes,
                    d.size_inv(),
                    limits(),
                    &mut stats,
                    &mut |_, _| {},
                )
                .unwrap();
                charge(&mut pairs, s, 2 * s);
                for i in 0..s {
                    let expected = |a: &[Fr]| {
                        (0..s)
                            .filter(|j| *j != i)
                            .map(|j| a[j] * nodes[j] / (nodes[i] - nodes[j]) * d.size_inv())
                            .sum::<Fr>()
                    };
                    assert_eq!(got.0[i], expected(&aligned.a));
                    assert_eq!(got.1[i], expected(&aligned.b));
                }
                assert!(stats.fft_max_size <= required_fft_size(s).unwrap());
                cases += 1;
            }
        }
        println!("T4_FINITE_PART seed={SEED} cases={cases} oracle_pair_visits={pairs}");
    }
    #[test]
    fn unavailable_intermediate_field_domain_and_overflow_preflight_without_allocating() {
        let mut limits = limits();
        limits.max_fft_size = usize::MAX;
        limits.max_allocation_bytes = usize::MAX;
        assert!(matches!(
            fast_preflight(1usize << 28, 0, limits),
            Err(Error::Bound("cross FFT domain"))
        ));
        assert!(matches!(
            fast_preflight(usize::MAX, 0, limits),
            Err(Error::Bound(_))
        ));
        assert!(matches!(
            quadratic_preflight(usize::MAX, 2, 1, 0, limits),
            Err(Error::Bound("cross pair overflow"))
        ));
        assert!(matches!(
            ceiling(
                1025,
                CrossLimits {
                    max_allocation_bytes: 1024,
                    ..limits
                }
            ),
            Err(Error::Bound("cross allocation"))
        ));
    }
}
