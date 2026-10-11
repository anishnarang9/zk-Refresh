use super::*;
use aes_gcm_siv::{
    aead::{AeadInPlace, KeyInit},
    Aes256GcmSiv, Nonce, Tag,
};
pub(crate) const HEADER: usize = 1024;
pub(crate) const AAD_PREFIX: &[u8] = b"dynark-bn254/persistence-envelope/v1";
pub(crate) fn u16_at(b: &[u8], i: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(i..add(i, 2)?)
            .ok_or(PersistenceError::Malformed("short integer"))?
            .try_into()
            .unwrap(),
    ))
}
pub(crate) fn u64_at(b: &[u8], i: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(i..add(i, 8)?)
            .ok_or(PersistenceError::Malformed("short integer"))?
            .try_into()
            .unwrap(),
    ))
}
pub(crate) fn count(b: &[u8], i: usize) -> Result<usize> {
    usize::try_from(u64_at(b, i)?).map_err(|_| PersistenceError::Bound("host count"))
}
pub(crate) fn bytes<const N: usize>(b: &[u8], i: usize) -> Result<[u8; N]> {
    Ok(b.get(i..add(i, N)?)
        .ok_or(PersistenceError::Malformed("short bytes"))?
        .try_into()
        .unwrap())
}
pub(crate) fn zero(b: &[u8], start: usize, end: usize) -> Result<()> {
    if b.get(start..end)
        .ok_or(PersistenceError::Malformed("short reserved"))?
        .iter()
        .any(|x| *x != 0)
    {
        return Err(PersistenceError::Malformed("reserved bytes"));
    }
    Ok(())
}
pub(crate) fn put16(b: &mut [u8], i: usize, x: u16) {
    b[i..i + 2].copy_from_slice(&x.to_le_bytes());
}
pub(crate) fn put64(b: &mut [u8], i: usize, x: u64) {
    b[i..i + 8].copy_from_slice(&x.to_le_bytes());
}
pub(crate) fn digest(prefix: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prefix);
    h.update(b);
    h.finalize().into()
}
fn common(c: &ExpectedContext, s: &ProviderSnapshot, h: &mut [u8; 1024]) {
    h[..8].copy_from_slice(b"DYNARKP1");
    for (offset, value) in [
        (8, 1),
        (10, 1024),
        (12, 1),
        (14, 1),
        (16, 1),
        (18, 1),
        (20, 1),
        (22, 1),
        (24, 1),
        (
            26,
            match c.reduction {
                Reduction::Original => 0,
                Reduction::InstanceAugmentedA => 1,
            },
        ),
        (28, 1),
        (30, 1),
    ] {
        put16(h, offset, value);
    }
    h[37] = 1;
    h[38] = 1;
    for (j, x) in shape_values(c.shape).iter().enumerate() {
        put64(h, 40 + 8 * j, *x);
    }
    put64(h, 144, s.session_epoch);
    put64(h, 152, s.key_epoch);
    for (offset, x) in [
        (176, s.key_id),
        (208, c.session),
        (240, c.credential),
        (272, c.action),
        (304, c.issuer),
        (336, c.application),
    ] {
        h[offset..offset + 32].copy_from_slice(&x);
    }
    for (j, x) in identity_values(c.identity).iter().enumerate() {
        h[464 + 32 * j..496 + 32 * j].copy_from_slice(x);
    }
    for (j, x) in c.descriptor.iter().enumerate() {
        h[624 + 32 * j..656 + 32 * j].copy_from_slice(x);
    }
    for (j, x) in c.material.iter().enumerate() {
        h[752 + 32 * j..784 + 32 * j].copy_from_slice(x);
    }
}
pub(crate) fn header(
    state: &DynamicState,
    c: &ExpectedContext,
    s: &ProviderSnapshot,
    r: Reservation,
    len: usize,
    _tier: SyncTier,
) -> Result<([u8; 1024], Receipt)> {
    let meta = codec::header_meta(state)?;
    let old = s.receipt;
    let revision = match old {
        Some(x) => x
            .revision
            .checked_add(1)
            .ok_or(PersistenceError::Bound("revision"))?,
        None => 1,
    };
    if old.is_some_and(|x| meta.binding.generation < x.generation) {
        return Err(PersistenceError::Trust("witness rollback"));
    }
    let receipt = Receipt {
        context: c.digest,
        session: c.session,
        session_epoch: s.session_epoch,
        revision,
        commit_id: r.commit_id,
        base_present: old.is_some(),
        base_id: old.map_or([0; 32], |x| x.commit_id),
        base_revision: old.map_or(0, |x| x.revision),
        base_generation: old.map_or(0, |x| x.generation),
        envelope_digest: [0; 32],
        key_id: s.key_id,
        key_epoch: s.key_epoch,
        generation: meta.binding.generation,
        state_token: meta.binding.anchor_state,
        config_digest: meta.config,
        statement_digest: meta.statement,
        schema: 1,
        units: 1,
        tier: SyncTier::FileAndDirectory,
    };
    let mut h = [0; 1024];
    common(c, s, &mut h);
    h[32] = u8::from(old.is_some());
    h[36] = meta.mode;
    for (offset, value) in [
        (80, len as u64),
        (88, len as u64),
        (96, add(len, 1040)? as u64),
        (104, receipt.base_revision),
        (112, revision),
        (120, receipt.generation),
        (128, meta.active_generation),
        (136, meta.builder_generation),
        (912, receipt.base_generation),
    ] {
        put64(&mut h, offset, value);
    }
    h[160..172].copy_from_slice(&r.nonce);
    for (offset, x) in [
        (368, receipt.base_id),
        (400, receipt.commit_id),
        (432, receipt.state_token),
        (848, receipt.config_digest),
        (880, receipt.statement_digest),
    ] {
        h[offset..offset + 32].copy_from_slice(&x);
    }
    Ok((h, receipt))
}
pub(crate) fn preflight(
    h: &[u8; 1024],
    file_len: u64,
    c: &ExpectedContext,
    s: &ProviderSnapshot,
    p: &LoadPolicy,
) -> Result<usize> {
    let r = s
        .receipt
        .ok_or(PersistenceError::RebuildRequired("missing receipt"))?;
    let mut expected = [0; 1024];
    common(c, s, &mut expected);
    if h[..32] != expected[..32] {
        return Err(PersistenceError::Unsupported("envelope/version/encoding"));
    }
    for (start, end) in [(37, 40), (40, 80), (144, 160), (176, 368), (464, 848)] {
        if h[start..end] != expected[start..end] {
            return Err(PersistenceError::Trust("header/context"));
        }
    }
    zero(h, 172, 176)?;
    zero(h, 920, 1024)?;
    if h[33..36] != [0; 3] || h[32] > 1 || !matches!(h[36], 1 | 2) {
        return Err(PersistenceError::Malformed("flags/mode"));
    }
    let len = count(h, 80)?;
    if len > p.max_record_bytes
        || add(len, 1040)? > p.max_record_bytes
        || u64_at(h, 88)? != len as u64
        || u64_at(h, 96)? != add(len, 1040)? as u64
        || file_len != add(len, 1040)? as u64
    {
        return Err(PersistenceError::Bound("record length"));
    }
    if r.context != c.digest
        || r.session != c.session
        || r.session_epoch != s.session_epoch
        || r.key_epoch != s.key_epoch
        || r.key_id != s.key_id
        || r.schema != 1
        || r.units != 1
        || r.tier != SyncTier::FileAndDirectory
        || r.commit_id == [0; 32]
    {
        return Err(PersistenceError::Trust("receipt"));
    }
    for (offset, value) in [
        (104, r.base_revision),
        (112, r.revision),
        (120, r.generation),
        (912, r.base_generation),
    ] {
        if u64_at(h, offset)? != value {
            return Err(PersistenceError::Trust("header/receipt integer"));
        }
    }
    for (offset, value) in [
        (368, r.base_id),
        (400, r.commit_id),
        (432, r.state_token),
        (848, r.config_digest),
        (880, r.statement_digest),
    ] {
        if bytes::<32>(h, offset)? != value {
            return Err(PersistenceError::Trust("header/receipt digest"));
        }
    }
    if (h[32] == 1) != r.base_present
        || if r.base_present {
            r.base_id == [0; 32]
                || r.base_revision.checked_add(1) != Some(r.revision)
                || r.generation < r.base_generation
        } else {
            r.base_id != [0; 32]
                || r.base_revision != 0
                || r.base_generation != 0
                || r.revision != 1
        }
    {
        return Err(PersistenceError::Malformed("base revision"));
    }
    if h[36] == 2 && (u64_at(h, 128)? != 0 || u64_at(h, 136)? != 0) {
        return Err(PersistenceError::Malformed("FullOnly generation"));
    }
    let buffer_peak = add(add(len, p.old_live_bytes)?, 12 * 1024)?;
    p.peak(buffer_peak, c.trusted_tables.0.public_bytes)?;
    Ok(len)
}
fn aad(h: &[u8; 1024]) -> [u8; HEADER + AAD_PREFIX.len()] {
    let mut a = [0; HEADER + AAD_PREFIX.len()];
    a[..AAD_PREFIX.len()].copy_from_slice(AAD_PREFIX);
    a[AAD_PREFIX.len()..].copy_from_slice(h);
    a
}
pub(crate) fn seal(k: &KeyLease, h: &[u8; 1024], p: &mut [u8]) -> Result<[u8; 16]> {
    let cipher =
        Aes256GcmSiv::new_from_slice(&*k.0).map_err(|_| PersistenceError::Trust("AEAD key"))?;
    let a = aad(h);
    let n = bytes::<12>(h, 160)?;
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&n), &a, p)
        .map_err(|_| PersistenceError::Bound("AEAD"))?;
    Ok(tag.into())
}
pub(crate) fn open(k: &KeyLease, h: &[u8; 1024], p: &mut [u8], tag: &[u8; 16]) -> Result<()> {
    let cipher =
        Aes256GcmSiv::new_from_slice(&*k.0).map_err(|_| PersistenceError::Trust("AEAD key"))?;
    let a = aad(h);
    let n = bytes::<12>(h, 160)?;
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(&n), &a, p, Tag::from_slice(tag))
        .map_err(|_| PersistenceError::RebuildRequired("authentication"))
}
