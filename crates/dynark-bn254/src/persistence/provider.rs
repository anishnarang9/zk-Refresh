use super::*;
use std::sync::{Mutex, MutexGuard};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidationReason {
    OwnRevocation,
    IssuerDisabled,
    ActionComplete,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyntheticCasFault {
    None,
    KnownNotAttempted,
    CommitThenUnknown,
    DelayThenUnknown,
    MalformedAfterCommit,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyntheticResolution {
    Pending,
    Execute,
    Cancel,
}
struct KeyNamespace {
    id: [u8; 32],
    epoch: u64,
    key: Zeroizing<[u8; 32]>,
    nonces: Vec<[u8; 12]>,
}
struct Session {
    snapshot: ProviderSnapshot,
    key: usize,
}
#[derive(Clone, Copy)]
struct Attempt {
    session: [u8; 32],
    epoch: u64,
    reservation: Reservation,
    expected: ProviderSnapshot,
    proposed: Option<Receipt>,
    done: Option<CasOutcome>,
}
struct Inner {
    keys: Vec<KeyNamespace>,
    sessions: Vec<Session>,
    attempts: Vec<Attempt>,
    max_sessions: usize,
    max_attempts: usize,
    fault: SyntheticCasFault,
    resolution: SyntheticResolution,
}
/// Development/test provider only. No state is durable or exportable. Restart
/// loses receipts, invalidation and uniqueness history; missing trust requires
/// explicit validated rebuilding and separately authorized enrollment.
pub struct SyntheticProvider {
    inner: Mutex<Inner>,
}
pub struct SyntheticUseLease<'a> {
    _guard: MutexGuard<'a, Inner>,
}
impl SyntheticProvider {
    pub fn new(max_sessions: usize, max_attempts: usize) -> Result<Self> {
        if max_sessions == 0 || max_attempts == 0 {
            return Err(PersistenceError::Bound("provider capacity"));
        }
        Ok(Self {
            inner: Mutex::new(Inner {
                keys: reserve(max_sessions)?,
                sessions: reserve(max_sessions)?,
                attempts: reserve(max_attempts)?,
                max_sessions,
                max_attempts,
                fault: SyntheticCasFault::None,
                resolution: SyntheticResolution::Pending,
            }),
        })
    }
    /// Explicit authorization. The caller attests that the enrolled producer was
    /// validated against this independently supplied package/holder/action scope.
    pub fn enroll_validated(
        &self,
        c: &ExpectedContext,
        key: KeyLease,
        key_id: [u8; 32],
        key_epoch: u64,
        session_epoch: u64,
    ) -> Result<()> {
        let mut i = self.lock()?;
        if key_id == [0; 32]
            || session_epoch == 0
            || key_epoch == 0
            || i.sessions.len() >= i.max_sessions
            || i.sessions.iter().any(|s| s.snapshot.session == c.session)
        {
            return Err(PersistenceError::Trust("enrollment"));
        }
        // Identical physical key bytes must share one nonce ledger, even when
        // a caller supplies a different public ID or epoch.
        if i.keys.iter().any(|existing| {
            (existing.id != key_id || existing.epoch != key_epoch) && *existing.key == *key.0
        }) {
            return Err(PersistenceError::Trust("physical key namespace alias"));
        }
        let k = match i
            .keys
            .iter()
            .position(|k| k.id == key_id && k.epoch == key_epoch)
        {
            Some(k) => {
                if *i.keys[k].key != *key.0 {
                    return Err(PersistenceError::Trust("key namespace"));
                }
                k
            }
            None => {
                let nonces = reserve(i.max_attempts)?;
                let k = i.keys.len();
                i.keys.push(KeyNamespace {
                    id: key_id,
                    epoch: key_epoch,
                    key: key.0,
                    nonces,
                });
                k
            }
        };
        i.sessions.push(Session {
            key: k,
            snapshot: ProviderSnapshot {
                context: c.digest,
                session: c.session,
                session_epoch,
                key_id,
                key_epoch,
                status: SessionStatus::Active,
                capability: ProviderCapability::ProcessLifetime,
                enrollment_authorized: true,
                receipt: None,
                unresolved: None,
            },
        });
        Ok(())
    }
    pub fn set_next_cas_fault(&self, f: SyntheticCasFault) -> Result<()> {
        self.lock()?.fault = f;
        Ok(())
    }
    pub fn set_resolution(&self, r: SyntheticResolution) -> Result<()> {
        self.lock()?.resolution = r;
        Ok(())
    }
    pub fn invalidate_issuer(&self, contexts: &[ExpectedContext]) -> Result<()> {
        // Caller selects authenticated issuer scope; each invalidation linearizes
        // independently. No distributed all-session atomicity is claimed.
        for c in contexts {
            let s = self.read(c.session)?;
            self.invalidate(
                c.session,
                s.session_epoch,
                InvalidationReason::IssuerDisabled,
            )?;
        }
        Ok(())
    }
    fn lock(&self) -> Result<MutexGuard<'_, Inner>> {
        self.inner
            .lock()
            .map_err(|_| PersistenceError::Trust("provider poisoned"))
    }
}
fn session(i: &Inner, id: [u8; 32]) -> Result<usize> {
    i.sessions
        .iter()
        .position(|s| s.snapshot.session == id)
        .ok_or(PersistenceError::RebuildRequired("unregistered session"))
}
fn exact(i: &Inner, e: &ProviderSnapshot) -> Result<usize> {
    let k = session(i, e.session)?;
    if i.sessions[k].snapshot != *e || e.status != SessionStatus::Active || e.unresolved.is_some() {
        return Err(PersistenceError::Fenced);
    }
    Ok(k)
}
fn proposal(e: &ProviderSnapshot, p: &Receipt, r: Reservation) -> bool {
    p.context == e.context
        && p.session == e.session
        && p.session_epoch == e.session_epoch
        && p.key_id == e.key_id
        && p.key_epoch == e.key_epoch
        && p.commit_id == r.commit_id
        && p.commit_id != [0; 32]
        && p.schema == 1
        && p.units == 1
        && p.tier == SyncTier::FileAndDirectory
        && p.envelope_digest != [0; 32]
        && match e.receipt {
            Some(old) => {
                p.base_present
                    && p.base_id == old.commit_id
                    && p.base_revision == old.revision
                    && p.base_generation == old.generation
                    && old.revision.checked_add(1) == Some(p.revision)
                    && p.generation >= old.generation
            }
            None => {
                e.enrollment_authorized
                    && !p.base_present
                    && p.base_id == [0; 32]
                    && p.base_revision == 0
                    && p.base_generation == 0
                    && p.revision == 1
            }
        }
}
impl TrustedProvider for SyntheticProvider {
    type UseLease<'a> = SyntheticUseLease<'a>;
    fn read(&self, id: [u8; 32]) -> Result<ProviderSnapshot> {
        let i = self
            .inner
            .try_lock()
            .map_err(|_| PersistenceError::Fenced)?;
        Ok(i.sessions[session(&i, id)?].snapshot)
    }
    fn key(&self, e: &ProviderSnapshot) -> Result<KeyLease> {
        let i = self.lock()?;
        let k = exact(&i, e)?;
        Ok(KeyLease::protected(*i.keys[i.sessions[k].key].key))
    }
    fn reserve(&self, e: &ProviderSnapshot, r: Reservation) -> Result<ReserveOutcome> {
        let mut i = self.lock()?;
        let k = exact(&i, e)?;
        let key = i.sessions[k].key;
        if i.attempts.len() >= i.max_attempts || i.keys[key].nonces.len() >= i.max_attempts {
            return Err(PersistenceError::ReservationExhausted);
        }
        if r.commit_id == [0; 32]
            || i.attempts
                .iter()
                .any(|a| a.reservation.commit_id == r.commit_id)
            || i.keys[key].nonces.contains(&r.nonce)
        {
            return Ok(ReserveOutcome::Duplicate);
        }
        i.keys[key].nonces.push(r.nonce);
        i.attempts.push(Attempt {
            session: e.session,
            epoch: e.session_epoch,
            reservation: r,
            expected: *e,
            proposed: None,
            done: None,
        });
        Ok(ReserveOutcome::Reserved)
    }
    fn compare_and_set(&self, e: &ProviderSnapshot, r: Reservation, p: Receipt) -> CasOutcome {
        let Ok(mut i) = self.lock() else {
            return CasOutcome::KnownNotAttempted;
        };
        let Ok(k) = session(&i, e.session) else {
            return CasOutcome::KnownNotAttempted;
        };
        let Some(a) = i.attempts.iter().position(|a| {
            a.session == e.session
                && a.epoch == e.session_epoch
                && a.reservation == r
                && a.expected == *e
        }) else {
            return CasOutcome::KnownNotAttempted;
        };
        if let Some(done) = i.attempts[a].done {
            return done;
        }
        if i.attempts[a].proposed.is_some() {
            return CasOutcome::Unknown;
        }
        if exact(&i, e).is_err() || !proposal(e, &p, r) {
            let out = CasOutcome::Conflict(i.sessions[k].snapshot);
            i.attempts[a].done = Some(out);
            return out;
        }
        let fault = i.fault;
        i.fault = SyntheticCasFault::None;
        if fault == SyntheticCasFault::KnownNotAttempted {
            i.attempts[a].done = Some(CasOutcome::KnownNotAttempted);
            return CasOutcome::KnownNotAttempted;
        }
        i.attempts[a].proposed = Some(p);
        if fault == SyntheticCasFault::DelayThenUnknown {
            i.sessions[k].snapshot.unresolved = Some(p.commit_id);
            return CasOutcome::Unknown;
        }
        i.sessions[k].snapshot.receipt = Some(p);
        i.sessions[k].snapshot.enrollment_authorized = false;
        i.attempts[a].done = Some(CasOutcome::Committed(p));
        if fault != SyntheticCasFault::None {
            i.sessions[k].snapshot.unresolved = Some(p.commit_id);
            return CasOutcome::Unknown;
        }
        CasOutcome::Committed(p)
    }
    fn resolve(&self, id: [u8; 32], op: [u8; 32]) -> CasOutcome {
        let Ok(mut i) = self.lock() else {
            return CasOutcome::Unknown;
        };
        let Ok(k) = session(&i, id) else {
            return CasOutcome::Unknown;
        };
        let Some(a) = i
            .attempts
            .iter()
            .position(|a| a.session == id && a.reservation.commit_id == op)
        else {
            return CasOutcome::Unknown;
        };
        if let Some(out) = i.attempts[a].done {
            if i.sessions[k].snapshot.unresolved == Some(op) {
                i.sessions[k].snapshot.unresolved = None;
            }
            return out;
        }
        let Some(p) = i.attempts[a].proposed else {
            return CasOutcome::Unknown;
        };
        if i.sessions[k].snapshot.session_epoch != i.attempts[a].epoch
            || i.sessions[k].snapshot.status != SessionStatus::Active
        {
            i.sessions[k].snapshot.unresolved = None;
            let out = CasOutcome::Conflict(i.sessions[k].snapshot);
            i.attempts[a].done = Some(out);
            return out;
        }
        match i.resolution {
            SyntheticResolution::Pending => CasOutcome::Unknown,
            SyntheticResolution::Cancel => {
                i.sessions[k].snapshot.unresolved = None;
                i.attempts[a].done = Some(CasOutcome::KnownNotAttempted);
                CasOutcome::KnownNotAttempted
            }
            SyntheticResolution::Execute => {
                let mut current = i.sessions[k].snapshot;
                current.unresolved = None;
                if current != i.attempts[a].expected {
                    i.sessions[k].snapshot.unresolved = None;
                    let out = CasOutcome::Conflict(i.sessions[k].snapshot);
                    i.attempts[a].done = Some(out);
                    return out;
                }
                i.sessions[k].snapshot.unresolved = None;
                i.sessions[k].snapshot.receipt = Some(p);
                i.sessions[k].snapshot.enrollment_authorized = false;
                i.attempts[a].done = Some(CasOutcome::Committed(p));
                CasOutcome::Committed(p)
            }
        }
    }
    fn use_lease<'a>(&'a self, e: &ProviderSnapshot) -> Result<Self::UseLease<'a>> {
        let i = self.lock()?;
        exact(&i, e)?;
        if e.receipt.is_none() {
            return Err(PersistenceError::RebuildRequired("no receipt"));
        }
        Ok(SyntheticUseLease { _guard: i })
    }
    fn invalidate(&self, id: [u8; 32], epoch: u64, _reason: InvalidationReason) -> Result<()> {
        let mut i = self.lock()?;
        let k = session(&i, id)?;
        if i.sessions[k].snapshot.session_epoch != epoch {
            return Err(PersistenceError::Fenced);
        }
        let next = epoch
            .checked_add(1)
            .ok_or(PersistenceError::Bound("session epoch"))?;
        i.sessions[k].snapshot.status = SessionStatus::Invalidated;
        i.sessions[k].snapshot.session_epoch = next;
        i.sessions[k].snapshot.enrollment_authorized = false;
        Ok(())
    }
}
