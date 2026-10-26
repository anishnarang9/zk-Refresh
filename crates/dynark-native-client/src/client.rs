use crate::{AuthenticatedTarget, ClientError, Digest, InvalidationReason, RootTarget};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientState {
    Import, Preparing, ReadyToProve, Proving, SubmissionReady, AwaitingOutcome,
    UncertainOutcome, Confirmed, Cancelled, PausedStaleIssuer, Invalidated,
    RebuildRequired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectOutcome { Confirmed, Absent, Unknown }

/// Pure lifecycle coordinator. Events are driven by trusted component adapters;
/// state events alone never produce a proof or authorize an application effect.
pub struct Client {
    action: Digest,
    state: ClientState,
    generation: u64,
    target: Option<RootTarget>,
    invalid: Option<InvalidationReason>,
    attempts: u32,
    max_attempts: u32,
}
impl Client {
    pub fn new(action: Digest, max_attempts: u32) -> Self {
        Self { action, state: ClientState::Import, generation: 0, target: None,
            invalid: None, attempts: 0, max_attempts }
    }
    pub fn after_restart(action: Digest, max_attempts: u32) -> Self {
        let mut result = Self::new(action, max_attempts);
        result.state = ClientState::RebuildRequired; result
    }
    pub fn state(&self) -> ClientState { self.state }
    pub fn generation(&self) -> u64 { self.generation }
    pub fn authenticate(&mut self, target: &impl AuthenticatedTarget, now_unix: u64) -> Result<u64, ClientError> {
        if target.binding().action != self.action { return Err(ClientError::Identity); }
        match target.authorize(now_unix) {
            Ok(()) => self.obtain_state(target.binding().target),
            Err(ClientError::StaleIssuer) => { self.pause_stale_issuer(); Err(ClientError::StaleIssuer) }
            Err(ClientError::Revoked) => { self.invalidate(InvalidationReason::Revoked); Err(ClientError::Revoked) }
            Err(ClientError::Expired) => { self.invalidate(InvalidationReason::Expired); Err(ClientError::Expired) }
            Err(error) => Err(error),
        }
    }
    fn fence(&self) -> Result<(), ClientError> {
        if let Some(reason) = self.invalid { return Err(ClientError::Invalidated(reason)); }
        match self.state {
            ClientState::Confirmed => Err(ClientError::Completed),
            ClientState::AwaitingOutcome | ClientState::UncertainOutcome => Err(ClientError::UncertainOutcome),
            ClientState::PausedStaleIssuer => Err(ClientError::StaleIssuer),
            _ => Ok(()),
        }
    }
    fn generation_check(&self, generation: u64) -> Result<(), ClientError> {
        self.fence()?;
        if generation != self.generation { return Err(ClientError::Superseded); }
        Ok(())
    }
    fn advance_generation(&mut self) -> Result<u64, ClientError> {
        self.generation = self.generation.checked_add(1).ok_or(ClientError::Generation)?;
        Ok(self.generation)
    }
    /// Call only after the M4 adapter has freshly authenticated this target.
    pub fn obtain_state(&mut self, target: RootTarget) -> Result<u64, ClientError> {
        if self.state != ClientState::PausedStaleIssuer { self.fence()?; }
        else if let Some(reason) = self.invalid { return Err(ClientError::Invalidated(reason)); }
        if self.attempts >= self.max_attempts { return Err(ClientError::RetryExhausted); }
        if let Some(old) = self.target {
            if target.version < old.version || (target.version == old.version && target != old) {
                return Err(ClientError::Version);
            }
            if target.issuer_version != old.issuer_version || target.policy_version != old.policy_version {
                let reason = if target.issuer_version != old.issuer_version { InvalidationReason::IssuerChanged }
                    else { InvalidationReason::PolicyChanged };
                self.invalidate(reason);
                return Err(ClientError::Invalidated(reason));
            }
        }
        let generation = self.advance_generation()?;
        self.attempts = self.attempts.checked_add(1).ok_or(ClientError::RetryExhausted)?;
        self.target = Some(target); self.state = ClientState::Preparing;
        Ok(generation)
    }
    fn step(&mut self, generation: u64, from: ClientState, to: ClientState) -> Result<(), ClientError> {
        self.generation_check(generation)?;
        if self.state != from { return Err(ClientError::State); }
        self.state = to; Ok(())
    }
    pub fn finish_preparation(&mut self, generation: u64) -> Result<(), ClientError> {
        self.step(generation, ClientState::Preparing, ClientState::ReadyToProve)
    }
    pub fn begin_proof(&mut self, generation: u64) -> Result<(), ClientError> {
        self.step(generation, ClientState::ReadyToProve, ClientState::Proving)
    }
    pub fn finish_proof(&mut self, generation: u64) -> Result<(), ClientError> {
        self.step(generation, ClientState::Proving, ClientState::SubmissionReady)
    }
    pub fn mark_submitted(&mut self, generation: u64) -> Result<(), ClientError> {
        self.step(generation, ClientState::SubmissionReady, ClientState::AwaitingOutcome)?;
        Ok(())
    }
    pub fn outcome(&mut self, action: Digest, outcome: EffectOutcome) -> Result<(), ClientError> {
        if action != self.action { return Err(ClientError::Identity); }
        if !matches!(self.state, ClientState::AwaitingOutcome | ClientState::UncertainOutcome) {
            return Err(ClientError::State);
        }
        self.state = match outcome {
            EffectOutcome::Confirmed => ClientState::Confirmed,
            EffectOutcome::Absent => ClientState::Import,
            EffectOutcome::Unknown => ClientState::UncertainOutcome,
        };
        Ok(())
    }
    pub fn cancel(&mut self) {
        if matches!(self.state, ClientState::AwaitingOutcome | ClientState::UncertainOutcome | ClientState::Confirmed) { return; }
        if self.advance_generation().is_err() { self.invalidate(InvalidationReason::Corruption); return; }
        self.state = ClientState::Cancelled;
    }
    pub fn pause_stale_issuer(&mut self) {
        if matches!(self.state, ClientState::AwaitingOutcome | ClientState::UncertainOutcome | ClientState::Confirmed) { return; }
        if self.advance_generation().is_err() { self.invalidate(InvalidationReason::Corruption); return; }
        self.state = ClientState::PausedStaleIssuer;
    }
    pub fn invalidate(&mut self, reason: InvalidationReason) {
        self.invalid = Some(reason); self.state = ClientState::Invalidated;
    }
}
