use crate::ClientError;
use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Instant};

#[derive(Clone)]
pub struct OperationControl {
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}
impl OperationControl {
    pub fn new(deadline: Instant) -> Self {
        Self { cancelled: Arc::new(AtomicBool::new(false)), deadline }
    }
    pub fn cancel(&self) { self.cancelled.store(true, Ordering::Release); }
    pub fn check(&self) -> Result<(), ClientError> {
        if self.cancelled.load(Ordering::Acquire) { return Err(ClientError::Cancelled); }
        if Instant::now() >= self.deadline { return Err(ClientError::Deadline); }
        Ok(())
    }
}
