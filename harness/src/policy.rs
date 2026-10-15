use crate::fixtures::field_from_decimal;
use crate::fixtures::Field;
use crate::registry::Registry;
use anyhow::{ensure, Result};
use serde::Serialize;
use serde_json::Value;
use solana_sdk::pubkey::Pubkey;
use std::collections::HashSet;
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    Strict,
    Historical,
}
#[derive(Serialize)]
pub struct Decision {
    pub accepted: bool,
    pub reason: &'static str,
}
pub struct VerifiedAuthorization {
    signals: Vec<String>,
}
pub fn verify_authorization(
    proof: &Value,
    signals: &[String],
    name: &str,
) -> Result<Option<VerifiedAuthorization>> {
    Ok(if crate::prover::verify(proof, signals, name)? {
        Some(VerifiedAuthorization {
            signals: signals.to_vec(),
        })
    } else {
        None
    })
}
#[derive(Default)]
pub struct AuthorizationState {
    consumed: HashSet<(Pubkey, Field)>,
}
#[derive(Clone, Copy)]
pub struct ActionContext {
    pub program: Pubkey,
    pub registry: Pubkey,
    pub recipient: Pubkey,
    pub action_id: Field,
}
impl AuthorizationState {
    pub fn is_consumed(&self, registry: &Pubkey, action_id: &Field) -> bool {
        self.consumed.contains(&(*registry, *action_id))
    }
    pub fn accept(
        &mut self,
        proof: &VerifiedAuthorization,
        registry: &Registry,
        policy: Policy,
        now: i64,
        context: ActionContext,
    ) -> Result<Decision> {
        if self
            .consumed
            .contains(&(context.registry, context.action_id))
        {
            return Ok(Decision {
                accepted: false,
                reason: "already-used",
            });
        }
        let expected_action = crate::solana::action_digest(
            &context.program,
            &context.registry,
            &context.recipient,
            &context.action_id,
        );
        if field_from_decimal(&proof.signals[4])? != expected_action {
            return Ok(Decision {
                accepted: false,
                reason: "action-mismatch",
            });
        }
        let decision = accept(&proof.signals, registry, policy, now)?;
        if decision.accepted {
            self.consumed.insert((context.registry, context.action_id));
        }
        Ok(decision)
    }
}
pub fn accept(
    signals: &[String],
    registry: &Registry,
    policy: Policy,
    now: i64,
) -> Result<Decision> {
    ensure!(signals.len() == 5, "Expected five public signals");
    let fields = signals
        .iter()
        .map(|value| field_from_decimal(value))
        .collect::<Result<Vec<_>>>()?;
    let not_before = signals[2].parse::<i64>()?;
    let not_after = signals[3].parse::<i64>()?;
    let reject = |reason| {
        Ok(Decision {
            accepted: false,
            reason,
        })
    };
    if not_before > now {
        return reject("not-yet-valid");
    }
    if not_after < now {
        return reject("expired");
    }
    if fields[1] != registry.issuer {
        return reject("issuer-mismatch");
    }
    let snapshot = registry
        .history
        .iter()
        .rev()
        .find(|snapshot| snapshot.root == fields[0]);
    let accepted = snapshot
        .map(|snapshot| {
            now.checked_sub(snapshot.published_at)
                .map(|age| {
                    age >= 0
                        && match policy {
                            Policy::Strict => fields[0] == registry.root(),
                            Policy::Historical => age <= 300,
                        }
                })
                .unwrap_or(false)
        })
        .unwrap_or(false);
    if !accepted {
        return reject("stale-root");
    }
    Ok(Decision {
        accepted: true,
        reason: "accepted",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{create_fixtures, field_decimal};
    #[test]
    fn verified_action_cannot_be_reused_under_a_new_receipt_id() {
        let mut registry =
            Registry::new(create_fixtures(1, 1_791_000_000, 1_791_086_400).unwrap()).unwrap();
        registry.snapshot(1000).unwrap();
        // This unit exercises policy after verification. Real proof composition is tested by the benchmark.
        let context = ActionContext {
            program: Pubkey::new_from_array([1; 32]),
            registry: Pubkey::new_from_array([2; 32]),
            recipient: Pubkey::new_from_array([4; 32]),
            action_id: [3; 32],
        };
        let expected_action = crate::solana::action_digest(
            &context.program,
            &context.registry,
            &context.recipient,
            &context.action_id,
        );
        let verified = VerifiedAuthorization {
            signals: vec![
                field_decimal(&registry.root()),
                field_decimal(&registry.issuer),
                "900".into(),
                "2000".into(),
                field_decimal(&expected_action),
            ],
        };
        let mut app = AuthorizationState::default();
        assert!(
            app.accept(&verified, &registry, Policy::Strict, 1001, context)
                .unwrap()
                .accepted
        );
        assert!(
            !app.accept(
                &verified,
                &registry,
                Policy::Strict,
                1001,
                ActionContext {
                    action_id: [6; 32],
                    ..context
                }
            )
            .unwrap()
            .accepted
        );
    }
}
