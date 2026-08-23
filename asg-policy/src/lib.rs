//! AgentScope policy engine: hand-written glob matcher plus rule evaluation
//! that turns kernel events into severity-tagged violations.

pub mod glob;
pub mod rules;

use serde::Serialize;

/// Violation severity ordering used by the dashboard chips.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// A single policy breach with machine-readable evidence.
#[derive(Debug, Clone, Serialize)]
pub struct Violation {
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
    pub evidence: serde_json::Value,
}

/// Evaluates one event against the rule set, returning zero or more violations.
pub fn eval(
    event: &asg_common::events::Event,
    rules: &asg_common::policy_types::RuleSet,
) -> Vec<Violation> {
    rules::eval_event(event, rules)
}
