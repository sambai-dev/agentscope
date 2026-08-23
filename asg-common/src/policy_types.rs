//! Policy configuration types shared by the collector, API and dashboard.

use serde::{Deserialize, Serialize};

/// Enforcement action attached to policy decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Deny,
    Warn,
    Audit,
}

/// Declarative rule set evaluated against every captured event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleSet {
    /// Glob patterns (with `**` support) marking secret-bearing paths.
    pub secret_path_globs: Vec<String>,
    /// Process basenames agents are never allowed to execute.
    pub denied_processes: Vec<String>,
    /// Destination hosts that trigger a critical network violation.
    pub denied_hosts: Vec<String>,
    /// Destination hosts that trigger a medium-severity warning.
    pub warn_hosts: Vec<String>,
    /// Ingest backpressure ceiling per second.
    pub max_events_per_sec: u32,
}

impl Default for RuleSet {
    fn default() -> Self {
        Self {
            secret_path_globs: [
                ".ssh/**",
                "**/.ssh/**",
                ".env",
                "**/.env",
                "**/.aws/**",
                "**/.kube/config",
                "**/*wallet*",
                "**/id_rsa*",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            denied_processes: [
                "npm", "pnpm", "yarn", "pip", "pip3", "cargo", "curl", "wget",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            denied_hosts: Vec::new(),
            warn_hosts: ["*.onion", "pastebin.com", "ngrok.io", "trycloudflare.com"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            max_events_per_sec: 10_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_json_uses_defaults() {
        let rs: RuleSet = serde_json::from_str("{\"denied_hosts\":[\"evil.dev\"]}").unwrap();
        assert_eq!(rs.denied_hosts, vec!["evil.dev".to_string()]);
        assert!(rs.secret_path_globs.contains(&".env".to_string()));
        assert_eq!(rs.max_events_per_sec, 10_000);
    }

    #[test]
    fn default_round_trip() {
        let rs = RuleSet::default();
        let json = serde_json::to_string(&rs).unwrap();
        let back: RuleSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back.denied_processes, rs.denied_processes);
        assert_eq!(back.warn_hosts, rs.warn_hosts);
    }
}
