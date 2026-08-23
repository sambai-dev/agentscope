//! Rule evaluation mapping kernel events to violations.

use crate::{Severity, Violation};
use asg_common::events::Event;
use asg_common::policy_types::RuleSet;
use serde_json::json;

/// Extracts the final path component treating both `/` and `\` as separators.
pub fn basename(path: &str) -> &str {
    let trimmed = path.trim_end_matches(['/', '\\']);
    match trimmed.rfind(['/', '\\']) {
        Some(idx) => &trimmed[idx + 1..],
        None => trimmed,
    }
}

/// Evaluates a single event, returning every violation it triggers.
pub fn eval_event(event: &Event, rules: &RuleSet) -> Vec<Violation> {
    match event {
        Event::ProcExec { comm, pid, tgid, args, .. } => {
            eval_proc_exec(comm, *pid, *tgid, args, rules)
        }
        Event::FileOpen { comm, path, tgid, is_write_hint, .. } => {
            eval_file_open(comm, path, *tgid, *is_write_hint, rules)
        }
        Event::NetConnect { comm, daddr, dport, tgid, .. } => {
            eval_net_connect(comm, daddr, *dport, *tgid, rules)
        }
        Event::CapEscalate { comm, caps, tgid, .. } => vec![Violation {
            rule_id: "CAP_ESCALATION".to_string(),
            severity: Severity::High,
            message: format!(
                "process '{}' (tgid {}) escalated capabilities to '{}'",
                comm, tgid, caps
            ),
            evidence: json!({ "comm": comm, "tgid": tgid, "caps": caps }),
        }],
    }
}

fn eval_proc_exec(
    comm: &str,
    pid: u32,
    tgid: u32,
    args: &[String],
    rules: &RuleSet,
) -> Vec<Violation> {
    let base = basename(comm).to_ascii_lowercase();
    if rules.denied_processes.iter().any(|d| d.to_ascii_lowercase() == base) {
        return vec![Violation {
            rule_id: "PROC_DENIED".to_string(),
            severity: Severity::Critical,
            message: format!("denied process '{}' (basename '{}') was executed", comm, base),
            evidence: json!({ "comm": comm, "pid": pid, "tgid": tgid, "args": args }),
        }];
    }
    Vec::new()
}

fn eval_file_open(
    comm: &str,
    path: &str,
    tgid: u32,
    is_write_hint: bool,
    rules: &RuleSet,
) -> Vec<Violation> {
    let normalized = normalize_path(path);
    let matched: Vec<&String> = rules
        .secret_path_globs
        .iter()
        .filter(|g| crate::glob::matches(g, &normalized))
        .collect();
    if matched.is_empty() {
        return Vec::new();
    }
    let mode = if is_write_hint { "write" } else { "read" };
    vec![Violation {
        rule_id: "SECRET_ACCESS".to_string(),
        severity: Severity::Critical,
        message: format!(
            "process '{}' opened secret path '{}' for {} (globs: {})",
            comm,
            normalized,
            mode,
            matched.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        ),
        evidence: json!({ "path": normalized, "comm": comm, "tgid": tgid, "mode": mode, "matched_globs": matched }),
    }]
}

fn eval_net_connect(
    comm: &str,
    daddr: &str,
    dport: u16,
    tgid: u32,
    rules: &RuleSet,
) -> Vec<Violation> {
    let denied = rules.denied_hosts.iter().find(|h| crate::glob::matches(h, daddr));
    if let Some(host) = denied {
        return vec![Violation {
            rule_id: "NET_DENIED".to_string(),
            severity: Severity::Critical,
            message: format!(
                "process '{}' connected to denied host '{}' port {}",
                comm, daddr, dport
            ),
            evidence: json!({ "host": daddr, "dport": dport, "comm": comm, "tgid": tgid, "matched_glob": host }),
        }];
    }
    let warned = rules.warn_hosts.iter().find(|h| crate::glob::matches(h, daddr));
    if let Some(host) = warned {
        return vec![Violation {
            rule_id: "NET_WARN".to_string(),
            severity: Severity::Medium,
            message: format!(
                "process '{}' connected to warn-listed host '{}' port {}",
                comm, daddr, dport
            ),
            evidence: json!({ "host": daddr, "dport": dport, "comm": comm, "tgid": tgid, "matched_glob": host }),
        }];
    }
    Vec::new()
}

/// Strips a leading `./` so globs like `.env` and `**/.env` behave uniformly.
fn normalize_path(path: &str) -> String {
    let mut p = path;
    while let Some(rest) = p.strip_prefix("./") {
        p = rest;
    }
    p.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_extraction() {
        assert_eq!(basename("npm"), "npm");
        assert_eq!(basename("/usr/bin/curl"), "curl");
        assert_eq!(basename("C:\\tools\\pip.exe"), "pip.exe");
        assert_eq!(basename("/usr/bin/"), "bin");
        assert_eq!(basename(""), "");
    }

    #[test]
    fn proc_exec_denied_by_basename_not_full_comm() {
        let rules = RuleSet::default();
        let e = Event::ProcExec {
            pid: 10,
            tgid: 11,
            ppid: 2,
            cgroup_id: 7,
            comm: "/usr/local/bin/npm".into(),
            args: vec!["install".into()],
            uid: 1000,
            ts_ns: 1,
        };
        let v = eval(&e, &rules);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule_id, "PROC_DENIED");
        assert_eq!(v[0].severity, Severity::Critical);
    }

    #[test]
    fn shell_is_allowed() {
        let rules = RuleSet::default();
        let e = Event::ProcExec {
            pid: 10,
            tgid: 11,
            ppid: 2,
            cgroup_id: 7,
            comm: "bash".into(),
            args: vec![],
            uid: 1000,
            ts_ns: 1,
        };
        assert!(eval(&e, &rules).is_empty());
    }

    #[test]
    fn secret_read_flagged_critical() {
        let rules = RuleSet::default();
        let e = Event::FileOpen {
            pid: 1,
            tgid: 2,
            comm: "cat".into(),
            path: "/home/dev/project/.env".into(),
            flags: 0,
            ts_ns: 5,
            is_write_hint: false,
        };
        let v = eval(&e, &rules);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule_id, "SECRET_ACCESS");
        assert_eq!(v[0].evidence["path"], "/home/dev/project/.env");
    }

    #[test]
    fn benign_open_allowed() {
        let rules = RuleSet::default();
        let e = Event::FileOpen {
            pid: 1,
            tgid: 2,
            comm: "gcc".into(),
            path: "/usr/include/stdio.h".into(),
            flags: 0,
            ts_ns: 6,
            is_write_hint: false,
        };
        assert!(eval(&e, &rules).is_empty());
    }

    #[test]
    fn net_denied_beats_warn_and_default_allows() {
        let rules = RuleSet::default();
        let allow = Event::NetConnect {
            pid: 1,
            tgid: 2,
            comm: "node".into(),
            daddr: "registry.npmjs.org".into(),
            dport: 443,
            family: "IPv4".into(),
            ts_ns: 7,
        };
        assert!(eval(&allow, &rules).is_empty());

        let warn = Event::NetConnect {
            pid: 1,
            tgid: 2,
            comm: "curl".into(),
            daddr: "ngrok.io".into(),
            dport: 443,
            family: "IPv4".into(),
            ts_ns: 8,
        };
        let v = eval(&warn, &rules);
        assert_eq!(v[0].rule_id, "NET_WARN");
        assert_eq!(v[0].severity, Severity::Medium);

        let mut strict = RuleSet::default();
        strict.denied_hosts.push("*.telemetry.dev".into());
        let deny = Event::NetConnect {
            pid: 1,
            tgid: 2,
            comm: "curl".into(),
            daddr: "evil.telemetry.dev".into(),
            dport: 443,
            family: "IPv4".into(),
            ts_ns: 9,
        };
        let v = eval(&deny, &strict);
        assert_eq!(v[0].rule_id, "NET_DENIED");
        assert_eq!(v[0].severity, Severity::Critical);
    }

    #[test]
    fn cap_escalation_high() {
        let rules = RuleSet::default();
        let e = Event::CapEscalate {
            pid: 3,
            tgid: 4,
            comm: "sudo".into(),
            caps: "CAP_SYS_ADMIN".into(),
            ts_ns: 10,
        };
        let v = eval(&e, &rules);
        assert_eq!(v[0].rule_id, "CAP_ESCALATION");
        assert_eq!(v[0].severity, Severity::High);
    }
}
