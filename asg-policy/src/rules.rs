//! Rule evaluation mapping kernel events to violations.

use crate::{Severity, Violation};
use asg_common::events::Event;
use asg_common::policy_types::RuleSet;
use serde_json::json;
use std::net::IpAddr;

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
        Event::ProcExec {
            comm,
            pid,
            tgid,
            args,
            ..
        } => eval_proc_exec(comm, *pid, *tgid, args, rules),
        Event::FileOpen {
            comm,
            path,
            tgid,
            is_write_hint,
            ..
        } => eval_file_open(comm, path, *tgid, *is_write_hint, rules),
        Event::NetConnect {
            comm,
            daddr,
            dport,
            tgid,
            ..
        } => eval_net_connect(comm, daddr, *dport, *tgid, rules),
        Event::CapEscalate {
            comm, caps, tgid, ..
        } => vec![Violation {
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
    if rules
        .denied_processes
        .iter()
        .any(|d| d.to_ascii_lowercase() == base)
    {
        return vec![Violation {
            rule_id: "PROC_DENIED".to_string(),
            severity: Severity::Critical,
            message: format!(
                "denied process '{}' (basename '{}') was executed",
                comm, base
            ),
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
            matched
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
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
    let denied = rules
        .denied_hosts
        .iter()
        .find(|h| destination_matches(h, daddr));
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
    let warned = rules
        .warn_hosts
        .iter()
        .find(|h| destination_matches(h, daddr));
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

/// Matches a destination against either an IP CIDR or the existing hostname/
/// address glob syntax. Kernel-sourced connect events carry numeric IPs, while
/// replay and application-sourced events may still carry DNS names.
fn destination_matches(pattern: &str, destination: &str) -> bool {
    if let Some((network, prefix)) = pattern.split_once('/') {
        if let (Ok(network), Ok(destination), Ok(prefix)) = (
            network.parse::<IpAddr>(),
            destination.parse::<IpAddr>(),
            prefix.parse::<u8>(),
        ) {
            return match (network, destination) {
                (IpAddr::V4(network), IpAddr::V4(destination)) if prefix <= 32 => {
                    let mask = if prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - prefix)
                    };
                    u32::from(network) & mask == u32::from(destination) & mask
                }
                (IpAddr::V6(network), IpAddr::V6(destination)) if prefix <= 128 => {
                    let mask = if prefix == 0 {
                        0
                    } else {
                        u128::MAX << (128 - prefix)
                    };
                    u128::from(network) & mask == u128::from(destination) & mask
                }
                _ => false,
            };
        }
    }
    crate::glob::matches(pattern, destination)
}

/// Normalizes a path for glob matching against secret path patterns.
///
/// Contract:
/// 1. All backslashes (`\`) are mapped to forward slashes (`/`).
/// 2. Verbatim prefixes `\\?\` and `\\.\` (Windows extended-length / device paths)
///    are stripped entirely.
/// 3. A leading `./` is stripped repeatedly (so `.env`, `./.env`, `././.env`
///    all normalize to `.env`).
/// 4. **Case folding** is applied to the ENTIRE path ONLY when the path has a
///    Windows drive prefix (`[A-Za-z]:/`) or a UNC prefix (`//host/share` or
///    `\\host\share` after backslash mapping). Pure Unix paths (no drive/UNC
///    prefix) remain case-sensitive.
/// 5. A pathological Unix file literally named like `C:\foo` (no drive prefix,
///    just a weird filename containing backslashes) is NOT case-folded — it
///    is treated as a Unix path with backslashes converted to forward slashes
///    (`C:/foo`), preserving case.
fn normalize_path(path: &str) -> String {
    let mut p = path.replace('\\', "/");

    // Strip Windows verbatim prefixes: \\?\ and \\.\ (after backslash->slash: //?/ and //./)
    if let Some(rest) = p.strip_prefix("//?/") {
        p = rest.to_string();
    } else if let Some(rest) = p.strip_prefix("//./") {
        p = rest.to_string();
    }

    // Strip leading ./ repeatedly
    while let Some(rest) = p.strip_prefix("./") {
        p = rest.to_string();
    }

    // Detect Windows drive prefix (C:/, D:/, etc.) or UNC prefix (//host/share).
    // A drive-letter path is considered Windows only if it has at least one more
    // path segment after the drive root (i.e., contains a '/' after "C:/").
    // This excludes the pathological Unix file literally named "C:\foo" which
    // becomes "C:/foo" (no additional separator) and stays case-sensitive.
    let has_drive_prefix = p.len() >= 3
        && p.as_bytes()[1] == b':'
        && p.as_bytes()[2] == b'/'
        && p[..1]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic());
    let has_unc_prefix = p.starts_with("//");
    let has_drive_with_segments = has_drive_prefix && p[3..].contains('/');
    let is_windows = has_unc_prefix || has_drive_with_segments;

    if is_windows {
        p.to_ascii_lowercase()
    } else {
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval;

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
    fn numeric_kernel_destinations_support_ipv4_and_ipv6_cidrs() {
        let rules = RuleSet {
            denied_hosts: vec!["203.0.113.0/24".into(), "2001:db8:dead::/48".into()],
            ..RuleSet::default()
        };

        for (daddr, family) in [("203.0.113.91", "IPv4"), ("2001:db8:dead:beef::1", "IPv6")] {
            let event = Event::NetConnect {
                pid: 1,
                tgid: 2,
                comm: "curl".into(),
                daddr: daddr.into(),
                dport: 443,
                family: family.into(),
                ts_ns: 1,
            };
            let violations = eval(&event, &rules);
            assert_eq!(violations.len(), 1, "{daddr} must match its CIDR");
            assert_eq!(violations[0].rule_id, "NET_DENIED");
        }

        let outside = Event::NetConnect {
            pid: 1,
            tgid: 2,
            comm: "curl".into(),
            daddr: "203.0.114.1".into(),
            dport: 443,
            family: "IPv4".into(),
            ts_ns: 1,
        };
        assert!(eval(&outside, &rules).is_empty());
    }

    #[test]
    fn malformed_cidr_does_not_match_numeric_destination() {
        assert!(!destination_matches("203.0.113.0/99", "203.0.113.1"));
        assert!(!destination_matches("2001:db8::/129", "2001:db8::1"));
        assert!(destination_matches("203.0.*", "203.0.113.1"));
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

    #[test]
    fn legacy_kernel_records_cannot_fabricate_path_or_host_violations() {
        // v0.1 identity-only kernel records still widen with empty path/daddr
        // sentinels; no rule may fire from absent evidence. comm-based rules
        // continue to work during a rolling probe/collector upgrade.
        let rules = RuleSet::default();
        for (kind, comm, expected) in [
            ("proc_exec", "npm", "PROC_DENIED"),
            ("proc_exec", "bash", ""),
            ("file_open", "cat", ""),
            ("net_connect", "curl", ""),
        ] {
            let raw = format!(
                "{{\"type\":\"{kind}\",\"pid\":1,\"tgid\":2,\"comm\":\"{comm}\",\"ts_ns\":3}}"
            );
            let rec: asg_common::events::KernelRecord =
                serde_json::from_str(&raw).expect("probe-shaped record must parse");
            let event = rec.widen().expect("kernel-producible kind");
            let violations = eval(&event, &rules);
            let ids: Vec<&str> = violations.iter().map(|v| v.rule_id.as_str()).collect();
            if expected.is_empty() {
                assert!(ids.is_empty(), "{kind}/{comm}: expected no violations");
            } else {
                assert_eq!(ids, [expected], "{kind}/{comm}");
            }
        }
    }

    #[test]
    fn captured_kernel_evidence_drives_real_policy_rules() {
        let open: asg_common::events::KernelRecord = serde_json::from_str(
            r#"{"type":"file_open","pid":1,"tgid":2,"comm":"cat","ts_ns":3,"path":"/workspace/.env","flags":0}"#,
        )
        .unwrap();
        let violations = eval(&open.widen().unwrap(), &RuleSet::default());
        assert_eq!(violations[0].rule_id, "SECRET_ACCESS");

        let connect: asg_common::events::KernelRecord = serde_json::from_str(
            r#"{"type":"net_connect","pid":1,"tgid":2,"comm":"curl","ts_ns":4,"daddr":"203.0.113.9","dport":443,"family":"IPv4"}"#,
        )
        .unwrap();
        let mut rules = RuleSet::default();
        rules.denied_hosts.push("203.0.113.0/24".into());
        let violations = eval(&connect.widen().unwrap(), &rules);
        assert_eq!(violations[0].rule_id, "NET_DENIED");
    }

    #[test]
    fn normalize_path_windows_vectors() {
        let cases: Vec<(&str, &str)> = vec![
            // Basic Unix paths (unchanged, case-sensitive)
            ("/home/user/.env", "/home/user/.env"),
            ("./.env", ".env"),
            ("././.env", ".env"),
            ("relative/path", "relative/path"),
            // Windows drive prefix: backslashes -> forward, case-folded
            (r"C:\Users\x\.env", "c:/users/x/.env"),
            (r"C:\USERS\X\.ENV", "c:/users/x/.env"),
            (r"D:\Secrets\key.pem", "d:/secrets/key.pem"),
            // Windows verbatim prefixes stripped, then treated as drive paths
            (r"\\?\C:\Users\x\.env", "c:/users/x/.env"),
            (r"\\.\C:\x\.env", "c:/x/.env"),
            (r"\\?\D:\Secrets\key.pem", "d:/secrets/key.pem"),
            // UNC paths: case-folded
            (r"//server/share/.env", "//server/share/.env"),
            (r"\\server\share\.env", "//server/share/.env"),
            (r"//SERVER/SHARE/.ENV", "//server/share/.env"),
            // Pathological Unix file literally named like "C:\foo" (single segment
            // after drive, no subdirectories) — backslashes converted, but NO case
            // folding because it lacks the multi-segment structure of a real Windows
            // path. A file literally named "C:\FOO\BAR" (with subdirs) IS case-folded
            // as it matches Windows path structure.
            (r"C:\foo", "C:/foo"),
            // Mixed: leading ./ on Windows paths
            (r"./C:\Users\x\.env", "c:/users/x/.env"),
            (r"././C:\Users\x\.env", "c:/users/x/.env"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                normalize_path(input),
                expected,
                "normalize_path({:?}) = {:?}, expected {:?}",
                input,
                normalize_path(input),
                expected
            );
        }
    }

    #[test]
    fn secret_detection_windows_paths_match_globs() {
        let rules = RuleSet::default();
        // Default secret globs include: .ssh/**, **/.ssh/**, .env, **/.env, **/.aws/**, **/.kube/config, **/*wallet*, **/id_rsa*
        let windows_secret_paths = vec![
            r"C:\Users\x\.env",
            r"\\?\C:\x\.env",
            r"C:\USERS\.Env",
            r"//server/share/.env",
            r"\\server\share\.ssh\id_rsa",
            r"D:\projects\.aws\credentials",
            r"C:\Users\bob\wallet.dat",
            r"C:\Users\alice\.kube\config",
        ];
        for path in windows_secret_paths {
            let e = Event::FileOpen {
                pid: 1,
                tgid: 2,
                comm: "cat".into(),
                path: path.into(),
                flags: 0,
                ts_ns: 5,
                is_write_hint: false,
            };
            let v = eval(&e, &rules);
            assert_eq!(
                v.len(),
                1,
                "path {:?} should trigger SECRET_ACCESS but got no violations",
                path
            );
            assert_eq!(
                v[0].rule_id, "SECRET_ACCESS",
                "path {:?} wrong rule id",
                path
            );
        }
    }

    #[test]
    fn secret_detection_unix_paths_unaffected() {
        let rules = RuleSet::default();
        let unix_secret_paths = vec![
            "/home/user/.env",
            "/home/user/.ssh/id_rsa",
            "/home/user/.aws/credentials",
            "/home/user/.kube/config",
            "/home/user/wallet.dat",
        ];
        for path in unix_secret_paths {
            let e = Event::FileOpen {
                pid: 1,
                tgid: 2,
                comm: "cat".into(),
                path: path.into(),
                flags: 0,
                ts_ns: 5,
                is_write_hint: false,
            };
            let v = eval(&e, &rules);
            assert_eq!(
                v.len(),
                1,
                "unix path {:?} should trigger SECRET_ACCESS but got no violations",
                path
            );
            assert_eq!(v[0].rule_id, "SECRET_ACCESS");
        }
    }

    #[test]
    fn secret_detection_case_sensitivity_unix_vs_windows() {
        let rules = RuleSet::default();
        // Unix path with different case should NOT match (case-sensitive)
        let e_unix = Event::FileOpen {
            pid: 1,
            tgid: 2,
            comm: "cat".into(),
            path: "/HOME/USER/.ENV".into(), // different case
            flags: 0,
            ts_ns: 5,
            is_write_hint: false,
        };
        let v = eval(&e_unix, &rules);
        // Unix paths are case-sensitive; .ENV != .env so no match
        assert!(v.is_empty(), "Unix path with wrong case should not match");

        // Windows path with different case SHOULD match (case-folded)
        let e_win = Event::FileOpen {
            pid: 1,
            tgid: 2,
            comm: "cat".into(),
            path: r"C:\USERS\X\.ENV".into(),
            flags: 0,
            ts_ns: 5,
            is_write_hint: false,
        };
        let v = eval(&e_win, &rules);
        assert_eq!(
            v.len(),
            1,
            "Windows path with different case should match after case-folding"
        );
        assert_eq!(v[0].rule_id, "SECRET_ACCESS");
    }
}
