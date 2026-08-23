//! End-to-end policy scenario: a scripted event list must produce an exact
//! violation rule-id sequence under the default and hardened rule sets.

use asg_common::events::Event;
use asg_common::policy_types::RuleSet;
use asg_policy::eval;

const BASE_TS: u64 = 1_787_356_800_000_000_000;

fn ts(i: usize) -> u64 {
    BASE_TS + (i as u64) * 120_000_000
}

fn scenario() -> Vec<Event> {
    vec![
        Event::ProcExec {
            pid: 400,
            tgid: 400,
            ppid: 1,
            cgroup_id: 9_001,
            comm: "bash".into(),
            args: vec!["-l".into()],
            uid: 1000,
            ts_ns: ts(0),
        },
        Event::ProcExec {
            pid: 401,
            tgid: 401,
            ppid: 400,
            cgroup_id: 9_001,
            comm: "node".into(),
            args: vec!["/usr/local/bin/claude-code".into()],
            uid: 1000,
            ts_ns: ts(1),
        },
        Event::ProcExec {
            pid: 402,
            tgid: 402,
            ppid: 401,
            cgroup_id: 9_001,
            comm: "npm".into(),
            args: vec!["exec", "setup-agent-tools"]
                .into_iter()
                .map(String::from)
                .collect(),
            uid: 1000,
            ts_ns: ts(2),
        },
        Event::NetConnect {
            pid: 403,
            tgid: 403,
            comm: "curl".into(),
            daddr: "registry.npmjs.org".into(),
            dport: 443,
            family: "IPv4".into(),
            ts_ns: ts(3),
        },
        Event::NetConnect {
            pid: 403,
            tgid: 403,
            comm: "curl".into(),
            daddr: "evil.telemetry.dev".into(),
            dport: 443,
            family: "IPv4".into(),
            ts_ns: ts(4),
        },
        Event::FileOpen {
            pid: 404,
            tgid: 404,
            comm: "cat".into(),
            path: "/home/dev/project/.env".into(),
            flags: 0,
            ts_ns: ts(5),
            is_write_hint: false,
        },
        Event::NetConnect {
            pid: 406,
            tgid: 406,
            comm: "wget".into(),
            daddr: "ngrok.io".into(),
            dport: 443,
            family: "IPv4".into(),
            ts_ns: ts(6),
        },
        Event::ProcExec {
            pid: 407,
            tgid: 407,
            ppid: 401,
            cgroup_id: 9_001,
            comm: "pip3".into(),
            args: vec!["install", "requests"]
                .into_iter()
                .map(String::from)
                .collect(),
            uid: 1000,
            ts_ns: ts(7),
        },
        Event::FileOpen {
            pid: 408,
            tgid: 408,
            comm: "ssh-keygen".into(),
            path: "/home/dev/.ssh/id_rsa".into(),
            flags: 0,
            ts_ns: ts(8),
            is_write_hint: false,
        },
        Event::CapEscalate {
            pid: 409,
            tgid: 409,
            comm: "sudo".into(),
            caps: "CAP_SYS_ADMIN".into(),
            ts_ns: ts(9),
        },
    ]
}

fn hardened_rules() -> RuleSet {
    RuleSet {
        denied_hosts: vec!["evil.telemetry.dev".to_string()],
        ..Default::default()
    }
}

#[test]
fn default_rules_produce_expected_sequence() {
    let rules = RuleSet::default();
    let s = |x: &str| x.to_string();
    let expected = vec![
        None,
        None,
        Some(s("PROC_DENIED")),
        None,
        None,
        Some(s("SECRET_ACCESS")),
        Some(s("NET_WARN")),
        Some(s("PROC_DENIED")),
        Some(s("SECRET_ACCESS")),
        Some(s("CAP_ESCALATION")),
    ];
    let got: Vec<Option<String>> = scenario()
        .iter()
        .map(|e| eval(e, &rules).first().map(|v| v.rule_id.clone()))
        .collect();
    assert_eq!(got, expected);
}

#[test]
fn hardened_rules_add_net_denial() {
    let rules = hardened_rules();
    let events = scenario();
    let ids: Vec<String> = events
        .iter()
        .flat_map(|e| eval(e, &rules))
        .map(|v| v.rule_id)
        .collect();
    assert!(ids.iter().any(|id| id == "NET_DENIED"));
    assert_eq!(
        ids,
        vec![
            "PROC_DENIED",
            "NET_DENIED",
            "SECRET_ACCESS",
            "NET_WARN",
            "PROC_DENIED",
            "SECRET_ACCESS",
            "CAP_ESCALATION"
        ]
    );
}

#[test]
fn every_violation_has_nonempty_message_and_evidence() {
    let rules = hardened_rules();
    for e in scenario() {
        for v in eval(&e, &rules) {
            assert!(!v.message.is_empty());
            assert!(v.evidence.is_object());
            assert!(!v.rule_id.is_empty());
        }
    }
}
