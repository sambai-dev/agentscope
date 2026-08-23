//! Deterministic simulated kernel-event source (all platforms).
//!
//! Replays a fixed 24-event scenario — shell spawn, agent child, package
//! manager abuse, secret reads, suspicious egress, capability escalation —
//! paced at 120 ms and looping forever with fresh task ids each pass so the
//! demo behaves identically on every machine.

use asg_common::events::Event;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tracing::warn;

/// Fixed scenario epoch: 2026-08-22T00:00:00Z.
pub const SCENARIO_BASE_TS_NS: u64 = 1_787_356_800_000_000_000;

/// Inter-event pacing inside one scenario pass.
pub const SCENARIO_PACE_MS: u64 = 120;

/// Number of events in one full scenario pass.
pub const SCENARIO_LEN: usize = 24;

fn ts(i: u64) -> u64 {
    SCENARIO_BASE_TS_NS + i * 120_000_000
}

/// Builds the scripted event list for pass `pass` with pass-scoped task ids.
pub fn script(pass: u64) -> Vec<Event> {
    let off = pass * 1_000;
    let cgid = 9_001 + pass;
    let t = |i: u64| ts(SCENARIO_LEN as u64 * pass + i);
    let p = |n: u32| n + off as u32;
    let s = |v: &str| v.to_string();

    vec![
        Event::ProcExec {
            pid: p(400),
            tgid: p(400),
            ppid: 1,
            cgroup_id: cgid,
            comm: s("bash"),
            args: vec![s("-l")],
            uid: 1000,
            ts_ns: t(0),
        },
        Event::ProcExec {
            pid: p(401),
            tgid: p(401),
            ppid: p(400),
            cgroup_id: cgid,
            comm: s("node"),
            args: vec![s("/usr/local/bin/claude-code")],
            uid: 1000,
            ts_ns: t(1),
        },
        Event::ProcExec {
            pid: p(402),
            tgid: p(402),
            ppid: p(401),
            cgroup_id: cgid,
            comm: s("npm"),
            args: vec![s("exec"), s("setup-agent-tools")],
            uid: 1000,
            ts_ns: t(2),
        },
        Event::ProcExec {
            pid: p(403),
            tgid: p(403),
            ppid: p(402),
            cgroup_id: cgid,
            comm: s("curl"),
            args: vec![s("https://registry.npmjs.org/-/ping")],
            uid: 1000,
            ts_ns: t(3),
        },
        Event::NetConnect {
            pid: p(404),
            tgid: p(403),
            comm: s("curl"),
            daddr: s("registry.npmjs.org"),
            dport: 443,
            family: s("IPv4"),
            ts_ns: t(4),
        },
        Event::NetConnect {
            pid: p(404),
            tgid: p(403),
            comm: s("curl"),
            daddr: s("evil.telemetry.dev"),
            dport: 443,
            family: s("IPv4"),
            ts_ns: t(5),
        },
        Event::FileOpen {
            pid: p(405),
            tgid: p(405),
            comm: s("cat"),
            path: s("/home/dev/project/.env"),
            flags: 0,
            ts_ns: t(6),
            is_write_hint: false,
        },
        Event::NetConnect {
            pid: p(406),
            tgid: p(406),
            comm: s("wget"),
            daddr: s("ngrok.io"),
            dport: 443,
            family: s("IPv4"),
            ts_ns: t(7),
        },
        Event::ProcExec {
            pid: p(407),
            tgid: p(407),
            ppid: p(401),
            cgroup_id: cgid,
            comm: s("pip3"),
            args: vec![s("install"), s("requests")],
            uid: 1000,
            ts_ns: t(8),
        },
        Event::FileOpen {
            pid: p(408),
            tgid: p(408),
            comm: s("ssh-keygen"),
            path: s("/home/dev/.ssh/id_rsa"),
            flags: 0,
            ts_ns: t(9),
            is_write_hint: false,
        },
        Event::CapEscalate {
            pid: p(409),
            tgid: p(409),
            comm: s("sudo"),
            caps: s("CAP_SYS_ADMIN,CAP_NET_ADMIN"),
            ts_ns: t(10),
        },
        Event::ProcExec {
            pid: p(410),
            tgid: p(410),
            ppid: p(400),
            cgroup_id: cgid,
            comm: s("git"),
            args: vec![s("status")],
            uid: 1000,
            ts_ns: t(11),
        },
        Event::FileOpen {
            pid: p(411),
            tgid: p(410),
            comm: s("git"),
            path: s("/home/dev/project/.git/index"),
            flags: 0,
            ts_ns: t(12),
            is_write_hint: false,
        },
        Event::NetConnect {
            pid: p(412),
            tgid: p(410),
            comm: s("git-remote-https"),
            daddr: s("github.com"),
            dport: 443,
            family: s("IPv4"),
            ts_ns: t(13),
        },
        Event::ProcExec {
            pid: p(413),
            tgid: p(413),
            ppid: p(400),
            cgroup_id: cgid,
            comm: s("rg"),
            args: vec![s("TODO"), s("src/")],
            uid: 1000,
            ts_ns: t(14),
        },
        Event::FileOpen {
            pid: p(414),
            tgid: p(413),
            comm: s("rg"),
            path: s("/home/dev/project/src/main.rs"),
            flags: 0,
            ts_ns: t(15),
            is_write_hint: false,
        },
        Event::ProcExec {
            pid: p(415),
            tgid: p(415),
            ppid: p(401),
            cgroup_id: cgid,
            comm: s("cargo"),
            args: vec![s("build"), s("--release")],
            uid: 1000,
            ts_ns: t(16),
        },
        Event::FileOpen {
            pid: p(416),
            tgid: p(415),
            comm: s("cargo"),
            path: s("/home/dev/.cargo/registry/index.crates.io.json"),
            flags: 0,
            ts_ns: t(17),
            is_write_hint: true,
        },
        Event::NetConnect {
            pid: p(417),
            tgid: p(415),
            comm: s("cargo"),
            daddr: s("static.crates.io"),
            dport: 443,
            family: s("IPv4"),
            ts_ns: t(18),
        },
        Event::ProcExec {
            pid: p(418),
            tgid: p(418),
            ppid: p(402),
            cgroup_id: cgid,
            comm: s("yarn"),
            args: vec![s("add"), s("left-pad")],
            uid: 1000,
            ts_ns: t(19),
        },
        Event::NetConnect {
            pid: p(419),
            tgid: p(418),
            comm: s("yarn"),
            daddr: s("registry.yarnpkg.com"),
            dport: 443,
            family: s("IPv4"),
            ts_ns: t(20),
        },
        Event::FileOpen {
            pid: p(420),
            tgid: p(420),
            comm: s("tee"),
            path: s("/etc/hosts"),
            flags: 0o644,
            ts_ns: t(21),
            is_write_hint: true,
        },
        Event::FileOpen {
            pid: p(421),
            tgid: p(405),
            comm: s("cat"),
            path: s("/home/dev/.aws/credentials"),
            flags: 0,
            ts_ns: t(22),
            is_write_hint: false,
        },
        Event::NetConnect {
            pid: p(422),
            tgid: p(403),
            comm: s("curl"),
            daddr: s("pastebin.com"),
            dport: 443,
            family: s("IPv4"),
            ts_ns: t(23),
        },
    ]
}

/// Runs the scenario forever, pacing events and rotating task ids per pass.
pub async fn run(tx: Sender<Event>) {
    let mut pass: u64 = 0;
    loop {
        for event in script(pass) {
            if tx.send(event).await.is_err() {
                warn!("event channel closed; simulator exiting");
                return;
            }
            tokio::time::sleep(Duration::from_millis(SCENARIO_PACE_MS)).await;
        }
        pass = pass.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_order_and_timestamps() {
        let a = script(0);
        let b = script(0);
        assert_eq!(a, b);
        assert_eq!(a.len(), SCENARIO_LEN);
        let mut last = 0u64;
        for e in &a {
            assert!(e.ts() > last);
            last = e.ts();
        }
    }

    #[test]
    fn passes_rotate_task_ids_but_keep_order() {
        let a: Vec<String> = script(0).iter().map(|e| format!("{:?}", e.kind())).collect();
        let b: Vec<String> = script(3).iter().map(|e| format!("{:?}", e.kind())).collect();
        assert_eq!(a, b);
        let first_a = &script(0)[0];
        let first_b = &script(3)[0];
        assert_ne!(first_a.tgid(), first_b.tgid());
    }

    #[test]
    fn scenario_contains_expected_violation_triggers() {
        use asg_common::policy_types::RuleSet;
        use asg_policy::eval;
        let rules = RuleSet::default();
        let ids: Vec<String> = script(0)
            .iter()
            .flat_map(|e| eval(e, &rules))
            .map(|v| v.rule_id)
            .collect();
        assert!(ids.contains(&"PROC_DENIED".to_string()));
        assert!(ids.contains(&"SECRET_ACCESS".to_string()));
        assert!(ids.contains(&"NET_WARN".to_string()));
        assert!(ids.contains(&"CAP_ESCALATION".to_string()));
    }
}
