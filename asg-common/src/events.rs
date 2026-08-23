//! Kernel event model mirroring what the eBPF probes emit per agent cgroup.

use serde::{Deserialize, Serialize};

/// A single syscall-level observation captured by a probe (or the simulator).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// sched_process_exec: a new program image replaced a task.
    ProcExec {
        pid: u32,
        tgid: u32,
        ppid: u32,
        cgroup_id: u64,
        comm: String,
        args: Vec<String>,
        uid: u32,
        ts_ns: u64,
    },
    /// sys_enter_openat: a path was opened for read or write.
    FileOpen {
        pid: u32,
        tgid: u32,
        comm: String,
        path: String,
        flags: u32,
        ts_ns: u64,
        is_write_hint: bool,
    },
    /// sys_enter_connect: an outbound connection attempt.
    NetConnect {
        pid: u32,
        tgid: u32,
        comm: String,
        daddr: String,
        dport: u16,
        family: String,
        ts_ns: u64,
    },
    /// Capability escalation observed on the current task.
    CapEscalate {
        pid: u32,
        tgid: u32,
        comm: String,
        caps: String,
        ts_ns: u64,
    },
}

impl Event {
    /// Snake-case discriminator matching the serde tag.
    pub fn kind(&self) -> &'static str {
        match self {
            Event::ProcExec { .. } => "proc_exec",
            Event::FileOpen { .. } => "file_open",
            Event::NetConnect { .. } => "net_connect",
            Event::CapEscalate { .. } => "cap_escalate",
        }
    }

    /// Thread-group id of the originating task.
    pub fn tgid(&self) -> u32 {
        match self {
            Event::ProcExec { tgid, .. }
            | Event::FileOpen { tgid, .. }
            | Event::NetConnect { tgid, .. }
            | Event::CapEscalate { tgid, .. } => *tgid,
        }
    }

    /// Monotonic capture timestamp in nanoseconds since the UNIX epoch.
    pub fn ts(&self) -> u64 {
        match self {
            Event::ProcExec { ts_ns, .. }
            | Event::FileOpen { ts_ns, .. }
            | Event::NetConnect { ts_ns, .. }
            | Event::CapEscalate { ts_ns, .. } => *ts_ns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Event {
        Event::FileOpen {
            pid: 1,
            tgid: 2,
            comm: "cat".into(),
            path: ".env".into(),
            flags: 0,
            ts_ns: 42,
            is_write_hint: false,
        }
    }

    #[test]
    fn serde_tag_round_trip() {
        let e = sample();
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"type\":\"file_open\""));
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn accessors() {
        let e = sample();
        assert_eq!(e.tgid(), 2);
        assert_eq!(e.ts(), 42);
    }
}
