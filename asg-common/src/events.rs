//! Kernel event model shared by every source.
//!
//! The full [`Event`] schema is what the pipeline (store, process tree,
//! policy) consumes. Today only the deterministic simulator and the replay
//! corpus can fill it completely: the eBPF probes emit identity fields only
//! ([`KernelRecord`]), which userspace widens into [`Event`] using the
//! documented sentinels — no argument/path/host data is invented.

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

    /// Capture timestamp in nanoseconds.
    ///
    /// The clock domain differs by source and is **not** reconciled today:
    /// eBPF probes stamp `bpf_ktime_get_ns()` (CLOCK_MONOTONIC nanoseconds
    /// since boot), while the simulator/replay corpus uses UNIX-epoch
    /// nanoseconds. Never compare or join timestamps across sources; see the
    /// README roadmap for reconciliation work.
    pub fn ts(&self) -> u64 {
        match self {
            Event::ProcExec { ts_ns, .. }
            | Event::FileOpen { ts_ns, .. }
            | Event::NetConnect { ts_ns, .. }
            | Event::CapEscalate { ts_ns, .. } => *ts_ns,
        }
    }
}

/// Placeholder parent id used when widening kernel records: pid 0 (the
/// swapper/idle task) is never a userspace parent, so process-tree building
/// renders an unknown root instead of linking to a real ancestor.
pub const KERNEL_UNKNOWN_PPID: u32 = 0;

/// Placeholder cgroup id used when widening kernel records: cgroup ids
/// handed out by the kernel are nonzero, so 0 reads unambiguously as
/// "not recorded" rather than pointing at a real container/cgroup.
pub const KERNEL_UNKNOWN_CGROUP_ID: u64 = 0;

/// Placeholder uid used when widening kernel records: matches the kernel's
/// own `INVALID_UID` overflow sentinel (`(uid_t)-1`).
pub const KERNEL_UNKNOWN_UID: u32 = u32::MAX;

/// Identity-only wire record: exactly one JSON object as emitted by the eBPF
/// probes into the `EVENTS` RingBuf (see `bpf/asg-ebpf/src/main.rs::emit`):
///
/// ```json
/// {"type":"proc_exec","pid":1,"tgid":1,"comm":"bash","ts_ns":0}
/// ```
///
/// The kernel cannot supply richer fields yet — argv/open paths/connect
/// destinations are userspace pointers that need `bpf_probe_read_user*`
/// access, and ppid/cgroup need extra helpers — so [`KernelRecord::widen`]
/// fills the remaining [`Event`] fields with fixed sentinels instead of
/// fabricated observations. Each choice is chosen to be inert downstream:
///
/// | Field | Sentinel | Why it is defensible |
/// |---|---|---|
/// | `ppid` | [`KERNEL_UNKNOWN_PPID`] (`0`) | pid 0 is never a userspace parent; tree building shows an unknown root |
/// | `cgroup_id` | [`KERNEL_UNKNOWN_CGROUP_ID`] (`0`) | real cgroup ids are nonzero; no false attribution to a container |
/// | `args` | empty vec | honest absence of argv; nothing invented for evidence output |
/// | `uid` | [`KERNEL_UNKNOWN_UID`] (`u32::MAX`) | mirrors the kernel's own `INVALID_UID` sentinel |
/// | `path` | empty string | secret-path globs cannot match `""`, so no synthetic `SECRET_ACCESS` can fire |
/// | `flags` | `0` | indistinguishable from `O_RDONLY`; a documented lossy placeholder until arg extraction lands |
/// | `is_write_hint` | `false` | no read/write direction is claimed |
/// | `daddr` | empty string | host rules cannot match `""`, so no synthetic `NET_*` violation can fire |
/// | `dport` | `0` | port 0 is reserved and never a valid connect destination |
/// | `family` | empty string | address family genuinely unknown |
///
/// `cap_escalate` has no probe at all and is not producible by the kernel
/// source; [`KernelRecord::widen`] returns `None` for that discriminator so
/// callers can count the record as unusable rather than inventing capability
/// data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelRecord {
    /// Probe discriminator: `proc_exec`, `file_open` or `net_connect`.
    #[serde(rename = "type")]
    pub kind: String,
    pub pid: u32,
    pub tgid: u32,
    pub comm: String,
    pub ts_ns: u64,
}

impl KernelRecord {
    /// Widens an identity-only kernel record into a full [`Event`], applying
    /// the sentinel values documented on this struct for every field the
    /// probes cannot observe yet.
    ///
    /// Returns `None` for discriminators the kernel source cannot produce
    /// (anything other than `proc_exec`, `file_open`, `net_connect`);
    /// callers must treat such records as malformed/dropped.
    pub fn widen(&self) -> Option<Event> {
        let Self {
            kind,
            pid,
            tgid,
            comm,
            ts_ns,
        } = self;
        match kind.as_str() {
            "proc_exec" => Some(Event::ProcExec {
                pid: *pid,
                tgid: *tgid,
                ppid: KERNEL_UNKNOWN_PPID,
                cgroup_id: KERNEL_UNKNOWN_CGROUP_ID,
                comm: comm.clone(),
                args: Vec::new(),
                uid: KERNEL_UNKNOWN_UID,
                ts_ns: *ts_ns,
            }),
            "file_open" => Some(Event::FileOpen {
                pid: *pid,
                tgid: *tgid,
                comm: comm.clone(),
                path: String::new(),
                flags: 0,
                ts_ns: *ts_ns,
                is_write_hint: false,
            }),
            "net_connect" => Some(Event::NetConnect {
                pid: *pid,
                tgid: *tgid,
                comm: comm.clone(),
                daddr: String::new(),
                dport: 0,
                family: String::new(),
                ts_ns: *ts_ns,
            }),
            _ => None,
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

    /// Byte-for-byte what `bpf/asg-ebpf/src/main.rs::emit` writes.
    fn probe_json(kind: &str, pid: u32, tgid: u32, comm: &str, ts_ns: u64) -> Vec<u8> {
        format!("{{\"type\":\"{kind}\",\"pid\":{pid},\"tgid\":{tgid},\"comm\":\"{comm}\",\"ts_ns\":{ts_ns}}}").into_bytes()
    }

    #[test]
    fn widen_proc_exec_uses_identity_and_sentinels() {
        let raw = probe_json("proc_exec", 4242, 4242, "npm", 123_456);
        let rec: KernelRecord = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            rec.widen(),
            Some(Event::ProcExec {
                pid: 4242,
                tgid: 4242,
                ppid: KERNEL_UNKNOWN_PPID,
                cgroup_id: KERNEL_UNKNOWN_CGROUP_ID,
                comm: "npm".into(),
                args: Vec::new(),
                uid: KERNEL_UNKNOWN_UID,
                ts_ns: 123_456,
            })
        );
    }

    #[test]
    fn widen_file_open_has_empty_inert_path() {
        let raw = probe_json("file_open", 7, 9, "cat", 1);
        let rec: KernelRecord = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            rec.widen(),
            Some(Event::FileOpen {
                pid: 7,
                tgid: 9,
                comm: "cat".into(),
                path: String::new(),
                flags: 0,
                ts_ns: 1,
                is_write_hint: false,
            })
        );
    }

    #[test]
    fn widen_net_connect_has_empty_inert_destination() {
        let raw = probe_json("net_connect", 7, 9, "curl", 2);
        let rec: KernelRecord = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            rec.widen(),
            Some(Event::NetConnect {
                pid: 7,
                tgid: 9,
                comm: "curl".into(),
                daddr: String::new(),
                dport: 0,
                family: String::new(),
                ts_ns: 2,
            })
        );
    }

    #[test]
    fn widen_rejects_kinds_the_kernel_cannot_produce() {
        // No cap_escalate probe exists; a record claiming it must be treated
        // as unusable rather than widened with invented capability data.
        let raw = probe_json("cap_escalate", 1, 1, "sudo", 3);
        let rec: KernelRecord = serde_json::from_slice(&raw).unwrap();
        assert_eq!(rec.widen(), None);
        let raw = probe_json("totally_bogus", 1, 1, "x", 4);
        let rec: KernelRecord = serde_json::from_slice(&raw).unwrap();
        assert_eq!(rec.widen(), None);
    }

    #[test]
    fn records_missing_identity_fields_are_malformed() {
        // What the probes emit today parses; dropping any identity field
        // must fail so the collector counts the record as dropped.
        assert!(serde_json::from_slice::<KernelRecord>(
            br#"{"type":"proc_exec","pid":1,"tgid":1,"comm":"npm"}"#
        )
        .is_err());
        assert!(serde_json::from_slice::<KernelRecord>(br#"{"nope":true}"#).is_err());
        // Truncated tail (RECORD_MAX clipping in the probe) is malformed too.
        assert!(serde_json::from_slice::<KernelRecord>(
            br#"{"type":"file_open","pid":1,"tgid":1,"comm":"ca"#
        )
        .is_err());
    }
}
