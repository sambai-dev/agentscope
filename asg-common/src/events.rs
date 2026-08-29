//! Kernel event model shared by every source.
//!
//! The full [`Event`] schema is what the pipeline (store, process tree,
//! policy) consumes. The eBPF probes emit a compact [`KernelRecord`] with
//! best-effort evidence read at the tracepoint: executable filename, open
//! path/flags, and numeric connect destination. Userspace widens it into
//! [`Event`], using documented sentinels only when a kernel read failed.

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

/// Kernel wire record: exactly one JSON object as emitted by the eBPF probes
/// into the `EVENTS` RingBuf (see `bpf/asg-ebpf/src/main.rs`):
///
/// ```json
/// {"type":"file_open","pid":1,"tgid":1,"comm":"cat","ts_ns":0,"path":".env","flags":0}
/// ```
///
/// Evidence fields are optional because tracepoint user-memory reads can fail
/// (for example, an invalid syscall pointer) and older v0.1 probe objects emit
/// identity-only records. [`KernelRecord::widen`] fills only missing fields
/// with inert sentinels instead of fabricating observations:
///
/// | Field | Sentinel | Why it is defensible |
/// |---|---|---|
/// | `ppid` | [`KERNEL_UNKNOWN_PPID`] (`0`) | pid 0 is never a userspace parent; tree building shows an unknown root |
/// | `cgroup_id` | [`KERNEL_UNKNOWN_CGROUP_ID`] (`0`) | real cgroup ids are nonzero; no false attribution to a container |
/// | `args` | empty vec | honest absence of an executable filename |
/// | `uid` | [`KERNEL_UNKNOWN_UID`] (`u32::MAX`) | mirrors the kernel's own `INVALID_UID` sentinel |
/// | `path` | empty string | secret-path globs cannot match `""`, so no synthetic `SECRET_ACCESS` can fire |
/// | `flags` | `0` | only used when the optional field was actually captured |
/// | `is_write_hint` | `false` | no read/write direction is claimed without captured flags |
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
    /// Executable filename captured from `sched_process_exec`. This is not
    /// the complete argv vector, so the probe emits it as `args[0]`.
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub cgroup_id: Option<u64>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub flags: Option<u32>,
    /// True when the open path filled the fixed capture buffer.
    #[serde(default)]
    pub path_truncated: bool,
    #[serde(default)]
    pub daddr: Option<String>,
    #[serde(default)]
    pub dport: Option<u16>,
    #[serde(default)]
    pub family: Option<String>,
}

impl KernelRecord {
    /// Widens a kernel record into a full [`Event`], applying the sentinel
    /// values documented on this struct for evidence the probe could not read.
    ///
    /// Returns `None` for discriminators the kernel source cannot produce
    /// (anything other than `proc_exec`, `file_open`, `net_connect`);
    /// callers must treat such records as malformed/dropped.
    pub fn widen(&self) -> Option<Event> {
        match self.kind.as_str() {
            "proc_exec" => Some(Event::ProcExec {
                pid: self.pid,
                tgid: self.tgid,
                ppid: KERNEL_UNKNOWN_PPID,
                cgroup_id: self.cgroup_id.unwrap_or(KERNEL_UNKNOWN_CGROUP_ID),
                comm: self.comm.clone(),
                args: self.args.clone(),
                uid: self.uid.unwrap_or(KERNEL_UNKNOWN_UID),
                ts_ns: self.ts_ns,
            }),
            "file_open" => {
                let flags = self.flags.unwrap_or(0);
                let mut path = self.path.clone().unwrap_or_default();
                if self.path_truncated {
                    path.push_str("<truncated>");
                }
                Some(Event::FileOpen {
                    pid: self.pid,
                    tgid: self.tgid,
                    comm: self.comm.clone(),
                    path,
                    flags,
                    ts_ns: self.ts_ns,
                    is_write_hint: self.flags.is_some() && flags & 0b11 != 0,
                })
            }
            "net_connect" => Some(Event::NetConnect {
                pid: self.pid,
                tgid: self.tgid,
                comm: self.comm.clone(),
                daddr: self.daddr.clone().unwrap_or_default(),
                dport: self.dport.unwrap_or(0),
                family: self.family.clone().unwrap_or_default(),
                ts_ns: self.ts_ns,
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
    fn widens_captured_kernel_evidence() {
        let exec: KernelRecord = serde_json::from_str(
            r#"{"type":"proc_exec","pid":7,"tgid":7,"comm":"node","ts_ns":1,"uid":1000,"cgroup_id":42,"args":["/usr/bin/node"]}"#,
        )
        .unwrap();
        assert!(matches!(
            exec.widen(),
            Some(Event::ProcExec {
                uid: 1000,
                cgroup_id: 42,
                args,
                ..
            }) if args == ["/usr/bin/node"]
        ));

        let open: KernelRecord = serde_json::from_str(
            r#"{"type":"file_open","pid":7,"tgid":7,"comm":"cat","ts_ns":2,"path":"/home/dev/.env","flags":2}"#,
        )
        .unwrap();
        assert!(matches!(
            open.widen(),
            Some(Event::FileOpen {
                path,
                flags: 2,
                is_write_hint: true,
                ..
            }) if path == "/home/dev/.env"
        ));

        let connect: KernelRecord = serde_json::from_str(
            r#"{"type":"net_connect","pid":7,"tgid":7,"comm":"curl","ts_ns":3,"daddr":"203.0.113.9","dport":443,"family":"IPv4"}"#,
        )
        .unwrap();
        assert!(matches!(
            connect.widen(),
            Some(Event::NetConnect {
                daddr,
                dport: 443,
                family,
                ..
            }) if daddr == "203.0.113.9" && family == "IPv4"
        ));
    }

    #[test]
    fn marks_truncated_kernel_paths() {
        let open: KernelRecord = serde_json::from_str(
            r#"{"type":"file_open","pid":7,"tgid":7,"comm":"cat","ts_ns":2,"path":"/very/long","flags":0,"path_truncated":true}"#,
        )
        .unwrap();
        assert!(matches!(
            open.widen(),
            Some(Event::FileOpen { path, .. }) if path == "/very/long<truncated>"
        ));
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
