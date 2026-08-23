//! Real eBPF kernel source: loads `bpf/asg.bpf.o`, attaches tracepoints and
//! forwards RingBuf payloads onto the ingest channel.
//!
//! Wire format is one identity-only [`KernelRecord`] per ring buffer record —
//! exactly the JSON the probes emit (`type`/`pid`/`tgid`/`comm`/`ts_ns`);
//! JSON keeps both sides dependency-free at an honest throughput tradeoff
//! documented in `bpf/README.md`. Each parsed record is widened into a full
//! [`Event`] via [`KernelRecord::widen`] using the sentinel values documented
//! in `asg-common/src/events.rs`: fields the kernel cannot observe yet are
//! filled with inert placeholders (empty path/args/daddr, unknown-parent pid
//! 0, `INVALID_UID`) — never fabricated observation data.
//!
//! Records that fail to parse or claim an unproducible kind are counted in
//! [`SourceRecordStats`] (rendered as `asg_source_records_*_total` on
//! `/api/metrics`); when a live source has dropped everything and ingested
//! nothing, `/healthz` degrades.

use crate::CollectorError;
use asg_common::events::{Event, KernelRecord};
use asg_common::stats::SourceRecordStats;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

/// Path of the compiled eBPF object, expected relative to the working dir.
pub const BPF_OBJECT_PATH: &str = "bpf/asg.bpf.o";

/// Map name shared with the eBPF program (`#[map(name = "EVENTS")]`).
pub const RING_BUF_MAP: &str = "EVENTS";

/// sched_process_exec tracepoint in `category/name` form.
pub const SCHED_PROCESS_EXEC: &str = "sched/sched_process_exec";

/// sys_enter_connect tracepoint in `category/name` form.
pub const SYS_ENTER_CONNECT: &str = "syscalls/sys_enter_connect";

/// sys_enter_openat tracepoint in `category/name` form.
pub const SYS_ENTER_OPENAT: &str = "syscalls/sys_enter_openat";

const PROBE_EXEC_PROGRAM: &str = "probe_exec";
const PROBE_CONNECT_PROGRAM: &str = "probe_connect";
const PROBE_OPENAT_PROGRAM: &str = "probe_openat";

static OBJECT_PATH_OVERRIDE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Overrides the default object path (wired to the CLI `--bpf-path` flag).
pub fn set_object_path(path: impl Into<String>) {
    let _ = OBJECT_PATH_OVERRIDE.set(path.into());
}

fn object_path() -> &'static str {
    OBJECT_PATH_OVERRIDE
        .get()
        .map(String::as_str)
        .unwrap_or(BPF_OBJECT_PATH)
}

/// Loads the eBPF object and spawns the kernel event poll loop.
pub async fn start(
    tx: Sender<Event>,
    stats: Arc<SourceRecordStats>,
) -> Result<JoinHandle<()>, CollectorError> {
    let mut bpf =
        aya::Ebpf::load_file(object_path()).map_err(|e| CollectorError::Aya(e.to_string()))?;

    attach_best_effort(&mut bpf, PROBE_EXEC_PROGRAM, SCHED_PROCESS_EXEC);
    attach_best_effort(&mut bpf, PROBE_CONNECT_PROGRAM, SYS_ENTER_CONNECT);
    attach_best_effort(&mut bpf, PROBE_OPENAT_PROGRAM, SYS_ENTER_OPENAT);

    let map = bpf
        .take_map(RING_BUF_MAP)
        .ok_or_else(|| CollectorError::Aya(format!("missing map {RING_BUF_MAP}")))?;
    let ring = aya::maps::RingBuf::try_from(map).map_err(|e| CollectorError::Aya(e.to_string()))?;

    info!(path = object_path(), "kernel source started");
    Ok(tokio::spawn(poll_loop(ring, tx, stats)))
}

fn attach_best_effort(bpf: &mut aya::Ebpf, program_name: &str, tracepoint: &str) {
    match try_attach(bpf, program_name, tracepoint) {
        Ok(()) => info!(program = program_name, tracepoint, "tracepoint attached"),
        Err(err) => error!(
            program = program_name,
            tracepoint,
            %err,
            "attach failed; continuing with partial coverage"
        ),
    }
}

fn try_attach(
    bpf: &mut aya::Ebpf,
    program_name: &str,
    tracepoint: &str,
) -> Result<(), CollectorError> {
    let (category, name) = tracepoint
        .split_once('/')
        .ok_or_else(|| CollectorError::Aya(format!("bad tracepoint id {tracepoint}")))?;
    let program = bpf
        .program_mut(program_name)
        .ok_or_else(|| CollectorError::Aya(format!("missing program {program_name}")))?;
    let tp: &mut aya::programs::TracePoint = program
        .try_into()
        .map_err(|e| CollectorError::Aya(format!("{program_name}: {e}")))?;
    tp.load().map_err(|e| CollectorError::Aya(e.to_string()))?;
    tp.attach(category, name)
        .map_err(|e| CollectorError::Aya(e.to_string()))?;
    Ok(())
}

/// Why a raw ring-buffer record had to be discarded.
#[derive(Debug, thiserror::Error)]
enum RecordError {
    /// Not valid JSON, missing identity fields, or truncated by the probe's
    /// `RECORD_MAX` clipping.
    #[error("malformed kernel record: {0}")]
    Json(#[from] serde_json::Error),
    /// Parsed, but claims a discriminator no kernel probe can emit (e.g.
    /// `cap_escalate`); widening refuses to invent the missing data.
    #[error("kernel cannot produce kind {0:?}")]
    UnproducibleKind(String),
}

/// Decodes one raw ring-buffer record into an [`Event`]: parses the
/// identity-only [`KernelRecord`] the probes write, then widens it with the
/// sentinel values documented in `asg-common/src/events.rs`.
fn decode_record(raw: &[u8]) -> Result<Event, RecordError> {
    let record: KernelRecord = serde_json::from_slice(raw)?;
    record
        .widen()
        .ok_or_else(|| RecordError::UnproducibleKind(record.kind.clone()))
}

async fn poll_loop(
    mut ring: aya::maps::RingBuf<aya::maps::MapData>,
    tx: Sender<Event>,
    stats: Arc<SourceRecordStats>,
) {
    while !tx.is_closed() {
        let mut drained = true;
        while let Some(item) = ring.next() {
            drained = false;
            match decode_record(&item) {
                Ok(event) => {
                    // Counted as ingested once widened; a closed channel ends
                    // the loop right after, so no double-counting concerns.
                    stats.inc_ingested();
                    if tx.send(event).await.is_err() {
                        warn!("event channel closed; kernel source exiting");
                        return;
                    }
                }
                Err(err) => {
                    stats.inc_dropped_malformed();
                    warn!(%err, "ring buffer payload dropped");
                }
            }
        }
        if drained {
            tokio::time::sleep(Duration::from_micros(250)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-for-byte what `bpf/asg-ebpf/src/main.rs::emit` writes.
    fn probe_bytes(kind: &str) -> Vec<u8> {
        format!("{{\"type\":\"{kind}\",\"pid\":1,\"tgid\":2,\"comm\":\"npm\",\"ts_ns\":9}}")
            .into_bytes()
    }

    #[test]
    fn decodes_and_widens_probe_records() {
        let event = decode_record(&probe_bytes("proc_exec")).unwrap();
        assert_eq!(event.kind(), "proc_exec");
        assert_eq!(event.tgid(), 2);
        assert_eq!(event.ts(), 9);
        let Event::ProcExec {
            ppid, args, uid, ..
        } = event
        else {
            panic!("expected ProcExec");
        };
        assert_eq!(ppid, asg_common::events::KERNEL_UNKNOWN_PPID);
        assert!(args.is_empty());
        assert_eq!(uid, asg_common::events::KERNEL_UNKNOWN_UID);
    }

    #[test]
    fn unproducible_kinds_are_rejected_not_invented() {
        match decode_record(&probe_bytes("cap_escalate")) {
            Err(RecordError::UnproducibleKind(kind)) => assert_eq!(kind, "cap_escalate"),
            other => panic!("expected UnproducibleKind, got {other:?}"),
        }
    }

    #[test]
    fn malformed_payloads_error_with_context() {
        for bad in [
            &b"not json"[..],
            br#"{"type":"proc_exec","pid":1}"#,
            br#"{"type":"file_open","pid":1,"tgid":2,"comm":"ca"#,
        ] {
            assert!(
                matches!(decode_record(bad), Err(RecordError::Json(_))),
                "{bad:?} must count as malformed"
            );
        }
    }
}
