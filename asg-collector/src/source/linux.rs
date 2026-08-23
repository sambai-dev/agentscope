//! Real eBPF kernel source: loads `bpf/asg.bpf.o`, attaches tracepoints and
//! forwards RingBuf payloads onto the ingest channel.
//!
//! Wire format is one serde_json-encoded [`Event`] per ring buffer record;
//! JSON keeps both sides dependency-free at an honest throughput tradeoff
//! documented in `bpf/README.md`.

use crate::CollectorError;
use asg_common::events::Event;
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
pub async fn start(tx: Sender<Event>) -> Result<JoinHandle<()>, CollectorError> {
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
    Ok(tokio::spawn(poll_loop(ring, tx)))
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

async fn poll_loop(mut ring: aya::maps::RingBuf<aya::maps::MapData>, tx: Sender<Event>) {
    while !tx.is_closed() {
        let mut drained = true;
        while let Some(item) = ring.next() {
            drained = false;
            match serde_json::from_slice::<Event>(&item) {
                Ok(event) => {
                    if tx.send(event).await.is_err() {
                        warn!("event channel closed; kernel source exiting");
                        return;
                    }
                }
                Err(err) => warn!(%err, "malformed ring buffer payload dropped"),
            }
        }
        if drained {
            tokio::time::sleep(Duration::from_micros(250)).await;
        }
    }
}
