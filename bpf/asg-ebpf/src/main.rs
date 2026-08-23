#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    helpers::gen::bpf_ktime_get_ns,
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use core::fmt::{Result as FmtResult, Write};

/// Upper bound of one JSON record; oversized payloads are truncated.
const RECORD_MAX: usize = 192;

#[map(name = "EVENTS")]
static EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

#[tracepoint]
pub fn probe_exec(_ctx: TracePointContext) -> u32 {
    emit("proc_exec")
}

#[tracepoint]
pub fn probe_connect(_ctx: TracePointContext) -> u32 {
    emit("net_connect")
}

#[tracepoint]
pub fn probe_openat(_ctx: TracePointContext) -> u32 {
    emit("file_open")
}

fn emit(kind: &str) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;
    let ts_ns = unsafe { bpf_ktime_get_ns() };
    let comm_raw = bpf_get_current_comm().unwrap_or([0u8; 16]);
    let comm = comm_str(&comm_raw);

    let mut buf = [0u8; RECORD_MAX];
    let n = {
        let mut w = RecordWriter { buf: &mut buf, pos: 0 };
        let _ = write!(
            w,
            "{{\"type\":\"{}\",\"pid\":{},\"tgid\":{},\"comm\":\"{}\",\"ts_ns\":{}}}",
            kind, pid, tgid, comm, ts_ns
        );
        w.pos
    };

    match EVENTS.output(&buf[..n], 0) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn comm_str(raw: &[u8]) -> &str {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    core::str::from_utf8(&raw[..end]).unwrap_or("unknown")
}

struct RecordWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl Write for RecordWriter<'_> {
    fn write_str(&mut self, s: &str) -> FmtResult {
        let bytes = s.as_bytes();
        let remaining = self.buf.len() - self.pos;
        let n = bytes.len().min(remaining);
        self.buf[self.pos..self.pos + n].copy_from_slice(&bytes[..n]);
        self.pos += n;
        Ok(())
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
