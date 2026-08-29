#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel_str_bytes, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
        generated::{bpf_get_current_cgroup_id, bpf_ktime_get_ns},
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
    EbpfContext,
};
use core::fmt::{Error as FmtError, Result as FmtResult, Write};

/// Fixed ring record size. The writer operates directly on reserved ring
/// memory, so this does not consume the eBPF stack. Userspace trims the zero
/// padding before parsing the JSON payload.
const RECORD_MAX: usize = 512;
/// Long enough for normal source-tree and credential paths while staying
/// below the verifier's 512-byte stack ceiling.
const PATH_MAX_CAPTURE: usize = 256;

// `trace_event_raw_sys_enter` is the common trace header (8 bytes), syscall
// id (8 bytes), then six native-width argument slots. AgentScope supports
// native 64-bit Linux processes, matching its x86_64/aarch64 release targets.
const SYSCALL_ARG1_OFFSET: usize = 24;
const SYSCALL_ARG2_OFFSET: usize = 32;
// `sched_process_exec` starts with the 8-byte common trace header followed by
// a `__data_loc` u32 for the inline filename.
const SCHED_EXEC_FILENAME_LOC_OFFSET: usize = 8;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[map(name = "EVENTS")]
static EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

#[tracepoint]
pub fn probe_exec(ctx: TracePointContext) -> u32 {
    let mut filename_buf = [0u8; PATH_MAX_CAPTURE];
    let filename = read_exec_filename(&ctx, &mut filename_buf).unwrap_or(&[]);
    emit_exec(filename)
}

#[tracepoint]
pub fn probe_connect(ctx: TracePointContext) -> u32 {
    match read_connect(&ctx) {
        Ok(destination) => emit_connect(Some(destination)),
        Err(_) => emit_connect(None),
    }
}

#[tracepoint]
pub fn probe_openat(ctx: TracePointContext) -> u32 {
    let mut path_buf = [0u8; PATH_MAX_CAPTURE];
    match read_openat(&ctx, &mut path_buf) {
        Ok((path, flags, truncated)) => emit_openat(path, flags, truncated),
        Err(_) => emit_openat(&[], 0, false),
    }
}

fn read_exec_filename<'a>(
    ctx: &TracePointContext,
    dest: &'a mut [u8; PATH_MAX_CAPTURE],
) -> Result<&'a [u8], i32> {
    // A __data_loc stores the offset in its low 16 bits and byte length in
    // its high 16 bits. The pointed-to bytes live in the trace record itself.
    let data_loc = unsafe { ctx.read_at::<u32>(SCHED_EXEC_FILENAME_LOC_OFFSET)? };
    let offset = (data_loc & 0xffff) as usize;
    if offset < 8 || offset > 4096 {
        return Err(-1);
    }
    let ptr = unsafe { ctx.as_ptr().cast::<u8>().add(offset) };
    unsafe { bpf_probe_read_kernel_str_bytes(ptr, dest) }
}

fn read_openat<'a>(
    ctx: &TracePointContext,
    dest: &'a mut [u8; PATH_MAX_CAPTURE],
) -> Result<(&'a [u8], u32, bool), i32> {
    let path_ptr = unsafe { ctx.read_at::<*const u8>(SYSCALL_ARG1_OFFSET)? };
    let flags = unsafe { ctx.read_at::<u64>(SYSCALL_ARG2_OFFSET)? } as u32;
    let path = unsafe { bpf_probe_read_user_str_bytes(path_ptr, dest)? };
    let truncated = path.len() == PATH_MAX_CAPTURE - 1;
    Ok((path, flags, truncated))
}

#[derive(Clone, Copy)]
enum Destination {
    V4 { octets: [u8; 4], port: u16 },
    V6 { segments: [u16; 8], port: u16 },
    Other { family: u16 },
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrV4 {
    family: u16,
    port_be: u16,
    address: [u8; 4],
    zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrV6 {
    family: u16,
    port_be: u16,
    flowinfo: u32,
    address: [u8; 16],
    scope_id: u32,
}

fn read_connect(ctx: &TracePointContext) -> Result<Destination, i32> {
    let sockaddr = unsafe { ctx.read_at::<*const u8>(SYSCALL_ARG1_OFFSET)? };
    let addr_len = unsafe { ctx.read_at::<u64>(SYSCALL_ARG2_OFFSET)? } as usize;
    if sockaddr.is_null() || addr_len < core::mem::size_of::<u16>() {
        return Err(-1);
    }

    let family = unsafe { bpf_probe_read_user(sockaddr.cast::<u16>())? };
    match family {
        AF_INET if addr_len >= core::mem::size_of::<SockAddrV4>() => {
            let addr = unsafe { bpf_probe_read_user(sockaddr.cast::<SockAddrV4>())? };
            Ok(Destination::V4 {
                octets: addr.address,
                port: u16::from_be(addr.port_be),
            })
        }
        AF_INET6 if addr_len >= core::mem::size_of::<SockAddrV6>() => {
            let addr = unsafe { bpf_probe_read_user(sockaddr.cast::<SockAddrV6>())? };
            let mut segments = [0u16; 8];
            let mut i = 0;
            while i < segments.len() {
                segments[i] = u16::from_be_bytes([addr.address[i * 2], addr.address[i * 2 + 1]]);
                i += 1;
            }
            Ok(Destination::V6 {
                segments,
                port: u16::from_be(addr.port_be),
            })
        }
        _ => Ok(Destination::Other { family }),
    }
}

fn emit_exec(filename: &[u8]) -> u32 {
    emit_record(|w, identity| {
        identity.write_prefix(w, "proc_exec")?;
        write!(
            w,
            ",\"uid\":{},\"cgroup_id\":{}",
            bpf_get_current_uid_gid() as u32,
            unsafe { bpf_get_current_cgroup_id() }
        )?;
        if !filename.is_empty() {
            w.write_str(",\"args\":[")?;
            w.write_json_string(filename)?;
            w.write_byte(b']')?;
        }
        w.write_byte(b'}')
    })
}

fn emit_openat(path: &[u8], flags: u32, truncated: bool) -> u32 {
    emit_record(|w, identity| {
        identity.write_prefix(w, "file_open")?;
        if !path.is_empty() {
            w.write_str(",\"path\":")?;
            w.write_json_string(path)?;
            write!(w, ",\"flags\":{flags}")?;
            if truncated {
                w.write_str(",\"path_truncated\":true")?;
            }
        }
        w.write_byte(b'}')
    })
}

fn emit_connect(destination: Option<Destination>) -> u32 {
    emit_record(|w, identity| {
        identity.write_prefix(w, "net_connect")?;
        match destination {
            Some(Destination::V4 { octets, port }) => {
                write!(
                    w,
                    ",\"daddr\":\"{}.{}.{}.{}\",\"dport\":{},\"family\":\"IPv4\"",
                    octets[0], octets[1], octets[2], octets[3], port
                )?;
            }
            Some(Destination::V6 { segments, port }) => {
                write!(
                    w,
                    ",\"daddr\":\"{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}\",\"dport\":{},\"family\":\"IPv6\"",
                    segments[0],
                    segments[1],
                    segments[2],
                    segments[3],
                    segments[4],
                    segments[5],
                    segments[6],
                    segments[7],
                    port
                )?;
            }
            Some(Destination::Other { family }) => {
                write!(w, ",\"family\":\"AF_{family}\"")?;
            }
            None => {}
        }
        w.write_byte(b'}')
    })
}

struct Identity {
    pid: u32,
    tgid: u32,
    ts_ns: u64,
    comm: [u8; 16],
}

impl Identity {
    fn capture() -> Self {
        let pid_tgid = bpf_get_current_pid_tgid();
        Self {
            tgid: (pid_tgid >> 32) as u32,
            pid: pid_tgid as u32,
            ts_ns: unsafe { bpf_ktime_get_ns() },
            comm: bpf_get_current_comm().unwrap_or([0u8; 16]),
        }
    }

    fn write_prefix(&self, w: &mut RecordWriter<'_>, kind: &str) -> FmtResult {
        write!(
            w,
            "{{\"type\":\"{}\",\"pid\":{},\"tgid\":{},\"comm\":",
            kind, self.pid, self.tgid
        )?;
        let comm_end = self
            .comm
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(self.comm.len());
        w.write_json_string(&self.comm[..comm_end])?;
        write!(w, ",\"ts_ns\":{}", self.ts_ns)
    }
}

fn emit_record(write_record: impl FnOnce(&mut RecordWriter<'_>, &Identity) -> FmtResult) -> u32 {
    let Some(mut entry) = EVENTS.reserve::<[u8; RECORD_MAX]>(0) else {
        return 1;
    };

    let wrote = {
        // SAFETY: `entry` owns a RECORD_MAX-byte uninitialized reservation.
        // Initializing every byte to zero makes the array valid before we
        // create a mutable reference. The writer then overwrites a prefix and
        // leaves a zero terminator/padding for userspace.
        let buf = unsafe {
            let ptr = entry.as_mut_ptr();
            core::ptr::write_bytes(ptr.cast::<u8>(), 0, RECORD_MAX);
            &mut *ptr
        };
        let mut writer = RecordWriter { buf, pos: 0 };
        write_record(&mut writer, &Identity::capture()).is_ok()
    };

    if wrote {
        entry.submit(0);
        0
    } else {
        entry.discard(0);
        1
    }
}

struct RecordWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl RecordWriter<'_> {
    fn write_byte(&mut self, byte: u8) -> FmtResult {
        if self.pos >= self.buf.len() {
            return Err(FmtError);
        }
        self.buf[self.pos] = byte;
        self.pos += 1;
        Ok(())
    }

    fn write_json_string(&mut self, bytes: &[u8]) -> FmtResult {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.write_byte(b'\"')?;
        for &byte in bytes {
            match byte {
                b'\"' => self.write_str("\\\"")?,
                b'\\' => self.write_str("\\\\")?,
                0x20..=0x7e => self.write_byte(byte)?,
                _ => {
                    self.write_str("\\u00")?;
                    self.write_byte(HEX[(byte >> 4) as usize])?;
                    self.write_byte(HEX[(byte & 0x0f) as usize])?;
                }
            }
        }
        self.write_byte(b'\"')
    }
}

impl Write for RecordWriter<'_> {
    fn write_str(&mut self, value: &str) -> FmtResult {
        let bytes = value.as_bytes();
        let end = self.pos.checked_add(bytes.len()).ok_or(FmtError)?;
        if end > self.buf.len() {
            return Err(FmtError);
        }
        self.buf[self.pos..end].copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
