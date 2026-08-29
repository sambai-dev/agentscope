# asg-ebpf

The AgentScope kernel probe. Compiles to an eBPF ELF object
(`bpf/asg.bpf.o`) that the collector loads at runtime with
[aya](https://aya-rs.dev).

## Probe coverage

| Program | Tracepoint | Additional evidence |
| --- | --- | --- |
| `probe_exec` | `sched/sched_process_exec` | executable filename in `args[0]`, uid, cgroup id |
| `probe_connect` | `syscalls/sys_enter_connect` | IPv4/IPv6 destination, network-order port, address family |
| `probe_openat` | `syscalls/sys_enter_openat` | requested path, open flags, truncation marker |

All three probes share one ring buffer map (`EVENTS`, 256 KiB). Each reserves
a fixed 512-byte slot and writes escaped JSON directly into that reservation,
leaving zero padding for userspace to trim. This avoids a record-sized eBPF
stack allocation and a second ring copy. Oversized records are discarded
rather than exposed as malformed/truncated JSON.

Identity fields come from `bpf_get_current_pid_tgid()`,
`bpf_get_current_comm()` and `bpf_ktime_get_ns()`. Exec identity also uses
`bpf_get_current_uid_gid()` and `bpf_get_current_cgroup_id()`.

## Timestamp domain

`ts_ns` comes from `bpf_ktime_get_ns()`: **CLOCK_MONOTONIC nanoseconds since
boot**, not UNIX epoch wall time. It is *not* comparable with the
simulator/replay corpus, which stamps UNIX-epoch nanoseconds. Userspace does
**not** reconcile the two clock domains today — ordering/joining across
sources is future work (see the README roadmap). Do not interpret a kernel
`ts_ns` as a wall-clock time.

## Argument capture

`sys_enter_openat` and `sys_enter_connect` expose native-width syscall
argument slots after the common trace header and syscall id. The probes read
the userspace filename and sockaddr with `bpf_probe_read_user*`, with explicit
length checks before IPv4/IPv6 decoding. `sched_process_exec` already stores
the executable filename inline in its trace record; the probe follows its
`__data_loc` offset and reads that kernel string.

The release targets native 64-bit Linux (x86_64/aarch64). Compat 32-bit
syscall layouts are not claimed. Open paths are capped at 255 bytes plus NUL;
a full buffer sets `path_truncated`, which userspace renders with a visible
`<truncated>` suffix.

## From record to event (widening)

The userspace collector trims zero padding, parses records into
`asg_common::events::KernelRecord`, and widens them into the full `Event`
schema. Optional evidence fields preserve compatibility with v0.1
identity-only probe objects and handle failed user-memory reads. Missing data
receives the inert sentinels documented in `asg-common/src/events.rs`; no
observation data is fabricated. Records that fail to parse or claim an
unproducible kind are counted on `/api/metrics`
(`asg_source_records_ingested_total`,
`asg_source_records_dropped_malformed_total`); when a live source has
dropped every record so far and ingested none, `/healthz` reports
`503 degraded`.

## Honest limitations (current)

- Exec evidence contains the executable filename, not full argv, and ppid is
  still unknown.
- `connect()` exposes numeric addresses, not DNS names. Use exact IPs, IP
  globs, or CIDRs in kernel-mode policy; hostname correlation is roadmap work.
- The requested open path is not a resolved inode path, so symlink/TOCTOU
  caveats remain.
- JSON remains a deliberate throughput tradeoff for an inspectable,
  backward-compatible wire format.
- comm strings are truncated by the kernel to 16 bytes.

## Build

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cd bpf/asg-ebpf
cargo build --release --target bpfel-unknown-none
cp target/bpfel-unknown-none/release/asg-ebpf ../../bpf/asg.bpf.o
```

## Load

```bash
sudo ./target/release/agentscope serve --source kernel --bpf-path bpf/asg.bpf.o
```

Requires root/CAP_BPF+CAP_PERFMON and a kernel >= 5.8 (ring buffers).
Attach failures per probe are logged and non-fatal: the collector runs
with partial coverage.
