# asg-ebpf

The AgentScope kernel probe. Compiles to an eBPF ELF object
(`bpf/asg.bpf.o`) that the collector loads at runtime with
[aya](https://aya-rs.dev).

## Probe coverage

| Program         | Tracepoint                    | Emits                                                        |
| --------------- | ----------------------------- | ------------------------------------------------------------ |
| `probe_exec`    | `sched/sched_process_exec`    | `{"type":"proc_exec","pid":..,"tgid":..,"comm":"..","ts_ns":..}` |
| `probe_connect` | `syscalls/sys_enter_connect`  | `{"type":"net_connect", ...same identity fields...}`          |
| `probe_openat`  | `syscalls/sys_enter_openat`   | `{"type":"file_open", ...same identity fields...}`            |

All three probes share one ring buffer map (`EVENTS`, 256 KiB) and emit
one compact JSON record per event. Identity fields come from
`bpf_get_current_pid_tgid()`, `bpf_get_current_comm()` and
`bpf_ktime_get_ns()`.

`ts_ns` is CLOCK_MONOTONIC (kernel monotonic clock), not wall time; the
userspace pipeline reconciles it against ingest time when ordering the
dashboard timeline.

## Honest limitations (current)

- **Argument extraction is not implemented yet.** The probes do not read
  tracepoint arguments, so:
  - `proc_exec` records carry no argv or ppid;
  - `net_connect` carries no destination address/port (the sockaddr lives
    in the `connect()` arg1 as a userspace pointer);
  - `file_open` carries no path (the filename lives in the `openat`
    arg1 as a userspace pointer).
  Reading them requires `ctx->args[N]` access through `pt_regs` /
  `bpf_probe_read_user_str_bytes`, which lands alongside the LSM work on
  the roadmap. The deterministic simulator and the replay corpus exercise
  the *full* schema so policy evaluation can be developed today.
- JSON wire format trades throughput for zero shared-schema crates.
  Switching to a packed binary layout is a mechanical change once arg
  extraction lands.
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
