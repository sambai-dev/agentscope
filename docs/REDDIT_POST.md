# Reddit post draft

**Subreddit targets:** r/rust, r/devops, r/programming

**Title:** I built an eBPF runtime-security sidecar for AI coding agents (Rust, aya, axum) — it watches what your Codex/Claude Code sessions actually do

---

Your autonomous agent has your AWS creds in its env and permission to run
`npm install`. That's a remote-code-execution subscription with a friendly UI.
So I built AgentScope: kernel-level audit + policy for coding agents.

**What it does**

- eBPF probes (aya, pure Rust) on `sched_process_exec`, `sys_enter_connect`,
  `sys_enter_openat` → RingBuf → Rust collector → policy engine
- Rules like: deny npm/pip/cargo/curl/wget exec, flag reads of
  `.env`, `.ssh/id_rsa`, `~/.aws/credentials`, wallets; warn on
  ngrok/trycloudflare/pastebin-style egress
- Violations stream live to a dark single-file dashboard (vanilla JS, no CDN):
  process tree, network map with denied hosts in red, file-access timeline,
  and a policy editor that hot-applies via PUT /v1/policy

**Why the kernel?** Because the process lies. LD_PRELOAD shims, wrapper
scripts and tampered CLIs all "work" against app-layer logs. Tracepoints
don't care what the binary claims — you get syscall ground truth out-of-band.

**The part r/rust might appreciate:** since eBPF needs Linux 5.8+ and root,
the whole thing would be untestable on most dev machines. So there's a
deterministic simulator source that replays the same scripted attack scenario
(24 events: shell spawns agent, agent runs npm, curl hits
registry.npmjs.org then evil.telemetry.dev, cat .env, ssh-key read, sudo cap
escalation...) paced at 120ms, looping forever. Same code path as real
collection, so `cargo test --workspace` exercises pipeline+policy+API on
Windows/macOS/Linux CI alike. The demo corpus is checked in
(`examples/scenario.jsonl`) and the replay subcommand feeds it through the
real ingest pipeline.

**Stack:** tokio, axum 0.8 (SSE via BroadcastStream), clap 4, thiserror,
hand-rolled Prometheus text exposition, hand-rolled glob matcher (~60 lines,
table-tested) because pulling globset for ten patterns felt silly. The eBPF
crate is no_std aya-ebpf, built separately with nightly + bpf-linker; on
Windows everything compiles clean because every Linux-only piece is
cfg-gated.

**Numbers** (release build, reproducible via `cargo run -p asg-cli --bin
bench --release`): policy eval p50 1.6µs (~621k/s), glob match p50 1.2µs
(~884k/s). The policy engine is not the bottleneck for workstation event
volumes; the kernel ring is sized well below what userspace can drain.

**Honest gaps** (threat model in repo): no payload inspection (encrypted
traffic is opaque), root can unload the probes, path rules have TOCTOU
windows, enforcement/deny is roadmap (today: observe + alert), exec capture
contains the executable filename rather than full argv, and kernel connect
events expose numeric IPs rather than DNS names. Open paths and IPv4/IPv6
destinations are captured from real syscall arguments.

Repo: https://github.com/sambai-dev/agentscope
Run it: `cargo run -p asg-cli -- serve` → http://localhost:8100

Feedback wanted, especially: rule defaults (would you really deny cargo?),
what you'd want in a SIEM export, and whether cgroup-scoped attach should
jump the queue ahead of LSM enforcement.
