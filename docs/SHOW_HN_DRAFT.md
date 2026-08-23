# Show HN draft

**Title:** Show HN: AgentScope – eBPF runtime security for AI coding agents

---

We've been letting autonomous coding agents (Codex, Claude Code, CI workers)
run `npm install`, curl arbitrary hosts and read files on machines that hold
our credentials. We wanted to know what they *actually do* — from the kernel,
not from whatever the process claims in its own logs.

AgentScope is a Rust workspace that:

1. Loads eBPF probes (aya) on tracepoints `sched_process_exec`,
   `sys_enter_connect` and `sys_enter_openat`, attributing events to agents
   by pid ancestry (cgroup-scoped attachment is roadmap).
2. Streams events over a ring buffer to a userspace collector.
3. Evaluates every event against a declarative policy: deny package managers,
   flag reads of `.env` / `.ssh/id_rsa` / AWS creds / wallet files, warn on
   unknown egress domains (ngrok/trycloudflare/pastebin are pre-seeded).
4. Serves violations over REST + SSE to a single-file dark dashboard with a
   live process tree, network map and file-access timeline.

The part we're most fond of: because kernel collection needs Linux 5.8+ and
root, the repo ships a **deterministic simulated event source** that replays
the exact same attack scenario everywhere — so `cargo run` works identically
on Windows/macOS CI, and the pipeline, policy engine and dashboard are all
under test on every commit, not just the Linux runners.

Honest limitations, in the README threat model: we can't see encrypted
payloads, root can unload our probes, path rules have TOCTOU windows, and the
eBPF probes currently emit identity fields only (pid/tgid/comm) while argument
extraction (paths, sockaddrs, argv) lands with the LSM work. Enforcement is
roadmap; today it's observe-and-alert.

Design choices you might find interesting:
- Tracepoints instead of LSM hooks for portability (LSM is roadmap).
- A hand-rolled ~60-line glob matcher (`**`, `*`, `?`) instead of pulling in
  globset/regex for ten default patterns.
- JSON as the ring buffer wire format — binary packing would be faster; we
  chose boring until profiling says otherwise.
- RingBuf over perf arrays for cross-CPU ordering (costs kernel ≥5.8).

Repo: https://github.com/sambai-dev/agentscope
Quickstart: `cargo run -p asg-cli -- serve` → http://localhost:8100
(replay the demo corpus without serving: `cargo run -p asg-cli -- replay --file examples/scenario.jsonl`)

Ask: what signals would you want watched for agents running in your org?
Would you block package-manager execs outright or gate them behind approval?

---

*First comment (self-post):*

Architecture sketch and threat model are in the repo docs
(docs/THREAT_MODEL.md maps each persona — malicious postinstall script,
prompt-injected agent exfiltrating .env, compromised tool binary — to the
exact rule ids and probes that catch them). Benchmarks are honest
Instant-based percentiles, no criterion — release build:
policy eval ~621k ops/s p50 1.6µs, glob match ~884k ops/s p50 1.2µs
(`cargo run -p asg-cli --bin bench --release`). CI runs clippy `-D warnings`
on both ubuntu and windows for the portable crates, plus a nightly job
building the actual eBPF ELF with bpf-linker against LLVM 18.
