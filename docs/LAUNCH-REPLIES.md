# Launch Q&A — prepared first-comment replies

Short, factual, ready-to-paste replies for likely HN/r/rust objections.
Every claim traces to the repo as shipped and its release artifacts.

---

## "Why not just use Tetragon / Falco / Tracee?"

They're excellent — and much heavier. Tetragon assumes a Kubernetes/Cilium
deployment shape and a policy model oriented to containers; Falco's rules
engine targets fleet-wide syscall anomaly detection; Tracee is a great
research scanner. AgentScope is deliberately small and agent-shaped: three
tracepoints, a declarative ruleset written for the exact threat model of a
coding agent (postinstall scripts, .env reads, egress to paste sites), a
single binary with an embedded dashboard, and a deterministic simulator so
the whole pipeline runs in CI on any OS. If you already run Tetragon, you
can express part of this there — the comparison work is literally on the
roadmap ("systematic comparison against Tetragon's policy model").

## "Why not Landlock / seccomp instead of observe-and-alert?"

Different layer, and we want both. seccomp filters syscalls per-process
before they happen; Landlock restricts filesystem access declaratively.
Both are enforcement primitives that must be applied when the process
spawns — which means you control them only if you also control process
creation. AgentScope addresses the case where you *don't*: an existing
agent harness spawns shells and npm on your machine today, and you want
ground truth about what actually happened plus a policy decision point
that isn't inside the agent's own trust boundary. Enforcement (LSM BPF,
deny-not-alert) is the top roadmap item — observe-first was chosen because
a false-positive deny bricks someone's build, while a false-positive alert
costs nothing. Ship observability, earn the right to enforce.

## "Why tracepoints instead of LSM hooks / fexit?"

Stated honestly in the README design notes: tracepoints are stable across
kernel versions, need no BTF gymnastics or per-version struct layouts, and
cover the three signals that matter most (exec, connect, openat). LSM BPF
gives stronger hook points (and is where enforcement will land), but costs
newer kernels and more maintenance. We start observable and portable;
hardening comes after.

## "Root required — so it can watch agents but root can bypass it?"

Yes, and that's documented as a non-guarantee: a root attacker can unload
the probes. The threat model is explicitly *not* "defend against root."
It's "the agent runs as your user, with your tokens, and its own logs are
written by the thing you're auditing." Kernel capture is out-of-band from
the monitored workload — LD_PRELOAD shims and log tampering don't help an
attacker at the agent's privilege level. If your adversary is root, you
need a different machine boundary entirely.

## "TOCTOU — path checks race"

Correct, non-guarantee in the threat model: we see `openat` enter with a
path string; between resolution and open the path can change. For the
dominant failure mode (agent reads `.env` and exfiltrates) the race
doesn't help the attacker — the read itself is observed. Closing TOCTOU
properly needs LSM inode-based hooks, same answer as the enforcement
question above.

## "Why JSON on the ring buffer? Isn't that slow?"

Measured tradeoff, written up in the design notes: binary packing would be
smaller/faster, but sharing schema crates between no_std eBPF and userspace
complicates the build matrix. The probe now reserves a fixed RingBuf slot and
writes escaped JSON directly into it, avoiding both a record-sized stack
allocation and a second copy. Oversized records are discarded rather than
emitted as malformed JSON. At ~620k policy evals/s (measured, release build)
the userspace side is nowhere near the bottleneck for one workstation.

## "Windows/macOS support is fake then"

The kernel collection is Linux-only and says so everywhere. What ships
cross-platform is everything *around* collection: collector plumbing, the
full policy engine (table-tested), REST/SSE API, dashboard — driven by a
deterministic simulator replaying the exact 24-event attack scenario
(`examples/scenario.jsonl`). Same code path as live capture below the
source adapter, so `cargo test --workspace` exercises the pipeline on every
commit on all three OSes. That's why the project has any CI at all.

## "Isn't this just auditd?"

auditd gives you the events; it doesn't give you the agent-shaped policy
layer (secret-path globs, package-manager denies, egress watchlists), the
process-tree attribution, the violations stream, the hot-reload policy API,
or the dashboard. Also auditd's netconnect visibility is weak without
additional probes. If you love auditd, AgentScope's rule file maps cleanly
onto it for most cases — happy to document that mapping.

## "Show me it catching something real"

On Linux, build the probe and run `agentscope serve --source kernel`; opening
`.env` produces a real `SECRET_ACCESS`, and a configured IP/CIDR rule
matches real IPv4/IPv6 connect events. For a portable demo, POST any line of
`examples/scenario.jsonl` or replay the whole corpus with `agentscope replay`.

## "Numbers?"

Release build, Instant-based percentiles, reproducible via
`cargo run -p asg-cli --bin bench --release`: policy_eval p50 1.58µs
(~621k/s), glob_match p50 1.24µs (~884k/s) on a Windows dev laptop.
Methodology in docs/BENCHMARKS.md. No criterion dependency; it's a tiny
hand-rolled harness on purpose.
