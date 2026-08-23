# AgentScope Threat Model

Version 0.1 · August 2026 · owners: sambai-dev

## 1. Scope

AgentScope observes and evaluates syscall-level activity of AI coding agents
(Codex, Claude Code, CI workers) and their child processes on Linux hosts:

- **In scope:** process execution (`sched_process_exec`), outbound network
  connects (`sys_enter_connect`), file opens (`sys_enter_openat`),
  capability escalation events; policy evaluation (deny/warn/audit);
  violation reporting over REST/SSE; live dashboard.
- **Out of scope:** content inspection (payloads are opaque), memory/process
  introspection beyond exec identity, non-Linux kernel collection,
  prevention of kernel-level compromise of the host.

## 2. Assets

| Asset | Description |
| --- | --- |
| Source credentials | `.env`, `.ssh/id_rsa*`, `~/.aws/credentials`, `~/.kube/config`, wallet files on dev machines and CI runners |
| Agent autonomy | The ability of an agent to execute installs and arbitrary commands unsupervised |
| Audit trail | The captured event stream + violations used for incident response |
| Policy integrity | The active `RuleSet`; tampering silences detection |
| Egress allow posture | Knowledge of which external hosts agents may contact |

## 3. Trust boundaries

```text
┌──────────────────────────────────────────────────────────────┐
│ T1: agent workload + dependencies (UNTRUSTED)                │
│   user processes: node/npm/curl/...                          │
└───────────────┬──────────────────────────────────────────────┘
                │ syscalls (observed, not trusted)
┌───────────────▼──────────────────────────────────────────────┐
│ T2: Linux kernel + eBPF probes (TRUSTED COMPUTE BASE)        │
└───────────────┬──────────────────────────────────────────────┘
                │ RingBuf records
┌───────────────▼──────────────────────────────────────────────┐
│ T3: asg-collector + asg-api (trusted daemon, root/CAP_BPF)   │
│     policy engine, violation store, dashboard                │
└───────────────┬──────────────────────────────────────────────┘
                │ HTTP/SSE
┌───────────────▼──────────────────────────────────────────────┐
│ T4: human operator / SOC console                             │
└──────────────────────────────────────────────────────────────┘
```

T1→T2 is the boundary that matters: everything the workload says or logs is
untrusted; only what the kernel observes counts. T3 runs privileged and must
be treated as part of the host security perimeter. The dashboard/API (no auth
in this release) must not be exposed to untrusted networks — see §6.

## 4. Personas and attack trees

### Persona A: malicious dependency postinstall script

An npm/pip package runs arbitrary code at install time inside the agent's job.

```text
A1. agent runs `npm exec <tool>`            → PROC_DENIED (probe: sched_process_exec)
    └─ A1.1 if allowed by policy, script spawns children → still attributed via ppid tree
A2. postinstall curls telemetry/exfil host  → NET_DENIED if listed;
                                              NET_WARN for tunnel domains (*.onion,
                                              pastebin.com, ngrok.io, trycloudflare.com)
                                              (probe: sys_enter_connect)
A3. script reads ~/.aws/credentials         → SECRET_ACCESS (probe: sys_enter_openat)
A4. script escalates via sudo/capset        → CAP_ESCALATION
```

Detection coverage: A1–A4 all land in the violations feed with the tgid that
links back to the agent process tree (`GET /v1/processes`).

### Persona B: prompt-injected agent exfiltrating `.env`

A poisoned instruction convinces the agent itself to leak secrets.

```text
B1. agent shells out `cat .env`             → SECRET_ACCESS (glob **/.env)
B2. agent opens .ssh/id_rsa                 → SECRET_ACCESS (globs .ssh/**, **/.ssh/**,
                                               **/id_rsa*)
B3. agent POSTs data to unknown host        → NET_WARN (unknown) or NET_DENIED (listed)
B4. agent tunnels via ngrok/trycloudflare   → NET_WARN (default warn list targets
                                               exactly these)
```

Correlation: file-open timeline shows B1/B2 immediately before B3's connect
for the same tgid — the dashboard's timeline + network map make the pairing
visible during triage.

### Persona C: compromised tool binary downloading payloads

A trojanized linter/formatter fetches a second stage.

```text
C1. binary connects to payload CDN          → NET_DENIED (if host listed) /
                                              NET_WARN (unknown-host signal)
C2. binary writes dropped file              → FileOpen write-hint event recorded
                                              (audit; no default rule fires unless path
                                               matches secret globs)
C3. binary elevates privileges              → CAP_ESCALATION
```

## 5. Detections ↔ rule ids ↔ probes

| Rule id | Severity | Trigger | Probe | Example evidence |
| --- | --- | --- | --- | --- |
| `PROC_DENIED` | critical | comm basename in `denied_processes` | sched_process_exec | `{comm, args}` |
| `SECRET_ACCESS` | critical | open path matches `secret_path_globs` | sys_enter_openat | `{path, matched_globs}` |
| `NET_DENIED` | critical | daddr matches `denied_hosts` | sys_enter_connect | `{host, dport}` |
| `NET_WARN` | medium | daddr matches `warn_hosts` | sys_enter_connect | `{host, dport}` |
| `CAP_ESCALATION` | high | capability escalation observed | (cap monitor) | `{caps}` |

## 6. Guarantees

- **Syscall-level ground truth.** Events come from kernel tracepoints, so
  userland evasion — `LD_PRELOAD` shims, wrapper scripts lying in their own
  logs, patched CLI binaries — does not change what is captured.
- **Out-of-band capture.** The collector runs outside the monitored process;
  the workload cannot suppress or edit its own audit trail without kernel
  privileges.
- **Deterministic evaluation.** Given the same rule set and event stream,
  violations are reproducible byte-for-byte (see `asg-policy/tests`).

## 7. Non-guarantees (known gaps)

- **Encrypted payloads.** We see the connection, never the contents; exfil
  over an allowed HTTPS host with innocuous volume stays invisible until egress
  rules catch the destination.
- **Root attackers.** An attacker with CAP_SYS_ADMIN can unload probes, rewrite
  rules via `PUT /v1/policy` if they reach the API, or simply stop the daemon.
- **TOCTOU on path rules.** Path-based matching sees the requested pathname;
  symlink swaps between open-time and use-time can route around globs.
  Kernel-side path resolution anchoring is future work alongside LSM.
- **Attribution gaps.** pid-ancestry attribution loses grandchildren whose
  parent exited before the child's event arrives; cgroup attach (roadmap)
  closes this.

## 8. Operational recommendations

1. Run the API/dashboard on localhost or a trusted management network; add an
   authenticating proxy before exposing it.
2. Ship violations (`GET /v1/violations`) to your SIEM continuously; the
   in-memory ring holds 5,000 entries only.
3. Keep `denied_processes` tight but real: blocking every package manager may
   break legitimate flows — pair deny with a review workflow.
4. Treat probe-attach failures (logged at startup) as incidents: partial
   coverage is silent to the workload otherwise.
