# AgentScope Benchmarks

Methodology and (placeholder) results for the policy-engine micro-benchmarks.

## How to run

```bash
cargo run -p asg-cli --bin bench --release
```

## Methodology

- **No criterion.** Timing uses `std::time::Instant` around whole rounds; we
  report hand-written percentiles (nearest-rank over 12 rounds) plus mean
  throughput. This is deliberately crude: the goal is regression visibility,
  not publication-grade statistics.
- **policy_eval** evaluates a synthetic mix of 100,000 events
  (`proc_exec` / `file_open` / `net_connect` / `cap_escalate`, with ~12%
  secret-path hits, ~25% denied processes and ~6% warn-listed hosts) through
  the default `RuleSet`.
- **glob_match** measures worst-case recursive segment matching: pattern
  `**/**/**/x` against an 11-segment deep path, 200,000 calls per round.
- A warmup round runs before timing; results below are per-operation
  nanoseconds (p50/p95/p99) and mean ops/s on the author's machine.
  Your numbers will differ; compare relative deltas only.

## Results

| op          |       n | p50 (ns/op) | p95 (ns/op) | p99 (ns/op) | ops/s |
|-------------|---------|-------------|-------------|-------------|-------|
| policy_eval | 100_000 | TBD         | TBD         | TBD         | TBD   |
| glob_match  | 200_000 | TBD         | TBD         | TBD         | TBD   |

Fill this table from your machine and note CPU/RAM/kernel in a footnote when
publishing comparisons.

## Reading the numbers

- `policy_eval` cost is dominated by glob evaluation of secret-path rules;
  adding globs scales roughly linearly for non-matching opens (first-glob
  miss walks all patterns).
- `glob_match` is intentionally adversarial: stacked `**` segments force
  backtracking. Real rule sets use at most one leading `**`, which short-
  circuits far faster than the worst case shown here.

## Regression workflow

Run before/after touching `asg-policy/src/glob.rs` or `rules.rs`; treat a
>20% p95 regression as a blocker unless accompanied by a capability win.
