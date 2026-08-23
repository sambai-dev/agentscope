//! Micro-benchmarks for the AgentScope policy engine.
//!
//! Run with `cargo run -p asg-cli --bin bench`. Uses Instant and a
//! hand-written percentile; no criterion dependency.

use asg_common::events::Event;
use asg_common::policy_types::RuleSet;
use asg_policy::{eval, glob};
use std::hint::black_box;
use std::time::Instant;

const EVAL_ROUNDS: usize = 12;
const GLOB_ROUNDS: usize = 12;
const EVAL_EVENTS: usize = 100_000;
const GLOB_CALLS: usize = 200_000;

const GLOB_PATTERN: &str = "**/**/**/x";
const GLOB_TEXT: &str = "a/b/c/d/e/f/g/h/i/j/x";

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let rank = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

fn synthetic_events(n: usize) -> Vec<Event> {
    (0..n)
        .map(|i| match i % 4 {
            0 => Event::ProcExec {
                pid: i as u32,
                tgid: i as u32,
                ppid: (i / 2) as u32,
                cgroup_id: 9_001,
                comm: if i % 8 == 0 { "npm" } else { "node" }.to_string(),
                args: vec!["install".to_string()],
                uid: 1000,
                ts_ns: i as u64,
            },
            1 => Event::FileOpen {
                pid: i as u32,
                tgid: i as u32,
                comm: "cat".to_string(),
                path: if i % 8 == 0 {
                    "/home/dev/project/.env".to_string()
                } else {
                    "/home/dev/project/src/main.rs".to_string()
                },
                flags: 0,
                ts_ns: i as u64,
                is_write_hint: false,
            },
            2 => Event::NetConnect {
                pid: i as u32,
                tgid: i as u32,
                comm: "curl".to_string(),
                daddr: if i % 16 == 0 {
                    "ngrok.io".to_string()
                } else {
                    "api.github.com".to_string()
                },
                dport: 443,
                family: "IPv4".to_string(),
                ts_ns: i as u64,
            },
            _ => Event::CapEscalate {
                pid: i as u32,
                tgid: i as u32,
                comm: "sudo".to_string(),
                caps: "CAP_SYS_ADMIN".to_string(),
                ts_ns: i as u64,
            },
        })
        .collect()
}

fn measure<F: FnMut()>(rounds: usize, mut op: F) -> Vec<f64> {
    op();
    (0..rounds)
        .map(|_| {
            let start = Instant::now();
            op();
            start.elapsed().as_secs_f64()
        })
        .collect()
}

fn print_row(name: &str, n: usize, mut durations_s: Vec<f64>) {
    durations_s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let per_op_ns = |s: f64| s * 1e9 / n as f64;
    let mean = durations_s.iter().sum::<f64>() / durations_s.len() as f64;
    println!(
        "| {:<14} | {:>7} | {:>10} | {:>10} | {:>10} | {:>12.0} |",
        name,
        n,
        format!("{:.1}", per_op_ns(percentile(&durations_s, 50.0))),
        format!("{:.1}", per_op_ns(percentile(&durations_s, 95.0))),
        format!("{:.1}", per_op_ns(percentile(&durations_s, 99.0))),
        n as f64 / mean,
    );
}

fn main() {
    let rules = RuleSet::default();
    let events = synthetic_events(EVAL_EVENTS);
    let mut violation_sink = 0usize;
    let eval_durations = measure(EVAL_ROUNDS, || {
        for event in &events {
            violation_sink += eval(black_box(event), &rules).len();
        }
    });

    let mut glob_sink = 0usize;
    let glob_durations = measure(GLOB_ROUNDS, || {
        for _ in 0..GLOB_CALLS {
            if glob::matches(GLOB_PATTERN, black_box(GLOB_TEXT)) {
                glob_sink += 1;
            }
        }
    });

    println!();
    println!("AgentScope policy-engine benchmarks");
    println!("(percentiles are per-operation nanoseconds)");
    println!();
    println!("| op             |       n |       p50 |       p95 |       p99 |         ops/s |");
    println!("|----------------|---------|-----------|-----------|-----------|---------------|");
    print_row("policy_eval", EVAL_EVENTS, eval_durations);
    print_row("glob_match", GLOB_CALLS, glob_durations);
    eprintln!("sink={violation_sink} {glob_sink}");
}
