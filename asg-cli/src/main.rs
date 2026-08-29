//! AgentScope CLI: `serve` runs the collector + API + dashboard,
//! `replay` pushes a JSONL corpus through the pipeline.

use anyhow::{Context, Result};
use asg_api::{router, AppState};
use asg_collector::{pipe, SourceMode};
use asg_common::events::Event;
use asg_common::policy_types::RuleSet;
use clap::{Parser, Subcommand, ValueEnum};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// How long `serve` waits for in-flight requests to drain after a shutdown
/// signal before exiting.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Parser)]
#[command(
    name = "agentscope",
    version,
    about = "eBPF runtime security for AI coding agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the collector and serve the security dashboard.
    Serve {
        #[arg(long, default_value_t = 8100)]
        port: u16,
        #[arg(long, value_enum, default_value_t = SourceArg::Simulated)]
        source: SourceArg,
        #[arg(long, default_value = "asg.bpf.o")]
        bpf_path: String,
    },
    /// Feed a JSONL event corpus through the ingest pipeline and exit.
    ///
    /// The input file contains one JSON event object per line (blank lines
    /// are skipped and never counted; reported line numbers refer to the
    /// real file). Each line carries a `"type"` discriminator of
    /// `proc_exec`, `file_open`, `net_connect` or `cap_escalate`, mirroring
    /// what the eBPF probes emit; see examples/scenario.jsonl for a full
    /// corpus.
    Replay {
        /// Path to a JSONL event file, e.g. --file examples/scenario.jsonl
        #[arg(long)]
        file: String,
        /// Skip malformed lines with a stderr warning instead of aborting on
        /// the first one; the summary reports how many lines were skipped.
        #[arg(long)]
        lenient: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SourceArg {
    Kernel,
    Simulated,
}

impl From<SourceArg> for SourceMode {
    fn from(value: SourceArg) -> Self {
        match value {
            SourceArg::Kernel => SourceMode::Kernel,
            SourceArg::Simulated => SourceMode::Simulated,
        }
    }
}

impl std::fmt::Display for SourceArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceArg::Kernel => write!(f, "kernel"),
            SourceArg::Simulated => write!(f, "simulated"),
        }
    }
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve {
            port,
            source,
            bpf_path,
        } => serve(port, source.into(), bpf_path).await,
        Command::Replay { file, lenient } => replay(&file, lenient).await,
    }
}

async fn serve(port: u16, mode: SourceMode, bpf_path: String) -> Result<()> {
    init_tracing();
    asg_collector::set_kernel_object_path(bpf_path);

    let (state, _stream_rx) = AppState::new(RuleSet::default());
    let (tx, rx) = pipe::make_channel(pipe::DEFAULT_CHANNEL_CAPACITY);

    // The kernel source reports raw ring-buffer record counts through the
    // same Arc that /api/metrics renders and /healthz inspects.
    let source_stats = state.metrics.source_stats();
    let source_task = asg_collector::start(mode, tx, source_stats)
        .await
        .context("starting event source")?;
    state.set_source_alive(true);
    let health_state = state.clone();
    tokio::spawn(async move {
        // Any exit of the source task means events stop flowing; reflect
        // that in /healthz instead of reporting a false "ok".
        if let Err(err) = source_task.await {
            tracing::warn!(%err, "event source died; /healthz now reports degraded");
        } else {
            tracing::warn!("event source stopped; /healthz now reports degraded");
        }
        health_state.set_source_alive(false);
    });

    let pipeline_state = state.clone();
    tokio::spawn(async move {
        pipe::drain(rx, move |event| {
            asg_api::ingest(&pipeline_state, event);
        })
        .await;
    });

    let app = router(state.clone());
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    tracing::info!(%addr, "AgentScope dashboard ready at http://localhost:{port}");

    // Stop accepting new connections on Ctrl+C/SIGTERM, then drain in-flight
    // requests for at most SHUTDOWN_DRAIN_TIMEOUT before exiting.
    let server = axum::serve(listener, app).with_graceful_shutdown(asg_api::shutdown_signal());
    match tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, server).await {
        Ok(result) => result.context("server error")?,
        Err(_) => {
            tracing::warn!(
                timeout_secs = SHUTDOWN_DRAIN_TIMEOUT.as_secs(),
                "drain timed out"
            )
        }
    }
    state.set_source_alive(false);
    tracing::info!(
        events_ingested = state.next_seq.load(std::sync::atomic::Ordering::SeqCst),
        "AgentScope dashboard shut down cleanly"
    );
    Ok(())
}

/// Outcome of pushing a corpus through the ingest pipeline.
#[derive(Debug)]
struct ReplaySummary {
    ingested: usize,
    /// Malformed lines skipped under `--lenient`.
    skipped: usize,
    /// Events shed by ingest backpressure (`max_events_per_sec`).
    throttled: usize,
    violations: usize,
    by_rule: BTreeMap<String, usize>,
}

/// Parses `content` (one JSON event per line, blank lines ignored) and feeds
/// every event through the pipeline. Line numbers in errors/warnings refer
/// to the real file, blanks included. Without `lenient`, the first malformed
/// line aborts with its real line number; with it, bad lines are warned to
/// stderr and counted.
fn replay_lines(
    state: &Arc<AppState>,
    file: &str,
    content: &str,
    lenient: bool,
) -> Result<ReplaySummary> {
    let mut summary = ReplaySummary {
        ingested: 0,
        skipped: 0,
        throttled: 0,
        violations: 0,
        by_rule: BTreeMap::new(),
    };
    for (idx, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed = serde_json::from_str::<Event>(line)
            .with_context(|| format!("{file} line {}: invalid event", idx + 1));
        let event = match parsed {
            Ok(event) => event,
            Err(err) if lenient => {
                eprintln!("warning: skipping {err:#}");
                summary.skipped += 1;
                continue;
            }
            Err(err) => return Err(err),
        };
        if asg_api::ingest(state, event) {
            summary.ingested += 1;
        } else {
            summary.throttled += 1;
        }
    }
    let violations = state
        .violations
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for v in violations.iter() {
        *summary
            .by_rule
            .entry(v.violation.rule_id.clone())
            .or_default() += 1;
    }
    summary.violations = violations.len();
    Ok(summary)
}

async fn replay(file: &str, lenient: bool) -> Result<()> {
    init_tracing();
    let (state, _rx) = AppState::new(RuleSet::default());
    let content = std::fs::read_to_string(file).with_context(|| format!("reading {file}"))?;
    let summary = replay_lines(&state, file, &content, lenient)?;

    println!("replayed {} events from {file}", summary.ingested);
    println!("violations: {}", summary.violations);
    for (rule, count) in &summary.by_rule {
        println!("  {rule:<18} x{count}");
    }
    if summary.skipped > 0 {
        println!("skipped {} malformed lines", summary.skipped);
    }
    if summary.throttled > 0 {
        println!("rate-limited {} events", summary.throttled);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"{"type":"file_open","pid":1,"tgid":2,"comm":"cat","path":"notes.txt","flags":0,"ts_ns":1,"is_write_hint":false}"#;
    const SECRET: &str = r#"{"type":"file_open","pid":3,"tgid":4,"comm":"cat","path":".env","flags":0,"ts_ns":2,"is_write_hint":false}"#;

    #[test]
    fn strict_replay_aborts_with_real_file_line_number() {
        // Blank line between the good and bad lines must still count toward
        // the reported number: the bad JSON really is on file line 3.
        let content = format!("{GOOD}\n\n{{not json}}\n{SECRET}\n");
        let (state, _rx) = AppState::new(RuleSet::default());
        let err = replay_lines(&state, "corpus.jsonl", &content, false)
            .expect_err("malformed line must abort in strict mode");
        let msg = format!("{err:#}");
        assert!(msg.contains("corpus.jsonl line 3"), "got: {msg}");
        assert!(msg.contains("invalid event"), "got: {msg}");
        // Nothing after the bad line was ingested.
        assert_eq!(state.events.lock().unwrap().len(), 1);
    }

    #[test]
    fn lenient_replay_skips_bad_lines_and_counts_them() {
        let content = format!("{GOOD}\n   \n{{not json}}\n{SECRET}\nalso bad\n");
        let (state, _rx) = AppState::new(RuleSet::default());
        let summary = replay_lines(&state, "corpus.jsonl", &content, true)
            .expect("lenient mode must not fail");
        assert_eq!(summary.ingested, 2);
        assert_eq!(summary.skipped, 2);
        assert_eq!(summary.violations, 1, "the .env read raises SECRET_ACCESS");
        assert_eq!(summary.by_rule.get("SECRET_ACCESS"), Some(&1));
        // Blank lines were never counted anywhere.
        assert_eq!(
            state.events.lock().unwrap().len(),
            2,
            "blank line must not consume an ingest slot"
        );
    }
}
