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
        #[arg(long, default_value = "bpf/asg.bpf.o")]
        bpf_path: String,
    },
    /// Feed a JSONL event corpus through the ingest pipeline and exit.
    ///
    /// The input file contains one JSON event object per line (blank lines
    /// are skipped). Each line carries a `"type"` discriminator of
    /// `proc_exec`, `file_open`, `net_connect` or `cap_escalate`, mirroring
    /// what the eBPF probes emit; see examples/scenario.jsonl for a full
    /// corpus.
    Replay {
        /// Path to a JSONL event file, e.g. --file examples/scenario.jsonl
        #[arg(long)]
        file: String,
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
        Command::Replay { file } => replay(&file).await,
    }
}

async fn serve(port: u16, mode: SourceMode, bpf_path: String) -> Result<()> {
    init_tracing();
    asg_collector::set_kernel_object_path(bpf_path);

    let (state, _stream_rx) = AppState::new(RuleSet::default());
    let (tx, rx) = pipe::make_channel(pipe::DEFAULT_CHANNEL_CAPACITY);

    let source_task = asg_collector::start(mode, tx)
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

async fn replay(file: &str) -> Result<()> {
    init_tracing();
    let (state, _rx) = AppState::new(RuleSet::default());
    let content = std::fs::read_to_string(file).with_context(|| format!("reading {file}"))?;

    let mut ingested = 0usize;
    for (idx, line) in content.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let event: Event = serde_json::from_str(line)
            .with_context(|| format!("{} line {}: invalid event", file, idx + 1))?;
        asg_api::ingest(&state, event);
        ingested += 1;
    }

    let violations = state.violations.lock().unwrap();
    let mut by_rule: BTreeMap<&str, usize> = BTreeMap::new();
    for v in violations.iter() {
        *by_rule.entry(v.violation.rule_id.as_str()).or_default() += 1;
    }

    println!("replayed {ingested} events from {file}");
    println!("violations: {}", violations.len());
    for (rule, count) in by_rule {
        println!("  {rule:<18} x{count}");
    }
    Ok(())
}
