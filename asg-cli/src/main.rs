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
    Replay {
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

    let _source_task = asg_collector::start(mode, tx)
        .await
        .context("starting event source")?;

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
    axum::serve(listener, app).await.context("server error")
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
