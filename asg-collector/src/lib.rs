//! AgentScope event collection: eBPF kernel probes on Linux and a
//! deterministic simulated source everywhere else.

pub mod pipe;
pub mod source;

use asg_common::events::Event;
use asg_common::stats::SourceRecordStats;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;

/// Errors surfaced while starting or running an event source.
#[derive(Debug, thiserror::Error)]
pub enum CollectorError {
    #[error("eBPF collection is unsupported on this platform; use --source simulated")]
    UnsupportedPlatform,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("aya error: {0}")]
    Aya(String),
}

/// Which backend produces kernel events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceMode {
    /// Attach real tracepoint probes via aya (Linux only).
    Kernel,
    /// Deterministic scripted scenario generator (all platforms).
    Simulated,
}

impl SourceMode {
    /// Parses the CLI `--source` flag value.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "kernel" => Some(Self::Kernel),
            "simulated" | "sim" => Some(Self::Simulated),
            _ => None,
        }
    }
}

/// Overrides the compiled eBPF object location used by kernel mode.
#[cfg(target_os = "linux")]
pub fn set_kernel_object_path(path: impl Into<String>) {
    source::linux::set_object_path(path);
}

/// No-op on non-Linux platforms where kernel mode is unavailable.
#[cfg(not(target_os = "linux"))]
pub fn set_kernel_object_path(_path: impl Into<String>) {}

/// Starts the requested source and spawns its event loop.
///
/// `stats` receives raw ring-buffer record counts (ingested vs dropped/
/// malformed). Only the kernel source writes them; the simulated source
/// produces no ring records, so on non-Linux hosts the handle is accepted
/// for signature parity and left untouched.
#[cfg(target_os = "linux")]
pub async fn start(
    mode: SourceMode,
    tx: Sender<Event>,
    stats: Arc<SourceRecordStats>,
) -> Result<JoinHandle<()>, CollectorError> {
    match mode {
        SourceMode::Kernel => source::linux::start(tx, stats).await,
        SourceMode::Simulated => Ok(tokio::spawn(source::sim::run(tx))),
    }
}

/// Non-Linux variant: kernel mode is unsupported and `stats` is unused.
#[cfg(not(target_os = "linux"))]
pub async fn start(
    mode: SourceMode,
    tx: Sender<Event>,
    _stats: Arc<SourceRecordStats>,
) -> Result<JoinHandle<()>, CollectorError> {
    match mode {
        SourceMode::Kernel => Err(CollectorError::UnsupportedPlatform),
        SourceMode::Simulated => Ok(tokio::spawn(source::sim::run(tx))),
    }
}
