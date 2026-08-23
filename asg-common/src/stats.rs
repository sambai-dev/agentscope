//! Shared counters between event sources and the API surface.
//!
//! The kernel source (asg-collector on Linux) is the sole writer; asg-api
//! owns the instance inside [`asg_api::metrics::Metrics`] and renders it.
//! Keeping the type here lets both crates share one `Arc` without a
//! collector -> api dependency.

use std::sync::atomic::{AtomicU64, Ordering};

/// Ingested-vs-dropped counters for raw kernel ring-buffer records.
///
/// "Ingested" means a record parsed and widened successfully and was handed
/// to the pipeline channel; "dropped/malformed" means the bytes could not be
/// parsed, were missing identity fields, or claimed a discriminator the
/// kernel source cannot produce. The simulated source produces no ring
/// records and never touches these counters.
#[derive(Debug, Default)]
pub struct SourceRecordStats {
    ingested: AtomicU64,
    dropped_malformed: AtomicU64,
}

impl SourceRecordStats {
    /// Creates zeroed counters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one ring-buffer record that was widened and forwarded.
    pub fn inc_ingested(&self) {
        self.ingested.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one ring-buffer record discarded as malformed/unusable.
    pub fn inc_dropped_malformed(&self) {
        self.dropped_malformed.fetch_add(1, Ordering::Relaxed);
    }

    /// Records successfully ingested so far.
    pub fn ingested(&self) -> u64 {
        self.ingested.load(Ordering::Relaxed)
    }

    /// Records dropped as malformed/unusable so far.
    pub fn dropped_malformed(&self) -> u64 {
        self.dropped_malformed.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_start_at_zero_and_accumulate() {
        let s = SourceRecordStats::new();
        assert_eq!((s.ingested(), s.dropped_malformed()), (0, 0));
        s.inc_ingested();
        s.inc_ingested();
        s.inc_dropped_malformed();
        assert_eq!((s.ingested(), s.dropped_malformed()), (2, 1));
    }
}
