//! Hand-rolled Prometheus text-format metrics (no prometheus crate).
//!
//! Counters are atomics; histogram buckets are computed on scrape from a
//! bounded ring of recent latency samples held in a mutex.

use asg_policy::Severity;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Latency bucket edges in milliseconds (`le` values, inclusive).
pub const INGEST_LATENCY_BUCKETS_MS: [f64; 7] = [0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];

const LATENCY_SAMPLE_CAP: usize = 8_192;

/// Process-wide counters and histograms for the API surface.
pub struct Metrics {
    events_total: AtomicU64,
    violations_total: AtomicU64,
    violations_critical_total: AtomicU64,
    violations_warn_total: AtomicU64,
    ingest_latency_ms_samples: Mutex<Vec<f64>>,
}

impl Metrics {
    /// Creates zeroed metrics.
    pub fn new() -> Self {
        Self {
            events_total: AtomicU64::new(0),
            violations_total: AtomicU64::new(0),
            violations_critical_total: AtomicU64::new(0),
            violations_warn_total: AtomicU64::new(0),
            ingest_latency_ms_samples: Mutex::new(Vec::new()),
        }
    }

    pub fn inc_events(&self) {
        self.events_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_violation(&self, severity: Severity) {
        self.violations_total.fetch_add(1, Ordering::Relaxed);
        match severity {
            Severity::Critical => {
                self.violations_critical_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            Severity::High | Severity::Medium | Severity::Low => {
                self.violations_warn_total.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn observe_ingest_latency_ms(&self, ms: f64) {
        let mut samples = self
            .ingest_latency_ms_samples
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if samples.len() >= LATENCY_SAMPLE_CAP {
            let drop_by = samples.len() - LATENCY_SAMPLE_CAP + 1;
            samples.drain(..drop_by);
        }
        samples.push(ms);
    }

    /// Renders the metrics registry in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let events = self.events_total.load(Ordering::Relaxed);
        let violations = self.violations_total.load(Ordering::Relaxed);
        let critical = self.violations_critical_total.load(Ordering::Relaxed);
        let warn = self.violations_warn_total.load(Ordering::Relaxed);

        let samples = self
            .ingest_latency_ms_samples
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = samples.len();
        let sum: f64 = samples.iter().sum();
        let mut out = String::with_capacity(1_024);

        out.push_str("# HELP asg_events_total Kernel events ingested.\n");
        out.push_str("# TYPE asg_events_total counter\n");
        out.push_str(&format!("asg_events_total {events}\n"));

        out.push_str("# HELP asg_violations_total Policy violations emitted.\n");
        out.push_str("# TYPE asg_violations_total counter\n");
        out.push_str(&format!("asg_violations_total {violations}\n"));
        out.push_str("# HELP asg_violations_critical_total Critical-severity violations.\n");
        out.push_str("# TYPE asg_violations_critical_total counter\n");
        out.push_str(&format!("asg_violations_critical_total {critical}\n"));
        out.push_str("# HELP asg_violations_warn_total Non-critical (warn) violations.\n");
        out.push_str("# TYPE asg_violations_warn_total counter\n");
        out.push_str(&format!("asg_violations_warn_total {warn}\n"));

        out.push_str("# HELP asg_ingest_latency_ms Ingest pipeline latency in milliseconds.\n");
        out.push_str("# TYPE asg_ingest_latency_ms histogram\n");
        for &edge in INGEST_LATENCY_BUCKETS_MS.iter() {
            let cumulative = samples.iter().filter(|&&v| v <= edge).count();
            out.push_str(&format!(
                "asg_ingest_latency_ms_bucket{{le=\"{edge}\"}} {cumulative}\n"
            ));
        }
        out.push_str(&format!(
            "asg_ingest_latency_ms_bucket{{le=\"+Inf\"}} {count}\n"
        ));
        out.push_str(&format!("asg_ingest_latency_ms_sum {sum:.6}\n"));
        out.push_str(&format!("asg_ingest_latency_ms_count {count}\n"));
        out
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_counters_and_histogram() {
        let m = Metrics::new();
        m.inc_events();
        m.inc_events();
        m.inc_violation(Severity::Critical);
        m.inc_violation(Severity::Medium);
        m.observe_ingest_latency_ms(0.3);
        m.observe_ingest_latency_ms(2.0);

        let text = m.render();
        assert!(text.contains("# TYPE asg_events_total counter"));
        assert!(text.contains("asg_events_total 2\n"));
        assert!(text.contains("asg_violations_total 2\n"));
        assert!(text.contains("asg_violations_critical_total 1\n"));
        assert!(text.contains("asg_violations_warn_total 1\n"));
        assert!(text.contains("asg_ingest_latency_ms_bucket{le=\"0.5\"} 1\n"));
        assert!(text.contains("asg_ingest_latency_ms_bucket{le=\"+Inf\"} 2\n"));
        assert!(text.contains("asg_ingest_latency_ms_count 2\n"));
    }

    #[test]
    fn sample_ring_is_bounded() {
        let m = Metrics::new();
        for i in 0..(LATENCY_SAMPLE_CAP + 500) {
            m.observe_ingest_latency_ms(i as f64);
        }
        assert!(m.ingest_latency_ms_samples.lock().unwrap().len() <= LATENCY_SAMPLE_CAP);
    }
}
