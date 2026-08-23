//! AgentScope HTTP API.
//!
//! Owns the shared [`AppState`], the ingest pipeline (store -> process tree
//! -> policy eval -> metrics -> broadcast) and every HTTP route including
//! the embedded dashboard.

pub mod metrics;

use asg_common::events::Event;
use asg_common::policy_types::RuleSet;
use asg_policy::{eval, Violation};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{
        sse::{Event as SseEvent, KeepAlive, Sse},
        Html, IntoResponse, Response,
    },
    routing::{get, post, put},
    Json, Router,
};
use metrics::Metrics;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Instant,
};
use tokio::sync::broadcast;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

/// Embedded dashboard (vanilla JS, zero CDN dependencies).
pub const INDEX_HTML: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/index.html"));

/// Cap on the in-memory event ring.
pub const EVENT_CAP: usize = 20_000;

/// Cap on the in-memory violation ring.
pub const VIOLATION_CAP: usize = 5_000;

/// Broadcast channel capacity for SSE subscribers.
pub const STREAM_CAPACITY: usize = 1_024;

/// An event with its monotonically assigned sequence number.
#[derive(Debug, Clone, Serialize)]
pub struct StoredEvent {
    pub seq: u64,
    pub event: Event,
}

/// A violation with its sequence number and wall-clock timestamp.
#[derive(Debug, Clone, Serialize)]
pub struct StoredViolation {
    pub seq: u64,
    pub ts_rfc3339: String,
    #[serde(flatten)]
    pub violation: Violation,
}

impl StoredViolation {
    fn new(seq: u64, ts_rfc3339: String, violation: Violation) -> Self {
        Self {
            seq,
            ts_rfc3339,
            violation,
        }
    }
}

/// Live message pushed to dashboard subscribers over SSE.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StreamMsg {
    Event(StoredEvent),
    Violation(StoredViolation),
    Pong,
}

/// Observed process record derived from `proc_exec` events.
#[derive(Debug, Clone)]
pub struct ProcRecord {
    pub tgid: u32,
    pub ppid: u32,
    pub comm: String,
    pub args: Vec<String>,
    pub cgroup_id: u64,
    pub uid: u32,
    pub first_seen_ts_ns: u64,
}

/// Serializable node of the process forest served by `/v1/processes`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProcNode {
    pub id: u32,
    pub comm: String,
    pub args: Vec<String>,
    pub ts_ns: u64,
    pub children: Vec<ProcNode>,
}

/// Shared server state guarded by locks; cheap to clone behind `Arc`.
pub struct AppState {
    pub events: Mutex<VecDeque<StoredEvent>>,
    pub processes: Mutex<HashMap<u32, ProcRecord>>,
    pub violations: Mutex<VecDeque<StoredViolation>>,
    pub ruleset: RwLock<RuleSet>,
    pub metrics: Arc<Metrics>,
    pub next_seq: AtomicU64,
    pub tx: broadcast::Sender<StreamMsg>,
    /// Whether the configured event source (simulated or eBPF collector) is
    /// currently producing events; drives `/healthz` readiness.
    source_alive: AtomicBool,
}

impl AppState {
    /// Creates a fresh state with the given starting rule set. The event
    /// source starts out marked down until the runtime marks it up.
    pub fn new(ruleset: RuleSet) -> (Arc<Self>, broadcast::Receiver<StreamMsg>) {
        let (tx, rx) = broadcast::channel(STREAM_CAPACITY);
        let state = Arc::new(Self {
            events: Mutex::new(VecDeque::new()),
            processes: Mutex::new(HashMap::new()),
            violations: Mutex::new(VecDeque::new()),
            ruleset: RwLock::new(ruleset),
            metrics: Arc::new(Metrics::new()),
            next_seq: AtomicU64::new(0),
            tx,
            source_alive: AtomicBool::new(false),
        });
        (state, rx)
    }

    /// Marks the event source as up (`true`) or down (`false`).
    pub fn set_source_alive(&self, alive: bool) {
        self.source_alive.store(alive, Ordering::SeqCst);
    }

    /// Returns `true` while the configured event source is producing.
    pub fn source_alive(&self) -> bool {
        self.source_alive.load(Ordering::SeqCst)
    }
}

/// Errors surfaced to API callers as JSON bodies.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

/// Builds the full router with shared state.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/api/metrics", get(api_metrics))
        .route("/v1/events", post(post_events).get(get_events))
        .route("/v1/processes", get(get_processes))
        .route("/v1/violations", get(get_violations))
        .route("/v1/policy", put(put_policy))
        .route("/v1/stream", get(get_stream))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

/// Readiness probe: `200 {"status":"ok"}` while the configured event source
/// (simulated or eBPF collector) is producing, otherwise `503` degraded so
/// orchestrators stop routing to an instance that cannot observe events.
async fn healthz(State(st): State<Arc<AppState>>) -> Response {
    if st.source_alive() {
        Json(json!({ "status": "ok" })).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "degraded",
                "reason": "event source not running",
            })),
        )
            .into_response()
    }
}

async fn api_metrics(State(st): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        st.metrics.render(),
    )
}

async fn post_events(
    State(st): State<Arc<AppState>>,
    body: Result<Json<serde_json::Value>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let Json(value) = body.map_err(|e| ApiError::BadRequest(e.body_text()))?;
    let events: Vec<Event> = match value {
        serde_json::Value::Array(_) => serde_json::from_value(value)
            .map_err(|e| ApiError::BadRequest(format!("invalid event array: {e}")))?,
        _ => vec![serde_json::from_value(value)
            .map_err(|e| ApiError::BadRequest(format!("invalid event: {e}")))?],
    };
    for event in &events {
        ingest(&st, event.clone());
    }
    Ok(Json(json!({ "accepted": events.len() })))
}

#[derive(Debug, Deserialize)]
struct EventsQuery {
    limit: Option<usize>,
    since_seq: Option<u64>,
}

async fn get_events(
    State(st): State<Arc<AppState>>,
    Query(q): Query<EventsQuery>,
) -> Json<Vec<StoredEvent>> {
    let limit = q.limit.unwrap_or(500).min(EVENT_CAP);
    let since = q.since_seq.unwrap_or(0);
    let events = st
        .events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let out: Vec<StoredEvent> = events
        .iter()
        .filter(|e| e.seq > since)
        .rev()
        .take(limit)
        .cloned()
        .collect();
    let mut out = out;
    out.reverse();
    Json(out)
}

async fn get_processes(State(st): State<Arc<AppState>>) -> Json<Vec<ProcNode>> {
    let records: Vec<ProcRecord> = st
        .processes
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .values()
        .cloned()
        .collect::<Vec<_>>();
    Json(build_process_forest(&records))
}

#[derive(Debug, Deserialize)]
struct LimitQuery {
    limit: Option<usize>,
}

async fn get_violations(
    State(st): State<Arc<AppState>>,
    Query(q): Query<LimitQuery>,
) -> Json<Vec<StoredViolation>> {
    let limit = q.limit.unwrap_or(200).min(VIOLATION_CAP);
    let violations = st
        .violations
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let out: Vec<StoredViolation> = violations.iter().rev().take(limit).cloned().collect();
    let mut out = out;
    out.reverse();
    Json(out)
}

async fn put_policy(
    State(st): State<Arc<AppState>>,
    Json(ruleset): Json<RuleSet>,
) -> Json<serde_json::Value> {
    let denied_count = ruleset.denied_processes.len();
    let secret_glob_count = ruleset.secret_path_globs.len();
    let denied_host_count = ruleset.denied_hosts.len();
    *st.ruleset
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = ruleset;
    tracing::info!(
        target: "audit",
        denied_processes = denied_count,
        secret_path_globs = secret_glob_count,
        denied_hosts = denied_host_count,
        "policy updated"
    );
    Json(json!({ "status": "applied" }))
}

async fn get_stream(
    State(st): State<Arc<AppState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = st.tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|msg| match msg {
        Ok(m) => Some(Ok::<_, Infallible>(SseEvent::default().data(
            serde_json::to_string(&m).unwrap_or_else(|_| "{\"kind\":\"pong\"}".into()),
        ))),
        Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(_)) => None,
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Resolves once the process is asked to shut down: Ctrl+C (SIGINT) on every
/// platform, plus SIGTERM on Unix. Feed the returned future to
/// [`axum::serve`] via `with_graceful_shutdown` to stop accepting new
/// connections and let in-flight requests finish.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            tracing::error!("failed to listen for Ctrl+C; shutdown signal disabled");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => {
                tracing::error!(%err, "failed to install SIGTERM handler; shutdown signal disabled");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("shutdown requested: interrupt"),
        _ = terminate => tracing::info!("shutdown requested: terminate"),
    }
}

/// Runs one event through the full pipeline: store, process tree, policy,
/// metrics and broadcast.
pub fn ingest(st: &Arc<AppState>, event: Event) {
    let started = Instant::now();
    st.metrics.inc_events();

    if let Event::ProcExec {
        tgid,
        ppid,
        comm,
        args,
        cgroup_id,
        uid,
        ts_ns,
        ..
    } = &event
    {
        st.processes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                *tgid,
                ProcRecord {
                    tgid: *tgid,
                    ppid: *ppid,
                    comm: comm.clone(),
                    args: args.clone(),
                    cgroup_id: *cgroup_id,
                    uid: *uid,
                    first_seen_ts_ns: *ts_ns,
                },
            );
    }

    let seq = st.next_seq.fetch_add(1, Ordering::SeqCst);
    let stored = StoredEvent { seq, event };
    {
        let mut events = st
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if events.len() >= EVENT_CAP {
            events.pop_front();
        }
        events.push_back(stored.clone());
    }

    let rules = st
        .ruleset
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    for violation in eval(&stored.event, &rules) {
        let severity = violation.severity;
        let stored_violation = StoredViolation::new(
            seq,
            asg_common::timeutil::ts_ns_to_rfc3339(event_now_ns()),
            violation,
        );
        st.metrics.inc_violation(severity);
        let mut violations = st
            .violations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if violations.len() >= VIOLATION_CAP {
            violations.pop_front();
        }
        violations.push_back(stored_violation.clone());
        drop(violations);
        let _ = st.tx.send(StreamMsg::Violation(stored_violation));
    }

    let _ = st.tx.send(StreamMsg::Event(stored));
    st.metrics
        .observe_ingest_latency_ms(started.elapsed().as_secs_f64() * 1_000.0);
}

fn event_now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or_default()
}

/// Builds a process forest from flat records, synthesizing placeholder roots
/// labelled `(unknown pid N)` for parents that were never observed.
pub fn build_process_forest(records: &[ProcRecord]) -> Vec<ProcNode> {
    let by_tgid: HashMap<u32, &ProcRecord> = records.iter().map(|r| (r.tgid, r)).collect();
    let mut children_of: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut sorted: Vec<&ProcRecord> = records.iter().collect();
    sorted.sort_by_key(|r| (r.first_seen_ts_ns, r.tgid));
    for rec in &sorted {
        children_of.entry(rec.ppid).or_default().push(rec.tgid);
    }

    let mut memo: HashMap<u32, ProcNode> = HashMap::new();

    fn node_for(
        tgid: u32,
        by_tgid: &HashMap<u32, &ProcRecord>,
        children_of: &HashMap<u32, Vec<u32>>,
        memo: &mut HashMap<u32, ProcNode>,
    ) -> ProcNode {
        if let Some(existing) = memo.get(&tgid) {
            return existing.clone();
        }
        let children = children_of
            .get(&tgid)
            .map(|kids| {
                kids.iter()
                    .filter(|kid| **kid != tgid)
                    .map(|&kid| node_for(kid, by_tgid, children_of, memo))
                    .collect()
            })
            .unwrap_or_default();
        let node = match by_tgid.get(&tgid) {
            Some(rec) => ProcNode {
                id: tgid,
                comm: rec.comm.clone(),
                args: rec.args.clone(),
                ts_ns: rec.first_seen_ts_ns,
                children,
            },
            None => ProcNode {
                id: tgid,
                comm: format!("(unknown pid {tgid})"),
                args: Vec::new(),
                ts_ns: 0,
                children,
            },
        };
        memo.insert(tgid, node.clone());
        node
    }

    let mut roots: Vec<ProcNode> = Vec::new();
    let mut synthetic: HashMap<u32, ProcNode> = HashMap::new();
    for rec in &sorted {
        let parent_observed = by_tgid.contains_key(&rec.ppid);
        if parent_observed && rec.ppid != rec.tgid {
            continue;
        }
        let child_node = node_for(rec.tgid, &by_tgid, &children_of, &mut memo);
        if rec.ppid == rec.tgid {
            roots.push(child_node);
            continue;
        }
        let wrapper = synthetic.entry(rec.ppid).or_insert_with(|| ProcNode {
            id: rec.ppid,
            comm: format!("(unknown pid {})", rec.ppid),
            args: Vec::new(),
            ts_ns: 0,
            children: Vec::new(),
        });
        wrapper.children.push(child_node);
    }
    roots.extend(synthetic.into_values());
    roots.sort_by_key(|n| (n.ts_ns, n.id));
    roots
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(tgid: u32, ppid: u32, ts: u64) -> ProcRecord {
        ProcRecord {
            tgid,
            ppid,
            comm: format!("proc{tgid}"),
            args: vec!["-x".into()],
            cgroup_id: 1,
            uid: 1000,
            first_seen_ts_ns: ts,
        }
    }

    #[test]
    fn unknown_parents_are_synthesized_and_deduped() {
        let records = vec![rec(400, 999, 10), rec(401, 400, 20), rec(402, 888, 30)];
        let forest = build_process_forest(&records);
        assert_eq!(forest.len(), 2);
        assert_eq!(
            forest.iter().map(|n| n.id).collect::<Vec<_>>(),
            vec![888, 999]
        );

        let synthetic = forest
            .iter()
            .find(|n| n.comm == "(unknown pid 999)")
            .expect("synthesized root");
        assert_eq!(synthetic.children.len(), 1);
        let bash_like = &synthetic.children[0];
        assert_eq!(bash_like.id, 400);
        assert_eq!(bash_like.children[0].id, 401);
        assert_eq!(bash_like.children[0].comm, "proc401");

        let other = forest
            .iter()
            .find(|n| n.comm == "(unknown pid 888)")
            .expect("second synthesized root");
        assert_eq!(other.children[0].id, 402);
    }

    #[test]
    fn observed_parent_chains_nest_without_synthetic_roots() {
        let records = vec![rec(300, 300, 1), rec(400, 300, 5), rec(500, 400, 9)];
        let forest = build_process_forest(&records);
        assert_eq!(forest.len(), 1);
        assert_eq!(forest[0].id, 300);
        assert_eq!(forest[0].children[0].id, 400);
        assert_eq!(forest[0].children[0].children[0].id, 500);
    }

    #[test]
    fn ingest_pipeline_stores_broadcasts_and_flags_secrets() {
        let (state, mut rx) = AppState::new(RuleSet::default());
        let e1 = Event::ProcExec {
            pid: 1,
            tgid: 2,
            ppid: 1,
            cgroup_id: 7,
            comm: "bash".into(),
            args: vec![],
            uid: 0,
            ts_ns: 1,
        };
        let e2 = Event::FileOpen {
            pid: 3,
            tgid: 4,
            comm: "cat".into(),
            path: ".env".into(),
            flags: 0,
            ts_ns: 2,
            is_write_hint: false,
        };
        ingest(&state, e1);
        ingest(&state, e2);

        assert_eq!(state.events.lock().unwrap().len(), 2);
        assert_eq!(state.processes.lock().unwrap().len(), 1);
        assert_eq!(state.violations.lock().unwrap().len(), 1);
        assert_eq!(
            state.violations.lock().unwrap()[0].violation.rule_id,
            "SECRET_ACCESS"
        );
        let first = rx.try_recv().unwrap();
        assert!(matches!(
            first,
            StreamMsg::Event(StoredEvent { seq: 0, .. })
        ));
        assert_eq!(state.next_seq.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn healthz_reflects_event_source_readiness() {
        let (state, _rx) = AppState::new(RuleSet::default());

        let body = healthz_body(State(state.clone())).await;
        assert_eq!(body.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.1["status"], "degraded");
        assert_eq!(body.1["reason"], "event source not running");

        state.set_source_alive(true);
        let body = healthz_body(State(state.clone())).await;
        assert_eq!(body.0, StatusCode::OK);
        assert_eq!(body.1["status"], "ok");

        state.set_source_alive(false);
        let body = healthz_body(State(state)).await;
        assert_eq!(body.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.1["status"], "degraded");
    }

    async fn healthz_body(st: State<Arc<AppState>>) -> (StatusCode, serde_json::Value) {
        let response = healthz(st).await;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
}
