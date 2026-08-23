//! Channel glue between event sources and consumers.

use asg_common::events::Event;
use tokio::sync::mpsc::{channel, Receiver, Sender};

/// Default bounded capacity for the ingest channel.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 4_096;

/// Creates a bounded mpsc pair carrying kernel events to the pipeline.
pub fn make_channel(capacity: usize) -> (Sender<Event>, Receiver<Event>) {
    channel(capacity)
}

/// Drains the receiver, invoking `on_event` per event under a tracing span.
pub async fn drain<F>(mut rx: Receiver<Event>, mut on_event: F)
where
    F: FnMut(Event),
{
    while let Some(event) = rx.recv().await {
        let span = tracing::info_span!("event", tgid = event.tgid(), ts_ns = event.ts());
        let _guard = span.enter();
        tracing::debug!(kind = event.kind(), "event received");
        on_event(event);
    }
}
