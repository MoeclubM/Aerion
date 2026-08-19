use super::*;
use tracing_subscriber::prelude::*;

#[tokio::test]
async fn bridges_tracing_events_to_receiver() {
    let bridge = LogBridge::new();
    let mut rx = bridge.subscribe();
    let subscriber = tracing_subscriber::registry().with(bridge.layer());
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(user = "u1", bytes = 42_u64, "connected");
    });

    let entry = rx.recv().await.expect("log bridge event");
    assert_eq!(entry.level, "INFO");
    assert_eq!(entry.message, "connected");
    assert_eq!(entry.fields.get("user").map(String::as_str), Some("u1"));
    assert_eq!(entry.fields.get("bytes").map(String::as_str), Some("42"));
}
