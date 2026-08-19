use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogEntry {
    pub level: String,
    pub target: String,
    pub message: String,
    pub fields: BTreeMap<String, String>,
}

#[derive(Clone, Default)]
pub struct LogBridge {
    subscribers: Arc<Mutex<Vec<mpsc::UnboundedSender<LogEntry>>>>,
}

#[derive(Clone)]
pub struct LogBridgeLayer {
    bridge: LogBridge,
}

#[derive(Default)]
struct LogVisitor {
    message: String,
    fields: BTreeMap<String, String>,
}

impl LogBridge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn layer(&self) -> LogBridgeLayer {
        LogBridgeLayer {
            bridge: self.clone(),
        }
    }

    pub fn subscribe(&self) -> mpsc::UnboundedReceiver<LogEntry> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.subscribers
            .lock()
            .expect("log bridge subscribers lock poisoned")
            .push(tx);
        rx
    }

    fn send(&self, entry: LogEntry) {
        self.subscribers
            .lock()
            .expect("log bridge subscribers lock poisoned")
            .retain(|subscriber| subscriber.send(entry.clone()).is_ok());
    }
}

impl<S> Layer<S> for LogBridgeLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let mut visitor = LogVisitor::default();
        event.record(&mut visitor);
        self.bridge.send(LogEntry {
            level: metadata.level().to_string(),
            target: metadata.target().to_string(),
            message: visitor.message,
            fields: visitor.fields,
        });
    }
}

impl Visit for LogVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.record_value(field, format!("{value:?}"));
    }
}

impl LogVisitor {
    fn record_value(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = value;
        } else {
            self.fields.insert(field.name().to_string(), value);
        }
    }
}

impl std::fmt::Debug for LogBridge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let subscribers = self
            .subscribers
            .lock()
            .expect("log bridge subscribers lock poisoned")
            .len();
        formatter
            .debug_struct("LogBridge")
            .field("subscribers", &subscribers)
            .finish()
    }
}

impl std::fmt::Debug for LogBridgeLayer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LogBridgeLayer")
            .field("bridge", &self.bridge)
            .finish()
    }
}

#[cfg(test)]
mod tests;
