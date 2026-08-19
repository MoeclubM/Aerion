use super::*;
use anyhow::{Context, Result};
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn task_abort_resolves_if_triggered_before_wait() -> Result<()> {
    let abort = TaskAbort::new();
    abort.trigger();
    timeout(Duration::from_millis(50), abort.cancelled())
        .await
        .context("TaskAbort must resolve after trigger")?;
    Ok(())
}
