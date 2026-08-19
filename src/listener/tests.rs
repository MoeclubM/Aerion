use super::*;

#[tokio::test]
async fn stop_token_notifies_waiters() {
    let token = ListenerStopToken::new();
    let waiter = token.clone();
    let task = tokio::spawn(async move {
        waiter.stopped().await;
        waiter.is_stopped()
    });
    token.stop();
    assert!(task.await.expect("join stop waiter"));
}

#[test]
fn accept_cancelled_detects_interrupted() {
    assert!(is_accept_cancelled(&std::io::Error::from(
        std::io::ErrorKind::Interrupted
    )));
}
