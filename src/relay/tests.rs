use super::*;
use crate::core::{CoreUser, ProxyCore};
use tokio::io::{BufWriter, duplex};
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn revocation_closes_idle_relays() -> Result<()> {
    let core = ProxyCore::new(vec![CoreUser::password("user", "secret")])?;
    let session = core.authenticate("secret").await?;
    let (mut client, mut left) = duplex(64);
    let (mut remote, mut right) = duplex(64);
    let task = tokio::spawn(async move {
        relay_bidirectional_counted(&mut left, &mut right, session, "test").await
    });
    core.replace_users(Vec::new())?;
    assert!(timeout(Duration::from_secs(2), task).await??.is_err());
    assert_eq!(client.read(&mut [0u8; 1]).await?, 0);
    assert_eq!(remote.read(&mut [0u8; 1]).await?, 0);
    Ok(())
}

#[tokio::test]
async fn buffered_writers_flush_without_waiting_for_fin() -> Result<()> {
    let (mut client, left) = duplex(64);
    let (mut remote, right) = duplex(64);
    let (lr, lw) = tokio::io::split(left);
    let (rr, rw) = tokio::io::split(right);
    let task = tokio::spawn(relay_split_counted(
        lr,
        BufWriter::new(lw),
        rr,
        BufWriter::new(rw),
        CoreSession::disabled(),
        "test",
    ));
    client.write_all(b"hello").await?;
    let mut bytes = [0; 5];
    timeout(Duration::from_secs(2), remote.read_exact(&mut bytes)).await??;
    assert_eq!(&bytes, b"hello");
    remote.write_all(b"world").await?;
    timeout(Duration::from_secs(2), client.read_exact(&mut bytes)).await??;
    assert_eq!(&bytes, b"world");
    client.shutdown().await?;
    timeout(Duration::from_secs(2), task).await???;
    assert_eq!(remote.read(&mut [0; 1]).await?, 0);
    Ok(())
}

#[tokio::test]
async fn either_fin_closes_both_writers_and_preserves_accounting() -> Result<()> {
    let core = ProxyCore::new(vec![CoreUser::password("user", "secret")])?;
    let session = core.authenticate("secret").await?;
    let (mut client, mut left) = duplex(64);
    let (mut remote, mut right) = duplex(64);
    let task = tokio::spawn(async move {
        relay_bidirectional_counted(&mut left, &mut right, session, "test").await
    });
    client.write_all(b"hello").await?;
    let mut bytes = [0; 5];
    timeout(Duration::from_secs(2), remote.read_exact(&mut bytes)).await??;
    remote.shutdown().await?;
    timeout(Duration::from_secs(2), task).await???;
    assert_eq!(client.read(&mut [0; 1]).await?, 0);
    let stats = core.snapshot().await;
    assert_eq!(stats[0].upload_bytes, 5);
    assert_eq!(stats[0].online_sessions, 0);
    Ok(())
}
