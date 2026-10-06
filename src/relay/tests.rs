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

#[tokio::test]
async fn simultaneous_backpressure_preserves_both_payloads_and_accounting() -> Result<()> {
    let core = ProxyCore::new(vec![CoreUser::password("user", "secret")])?;
    let session = core.authenticate("secret").await?;
    let (client, left) = duplex(17);
    let (remote, right) = duplex(19);
    let (lr, lw) = tokio::io::split(left);
    let (rr, rw) = tokio::io::split(right);
    let task = tokio::spawn(relay_split_counted(
        lr,
        BufWriter::with_capacity(4096, lw),
        rr,
        BufWriter::with_capacity(4096, rw),
        session,
        "backpressure",
    ));
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut dr, mut dw) = tokio::io::split(remote);
    let upload = (0..131072).map(|i| i as u8).collect::<Vec<_>>();
    let download = (0..65537).map(|i| (i * 7) as u8).collect::<Vec<_>>();
    let mut received_upload = vec![0; upload.len()];
    let mut received_download = vec![0; download.len()];
    timeout(Duration::from_secs(5), async {
        tokio::try_join!(
            cw.write_all(&upload),
            dw.write_all(&download),
            dr.read_exact(&mut received_upload),
            cr.read_exact(&mut received_download),
        )?;
        cw.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    })
    .await??;
    timeout(Duration::from_secs(2), task).await???;
    assert_eq!(received_upload, upload);
    assert_eq!(received_download, download);
    let stats = core.snapshot().await;
    assert_eq!(stats[0].upload_bytes, upload.len() as u64);
    assert_eq!(stats[0].download_bytes, download.len() as u64);
    assert_eq!(stats[0].online_sessions, 0);
    Ok(())
}

#[tokio::test]
async fn eof_flushes_the_last_buffered_payload() -> Result<()> {
    let payload = b"last buffered payload";
    let reader = payload.as_slice();
    let mut writer = BufWriter::new(Vec::new());
    let (_remote, right_reader) = duplex(16);
    relay_split_counted(
        reader,
        tokio::io::sink(),
        right_reader,
        &mut writer,
        CoreSession::disabled(),
        "eof",
    )
    .await?;
    assert_eq!(writer.get_ref(), payload);
    Ok(())
}

#[tokio::test]
async fn rate_limit_wait_flushes_previously_accepted_bytes() -> Result<()> {
    let mut user = CoreUser::password("user", "secret");
    user.upload_limit_bps = Some(2);
    let core = ProxyCore::new(vec![user])?;
    let session = core.authenticate("secret").await?;
    let (mut source, left) = duplex(4);
    let (mut destination, right) = duplex(16);
    let (lr, lw) = tokio::io::split(left);
    let (rr, rw) = tokio::io::split(right);
    let task = tokio::spawn(relay_split_counted(
        lr,
        BufWriter::new(lw),
        rr,
        BufWriter::new(rw),
        session,
        "rate limit",
    ));
    source.write_all(b"abcd").await?;
    tokio::task::yield_now().await;
    source.write_all(b"efgh").await?;
    let mut bytes = [0; 4];
    timeout(Duration::from_secs(3), destination.read_exact(&mut bytes)).await??;
    assert_eq!(&bytes, b"abcd");
    destination.read_exact(&mut bytes).await?;
    assert_eq!(&bytes, b"efgh");
    source.shutdown().await?;
    timeout(Duration::from_secs(2), task).await???;
    Ok(())
}

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/performance/relay.rs"
));
