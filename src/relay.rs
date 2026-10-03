use crate::core::CoreSession;
use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn relay_bidirectional_counted<A, B>(
    left: &mut A,
    right: &mut B,
    session: CoreSession,
    label: &str,
) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (left_reader, left_writer) = tokio::io::split(left);
    let (right_reader, right_writer) = tokio::io::split(right);
    relay_split_counted(
        left_reader,
        left_writer,
        right_reader,
        right_writer,
        session,
        label,
    )
    .await
}

pub async fn relay_split_counted<LR, LW, RR, RW>(
    mut left_reader: LR,
    mut left_writer: LW,
    mut right_reader: RR,
    mut right_writer: RW,
    session: CoreSession,
    label: &str,
) -> Result<()>
where
    LR: AsyncRead + Unpin,
    LW: AsyncWrite + Unpin,
    RR: AsyncRead + Unpin,
    RW: AsyncWrite + Unpin,
{
    let uplink_session = session.clone();
    let uplink = async {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            let read = left_reader
                .read(&mut buffer)
                .await
                .with_context(|| format!("read {label} uplink"))?;
            if read == 0 {
                return Ok::<(), anyhow::Error>(());
            }
            uplink_session.record_upload(read).await?;
            right_writer
                .write_all(&buffer[..read])
                .await
                .with_context(|| format!("write {label} uplink"))?;
            right_writer
                .flush()
                .await
                .with_context(|| format!("flush {label} uplink"))?;
        }
    };
    let downlink = async {
        let mut buffer = vec![0u8; 32 * 1024];
        loop {
            let read = right_reader
                .read(&mut buffer)
                .await
                .with_context(|| format!("read {label} downlink"))?;
            if read == 0 {
                return Ok::<(), anyhow::Error>(());
            }
            session.record_download(read).await?;
            left_writer
                .write_all(&buffer[..read])
                .await
                .with_context(|| format!("write {label} downlink"))?;
            left_writer
                .flush()
                .await
                .with_context(|| format!("flush {label} downlink"))?;
        }
    };
    let result = tokio::select! {
        _ = session.cancelled() => Err(anyhow::anyhow!("core session cancelled")),
        result = uplink => result,
        result = downlink => result,
    };
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let _ = tokio::join!(right_writer.shutdown(), left_writer.shutdown());
    })
    .await;
    result
}

#[cfg(test)]
mod tests;
