use std::io::{self, IoSlice};
use tokio::io::{AsyncWrite, AsyncWriteExt};

// Callers retain their writer lock for the whole frame and decide when to flush.
// Handles partial writes and writers whose default write_vectored is scalar.
pub(crate) async fn write_all_vectored<W: AsyncWrite + Unpin>(
    writer: &mut W,
    buffers: &mut [IoSlice<'_>],
) -> io::Result<()> {
    let mut remaining = buffers;
    while !remaining.is_empty() {
        // Empty payload/padding must not turn a valid empty frame into WriteZero.
        IoSlice::advance_slices(&mut remaining, 0);
        if remaining.is_empty() {
            break;
        }
        let written = writer.write_vectored(remaining).await?;
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        IoSlice::advance_slices(&mut remaining, written);
    }
    Ok(())
}

pub(crate) async fn write_frame_parts<W: AsyncWrite + Unpin>(
    writer: &mut W,
    header: &[u8],
    payload: &[u8],
) -> io::Result<()> {
    if writer.is_write_vectored() {
        write_all_vectored(writer, &mut [IoSlice::new(header), IoSlice::new(payload)]).await
    } else {
        // Record/mux writers may encode each scalar write as a separate record.
        // Keep their header and payload together, as before the extraction.
        let mut frame = Vec::with_capacity(header.len() + payload.len());
        frame.extend_from_slice(header);
        frame.extend_from_slice(payload);
        writer.write_all(&frame).await
    }
}

#[cfg(test)]
mod tests;
