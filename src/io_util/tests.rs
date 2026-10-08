use super::*;
use tokio::io::{AsyncReadExt, duplex};

#[tokio::test]
async fn fragmented_scalar_writes_preserve_header_payload_and_empty_slices() -> io::Result<()> {
    let (mut writer, mut reader) = duplex(3);
    let payload = (0..1025).map(|i| i as u8).collect::<Vec<_>>();
    let send = async {
        let mut buffers = [
            IoSlice::new(b"header"),
            IoSlice::new(b""),
            IoSlice::new(&payload),
            IoSlice::new(b""),
            IoSlice::new(b"tail"),
        ];
        write_all_vectored(&mut writer, &mut buffers).await?;
        writer.shutdown().await
    };
    let receive = async {
        let mut received = Vec::new();
        reader.read_to_end(&mut received).await?;
        Ok::<_, io::Error>(received)
    };
    let (_, received) = tokio::try_join!(send, receive)?;
    assert_eq!(received, [b"header".as_slice(), &payload, b"tail"].concat());
    Ok(())
}

#[tokio::test]
async fn entirely_empty_slices_do_not_write_or_fail() -> io::Result<()> {
    let mut writer = Vec::new();
    write_all_vectored(&mut writer, &mut [IoSlice::new(b""), IoSlice::new(b"")]).await?;
    assert!(writer.is_empty());
    Ok(())
}

#[tokio::test]
async fn closed_destination_propagates_io_error() -> io::Result<()> {
    let (mut writer, reader) = duplex(3);
    drop(reader);
    let error = write_all_vectored(&mut writer, &mut [IoSlice::new(b"frame")])
        .await
        .expect_err("closed destination must fail");
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    Ok(())
}
