use super::*;
use tokio::net::TcpListener;

#[tokio::test]
async fn rejects_greetings_without_supported_authentication() -> Result<()> {
    for greeting in [vec![5, 1, 2], vec![5, 0]] {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let mut client = TcpStream::connect(listener.local_addr()?).await?;
        let (mut server, _) = listener.accept().await?;
        let task = tokio::spawn(async move { read_request(&mut server).await });
        client.write_all(&greeting).await?;
        let mut reply = [0; 2];
        client.read_exact(&mut reply).await?;
        assert_eq!(reply, [5, 0xff]);
        assert!(task.await?.is_err());
    }
    Ok(())
}

#[test]
fn udp_associate_uses_upstream_ip_for_unspecified_bind() -> Result<()> {
    assert_eq!(
        normalize_udp_bind("0.0.0.0:5300".parse()?, "192.0.2.10:1080".parse()?),
        "192.0.2.10:5300".parse::<SocketAddr>()?
    );
    assert_eq!(
        normalize_udp_bind("[::]:5300".parse()?, "[2001:db8::1]:1080".parse()?),
        "[2001:db8::1]:5300".parse::<SocketAddr>()?
    );
    assert_eq!(
        normalize_udp_bind("198.51.100.5:5300".parse()?, "192.0.2.10:1080".parse()?),
        "198.51.100.5:5300".parse::<SocketAddr>()?
    );
    Ok(())
}
