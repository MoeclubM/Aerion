use super::{SudokuClientConfig, SudokuOptions, sudoku_key_seed, timestamp};
use crate::vless_transport::{BoxedTransportStream, VlessTransportConfig};
use crate::{socket_protect, tls, vless_http, vless_websocket};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

fn auth(seed: &str, ts: u64) -> Vec<u8> {
    let key = Sha256::digest(format!("sudoku-httpmask-auth-v1:{seed}").as_bytes());
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
    mac.update(b"ws\0GET\0/ws\0");
    mac.update(&ts.to_be_bytes());
    let mut token = ts.to_be_bytes().to_vec();
    token.extend(&mac.finalize().into_bytes()[..16]);
    token
}
fn path(options: &SudokuOptions) -> String {
    if options.path_root.is_empty() {
        "/ws".into()
    } else {
        format!("/{}/ws", options.path_root.trim_matches('/'))
    }
}
pub(super) async fn client(config: &SudokuClientConfig) -> Result<BoxedTransportStream> {
    let stream =
        socket_protect::connect_tcp_host_port(&config.server_host, config.server_port).await?;
    let options = &config.options;
    if !options.http_mask {
        return Ok(Box::new(stream));
    }
    let host = if options.http_mask_host.is_empty() {
        &config.server_host
    } else {
        &options.http_mask_host
    };
    let mut stream: BoxedTransportStream = if options.http_mask_tls {
        let name = rustls::pki_types::ServerName::try_from(host.to_string())
            .context("Sudoku HTTPMask TLS server name")?;
        Box::new(
            tokio_rustls::TlsConnector::from(tls::client_config(false))
                .connect(name, stream)
                .await?,
        )
    } else {
        Box::new(stream)
    };
    if options.http_mask_mode == "legacy" {
        stream
            .write_all(
                format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
        return Ok(stream);
    }
    let seed = sudoku_key_seed(&config.key)?;
    let header = (
        "Authorization".into(),
        format!(
            "Bearer {}",
            URL_SAFE_NO_PAD.encode(auth(&seed, timestamp()?))
        ),
    );
    let transport =
        VlessTransportConfig::websocket(Some(path(options)), Some(host.to_string()), vec![header]);
    Ok(Box::new(
        vless_websocket::client(stream, &transport, host).await?,
    ))
}
pub(super) async fn server(
    mut stream: TcpStream,
    options: &SudokuOptions,
    credentials: &[String],
) -> Result<BoxedTransportStream> {
    if !options.http_mask {
        return Ok(Box::new(stream));
    }
    let mut probe = [0; 4];
    let n = stream.peek(&mut probe).await?;
    if n < 3 || &probe[..3] != b"GET" {
        return Ok(Box::new(stream));
    }
    let request = vless_http::read_http_head(&mut stream).await?;
    if !request.to_ascii_lowercase().contains("upgrade: websocket") {
        ensure!(
            options.http_mask_mode == "legacy",
            "Sudoku requires a WebSocket upgrade"
        );
        return Ok(Box::new(stream));
    }
    ensure!(
        options.http_mask_mode == "ws",
        "Sudoku WebSocket mode is disabled"
    );
    let token = vless_http::header_value(&request, "Authorization")
        .context("Sudoku WebSocket authorization missing")?;
    let token = URL_SAFE_NO_PAD.decode(token.strip_prefix("Bearer ").unwrap_or(token))?;
    ensure!(token.len() == 24, "invalid Sudoku WebSocket authorization");
    let ts = u64::from_be_bytes(token[..8].try_into()?);
    ensure!(
        timestamp()?.abs_diff(ts) <= 60,
        "expired Sudoku WebSocket authorization"
    );
    let authenticated = credentials.iter().any(|credential| {
        sudoku_key_seed(credential)
            .is_ok_and(|seed| crate::protocol::constant_time_eq(&auth(&seed, ts), &token))
    });
    ensure!(authenticated, "invalid Sudoku WebSocket authorization");
    let transport = VlessTransportConfig::websocket(Some(path(options)), None, Vec::new());
    Ok(Box::new(
        vless_websocket::server_with_head(stream, &transport, &request).await?,
    ))
}
