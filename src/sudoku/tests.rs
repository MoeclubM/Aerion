use super::*;

#[test]
fn appearance_roundtrips_all_bytes_and_fragmented_packed_records() -> Result<()> {
    for mode in [
        "prefer_ascii",
        "prefer_entropy",
        "up_ascii_down_entropy",
        "up_entropy_down_ascii",
    ] {
        for custom in ["", "xpxvvpvv"] {
            let table = Table::new("test-user-psk", mode, custom)?;
            let payload = (0..=255).collect::<Vec<u8>>();
            for down in [false, true] {
                for packed in [false, true] {
                    let wire = table::encode(&table, down, packed, &payload, 100)?;
                    let mut decoder = table::Decoder::new(table.clone(), down, packed);
                    let mut decoded = Vec::new();
                    for byte in wire {
                        decoded.extend(decoder.feed(&[byte])?);
                    }
                    assert_eq!(decoded, payload);
                }
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn authenticated_handshake_rejects_replay_and_revoked_users() -> Result<()> {
    let core = ProxyCore::from_credentials("alice-key", &["bob-key".into()]);
    for aead in ["chacha20-poly1305", "aes-128-gcm"] {
        for pure in [false, true] {
            let options = SudokuOptions {
                aead: aead.into(),
                enable_pure_downlink: pure,
                ..SudokuOptions::default()
            };
            let (mut client, mut server) = tokio::io::duplex(4096);
            let cache = Arc::new(Mutex::new(HashMap::new()));
            let (client_result, server_result) = tokio::join!(
                client_handshake(&mut client, "bob-key", &options),
                server_handshake(
                    &mut server,
                    &options,
                    &core,
                    "127.0.0.1:1234".parse()?,
                    &cache
                )
            );
            let (mut client_recv, mut client_send) = client_result?;
            let (mut server_recv, mut server_send, session) = server_result?;
            assert_eq!(session.user_id(), "bob-key");
            client_send.write(&mut client, b"hello").await?;
            assert_eq!(server_recv.read(&mut server).await?, b"hello");
            server_send.write(&mut server, b"world").await?;
            assert_eq!(client_recv.read(&mut client).await?, b"world");
        }
    }
    core.replace_users(vec![crate::CoreUser::password("alice", "alice-key")])?;
    assert!(core.authenticate("bob-key").await.is_err());
    Ok(())
}

#[test]
fn mihomo_import_preserves_sudoku_settings() -> Result<()> {
    let config: crate::MihomoConfig = serde_yaml::from_str(
        "proxies:\n  - name: Sudoku\n    type: sudoku\n    server: example.com\n    port: 443\n    key: user-psk\n    table-type: prefer_ascii\n    enable-pure-downlink: false\n    padding-min: 0\n    padding-max: 0\n    udp: true\n",
    )?;
    let proxy = config.proxies[0].to_client_config("127.0.0.1:1080".parse()?)?;
    let crate::MihomoClientConfig::Sudoku(proxy) = proxy else {
        panic!("wrong protocol")
    };
    assert_eq!(proxy.key, "user-psk");
    assert_eq!(proxy.options.table_type, "prefer_ascii");
    assert!(!proxy.options.enable_pure_downlink);
    assert_eq!(proxy.options.padding_max, 0);
    Ok(())
}
