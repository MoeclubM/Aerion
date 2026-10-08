mod sudoku_performance {
    use super::*;
    use std::time::Instant;

    #[test]
    #[ignore = "release benchmark run by protocol-performance workflow"]
    fn records_and_multiuser_handshakes() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            for method in ["aes-128-gcm", "chacha20-poly1305"] {
                for packed in [false, true] {
                    for size in [64, 1024, 32768] {
                        let table = Table::new("performance-key", "prefer_entropy", "")?;
                        let payload = vec![0x5a; size];
                        let mut sender =
                            Sender::new(table.clone(), true, packed, [3; 32], method, 5)?;
                        let mut receiver = Receiver::new(table, true, packed, [3; 32], method);
                        let (mut write, mut read) = tokio::io::duplex(8192);
                        let start = Instant::now();
                        let mut count = 0;
                        while count < 128 || start.elapsed() < Duration::from_millis(250) {
                            let (_, decoded) = tokio::try_join!(
                                sender.write(&mut write, &payload),
                                receiver.read(&mut read)
                            )?;
                            assert_eq!(decoded, payload);
                            count += 1;
                        }
                        println!(
                            "PERF sudoku-record-{method}-{packed}-{size} {:.3}",
                            count as f64 * size as f64 / start.elapsed().as_secs_f64() / 1048576.0
                        );
                    }
                }
            }
            for users in [1, 128, 2838] {
                let core = ProxyCore::new(
                    (0..users)
                        .map(|i| crate::CoreUser::password(format!("user-{i}"), format!("key-{i}")))
                        .collect(),
                )?;
                // HashMap iteration is randomized per process. Use the same
                // relative search position in both builds instead of timing
                // whichever position a fixed credential happens to occupy.
                let key = core.known_credentials()[users / 2].clone();
                let options = SudokuOptions {
                    aead: "aes-128-gcm".into(),
                    ..Default::default()
                };
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let address = listener.local_addr()?;
                let server = tokio::spawn(run_sudoku_server_listener_with_core(
                    listener,
                    SudokuServerConfig {
                        listen: address,
                        key: String::new(),
                        users: Vec::new(),
                        options: options.clone(),
                    },
                    core,
                ));
                let destination = TcpListener::bind("127.0.0.1:0").await?;
                let target = ProxyTarget::Ip(destination.local_addr()?);
                let responder = tokio::spawn(async move {
                    loop {
                        let (mut stream, _) = destination.accept().await?;
                        tokio::spawn(async move {
                            let mut byte = [0];
                            if stream.read_exact(&mut byte).await.is_ok() {
                                let _ = stream.write_all(&byte).await;
                            }
                        });
                    }
                    #[allow(unreachable_code)]
                    Ok::<(), anyhow::Error>(())
                });
                // Warm the listener once; compare steady-state new TCP sessions.
                let mut count = 0;
                let mut start = Instant::now();
                while count < 32 || start.elapsed() < Duration::from_millis(500) {
                    let mut wire = TcpStream::connect(address).await?;
                    wire.set_nodelay(true)?;
                    let (mut receiver, mut sender) =
                        client_handshake(&mut wire, &key, &options).await?;
                    let mut target_bytes = Vec::new();
                    uot::write_socks_address(&mut target_bytes, &target)?;
                    sender.kip(&mut wire, 0x10, &target_bytes).await?;
                    sender.write(&mut wire, b"!").await?;
                    assert_eq!(receiver.read(&mut wire).await?, b"!");
                    if count == 0 {
                        start = Instant::now();
                    }
                    count += 1;
                }
                // MiB/s with one MiB per session expresses new sessions/s in
                // the common PERF format; these labels measure handshake rate.
                println!(
                    "PERF sudoku-handshakes-{users}-users {:.3}",
                    (count - 1) as f64 / start.elapsed().as_secs_f64()
                );
                server.abort();
                responder.abort();
            }
            Ok::<(), anyhow::Error>(())
        })
    }
}
