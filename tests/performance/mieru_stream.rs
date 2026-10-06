mod transport_performance {
    use super::*;
    use std::hint::black_box;

    #[tokio::test]
    #[ignore = "release benchmark run by transport-performance workflow"]
    async fn mieru_encrypted_stream() -> Result<()> {
        for size in [64, 1024, 32768] {
            for capacity in [8192, 65536] {
                for padded in [false, true] {
                    let pattern = (!padded).then_some(MieruTrafficPattern {
                        tcp_fragment: None,
                        nonce: None,
                        padding: Some(MieruPaddingPattern {
                            max_middle_padding_len: Some(0),
                            max_end_padding_len: Some(0),
                        }),
                    });
                    let (sender, mut receiver) = tokio::io::duplex(capacity);
                    let cipher = MieruCipher::new([0x11; KEY_LEN], true, "alice".into(), None);
                    let mut send = MieruStreamWriter::new(sender, Some(cipher.clone()), pattern);
                    let mut receive = cipher;
                    let payload = vec![0x42; size];
                    let mut iterations = 0u32;
                    let mut start = Instant::now();
                    loop {
                        let segment = MieruSegment {
                            metadata: MieruMetadata::DataAck(MieruDataAckMetadata {
                                protocol: DATA_CLIENT_TO_SERVER,
                                session_id: 7,
                                seq: iterations,
                                un_ack_seq: 0,
                                window_size: ACK_WINDOW_SIZE,
                                fragment: 0,
                                prefix_len: 0,
                                payload_len: 0,
                                suffix_len: 0,
                            }),
                            payload: payload.clone(),
                        };
                        tokio::try_join!(send.write_segment(segment), async {
                            let segment =
                                read_mieru_segment(&mut receiver, &mut receive, iterations == 0)
                                    .await?;
                            assert_eq!(segment.metadata.seq(), iterations);
                            assert_eq!(black_box(segment.payload), payload);
                            Ok::<(), anyhow::Error>(())
                        },)?;
                        iterations += 1;
                        if iterations == 16 {
                            start = Instant::now();
                        }
                        if iterations > 16 && start.elapsed() >= Duration::from_millis(350) {
                            break;
                        }
                    }
                    println!(
                        "PERF mieru-stream-padded-{padded}-{size}-pipe-{capacity} {:.3}",
                        size as f64 * (iterations - 16) as f64
                            / start.elapsed().as_secs_f64()
                            / 1048576.0
                    );
                }
            }
        }
        Ok(())
    }
}
