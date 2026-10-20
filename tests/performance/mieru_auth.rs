mod authentication_performance {
    use super::*;
    use std::hint::black_box;

    fn measure(label: &str, mut action: impl FnMut()) {
        action();
        let start = std::time::Instant::now();
        let mut iterations = 0;
        while iterations < 2 || start.elapsed() < Duration::from_millis(250) {
            action();
            iterations += 1;
        }
        println!("PERF {label} {:.3}", iterations as f64 / start.elapsed().as_secs_f64());
    }

    #[test]
    #[ignore = "release benchmark run by protocol-performance workflow"]
    fn mieru_authentication() -> Result<()> {
        for count in [128, 365, 2855] {
            let users = (0..count).map(|i| {
                let username = format!("auth-user-{i}");
                MieruUserSecret { hashed_password: crypto::hash_mieru_password(b"secret", username.as_bytes()),
                    username, password: String::new() }
            }).collect::<Vec<_>>();
            measure(&format!("mieru-key-scan-{count}"), || {
                for user in &users { black_box(crypto::current_mieru_key(black_box(&user.hashed_password)).unwrap()); }
            });
            let selected = users.last().unwrap();
            let key = crypto::current_mieru_key(&selected.hashed_password)?;
            for hinted in [true, false] {
                let mut cipher = MieruCipher::new(key, false,
                    if hinted { selected.username.clone() } else { "legacy-unhinted".into() }, None);
                let packet = encode_mieru_packet_segment(&mut cipher, MieruSegment {
                    metadata: MieruMetadata::DataAck(MieruDataAckMetadata {
                        protocol: DATA_CLIENT_TO_SERVER, session_id: 1, seq: 1,
                        un_ack_seq: 0, window_size: 32, fragment: 0, prefix_len: 0, payload_len: 0, suffix_len: 0,
                    }), payload: Vec::new(),
                }, 1400, None)?;
                let replay = MieruReplayCache::new();
                measure(&format!("mieru-auth-{hinted}-{count}"), || {
                    black_box(decode_mieru_packet_segment_for_server(black_box(&packet), black_box(&users), false, None, &replay).unwrap());
                });
            }
        }
        Ok(())
    }
}
