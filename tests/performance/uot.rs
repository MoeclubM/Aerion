mod protocol_performance {
    use super::*;
    use std::hint::black_box;
    mod support {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/performance/support.rs"
        ));
    }

    #[test]
    #[ignore = "release benchmark run by protocol-performance workflow"]
    fn uot_parse() -> Result<()> {
        let target = ProxyTarget::Ip("[::1]:53".parse()?);
        let request = legacy_associate_request();
        for size in [64, 1024, 16384] {
            let packet = encode_associate_packet(&target, &vec![0x42; size])?;
            let mut pending = Vec::with_capacity(packet.len());
            support::measure(&format!("uot-parse-{size}"), size, || {
                pending.extend_from_slice(black_box(&packet));
                let (_, payload, _) = take_stream_packet(&request, &mut pending).unwrap().unwrap();
                assert_eq!(black_box(payload).len(), size);
                assert!(pending.is_empty());
            });
        }
        Ok(())
    }
}
